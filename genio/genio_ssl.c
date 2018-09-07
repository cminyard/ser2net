/*
 *  ser2net - A program for allowing ssl connections
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <errno.h>
#include "genio_internal.h"

#ifdef HAVE_OPENSSL

#include "genio_base.h"

#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <assert.h>
#include <syslog.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

int
ssl_genio_alloc(struct genio *child, char *args[],
		struct genio_os_funcs *o,
		unsigned int max_read_size,
		const struct genio_callbacks *cbs, void *user_data,
		struct genio **net)
{
    int err;
    struct genio_filter *filter;
    struct genio_ll *ll;
    struct genio *io;

    err = genio_ssl_filter_alloc(o, args, max_read_size, &filter);
    if (err)
	return err;

    ll = genio_genio_ll_alloc(o, child);
    if (!ll) {
	filter->ops->free(filter);
	return ENOMEM;
    }

    io = base_genio_alloc(o, ll, filter, GENIO_TYPE_SSL, cbs, user_data);
    if (!io) {
	ll->ops->free(ll);
	filter->ops->free(filter);
	return ENOMEM;
    }

    *net = io;
    return 0;
}

struct sslna_data {
    struct genio_acceptor acceptor;

    char *name;
    unsigned int max_read_size;
    unsigned int max_write_size;

    struct genio_os_funcs *o;

    struct genio_lock *lock;

    struct genio_acceptor *child;

    char *keyfile;
    char *certfile;
    char *CAfilepath;

    unsigned int refcount;
    unsigned int in_cb_count;

    bool enabled;
    bool in_shutdown;
    bool call_shutdown_done;
    void (*shutdown_done)(struct genio_acceptor *acceptor,
			  void *shutdown_data);
    void *shutdown_data;
};

#define acc_to_nadata(acc) container_of(acc, struct sslna_data, acceptor);

static void
sslna_lock(struct sslna_data *nadata)
{
    nadata->o->lock(nadata->lock);
}

static void
sslna_unlock(struct sslna_data *nadata)
{
    nadata->o->unlock(nadata->lock);
}

static void
sslna_finish_free(struct sslna_data *nadata)
{
    if (nadata->child)
	genio_acc_free(nadata->child);
    if (nadata->keyfile)
	nadata->o->free(nadata->o, nadata->keyfile);
    if (nadata->certfile)
	nadata->o->free(nadata->o, nadata->certfile);
    if (nadata->lock)
	nadata->o->free_lock(nadata->lock);
    if (nadata->name)
	nadata->o->free(nadata->o, nadata->name);
    if (nadata->CAfilepath)
	nadata->o->free(nadata->o, nadata->CAfilepath);
    nadata->o->free(nadata->o, nadata);
}

static void
sslna_ref(struct sslna_data *nadata)
{
    nadata->refcount++;
}

static void
sslna_deref_and_unlock(struct sslna_data *nadata)
{
    unsigned int count;

    assert(nadata->refcount > 0);
    count = --nadata->refcount;
    sslna_unlock(nadata);
    if (count == 0)
	sslna_finish_free(nadata);
}

static void
sslna_finish_shutdown_unlock(struct sslna_data *nadata)
{
    void *shutdown_data;
    void (*shutdown_done)(struct genio_acceptor *acceptor,
			  void *shutdown_data);

    nadata->in_shutdown = false;
    shutdown_done = nadata->shutdown_done;
    shutdown_data = nadata->shutdown_data;
    nadata->shutdown_done = NULL;
    sslna_unlock(nadata);

    if (shutdown_done)
	shutdown_done(&nadata->acceptor, shutdown_data);

    sslna_lock(nadata);
    sslna_deref_and_unlock(nadata);
}

static void
sslna_in_cb(struct sslna_data *nadata)
{
    sslna_ref(nadata);
    nadata->in_cb_count++;
}

static void
sslna_leave_cb_unlock(struct sslna_data *nadata)
{
    nadata->in_cb_count--;
    if (nadata->in_cb_count == 0 && nadata->call_shutdown_done)
	sslna_finish_shutdown_unlock(nadata);
    else
	sslna_deref_and_unlock(nadata);
}

static int
sslna_startup(struct genio_acceptor *acceptor)
{
    struct sslna_data *nadata = acc_to_nadata(acceptor);

    return genio_acc_startup(nadata->child);
}

static void
sslna_child_shutdown(struct genio_acceptor *acceptor,
		     void *shutdown_data)
{
    struct sslna_data *nadata = shutdown_data;

    sslna_lock(nadata);
    if (nadata->in_cb_count) {
	nadata->call_shutdown_done = true;
	sslna_unlock(nadata);
    } else {
	sslna_finish_shutdown_unlock(nadata);
    }
}

static int
sslna_shutdown(struct genio_acceptor *acceptor,
	       void (*shutdown_done)(struct genio_acceptor *acceptor,
				     void *shutdown_data),
	       void *shutdown_data)
{
    struct sslna_data *nadata = acc_to_nadata(acceptor);
    int rv = EBUSY;

    sslna_lock(nadata);
    if (nadata->enabled) {
	nadata->shutdown_done = shutdown_done;
	nadata->shutdown_data = shutdown_data;

	rv = genio_acc_shutdown(nadata->child, sslna_child_shutdown, nadata);
	if (!rv) {
	    sslna_ref(nadata);
	    nadata->enabled = false;
	    nadata->in_shutdown = true;
	}
    }
    sslna_unlock(nadata);
    return rv;
}

static void
sslna_set_accept_callback_enable(struct genio_acceptor *acceptor, bool enabled)
{
    struct sslna_data *nadata = acc_to_nadata(acceptor);

    genio_acc_set_accept_callback_enable(nadata->child, enabled);
}

static void
sslna_free(struct genio_acceptor *acceptor)
{
    struct sslna_data *nadata = acc_to_nadata(acceptor);

    sslna_lock(nadata);
    sslna_deref_and_unlock(nadata);
}

struct sslna_connect_data {
    struct genio_os_funcs *o;
    struct genio_lock *lock;
    bool ignore;
    void (*connect_done)(struct genio *net, int err, void *cb_data);
    void *cb_data;
    struct genio *io;
};

static void
sslna_child_connect_done(struct genio *net, int err, void *cb_data)
{
    struct sslna_connect_data *cdata = cb_data;
    struct genio_os_funcs *o = cdata->o;

    o->lock(cdata->lock);
    if (cdata->ignore) {
	genio_free(net);
	goto out_free;
    }

    if (err) {
	cdata->connect_done(cdata->io, err, cdata->cb_data);
	genio_free(cdata->io);
	goto out_free;
    }

    err = genio_open(cdata->io, cdata->connect_done, cdata->cb_data);
    if (err) {
	cdata->connect_done(cdata->io, err, cdata->cb_data);
	genio_free(cdata->io);
    }

 out_free:
    o->unlock(cdata->lock);

    o->free_lock(cdata->lock);
    o->free(o, cdata);
}

int
sslna_connect(struct genio_acceptor *acceptor, void *addr,
	      void (*connect_done)(struct genio *net, int err,
				   void *cb_data),
	      void *cb_data, struct genio **new_net)
{
    struct sslna_data *nadata = acc_to_nadata(acceptor);
    struct genio_os_funcs *o = nadata->o;
    int err;
    struct sslna_connect_data *cdata;
    struct genio *io, *child;
    char *args[2] = {NULL, NULL};

    cdata = o->zalloc(o, sizeof(*cdata));
    if (!cdata) {
	err = ENOMEM;
	goto out;
    }

    cdata->lock = o->alloc_lock(o);
    if (!cdata->lock) {
	o->free(o, cdata);
	err = ENOMEM;
	goto out;
    }

    args[0] = o->zalloc(o, strlen(nadata->CAfilepath) + 4);
    if (!args[0]) {
	o->free_lock(cdata->lock);
	o->free(o, cdata);
	err = ENOMEM;
	goto out;
    }
    strcpy(args[0], "CA=");
    strcat(args[0], nadata->CAfilepath);

    cdata->connect_done = connect_done;
    cdata->cb_data = cb_data;

    o->lock(cdata->lock);
    err = genio_acc_connect(nadata->child, addr, sslna_child_connect_done,
			    cdata, &child);
    if (err) {
	o->free_lock(cdata->lock);
	o->free(o, cdata);
	goto out;
    }

    err = ssl_genio_alloc(io, args, nadata->o, nadata->max_read_size,
			  NULL, NULL, &io);
    if (err)
	cdata->ignore = true;
    else
	cdata->io = io;

    o->unlock(cdata->lock);

 out:
    if (args[0])
	o->free(o, args[0]);
    return err;

}

static const struct genio_acceptor_functions genio_acc_ssl_funcs = {
    .startup = sslna_startup,
    .shutdown = sslna_shutdown,
    .set_accept_callback_enable = sslna_set_accept_callback_enable,
    .free = sslna_free,
    .connect = sslna_connect
};

static void
sslna_finish_server_open(struct genio *net, int err, void *cb_data)
{
    struct sslna_data *nadata = cb_data;

    if (err)
	genio_free(net);
    else
	nadata->acceptor.cbs->new_connection(&nadata->acceptor, net);

    sslna_lock(nadata);
    sslna_leave_cb_unlock(nadata);
}

static void
sslna_new_child_connection(struct genio_acceptor *acceptor, struct genio *io)
{
    struct sslna_data *nadata = genio_acc_get_user_data(acceptor);
    struct genio_os_funcs *o = nadata->o;
    struct genio_filter *filter;
    struct genio_ll *ll;
    int err;

    err = genio_ssl_server_filter_alloc(o, nadata->keyfile, nadata->certfile,
					nadata->CAfilepath,
					nadata->max_read_size,
					nadata->max_write_size,
					&filter);
    if (err)
	goto out_err;

    ll = genio_genio_ll_alloc(o, io);
    if (!ll) {
	filter->ops->free(filter);
	goto out_nomem;
    }

    sslna_lock(nadata);
    io = base_genio_server_alloc(o, ll, filter, GENIO_TYPE_SSL,
				 sslna_finish_server_open, nadata);
    if (io) {
	sslna_in_cb(nadata);
	sslna_unlock(nadata);
    } else {
	sslna_unlock(nadata);
	ll->ops->free(ll);
	filter->ops->free(filter);
	goto out_nomem;
    }
    return;

 out_nomem:
    err = ENOMEM;
 out_err:
    syslog(LOG_ERR, "Error allocating ssl genio: %s", strerror(err));
}

static struct genio_acceptor_callbacks sslna_acc_cbs = {
    .new_connection = sslna_new_child_connection
};

int
ssl_genio_acceptor_alloc(const char *name,
			 char *args[],
			 struct genio_os_funcs *o,
			 struct genio_acceptor *child,
			 unsigned int max_read_size,
			 const struct genio_acceptor_callbacks *cbs,
			 void *user_data,
			 struct genio_acceptor **acceptor)
{
    struct genio_acceptor *acc;
    struct sslna_data *nadata;
    const char *keyfile = NULL;
    const char *certfile = NULL;
    const char *CAfilepath = NULL;
    unsigned int i;
    unsigned int max_write_size = 4096; /* FIXME - magic number. */

    for (i = 0; args[i]; i++) {
	if (genio_check_keyvalue(args[i], "CA", &CAfilepath))
	    continue;
	if (genio_check_keyvalue(args[i], "key", &keyfile))
	    continue;
	if (genio_check_keyvalue(args[i], "cert", &certfile))
	    continue;
	if (genio_check_keyuint(args[i], "maxwrite", &max_write_size) > 0)
	    continue;
	return EINVAL;
    }

    if (!CAfilepath || !keyfile)
	return EINVAL;

    nadata = o->zalloc(o, sizeof(*nadata));
    if (!nadata)
	return ENOMEM;

    nadata->max_write_size = max_write_size;

    nadata->name = genio_strdup(o, name);
    if (!nadata->name)
	goto out_nomem;

    nadata->keyfile = genio_strdup(o, keyfile);
    if (!nadata->keyfile)
	goto out_nomem;

    if (!certfile)
	certfile = keyfile;

    nadata->certfile = genio_strdup(o, certfile);
    if (!nadata->certfile)
	goto out_nomem;

    nadata->CAfilepath = genio_strdup(o, CAfilepath);
    if (!nadata->CAfilepath)
	goto out_nomem;

    nadata->lock = o->alloc_lock(o);
    if (!nadata->lock)
	goto out_nomem;

    acc = &nadata->acceptor;
    acc->cbs = cbs;
    acc->user_data = user_data;
    acc->funcs = &genio_acc_ssl_funcs;
    acc->type = GENIO_TYPE_SSL;

    nadata->o = o;
    nadata->child = child;
    nadata->refcount = 1;
    nadata->max_read_size = max_read_size;

    genio_acc_set_callbacks(child, &sslna_acc_cbs, nadata);

    *acceptor = acc;

    return 0;

out_nomem:
    sslna_finish_free(nadata);
    return ENOMEM;
}

#else /* HAVE_OPENSSL */
int
ssl_genio_alloc(struct genio *child, char *args[],
		struct genio_os_funcs *o,
		unsigned int max_read_size,
		const struct genio_callbacks *cbs, void *user_data,
		struct genio **net)
{
    return ENOTSUP;
}

int
ssl_genio_acceptor_alloc(const char *name,
			 char *args[],
			 struct genio_os_funcs *o,
			 struct genio_acceptor *child,
			 unsigned int max_read_size,
			 const struct genio_acceptor_callbacks *cbs,
			 void *user_data,
			 struct genio_acceptor **acceptor)
{
    return ENOTSUP;
}

#endif /* HAVE_OPENSSL */
