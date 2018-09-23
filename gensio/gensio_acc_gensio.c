/*
 *  gensio - A library for abstracting stream I/O
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

#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <assert.h>
#include <syslog.h>

#include <gensio/gensio_internal.h>
#include <gensio/gensio_base.h>

struct basena_data {
    struct gensio_acceptor acceptor;

    char *name;

    struct gensio_os_funcs *o;

    struct gensio_lock *lock;

    struct gensio_acceptor *child;

    const struct gensio_gensio_acc_cbs *acc_cbs;
    void *acc_data;

    unsigned int refcount;
    unsigned int in_cb_count;

    bool enabled;
    bool in_shutdown;
    bool call_shutdown_done;
    void (*shutdown_done)(struct gensio_acceptor *acceptor,
			  void *shutdown_data);
    void *shutdown_data;
};

#define acc_to_nadata(acc) container_of(acc, struct basena_data, acceptor);

static void
basena_lock(struct basena_data *nadata)
{
    nadata->o->lock(nadata->lock);
}

static void
basena_unlock(struct basena_data *nadata)
{
    nadata->o->unlock(nadata->lock);
}

static void
basena_finish_free(struct basena_data *nadata)
{
    if (nadata->child)
	gensio_acc_free(nadata->child);
    if (nadata->lock)
	nadata->o->free_lock(nadata->lock);
    if (nadata->name)
	nadata->o->free(nadata->o, nadata->name);
    if (nadata->acc_cbs)
	nadata->acc_cbs->free(nadata->acc_data);
    nadata->o->free(nadata->o, nadata);
}

static void
basena_ref(struct basena_data *nadata)
{
    nadata->refcount++;
}

static void
basena_deref_and_unlock(struct basena_data *nadata)
{
    unsigned int count;

    assert(nadata->refcount > 0);
    count = --nadata->refcount;
    basena_unlock(nadata);
    if (count == 0)
	basena_finish_free(nadata);
}

static void
basena_finish_shutdown_unlock(struct basena_data *nadata)
{
    void *shutdown_data;
    void (*shutdown_done)(struct gensio_acceptor *acceptor,
			  void *shutdown_data);

    nadata->in_shutdown = false;
    shutdown_done = nadata->shutdown_done;
    shutdown_data = nadata->shutdown_data;
    nadata->shutdown_done = NULL;
    basena_unlock(nadata);

    if (shutdown_done)
	shutdown_done(&nadata->acceptor, shutdown_data);

    basena_lock(nadata);
    basena_deref_and_unlock(nadata);
}

static void
basena_in_cb(struct basena_data *nadata)
{
    basena_ref(nadata);
    nadata->in_cb_count++;
}

static void
basena_leave_cb_unlock(struct basena_data *nadata)
{
    nadata->in_cb_count--;
    if (nadata->in_cb_count == 0 && nadata->call_shutdown_done)
	basena_finish_shutdown_unlock(nadata);
    else
	basena_deref_and_unlock(nadata);
}

static int
basena_startup(struct gensio_acceptor *acceptor)
{
    struct basena_data *nadata = acc_to_nadata(acceptor);

    return gensio_acc_startup(nadata->child);
}

static void
basena_child_shutdown(struct gensio_acceptor *acceptor,
		     void *shutdown_data)
{
    struct basena_data *nadata = shutdown_data;

    basena_lock(nadata);
    if (nadata->in_cb_count) {
	nadata->call_shutdown_done = true;
	basena_unlock(nadata);
    } else {
	basena_finish_shutdown_unlock(nadata);
    }
}

static int
basena_shutdown(struct gensio_acceptor *acceptor,
	       void (*shutdown_done)(struct gensio_acceptor *acceptor,
				     void *shutdown_data),
	       void *shutdown_data)
{
    struct basena_data *nadata = acc_to_nadata(acceptor);
    int rv = EBUSY;

    basena_lock(nadata);
    if (nadata->enabled) {
	nadata->shutdown_done = shutdown_done;
	nadata->shutdown_data = shutdown_data;

	rv = gensio_acc_shutdown(nadata->child, basena_child_shutdown, nadata);
	if (!rv) {
	    basena_ref(nadata);
	    nadata->enabled = false;
	    nadata->in_shutdown = true;
	}
    }
    basena_unlock(nadata);
    return rv;
}

static void
basena_set_accept_callback_enable(struct gensio_acceptor *acceptor,
				  bool enabled)
{
    struct basena_data *nadata = acc_to_nadata(acceptor);

    gensio_acc_set_accept_callback_enable(nadata->child, enabled);
}

static void
basena_free(struct gensio_acceptor *acceptor)
{
    struct basena_data *nadata = acc_to_nadata(acceptor);

    basena_lock(nadata);
    basena_deref_and_unlock(nadata);
}

struct basena_connect_data {
    struct basena_data *nadata;
    struct gensio_lock *lock;
    void (*connect_done)(struct gensio *net, int err, void *cb_data);
    void *cb_data;
    bool ignore;
    struct gensio *io;
};

static void
basena_child_connect_done(struct gensio *net, int err, void *cb_data)
{
    struct basena_connect_data *cdata = cb_data;
    struct basena_data *nadata = cdata->nadata;
    struct gensio_os_funcs *o = nadata->o;

    /* Just make sure basena_connect has finished. */
    o->lock(cdata->lock);
    o->unlock(cdata->lock);

    if (cdata->ignore)
	goto out_free;

    if (err) {
	cdata->connect_done(cdata->io, err, cdata->cb_data);
	goto out_free;
    }

    err = gensio_open(cdata->io, cdata->connect_done, cdata->cb_data);
    if (err)
	cdata->connect_done(cdata->io, err, cdata->cb_data);

 out_free:
    o->free(o, cdata);

    basena_lock(nadata);
    basena_leave_cb_unlock(nadata);
}

int
basena_connect(struct gensio_acceptor *acceptor, void *addr,
	       void (*connect_done)(struct gensio *net, int err, void *cb_data),
	       void *cb_data, struct gensio **new_net)
{
    struct basena_data *nadata = acc_to_nadata(acceptor);
    struct gensio_os_funcs *o = nadata->o;
    int err;
    struct basena_connect_data *cdata;
    struct gensio *child = NULL;

    cdata = o->zalloc(o, sizeof(*cdata));
    if (!cdata)
	return ENOMEM;

    cdata->lock = o->alloc_lock(o);
    if (!cdata) {
	err = ENOMEM;
	goto out;
    }
    
    cdata->nadata = nadata;
    cdata->connect_done = connect_done;
    cdata->cb_data = cb_data;

    o->lock(cdata->lock);
    err = gensio_acc_connect(nadata->child, addr, basena_child_connect_done,
			     cdata, &child);
    if (err) {
	o->unlock(cdata->lock);
	goto out;
    }

    basena_in_cb(nadata);

    err = nadata->acc_cbs->connect_start(nadata->acc_data, child, &cdata->io);
    if (err) {
	cdata->ignore = true;
	o->unlock(cdata->lock);
	return err;
    }
	
    o->unlock(cdata->lock);

 out:
    if (err) {
	if (cdata->lock)
	    o->free_lock(cdata->lock);
	if (child)
	    gensio_free(child);
	o->free(o, cdata);
    }
    return err;
}

static const struct gensio_acceptor_functions gensio_acc_basena_funcs = {
    .startup = basena_startup,
    .shutdown = basena_shutdown,
    .set_accept_callback_enable = basena_set_accept_callback_enable,
    .free = basena_free,
    .connect = basena_connect
};

static void
basena_finish_server_open(struct gensio *net, int err, void *cb_data)
{
    struct basena_data *nadata = cb_data;

    if (err)
	gensio_free(net);
    else
	nadata->acceptor.cb(&nadata->acceptor, GENSIO_ACC_EVENT_NEW_CONNECTION,
			    net);

    basena_lock(nadata);
    basena_leave_cb_unlock(nadata);
}

static int
basena_child_event(struct gensio_acceptor *acceptor, int event,
		   void *data)
{
    struct basena_data *nadata = gensio_acc_get_user_data(acceptor);
    struct gensio_os_funcs *o = nadata->o;
    struct gensio_filter *filter;
    struct gensio_ll *ll;
    struct gensio *io;
    void *finish_data;
    int err;

    if (event != GENSIO_ACC_EVENT_NEW_CONNECTION)
	return ENOTSUP;

    io = data;

    err = nadata->acc_cbs->new_child(nadata->acc_data, &finish_data, &filter);
    if (err)
	goto out_err;

    ll = gensio_gensio_ll_alloc(o, io);
    if (!ll) {
	filter->ops->free(filter);
	goto out_nomem;
    }

    basena_lock(nadata);
    io = base_gensio_server_alloc(o, ll, filter, nadata->acceptor.type,
				  false, false,
				  basena_finish_server_open, nadata);
    if (io) {
	basena_in_cb(nadata);
	if (nadata->acc_cbs->finish_child)
	    nadata->acc_cbs->finish_child(nadata->acc_data, finish_data, io);
	basena_unlock(nadata);
    } else {
	basena_unlock(nadata);
	ll->ops->free(ll);
	filter->ops->free(filter);
	goto out_nomem;
    }
    return 0;

 out_nomem:
    err = ENOMEM;
 out_err:
    syslog(LOG_ERR, "Error allocating basena gensio: %s", strerror(err));

    return 0;
}

int
gensio_gensio_acceptor_alloc(const char *name,
			     struct gensio_os_funcs *o,
			     struct gensio_acceptor *child,
			     enum gensio_type type,
			     bool is_packet, bool is_reliable,
			     gensio_acceptor_event cb, void *user_data,
			     const struct gensio_gensio_acc_cbs *acc_cbs,
			     void *acc_data,
			     struct gensio_acceptor **acceptor)
{
    struct gensio_acceptor *acc;
    struct basena_data *nadata;

    nadata = o->zalloc(o, sizeof(*nadata));
    if (!nadata)
	return ENOMEM;

    nadata->name = gensio_strdup(o, name);
    if (!nadata->name)
	goto out_nomem;

    nadata->lock = o->alloc_lock(o);
    if (!nadata->lock)
	goto out_nomem;

    acc = &nadata->acceptor;
    acc->cb = cb;
    acc->user_data = user_data;
    acc->funcs = &gensio_acc_basena_funcs;
    acc->type = type;

    nadata->o = o;
    nadata->child = child;
    nadata->acc_cbs = acc_cbs;
    nadata->acc_data = acc_data;
    nadata->refcount = 1;

    gensio_acc_set_callback(child, basena_child_event, nadata);

    *acceptor = acc;

    return 0;

out_nomem:
    basena_finish_free(nadata);
    return ENOMEM;
}
