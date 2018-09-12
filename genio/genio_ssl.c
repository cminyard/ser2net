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
    child->funcs->ref(child);

    io = base_genio_alloc(o, ll, filter, GENIO_TYPE_SSL, cbs, user_data);
    if (!io) {
	ll->ops->free(ll);
	filter->ops->free(filter);
	return ENOMEM;
    }
    genio_free(child); /* Lose the ref we acquired. */

    *net = io;
    return 0;
}

struct sslna_data {
    unsigned int max_read_size;
    unsigned int max_write_size;

    struct genio_os_funcs *o;

    char *keyfile;
    char *certfile;
    char *CAfilepath;
};

static void
sslna_free(void *acc_data)
{
    struct sslna_data *nadata = acc_data;

    if (nadata->keyfile)
	nadata->o->free(nadata->o, nadata->keyfile);
    if (nadata->certfile)
	nadata->o->free(nadata->o, nadata->certfile);
    if (nadata->CAfilepath)
	nadata->o->free(nadata->o, nadata->CAfilepath);
    nadata->o->free(nadata->o, nadata);
}

int
sslna_connect_start(void *acc_data, struct genio *child, struct genio **rio)
{
    struct sslna_data *nadata = acc_data;
    struct genio_os_funcs *o = nadata->o;
    int err;
    struct genio *io = NULL;
    char *args[2] = {NULL, NULL};

    args[0] = o->zalloc(o, strlen(nadata->CAfilepath) + 4);
    if (!args[0])
	return ENOMEM;

    strcpy(args[0], "CA=");
    strcat(args[0], nadata->CAfilepath);

    err = ssl_genio_alloc(child, args, o, nadata->max_read_size,
			  NULL, NULL, &io);

    if (args[0])
	o->free(o, args[0]);

    return err;
}

static int
sslna_new_child(void *acc_data, struct genio_filter **filter)
{
    struct sslna_data *nadata = acc_data;
    int err;

    err = genio_ssl_server_filter_alloc(nadata->o,
					nadata->keyfile, nadata->certfile,
					nadata->CAfilepath,
					nadata->max_read_size,
					nadata->max_write_size,
					filter);
    return err;
}

static const struct genio_genio_acc_cbs genio_acc_ssl_funcs = {
    .connect_start = sslna_connect_start,
    .new_child = sslna_new_child,
    .free = sslna_free,
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
    struct sslna_data *nadata;
    const char *keyfile = NULL;
    const char *certfile = NULL;
    const char *CAfilepath = NULL;
    int err;
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

    nadata->o = o;
    nadata->max_write_size = max_write_size;
    nadata->max_read_size = max_read_size;

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

    err = genio_genio_acceptor_alloc(name, o, child, GENIO_TYPE_SSL,
				     cbs, user_data,
				     &genio_acc_ssl_funcs, nadata, acceptor);
    if (err)
	goto out_err;

    return 0;

 out_nomem:
    err = ENOMEM;
 out_err:
    sslna_free(nadata);
    return err;
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
