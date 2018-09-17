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

#include <errno.h>

#include <gensio/gensio_internal.h>

#ifdef HAVE_OPENSSL

#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <assert.h>
#include <syslog.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <gensio/gensio_base.h>

int
ssl_gensio_alloc(struct gensio *child, char *args[],
		 struct gensio_os_funcs *o,
		 const struct gensio_callbacks *cbs, void *user_data,
		 struct gensio **net)
{
    int err;
    struct gensio_filter *filter;
    struct gensio_ll *ll;
    struct gensio *io;

    err = gensio_ssl_filter_alloc(o, args, &filter);
    if (err)
	return err;

    ll = gensio_gensio_ll_alloc(o, child);
    if (!ll) {
	filter->ops->free(filter);
	return ENOMEM;
    }
    child->funcs->ref(child);

    io = base_gensio_alloc(o, ll, filter, GENSIO_TYPE_SSL, cbs, user_data);
    if (!io) {
	ll->ops->free(ll);
	filter->ops->free(filter);
	return ENOMEM;
    }
    gensio_free(child); /* Lose the ref we acquired. */

    *net = io;
    return 0;
}

struct sslna_data {
    unsigned int max_read_size;
    unsigned int max_write_size;

    struct gensio_os_funcs *o;

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
sslna_connect_start(void *acc_data, struct gensio *child, struct gensio **rio)
{
    struct sslna_data *nadata = acc_data;
    struct gensio_os_funcs *o = nadata->o;
    int err;
    struct gensio *io = NULL;
    char *args[4] = {NULL, NULL, NULL};
    char buf1[50], buf2[50];
    int i;

    args[0] = o->zalloc(o, strlen(nadata->CAfilepath) + 4);
    if (!args[0])
	return ENOMEM;

    strcpy(args[0], "CA=");
    strcat(args[0], nadata->CAfilepath);

    i = 1;
    if (nadata->max_read_size != SSL3_RT_MAX_PLAIN_LENGTH) {
	snprintf(buf1, sizeof(buf1), "readbuf=%d", nadata->max_read_size);
	args[i++] = buf1;
    }
    if (nadata->max_write_size != SSL3_RT_MAX_PLAIN_LENGTH) {
	snprintf(buf2, sizeof(buf2), "writebuf=%d", nadata->max_write_size);
	args[i++] = buf2;
    }

    err = ssl_gensio_alloc(child, args, o, NULL, NULL, &io);

    if (args[0])
	o->free(o, args[0]);

    return err;
}

static int
sslna_new_child(void *acc_data, void **finish_data,
		struct gensio_filter **filter)
{
    struct sslna_data *nadata = acc_data;
    int err;

    err = gensio_ssl_server_filter_alloc(nadata->o,
					 nadata->keyfile, nadata->certfile,
					 nadata->CAfilepath,
					 nadata->max_read_size,
					 nadata->max_write_size,
					 filter);
    return err;
}

static const struct gensio_gensio_acc_cbs gensio_acc_ssl_funcs = {
    .connect_start = sslna_connect_start,
    .new_child = sslna_new_child,
    .free = sslna_free,
};

int
ssl_gensio_acceptor_alloc(const char *name,
			  char *args[],
			  struct gensio_os_funcs *o,
			  struct gensio_acceptor *child,
			  const struct gensio_acceptor_callbacks *cbs,
			  void *user_data,
			  struct gensio_acceptor **acceptor)
{
    struct sslna_data *nadata;
    const char *keyfile = NULL;
    const char *certfile = NULL;
    const char *CAfilepath = NULL;
    int err;
    unsigned int i;
    unsigned int max_write_size = SSL3_RT_MAX_PLAIN_LENGTH;
    unsigned int max_read_size = SSL3_RT_MAX_PLAIN_LENGTH;

    for (i = 0; args[i]; i++) {
	if (gensio_check_keyvalue(args[i], "CA", &CAfilepath))
	    continue;
	if (gensio_check_keyvalue(args[i], "key", &keyfile))
	    continue;
	if (gensio_check_keyvalue(args[i], "cert", &certfile))
	    continue;
	if (gensio_check_keyuint(args[i], "writebuf", &max_write_size) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "readbuf", &max_read_size) > 0)
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

    nadata->keyfile = gensio_strdup(o, keyfile);
    if (!nadata->keyfile)
	goto out_nomem;

    if (!certfile)
	certfile = keyfile;

    nadata->certfile = gensio_strdup(o, certfile);
    if (!nadata->certfile)
	goto out_nomem;

    nadata->CAfilepath = gensio_strdup(o, CAfilepath);
    if (!nadata->CAfilepath)
	goto out_nomem;

    err = gensio_gensio_acceptor_alloc(name, o, child, GENSIO_TYPE_SSL,
				       cbs, user_data,
				       &gensio_acc_ssl_funcs, nadata, acceptor);
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
ssl_gensio_alloc(struct gensio *child, char *args[],
		 struct gensio_os_funcs *o,
		 const struct gensio_callbacks *cbs, void *user_data,
		 struct gensio **net)
{
    return ENOTSUP;
}

int
ssl_gensio_acceptor_alloc(const char *name,
			  char *args[],
			  struct gensio_os_funcs *o,
			  struct gensio_acceptor *child,
			  unsigned int max_read_size,
			  const struct gensio_acceptor_callbacks *cbs,
			  void *user_data,
			  struct gensio_acceptor **acceptor)
{
    return ENOTSUP;
}

#endif /* HAVE_OPENSSL */
