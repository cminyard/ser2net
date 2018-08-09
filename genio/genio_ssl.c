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

#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <assert.h>
#include <syslog.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

static void
genio_do_ssl_init(void *cb_data)
{
    SSL_library_init();
}

static struct genio_once genio_ssl_init_once;

static void
genio_ssl_initialize(struct genio_os_funcs *o)
{
    o->call_once(o, &genio_ssl_init_once, genio_do_ssl_init, NULL);
}

struct ssln_data {
    struct genio net;

    struct genio_os_funcs *o;

    struct genio_lock *lock;

    struct genio *child;

    SSL_CTX *ctx;
    SSL *ssl;
    BIO *ssl_bio;
    BIO *io_bio;

    bool in_open;
    void (*open_done)(struct genio *net, int err, void *open_data);
    void *open_data;

    bool in_free;
    bool closed;
    bool in_close;
    bool finish_close_on_write;

    void (*close_done)(struct genio *net, void *close_data);
    void *close_data;

    bool read_enabled;
    bool in_read;
    bool deferred_read;
    unsigned char *read_data;
    unsigned int data_pos;
    unsigned int data_pending_len;
    unsigned int max_read_size;

    bool xmit_enabled;

    unsigned char xmit_buf[1024];
    unsigned int xmit_buf_curr;
    unsigned int xmit_buf_len;
    int saved_xmit_err;

    /*
     * Used to run read callbacks from the selector to avoid running
     * it directly from user calls.
     */
    bool deferred_op_pending;
    struct genio_runner *deferred_op_runner;

    struct stel_req *reqs;
};

#define mygenio_to_ssln(v) container_of(v, struct ssln_data, net)

static void
ssln_lock(struct ssln_data *ndata)
{
    ndata->o->lock(ndata->lock);
}

static void
ssln_unlock(struct ssln_data *ndata)
{
    ndata->o->unlock(ndata->lock);
}

static int
ssln_write(struct genio *net, unsigned int *rcount,
	   const void *buf, unsigned int buflen)
{
    struct ssln_data *ndata = mygenio_to_ssln(net);
    int err = 0;

    ssln_lock(ndata);
    if (ndata->closed || ndata->in_open) {
	err = EBADF;
	goto out_unlock;
    }
    if (ndata->saved_xmit_err) {
	err = ndata->saved_xmit_err;
	ndata->saved_xmit_err = 0;
	goto out_unlock;
    }

    err = SSL_write(ndata->ssl, buf, buflen);
    if (err < 0) {
	err = ECOMM; /* FIXME */
    } else {
	*rcount = err;
	err = 0;
    }

    if (!ndata->xmit_buf_len) {
	int rdlen = BIO_read(ndata->io_bio, ndata->xmit_buf,
			     sizeof(ndata->xmit_buf));

	if (rdlen > 0) {
	    ndata->xmit_buf_len = rdlen;
	    ndata->xmit_buf_curr = 0;
	    genio_set_write_callback_enable(ndata->child, true);
	}
    }
 out_unlock:
    ssln_unlock(ndata);
    return err;
}

static int
ssln_raddr_to_str(struct genio *net, int *pos,
		  char *buf, unsigned int buflen)
{
    struct ssln_data *ndata = mygenio_to_ssln(net);

    return genio_raddr_to_str(ndata->child, pos, buf, buflen);
}

static socklen_t
ssln_get_raddr(struct genio *net,
	       struct sockaddr *addr, socklen_t addrlen)
{
    struct ssln_data *ndata = mygenio_to_ssln(net);

    return genio_get_raddr(ndata->child, addr, addrlen);
}

static void
ssln_ssl_cleanup(struct ssln_data *ndata)
{
    if (ndata->ssl)
	SSL_free(ndata->ssl);
    ndata->ssl = NULL;
    ndata->ssl_bio = NULL;
    ndata->io_bio = NULL;
}

static int
ssln_ssl_setup(struct ssln_data *ndata)
{
    int success;

    ndata->ssl = SSL_new(ndata->ctx);
    if (!ndata->ssl)
	return ENOMEM;

    success = BIO_new_bio_pair(&ndata->ssl_bio, ndata->max_read_size,
			       &ndata->io_bio, ndata->max_read_size);
    if (!success) {
	SSL_free(ndata->ssl);
	ndata->ssl = NULL;
	return ENOMEM;
    }

    SSL_set_bio(ndata->ssl, ndata->ssl_bio, ndata->ssl_bio);
    return 0;
}

static void
ssln_finish_free(struct ssln_data *ndata)
{
    if (ndata->ssl)
	SSL_free(ndata->ssl);
    if (ndata->ctx)
	SSL_CTX_free(ndata->ctx);
    if (ndata->lock)
	ndata->o->free_lock(ndata->lock);
    if (ndata->read_data)
	ndata->o->free(ndata->o, ndata->read_data);
    if (ndata->deferred_op_runner)
	ndata->o->free_runner(ndata->deferred_op_runner);
    ndata->o->free(ndata->o, ndata);
}

static void
ssln_deferred_op(struct genio_runner *runner, void *cbdata)
{
    struct ssln_data *ndata = cbdata;
    struct genio *net = &ndata->net;
    unsigned int count;
    bool in_read;

    ssln_lock(ndata);
 restart:
    if (ndata->deferred_read) {
	in_read = ndata->in_read;
	ndata->deferred_read = false;
    }

    if (in_read) {
    process_more:
	if (!ndata->data_pending_len) {
	    int rlen = SSL_read(ndata->ssl, ndata->read_data,
				ndata->max_read_size);

	    if (rlen > 0)
		ndata->data_pending_len = rlen;
	}
	if (ndata->data_pending_len) {
	    ssln_unlock(ndata);
	    count = net->cbs->read_callback(net, 0,
					    ndata->read_data + ndata->data_pos,
					    ndata->data_pending_len, 0);
	    ssln_lock(ndata);
	    if (count >= ndata->data_pending_len) {
		ndata->data_pending_len = 0;
		ndata->data_pos = 0;
		goto process_more;
	    } else {
		ndata->read_enabled = false;
		ndata->data_pending_len -= count;
		ndata->data_pos += count;
	    }
	}
	ndata->in_read = false;


	if (ndata->read_enabled || BIO_should_read(ndata->io_bio))
	    genio_set_read_callback_enable(ndata->child, true);
    }

    if (ndata->deferred_read)
	/* Something was added, process it. */
	goto restart;

    ndata->deferred_op_pending = false;
    ssln_unlock(ndata);
}

static void
ssln_genio_close_done(struct genio *net, void *close_data)
{
    struct ssln_data *ndata = genio_get_user_data(net);

    ssln_lock(ndata);
    ndata->in_open = false;
    ndata->in_close = false;
    ssln_ssl_cleanup(ndata);
    ssln_unlock(ndata);

    if (ndata->close_done)
	ndata->close_done(&ndata->net, ndata->close_data);

    ssln_lock(ndata);
    if (ndata->in_free) {
	ssln_unlock(ndata);
	ssln_finish_free(ndata);
    } else {
	ssln_unlock(ndata);
    }
}

static void
ssln_finish_open(struct ssln_data *ndata, int err)
{
    ssln_lock(ndata);
    ndata->closed = false;
    if (err) {
	ndata->closed = true;
	ssln_ssl_cleanup(ndata);
    } else {
	long verify_err = SSL_get_verify_result(ndata->ssl);

	if (verify_err != X509_V_OK)
	    err = EKEYREJECTED;
    }
    ssln_unlock(ndata);

    if (ndata->open_done)
	ndata->open_done(&ndata->net, err, ndata->open_data);

    ssln_lock(ndata);
    ndata->in_open = false;
    ssln_unlock(ndata);
}

static void
ssln_genio_close_on_open_fail(struct genio *net, void *close_data)
{
    struct ssln_data *ndata = genio_get_user_data(net);

    ssln_finish_open(ndata, ECOMM);
}

static void
ssln_try_connect(struct ssln_data *ndata)
{
    int success;

    genio_set_write_callback_enable(ndata->child, false);
    genio_set_read_callback_enable(ndata->child, false);

    if (ndata->net.is_client)
	success = SSL_connect(ndata->ssl);
    else
	success = SSL_accept(ndata->ssl);

    if (!success) {
    failure:
        ERR_print_errors_fp(stderr);
	genio_close(ndata->child, ssln_genio_close_on_open_fail, NULL);
    } else if (success == 1) {
	ssln_unlock(ndata);
	ssln_finish_open(ndata, 0);
	ssln_lock(ndata);
    } else {
	int err = SSL_get_error(ndata->ssl, success);

	switch (err) {
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
	    break;

	default:
	    goto failure;
	}
    }
}

static void
ssln_set_child_enables(struct ssln_data *ndata)
{
    if (BIO_pending(ndata->io_bio))
	genio_set_write_callback_enable(ndata->child, true);
    if (ndata->read_enabled || ndata->in_close || ndata->in_open)
	genio_set_read_callback_enable(ndata->child, true);
}

static void
ssln_sub_open_done(struct genio *net, int err, void *cb_data)
{
    struct ssln_data *ndata = cb_data;

    if (err) {
	ssln_finish_open(ndata, err);
	return;
    }

    ssln_lock(ndata);
    ssln_try_connect(ndata);
    ssln_set_child_enables(ndata);
    ssln_unlock(ndata);
}

static int
ssln_open(struct genio *net, void (*open_done)(struct genio *net,
					       int err,
					       void *open_data),
	  void *open_data)
{
    struct ssln_data *ndata = mygenio_to_ssln(net);
    int err = EBUSY;

    ssln_lock(ndata);
    if (ndata->closed && !ndata->in_close) {
	err = ssln_ssl_setup(ndata);
	if (err)
	    goto out_err;
	SSL_set_connect_state(ndata->ssl);

	ndata->open_done = open_done;
	ndata->open_data = open_data;
	err = genio_open(ndata->child, ssln_sub_open_done, ndata);
	if (err)
	    goto out_err;

	ndata->in_open = true;
	ndata->closed = false;
    }
    ssln_unlock(ndata);

    return 0;

 out_err:
    ssln_unlock(ndata);
    ssln_ssl_cleanup(ndata);
    return err;
}

static void
ssln_try_close(struct ssln_data *ndata)
{
    int success;

    genio_set_write_callback_enable(ndata->child, false);
    genio_set_read_callback_enable(ndata->child, false);

    if (ndata->finish_close_on_write) {
	ndata->finish_close_on_write = false;
	genio_close(ndata->child, ssln_genio_close_done, NULL);
	return;
    }

    success = SSL_shutdown(ndata->ssl);
    ssln_unlock(ndata);
    if (success == 1 || success < 0) {
	if (BIO_pending(ndata->io_bio))
	    ndata->finish_close_on_write = true;
	else
	    genio_close(ndata->child, ssln_genio_close_done, NULL);
    }
}

static void
__ssln_close(struct ssln_data *ndata, void (*close_done)(struct genio *net,
							 void *close_data),
	     void *close_data)
{
    ndata->close_done = close_done;
    ndata->close_data = close_data;
    ndata->closed = true;
    ndata->in_close = true;
    ssln_try_close(ndata);
    ssln_set_child_enables(ndata);
}

static int
ssln_close(struct genio *net, void (*close_done)(struct genio *net,
						 void *close_data),
	   void *close_data)
{
    struct ssln_data *ndata = mygenio_to_ssln(net);
    int err = 0;

    ssln_lock(ndata);
    if (ndata->closed || ndata->in_close) {
	ssln_unlock(ndata);
	err = EBUSY;
    } else {
	__ssln_close(ndata, close_done, close_data); /* Releases lock. */
    }

    return err;
}

static void
ssln_free(struct genio *net)
{
    struct ssln_data *ndata = mygenio_to_ssln(net);

    ssln_lock(ndata);
    ndata->in_free = true;
    if (ndata->in_close) {
	ndata->close_done = NULL;
	ssln_unlock(ndata);
    } else if (ndata->closed) {
	ssln_unlock(ndata);
	ssln_finish_free(ndata);
    } else {
	__ssln_close(ndata, NULL, NULL); /* Releases lock */
    }
}

static void
ssln_set_read_callback_enable(struct genio *net, bool enabled)
{
    struct ssln_data *ndata = mygenio_to_ssln(net);
    char buf[1];

    ssln_lock(ndata);
    if (ndata->closed)
	goto out_unlock;
    ndata->read_enabled = enabled;
    if (ndata->in_read || ndata->in_open ||
			(ndata->data_pending_len && !enabled)) {
	/* Nothing to do, let the read/open handling wake things up. */
    } else if (ndata->data_pending_len || SSL_peek(ndata->ssl, buf, 1) > 0) {
	/*
	 * Note that SSL_pending() was not working, so SSL_peek was used.
	 * openssl version 1.0.2g.
	 */
	ndata->deferred_read = true;
	ndata->in_read = true;
	if (!ndata->deferred_op_pending) {
	    /* Call the read from the selector to avoid lock nesting issues. */
	    ndata->deferred_op_pending = true;
	    ndata->o->run(ndata->deferred_op_runner);
	}
    } else {
	genio_set_read_callback_enable(ndata->child, enabled);
    }
 out_unlock:
    ssln_unlock(ndata);
}

static void
ssln_set_write_callback_enable(struct genio *net, bool enabled)
{
    struct ssln_data *ndata = mygenio_to_ssln(net);

    ssln_lock(ndata);
    if (ndata->closed)
	goto out_unlock;
    if (ndata->xmit_enabled != enabled) {
	ndata->xmit_enabled = enabled;
	if ((enabled || !ndata->xmit_buf_len) && !ndata->in_open)
	    /* Only disable if we don't have data pending. */
	    genio_set_write_callback_enable(ndata->child, enabled);
    }
 out_unlock:
    ssln_unlock(ndata);
}

static const struct genio_functions ssln_net_funcs = {
    .write = ssln_write,
    .raddr_to_str = ssln_raddr_to_str,
    .get_raddr = ssln_get_raddr,
    .open = ssln_open,
    .close = ssln_close,
    .free = ssln_free,
    .set_read_callback_enable = ssln_set_read_callback_enable,
    .set_write_callback_enable = ssln_set_write_callback_enable
};

static unsigned int
ssln_genio_read(struct genio *net, int readerr,
		unsigned char *ibuf, unsigned int buflen,
		unsigned int flags)
{
    struct ssln_data *ndata = genio_get_user_data(net);
    struct genio *mynet = &ndata->net;
    unsigned char *buf = ibuf;
    unsigned int count = 0;

    ssln_lock(ndata);
    if (readerr) {
	/* Do this here so the user can modify it. */
	ndata->read_enabled = false;
	ndata->data_pending_len = 0;
	if (ndata->in_open) {
	    genio_close(ndata->child, ssln_genio_close_on_open_fail, NULL);
	} else if (mynet->cbs && !ndata->in_open) {
	    ndata->closed = true;
	    SSL_clear(ndata->ssl);
	    ssln_unlock(ndata);
	    mynet->cbs->read_callback(mynet, readerr, NULL, 0, 0);
	    ssln_lock(ndata);
	} else {
	    __ssln_close(ndata, NULL, NULL);
	}
	goto out_finish;
    }

    genio_set_read_callback_enable(ndata->child, false);

    ndata->in_read = true;
 process_more:
    if (buflen > 0) {
	unsigned int wrlen = BIO_write(ndata->io_bio, buf, buflen);

	/* FIXME - do we need error handling? */
	if (wrlen < 0)
	    wrlen = 0;
	buf += wrlen;
	buflen -= wrlen;

	if (ndata->in_open)
	    ssln_try_connect(ndata);
	if (ndata->in_close)
	    ssln_try_close(ndata);
    }

    if (!ndata->closed && !ndata->in_open &&
		ndata->read_enabled && !ndata->data_pending_len) {
	int rlen;

	rlen = SSL_read(ndata->ssl, ndata->read_data, ndata->max_read_size);
	if (rlen > 0)
	    ndata->data_pending_len = rlen;
	if (ndata->data_pending_len) {
	    ssln_unlock(ndata);
	    count = mynet->cbs->read_callback(&ndata->net, 0,
					      ndata->read_data,
					      ndata->data_pending_len, 0);
	    ssln_lock(ndata);
	    if (count == ndata->data_pending_len) {
		ndata->data_pending_len = 0;
		goto process_more;
	    } else {
		ndata->read_enabled = false;
		ndata->data_pending_len -= count;
		ndata->data_pos = count;
	    }
	}
    }
    ndata->in_read = false;

 out_finish:
    ssln_set_child_enables(ndata);
    ssln_unlock(ndata);

    return buf - ibuf;
}

void
ssln_genio_write_ready(struct genio *net)
{
    struct ssln_data *ndata = genio_get_user_data(net);
    bool do_cb = true;

    ssln_lock(ndata);
 restart:
    if (ndata->xmit_buf_len) {
	int err;
	unsigned int written;

	err = genio_write(net, &written, ndata->xmit_buf + ndata->xmit_buf_curr,
			  ndata->xmit_buf_len - ndata->xmit_buf_curr);
	if (err) {
	    ndata->saved_xmit_err = err;
	    ndata->xmit_buf_len = 0;
	} else {
	    ndata->xmit_buf_curr += written;
	    if (ndata->xmit_buf_curr == ndata->xmit_buf_len)
		ndata->xmit_buf_len = 0;
	    else
		/* Still more data to write. */
		do_cb = false;
	}
    }
    if (ndata->xmit_buf_len == 0) {
	int rdlen = BIO_read(ndata->io_bio, ndata->xmit_buf,
			     sizeof(ndata->xmit_buf));

	/* FIXME - error handling? */
	if (rdlen > 0) {
	    ndata->xmit_buf_len = rdlen;
	    ndata->xmit_buf_curr = 0;
	    goto restart;
	}
    }

    if (ndata->in_open)
	ssln_try_connect(ndata);
    if (ndata->in_close)
	ssln_try_close(ndata);
    if (!ndata->in_open && do_cb) {
	if (!ndata->xmit_enabled) {
	    genio_set_write_callback_enable(ndata->child, false);
	} else {
	    ssln_unlock(ndata);
	    ndata->net.cbs->write_callback(&ndata->net);
	    ssln_lock(ndata);
	}
    }

    if (ndata->xmit_buf_len)
	genio_set_write_callback_enable(ndata->child, true);
    ssln_set_child_enables(ndata);
    ssln_unlock(ndata);
}

void
ssln_genio_urgent(struct genio *net)
{
}

static const struct genio_callbacks ssln_genio_callbacks = {
    .read_callback = ssln_genio_read,
    .write_callback = ssln_genio_write_ready,
    .urgent_callback = ssln_genio_urgent,
};

static struct ssln_data *
ssln_alloc(struct genio *child, struct genio_os_funcs *o,
	   SSL_CTX *ctx,
	   unsigned int max_read_size,
	   const struct genio_callbacks *cbs, void *user_data)
{
    struct ssln_data *ndata = o->zalloc(o, sizeof(*ndata));

    if (!ndata)
	return NULL;

    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);

    ndata->max_read_size = max_read_size;
    ndata->o = o;

    ndata->lock = o->alloc_lock(o);
    if (!ndata->lock)
	goto out_nomem;

    ndata->read_data = o->zalloc(o, max_read_size);
    if (!ndata->read_data)
	goto out_nomem;

    ndata->deferred_op_runner = o->alloc_runner(o, ssln_deferred_op, ndata);
    if (!ndata->deferred_op_runner)
	goto out_nomem;

    ndata->ctx = ctx;
    ndata->child = child;
    ndata->net.user_data = user_data;
    ndata->net.cbs = cbs;
    ndata->net.funcs = &ssln_net_funcs;
    ndata->net.type = GENIO_TYPE_SSL;
    genio_set_callbacks(child, &ssln_genio_callbacks, ndata);
    ndata->closed = true;

    return ndata;

out_nomem:
    ssln_finish_free(ndata);
    return NULL;
}

int
ssl_genio_alloc(struct genio *child, char *args[],
		struct genio_os_funcs *o,
		unsigned int max_read_size,
		const struct genio_callbacks *cbs, void *user_data,
		struct genio **net)
{
    struct ssln_data *ndata;
    const char *CAfilepath = NULL;
    const char *CAfile = NULL, *CApath = NULL;
    SSL_CTX *ctx;
    int success;
    unsigned int i;

    genio_ssl_initialize(o);

    for (i = 0; args[i]; i++) {
	if (genio_check_keyvalue(args[i], "CA", &CAfilepath))
	    continue;
	return EINVAL;
    }

    if (!CAfilepath)
	return EINVAL;

    if (CAfilepath[strlen(CAfilepath) - 1] == '/')
	CApath = CAfilepath;
    else
	CAfile = CAfilepath;

    ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ctx)
	return ENOMEM;

    success = SSL_CTX_load_verify_locations(ctx, CAfile, CApath);
    if (!success) {
        ERR_print_errors_fp(stderr);
	SSL_CTX_free(ctx);
	return ENOMEM;
    }

    ndata = ssln_alloc(child, o, ctx, max_read_size, cbs, user_data);
    if (ndata) {
	ndata->net.is_client = true;
	*net = &ndata->net;
    } else {
	SSL_CTX_free(ctx);
	return ENOMEM;
    }
    return 0;
}

struct sslna_data {
    struct genio_acceptor acceptor;

    char *name;
    unsigned int max_read_size;

    struct genio_os_funcs *o;

    struct genio_lock *lock;

    struct genio_acceptor *child;

    char *keyfile;
    char *certfile;
    char *CAfilepath;

    unsigned int refcount;

    bool enabled;
    bool in_shutdown;
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
    void (*shutdown_done)(struct genio_acceptor *acceptor,
			  void *shutdown_data);

    sslna_lock(nadata);
    nadata->in_shutdown = false;
    shutdown_done = nadata->shutdown_done;
    shutdown_data = nadata->shutdown_data;
    nadata->shutdown_done = NULL;
    sslna_ref(nadata);
    sslna_unlock(nadata);

    if (shutdown_done)
	shutdown_done(&nadata->acceptor, shutdown_data);

    sslna_lock(nadata);
    sslna_deref_and_unlock(nadata);
}

static int
i_sslna_shutdown(struct sslna_data *nadata,
		 void (*shutdown_done)(struct genio_acceptor *acceptor,
				       void *shutdown_data),
		 void *shutdown_data)
{
    int rv;

    nadata->shutdown_done = shutdown_done;
    nadata->shutdown_data = shutdown_data;

    rv = genio_acc_shutdown(nadata->child, sslna_child_shutdown, nadata);
    if (!rv) {
	nadata->enabled = false;
	nadata->in_shutdown = true;
    }

    return rv;
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
    if (nadata->enabled)
	rv = i_sslna_shutdown(nadata, shutdown_done, shutdown_data);
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

static void
sslna_child_connect_done(struct genio *net, int err, void *cb_data)
{
    struct sslna_data *nadata = cb_data;
    struct ssln_data *ndata;

    sslna_lock(nadata);
    ndata = genio_get_user_data(net); 
   if (!err)
	err = genio_open(&ndata->net, ndata->open_done, ndata->open_data);
    sslna_unlock(nadata);

    if (err) {
	genio_free(net);
	ndata->open_done(&ndata->net, err, ndata->open_data);
	ssln_finish_free(ndata);
    }
}

int
sslna_connect(struct genio_acceptor *acceptor, void *addr,
	      void (*connect_done)(struct genio *net, int err,
				   void *cb_data),
	      void *cb_data, struct genio **new_net)
{
    struct sslna_data *nadata = acc_to_nadata(acceptor);
    struct genio *net = NULL;
    struct ssln_data *ndata;
    int err;
    char *args[2] = {NULL, NULL};

    args[0] = malloc(strlen(nadata->CAfilepath) + 4);
    if (!args[0])
	return ENOMEM;
    strcpy(args[0], "CA=");
    strcat(args[0], nadata->CAfilepath);

    err = genio_acc_connect(nadata->child, addr, sslna_child_connect_done,
			    nadata, &net);
    if (err)
	goto out_err;

    err = ssl_genio_alloc(net, args, nadata->o, nadata->max_read_size,
			  NULL, NULL, new_net);
    if (err)
	goto out_err;

    ndata = mygenio_to_ssln(*new_net);
    genio_set_user_data(net, ndata);
    ndata->open_done = connect_done;
    ndata->open_data = cb_data;

    return 0;

 out_err:
    if (net)
	genio_free(net);
    if (args[0])
	free(args[0]);
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

    /* FIXME - need to make sure nadata stays around for this. */
    if (!err)
	nadata->acceptor.cbs->new_connection(&nadata->acceptor, net);
}

static void
sslna_new_child_connection(struct genio_acceptor *acceptor, struct genio *net)
{
    struct sslna_data *nadata = genio_acc_get_user_data(acceptor);
    struct ssln_data *ndata;
    SSL_CTX *ctx = NULL;

    ctx = SSL_CTX_new(SSLv23_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
	goto err;
    }

    if (nadata->CAfilepath) {
	char *CAfilepath = nadata->CAfilepath;
	char *CAfile = NULL, *CApath = NULL;

	if (CAfilepath[strlen(CAfilepath) - 1] == '/')
	    CApath = CAfilepath;
	else
	    CAfile = CAfilepath;
	if (!SSL_CTX_load_verify_locations(ctx, CAfile, CApath))
	    goto err;
    }

    if (!SSL_CTX_use_certificate_chain_file(ctx, nadata->certfile))
	goto err;
    if (!SSL_CTX_use_PrivateKey_file(ctx, nadata->keyfile, SSL_FILETYPE_PEM))
        goto err;
    if (!SSL_CTX_check_private_key(ctx))
        goto err;

    ndata = ssln_alloc(net, nadata->o, ctx, nadata->max_read_size, NULL, NULL);
    if (ndata) {
	int err;

	ctx = NULL; /* Part of ndata now. */
	err = ssln_ssl_setup(ndata);
	if (err) {
	    ssln_finish_free(ndata);
	    goto err;
	}
	SSL_set_accept_state(ndata->ssl);
	ndata->in_open = true;
	ndata->closed = false;
	ndata->open_done = sslna_finish_server_open;
	ndata->open_data = nadata;
	ssln_try_connect(ndata);
	ssln_set_child_enables(ndata);
    } else {
	syslog(LOG_ERR, "Error allocating ssl genio for %s", nadata->name);
	goto err_nomem;
    }
    return;
    
err:
    syslog(LOG_ERR, "Error setting up ssl for %s", nadata->name);
err_nomem:
    genio_free(net);
    if (ctx)
	SSL_CTX_free(ctx);
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

    genio_ssl_initialize(o);

    for (i = 0; args[i]; i++) {
	if (genio_check_keyvalue(args[i], "CA", &CAfilepath))
	    continue;
	if (genio_check_keyvalue(args[i], "key", &keyfile))
	    continue;
	if (genio_check_keyvalue(args[i], "cert", &certfile))
	    continue;
	return EINVAL;
    }

    if (!CAfilepath || !keyfile)
	return EINVAL;

    nadata = o->zalloc(o, sizeof(*nadata));
    if (!nadata)
	return ENOMEM;

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
