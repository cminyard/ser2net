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

#include <gensio/gensio_class.h>
#include <gensio/gensio_acc_gensio.h>
#include <gensio/gensio_ll_gensio.h>

struct basena_data {
    struct gensio_accepter *acc;

    struct gensio_os_funcs *o;

    struct gensio_lock *lock;

    struct gensio_accepter *child;

    gensio_gensio_acc_cb acc_cb;
    void *acc_data;

    unsigned int refcount;
    unsigned int in_cb_count;

    bool enabled;
    bool in_shutdown;
    bool call_shutdown_done;
    void (*shutdown_done)(struct gensio_accepter *accepter,
			  void *shutdown_data);
    void *shutdown_data;
};

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
    if (nadata->acc_cb)
	nadata->acc_cb(nadata->acc_data, GENSIO_GENSIO_ACC_FREE, NULL, NULL);
    if (nadata->acc)
	gensio_acc_data_free(nadata->acc);
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
    void (*shutdown_done)(struct gensio_accepter *accepter,
			  void *shutdown_data);

    nadata->in_shutdown = false;
    shutdown_done = nadata->shutdown_done;
    shutdown_data = nadata->shutdown_data;
    nadata->shutdown_done = NULL;
    basena_unlock(nadata);

    if (shutdown_done)
	shutdown_done(nadata->acc, shutdown_data);

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
basena_startup(struct gensio_accepter *accepter)
{
    struct basena_data *nadata = gensio_acc_get_gensio_data(accepter);
    int err;

    basena_lock(nadata);
    err = gensio_acc_startup(nadata->child);
    if (!err)
	nadata->enabled = true;
    basena_unlock(nadata);

    return err;
}

static void
basena_child_shutdown(struct gensio_accepter *accepter,
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
basena_shutdown(struct gensio_accepter *accepter,
	       void (*shutdown_done)(struct gensio_accepter *accepter,
				     void *shutdown_data),
	       void *shutdown_data)
{
    struct basena_data *nadata = gensio_acc_get_gensio_data(accepter);
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
basena_set_accept_callback_enable(struct gensio_accepter *accepter,
				  bool enabled)
{
    struct basena_data *nadata = gensio_acc_get_gensio_data(accepter);

    gensio_acc_set_accept_callback_enable(nadata->child, enabled);
}

static void
basena_free(struct gensio_accepter *accepter)
{
    struct basena_data *nadata = gensio_acc_get_gensio_data(accepter);

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
basena_connect(struct gensio_accepter *accepter, void *addr,
	       void (*connect_done)(struct gensio *net, int err, void *cb_data),
	       void *cb_data, struct gensio **new_net)
{
    struct basena_data *nadata = gensio_acc_get_gensio_data(accepter);
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

    err = nadata->acc_cb(nadata->acc_data, GENSIO_GENSIO_ACC_CONNECT_START,
			 child, &cdata->io);
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

static int
gensio_acc_base_func(struct gensio_accepter *acc, int func, int val,
		    void *addr, void *done, void *data,
		    void *ret)
{
    switch (func) {
    case GENSIO_ACC_FUNC_STARTUP:
	return basena_startup(acc);

    case GENSIO_ACC_FUNC_SHUTDOWN:
	return basena_shutdown(acc, done, data);

    case GENSIO_ACC_FUNC_SET_ACCEPT_CALLBACK:
	basena_set_accept_callback_enable(acc, val);
	return 0;

    case GENSIO_ACC_FUNC_FREE:
	basena_free(acc);
	return 0;

    case GENSIO_ACC_FUNC_CONNECT:
	return basena_connect(acc, addr, done, data, ret);

    default:
	return ENOTSUP;
    }
}

static void
basena_finish_server_open(struct gensio *net, int err, void *cb_data)
{
    struct basena_data *nadata = cb_data;

    if (err)
	gensio_free(net);
    else
	gensio_acc_cb(nadata->acc, GENSIO_ACC_EVENT_NEW_CONNECTION, net);

    basena_lock(nadata);
    basena_leave_cb_unlock(nadata);
}

static int
basena_child_event(struct gensio_accepter *accepter, int event,
		   void *data)
{
    struct basena_data *nadata = gensio_acc_get_user_data(accepter);
    struct gensio_os_funcs *o = nadata->o;
    struct gensio_filter *filter;
    struct gensio_ll *ll;
    struct gensio *io;
    void *finish_data;
    int err;

    if (event == GENSIO_ACC_EVENT_LOG) {
	gensio_acc_cb(nadata->acc, event, data);
	return 0;
    }

    if (event != GENSIO_ACC_EVENT_NEW_CONNECTION)
	return ENOTSUP;

    io = data;

    err = nadata->acc_cb(nadata->acc_data, GENSIO_GENSIO_ACC_NEW_CHILD,
			 &finish_data, &filter);
    if (err)
	goto out_err;

    ll = gensio_gensio_ll_alloc(o, io);
    if (!ll) {
	gensio_filter_free(filter);
	goto out_nomem;
    }

    basena_lock(nadata);
    io = base_gensio_server_alloc(o, ll, filter,
				  gensio_acc_get_type(nadata->acc, 0),
				  basena_finish_server_open, nadata);
    if (io) {
	basena_in_cb(nadata);
	err = nadata->acc_cb(nadata->acc_data, GENSIO_GENSIO_ACC_FINISH_PARENT,
			     finish_data, io);
	if (err && err != ENOTSUP) {
	    basena_unlock(nadata);
	    gensio_free(io);
	    gensio_ll_free(ll);
	    gensio_filter_free(filter);
	    goto out_err;
	}
	basena_unlock(nadata);
    } else {
	basena_unlock(nadata);
	gensio_ll_free(ll);
	gensio_filter_free(filter);
	goto out_nomem;
    }
    return 0;

 out_nomem:
    err = ENOMEM;
 out_err:
    gensio_acc_log(nadata->acc, GENSIO_LOG_ERR,
		   "Error allocating basena gensio: %s", strerror(err));
    return 0;
}

int
gensio_gensio_accepter_alloc(struct gensio_accepter *child,
			     struct gensio_os_funcs *o,
			     const char *typename,
			     gensio_accepter_event cb, void *user_data,
			     gensio_gensio_acc_cb acc_cb,
			     void *acc_data,
			     struct gensio_accepter **accepter)
{
    struct basena_data *nadata;

    nadata = o->zalloc(o, sizeof(*nadata));
    if (!nadata)
	return ENOMEM;

    nadata->lock = o->alloc_lock(o);
    if (!nadata->lock)
	goto out_nomem;

    nadata->acc = gensio_acc_data_alloc(o, cb, user_data, gensio_acc_base_func,
					child, typename, nadata);
    if (!nadata->acc)
	goto out_nomem;

    nadata->o = o;
    nadata->child = child;
    nadata->acc_cb = acc_cb;
    nadata->acc_data = acc_data;
    nadata->refcount = 1;

    gensio_acc_set_callback(child, basena_child_event, nadata);

    *accepter = nadata->acc;

    return 0;

out_nomem:
    basena_finish_free(nadata);
    return ENOMEM;
}
