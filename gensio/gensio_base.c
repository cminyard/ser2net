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
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

#include <gensio/gensio_class.h>
#include <gensio/gensio_base.h>

#ifdef DEBUG_ON
#define ENABLE_PRBUF 1
#include <utils/utils.h>
#endif

enum basen_state { BASEN_CLOSED,
		   BASEN_IN_LL_OPEN,
		   BASEN_IN_FILTER_OPEN,
		   BASEN_OPEN,
		   BASEN_CLOSE_WAIT_DRAIN,
		   BASEN_IN_FILTER_CLOSE,
		   BASEN_IN_LL_CLOSE };

struct basen_data {
    struct gensio *io;

    struct gensio_os_funcs *o;
    struct gensio_filter *filter;
    struct gensio_ll *ll;

    struct gensio_lock *lock;
    struct gensio_timer *timer;
    bool timer_start_pending;
    struct timeval pending_timer;

    unsigned int refcount;

    unsigned int freeref;

    enum basen_state state;

    gensio_done_err open_done;
    void *open_data;

    gensio_done close_done;
    void *close_data;

    bool read_enabled;
    bool in_read;

    bool xmit_enabled;
    bool tmp_xmit_enabled; /* Make sure the xmit code get called once. */

    int saved_xmit_err;

    /*
     * We got an error from the lower layer, it's probably not working
     * any more.
     */
    bool ll_err_occurred;

    /*
     * Used to run user callbacks from the selector to avoid running
     * it directly from user calls.
     */
    bool deferred_op_pending;
    struct gensio_runner *deferred_op_runner;

    bool deferred_read;
    bool deferred_open;
    bool deferred_close;

    struct stel_req *reqs;
};

static void
basen_lock(struct basen_data *ndata)
{
    ndata->o->lock(ndata->lock);
}

static void
basen_unlock(struct basen_data *ndata)
{
    ndata->o->unlock(ndata->lock);
}

static void
basen_finish_free(struct basen_data *ndata)
{
    if (ndata->lock)
	ndata->o->free_lock(ndata->lock);
    if (ndata->timer)
	ndata->o->free_timer(ndata->timer);
    if (ndata->deferred_op_runner)
	ndata->o->free_runner(ndata->deferred_op_runner);
    if (ndata->filter)
	gensio_filter_free(ndata->filter);
    if (ndata->ll)
	gensio_ll_free(ndata->ll);
    if (ndata->io)
	gensio_data_free(ndata->io);
    ndata->o->free(ndata->o, ndata);
}

static void
basen_timer_stopped(struct gensio_timer *t, void *cb_data)
{
    struct basen_data *ndata = cb_data;

    basen_finish_free(ndata);
}

static void
basen_ref(struct basen_data *ndata)
{
    ndata->refcount++;
}

/*
 * This can *only* be called if the refcount is guaranteed not to reach
 * zero.
 */
static void
basen_deref(struct basen_data *ndata)
{
    assert(ndata->refcount > 1);
    ndata->refcount--;
}

static void
basen_deref_and_unlock(struct basen_data *ndata)
{
    unsigned int count;

    assert(ndata->refcount > 0);
    count = --ndata->refcount;
    basen_unlock(ndata);
    if (count == 0) {
	if (ndata->timer) {
	    int err = ndata->o->stop_timer_with_done(ndata->timer,
						     basen_timer_stopped,
						     ndata);

	    if (err != ETIMEDOUT)
		return;
	}
	basen_finish_free(ndata);
    }
}

static bool
filter_ul_read_pending(struct basen_data *ndata)
{
    if (ndata->filter)
	return gensio_filter_ul_read_pending(ndata->filter);
    return false;
}

static bool
filter_ll_write_pending(struct basen_data *ndata)
{
    if (ndata->filter)
	return gensio_filter_ll_write_pending(ndata->filter);
    return false;
}

static bool
filter_ll_read_needed(struct basen_data *ndata)
{
    if (ndata->filter)
	return gensio_filter_ll_read_needed(ndata->filter);
    return false;
}

/* Provides a way to verify keys and such. */
static int
filter_check_open_done(struct basen_data *ndata)
{
    if (ndata->filter)
	return gensio_filter_check_open_done(ndata->filter);
    return 0;
}

static int
filter_try_connect(struct basen_data *ndata, struct timeval *timeout)
{
    if (ndata->filter)
	return gensio_filter_try_connect(ndata->filter, timeout);
    return 0;
}

static int
filter_try_disconnect(struct basen_data *ndata, struct timeval *timeout)
{
    if (ndata->filter)
	return gensio_filter_try_disconnect(ndata->filter, timeout);
    return 0;
}

static int
filter_ul_write(struct basen_data *ndata, gensio_ul_filter_data_handler handler,
		unsigned int *rcount,
		const unsigned char *buf, unsigned int buflen)
{
    if (ndata->filter)
	return gensio_filter_ul_write(ndata->filter, handler,
				      ndata, rcount, buf, buflen);
    return handler(ndata, rcount, buf, buflen);
}	     

static int
filter_ll_write(struct basen_data *ndata, gensio_ll_filter_data_handler handler,
		unsigned int *rcount,
		unsigned char *buf, unsigned int buflen)
{
    if (ndata->filter)
	return gensio_filter_ll_write(ndata->filter, handler,
				      ndata, rcount, buf, buflen);
    return handler(ndata, rcount, buf, buflen);
}	     

static void
filter_ll_urgent(struct basen_data *ndata)
{
    if (ndata->filter)
	gensio_filter_ll_urgent(ndata->filter);
    gensio_cb(ndata->io, GENSIO_EVENT_URGENT, 0, NULL, NULL, NULL);
}

static int
filter_setup(struct basen_data *ndata)
{
    if (ndata->filter)
	return gensio_filter_setup(ndata->filter);
    return 0;
}

static void
filter_cleanup(struct basen_data *ndata)
{
    if (ndata->filter)
	gensio_filter_cleanup(ndata->filter);
}


static int
ll_write(struct basen_data *ndata, unsigned int *rcount,
	 const unsigned char *buf, unsigned int buflen)
{
#ifdef DEBUG_ON
    printf("LL write:");
    prbuf(buf, buflen);
#endif
    return gensio_ll_write(ndata->ll, rcount, buf, buflen);
}

static int
ll_raddr_to_str(struct basen_data *ndata, unsigned int *pos,
		char *buf, unsigned int buflen)
{
    return gensio_ll_raddr_to_str(ndata->ll, pos, buf, buflen);
}

static int
ll_get_raddr(struct basen_data *ndata, void *addr, unsigned int *addrlen)
{
    return gensio_ll_get_raddr(ndata->ll, addr, addrlen);
}

static int
ll_remote_id(struct basen_data *ndata, int *id)
{
    return gensio_ll_remote_id(ndata->ll, id);
}

/*
 * Returns 0 if the open was immediate, EINPROGRESS if it was deferred,
 * and an errno otherwise.
 */
static int
ll_open(struct basen_data *ndata, gensio_ll_open_done done, void *open_data)
{
    return gensio_ll_open(ndata->ll, done, open_data);
}

static void basen_sched_deferred_op(struct basen_data *ndata);

static void
ll_close(struct basen_data *ndata, gensio_ll_close_done done, void *close_data)
{
    int err;

    err = gensio_ll_close(ndata->ll, done, close_data);
    if (err == EINPROGRESS) {
	basen_ref(ndata);
    } else {
	ndata->deferred_close = true;
	basen_sched_deferred_op(ndata);
    }
}

static void
ll_set_read_callback_enable(struct basen_data *ndata, bool enable)
{
    gensio_ll_set_read_callback(ndata->ll, enable);
}

static void
ll_set_write_callback_enable(struct basen_data *ndata, bool enable)
{
    gensio_ll_set_write_callback(ndata->ll, enable);
}

static void
basen_set_ll_enables(struct basen_data *ndata)
{
    if (filter_ll_write_pending(ndata) || ndata->xmit_enabled ||
		ndata->tmp_xmit_enabled)
	ll_set_write_callback_enable(ndata, true);
    if (((((ndata->read_enabled && !filter_ul_read_pending(ndata)) ||
		filter_ll_read_needed(ndata)) && ndata->state == BASEN_OPEN) ||
	    ndata->state == BASEN_IN_FILTER_OPEN ||
	    ndata->state == BASEN_IN_FILTER_CLOSE) &&
	   !ndata->in_read)
	ll_set_read_callback_enable(ndata, true);
}

static int
basen_write_data_handler(void *cb_data,
			 unsigned int *rcount,
			 const unsigned char *buf,
			 unsigned int buflen)
{
    struct basen_data *ndata = cb_data;

    return ll_write(ndata, rcount, buf, buflen);
}

static int
basen_write(struct gensio *io, unsigned int *rcount,
	    const void *buf, unsigned int buflen)
{
    struct basen_data *ndata = gensio_get_gensio_data(io);
    int err = 0;

    basen_lock(ndata);
    if (ndata->state != BASEN_OPEN) {
	err = EBADF;
	goto out_unlock;
    }
    if (ndata->saved_xmit_err) {
	err = ndata->saved_xmit_err;
	ndata->saved_xmit_err = 0;
	goto out_unlock;
    }

    err = filter_ul_write(ndata, basen_write_data_handler, rcount, buf, buflen);

 out_unlock:
    basen_set_ll_enables(ndata);
    basen_unlock(ndata);

    return err;
}

static int
basen_raddr_to_str(struct gensio *io, unsigned int *pos,
		  char *buf, unsigned int buflen)
{
    struct basen_data *ndata = gensio_get_gensio_data(io);

    return ll_raddr_to_str(ndata, pos, buf, buflen);
}

static int
basen_get_raddr(struct gensio *io, void *addr, unsigned int *addrlen)
{
    struct basen_data *ndata = gensio_get_gensio_data(io);

    return ll_get_raddr(ndata, addr, addrlen);
}

static int
basen_remote_id(struct gensio *io, int *id)
{
    struct basen_data *ndata = gensio_get_gensio_data(io);

    return ll_remote_id(ndata, id);
}

static int
basen_read_data_handler(void *cb_data,
			unsigned int *rcount,
			unsigned char *buf,
			unsigned int buflen)
{
    struct basen_data *ndata = cb_data;
    unsigned int count = 0, rval;

 retry:
    if (ndata->state == BASEN_OPEN && ndata->read_enabled) {
	rval = buflen - count;
	gensio_cb(ndata->io, GENSIO_EVENT_READ, 0, buf + count, &rval, NULL);
	count += rval;
	if (count < buflen)
	    goto retry;
    }

    *rcount = count;
    return 0;
}

static void basen_finish_close(struct basen_data *ndata);

static void basen_try_connect(struct basen_data *ndata);

static void
basen_deferred_op(struct gensio_runner *runner, void *cbdata)
{
    struct basen_data *ndata = cbdata;

    basen_lock(ndata);
 retry:
    if (ndata->deferred_open) {
	ndata->deferred_open = false;
	basen_try_connect(ndata);
    }

    if (ndata->deferred_close) {
	ndata->deferred_close = false;
	basen_finish_close(ndata);
    }

    if (ndata->deferred_read) {
	if (ndata->state != BASEN_OPEN)
	    goto out_unlock;

	ndata->deferred_read = false;

	basen_unlock(ndata);
	filter_ll_write(ndata, basen_read_data_handler,
			NULL, NULL, 0);
	basen_lock(ndata);

	ndata->in_read = false;
	/* FIXME - error handling? */
    }

    if (ndata->deferred_read || ndata->deferred_open || ndata->deferred_close)
	goto retry;

 out_unlock:
    ndata->deferred_op_pending = false;
    basen_set_ll_enables(ndata);
    basen_deref_and_unlock(ndata);
}

static void
basen_sched_deferred_op(struct basen_data *ndata)
{
    if (!ndata->deferred_op_pending) {
	/* Call the read from the selector to avoid lock nesting issues. */
	ndata->deferred_op_pending = true;
	basen_ref(ndata);
	ndata->o->run(ndata->deferred_op_runner);
    }
}

static void
basen_finish_close(struct basen_data *ndata)
{
    filter_cleanup(ndata);
    ndata->state = BASEN_CLOSED;
    if (ndata->close_done) {
	basen_unlock(ndata);
	ndata->close_done(ndata->io, ndata->close_data);
	basen_lock(ndata);
    }
}

static void
basen_finish_open(struct basen_data *ndata, int err)
{
    if (err) {
	ndata->state = BASEN_CLOSED;
	filter_cleanup(ndata);
    } else {
	ndata->state = BASEN_OPEN;
	if (ndata->timer_start_pending)
	    ndata->o->start_timer(ndata->timer, &ndata->pending_timer);
    }

    if (ndata->open_done) {
	basen_unlock(ndata);
	ndata->open_done(ndata->io, err, ndata->open_data);
	basen_lock(ndata);
    }
}

static void
basen_ll_close_done(void *cb_data, void *close_data)
{
    struct basen_data *ndata = cb_data;

    basen_lock(ndata);
    basen_finish_close(ndata);
    basen_deref_and_unlock(ndata);
}

static void
basen_ll_close_on_err(void *cb_data, void *close_data)
{
    struct basen_data *ndata = cb_data;

    basen_lock(ndata);
    basen_finish_open(ndata, (long) close_data);
    basen_deref_and_unlock(ndata);
}

static void
basen_try_connect(struct basen_data *ndata)
{
    int err;
    struct timeval timeout = {0, 0};

    assert(ndata->state == BASEN_IN_FILTER_OPEN);
    if (ndata->state != BASEN_IN_FILTER_OPEN)
	/*
	 * We can race between the timer, input, and output, make sure
	 * not to call this extraneously.
	 */
	return;

    ll_set_write_callback_enable(ndata, false);
    ll_set_read_callback_enable(ndata, false);

    err = filter_try_connect(ndata, &timeout);
    if (err == EINPROGRESS)
	return;
    if (err == EAGAIN) {
	ndata->o->start_timer(ndata->timer, &timeout);
	return;
    }

    if (!err)
	err = filter_check_open_done(ndata);

    if (err) {
	ndata->state = BASEN_IN_LL_CLOSE;
	ll_close(ndata, basen_ll_close_on_err, (void *) (long) err);
    } else {
	basen_finish_open(ndata, 0);
    }
}

static void
basen_ll_open_done(void *cb_data, int err, void *open_data)
{
    struct basen_data *ndata = cb_data;

    basen_lock(ndata);
    if (err) {
	basen_finish_open(ndata, err);
    } else {
	ndata->state = BASEN_IN_FILTER_OPEN;
	basen_try_connect(ndata);
	basen_set_ll_enables(ndata);
    }
    basen_deref_and_unlock(ndata);
}

static int
basen_open(struct gensio *io, gensio_done_err open_done, void *open_data)
{
    struct basen_data *ndata = gensio_get_gensio_data(io);
    int err = EBUSY;

    basen_lock(ndata);
    if (ndata->state == BASEN_CLOSED) {
	err = filter_setup(ndata);
	if (err)
	    goto out_err;

	ndata->in_read = false;
	ndata->deferred_read = false;
	ndata->deferred_open = false;
	ndata->deferred_close = false;
	ndata->read_enabled = false;
	ndata->xmit_enabled = false;
	ndata->timer_start_pending = false;

	ndata->open_done = open_done;
	ndata->open_data = open_data;
	err = ll_open(ndata, basen_ll_open_done, NULL);
	if (err == 0) {
	    ndata->state = BASEN_IN_FILTER_OPEN;
	    ndata->deferred_open = true;
	    basen_sched_deferred_op(ndata);
	} else if (err == EINPROGRESS) {
	    ndata->state = BASEN_IN_LL_OPEN;
	    basen_ref(ndata);
	    err = 0;
	} else {
	    filter_cleanup(ndata);
	    goto out_err;
	}	    
    }
 out_err:
    basen_unlock(ndata);

    return err;
}

static void
basen_try_close(struct basen_data *ndata)
{
    int err;
    struct timeval timeout = {0, 0};

    ll_set_write_callback_enable(ndata, false);
    ll_set_read_callback_enable(ndata, false);

    err = filter_try_disconnect(ndata, &timeout);
    if (err == EINPROGRESS)
	return;
    if (err == EAGAIN) {
	ndata->o->start_timer(ndata->timer, &timeout);
	return;
    }

    /* FIXME - error handling? */
    ndata->state = BASEN_IN_LL_CLOSE;
    ll_close(ndata, basen_ll_close_done, NULL);
}

static void
basen_i_close(struct basen_data *ndata,
	      gensio_done close_done, void *close_data)
{
    ndata->close_done = close_done;
    ndata->close_data = close_data;
    if (ndata->ll_err_occurred) {
	ndata->state = BASEN_IN_LL_CLOSE;
	ll_close(ndata, basen_ll_close_done, NULL);
    } else if (filter_ll_write_pending(ndata)) {
	ndata->state = BASEN_CLOSE_WAIT_DRAIN;
    } else {
	ndata->state = BASEN_IN_FILTER_CLOSE;
	basen_try_close(ndata);
    }
    basen_set_ll_enables(ndata);
}

static int
basen_close(struct gensio *io, gensio_done close_done, void *close_data)
{
    struct basen_data *ndata = gensio_get_gensio_data(io);
    int err = 0;

    basen_lock(ndata);
    if (ndata->state != BASEN_OPEN) {
	if (ndata->state == BASEN_IN_FILTER_OPEN ||
			ndata->state == BASEN_IN_LL_OPEN) {
	    basen_i_close(ndata, close_done, close_data);
	    basen_deref(ndata);
	} else {
	    err = EBUSY;
	}
    } else {
	basen_i_close(ndata, close_done, close_data);
    }
    basen_unlock(ndata);

    return err;
}

static void
basen_free(struct gensio *io)
{
    struct basen_data *ndata = gensio_get_gensio_data(io);

    basen_lock(ndata);
    assert(ndata->freeref > 0);
    if (--ndata->freeref > 0) {
	basen_unlock(ndata);
	return;
    }

    if (ndata->state == BASEN_IN_FILTER_CLOSE ||
		ndata->state == BASEN_IN_LL_CLOSE) {
	ndata->close_done = NULL;
    } else if (ndata->state == BASEN_IN_FILTER_OPEN ||
			ndata->state == BASEN_IN_LL_OPEN) {
	basen_i_close(ndata, NULL, NULL);
	/* We have to lose the reference that in_open state is holding. */
	basen_deref(ndata);
    } else if (ndata->state != BASEN_CLOSED)
	basen_i_close(ndata, NULL, NULL);
    /* Lose the initial ref so it will be freed when done. */
    basen_deref_and_unlock(ndata);
}

static void
basen_do_ref(struct gensio *io)
{
    struct basen_data *ndata = gensio_get_gensio_data(io);

    basen_lock(ndata);
    ndata->freeref++;
    basen_unlock(ndata);
}

static void
basen_timeout(struct gensio_timer *timer, void *cb_data)
{
    struct basen_data *ndata = cb_data;

    basen_lock(ndata);
    switch (ndata->state) {
    case BASEN_IN_FILTER_OPEN:
	basen_try_connect(ndata);
	break;

    case BASEN_IN_FILTER_CLOSE:
	basen_try_close(ndata);
	break;

    case BASEN_OPEN:
	basen_unlock(ndata);
	gensio_filter_timeout(ndata->filter);
	basen_lock(ndata);
	break;

    default:
	break;
    }
    basen_set_ll_enables(ndata);
    basen_unlock(ndata);
}

static void
basen_set_read_callback_enable(struct gensio *io, bool enabled)
{
    struct basen_data *ndata = gensio_get_gensio_data(io);
    bool read_pending;

    basen_lock(ndata);
    if (ndata->state == BASEN_CLOSED || ndata->state == BASEN_IN_FILTER_CLOSE ||
		ndata->state == BASEN_IN_LL_CLOSE)
	goto out_unlock;
    ndata->read_enabled = enabled;
    read_pending = filter_ul_read_pending(ndata);
    if (ndata->in_read || ndata->state == BASEN_IN_FILTER_OPEN ||
			ndata->state == BASEN_IN_LL_OPEN ||
			(read_pending && !enabled)) {
	/* Nothing to do, let the read/open handling wake things up. */
    } else if (read_pending) {
	/* in_read keeps this from getting called while pending. */
	ndata->in_read = true;
	ndata->deferred_read = true;
	basen_sched_deferred_op(ndata);
    } else {
	/*
	 * FIXME - here (and other places) we don't disable the low-level
	 * handler, that is done in the callbacks.  That's not optimal,
	 * need to figure out a way to set this more accurately.
	 */
	basen_set_ll_enables(ndata);
    }
 out_unlock:
    basen_unlock(ndata);
}

static void
basen_set_write_callback_enable(struct gensio *io, bool enabled)
{
    struct basen_data *ndata = gensio_get_gensio_data(io);

    basen_lock(ndata);
    if (ndata->state == BASEN_CLOSED || ndata->state == BASEN_IN_FILTER_CLOSE ||
			ndata->state == BASEN_IN_LL_CLOSE)
	goto out_unlock;
    if (ndata->xmit_enabled != enabled) {
	ndata->xmit_enabled = enabled;
	basen_set_ll_enables(ndata);
    }
 out_unlock:
    basen_unlock(ndata);
}

static int
gensio_base_func(struct gensio *io, int func, unsigned int *count,
		const void *buf, unsigned int buflen,
		void *auxdata)
{
    switch (func) {
    case GENSIO_FUNC_WRITE:
	return basen_write(io, count, buf, buflen);

    case GENSIO_FUNC_RADDR_TO_STR:
	return basen_raddr_to_str(io, count, auxdata, buflen);

    case GENSIO_FUNC_GET_RADDR:
	return basen_get_raddr(io, auxdata, count);

    case GENSIO_FUNC_OPEN:
	return basen_open(io, buf, auxdata);

    case GENSIO_FUNC_CLOSE:
	return basen_close(io, buf, auxdata);

    case GENSIO_FUNC_FREE:
	basen_free(io);
	return 0;

    case GENSIO_FUNC_REF:
	basen_do_ref(io);
	return 0;

    case GENSIO_FUNC_SET_READ_CALLBACK:
	basen_set_read_callback_enable(io, buflen);
	return 0;

    case GENSIO_FUNC_SET_WRITE_CALLBACK:
	basen_set_write_callback_enable(io, buflen);
	return 0;

    case GENSIO_FUNC_REMOTE_ID:
	return basen_remote_id(io, auxdata);

    default:
	return ENOTSUP;
    }
}

static unsigned int
basen_ll_read(void *cb_data, int readerr,
	      unsigned char *ibuf, unsigned int buflen)
{
    struct basen_data *ndata = cb_data;
    struct gensio *io = ndata->io;
    unsigned char *buf = ibuf;

#ifdef DEBUG_ON
    printf("LL read:");
    prbuf(buf, buflen);
#endif
    basen_lock(ndata);
    ll_set_read_callback_enable(ndata, false);
    if (readerr) {
	/* Do this here so the user can modify it. */
	ndata->read_enabled = false;
	ndata->ll_err_occurred = true;
	if (ndata->state == BASEN_IN_FILTER_OPEN ||
			ndata->state == BASEN_IN_LL_OPEN) {
	    ndata->state = BASEN_IN_LL_CLOSE;
	    ll_close(ndata, basen_ll_close_on_err, (void *) (long) ECOMM);
	} else if (ndata->state == BASEN_CLOSE_WAIT_DRAIN ||
			ndata->state == BASEN_IN_FILTER_CLOSE) {
	    ndata->state = BASEN_IN_LL_CLOSE;
	    ll_close(ndata, basen_ll_close_done, NULL);
	} else if (gensio_get_cb(io)) {
	    unsigned int len = 0;

	    basen_unlock(ndata);
	    gensio_cb(io, GENSIO_EVENT_READ, readerr, NULL, &len, NULL);
	    basen_lock(ndata);
	} else {
	    basen_i_close(ndata, NULL, NULL);
	}
	goto out_finish;
    }

    if (ndata->in_read)
	/* Currently in a deferred read, just let that handle it. */
	goto out_unlock;

    if (buflen > 0) {
	unsigned int wrlen = 0;

	ndata->in_read = true;
	basen_unlock(ndata);
	filter_ll_write(ndata, basen_read_data_handler, &wrlen,
			buf, buflen);
	basen_lock(ndata);
	ndata->in_read = false;
	/* FIXME - error handling? */

	buf += wrlen;
	buflen -= wrlen;

	if (ndata->state == BASEN_IN_FILTER_OPEN)
	    basen_try_connect(ndata);
	if (ndata->state == BASEN_IN_FILTER_CLOSE)
	    basen_try_close(ndata);
    }

 out_finish:
    basen_set_ll_enables(ndata);
 out_unlock:
    basen_unlock(ndata);

    return buf - ibuf;
}

static void
basen_ll_write_ready(void *cb_data)
{
    struct basen_data *ndata = cb_data;
    int err;

    basen_lock(ndata);
    ll_set_write_callback_enable(ndata, false);
    if (filter_ll_write_pending(ndata)) {
	err = filter_ul_write(ndata, basen_write_data_handler, NULL, NULL, 0);
	if (err)
	    ndata->saved_xmit_err = err;
    }

    if (ndata->state == BASEN_CLOSE_WAIT_DRAIN &&
		!filter_ll_write_pending(ndata))
	ndata->state = BASEN_IN_FILTER_CLOSE;
    if (ndata->state == BASEN_IN_FILTER_OPEN)
	basen_try_connect(ndata);
    if (ndata->state == BASEN_IN_FILTER_CLOSE)
	basen_try_close(ndata);
    if (ndata->state != BASEN_IN_FILTER_OPEN && !filter_ll_write_pending(ndata)
		&& ndata->xmit_enabled) {
	basen_unlock(ndata);
	gensio_cb(ndata->io, GENSIO_EVENT_WRITE_READY, 0, NULL, 0, NULL);
	basen_lock(ndata);
    }

    ndata->tmp_xmit_enabled = false;

    basen_set_ll_enables(ndata);
    basen_unlock(ndata);
}

static void
basen_ll_urgent(void *cb_data)
{
    struct basen_data *ndata = cb_data;

    filter_ll_urgent(ndata);
}

static unsigned int
gensio_ll_base_cb(void *cb_data, int op, int val,
		  void *buf, unsigned int buflen,
		  void *data)
{
    switch (op) {
    case GENSIO_LL_CB_READ:
	return basen_ll_read(cb_data, val, buf, buflen);

    case GENSIO_LL_CB_WRITE_READY:
	basen_ll_write_ready(cb_data);
	return 0;

    case GENSIO_LL_CB_URGENT:
	basen_ll_urgent(cb_data);
	return 0;

    default:
	return 0;
    }
};

static void
basen_output_ready(void *cb_data)
{
    struct basen_data *ndata = cb_data;

    ll_set_write_callback_enable(ndata, true);
}

static void
basen_start_timer(void *cb_data, struct timeval *timeout)
{
    struct basen_data *ndata = cb_data;

    basen_lock(ndata);
    if (ndata->state == BASEN_OPEN) {
	ndata->o->start_timer(ndata->timer, timeout);
    } else {
	ndata->timer_start_pending = true;
	ndata->pending_timer = *timeout;
    }
    basen_unlock(ndata);
}

static int
gensio_base_filter_cb(void *cb_data, int op, void *data)
{
    switch (op) {
    case GENSIO_FILTER_CB_OUTPUT_READY:
	basen_output_ready(cb_data);
	return 0;

    case GENSIO_FILTER_CB_START_TIMER:
	basen_start_timer(cb_data, data);
	return 0;

    default:
	return ENOTSUP;
    }
}

static struct gensio *
gensio_i_alloc(struct gensio_os_funcs *o,
	       struct gensio_ll *ll,
	       struct gensio_filter *filter,
	       const char *typename,
	       bool is_client,
	       gensio_done_err open_done, void *open_data,
	       gensio_event cb, void *user_data)
{
    struct basen_data *ndata = o->zalloc(o, sizeof(*ndata));

    if (!ndata)
	return NULL;

    ndata->o = o;
    ndata->refcount = 1;
    ndata->freeref = 1;

    ndata->lock = o->alloc_lock(o);
    if (!ndata->lock)
	goto out_nomem;

    ndata->timer = o->alloc_timer(o, basen_timeout, ndata);
    if (!ndata->timer)
	goto out_nomem;

    ndata->deferred_op_runner = o->alloc_runner(o, basen_deferred_op, ndata);
    if (!ndata->deferred_op_runner)
	goto out_nomem;

    ndata->ll = ll;
    ndata->filter = filter;
    if (filter)
	gensio_filter_set_callback(filter, gensio_base_filter_cb, ndata);
    ndata->io = gensio_data_alloc(o, cb, user_data, gensio_base_func,
				  ll->child, typename, ndata);
    if (!ndata->io)
	goto out_nomem;
    gensio_set_is_client(ndata->io, is_client);
    gensio_ll_set_callback(ll, gensio_ll_base_cb, ndata);
    if (is_client)
	ndata->state = BASEN_CLOSED;
    else {
	if (filter_setup(ndata))
	    goto out_nomem;

	ndata->open_done = open_done;
	ndata->open_data = open_data;
	ndata->state = BASEN_IN_FILTER_OPEN;
	/* Call the first try open from the xmit handler. */
	ndata->tmp_xmit_enabled = true;
	basen_set_ll_enables(ndata);
    }

    return ndata->io;

out_nomem:
    basen_finish_free(ndata);
    return NULL;
}

struct gensio *
base_gensio_alloc(struct gensio_os_funcs *o,
		  struct gensio_ll *ll,
		  struct gensio_filter *filter,
		  const char *typename,
		  gensio_event cb, void *user_data)
{
    return gensio_i_alloc(o, ll, filter, typename, true,
			  NULL, NULL, cb, user_data);
}

struct gensio *
base_gensio_server_alloc(struct gensio_os_funcs *o,
			 struct gensio_ll *ll,
			 struct gensio_filter *filter,
			 const char *typename,
			 gensio_done_err open_done, void *open_data)
{
    return gensio_i_alloc(o, ll, filter, typename, false,
			  open_done, open_data, NULL, NULL);
}

void
gensio_filter_set_callback(struct gensio_filter *filter,
			   gensio_filter_cb cb, void *cb_data)
{
    filter->func(filter, GENSIO_FILTER_FUNC_SET_CALLBACK,
		 cb, cb_data,
		 NULL, NULL, NULL, 0);
}

bool
gensio_filter_ul_read_pending(struct gensio_filter *filter)
{
    return filter->func(filter, GENSIO_FILTER_FUNC_UL_READ_PENDING,
			NULL, NULL, NULL, NULL, NULL, 0);
}

bool
gensio_filter_ll_write_pending(struct gensio_filter *filter)
{
    return filter->func(filter, GENSIO_FILTER_FUNC_UL_WRITE_PENDING,
			NULL, NULL, NULL, NULL, NULL, 0);
}

bool
gensio_filter_ll_read_needed(struct gensio_filter *filter)
{
    return filter->func(filter, GENSIO_FILTER_FUNC_LL_READ_NEEDED,
			NULL, NULL, NULL, NULL, NULL, 0);
}

int
gensio_filter_check_open_done(struct gensio_filter *filter)
{
    return filter->func(filter, GENSIO_FILTER_FUNC_CHECK_OPEN_DONE,
			NULL, NULL, NULL, NULL, NULL, 0);
}

int
gensio_filter_try_connect(struct gensio_filter *filter,
			  struct timeval *timeout)
{
    return filter->func(filter, GENSIO_FILTER_FUNC_TRY_CONNECT,
			NULL, timeout, NULL, NULL, NULL, 0);
}

int
gensio_filter_try_disconnect(struct gensio_filter *filter,
			     struct timeval *timeout)
{
    return filter->func(filter, GENSIO_FILTER_FUNC_TRY_DISCONNECT,
			NULL, timeout, NULL, NULL, NULL, 0);
}

int
gensio_filter_ul_write(struct gensio_filter *filter,
		       gensio_ul_filter_data_handler handler, void *cb_data,
		       unsigned int *rcount,
		       const unsigned char *buf, unsigned int buflen)
{
    return filter->func(filter, GENSIO_FILTER_FUNC_UL_WRITE,
			handler, cb_data, rcount, NULL, buf, buflen);
}

int
gensio_filter_ll_write(struct gensio_filter *filter,
		       gensio_ll_filter_data_handler handler, void *cb_data,
		       unsigned int *rcount,
		       unsigned char *buf, unsigned int buflen)
{
    return filter->func(filter, GENSIO_FILTER_FUNC_LL_WRITE,
			handler, cb_data, rcount, buf, NULL, buflen);
}

void
gensio_filter_ll_urgent(struct gensio_filter *filter)
{
    filter->func(filter, GENSIO_FILTER_FUNC_LL_URGENT,
		 NULL, NULL, NULL, NULL, NULL, 0);
}

void
gensio_filter_timeout(struct gensio_filter *filter)
{
    filter->func(filter, GENSIO_FILTER_FUNC_TIMEOUT,
		 NULL, NULL, NULL, NULL, NULL, 0);
}

int
gensio_filter_setup(struct gensio_filter *filter)
{
    return filter->func(filter, GENSIO_FILTER_FUNC_SETUP,
			NULL, NULL, NULL, NULL, NULL, 0);
}

void
gensio_filter_cleanup(struct gensio_filter *filter)
{
    filter->func(filter, GENSIO_FILTER_FUNC_CLEANUP,
		 NULL, NULL, NULL, NULL, NULL, 0);
}

void
gensio_filter_free(struct gensio_filter *filter)
{
    filter->func(filter, GENSIO_FILTER_FUNC_FREE,
		 NULL, NULL, NULL, NULL, NULL, 0);
}

void
gensio_ll_set_callback(struct gensio_ll *ll,
		       gensio_ll_cb cb, void *cb_data)
{
    ll->func(ll, GENSIO_LL_FUNC_SET_CALLBACK, 0, cb, cb_data,
	     NULL, NULL, NULL, 0);
}

int
gensio_ll_write(struct gensio_ll *ll, unsigned int *rcount,
		const unsigned char *buf, unsigned int buflen)
{
    return ll->func(ll, GENSIO_LL_FUNC_WRITE, 0, NULL, NULL,
		    rcount, NULL, buf, buflen);
}

int
gensio_ll_raddr_to_str(struct gensio_ll *ll, unsigned int *pos,
		       char *buf, unsigned int buflen)
{
    return ll->func(ll, GENSIO_LL_FUNC_RADDR_TO_STR, 0, NULL, NULL,
		    pos, buf, NULL, buflen);
}

int
gensio_ll_get_raddr(struct gensio_ll *ll,
		    void *addr, unsigned int *addrlen)
{
    return ll->func(ll, GENSIO_LL_FUNC_GET_RADDR, 0, NULL, NULL,
		    addrlen, addr, NULL, 0);
}

int
gensio_ll_remote_id(struct gensio_ll *ll, int *id)
{
    return ll->func(ll, GENSIO_LL_FUNC_REMOTE_ID, 0, NULL, id,
		    NULL, NULL, NULL, 0);
}

int
gensio_ll_open(struct gensio_ll *ll,
	       gensio_ll_open_done done, void *open_data)
{
    return ll->func(ll, GENSIO_LL_FUNC_OPEN, 0, done, open_data,
		    NULL, NULL, NULL, 0);
}

int
gensio_ll_close(struct gensio_ll *ll,
		gensio_ll_close_done done, void *close_data)
{
    return ll->func(ll, GENSIO_LL_FUNC_CLOSE, 0, done, close_data,
		    NULL, NULL, NULL, 0);
}

void
gensio_ll_set_read_callback(struct gensio_ll *ll, bool enabled)
{
    ll->func(ll, GENSIO_LL_FUNC_SET_READ_CALLBACK, enabled, NULL, NULL,
	     NULL, NULL, NULL, 0);
}

void
gensio_ll_set_write_callback(struct gensio_ll *ll, bool enabled)
{
    ll->func(ll, GENSIO_LL_FUNC_SET_WRITE_CALLBACK, enabled, NULL, NULL,
	     NULL, NULL, NULL, 0);
}

void
gensio_ll_free(struct gensio_ll *ll)
{
    ll->func(ll, GENSIO_LL_FUNC_FREE, 0, NULL, NULL,
	     NULL, NULL, NULL, 0);
}
