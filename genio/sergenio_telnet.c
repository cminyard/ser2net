/*
 *  ser2net - A program for allowing telnet connection to serial ports
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

#include "utils/utils.h"
#include "utils/telnet.h"

#include "sergenio_internal.h"

#define SERCTL_WAIT_TIME 5

struct stel_req {
    int option;
    int minval;
    int maxval;
    void (*done)(struct sergenio *sio, int err, int val, void *cb_data);
    void *cb_data;
    int time_left;
    struct stel_req *next;
};

struct stel_data {
    struct sergenio sio;

    struct genio_os_funcs *o;

    struct genio_lock *lock;

    struct genio_timer *timer;

    bool in_open;
    void (*open_done)(struct genio *net, int err, void *open_data);
    void *open_data;
    unsigned int open_wait_count;

    bool in_free;
    bool closed;
    unsigned int close_count;

    void (*close_done)(struct genio *net, void *close_data);
    void *close_data;

    struct genio *child;

    bool read_enabled;
    bool in_read;
    bool deferred_read;
    unsigned char read_data[1024];
    unsigned int data_pos;
    unsigned int data_pending_len;
    int in_urgent;

    struct telnet_data_s tn_data;
    bool cisco_baud;
    bool allow_2217;
    bool do_2217;

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

#define mygenio_to_stel(v) container_of((struct sergenio *) v->parent_object, \
					struct stel_data, sio)
#define mysergenio_to_stel(v) container_of(v, struct stel_data, sio)

static void
stel_lock(struct stel_data *sdata)
{
    sdata->o->lock(sdata->lock);
}

static void
stel_unlock(struct stel_data *sdata)
{
    sdata->o->unlock(sdata->lock);
}

static int
stel_queue(struct stel_data *sdata, int option,
	   int minval, int maxval,
	   void (*done)(struct sergenio *sio, int err,
			int baud, void *cb_data),
	   void *cb_data)
{
    struct stel_req *curr, *req;

    if (!sdata->do_2217)
	return ENOTSUP;

    req = sdata->o->zalloc(sdata->o, sizeof(*req));
    if (!req)
	return ENOMEM;

    req->option = option;
    req->done = done;
    req->cb_data = cb_data;
    req->minval = minval;
    if (!maxval)
	maxval = INT_MAX;
    req->maxval = maxval;
    req->time_left = SERCTL_WAIT_TIME;
    req->next = NULL;

    stel_lock(sdata);
    curr = sdata->reqs;
    if (!curr) {
	sdata->reqs = req;
    } else {
	while (curr->next)
	    curr = curr->next;
	curr->next = req;
    }
    stel_unlock(sdata);

    return 0;
}

static int
stel_baud(struct sergenio *sio, int baud,
	  void (*done)(struct sergenio *sio, int err,
		       int baud, void *cb_data),
	  void *cb_data)
{
    struct stel_data *sdata = mysergenio_to_stel(sio);
    unsigned char buf[6];
    int err;

    err = stel_queue(sdata, 1, 0, 0, done, cb_data);
    if (err)
	return err;

    buf[0] = 44;
    buf[1] = 1;
    if (sdata->cisco_baud) {
	buf[2] = baud_to_cisco_baud(baud);
	telnet_send_option(&sdata->tn_data, buf, 3);
    } else {
	buf[2] = baud >> 24;
	buf[3] = baud >> 16;
	buf[4] = baud >> 8;
	buf[5] = baud;
	telnet_send_option(&sdata->tn_data, buf, 6);
    }
    return 0;
}

static int
stel_queue_and_send(struct sergenio *sio, int option, int val,
		    int minval, int maxval,
		    void (*done)(struct sergenio *sio, int err, int val,
				 void *cb_data),
		    void *cb_data)
{
    struct stel_data *sdata = mysergenio_to_stel(sio);
    unsigned char buf[3];
    int err;

    err = stel_queue(sdata, option, minval, maxval, done, cb_data);
    if (err)
	return err;

    buf[0] = 44;
    buf[1] = option;
    buf[2] = val + minval;
    telnet_send_option(&sdata->tn_data, buf, 3);

    return 0;
}

static int
stel_datasize(struct sergenio *sio, int datasize,
	      void (*done)(struct sergenio *sio, int err, int datasize,
			   void *cb_data),
	      void *cb_data)
{
    return stel_queue_and_send(sio, 2, datasize, 0, 0, done, cb_data);
}

static int
stel_parity(struct sergenio *sio, int parity,
	    void (*done)(struct sergenio *sio, int err, int parity,
			 void *cb_data),
	    void *cb_data)
{
    return stel_queue_and_send(sio, 3, parity, 0, 0, done, cb_data);
}

static int
stel_stopbits(struct sergenio *sio, int stopbits,
	      void (*done)(struct sergenio *sio, int err, int stopbits,
			   void *cb_data),
	      void *cb_data)
{
    return stel_queue_and_send(sio, 4, stopbits, 0, 0, done, cb_data);
}

static int
stel_flowcontrol(struct sergenio *sio, int flowcontrol,
		 void (*done)(struct sergenio *sio, int err,
			      int flowcontrol, void *cb_data),
		 void *cb_data)
{
    return stel_queue_and_send(sio, 5, flowcontrol, 0, 3, done, cb_data);
}

static int
stel_sbreak(struct sergenio *sio, int breakv,
	    void (*done)(struct sergenio *sio, int err, int breakv,
			 void *cb_data),
	    void *cb_data)
{
    return stel_queue_and_send(sio, 5, breakv, 4, 6, done, cb_data);
}

static int
stel_dtr(struct sergenio *sio, int dtr,
	 void (*done)(struct sergenio *sio, int err, int dtr,
		      void *cb_data),
	 void *cb_data)
{
    return stel_queue_and_send(sio, 5, dtr, 7, 9, done, cb_data);
}

static int
stel_rts(struct sergenio *sio, int rts,
	 void (*done)(struct sergenio *sio, int err, int rts,
		      void *cb_data),
	 void *cb_data)
{
    return stel_queue_and_send(sio, 5, rts, 10, 12, done, cb_data);
}

static const struct sergenio_functions stel_funcs = {
    .baud = stel_baud,
    .datasize = stel_datasize,
    .parity = stel_parity,
    .stopbits = stel_stopbits,
    .flowcontrol = stel_flowcontrol,
    .sbreak = stel_sbreak,
    .dtr = stel_dtr,
    .rts = stel_rts,
};

static int
stel_write(struct genio *net, unsigned int *rcount,
	   const void *buf, unsigned int buflen)
{
    struct stel_data *sdata = mygenio_to_stel(net);
    const unsigned char *inbuf = buf;
    unsigned int inlen = buflen;
    int err = 0;

    stel_lock(sdata);
    if (sdata->closed) {
	err = EBADF;
	goto out_unlock;
    }
    if (sdata->saved_xmit_err) {
	err = sdata->saved_xmit_err;
	sdata->saved_xmit_err = 0;
	goto out_unlock;
    }

    if (sdata->xmit_buf_len) {
	*rcount = 0;
	goto out_unlock;
    }

 send_more:
    sdata->xmit_buf_len = process_telnet_xmit(sdata->xmit_buf,
					      sizeof(sdata->xmit_buf),
					      &inbuf, &inlen);
    err = genio_write(sdata->child, &sdata->xmit_buf_curr,
		      sdata->xmit_buf, sdata->xmit_buf_len);
    if (err) {
	sdata->xmit_buf_len = 0;
	goto out_unlock;
    }

    if (sdata->xmit_buf_curr == sdata->xmit_buf_len) {
	sdata->xmit_buf_len = 0;
	if (inlen)
	    goto send_more;
    }

    *rcount = buflen - inlen;
 out_unlock:
    stel_unlock(sdata);
    return err;
}

static int
stel_raddr_to_str(struct genio *net, int *pos,
		  char *buf, unsigned int buflen)
{
    struct stel_data *sdata = mygenio_to_stel(net);

    return genio_raddr_to_str(sdata->child, pos, buf, buflen);
}

static int
stel_get_raddr(struct genio *net,
	       struct sockaddr *addr, socklen_t *addrlen)
{
    struct stel_data *sdata = mygenio_to_stel(net);

    return genio_get_raddr(sdata->child, addr, addrlen);
}

static void
stel_free_data(struct stel_data *sdata)
{
    struct stel_req *req, *prev;

    if (sdata->timer)
	sdata->o->free_timer(sdata->timer);
    req = sdata->reqs;
    while (req) {
	prev = req;
	req = req->next;
	sdata->o->free(sdata->o, prev);
    }
    if (sdata->deferred_op_runner)
	sdata->o->free_runner(sdata->deferred_op_runner);
    if (sdata->sio.io)
	sdata->o->free(sdata->o, sdata->sio.io);
    sdata->o->free(sdata->o, sdata);
}

static void
stel_finish_free(struct stel_data *sdata)
{
    genio_free(sdata->child);
    telnet_cleanup(&sdata->tn_data);
    stel_free_data(sdata);
}

static void
check_finish_close(struct stel_data *sdata)
{
    stel_lock(sdata);
    if (sdata->close_count > 1) {
	sdata->close_count--;
	stel_unlock(sdata);
	return;
    }
    stel_unlock(sdata);

    sdata->in_open = false;

    if (sdata->close_done)
	sdata->close_done(sdata->sio.io, sdata->close_data);

    stel_lock(sdata);
    /* delay this until here to keep stel_free() from freeing it. */
    sdata->close_count--;
    if (sdata->in_free) {
	stel_unlock(sdata);
	stel_finish_free(sdata);
    } else {
	stel_unlock(sdata);
    }
}

/* Must be called with sdata->lock held */
static void
stel_finish_read(struct stel_data *sdata, unsigned int count)
{
    if (count < sdata->data_pending_len) {
	/* The user didn't consume all the data. */
	sdata->data_pending_len -= count;
	sdata->data_pos += count;
    } else {
	sdata->data_pending_len = 0;
    }

    sdata->in_read = false;
}

static void
stel_deferred_op(struct genio_runner *runner, void *cbdata)
{
    struct stel_data *sdata = cbdata;
    struct genio *io = sdata->sio.io;
    unsigned int count;
    bool in_read;

    stel_lock(sdata);
 restart:
    if (sdata->deferred_read) {
	in_read = sdata->in_read;
	sdata->deferred_read = false;
    }

    if (in_read) {
    retry:
	stel_unlock(sdata);
	count = io->cbs->read_callback(io, 0,
				       &sdata->read_data[sdata->data_pos],
				       sdata->data_pending_len, 0);
	stel_lock(sdata);
	stel_finish_read(sdata, count);
	if (sdata->data_pending_len)
	    goto retry;
    }

    if (sdata->deferred_read)
	/* Something was added, process it. */
	goto restart;

    if (sdata->read_enabled || sdata->in_open)
	genio_set_read_callback_enable(sdata->child, true);

    sdata->deferred_op_pending = false;
    stel_unlock(sdata);
}

static void
stel_timer_stopped(struct genio_timer *timer,
		   void *cb_data)
{
    check_finish_close(cb_data);
}

static void
stel_genio_close_done(struct genio *io, void *close_data)
{
    struct stel_data *sdata = genio_get_user_data(io);

    check_finish_close(sdata);
}

static void
stel_sub_open_done(struct genio *io, int err, void *cb_data)
{
    struct stel_data *sdata = cb_data;

    /*
     * Wait until we get the DO/DONT back from the remote end for the
     * com port before reporting open success.  That way we don't
     * issue com port commands before everything is ready.
     */
    if (err && sdata->open_done)
	sdata->open_done(sdata->sio.io, err, sdata->open_data);

    stel_lock(sdata);
    if (err) {
	sdata->open_wait_count = 0;
	sdata->in_open = false;
	sdata->closed = true;
	sdata->o->stop_timer(sdata->timer);
    } else {
	/* Wait three timeouts for com port do/dont. */
	sdata->open_wait_count = 3;
	/* Enable low-level for telnet processing. */
	genio_set_read_callback_enable(sdata->child, true);
	genio_set_write_callback_enable(sdata->child, true);
    }
    stel_unlock(sdata);
}

static int
stel_open(struct genio *io, void (*open_done)(struct genio *io,
					      int err,
					      void *open_data),
	  void *open_data)
{
    struct stel_data *sdata = mygenio_to_stel(io);
    struct timeval timeout;
    int err = EBUSY;

    stel_lock(sdata);
    if (sdata->closed && !sdata->close_count) {
	sdata->open_done = open_done;
	sdata->open_data = open_data;
	err = genio_open(sdata->child, stel_sub_open_done, sdata);
	if (!err) {
	    sdata->in_open = true;
	    sdata->closed = false;
	    timeout.tv_sec = 1;
	    timeout.tv_usec = 0;
	    sdata->o->start_timer(sdata->timer, &timeout);
	}
    }
    stel_unlock(sdata);

    return err;
}

static void
__stel_close(struct stel_data *sdata, void (*close_done)(struct genio *io,
							 void *close_data),
	     void *close_data)
{
    sdata->close_done = close_done;
    sdata->close_data = close_data;
    sdata->closed = true;
    sdata->close_count = 2; /* One for timer and one for genio. */
    stel_unlock(sdata);
    sdata->o->stop_timer_with_done(sdata->timer, stel_timer_stopped, sdata);
    genio_close(sdata->child, stel_genio_close_done, NULL);
}

static int
stel_close(struct genio *io, void (*close_done)(struct genio *io,
						void *close_data),
	   void *close_data)
{
    struct stel_data *sdata = mygenio_to_stel(io);
    int err = 0;

    stel_lock(sdata);
    if (sdata->closed || sdata->close_count) {
	stel_unlock(sdata);
	err = EBUSY;
    } else {
	__stel_close(sdata, close_done, close_data); /* Releases lock. */
    }

    return err;
}

static void
stel_free(struct genio *io)
{
    struct stel_data *sdata = mygenio_to_stel(io);

    stel_lock(sdata);
    sdata->in_free = true;
    if (sdata->close_count) {
	sdata->close_done = NULL;
	stel_unlock(sdata);
    } else if (sdata->closed) {
	stel_unlock(sdata);
	stel_finish_free(sdata);
    } else {
	__stel_close(sdata, NULL, NULL); /* Releases lock */
    }
}

static void
stel_set_read_callback_enable(struct genio *io, bool enabled)
{
    struct stel_data *sdata = mygenio_to_stel(io);

    stel_lock(sdata);
    if (sdata->closed)
	goto out_unlock;
    sdata->read_enabled = enabled;
    if (sdata->in_read || sdata->in_open ||
			(sdata->data_pending_len && !enabled)) {
	/* Nothing to do, let the read/open handling wake things up. */
    } else if (sdata->data_pending_len) {
	sdata->deferred_read = true;
	sdata->in_read = true;
	if (!sdata->deferred_op_pending) {
	    /* Call the read from the selector to avoid lock nesting issues. */
	    sdata->deferred_op_pending = true;
	    sdata->o->run(sdata->deferred_op_runner);
	}
    } else {
	genio_set_read_callback_enable(sdata->child, enabled);
    }
 out_unlock:
    stel_unlock(sdata);
}

static void
stel_set_write_callback_enable(struct genio *io, bool enabled)
{
    struct stel_data *sdata = mygenio_to_stel(io);

    stel_lock(sdata);
    if (sdata->closed)
	goto out_unlock;
    if (sdata->xmit_enabled != enabled) {
	sdata->xmit_enabled = enabled;
	if ((enabled || !sdata->xmit_buf_len) && !sdata->in_open)
	    /* Only disable if we don't have data pending. */
	    genio_set_write_callback_enable(sdata->child, enabled);
    }
 out_unlock:
    stel_unlock(sdata);
}

static const struct genio_functions stel_io_funcs = {
    .write = stel_write,
    .raddr_to_str = stel_raddr_to_str,
    .get_raddr = stel_get_raddr,
    .open = stel_open,
    .close = stel_close,
    .free = stel_free,
    .set_read_callback_enable = stel_set_read_callback_enable,
    .set_write_callback_enable = stel_set_write_callback_enable
};

static unsigned int
stel_genio_read(struct genio *io, int readerr,
		unsigned char *ibuf, unsigned int buflen,
		unsigned int flags)
{
    struct stel_data *sdata = genio_get_user_data(io);
    struct genio *myio = sdata->sio.io;
    unsigned char *buf = ibuf;
    unsigned int count = 0, len;

    stel_lock(sdata);
    if (sdata->in_open && readerr) {
	stel_unlock(sdata);
	if (sdata->open_done)
	    sdata->open_done(sdata->sio.io, readerr, sdata->open_data);
	stel_lock(sdata);
	sdata->open_wait_count = 0;
	sdata->in_open = false;
	sdata->closed = true;
	sdata->o->stop_timer(sdata->timer);
	goto out_unlock;
    }

    if (!sdata->in_open && (!sdata->read_enabled || sdata->data_pending_len))
	goto out_unlock;

    if (readerr) {
	/* Do this here so the user can modify it. */
	sdata->read_enabled = false;
	stel_unlock(sdata);
	myio->cbs->read_callback(sdata->sio.io, readerr, NULL, 0, 0);
	goto out_unlock;
    }

    genio_set_read_callback_enable(sdata->child, false);
    sdata->data_pos = 0;

    while (sdata->in_urgent && buflen) {
	if (sdata->in_urgent == 2) {
	    if (*buf == TN_DATA_MARK)
		sdata->in_urgent = 0;
	    else
		sdata->in_urgent = 1;
	} else if (*buf == TN_IAC) {
	    sdata->in_urgent = 2;
	}
	buf++;
	buflen--;
    }

 process_more:
    sdata->in_read = true;
    stel_unlock(sdata);
    len = process_telnet_data(sdata->read_data,
			      sizeof(sdata->read_data),
			      &buf, &buflen,
			      &sdata->tn_data);
    stel_lock(sdata);
    sdata->in_read = false;
    sdata->data_pending_len = len;
    if (sdata->data_pending_len) {
	if (sdata->in_open)
	    /* Ignore user data until we get the telnet com port do/dont. */
	    count = sdata->data_pending_len;
	else if (sdata->read_enabled) {
	retry:
	    sdata->in_read = true;
	    stel_unlock(sdata);
	    count = myio->cbs->read_callback(sdata->sio.io, 0,
					     sdata->read_data,
					     sdata->data_pending_len, 0);
	    stel_lock(sdata);
	    stel_finish_read(sdata, count);
	    if (sdata->data_pending_len)
		goto retry;
	} else {
	    count = 0;
	}
	if (count == sdata->data_pending_len && buflen)
	    goto process_more;
    }

    if ((!buflen && sdata->read_enabled) || sdata->in_open)
	genio_set_read_callback_enable(sdata->child, true);

 out_unlock:
    stel_unlock(sdata);

    return buf - ibuf;
}

static int
buffer_genio_write(void *cbdata, void *buf, size_t buflen, size_t *rwritten)
{
    struct genio *io = cbdata;
    int err;
    unsigned int written;

    err = genio_write(io, &written, buf, buflen);
    if (err)
	return err;
    *rwritten = written;
    return 0;
}

void
stel_genio_write(struct genio *io)
{
    struct stel_data *sdata = genio_get_user_data(io);
    bool do_cb = true;

    stel_lock(sdata);
    if (buffer_cursize(&sdata->tn_data.out_telnet_cmd) > 0) {
	int err;

	if (buffer_write(buffer_genio_write, io,
			 &sdata->tn_data.out_telnet_cmd, &err) == -1) {
	    sdata->saved_xmit_err = err;
	    if (buffer_cursize(&sdata->tn_data.out_telnet_cmd) > 0) {
		/* Still data to transmit. */
		do_cb = false;
		goto out_unlock;
	    }
	}
    }
    if (sdata->xmit_buf_len) {
	int err;
	unsigned int written;

	err = genio_write(io, &written, sdata->xmit_buf + sdata->xmit_buf_curr,
			  sdata->xmit_buf_len - sdata->xmit_buf_curr);
	if (err) {
	    sdata->saved_xmit_err = err;
	    sdata->xmit_buf_len = 0;
	} else {
	    sdata->xmit_buf_curr += written;
	    if (sdata->xmit_buf_curr == sdata->xmit_buf_len)
		sdata->xmit_buf_len = 0;
	    else
		/* Still more data to write. */
		do_cb = false;
	}
    }
 out_unlock:
    stel_unlock(sdata);

    if (do_cb) {
	if (!sdata->xmit_enabled)
	    genio_set_write_callback_enable(sdata->child, false);
	sdata->sio.io->cbs->write_callback(sdata->sio.io);
    }
}

void
stel_genio_urgent(struct genio *io)
{
    struct stel_data *sdata = genio_get_user_data(io);

    stel_lock(sdata);
    sdata->in_urgent = 1;
    sdata->data_pending_len = 0;
    stel_unlock(sdata);
    genio_set_read_callback_enable(sdata->child, true);
}

static const struct genio_callbacks stel_genio_callbacks = {
    .read_callback = stel_genio_read,
    .write_callback = stel_genio_write,
    .urgent_callback = stel_genio_urgent,
};

static void
sergenio_telnet_output_ready(void *cb_data)
{
    struct stel_data *sdata = cb_data;

    genio_set_write_callback_enable(sdata->child, true);
}

static void
sergenio_telnet_cmd_handler(void *cb_data, unsigned char cmd)
{
}

static int
com_port_will_do(void *cb_data, unsigned char cmd)
{
    struct stel_data *sdata = cb_data;

    if (cmd != TN_DO && cmd != TN_DONT)
	/* We only handle these. */
	return 0;

    if (cmd == TN_DONT)
	/* The remote end turned off RFC2217 handling. */
	sdata->do_2217 = false;
    else
	sdata->do_2217 = sdata->allow_2217;

    if (sdata->in_open) {
	if (sdata->open_done)
	    sdata->open_done(sdata->sio.io, 0, sdata->open_data);
	sdata->in_open = false;
	sdata->open_wait_count = 0;
	genio_set_write_callback_enable(sdata->child, sdata->xmit_enabled);
    }

    return 1;
}

static void
com_port_handler(void *cb_data, unsigned char *option, int len)
{
    struct stel_data *sdata = cb_data;
    int val = 0, cmd;
    struct stel_req *curr, *prev = NULL;

    if (len < 2)
	return;
    if (option[1] < 100)
	return;
    cmd = option[1] - 100;

    switch (cmd) {
    case 1:
	if (len == 3) {
	    sdata->cisco_baud = true;
	    val = cisco_baud_to_baud(option[2]);
	} else if (len >= 6) {
	    val = option[2] << 24;
	    val |= option[3] << 16;
	    val |= option[4] << 8;
	    val |= option[5];
	}
	break;

    default:
	if (len == 3)
	    val = option[2];
	break;
    }

    stel_lock(sdata);
    curr = sdata->reqs;
    while (curr && curr->option != cmd &&
			val >= curr->minval && val <= curr->maxval) {
	prev = curr;
	curr = curr->next;
    }
    if (curr) {
	if (prev)
	    prev->next = curr->next;
	else
	    sdata->reqs = curr->next;
    }
    stel_unlock(sdata);

    if (curr) {
	if (curr->done)
	    curr->done(&sdata->sio, 0, val - curr->minval, curr->cb_data);
	sdata->o->free(sdata->o, curr);
    }
}

static const struct telnet_cmd sergenio_telnet_cmds[] = {
    /*                        I will,  I do,  sent will, sent do */
    { TN_OPT_SUPPRESS_GO_AHEAD,	   1,     0,          0,       0, },
    { TN_OPT_ECHO,		   1,     0,          0,       0, },
    { TN_OPT_BINARY_TRANSMISSION,  1,     1,          0,       0, },
    { TN_OPT_COM_PORT,		   1,     0,          1,       0,
      .option_handler = com_port_handler, .will_do_handler = com_port_will_do },
    { TELNET_CMD_END_OPTION }
};

static const unsigned char sergenio_telnet_init_seq[] = {
    TN_IAC, TN_WILL, TN_OPT_COM_PORT,
};

static void
sergenio_telnet_timeout(struct genio_timer *timer, void *cb_data)
{
    struct stel_data *sdata = cb_data;
    struct timeval timeout;
    struct stel_req *req, *curr, *prev = NULL, *to_complete = NULL;

    stel_lock(sdata);
    if (sdata->close_count) {
	stel_unlock(sdata);
	return;
    }

    if (sdata->open_wait_count) {
	if (--sdata->open_wait_count == 0) {
	    stel_unlock(sdata);
	    if (sdata->open_done)
		sdata->open_done(sdata->sio.io, ETIMEDOUT, sdata->open_data);
	    stel_lock(sdata);
	    sdata->in_open = false;
	    sdata->closed = true;
	    sdata->o->stop_timer(sdata->timer);
	    stel_unlock(sdata);
	    return;
	}
    }

    req = sdata->reqs;
    while (req) {
	if (--req->time_left == 0) {
	    if (!prev)
		sdata->reqs = req->next;
	    else
		prev->next = req->next;
	    req->next = NULL;
	    curr = to_complete;
	    if (!curr) {
		to_complete = req;
	    } else {
		while (curr->next)
		    curr = curr->next;
		curr->next = req;
	    }
	} else {
	    prev = req;
	    req = req->next;
	}
    }
    stel_unlock(sdata);

    req = to_complete;
    while (req) {
	req->done(&sdata->sio, ETIMEDOUT, 0, req->cb_data);
	prev = req;
	req = req->next;
	sdata->o->free(sdata->o, prev);
    }

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    sdata->o->start_timer(timer, &timeout);
}

static int
sergenio_process_args(struct stel_data *sdata, char *args[])
{
    unsigned int i;

    if (!args)
	return 0;

    for (i = 0; args[i]; i++) {
	const char *val;

	if (cmpstrval(args[i], "rfc2217=", &val)) {
	    if ((strcmp(val, "true") == 0) || (strcmp(val, "1") == 0))
		sdata->allow_2217 = true;
	    else if ((strcmp(val, "false") == 0) || (strcmp(val, "0") == 0))
		sdata->allow_2217 = false;
	    else
		return EINVAL;
	} else {
	    return EINVAL;
	}
    }

    return 0;
}

int
sergenio_telnet_alloc(struct genio *child, char *args[],
		      struct genio_os_funcs *o,
		      const struct sergenio_callbacks *scbs,
		      const struct genio_callbacks *cbs, void *user_data,
		      struct sergenio **sio)
{
    struct stel_data *sdata = o->zalloc(o, sizeof(*sdata));
    int err;

    if (!sdata)
	return ENOMEM;

    sdata->allow_2217 = true;

    err = sergenio_process_args(sdata, args);
    if (err)
	goto out_err;

    sdata->lock = o->alloc_lock(o);
    if (!sdata->lock)
	goto out_nomem;

    sdata->timer = o->alloc_timer(o, sergenio_telnet_timeout, sdata);
    if (!sdata->timer)
	goto out_nomem;

    sdata->deferred_op_runner = o->alloc_runner(o, stel_deferred_op, sdata);
    if (!sdata->deferred_op_runner)
	goto out_nomem;

    sdata->sio.io = o->zalloc(o, sizeof(*sdata->sio.io));
    if (!sdata->sio.io)
	goto out_nomem;

    sdata->o = o;
    sdata->child = child;
    sdata->sio.scbs = scbs;
    sdata->sio.io->parent_object = &sdata->sio;
    sdata->sio.io->user_data = user_data;
    sdata->sio.funcs = &stel_funcs;
    sdata->sio.io->cbs = cbs;
    sdata->sio.io->funcs = &stel_io_funcs;
    sdata->sio.io->type = GENIO_TYPE_SER_TELNET;
    sdata->sio.io->is_client = true;
    genio_set_callbacks(child, &stel_genio_callbacks, sdata);
    sdata->closed = true;

    err = telnet_init(&sdata->tn_data, sdata, sergenio_telnet_output_ready,
		      sergenio_telnet_cmd_handler, sergenio_telnet_cmds,
		      sergenio_telnet_init_seq,
		      sdata->allow_2217 ? sizeof(sergenio_telnet_init_seq) : 0);
    if (err)
	goto out_err;

    *sio = &sdata->sio;

    return 0;

 out_nomem:
    err = ENOMEM;
 out_err:
    stel_free_data(sdata);
    return err;
}
