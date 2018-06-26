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

#include "utils/utils.h"
#include "utils/locking.h"
#include "utils/telnet.h"

#include "sergenio_internal.h"

#define SERCTL_WAIT_TIME 5

struct stel_req {
    int option;
    int minval;
    int maxval;
    void (*done)(struct sergenio *snet, int err, int val, void *cb_data);
    void *cb_data;
    int time_left;
    struct stel_req *next;
};

struct stel_data {
    struct sergenio snet;

    DEFINE_LOCK(, lock);

    struct sel_timer_s *timer;

    bool in_free;
    bool closed;
    unsigned int close_count;

    void (*close_done)(struct genio *net);

    struct genio *net;

    unsigned char recv_buf[1024];
    unsigned int recv_buf_curr;
    unsigned int recv_buf_len;
    int in_urgent;

    struct telnet_data_s tn_data;
    bool cisco_baud;

    bool xmit_enabled;

    unsigned char xmit_buf[1024];
    unsigned int xmit_buf_curr;
    unsigned int xmit_buf_len;
    int saved_xmit_err;

    struct stel_req *reqs;
};

#define mygenio_to_stel(v) container_of(v, struct stel_data, snet.net)
#define mysergenio_to_stel(v) container_of(v, struct stel_data, snet)

static int
stel_queue(struct stel_data *sdata, int option, 
	   int minval, int maxval,
	   void (*done)(struct sergenio *snet, int err,
			int baud, void *cb_data),
	   void *cb_data)
{
    struct stel_req *curr, *req = malloc(sizeof(*req));
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

    LOCK(sdata->lock);
    curr = sdata->reqs;
    if (!curr) {
	sdata->reqs = curr;
    } else {
	while (curr->next)
	    curr = curr->next;
	curr->next = req;
    }
    UNLOCK(sdata->lock);

    return 0;
}

static int
stel_baud(struct sergenio *snet, int baud,
	  void (*done)(struct sergenio *snet, int err,
		       int baud, void *cb_data),
	  void *cb_data)
{
    struct stel_data *sdata = mysergenio_to_stel(snet);
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
stel_queue_and_send(struct sergenio *snet, int option, int val,
		    int minval, int maxval,
		    void (*done)(struct sergenio *snet, int err, int datasize,
				 void *cb_data),
		    void *cb_data)
{
    struct stel_data *sdata = mysergenio_to_stel(snet);
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
stel_datasize(struct sergenio *snet, int datasize,
	      void (*done)(struct sergenio *snet, int err, int datasize,
			   void *cb_data),
	      void *cb_data)
{
    return stel_queue_and_send(snet, 2, datasize, 0, 0, done, cb_data);
}

static int
stel_parity(struct sergenio *snet, int parity,
	    void (*done)(struct sergenio *snet, int err, int parity,
			 void *cb_data),
	    void *cb_data)
{
    return stel_queue_and_send(snet, 3, parity, 0, 0, done, cb_data);
}

static int
stel_stopbits(struct sergenio *snet, int stopbits,
	      void (*done)(struct sergenio *snet, int err, int stopbits,
			   void *cb_data),
	      void *cb_data)
{
    return stel_queue_and_send(snet, 4, stopbits, 0, 0, done, cb_data);
}

static int
stel_flowcontrol(struct sergenio *snet, int flowcontrol,
		 void (*done)(struct sergenio *snet, int err,
			      int flowcontrol, void *cb_data),
		 void *cb_data)
{
    return stel_queue_and_send(snet, 5, flowcontrol, 0, 3, done, cb_data);
}

static int
stel_breakv(struct sergenio *snet, int breakv,
	    void (*done)(struct sergenio *snet, int err, int breakv,
			 void *cb_data),
	    void *cb_data)
{
    return stel_queue_and_send(snet, 5, breakv, 4, 6, done, cb_data);
}

static int
stel_dtr(struct sergenio *snet, int dtr,
	 void (*done)(struct sergenio *snet, int err, int dtr,
		      void *cb_data),
	 void *cb_data)
{
    return stel_queue_and_send(snet, 5, dtr, 7, 9, done, cb_data);
}

static int
stel_rts(struct sergenio *snet, int rts,
	 void (*done)(struct sergenio *snet, int err, int rts,
		      void *cb_data),
	 void *cb_data)
{
    return stel_queue_and_send(snet, 5, rts, 10, 12, done, cb_data);
}

static const struct sergenio_functions stel_funcs = {
    .baud = stel_baud,
    .datasize = stel_datasize,
    .parity = stel_parity,
    .stopbits = stel_stopbits,
    .flowcontrol = stel_flowcontrol,
    .breakv = stel_breakv,
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

    LOCK(sdata->lock);
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
    err = genio_write(sdata->net, &sdata->xmit_buf_curr,
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
    UNLOCK(sdata->lock);
    return err;
}

static int
stel_raddr_to_str(struct genio *net, int *pos,
		  char *buf, unsigned int buflen)
{
    struct stel_data *sdata = mygenio_to_stel(net);

    return genio_raddr_to_str(sdata->net, pos, buf, buflen);
}

static socklen_t
stel_get_raddr(struct genio *net,
	       struct sockaddr *addr, socklen_t addrlen)
{
    struct stel_data *sdata = mygenio_to_stel(net);

    return genio_get_raddr(sdata->net, addr, addrlen);
}

static void
stel_finish_free(struct stel_data *sdata)
{
    struct stel_req *req, *prev;

    genio_free(sdata->net);
    sel_free_timer(sdata->timer);
    telnet_cleanup(&sdata->tn_data);
    req = sdata->reqs;
    while (req) {
	prev = req;
	req = req->next;
	free(prev);
    }
    free(sdata);
}

static void
check_finish_close(struct stel_data *sdata)
{
    LOCK(sdata->lock);
    if (sdata->close_count > 1) {
	sdata->close_count--;
	UNLOCK(sdata->lock);
	return;
    }
    UNLOCK(sdata->lock);

    if (sdata->close_done)
	sdata->close_done(&sdata->snet.net);

    LOCK(sdata->lock);
    sdata->close_count--; /* Keep stel_free() from freeing it. */
    if (sdata->in_free) {
	UNLOCK(sdata->lock);
	stel_finish_free(sdata);
    } else {
	UNLOCK(sdata->lock);
    }
}

static void
stel_timer_stopped(struct selector_s *sel,
		  struct sel_timer_s *timer,
		  void *cb_data)
{
    check_finish_close(cb_data);
}

static void
stel_genio_close_done(struct genio *net)
{
    struct stel_data *sdata = genio_get_user_data(net);

    check_finish_close(sdata);
}

static int
stel_open(struct genio *net)
{
    struct stel_data *sdata = genio_get_user_data(net);
    struct timeval timeout;
    int err;

    LOCK(sdata->lock);
    if (sdata->closed && !sdata->close_count)
    err = genio_open(sdata->net);

    if (!err) {
	sel_get_monotonic_time(&timeout);
	timeout.tv_sec += 1;
	sel_start_timer(sdata->timer, &timeout);
    }

    return err;
}

static void
__stel_close(struct stel_data *sdata, void (*close_done)(struct genio *net))
{
    sdata->close_done = close_done;
    sdata->closed = true;
    sdata->close_count = 2; /* One for timer and one for genio. */
    UNLOCK(sdata->lock);
    sel_stop_timer_with_done(sdata->timer, stel_timer_stopped, sdata);
    genio_close(sdata->net, stel_genio_close_done);
}

static int
stel_close(struct genio *net, void (*close_done)(struct genio *net))
{
    struct stel_data *sdata = mygenio_to_stel(net);
    int err = 0;

    LOCK(sdata->lock);
    if (sdata->closed || sdata->close_count) {
	UNLOCK(sdata->lock);
	err = EBUSY;
    } else {
	__stel_close(sdata, close_done); /* Releases lock. */
    }

    return err;
}

static void
stel_free(struct genio *net)
{
    struct stel_data *sdata = mygenio_to_stel(net);

    LOCK(sdata->lock);
    if (sdata->close_count) {
	sdata->in_free = true;
	sdata->close_done = NULL;
	UNLOCK(sdata->lock);
    } else if (sdata->closed) {
	UNLOCK(sdata->lock);
	stel_finish_free(sdata);
    } else {
	__stel_close(sdata, NULL); /* Releases lock */
    }
}

static void
stel_set_read_callback_enable(struct genio *net, bool enabled)
{
    struct stel_data *sdata = mygenio_to_stel(net);

    genio_set_read_callback_enable(sdata->net, enabled);
}

static void
stel_set_write_callback_enable(struct genio *net, bool enabled)
{
    struct stel_data *sdata = mygenio_to_stel(net);

    LOCK(sdata->lock);
    if (sdata->xmit_enabled != enabled) {
	sdata->xmit_enabled = enabled;
	if (enabled || !sdata->xmit_buf_len)
	    /* Only disable if we don't have data pending. */
	    genio_set_write_callback_enable(sdata->net, enabled);
    }
    UNLOCK(sdata->lock);
}

static const struct genio_functions stel_net_funcs = {
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
stel_genio_read(struct genio *net, int readerr,
		unsigned char *ibuf, unsigned int buflen,
		unsigned int flags)
{
    struct stel_data *sdata = genio_get_user_data(net);
    struct genio *mynet = &sdata->snet.net;
    unsigned char *buf = ibuf;

    if (readerr) {
	mynet->cbs->read_callback(&sdata->snet.net, readerr,
				  NULL, 0, 0);
	return 0;
    }

    LOCK(sdata->lock);
    if (sdata->recv_buf_len)
	goto out_shutdown;

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
    sdata->recv_buf_len = process_telnet_data(sdata->recv_buf,
					      sizeof(sdata->recv_buf),
					      &buf, &buflen, &sdata->tn_data);

    if (!sdata->recv_buf_len)
	goto out_unlock;

    sdata->recv_buf_curr = mynet->cbs->read_callback(&sdata->snet.net, 0,
						     sdata->recv_buf,
						     sdata->recv_buf_len, 0);
    if (sdata->recv_buf_curr == sdata->recv_buf_len) {
	if (buflen)
	    goto process_more;
	sdata->recv_buf_len = 0;
    }

 out_shutdown:
    if (sdata->recv_buf_len)
	genio_set_read_callback_enable(sdata->net, false);
out_unlock:
    UNLOCK(sdata->lock);
    
    return ibuf - buf;
}

void
stel_genio_write(struct genio *net)
{
    struct stel_data *sdata = genio_get_user_data(net);
    bool do_cb = true;

    LOCK(sdata->lock);
    if (sdata->xmit_buf_len) {
	int err;
	unsigned int written;

	err = genio_write(net, &written, sdata->xmit_buf + sdata->xmit_buf_curr,
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
    UNLOCK(sdata->lock);

    if (do_cb) {
	if (!sdata->xmit_enabled)
	    genio_set_write_callback_enable(sdata->net, false);
	sdata->snet.net.cbs->write_callback(&sdata->snet.net);
    }
}

void
stel_genio_urgent(struct genio *net)
{
    struct stel_data *sdata = genio_get_user_data(net);

    LOCK(sdata->lock);
    sdata->in_urgent = 1;
    sdata->recv_buf_len = 0;
    UNLOCK(sdata->lock);
    genio_set_read_callback_enable(sdata->net, true);
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

    genio_set_write_callback_enable(sdata->net, true);
}

static void
sergenio_telnet_cmd_handler(void *cb_data, unsigned char cmd)
{
}

static void
com_port_handler(void *cb_data, unsigned char *option, int len)
{
    struct stel_data *sdata = cb_data;
    int val = 0;
    struct stel_req *curr, *prev = NULL;

    if (len < 2)
	return;

    switch (option[1]) {
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

    LOCK(sdata->lock);
    curr = sdata->reqs;
    while (curr && curr->option != option[1] &&
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
    UNLOCK(sdata->lock);

    if (curr) {
	if (curr->done)
	    curr->done(&sdata->snet, 0, val, curr->cb_data);
	free(curr);
    }
}

static const struct telnet_cmd sergenio_telnet_cmds[] = {
    /*                        I will,  I do,  sent will, sent do */
    { TN_OPT_SUPPRESS_GO_AHEAD,	   1,     0,          0,       0, },
    { TN_OPT_ECHO,		   1,     0,          0,       0, },
    { TN_OPT_BINARY_TRANSMISSION,  1,     1,          0,       0, },
    { TN_OPT_COM_PORT,		   1,     1,          0,       0,
      .option_handler = com_port_handler },
    { TELNET_CMD_END_OPTION }
};

static const unsigned char sergenio_telnet_init_seq[] = { };

static void
sergenio_telnet_timeout(struct selector_s *sel, struct sel_timer_s *timer,
			void *cb_data)
{
    struct stel_data *sdata = cb_data;
    struct timeval timeout;
    struct stel_req *req, *curr, *prev = NULL, *to_complete = NULL;

    LOCK(sdata->lock);
    if (sdata->close_count) {
	UNLOCK(sdata->lock);
	return;
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
    UNLOCK(sdata->lock);

    req = to_complete;
    while (req) {
	req->done(&sdata->snet, ETIMEDOUT, 0, req->cb_data);
	prev = req;
	req = req->next;
	free(prev);
    }

    sel_get_monotonic_time(&timeout);
    timeout.tv_sec += 1;
    sel_start_timer(timer, &timeout);
}

int
sergenio_telnet_alloc(struct genio *net, struct selector_s *sel,
		      struct sergenio_callbacks *scbs,
		      struct genio_callbacks *cbs, void *user_data,
		      struct sergenio **snet)
{
    struct stel_data *sdata = malloc(sizeof(*sdata));
    int err;

    if (!sdata)
	return ENOMEM;

    err = sel_alloc_timer(sel, sergenio_telnet_timeout, sdata, &sdata->timer);
    if (err) {
	free(sdata);
	return err;
    }

    sdata->net = net;
    sdata->snet.scbs = scbs;
    sdata->snet.net.user_data = user_data;
    sdata->snet.funcs = &stel_funcs;
    sdata->snet.net.cbs = cbs;
    sdata->snet.net.funcs = &stel_net_funcs;
    genio_set_callbacks(net, &stel_genio_callbacks, sdata);

    err = telnet_init(&sdata->tn_data, sdata, sergenio_telnet_output_ready,
		      sergenio_telnet_cmd_handler, sergenio_telnet_cmds,
		      sergenio_telnet_init_seq,
		      sizeof(sergenio_telnet_init_seq));
    if (err) {
	sel_free_timer(sdata->timer);
	free(sdata);
    }

    return err;
}
