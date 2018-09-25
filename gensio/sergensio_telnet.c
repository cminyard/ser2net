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
#include <stdio.h>

#include <utils/utils.h>
#include <utils/telnet.h>

#include <gensio/sergensio_internal.h>
#include <gensio/gensio_ll_gensio.h>
#include <gensio/gensio_filter_telnet.h>
#include <gensio/gensio_acc_gensio.h>

#define SERCTL_WAIT_TIME 5

struct stel_req {
    int option;
    int minval;
    int maxval;
    void (*done)(struct sergensio *sio, int err, int val, void *cb_data);
    void (*donesig)(struct sergensio *sio, int err, char *sig,
		    unsigned int sig_len, void *cb_data);
    void *cb_data;
    int time_left;
    struct stel_req *next;
};

struct stel_data {
    struct sergensio *sio;

    struct gensio_os_funcs *o;

    struct gensio_filter *filter;
    const struct gensio_telnet_filter_rops *rops;
    struct gensio_lock *lock;

    bool allow_2217;
    bool do_2217;
    bool cisco_baud;
    bool reported_modemstate;

    struct stel_req *reqs;
};

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
	   void (*done)(struct sergensio *sio, int err,
			int baud, void *cb_data),
	   void (*donesig)(struct sergensio *sio, int err, char *sig,
			   unsigned int sig_len, void *cb_data),
	   void *cb_data)
{
    struct stel_req *curr, *req;
    struct timeval timeout;

    if (!sdata->do_2217)
	return ENOTSUP;

    req = sdata->o->zalloc(sdata->o, sizeof(*req));
    if (!req)
	return ENOMEM;

    req->option = option;
    req->done = done;
    req->donesig = donesig;
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

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    sdata->rops->start_timer(sdata->filter, &timeout);

    return 0;
}

static int
stel_baud(struct sergensio *sio, int baud,
	  void (*done)(struct sergensio *sio, int err,
		       int baud, void *cb_data),
	  void *cb_data)
{
    struct stel_data *sdata = sergensio_get_gensio_data(sio);
    bool is_client = gensio_is_client(sergensio_to_gensio(sio));
    unsigned char buf[6];
    int err;

    if (is_client) {
	err = stel_queue(sdata, 1, 0, 0, done, NULL, cb_data);
	if (err)
	    return err;
	buf[1] = 1;
    } else {
	buf[1] = 101;
    }

    buf[0] = 44;
    if (sdata->cisco_baud) {
	buf[2] = baud_to_cisco_baud(baud);
	sdata->rops->send_option(sdata->filter, buf, 3);
    } else {
	buf[2] = baud >> 24;
	buf[3] = baud >> 16;
	buf[4] = baud >> 8;
	buf[5] = baud;
	sdata->rops->send_option(sdata->filter, buf, 6);
    }
    return 0;
}

static int
stel_queue_and_send(struct sergensio *sio, int option, int val,
		    int xmitbase, int minval, int maxval,
		    void (*done)(struct sergensio *sio, int err, int val,
				 void *cb_data),
		    void *cb_data)
{
    struct stel_data *sdata = sergensio_get_gensio_data(sio);
    unsigned char buf[3];
    bool is_client = gensio_is_client(sergensio_to_gensio(sio));
    int err;

    if (val < minval || val > maxval)
	return EINVAL;

    if (is_client) {
	err = stel_queue(sdata, option, xmitbase, xmitbase + maxval,
			 done, NULL, cb_data);
	if (err)
	    return err;
    } else {
	option += 100;
    }

    buf[0] = 44;
    buf[1] = option;
    buf[2] = val + xmitbase;
    sdata->rops->send_option(sdata->filter, buf, 3);

    return 0;
}

static int
stel_datasize(struct sergensio *sio, int datasize,
	      void (*done)(struct sergensio *sio, int err, int datasize,
			   void *cb_data),
	      void *cb_data)
{
    return stel_queue_and_send(sio, 2, datasize, 0, 0, 8, done, cb_data);
}

static int
stel_parity(struct sergensio *sio, int parity,
	    void (*done)(struct sergensio *sio, int err, int parity,
			 void *cb_data),
	    void *cb_data)
{
    return stel_queue_and_send(sio, 3, parity, 0, 0, 5, done, cb_data);
}

static int
stel_stopbits(struct sergensio *sio, int stopbits,
	      void (*done)(struct sergensio *sio, int err, int stopbits,
			   void *cb_data),
	      void *cb_data)
{
    return stel_queue_and_send(sio, 4, stopbits, 0, 0, 3, done, cb_data);
}

static int
stel_flowcontrol(struct sergensio *sio, int flowcontrol,
		 void (*done)(struct sergensio *sio, int err,
			      int flowcontrol, void *cb_data),
		 void *cb_data)
{
    return stel_queue_and_send(sio, 5, flowcontrol, 0, 0, 3, done, cb_data);
}

static int
stel_iflowcontrol(struct sergensio *sio, int iflowcontrol,
		  void (*done)(struct sergensio *sio, int err,
			       int iflowcontrol, void *cb_data),
		  void *cb_data)
{
    return stel_queue_and_send(sio, 5, iflowcontrol, 13, 0, 6, done, cb_data);
}

static int
stel_sbreak(struct sergensio *sio, int breakv,
	    void (*done)(struct sergensio *sio, int err, int breakv,
			 void *cb_data),
	    void *cb_data)
{
    return stel_queue_and_send(sio, 5, breakv, 4, 0, 2, done, cb_data);
}

static int
stel_dtr(struct sergensio *sio, int dtr,
	 void (*done)(struct sergensio *sio, int err, int dtr,
		      void *cb_data),
	 void *cb_data)
{
    return stel_queue_and_send(sio, 5, dtr, 7, 0, 2, done, cb_data);
}

static int
stel_rts(struct sergensio *sio, int rts,
	 void (*done)(struct sergensio *sio, int err, int rts,
		      void *cb_data),
	 void *cb_data)
{
    return stel_queue_and_send(sio, 5, rts, 10, 0, 2, done, cb_data);
}

static int
stel_signature(struct sergensio *sio, char *sig, unsigned int sig_len,
	       void (*done)(struct sergensio *sio, int err, char *sig,
			    unsigned int sig_len, void *cb_data),
	       void *cb_data)
{
    struct stel_data *sdata = sergensio_get_gensio_data(sio);
    unsigned char outopt[MAX_TELNET_CMD_XMIT_BUF];
    bool is_client = gensio_is_client(sergensio_to_gensio(sio));

    if (sig_len > (MAX_TELNET_CMD_XMIT_BUF - 2))
	sig_len = MAX_TELNET_CMD_XMIT_BUF - 2;

    if (is_client) {
	int err = stel_queue(sdata, 0, 0, 0, NULL, done, cb_data);
	if (err)
	    return err;

	outopt[0] = 44;
	outopt[1] = 0;
	sdata->rops->send_option(sdata->filter, outopt, 2);
    } else {
	outopt[0] = 44;
	outopt[1] = 100;
	strncpy((char *) outopt + 2, sig, sig_len);

	sdata->rops->send_option(sdata->filter, outopt, sig_len + 2);
    }

    return 0;
}

static int
stel_send(struct sergensio *sio, unsigned int opt, unsigned int val)
{
    struct stel_data *sdata = sergensio_get_gensio_data(sio);
    unsigned char buf[3];

    buf[0] = 44;
    buf[1] = opt;
    buf[2] = val;

    if (!sergensio_is_client(sio))
	buf[1] += 100;

    sdata->rops->send_option(sdata->filter, buf, 3);

    return 0;
}

static int
stel_modemstate(struct sergensio *sio, unsigned int val)
{
    unsigned int opt;

    if (sergensio_is_client(sio))
	opt = 11;
    else
	opt = 7;
    return stel_send(sio, opt, val);
}

static int
stel_linestate(struct sergensio *sio, unsigned int val)
{
    unsigned int opt;

    if (sergensio_is_client(sio))
	opt = 10;
    else
	opt = 6;
    return stel_send(sio, opt, val);
}

static int
stel_flowcontrol_state(struct sergensio *sio, bool val)
{
    struct stel_data *sdata = sergensio_get_gensio_data(sio);
    unsigned char buf[2];

    buf[0] = 44;

    if (val)
	buf[1] = 8;
    else
	buf[1] = 9;
    if (!sergensio_is_client(sio))
	buf[1] += 100;

    sdata->rops->send_option(sdata->filter, buf, 2);

    return 0;
}

static int
stel_flush(struct sergensio *sio, unsigned int val)
{
    return stel_send(sio, 12, val);
}

static const struct sergensio_functions stel_funcs = {
    .baud = stel_baud,
    .datasize = stel_datasize,
    .parity = stel_parity,
    .stopbits = stel_stopbits,
    .flowcontrol = stel_flowcontrol,
    .iflowcontrol = stel_iflowcontrol,
    .sbreak = stel_sbreak,
    .dtr = stel_dtr,
    .rts = stel_rts,
    .modemstate = stel_modemstate,
    .linestate = stel_linestate,
    .flowcontrol_state = stel_flowcontrol_state,
    .flush = stel_flush,
    .signature = stel_signature
};

static int
stel_com_port_will_do(void *handler_data, unsigned char cmd)
{
    struct stel_data *sdata = handler_data;

    if (cmd != TN_DO && cmd != TN_DONT)
	/* We only handle these. */
	return 0;

    if (cmd == TN_DONT)
	/* The remote end turned off RFC2217 handling. */
	sdata->do_2217 = false;
    else
	sdata->do_2217 = sdata->allow_2217;

    return sdata->do_2217;
}

static void
stel_com_port_cmd(void *handler_data, const unsigned char *option,
		  unsigned int len)
{
    struct stel_data *sdata = handler_data;
    int val = 0, cmd;
    struct stel_req *curr, *prev = NULL;
    char *sig = NULL;
    unsigned int sig_len, vlen = sizeof(int);
    struct gensio *io = sergensio_to_gensio(sdata->sio);

    if (len < 2)
	return;
    if (option[1] < 100)
	return;
    cmd = option[1] - 100;

    switch (cmd) {
    case 0:
	sig = (char *) (option + 2);
	sig_len = len - 2;
	break;

    case 1:
	if (len < 3)
	    return;
	if (len < 6) {
	    sdata->cisco_baud = true;
	    val = cisco_baud_to_baud(option[2]);
	} else {
	    val = option[2] << 24;
	    val |= option[3] << 16;
	    val |= option[4] << 8;
	    val |= option[5];
	}
	break;

    case 6:
	if (len < 3)
	    return;
	val = option[2];
	gensio_cb(io, GENSIO_EVENT_SER_LINESTATE, 0,
		  (unsigned char *) &val, &vlen, 0, NULL);
	return;

    case 7:
	if (len < 3)
	    return;
	val = option[2];
	gensio_cb(io, GENSIO_EVENT_SER_MODEMSTATE, 0,
		  (unsigned char *) &val, &vlen, 0, NULL);
	return;

    case 8:
	val = 1;
	gensio_cb(io, GENSIO_EVENT_SER_FLOWCONTROL, 0,
		  (unsigned char *) &val, &vlen, 0, NULL);
	return;

    case 9:
	val = 0;
	gensio_cb(io, GENSIO_EVENT_SER_FLOWCONTROL, 0,
		  (unsigned char *) &val, &vlen, 0, NULL);
	return;

    case 12:
	if (len < 3)
	    return;
	val = option[2];
	gensio_cb(io, GENSIO_EVENT_SER_FLUSH, 0,
		  (unsigned char *) &val, &vlen, 0, NULL);
	return;

    default:
	if (len < 3)
	    return;
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
	if (sig) {
	    if (curr->donesig)
		curr->donesig(sdata->sio, 0, sig, sig_len, curr->cb_data);
	} else {
	    if (curr->done)
		curr->done(sdata->sio, 0, val - curr->minval, curr->cb_data);
	}
	sdata->o->free(sdata->o, curr);
	return;
    }
}

static void
stel_timeout(void *handler_data)
{
    struct stel_data *sdata = handler_data;
    struct timeval timeout;
    struct stel_req *req, *curr, *prev = NULL, *to_complete = NULL;

    stel_lock(sdata);
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

    if (sdata->reqs) {
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;
	sdata->rops->start_timer(sdata->filter, &timeout);
    }
    stel_unlock(sdata);

    req = to_complete;
    while (req) {
	req->done(sdata->sio, ETIMEDOUT, 0, req->cb_data);
	prev = req;
	req = req->next;
	sdata->o->free(sdata->o, prev);
    }
}

static void
stel_got_sync(void *handler_data)
{
    /* Nothing to do, break handling is only on the server side. */
}

static void
stel_free(void *handler_data)
{
    struct stel_data *sdata = handler_data;

    if (sdata->lock)
	sdata->o->free_lock(sdata->lock);
    while (sdata->reqs) {
	struct stel_req *req = sdata->reqs;

	sdata->reqs = req->next;
	sdata->o->free(sdata->o, req);
    }
    if (sdata->sio)
	sergensio_data_free(sdata->sio);
    sdata->o->free(sdata->o, sdata);
}

struct gensio_telnet_filter_callbacks sergensio_telnet_filter_cbs = {
    .got_sync = stel_got_sync,
    .com_port_will_do = stel_com_port_will_do,
    .com_port_cmd = stel_com_port_cmd,
    .timeout = stel_timeout,
    .free = stel_free
};

int
telnet_gensio_alloc(struct gensio *child, char *args[],
		    struct gensio_os_funcs *o,
		    gensio_event cb, void *user_data,
		    struct gensio **rio)
{
    struct stel_data *sdata;
    struct gensio_ll *ll;
    struct gensio_filter *filter;
    struct gensio *io;
    unsigned int i;
    bool allow_2217 = true;
    int err;

    for (i = 0; args[i]; i++) {
	const char *val;

	if (cmpstrval(args[i], "rfc2217=", &val)) {
	    if ((strcmp(val, "true") == 0) || (strcmp(val, "1") == 0))
		allow_2217 = true;
	    else if ((strcmp(val, "false") == 0) || (strcmp(val, "0") == 0))
		allow_2217 = false;
	    else
		return EINVAL;
	}
	/* Ignore everything else, the filter will handle it. */
    }

    sdata = o->zalloc(o, sizeof(*sdata));
    if (!sdata)
	return ENOMEM;

    sdata->o = o;
    sdata->allow_2217 = allow_2217;

    sdata->lock = o->alloc_lock(o);
    if (!sdata->lock)
	goto out_nomem;

    ll = gensio_gensio_ll_alloc(o, child);
    if (!ll)
	goto out_nomem;
    gensio_ref(child);

    err = gensio_telnet_filter_alloc(o, args, &sergensio_telnet_filter_cbs,
				     sdata, &sdata->rops, &filter);
    if (err) {
	gensio_ll_free(ll);
	goto out_err;
    }

    io = base_gensio_alloc(o, ll, filter, "telnet", cb, user_data);
    if (!io) {
	gensio_filter_free(filter);
	gensio_ll_free(ll);
	goto out_nomem;
    }
    gensio_set_is_reliable(io, gensio_is_reliable(child));
    gensio_free(child); /* Lose the ref we acquired. */

    sdata->sio = sergensio_data_alloc(o, io, &stel_funcs, sdata);
    if (!sdata->sio) {
	gensio_free(io);
	goto out_nomem;
    }

    sdata->filter = filter;
    if (allow_2217) {
	err = gensio_addclass(io, "sergensio", sdata->sio);
	if (err) {
	    gensio_free(io);
	    goto out_err;
	}
    }
    sdata->reported_modemstate = true;

    *rio = io;

    return 0;

 out_nomem:
    err = ENOMEM;
 out_err:
    stel_free(sdata);
    return err;
}

int
str_to_telnet_gensio(const char *str, char *args[],
		     struct gensio_os_funcs *o,
		     gensio_event cb, void *user_data,
		     struct gensio **new_gensio)
{
    int err;
    struct gensio *io2;

    err = str_to_gensio(str, o, NULL, NULL, &io2);
    if (err)
	return err;

    err = telnet_gensio_alloc(io2, args, o, cb, user_data, new_gensio);
    if (err)
	gensio_free(io2);

    return err;
}

struct stela_data {
    unsigned int max_read_size;
    unsigned int max_write_size;

    struct gensio_os_funcs *o;

    bool allow_2217;
    bool is_reliable;
};

static void
stela_free(void *acc_data)
{
    struct stela_data *stela = acc_data;

    stela->o->free(stela->o, stela);
}

int
stela_connect_start(void *acc_data, struct gensio *child, struct gensio **rio)
{
    struct stela_data *stela = acc_data;
    struct gensio_os_funcs *o = stela->o;
    char *args[2] = {NULL, NULL};

    return telnet_gensio_alloc(child, args, o, NULL, NULL, rio);
}

static int
stela_cb_com_port_will_do(void *handler_data, unsigned char cmd)
{
    struct stel_data *sdata = handler_data;

    if (cmd != TN_WILL && cmd != TN_WONT)
	/* We only handle these. */
	return 0;
    stel_lock(sdata);
    if (cmd == TN_WONT)
	/* The remote end turned off RFC2217 handling. */
	sdata->do_2217 = false;
    else
	sdata->do_2217 = sdata->allow_2217;

    if (!sdata->reported_modemstate &&sdata->do_2217) {
	struct gensio *io = sergensio_to_gensio(sdata->sio);

	if (gensio_get_cb(io)) {
	    int val = 255;
	    unsigned int vlen = sizeof(val);

	    sdata->reported_modemstate = true;
	    gensio_cb(io, GENSIO_EVENT_SER_MODEMSTATE, 0,
		      (unsigned char *) &val, &vlen, 0, NULL);
	} else {
	    struct timeval timeout;

	    /* Schedule a modemstate report once the callbacks are set. */
	    timeout.tv_sec = 0;
	    timeout.tv_usec = 1000;
	    sdata->rops->start_timer(sdata->filter, &timeout);
	}
    }
    stel_unlock(sdata);

    return sdata->do_2217;
}

static void
stela_cb_com_port_cmd(void *handler_data, const unsigned char *option,
		      unsigned int len)
{
    struct stel_data *sdata = handler_data;
    int val = 0;
    unsigned int vlen = sizeof(int);
    struct gensio *io = sergensio_to_gensio(sdata->sio);

    if (len < 2)
	return;
    if (option[1] >= 100)
	return;

    switch (option[1]) {
    case 1:
	if (len < 3)
	    return;
	if (len < 6) {
	    sdata->cisco_baud = true;
	    val = cisco_baud_to_baud(option[2]);
	} else {
	    val = option[2] << 24;
	    val |= option[3] << 16;
	    val |= option[4] << 8;
	    val |= option[5];
	}
	gensio_cb(io, GENSIO_EVENT_SER_BAUD, 0,
		  (unsigned char *) &val, &vlen, 0, NULL);
	break;

    case 2:
	if (len < 3)
	    return;
	val = option[2];
	gensio_cb(io, GENSIO_EVENT_SER_DATASIZE, 0,
		  (unsigned char *) &val, &vlen, 0, NULL);
	break;

    case 3:
	if (len < 3)
	    return;
	val = option[2];
	gensio_cb(io, GENSIO_EVENT_SER_PARITY, 0,
		  (unsigned char *) &val, &vlen, 0, NULL);
	break;

    case 4:
	if (len < 3)
	    return;
	val = option[2];
	gensio_cb(io, GENSIO_EVENT_SER_STOPBITS, 0,
		  (unsigned char *) &val, &vlen, 0, NULL);
	break;

    case 5:
	if (len < 3)
	    return;
	switch(option[2]) {
	case 0: case 1: case 2: case 3:
	    val = option[2];
	    gensio_cb(io, GENSIO_EVENT_SER_FLOWCONTROL, 0,
		      (unsigned char *) &val, &vlen, 0, NULL);
	    break;
	case 4: case 5: case 6:
	    val = option[2] - 4;
	    gensio_cb(io, GENSIO_EVENT_SER_SBREAK, 0,
		      (unsigned char *) &val, &vlen, 0, NULL);
	    break;
	case 7: case 8: case 9:
	    val = option[2] - 7;
	    gensio_cb(io, GENSIO_EVENT_SER_DTR, 0,
		      (unsigned char *) &val, &vlen, 0, NULL);
	    break;
	case 10: case 11: case 12:
	    val = option[2] - 10;
	    gensio_cb(io, GENSIO_EVENT_SER_RTS, 0,
		      (unsigned char *) &val, &vlen, 0, NULL);
	    break;
	case 13: case 14: case 15: case 16: case 17: case 18: case 19:
	    val = option[2] - 13;
	    gensio_cb(io, GENSIO_EVENT_SER_IFLOWCONTROL, 0,
		      (unsigned char *) &val, &vlen, 0, NULL);
	}
	break;

    case 8:
	val = 1;
	gensio_cb(io, GENSIO_EVENT_SER_FLOWCONTROL, 0,
		  (unsigned char *) &val, &vlen, 0, NULL);
	break;

    case 9:
	val = 0;
	gensio_cb(io, GENSIO_EVENT_SER_FLOWCONTROL, 0,
		  (unsigned char *) &val, &vlen, 0, NULL);
	break;

    case 10:
	if (len < 3)
	    return;
	val = option[2];
	gensio_cb(io, GENSIO_EVENT_SER_LINESTATE, 0,
		  (unsigned char *) &val, &vlen, 0, NULL);
	break;

    case 11:
	if (len < 3)
	    return;
	val = option[2];
	gensio_cb(io, GENSIO_EVENT_SER_MODEMSTATE, 0,
		  (unsigned char *) &val, &vlen, 0, NULL);
	break;
	
    case 12:
	if (len < 3)
	    return;
	val = option[2];
	gensio_cb(io, GENSIO_EVENT_SER_FLUSH, 0,
		  (unsigned char *) &val, &vlen, 0, NULL);
	break;

    default:
	break;
    }
}

static void
stela_cb_got_sync(void *handler_data)
{
    struct stel_data *sdata = handler_data;
    struct gensio *io = sergensio_to_gensio(sdata->sio);

    gensio_cb(io, GENSIO_EVENT_SER_SYNC, 0, NULL, 0, 0, NULL);
}

static void
stela_cb_free(void *handler_data)
{
    struct stel_data *sdata = handler_data;

    sdata->o->free(sdata->o, sdata);
}

static void
stela_timeout(void *handler_data)
{
    struct stel_data *sdata = handler_data;

    stel_lock(sdata);
    if (!sdata->reported_modemstate &&sdata->do_2217) {
	struct gensio *io = sergensio_to_gensio(sdata->sio);
	int val = 255;
	unsigned int vlen = sizeof(val);

	if (gensio_get_cb(io)) {
	    sdata->reported_modemstate = true;
	    gensio_cb(io, GENSIO_EVENT_SER_MODEMSTATE, 0,
		      (unsigned char *) &val, &vlen, 0, NULL);
	} else {
	    struct timeval timeout;

	    timeout.tv_sec = 0;
	    timeout.tv_usec = 1000;
	    sdata->rops->start_timer(sdata->filter, &timeout);
	}
    }
    stel_unlock(sdata);
}

struct gensio_telnet_filter_callbacks sergensio_telnet_server_filter_cbs = {
    .got_sync = stela_cb_got_sync,
    .com_port_will_do = stela_cb_com_port_will_do,
    .com_port_cmd = stela_cb_com_port_cmd,
    .timeout = stela_timeout,
    .free = stela_cb_free
};

static int
stela_new_child(void *acc_data, void **finish_data,
		struct gensio_filter **filter)
{
    struct stela_data *stela = acc_data;
    struct gensio_os_funcs *o = stela->o;
    struct stel_data *sdata;
    int err;

    sdata = o->zalloc(o, sizeof(*sdata));
    if (!sdata)
	return ENOMEM;

    sdata->o = o;
    sdata->allow_2217 = stela->allow_2217;

    sdata->lock = o->alloc_lock(o);
    if (!sdata->lock) {
	o->free(o, sdata);
	return ENOMEM;
    }

    err = gensio_telnet_server_filter_alloc(o,
					    stela->allow_2217,
					    stela->max_read_size,
					    stela->max_write_size,
					    &sergensio_telnet_server_filter_cbs,
					    sdata,
					    &sdata->rops,
					    filter);
    if (err) {
	o->free_lock(sdata->lock);
	o->free(o, sdata);
    } else {
	sdata->filter = *filter;
	*finish_data = sdata;
    }

    return err;
}

static int
stela_finish_parent(void *acc_data, void *finish_data, struct gensio *io)
{
    struct stela_data *stela = acc_data;
    struct stel_data *sdata = finish_data;

    sdata->sio = sergensio_data_alloc(sdata->o, io, &stel_funcs, sdata);
    if (!sdata->sio)
	return ENOMEM;

    if (sdata->allow_2217) {
	int err = gensio_addclass(io, "sergensio", sdata->sio);

	if (err) {
	    sergensio_data_free(sdata->sio);
	    sdata->sio = NULL;
	    return err;
	}
    }
    gensio_set_is_reliable(io, stela->is_reliable);
    return 0;
}

static int
gensio_gensio_acc_telnet_cb(void *acc_data, int op, void *data1, void *data2)
{
    switch (op) {
    case GENSIO_GENSIO_ACC_CONNECT_START:
	return stela_connect_start(acc_data, data1, data2);

    case GENSIO_GENSIO_ACC_NEW_CHILD:
	return stela_new_child(acc_data, data1, data2);

    case GENSIO_GENSIO_ACC_FINISH_PARENT:
	return stela_finish_parent(acc_data, data1, data2);

    case GENSIO_GENSIO_ACC_FREE:
	stela_free(acc_data);
	return 0;

    default:
	return ENOTSUP;
    }
}

int
telnet_gensio_accepter_alloc(struct gensio_accepter *child, char *args[],
			     struct gensio_os_funcs *o,
			     gensio_accepter_event cb, void *user_data,
			     struct gensio_accepter **accepter)
{
    struct stela_data *stela;
    int err;
    unsigned int i;
    unsigned int max_read_size = GENSIO_DEFAULT_BUF_SIZE;
    unsigned int max_write_size = GENSIO_DEFAULT_BUF_SIZE;
    bool allow_2217 = false;

    for (i = 0; args[i]; i++) {
	const char *val;

	if (strcmp(args[i], "rfc2217") == 0) {
	    allow_2217 = true;
	    continue;
	} else if (cmpstrval(args[i], "rfc2217=", &val)) {
	    if ((strcmp(val, "true") == 0) || (strcmp(val, "1") == 0))
		allow_2217 = true;
	    else if ((strcmp(val, "false") == 0) || (strcmp(val, "0") == 0))
		allow_2217 = false;
	    else
		return EINVAL;
	    continue;
	}
	if (gensio_check_keyuint(args[i], "writebuf", &max_write_size) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	return EINVAL;
    }

    stela = o->zalloc(o, sizeof(*stela));
    if (!stela)
	return ENOMEM;

    stela->o = o;
    stela->max_write_size = max_write_size;
    stela->max_read_size = max_read_size;
    stela->allow_2217 = allow_2217;
    stela->is_reliable = gensio_acc_is_reliable(child);

    err = gensio_gensio_accepter_alloc(child, o, "telnet",
				       cb, user_data,
				       gensio_gensio_acc_telnet_cb, stela,
				       accepter);
    if (err)
	goto out_err;
    gensio_acc_set_is_reliable(*accepter, stela->is_reliable);

    return 0;

 out_err:
    stela_free(stela);
    return err;
}

int
str_to_telnet_gensio_accepter(const char *str, char *args[],
			      struct gensio_os_funcs *o,
			      gensio_accepter_event cb,
			      void *user_data,
			      struct gensio_accepter **acc)
{
    int err;
    struct gensio_accepter *acc2 = NULL;

    err = str_to_gensio_accepter(str, o, NULL, NULL, &acc2);
    if (!err) {
	err = telnet_gensio_accepter_alloc(acc2, args, o, cb, user_data, acc);
	if (err)
	    gensio_acc_free(acc2);
    }

    return err;
}
