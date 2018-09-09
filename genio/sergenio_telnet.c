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

#include <genio/sergenio_internal.h>
#include <genio/genio_base.h>

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

    struct genio_filter *filter;
    const struct genio_telnet_filter_rops *rops;
    struct genio_lock *lock;

    bool allow_2217;
    bool do_2217;
    bool cisco_baud;

    struct stel_req *reqs;
};

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
    struct timeval timeout;

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

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    sdata->rops->start_timer(sdata->filter, &timeout);

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
    sdata->rops->send_option(sdata->filter, buf, 3);

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
sergenio_com_port_will_do(void *handler_data, unsigned char cmd)
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

    return 1;
}

static void
sergenio_com_port_cmd(void *handler_data, const unsigned char *option,
		      unsigned int len)
{
    struct stel_data *sdata = handler_data;
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

static void
telnet_timeout(void *handler_data)
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
	req->done(&sdata->sio, ETIMEDOUT, 0, req->cb_data);
	prev = req;
	req = req->next;
	sdata->o->free(sdata->o, prev);
    }
}

static void
sergenio_got_sync(void *handler_data)
{
    /* Nothing to do, break handling is only on the server side. */
}

static void
sergenio_free(void *handler_data)
{
    struct stel_data *sdata = handler_data;

    if (sdata->lock)
	sdata->o->free_lock(sdata->lock);
    while (sdata->reqs) {
	struct stel_req *req = sdata->reqs;

	sdata->reqs = req->next;
	sdata->o->free(sdata->o, req);
    }
    sdata->o->free(sdata->o, sdata);
}

struct genio_telnet_filter_callbacks sergenio_telnet_filter_cbs = {
    .got_sync = sergenio_got_sync,
    .com_port_will_do = sergenio_com_port_will_do,
    .com_port_cmd = sergenio_com_port_cmd,
    .timeout = telnet_timeout,
    .free = sergenio_free
};

int
sergenio_telnet_alloc(struct genio *child, char *args[],
		      struct genio_os_funcs *o,
		      const struct sergenio_callbacks *scbs,
		      const struct genio_callbacks *cbs, void *user_data,
		      struct sergenio **sio)
{
    struct stel_data *sdata;
    struct genio_ll *ll;
    struct genio_filter *filter;
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

    ll = genio_genio_ll_alloc(o, child);
    if (!ll)
	goto out_nomem;
    child->funcs->ref(child);

    err = genio_telnet_filter_alloc(o, args, &sergenio_telnet_filter_cbs,
				    sdata, &sdata->rops, &filter);
    if (err) {
	ll->ops->free(ll);
	goto out_err;
    }

    sdata->sio.io = base_genio_alloc(o, ll, filter, GENIO_TYPE_SER_TELNET,
				     cbs, user_data);
    if (!sdata->sio.io) {
	filter->ops->free(filter);
	ll->ops->free(ll);
	goto out_err;
    }
    genio_free(child); /* Lose the ref we acquired. */

    sdata->o = o;
    sdata->filter = filter;
    sdata->sio.scbs = scbs;
    sdata->sio.io->parent_object = &sdata->sio;
    sdata->sio.funcs = &stel_funcs;

    *sio = &sdata->sio;

    return 0;

 out_nomem:
    err = ENOMEM;
 out_err:
    sergenio_free(sdata);
    return err;
}
