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

#include "utils/waiter.h"
#include "sergenio_internal.h"

struct genio *
sergenio_to_genio(struct sergenio *snet)
{
    return &snet->net;
}

static enum genio_type sergenio_types[] =
{
    GENIO_TYPE_SER_TELNET,
    GENIO_TYPE_SER_TERMIOS,
    GENIO_TYPE_INVALID
};

struct sergenio *
genio_to_sergenio(struct genio *net)
{
    if (!genio_match_type(net, sergenio_types))
	abort();
    return container_of(net, struct sergenio, net);
}

int
sergenio_baud(struct sergenio *snet, int baud,
	      void (*done)(struct sergenio *snet, int err,
			   int baud, void *cb_data),
	      void *cb_data)
{
    return snet->funcs->baud(snet, baud, done, cb_data);
}

int
sergenio_datasize(struct sergenio *snet, int datasize,
		  void (*done)(struct sergenio *snet, int err, int datasize,
			       void *cb_data),
		  void *cb_data)
{
    return snet->funcs->datasize(snet, datasize, done, cb_data);
}

int
sergenio_parity(struct sergenio *snet, int parity,
		void (*done)(struct sergenio *snet, int err, int parity,
			     void *cb_data),
		void *cb_data)
{
    return snet->funcs->parity(snet, parity, done, cb_data);
}

int
sergenio_stopbits(struct sergenio *snet, int stopbits,
		  void (*done)(struct sergenio *snet, int err, int stopbits,
			       void *cb_data),
		  void *cb_data)
{
    return snet->funcs->stopbits(snet, stopbits, done, cb_data);
}

int
sergenio_flowcontrol(struct sergenio *snet, int flowcontrol,
		     void (*done)(struct sergenio *snet, int err,
				  int flowcontrol, void *cb_data),
		     void *cb_data)
{
    return snet->funcs->flowcontrol(snet, flowcontrol, done, cb_data);
}

int
sergenio_break(struct sergenio *snet, int breakv,
	       void (*done)(struct sergenio *snet, int err, int breakv,
			    void *cb_data),
	       void *cb_data)
{
    return snet->funcs->breakv(snet, breakv, done, cb_data);
}

int
sergenio_dtr(struct sergenio *snet, int dtr,
	     void (*done)(struct sergenio *snet, int err, int dtr,
			  void *cb_data),
	     void *cb_data)
{
    return snet->funcs->dtr(snet, dtr, done, cb_data);
}

int
sergenio_rts(struct sergenio *snet, int rts,
	     void (*done)(struct sergenio *snet, int err, int rts,
			  void *cb_data),
	     void *cb_data)
{
    return snet->funcs->rts(snet, rts, done, cb_data);
}

void *
sergenio_get_user_data(struct sergenio *snet)
{
    return snet->net.user_data;
}

struct sergenio_b {
    struct sergenio *snet;
    struct selector_s *sel;
    int wake_sig;
};

struct sergenio_b_data {
    struct waiter_s *waiter;
    int err;
    int val;
};

int
sergenio_b_alloc(struct sergenio *snet, struct selector_s *sel,
		 int wake_sig, struct sergenio_b **new_sbnet)
{
    struct sergenio_b *sbnet = malloc(sizeof(*sbnet));

    if (!sbnet)
	return ENOMEM;

    sbnet->snet = snet;
    sbnet->sel = sel;
    sbnet->wake_sig = wake_sig;
    *new_sbnet = sbnet;

    return 0;
}

static void sergenio_done(struct sergenio *snet, int err,
			  int val, void *cb_data)
{
    struct sergenio_b_data *data = cb_data;

    data->err = err;
    data->val = val;
    wake_waiter(data->waiter);
}

int
sergenio_baud_b(struct sergenio_b *sbnet, int *baud)
{
    struct sergenio_b_data data;
    int err;

    data.waiter = alloc_waiter(sbnet->sel, sbnet->wake_sig);
    if (!data.waiter)
	return ENOMEM;

    data.err = 0;
    err = sergenio_baud(sbnet->snet, *baud, sergenio_done, &data);
    if (!err)
	wait_for_waiter(data.waiter, 1);
    free_waiter(data.waiter);
    err = data.err;
    if (!err)
	*baud = data.val;

    return err;
}

int
sergenio_datasize_b(struct sergenio_b *sbnet, int *datasize)
{
    struct sergenio_b_data data;
    int err;

    data.waiter = alloc_waiter(sbnet->sel, sbnet->wake_sig);
    if (!data.waiter)
	return ENOMEM;

    data.err = 0;
    err = sergenio_datasize(sbnet->snet, *datasize, sergenio_done, &data);
    if (!err)
	wait_for_waiter(data.waiter, 1);
    free_waiter(data.waiter);
    err = data.err;
    if (!err)
	*datasize = data.val;

    return err;
}

int
sergenio_parity_b(struct sergenio_b *sbnet, int *parity)
{
    struct sergenio_b_data data;
    int err;

    data.waiter = alloc_waiter(sbnet->sel, sbnet->wake_sig);
    if (!data.waiter)
	return ENOMEM;

    data.err = 0;
    err = sergenio_parity(sbnet->snet, *parity, sergenio_done, &data);
    if (!err)
	wait_for_waiter(data.waiter, 1);
    free_waiter(data.waiter);
    err = data.err;
    if (!err)
	*parity = data.val;

    return err;
}

int
sergenio_stopbits_b(struct sergenio_b *sbnet, int *stopbits)
{
    struct sergenio_b_data data;
    int err;

    data.waiter = alloc_waiter(sbnet->sel, sbnet->wake_sig);
    if (!data.waiter)
	return ENOMEM;

    data.err = 0;
    err = sergenio_stopbits(sbnet->snet, *stopbits, sergenio_done, &data);
    if (!err)
	wait_for_waiter(data.waiter, 1);
    free_waiter(data.waiter);
    err = data.err;
    if (!err)
	*stopbits = data.val;

    return err;
}

int
sergenio_flowcontrol_b(struct sergenio_b *sbnet, int *flowcontrol)
{
    struct sergenio_b_data data;
    int err;

    data.waiter = alloc_waiter(sbnet->sel, sbnet->wake_sig);
    if (!data.waiter)
	return ENOMEM;

    data.err = 0;
    err = sergenio_flowcontrol(sbnet->snet, *flowcontrol, sergenio_done, &data);
    if (!err)
	wait_for_waiter(data.waiter, 1);
    free_waiter(data.waiter);
    err = data.err;
    if (!err)
	*flowcontrol = data.val;

    return err;
}

int
sergenio_break_b(struct sergenio_b *sbnet, int *breakv)
{
    struct sergenio_b_data data;
    int err;

    data.waiter = alloc_waiter(sbnet->sel, sbnet->wake_sig);
    if (!data.waiter)
	return ENOMEM;

    data.err = 0;
    err = sergenio_break(sbnet->snet, *breakv, sergenio_done, &data);
    if (!err)
	wait_for_waiter(data.waiter, 1);
    free_waiter(data.waiter);
    err = data.err;
    if (!err)
	*breakv = data.val;

    return err;
}

int
sergenio_dtr_b(struct sergenio_b *sbnet, int *dtr)
{
    struct sergenio_b_data data;
    int err;

    data.waiter = alloc_waiter(sbnet->sel, sbnet->wake_sig);
    if (!data.waiter)
	return ENOMEM;

    data.err = 0;
    err = sergenio_dtr(sbnet->snet, *dtr, sergenio_done, &data);
    if (!err)
	wait_for_waiter(data.waiter, 1);
    free_waiter(data.waiter);
    err = data.err;
    if (!err)
	*dtr = data.val;

    return err;
}

int
sergenio_rts_b(struct sergenio_b *sbnet, int *rts)
{
    struct sergenio_b_data data;
    int err;

    data.waiter = alloc_waiter(sbnet->sel, sbnet->wake_sig);
    if (!data.waiter)
	return ENOMEM;

    data.err = 0;
    err = sergenio_rts(sbnet->snet, *rts, sergenio_done, &data);
    if (!err)
	wait_for_waiter(data.waiter, 1);
    free_waiter(data.waiter);
    err = data.err;
    if (!err)
	*rts = data.val;

    return err;
}
