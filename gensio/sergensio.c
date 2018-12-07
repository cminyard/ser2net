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
#include <string.h>
#include <errno.h>

#include <gensio/sergensio_class.h>

#include "utils.h"

struct sergensio {
    struct gensio_os_funcs *o;

    struct gensio *io;

    sergensio_func func;

    void *gensio_data;
};

struct gensio *
sergensio_to_gensio(struct sergensio *sio)
{
    return sio->io;
}

struct sergensio *
gensio_to_sergensio(struct gensio *io)
{
    return gensio_getclass(io, "sergensio");
}

struct sergensio *
sergensio_data_alloc(struct gensio_os_funcs *o, struct gensio *io,
		     sergensio_func func, void *gensio_data)
{
    struct sergensio *sio = o->zalloc(o, sizeof(*sio));

    if (!sio)
	return NULL;

    sio->o = o;
    sio->io = io;
    sio->func = func;
    sio->gensio_data = gensio_data;
    return sio;
}

void
sergensio_data_free(struct sergensio *sio)
{
    sio->o->free(sio->o, sio);
}

void *
sergensio_get_gensio_data(struct sergensio *sio)
{
    return sio->gensio_data;
}

int
sergensio_baud(struct sergensio *sio, unsigned int baud,
	       sergensio_done done, void *cb_data)
{
    return sio->func(sio, SERGENSIO_FUNC_BAUD, baud, NULL, done, cb_data);
}

int
sergensio_datasize(struct sergensio *sio, unsigned int datasize,
		   sergensio_done done, void *cb_data)
{
    return sio->func(sio, SERGENSIO_FUNC_DATASIZE, datasize, NULL,
		     done, cb_data);
}

int
sergensio_parity(struct sergensio *sio, unsigned int parity,
		 sergensio_done done, void *cb_data)
{
    return sio->func(sio, SERGENSIO_FUNC_PARITY, parity, NULL, done, cb_data);
}

int
sergensio_stopbits(struct sergensio *sio, unsigned int stopbits,
		   sergensio_done done, void *cb_data)
{
    return sio->func(sio, SERGENSIO_FUNC_STOPBITS, stopbits, NULL,
		     done, cb_data);
}

int
sergensio_flowcontrol(struct sergensio *sio, unsigned int flowcontrol,
		      sergensio_done done, void *cb_data)
{
    return sio->func(sio, SERGENSIO_FUNC_FLOWCONTROL, flowcontrol, NULL,
		     done, cb_data);
}

int
sergensio_iflowcontrol(struct sergensio *sio, unsigned int iflowcontrol,
		       sergensio_done done, void *cb_data)
{
    return sio->func(sio, SERGENSIO_FUNC_IFLOWCONTROL, iflowcontrol, NULL,
		     done, cb_data);
}

int
sergensio_sbreak(struct sergensio *sio, unsigned int breakv,
		 sergensio_done done, void *cb_data)
{
    return sio->func(sio, SERGENSIO_FUNC_SBREAK, breakv, NULL,
		     done, cb_data);
}

int
sergensio_dtr(struct sergensio *sio, unsigned int dtr,
	      sergensio_done done, void *cb_data)
{
    return sio->func(sio, SERGENSIO_FUNC_DTR, dtr, NULL, done, cb_data);
}

int
sergensio_rts(struct sergensio *sio, unsigned int rts,
	      sergensio_done done, void *cb_data)
{
    return sio->func(sio, SERGENSIO_FUNC_RTS, rts, NULL, done, cb_data);
}

int
sergensio_signature(struct sergensio *sio, char *sig, unsigned int len,
		    sergensio_done_sig done, void *cb_data)
{
    return sio->func(sio, SERGENSIO_FUNC_SIGNATURE, len, sig,
		     done, cb_data);
}

int
sergensio_modemstate(struct sergensio *sio, unsigned int val)
{
    return sio->func(sio, SERGENSIO_FUNC_MODEMSTATE, val, NULL, NULL, NULL);
}

int
sergensio_linestate(struct sergensio *sio, unsigned int val)
{
    return sio->func(sio, SERGENSIO_FUNC_LINESTATE, val, NULL, NULL, NULL);
}

int
sergensio_flowcontrol_state(struct sergensio *sio, bool val)
{
    return sio->func(sio, SERGENSIO_FUNC_FLOWCONTROL_STATE, val,
		     NULL, NULL, NULL);
}

int
sergensio_flush(struct sergensio *sio, unsigned int val)
{
    return sio->func(sio, SERGENSIO_FUNC_FLUSH, val, NULL, NULL, NULL);
}

int
sergensio_send_break(struct sergensio *sio)
{
    return sio->func(sio, SERGENSIO_FUNC_SEND_BREAK, 0, NULL, NULL, NULL);
}

bool
sergensio_is_client(struct sergensio *sio)
{
    struct gensio *io = sergensio_to_gensio(sio);

    return gensio_is_client(io);
}

void *
sergensio_get_user_data(struct sergensio *sio)
{
    return gensio_get_user_data(sio->io);
}

struct sergensio_b {
    struct sergensio *sio;
    struct gensio_os_funcs *o;
};

struct sergensio_b_data {
    struct gensio_os_funcs *o;
    struct gensio_waiter *waiter;
    int err;
    unsigned int val;
};

int
sergensio_b_alloc(struct sergensio *sio, struct gensio_os_funcs *o,
		  struct sergensio_b **new_sbio)
{
    struct sergensio_b *sbio = malloc(sizeof(*sbio));

    if (!sbio)
	return ENOMEM;

    sbio->sio = sio;
    sbio->o = o;
    *new_sbio = sbio;

    return 0;
}

void sergensio_b_free(struct sergensio_b *sbio)
{
    free(sbio);
}

static void sergensio_op_done(struct sergensio *sio, int err,
			      unsigned int val, void *cb_data)
{
    struct sergensio_b_data *data = cb_data;

    data->err = err;
    data->val = val;
    data->o->wake(data->waiter);
}

int
sergensio_baud_b(struct sergensio_b *sbio, int *baud)
{
    struct sergensio_b_data data;
    int err;

    data.waiter = sbio->o->alloc_waiter(sbio->o);
    if (!data.waiter)
	return ENOMEM;

    data.err = 0;
    data.o = sbio->o;
    err = sergensio_baud(sbio->sio, *baud, sergensio_op_done, &data);
    if (!err)
	sbio->o->wait(data.waiter, 1, NULL);
    sbio->o->free_waiter(data.waiter);
    if (!err)
	err = data.err;
    if (!err)
	*baud = data.val;

    return err;
}

int
sergensio_datasize_b(struct sergensio_b *sbio, int *datasize)
{
    struct sergensio_b_data data;
    int err;

    data.waiter = sbio->o->alloc_waiter(sbio->o);
    if (!data.waiter)
	return ENOMEM;

    data.err = 0;
    data.o = sbio->o;
    err = sergensio_datasize(sbio->sio, *datasize, sergensio_op_done, &data);
    if (!err)
	sbio->o->wait(data.waiter, 1, NULL);
    sbio->o->free_waiter(data.waiter);
    if (!err)
	err = data.err;
    if (!err)
	*datasize = data.val;

    return err;
}

int
sergensio_parity_b(struct sergensio_b *sbio, int *parity)
{
    struct sergensio_b_data data;
    int err;

    data.waiter = sbio->o->alloc_waiter(sbio->o);
    if (!data.waiter)
	return ENOMEM;

    data.err = 0;
    data.o = sbio->o;
    err = sergensio_parity(sbio->sio, *parity, sergensio_op_done, &data);
    if (!err)
	sbio->o->wait(data.waiter, 1, NULL);
    sbio->o->free_waiter(data.waiter);
    if (!err)
	err = data.err;
    if (!err)
	*parity = data.val;

    return err;
}

int
sergensio_stopbits_b(struct sergensio_b *sbio, int *stopbits)
{
    struct sergensio_b_data data;
    int err;

    data.waiter = sbio->o->alloc_waiter(sbio->o);
    if (!data.waiter)
	return ENOMEM;

    data.err = 0;
    data.o = sbio->o;
    err = sergensio_stopbits(sbio->sio, *stopbits, sergensio_op_done, &data);
    if (!err)
	sbio->o->wait(data.waiter, 1, NULL);
    sbio->o->free_waiter(data.waiter);
    if (!err)
	err = data.err;
    if (!err)
	*stopbits = data.val;

    return err;
}

int
sergensio_flowcontrol_b(struct sergensio_b *sbio, int *flowcontrol)
{
    struct sergensio_b_data data;
    int err;

    data.waiter = sbio->o->alloc_waiter(sbio->o);
    if (!data.waiter)
	return ENOMEM;

    data.err = 0;
    data.o = sbio->o;
    err = sergensio_flowcontrol(sbio->sio, *flowcontrol,
				sergensio_op_done, &data);
    if (!err)
	sbio->o->wait(data.waiter, 1, NULL);
    sbio->o->free_waiter(data.waiter);
    if (!err)
	err = data.err;
    if (!err)
	*flowcontrol = data.val;

    return err;
}

int
sergensio_iflowcontrol_b(struct sergensio_b *sbio, int *iflowcontrol)
{
    struct sergensio_b_data data;
    int err;

    data.waiter = sbio->o->alloc_waiter(sbio->o);
    if (!data.waiter)
	return ENOMEM;

    data.err = 0;
    data.o = sbio->o;
    err = sergensio_iflowcontrol(sbio->sio, *iflowcontrol, sergensio_op_done,
				 &data);
    if (!err)
	sbio->o->wait(data.waiter, 1, NULL);
    sbio->o->free_waiter(data.waiter);
    if (!err)
	err = data.err;
    if (!err)
	*iflowcontrol = data.val;

    return err;
}

int
sergensio_sbreak_b(struct sergensio_b *sbio, int *breakv)
{
    struct sergensio_b_data data;
    int err;

    data.waiter = sbio->o->alloc_waiter(sbio->o);
    if (!data.waiter)
	return ENOMEM;

    data.err = 0;
    data.o = sbio->o;
    err = sergensio_sbreak(sbio->sio, *breakv, sergensio_op_done, &data);
    if (!err)
	sbio->o->wait(data.waiter, 1, NULL);
    sbio->o->free_waiter(data.waiter);
    if (!err)
	err = data.err;
    if (!err)
	*breakv = data.val;

    return err;
}

int
sergensio_dtr_b(struct sergensio_b *sbio, int *dtr)
{
    struct sergensio_b_data data;
    int err;

    data.waiter = sbio->o->alloc_waiter(sbio->o);
    if (!data.waiter)
	return ENOMEM;

    data.err = 0;
    data.o = sbio->o;
    err = sergensio_dtr(sbio->sio, *dtr, sergensio_op_done, &data);
    if (!err)
	sbio->o->wait(data.waiter, 1, NULL);
    sbio->o->free_waiter(data.waiter);
    if (!err)
	err = data.err;
    if (!err)
	*dtr = data.val;

    return err;
}

int
sergensio_rts_b(struct sergensio_b *sbio, int *rts)
{
    struct sergensio_b_data data;
    int err;

    data.waiter = sbio->o->alloc_waiter(sbio->o);
    if (!data.waiter)
	return ENOMEM;

    data.err = 0;
    data.o = sbio->o;
    err = sergensio_rts(sbio->sio, *rts, sergensio_op_done, &data);
    if (!err)
	sbio->o->wait(data.waiter, 1, NULL);
    sbio->o->free_waiter(data.waiter);
    if (!err)
	err = data.err;
    if (!err)
	*rts = data.val;

    return err;
}
