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

#include <utils/utils.h>

#include <gensio/sergensio_internal.h>

struct gensio *
sergensio_to_gensio(struct sergensio *sio)
{
    return sio->io;
}

static enum gensio_type sergensio_types[] =
{
    GENSIO_TYPE_SER_TELNET,
    GENSIO_TYPE_SER_TERMIOS,
    GENSIO_TYPE_INVALID
};

bool
is_sergensio(struct gensio *io)
{
    return gensio_match_type(io, sergensio_types);
}

struct sergensio *
gensio_to_sergensio(struct gensio *io)
{
    if (!is_sergensio(io))
	return NULL;
    return io->parent_object;
}

int
sergensio_baud(struct sergensio *sio, int baud,
	       void (*done)(struct sergensio *sio, int err,
			    int baud, void *cb_data),
	       void *cb_data)
{
    return sio->funcs->baud(sio, baud, done, cb_data);
}

int
sergensio_datasize(struct sergensio *sio, int datasize,
		   void (*done)(struct sergensio *sio, int err, int datasize,
				void *cb_data),
		   void *cb_data)
{
    return sio->funcs->datasize(sio, datasize, done, cb_data);
}

int
sergensio_parity(struct sergensio *sio, int parity,
		 void (*done)(struct sergensio *sio, int err, int parity,
			      void *cb_data),
		 void *cb_data)
{
    return sio->funcs->parity(sio, parity, done, cb_data);
}

int
sergensio_stopbits(struct sergensio *sio, int stopbits,
		   void (*done)(struct sergensio *sio, int err, int stopbits,
				void *cb_data),
		   void *cb_data)
{
    return sio->funcs->stopbits(sio, stopbits, done, cb_data);
}

int
sergensio_flowcontrol(struct sergensio *sio, int flowcontrol,
		      void (*done)(struct sergensio *sio, int err,
				   int flowcontrol, void *cb_data),
		      void *cb_data)
{
    return sio->funcs->flowcontrol(sio, flowcontrol, done, cb_data);
}

int
sergensio_iflowcontrol(struct sergensio *sio, int iflowcontrol,
		       void (*done)(struct sergensio *sio, int err,
				    int iflowcontrol, void *cb_data),
		       void *cb_data)
{
    return sio->funcs->iflowcontrol(sio, iflowcontrol, done, cb_data);
}

int
sergensio_sbreak(struct sergensio *sio, int breakv,
		 void (*done)(struct sergensio *sio, int err, int breakv,
			      void *cb_data),
		 void *cb_data)
{
    return sio->funcs->sbreak(sio, breakv, done, cb_data);
}

int
sergensio_dtr(struct sergensio *sio, int dtr,
	      void (*done)(struct sergensio *sio, int err, int dtr,
			   void *cb_data),
	      void *cb_data)
{
    return sio->funcs->dtr(sio, dtr, done, cb_data);
}

int
sergensio_rts(struct sergensio *sio, int rts,
	      void (*done)(struct sergensio *sio, int err, int rts,
			   void *cb_data),
	      void *cb_data)
{
    return sio->funcs->rts(sio, rts, done, cb_data);
}

int
sergensio_signature(struct sergensio *sio, char *sig, unsigned int len,
		    void (*done)(struct sergensio *sio, int err, char *sig,
				unsigned int sig_len, void *cb_data),
		    void *cb_data)
{
    if (!sio->funcs->signature)
	return ENOTSUP;
    return sio->funcs->signature(sio, sig, len, done, cb_data);
}

int
sergensio_modemstate(struct sergensio *sio, unsigned int val)
{
    if (!sio->funcs->modemstate)
	return ENOTSUP;
    return sio->funcs->modemstate(sio, val);
}

int
sergensio_linestate(struct sergensio *sio, unsigned int val)
{
    if (!sio->funcs->linestate)
	return ENOTSUP;
    return sio->funcs->linestate(sio, val);
}

int
sergensio_flowcontrol_state(struct sergensio *sio, bool val)
{
    if (!sio->funcs->flowcontrol_state)
	return ENOTSUP;
    return sio->funcs->flowcontrol_state(sio, val);
}

int
sergensio_flush(struct sergensio *sio, unsigned int val)
{
    if (!sio->funcs->flush)
	return ENOTSUP;
    return sio->funcs->flush(sio, val);
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
    return sio->io->user_data;
}

struct sergensio_b {
    struct sergensio *sio;
    struct gensio_os_funcs *o;
};

struct sergensio_b_data {
    struct gensio_os_funcs *o;
    struct gensio_waiter *waiter;
    int err;
    int val;
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

static void sergensio_done(struct sergensio *sio, int err,
			   int val, void *cb_data)
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
    err = sergensio_baud(sbio->sio, *baud, sergensio_done, &data);
    if (!err)
	sbio->o->wait(data.waiter, NULL);
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
    err = sergensio_datasize(sbio->sio, *datasize, sergensio_done, &data);
    if (!err)
	sbio->o->wait(data.waiter, NULL);
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
    err = sergensio_parity(sbio->sio, *parity, sergensio_done, &data);
    if (!err)
	sbio->o->wait(data.waiter, NULL);
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
    err = sergensio_stopbits(sbio->sio, *stopbits, sergensio_done, &data);
    if (!err)
	sbio->o->wait(data.waiter, NULL);
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
    err = sergensio_flowcontrol(sbio->sio, *flowcontrol, sergensio_done, &data);
    if (!err)
	sbio->o->wait(data.waiter, NULL);
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
    err = sergensio_iflowcontrol(sbio->sio, *iflowcontrol, sergensio_done,
				 &data);
    if (!err)
	sbio->o->wait(data.waiter, NULL);
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
    err = sergensio_sbreak(sbio->sio, *breakv, sergensio_done, &data);
    if (!err)
	sbio->o->wait(data.waiter, NULL);
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
    err = sergensio_dtr(sbio->sio, *dtr, sergensio_done, &data);
    if (!err)
	sbio->o->wait(data.waiter, NULL);
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
    err = sergensio_rts(sbio->sio, *rts, sergensio_done, &data);
    if (!err)
	sbio->o->wait(data.waiter, NULL);
    sbio->o->free_waiter(data.waiter);
    if (!err)
	err = data.err;
    if (!err)
	*rts = data.val;

    return err;
}

void
sergensio_set_ser_cbs(struct sergensio *sio,
		      struct sergensio_callbacks *scbs)
{
    sio->scbs = scbs;
    if (sio->funcs->callbacks_set)
	sio->funcs->callbacks_set(sio);
}
