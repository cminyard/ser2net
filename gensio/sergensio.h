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

/*
 * This include file defines an I/O abstraction to allow code to use a
 * serial port without having to know the underlying details.
 */

#ifndef SERGENSIO_H
#define SERGENSIO_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <gensio/gensio.h>

struct sergensio;

/*
 * Cast between sergensio and gensio types.  If
 */
struct gensio *sergensio_to_gensio(struct sergensio *sio);
struct sergensio *gensio_to_sergensio(struct gensio *io);

typedef void (*sergensio_done)(struct sergensio *sio, int err,
			       unsigned int val, void *cb_data);

typedef void (*sergensio_done_sig)(struct sergensio *sio, int err, char *sig,
				   unsigned int len, void *cb_data);

/*
 * The following functions set various serial parameters.  The done()
 * callback is called if the function does not return an error,
 * otherwise it is not called.  The done callback may have an error,
 * if so the data is not valid.  Otherwise the data given is the actual
 * set value.
 *
 * If you pass a zero to the value to this, the value is not set, it
 * is only fetched.  This can be used to get the current value.
 *
 * If the done() callback is NULL, no callback is done.  Also, in server
 * mode, this will send the server version and the done callback is
 * ignored.
 */

int sergensio_baud(struct sergensio *sio, unsigned int baud,
		   sergensio_done done, void *cb_data);

int sergensio_datasize(struct sergensio *sio, unsigned int datasize,
		       sergensio_done done, void *cb_data);

#define SERGENSIO_PARITY_NONE	1
#define SERGENSIO_PARITY_ODD	2
#define SERGENSIO_PARITY_EVEN	3
#define SERGENSIO_PARITY_MARK	4
#define SERGENSIO_PARITY_SPACE	5
int sergensio_parity(struct sergensio *sio, unsigned int parity,
		     sergensio_done done, void *cb_data);

int sergensio_stopbits(struct sergensio *sio, unsigned int stopbits,
		       sergensio_done done, void *cb_data);

#define SERGENSIO_FLOWCONTROL_NONE	1
#define SERGENSIO_FLOWCONTROL_XON_XOFF	2
#define SERGENSIO_FLOWCONTROL_RTS_CTS	3
int sergensio_flowcontrol(struct sergensio *sio, unsigned int flowcontrol,
			  sergensio_done done, void *cb_data);

#define SERGENSIO_FLOWCONTROL_DCD	4
#define SERGENSIO_FLOWCONTROL_DTR	5
#define SERGENSIO_FLOWCONTROL_DSR	6
int sergensio_iflowcontrol(struct sergensio *sio, unsigned int iflowcontrol,
			   sergensio_done done, void *cb_data);

#define SERGENSIO_BREAK_ON	1
#define SERGENSIO_BREAK_OFF	2
int sergensio_sbreak(struct sergensio *sio, unsigned int breakv,
		     sergensio_done done, void *cb_data);

#define SERGENSIO_DTR_ON	1
#define SERGENSIO_DTR_OFF	2
int sergensio_dtr(struct sergensio *sio, unsigned int dtr,
		  sergensio_done done, void *cb_data);

#define SERGENSIO_RTS_ON	1
#define SERGENSIO_RTS_OFF	2
int sergensio_rts(struct sergensio *sio, unsigned int rts,
		  sergensio_done done, void *cb_data);

int sergensio_signature(struct sergensio *sio, char *sig, unsigned int len,
			sergensio_done_sig done, void *cb_data);

/*
 * For linestate and modemstate, on a client this sets the mask, on
 * the server this is reporting the current state to the client.
 */
#define SERGENSIO_LINESTATE_DATA_READY		(1 << 0)
#define SERGENSIO_LINESTATE_OVERRUN_ERR		(1 << 1)
#define SERGENSIO_LINESTATE_PARITY_ERR		(1 << 2)
#define SERGENSIO_LINESTATE_FRAMING_ERR		(1 << 3)
#define SERGENSIO_LINESTATE_BREAK		(1 << 4)
#define SERGENSIO_LINESTATE_XMIT_HOLD_EMPTY	(1 << 5)
#define SERGENSIO_LINESTATE_XMIT_SHIFT_EMPTY	(1 << 6)
#define SERGENSIO_LINESTATE_TIMEOUT_ERR		(1 << 7)
int sergensio_linestate(struct sergensio *sio, unsigned int linestate);

/* Note that for modemstate you should use the low 4 bits. */
#define SERGENSIO_MODEMSTATE_CTS_CHANGED	(1 << 0)
#define SERGENSIO_MODEMSTATE_DSR_CHANGED	(1 << 1)
#define SERGENSIO_MODEMSTATE_RI_CHANGED		(1 << 2)
#define SERGENSIO_MODEMSTATE_CD_CHANGED		(1 << 3)
#define SERGENSIO_MODEMSTATE_CTS		(1 << 4)
#define SERGENSIO_MODEMSTATE_DSR		(1 << 5)
#define SERGENSIO_MODEMSTATE_RI			(1 << 6)
#define SERGENSIO_MODEMSTATE_CD			(1 << 7)
int sergensio_modemstate(struct sergensio *sio, unsigned int modemstate);

/*
 * Tell the remote end to enable or disable flow control.
 */
int sergensio_flowcontrol_state(struct sergensio *sio, bool val);

/*
 * Tell the remote end to flush its buffers.
 */
#define SERGIO_FLUSH_RCV_BUFFER		1
#define SERGIO_FLUSH_XMIT_BUFFER	2
#define SERGIO_FLUSH_RCV_XMIT_BUFFERS	3
int sergensio_flush(struct sergensio *sio, unsigned int val);

/*
 * Tell the remote end to send a break.
 */
int sergensio_send_break(struct sergensio *sio);

/*
 * Return the user data supplied in the alloc function.
 */
void *sergensio_get_user_data(struct sergensio *io);

/*
 * The following is blocking values for the serial port setting calls.
 * You allocate one of these, then you can use it to request values
 * without having to do your own callback.  It blocks using the
 * selector framework, so selector calls will still happen while
 * blocked.  See the selector code for details on wake_sig.
 *
 * The value is passed in using a pointer.  If it points to a zero
 * value, no set it done, it only fetches the current value.
 *
 * The free function should only be called if the code is not currently
 * in a blocking call using the sbio.
 *
 * These should not be called from a server gensio.
 */
struct sergensio_b;

int sergensio_b_alloc(struct sergensio *sio, struct gensio_os_funcs *o,
		      struct sergensio_b **new_sbio);
void sergensio_b_free(struct sergensio_b *sbio);
int sergensio_baud_b(struct sergensio_b *sbio, int *baud);
int sergensio_datasize_b(struct sergensio_b *sbio, int *datasize);
int sergensio_parity_b(struct sergensio_b *sbio, int *parity);
int sergensio_stopbits_b(struct sergensio_b *sbio, int *stopbits);
int sergensio_flowcontrol_b(struct sergensio_b *sbio, int *flowcontrol);
int sergensio_iflowcontrol_b(struct sergensio_b *sbio, int *iflowcontrol);
int sergensio_sbreak_b(struct sergensio_b *sbio, int *breakv);
int sergensio_dtr_b(struct sergensio_b *sbio, int *dtr);
int sergensio_rts_b(struct sergensio_b *sbio, int *rts);

/*
 * Events for dynamic changes to the serial port.  Users can ignore these
 * if they don't care.
 */

/*
 * On the client side, these are for reporting changes to the client.
 * On the server side, this is for reporting that the client has
 * requested the mask be changed.  buf points to an unsigned integer
 * holding the modem or line state.
 */
#define GENSIO_EVENT_SER_MODEMSTATE	(SERGENIO_EVENT_BASE + 1)
#define GENSIO_EVENT_SER_LINESTATE	(SERGENIO_EVENT_BASE + 2)

/*
 * On the server side, these are for reporting that the client is
 * requesting the signature (sig and sig_len are not used).  On
 * the client side, this is the signature response.  The signature
 * is in buf and the signature length is in buflen.  The return value
 * in buflen is ignored.
 */
#define GENSIO_EVENT_SER_SIGNATURE	(SERGENIO_EVENT_BASE + 3)

/*
 * The remote end is asking the user to flow control or flush.  Client
 * or server.
 */
#define GENSIO_EVENT_SER_FLOW_STATE	(SERGENIO_EVENT_BASE + 4)
#define GENSIO_EVENT_SER_FLUSH		(SERGENIO_EVENT_BASE + 5)

/* Got a sync from the other end.  Client or server. */
#define GENSIO_EVENT_SER_SYNC		(SERGENIO_EVENT_BASE + 6)

/*
 * Server callbacks.  These only come in in server mode, you must
 * call the equivalent sergensio_xxx() function to return the response,
 * though the done callback is ignored in that case.  buf points to
 * an integer holding the value.
 */
#define GENSIO_EVENT_SER_BAUD		(SERGENIO_EVENT_BASE + 7)
#define GENSIO_EVENT_SER_DATASIZE	(SERGENIO_EVENT_BASE + 8)
#define GENSIO_EVENT_SER_PARITY		(SERGENIO_EVENT_BASE + 9)
#define GENSIO_EVENT_SER_STOPBITS	(SERGENIO_EVENT_BASE + 10)
#define GENSIO_EVENT_SER_FLOWCONTROL	(SERGENIO_EVENT_BASE + 11)
#define GENSIO_EVENT_SER_IFLOWCONTROL	(SERGENIO_EVENT_BASE + 12)
#define GENSIO_EVENT_SER_SBREAK		(SERGENIO_EVENT_BASE + 13)
#define GENSIO_EVENT_SER_DTR		(SERGENIO_EVENT_BASE + 14)
#define GENSIO_EVENT_SER_RTS		(SERGENIO_EVENT_BASE + 15)

/*
 * Got a request from the other end to send a break.  Client or
 * server.
 */
#define GENSIO_EVENT_SER_SEND_BREAK	(SERGENIO_EVENT_BASE + 16)

bool sergensio_is_client(struct sergensio *sio);

#ifdef __cplusplus
}
#endif

#endif /* SERGENSIO_H */
