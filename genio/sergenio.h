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

/*
 * This include file defines an I/O abstraction to allow code to use a
 * serial port without having to know the underlying details.
 */

#ifndef SER2NET_SERGENIO_H
#define SER2NET_SERGENIO_H

#include "genio.h"

#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

struct sergenio;

/*
 * Cast between sergenio and genio types.  If
 */
struct genio *sergenio_to_genio(struct sergenio *sio);
struct sergenio *genio_to_sergenio(struct genio *io);
bool is_sergenio(struct genio *io);

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

int sergenio_baud(struct sergenio *sio, int baud,
		  void (*done)(struct sergenio *sio, int err,
			       int baud, void *cb_data),
		  void *cb_data);

int sergenio_datasize(struct sergenio *sio, int datasize,
		      void (*done)(struct sergenio *sio, int err, int datasize,
				   void *cb_data),
		      void *cb_data);

#define SERGENIO_PARITY_NONE	1
#define SERGENIO_PARITY_ODD	2
#define SERGENIO_PARITY_EVEN	3
#define SERGENIO_PARITY_MARK	4
#define SERGENIO_PARITY_SPACE	5
int sergenio_parity(struct sergenio *sio, int parity,
		    void (*done)(struct sergenio *sio, int err, int parity,
				 void *cb_data),
		    void *cb_data);

int sergenio_stopbits(struct sergenio *sio, int stopbits,
		      void (*done)(struct sergenio *sio, int err, int stopbits,
				   void *cb_data),
		      void *cb_data);

#define SERGENIO_FLOWCONTROL_NONE	1
#define SERGENIO_FLOWCONTROL_XON_XOFF	2
#define SERGENIO_FLOWCONTROL_RTS_CTS	3
int sergenio_flowcontrol(struct sergenio *sio, int flowcontrol,
			 void (*done)(struct sergenio *sio, int err,
				      int flowcontrol, void *cb_data),
			 void *cb_data);

#define SERGENIO_BREAK_ON	1
#define SERGENIO_BREAK_OFF	2
int sergenio_sbreak(struct sergenio *sio, int breakv,
		    void (*done)(struct sergenio *sio, int err, int breakv,
				 void *cb_data),
		    void *cb_data);

#define SERGENIO_DTR_ON		1
#define SERGENIO_DTR_OFF	2
int sergenio_dtr(struct sergenio *sio, int dtr,
		 void (*done)(struct sergenio *sio, int err, int dtr,
			      void *cb_data),
		 void *cb_data);

#define SERGENIO_RTS_ON		1
#define SERGENIO_RTS_OFF	2
int sergenio_rts(struct sergenio *sio, int rts,
		 void (*done)(struct sergenio *sio, int err, int rts,
			      void *cb_data),
		 void *cb_data);

/*
 * For linestate and modemstate, on a client this sets the mask, on
 * the server this is reporting the current state to the client.
 */
#define SERGENIO_LINESTATE_DATA_READY		(1 << 0)
#define SERGENIO_LINESTATE_OVERRUN_ERR		(1 << 1)
#define SERGENIO_LINESTATE_PARITY_ERR		(1 << 2)
#define SERGENIO_LINESTATE_FRAMING_ERR		(1 << 3)
#define SERGENIO_LINESTATE_BREAK		(1 << 4)
#define SERGENIO_LINESTATE_XMIT_HOLD_EMPTY	(1 << 5)
#define SERGENIO_LINESTATE_XMIT_SHIFT_EMPTY	(1 << 6)
#define SERGENIO_LINESTATE_TIMEOUT_ERR		(1 << 7)
int sergenio_linestate(struct sergenio *sio, unsigned int linestate);

#define SERGENIO_MODEMSTATE_CTS_CHANGED		(1 << 0)
#define SERGENIO_MODEMSTATE_DSR_CHANGED		(1 << 1)
#define SERGENIO_MODEMSTATE_RI_CHANGED		(1 << 2)
#define SERGENIO_MODEMSTATE_CD_CHANGED		(1 << 3)
#define SERGENIO_MODEMSTATE_CTS			(1 << 4)
#define SERGENIO_MODEMSTATE_DSR			(1 << 5)
#define SERGENIO_MODEMSTATE_RI			(1 << 6)
#define SERGENIO_MODEMSTATE_CD			(1 << 7)
int sergenio_modemstate(struct sergenio *sio, unsigned int modemstate);

/*
 * Tell the remote end to enable or disable flow control.
 */
int sergenio_flowcontrol_state(struct sergenio *sio, bool val);

/*
 *
 */
#define SERGIO_FLUSH_RCV_BUFFER		1
#define SERGIO_FLUSH_XMIT_BUFFER	2
#define SERGIO_FLUSH_RCV_XMIT_BUFFERS	3
int sergino_flush(struct sergenio *sio, unsigned int val);


/*
 * Return the user data supplied in the alloc function.
 */
void *sergenio_get_user_data(struct sergenio *io);

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
 */
struct sergenio_b;

int sergenio_b_alloc(struct sergenio *sio, struct genio_os_funcs *o,
		     struct sergenio_b **new_sbio);
void sergenio_b_free(struct sergenio_b *sbio);
int sergenio_baud_b(struct sergenio_b *sbio, int *baud);
int sergenio_datasize_b(struct sergenio_b *sbio, int *datasize);
int sergenio_parity_b(struct sergenio_b *sbio, int *parity);
int sergenio_stopbits_b(struct sergenio_b *sbio, int *stopbits);
int sergenio_flowcontrol_b(struct sergenio_b *sbio, int *flowcontrol);
int sergenio_sbreak_b(struct sergenio_b *sbio, int *breakv);
int sergenio_dtr_b(struct sergenio_b *sbio, int *dtr);
int sergenio_rts_b(struct sergenio_b *sbio, int *rts);

/*
 * Callbacks for dynamic changes to the serial port.  The user may
 * supply a NULL one of these if they don't care.
 */

struct sergenio_callbacks {
    /*
     * On the client side, these are for reporting changes to the
     * client.  On the server side, this is for reporting that the
     * client has requested the mask be changed.
     */
    void (*modemstate)(struct sergenio *sio, unsigned int modemstate);
    void (*linestate)(struct sergenio *sio, unsigned int linestate);

    /*
     * The remote end is asking the user to flow control or flush.
     */
    void (*flowcontrol_state)(struct sergenio *sio, bool val);
    void (*flush)(struct sergenio *sio, unsigned int val);

    /*
     * Server callbacks.  These only come in in server mode, you must
     * call the equivalent sergenio_xxx() function to return the response,
     * though the done callback is ignored in that case.
     */
    void (*baud)(struct sergenio *sio, int baud);
    void (*datasize)(struct sergenio *sio, int datasize);
    void (*parity)(struct sergenio *sio, int parity);
    void (*stopbits)(struct sergenio *sio, int stopbits);
    void (*flowcontrol)(struct sergenio *sio, int flowcontrol);
    void (*sbreak)(struct sergenio *sio, int breakv);
    void (*dtr)(struct sergenio *sio, int dtr);
    void (*rts)(struct sergenio *sio, int rts);
};

bool sergenio_is_client(struct sergenio *sio);

/*
 * Set the sergenio callbacks.  This should only be done if the genio
 * is closed or completely disabled for read and not in a write.
 */
void sergenio_set_ser_cbs(struct sergenio *sio,
			  struct sergenio_callbacks *scbs);

/*
 * Allocate a sergenio based on a string.
 */
int str_to_sergenio(const char *str, struct genio_os_funcs *o,
		    unsigned int read_buffer_size,
		    const struct sergenio_callbacks *scbs,
		    const struct genio_callbacks *cbs, void *user_data,
		    struct sergenio **sio);

int sergenio_telnet_alloc(struct genio *child, char *args[],
			  struct genio_os_funcs *o,
			  const struct sergenio_callbacks *scbs,
			  const struct genio_callbacks *cbs, void *user_data,
			  struct sergenio **sio);

int sergenio_termios_alloc(const char *devname, struct genio_os_funcs *o,
			   unsigned int read_buffer_size,
			   const struct sergenio_callbacks *scbs,
			   const struct genio_callbacks *cbs, void *user_data,
			   struct sergenio **sio);

#endif /* SER2NET_SERGENIO_H */
