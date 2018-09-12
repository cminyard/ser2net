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
struct genio *sergenio_to_genio(struct sergenio *snet);
struct sergenio *genio_to_sergenio(struct genio *net);
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
 * If the done() callback is NULL, no callback is done.
 */

int sergenio_baud(struct sergenio *snet, int baud,
		  void (*done)(struct sergenio *snet, int err,
			       int baud, void *cb_data),
		  void *cb_data);

int sergenio_datasize(struct sergenio *snet, int datasize,
		      void (*done)(struct sergenio *snet, int err, int datasize,
				   void *cb_data),
		      void *cb_data);

#define SERGENIO_PARITY_NONE	1
#define SERGENIO_PARITY_ODD	2
#define SERGENIO_PARITY_EVEN	3
#define SERGENIO_PARITY_MARK	4
#define SERGENIO_PARITY_SPACE	5
int sergenio_parity(struct sergenio *snet, int parity,
		    void (*done)(struct sergenio *snet, int err, int parity,
				 void *cb_data),
		    void *cb_data);

int sergenio_stopbits(struct sergenio *snet, int stopbits,
		      void (*done)(struct sergenio *snet, int err, int stopbits,
				   void *cb_data),
		      void *cb_data);

#define SERGENIO_FLOWCONTROL_NONE	1
#define SERGENIO_FLOWCONTROL_XON_XOFF	2
#define SERGENIO_FLOWCONTROL_RTS_CTS	3
int sergenio_flowcontrol(struct sergenio *snet, int flowcontrol,
			 void (*done)(struct sergenio *snet, int err,
				      int flowcontrol, void *cb_data),
			 void *cb_data);

#define SERGENIO_BREAK_ON	1
#define SERGENIO_BREAK_OFF	2
int sergenio_sbreak(struct sergenio *snet, int breakv,
		    void (*done)(struct sergenio *snet, int err, int breakv,
				 void *cb_data),
		    void *cb_data);

#define SERGENIO_DTR_ON		1
#define SERGENIO_DTR_OFF	2
int sergenio_dtr(struct sergenio *snet, int dtr,
		 void (*done)(struct sergenio *snet, int err, int dtr,
			      void *cb_data),
		 void *cb_data);

#define SERGENIO_RTS_ON		1
#define SERGENIO_RTS_OFF	2
int sergenio_rts(struct sergenio *snet, int rts,
		 void (*done)(struct sergenio *snet, int err, int rts,
			      void *cb_data),
		 void *cb_data);

/*
 * Return the user data supplied in the alloc function.
 */
void *sergenio_get_user_data(struct sergenio *net);

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
 * in a blocking call using the sbnet.
 */
struct sergenio_b;

int sergenio_b_alloc(struct sergenio *snet, struct genio_os_funcs *o,
		     struct sergenio_b **new_sbnet);
void sergenio_b_free(struct sergenio_b *sbnet);
int sergenio_baud_b(struct sergenio_b *sbnet, int *baud);
int sergenio_datasize_b(struct sergenio_b *sbnet, int *datasize);
int sergenio_parity_b(struct sergenio_b *sbnet, int *parity);
int sergenio_stopbits_b(struct sergenio_b *sbnet, int *stopbits);
int sergenio_flowcontrol_b(struct sergenio_b *sbnet, int *flowcontrol);
int sergenio_sbreak_b(struct sergenio_b *sbnet, int *breakv);
int sergenio_dtr_b(struct sergenio_b *sbnet, int *dtr);
int sergenio_rts_b(struct sergenio_b *sbnet, int *rts);

/*
 * Callbacks for dynamic changes to the serial port.  The user may
 * supply a NULL one of these if they don't care.
 */

struct sergenio_callbacks {
    void (*modemstate_change)(struct sergenio *snet, unsigned int changed_mask,
			      unsigned int modemstate);

    void (*linestate_change)(struct sergenio *snet, unsigned int changed_mask,
			     unsigned int linestate);
};

/*
 * Set the sergenio callbacks.  This should only be done if the genio
 * is closed or completely disabled for read and not in a write.
 */
void sergenio_set_ser_cbs(struct sergenio *sio,
			  struct sergenio_callbacks *scbs);

/*
 * Server callbacks
 */
struct sergenio_server_cbs {
    void (*baud)(void *cb_data, int *baud);
    void (*datasize)(void *cb_data, int *datasize);
    void (*parity)(void *cb_data, int *parity);
    void (*stopbits)(void *cb_data, int *stopbits);
    void (*flowcontrol)(void *cb_data, int *flowcontrol);
    void (*sbreak)(void *cb_data, int *breakv);
    void (*dtr)(void *cb_data, int *dtr);
    void (*rts)(void *cb_data, int *rts);
};

/*
 * Allocate a sergenio based on a string.
 */
int str_to_sergenio(const char *str, struct genio_os_funcs *o,
		    unsigned int read_buffer_size,
		    const struct sergenio_callbacks *scbs,
		    const struct genio_callbacks *cbs, void *user_data,
		    struct sergenio **snet);

int sergenio_telnet_alloc(struct genio *child, char *args[],
			  struct genio_os_funcs *o,
			  const struct sergenio_callbacks *scbs,
			  const struct genio_callbacks *cbs, void *user_data,
			  struct sergenio **snet);

int sergenio_termios_alloc(const char *devname, struct genio_os_funcs *o,
			   unsigned int read_buffer_size,
			   const struct sergenio_callbacks *scbs,
			   const struct genio_callbacks *cbs, void *user_data,
			   struct sergenio **snet);

#endif /* SER2NET_SERGENIO_H */
