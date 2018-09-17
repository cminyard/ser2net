/*
 *  ser2net - A program for allowing telnet connection to serial ports
 *  Copyright (C) 2001  Corey Minyard <minyard@acm.org>
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

#ifndef SER2NET_SERGENIO_INTERNAL_H
#define SER2NET_SERGENIO_INTERNAL_H

#include <stddef.h>
#include "genio_internal.h"
#include "sergenio.h"

struct sergenio_functions {
    int (*baud)(struct sergenio *sio, int baud,
		void (*done)(struct sergenio *sio, int err,
			     int baud, void *cb_data),
		void *cb_data);

    int (*datasize)(struct sergenio *sio, int datasize,
		    void (*done)(struct sergenio *sio, int err, int datasize,
				 void *cb_data),
		    void *cb_data);

    int (*parity)(struct sergenio *sio, int parity,
		  void (*done)(struct sergenio *sio, int err, int parity,
			       void *cb_data),
		  void *cb_data);

    int (*stopbits)(struct sergenio *sio, int stopbits,
		    void (*done)(struct sergenio *sio, int err, int stopbits,
				 void *cb_data),
		    void *cb_data);

    int (*flowcontrol)(struct sergenio *sio, int flowcontrol,
		       void (*done)(struct sergenio *sio, int err,
				    int flowcontrol, void *cb_data),
		       void *cb_data);

    int (*iflowcontrol)(struct sergenio *sio, int iflowcontrol,
			void (*done)(struct sergenio *sio, int err,
				     int iflowcontrol, void *cb_data),
			void *cb_data);

    int (*sbreak)(struct sergenio *sio, int breakv,
		  void (*done)(struct sergenio *sio, int err, int breakv,
			       void *cb_data),
		  void *cb_data);

    int (*dtr)(struct sergenio *sio, int dtr,
	       void (*done)(struct sergenio *sio, int err, int dtr,
			    void *cb_data),
	       void *cb_data);

    int (*rts)(struct sergenio *sio, int rts,
	       void (*done)(struct sergenio *sio, int err, int rts,
			    void *cb_data),
	       void *cb_data);

    int (*modemstate)(struct sergenio *sio, unsigned int val);
    int (*linestate)(struct sergenio *sio, unsigned int val);
    int (*flowcontrol_state)(struct sergenio *sio, bool val);
    int (*flush)(struct sergenio *sio, unsigned int val);

    int (*signature)(struct sergenio *sio, char *sig, unsigned int len,
		     void (*done)(struct sergenio *sio, int err, char *sig,
				  unsigned int sig_len, void *cb_data),
		     void *cb_data);
};

/*
 * This structure represents a network connection, return from the
 * acceptor callback in sergenio_acceptor.
 */
struct sergenio {
    struct genio *io;

    const struct sergenio_callbacks *scbs;

    const struct sergenio_functions *funcs;
};

#endif /* SER2NET_SERGENIO_INTERNAL_H */
