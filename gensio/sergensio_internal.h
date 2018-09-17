/*
 *  gensio - A library for abstracting stream I/O
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

#ifndef SERGENSIO_INTERNAL_H
#define SERGENSIO_INTERNAL_H

#include <stddef.h>
#include <gensio/gensio_internal.h>
#include <gensio/sergensio.h>

#define GENSIO_TELNET_DEFAULT_BUFSIZE 1024

struct sergensio_functions {
    int (*baud)(struct sergensio *sio, int baud,
		void (*done)(struct sergensio *sio, int err,
			     int baud, void *cb_data),
		void *cb_data);

    int (*datasize)(struct sergensio *sio, int datasize,
		    void (*done)(struct sergensio *sio, int err, int datasize,
				 void *cb_data),
		    void *cb_data);

    int (*parity)(struct sergensio *sio, int parity,
		  void (*done)(struct sergensio *sio, int err, int parity,
			       void *cb_data),
		  void *cb_data);

    int (*stopbits)(struct sergensio *sio, int stopbits,
		    void (*done)(struct sergensio *sio, int err, int stopbits,
				 void *cb_data),
		    void *cb_data);

    int (*flowcontrol)(struct sergensio *sio, int flowcontrol,
		       void (*done)(struct sergensio *sio, int err,
				    int flowcontrol, void *cb_data),
		       void *cb_data);

    int (*iflowcontrol)(struct sergensio *sio, int iflowcontrol,
			void (*done)(struct sergensio *sio, int err,
				     int iflowcontrol, void *cb_data),
			void *cb_data);

    int (*sbreak)(struct sergensio *sio, int breakv,
		  void (*done)(struct sergensio *sio, int err, int breakv,
			       void *cb_data),
		  void *cb_data);

    int (*dtr)(struct sergensio *sio, int dtr,
	       void (*done)(struct sergensio *sio, int err, int dtr,
			    void *cb_data),
	       void *cb_data);

    int (*rts)(struct sergensio *sio, int rts,
	       void (*done)(struct sergensio *sio, int err, int rts,
			    void *cb_data),
	       void *cb_data);

    int (*modemstate)(struct sergensio *sio, unsigned int val);
    int (*linestate)(struct sergensio *sio, unsigned int val);
    int (*flowcontrol_state)(struct sergensio *sio, bool val);
    int (*flush)(struct sergensio *sio, unsigned int val);

    int (*signature)(struct sergensio *sio, char *sig, unsigned int len,
		     void (*done)(struct sergensio *sio, int err, char *sig,
				  unsigned int sig_len, void *cb_data),
		     void *cb_data);

    void (*callbacks_set)(struct sergensio *sio);
};

/*
 * This structure represents a network connection, return from the
 * acceptor callback in sergensio_acceptor.
 */
struct sergensio {
    struct gensio *io;

    const struct sergensio_callbacks *scbs;

    const struct sergensio_functions *funcs;
};

#endif /* SERGENSIO_INTERNAL_H */
