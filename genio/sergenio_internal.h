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
    int (*baud)(struct sergenio *snet, int baud,
		void (*done)(struct sergenio *snet, int err,
			     int baud, void *cb_data),
		void *cb_data);

    int (*datasize)(struct sergenio *snet, int datasize,
		    void (*done)(struct sergenio *snet, int err, int datasize,
				 void *cb_data),
		    void *cb_data);

    int (*parity)(struct sergenio *snet, int parity,
		  void (*done)(struct sergenio *snet, int err, int parity,
			       void *cb_data),
		  void *cb_data);

    int (*stopbits)(struct sergenio *snet, int stopbits,
		    void (*done)(struct sergenio *snet, int err, int stopbits,
				 void *cb_data),
		    void *cb_data);

    int (*flowcontrol)(struct sergenio *snet, int flowcontrol,
		       void (*done)(struct sergenio *snet, int err,
				    int flowcontrol, void *cb_data),
		       void *cb_data);

    int (*breakv)(struct sergenio *snet, int breakv,
		 void (*done)(struct sergenio *snet, int err, int breakv,
			      void *cb_data),
		 void *cb_data);

    int (*dtr)(struct sergenio *snet, int dtr,
	       void (*done)(struct sergenio *snet, int err, int dtr,
			    void *cb_data),
	       void *cb_data);

    int (*rts)(struct sergenio *snet, int rts,
	       void (*done)(struct sergenio *snet, int err, int rts,
			    void *cb_data),
	       void *cb_data);
};

/*
 * This structure represents a network connection, return from the
 * acceptor callback in sergenio_acceptor.
 */
struct sergenio {
    struct genio net;

    const struct sergenio_callbacks *scbs;

    const struct sergenio_functions *funcs;
};

#endif /* SER2NET_SERGENIO_INTERNAL_H */
