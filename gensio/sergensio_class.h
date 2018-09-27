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

#ifndef SERGENSIO_CLASS_H
#define SERGENSIO_CLASS_H

#include <stddef.h>
#include <gensio/gensio_class.h>
#include <gensio/sergensio.h>

#define SERGENSIO_FUNC_BAUD			1
#define SERGENSIO_FUNC_DATASIZE			2
#define SERGENSIO_FUNC_PARITY			3
#define SERGENSIO_FUNC_STOPBITS			4
#define SERGENSIO_FUNC_FLOWCONTROL		5
#define SERGENSIO_FUNC_IFLOWCONTROL		6
#define SERGENSIO_FUNC_SBREAK			7
#define SERGENSIO_FUNC_DTR			8
#define SERGENSIO_FUNC_RTS			9
#define SERGENSIO_FUNC_MODEMSTATE		10
#define SERGENSIO_FUNC_LINESTATE		11
#define SERGENSIO_FUNC_FLOWCONTROL_STATE	12
#define SERGENSIO_FUNC_FLUSH			13
#define SERGENSIO_FUNC_SIGNATURE		14
#define SERGENSIO_FUNC_SEND_BREAK		15

typedef int (*sergensio_func)(struct sergensio *sio, int op, int val, char *buf,
			      void *done, void *cb_data);


struct sergensio *sergensio_data_alloc(struct gensio_os_funcs *o,
				       struct gensio *io,
				       sergensio_func func,
				       void *gensio_data);
void sergensio_data_free(struct sergensio *sio);

void *sergensio_get_gensio_data(struct sergensio *sio);

#endif /* SERGENSIO_CLASS_H */
