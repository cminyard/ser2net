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

#ifndef DEVCFG
#define DEVCFG

#include <termios.h>
#include "dataxfer.h"

struct io;

typedef struct trace_info_s
{
    int            hexdump;     /* output each block as a hexdump */
    int            timestamp;   /* preceed each line with a timestamp */
    const char     *file;        /* open file.  NULL if not used */
} trace_info_t;

typedef struct dev_info {
    /* Allow RFC 2217 mode */
    int allow_2217;

    /* Banner to display at startup, or NULL if none. */
    const char *banner;

    /* RFC 2217 signature. */
    const char *signature;

    /* String to send to device at startup, or NULL if none. */
    const char *openstr;

    /* String to send to device at close, or NULL if none. */
    const char *closestr;

    /*
     * File to read/write trace, NULL if none.  If the same, then
     * trace information is in the same file, only one open is done.
     */
    trace_info_t trace_read;
    trace_info_t trace_write;
    trace_info_t trace_both;
} dev_info_t;

int devcfg_init(struct io *io, struct absout *eout, const char *instr,
		int (*otherconfig)(void *data, struct absout *eout,
				   const char *item),
		void *data);

#endif /* DEVCFG */
