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

#ifndef _SER2NET_BUFFER_H
#define _SER2NET_BUFFER_H

struct sbuf {
    unsigned char *buf;
    unsigned int maxsize;
    unsigned int cursize;
    unsigned int pos;
};

typedef int (*buffer_do_write)(void *cbdata, void *buf, unsigned int buflen,
			       unsigned int *written);

int buffer_write(buffer_do_write do_write, void *cb_data,
		 struct sbuf *buf, int *buferr);

int buffer_output(struct sbuf *buf, const unsigned char *data,
		  unsigned int len);

int buffer_outchar(struct sbuf *buf, unsigned char data);

int buffer_init(struct sbuf *buf, unsigned char *data, unsigned int datalen);

#define buffer_left(buf) ((buf)->maxsize - (buf)->cursize)

#define buffer_cursize(buf) ((buf)->cursize)

#define buffer_curptr(bufp) ((bufp)->buf + (bufp)->pos)

#define buffer_reset(buf) \
    do {			\
	(buf)->cursize = 0;	\
	(buf)->pos = 0;		\
    } while(0)

#endif /* _SER2NET_BUFFER_H */
