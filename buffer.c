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

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include "buffer.h"
#include "devio.h"

static int
lbuffer_write(struct devio *io, int fd, struct sbuf *buf, int *buferr,
	      const struct sockaddr *addr, socklen_t addrlen)
{
    ssize_t write_count;
    int towrite1;
    int towrite2 = 0;

    if (buf->pos + buf->cursize > buf->maxsize) {
	towrite1 = buf->maxsize - buf->pos;
	towrite2 = buf->cursize - towrite1;
    } else
	towrite1 = buf->cursize;

    if (towrite1 > 0) {
	if (io)
	    write_count = io->f->write(io, buf->buf + buf->pos, towrite1);
	else if (addr)
	    write_count = sendto(fd, buf->buf + buf->pos, towrite1, 0,
				 addr, addrlen);
	else
	    write_count = write(fd, buf->buf + buf->pos, towrite1);
	if (write_count == -1) {
	    if (errno == EINTR) {
		/* EINTR means we were interrupted, just retry by returning. */
		return 0;
	    } else if (errno == EAGAIN) {
		/* This again was due to O_NONBLOCK, just ignore it. */
		return 0;
	    } else {
		*buferr = errno;
		return -1;
	    }
	}
	buf->pos += write_count;
	buf->cursize -= write_count;
    }

    if (towrite2 > 0) {
	/* We wrapped */
	buf->pos = 0;
	if (io)
	    write_count = io->f->write(io, buf->buf + buf->pos, towrite2);
	else if (addr)
	    write_count = sendto(fd, buf->buf + buf->pos, towrite2, 0,
				 addr, addrlen);
	else
	    write_count = write(fd, buf->buf + buf->pos, towrite2);
	if (write_count == -1) {
	    if (errno == EINTR) {
		/* EINTR means we were interrupted, just retry by returning. */
		return 0;
	    } else if (errno == EAGAIN) {
		/* This again was due to O_NONBLOCK, just ignore it. */
		return 0;
	    } else {
		*buferr = errno;
		return -1;
	    }
	}
	buf->pos += write_count;
	buf->cursize -= write_count;
    }

    return 0;
}

int
buffer_write(int fd, struct sbuf *buf, int *buferr)
{
    return lbuffer_write(NULL, fd, buf, buferr, NULL, 0);
}

int
buffer_sendto(int fd, const struct sockaddr *addr, socklen_t addrlen,
	      struct sbuf *buf, int *buferr)
{
    return lbuffer_write(NULL, fd, buf, buferr, addr, addrlen);
}

int
buffer_io_write(struct devio *io, struct sbuf *buf, int *buferr)
{
    return lbuffer_write(io, 0, buf, buferr, NULL, 0);
}

int
buffer_output(struct sbuf *buf, unsigned char *data, unsigned int len)
{
    int end;

    if (buffer_left(buf) < len)
	return -1;

    end = buf->pos + buf->cursize;
    if (end > buf->maxsize)
	end -= buf->maxsize;
    if (end + len > buf->maxsize) {
	int availend = buf->maxsize - end;
	memcpy(buf->buf + end, data, availend);
	buf->cursize += availend;
	end = 0;
	len -= availend;
	data += availend;
    }
    memcpy(buf->buf + end, data, len);
    buf->cursize += len;
    return 0;
}

int
buffer_outchar(struct sbuf *buf, unsigned char data)
{
    int end;

    if (buffer_left(buf) < 1)
	return -1;

    end = buf->pos + buf->cursize;
    if (end >= buf->maxsize)
	end -= buf->maxsize;
    buf->buf[end] = data;
    buf->cursize += 1;
    return 0;
}

int
buffer_init(struct sbuf *buf, unsigned char *data, unsigned int datasize)
{
    if (data) {
	buf->buf = data;
    } else {
	buf->buf = malloc(datasize);
	if (!buf->buf)
	    return ENOMEM;
    }
    buf->maxsize = datasize;
    buf->cursize = 0;
    buf->pos = 0;

    return 0;
}
