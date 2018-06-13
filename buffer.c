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
do_write(struct devio *io, struct netio *net, int fd, void  *buf, size_t buflen,
	 size_t *written)
{
    int err = 0;
    ssize_t write_count;

    if (io) {
	write_count = io->f->write(io, buf, buflen);
	if (write_count == -1)
	    err = errno;
    } else if (net) {
	int count;

	write_count = -1;
	err = netio_write(net, &count, buf, buflen);
	if (!err)
	    write_count = count;
    } else {
	write_count = write(fd, buf, buflen);
	if (write_count == -1)
	    err = errno;
    }

    if (err == EINTR || err == EAGAIN || err == EWOULDBLOCK) {
	err = 0;
	*written = 0;
    } else if (!err) {
	*written = write_count;
    }
    return err;
}

static int
lbuffer_write(struct devio *io, struct netio *net, int fd,
	      struct sbuf *buf, int *buferr)
{
    int err;
    size_t write_count;
    int towrite1;
    int towrite2 = 0;

    if (buf->pos + buf->cursize > buf->maxsize) {
	towrite1 = buf->maxsize - buf->pos;
	towrite2 = buf->cursize - towrite1;
    } else {
	towrite1 = buf->cursize;
    }

    if (towrite1 > 0) {
	err = do_write(io, net, fd, buf->buf + buf->pos, towrite1,
		       &write_count);
	if (err) {
	    *buferr = err;
	    return -1;
	}

	buf->pos += write_count;
	buf->cursize -= write_count;
	if (write_count < towrite1)
	    return 0;
    }

    if (towrite2 > 0) {
	/* We wrapped */
	buf->pos = 0;
	err = do_write(io, net, fd, buf->buf, towrite2, &write_count);
	if (err) {
	    *buferr = errno;
	    return -1;
	}
	buf->pos += write_count;
	buf->cursize -= write_count;
    }

    return 0;
}

int
buffer_write(int fd, struct sbuf *buf, int *buferr)
{
    return lbuffer_write(NULL, NULL, fd, buf, buferr);
}

int
buffer_net_send(struct netio *net, struct sbuf *buf, int *buferr)
{
    return lbuffer_write(NULL, net, -1, buf, buferr);
}

int
buffer_io_write(struct devio *io, struct sbuf *buf, int *buferr)
{
    return lbuffer_write(io, NULL, -1, buf, buferr);
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
