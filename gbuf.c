/*
 *  ser2net - A program for allowing telnet connection to serial ports
 *  Copyright (C) 2001-2020  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "gbuf.h"

gensiods
gbuf_room_left(struct gbuf *buf) {
    return buf->maxsize - buf->cursize;
}

void
gbuf_append(struct gbuf *buf, unsigned char *data, gensiods len)
{
    memcpy(buf->buf + buf->pos, data, len);
    buf->cursize += len;
    buf->pos += len;
}

gensiods
gbuf_cursize(struct gbuf *buf)
{
    return buf->cursize;
}

void
gbuf_reset(struct gbuf *buf)
{
    buf->cursize = 0;
    buf->pos = 0;
}

int
gbuf_init(struct gbuf *buf, gensiods size)
{
    buf->buf = malloc(size);
    if (!buf->buf)
	return ENOMEM;

    buf->maxsize = size;
    gbuf_reset(buf);
    return 0;
}

void
gbuf_free(struct gbuf *buf)
{
    if (buf->buf)
	free(buf->buf);
    free(buf);
}
