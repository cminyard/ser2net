/*
 *  ser2net - A program for allowing telnet connection to serial ports
 *  Copyright (C) 2001-2020  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: GPL-2.0-only
 *
 *  In addition, as a special exception, the copyright holders of
 *  ser2net give you permission to combine ser2net with free software
 *  programs or libraries that are released under the GNU LGPL and
 *  with code included in the standard release of OpenSSL under the
 *  OpenSSL license (or modified versions of such code, with unchanged
 *  license). You may copy and distribute such a system following the
 *  terms of the GNU GPL for ser2net and the licenses of the other code
 *  concerned, provided that you include the source code of that
 *  other code when and as the GNU GPL requires distribution of source
 *  code.
 *
 *  Note that people who make modified versions of ser2net are not
 *  obligated to grant this special exception for their modified
 *  versions; it is their choice whether to do so. The GNU General
 *  Public License gives permission to release a modified version
 *  without this exception; this exception also makes it possible to
 *  release a modified version which carries forward this exception.
 */

#include <stdlib.h>
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
	return GE_NOMEM;

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
