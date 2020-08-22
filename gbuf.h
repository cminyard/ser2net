/*
 *  ser2net - A program for allowing telnet connection to serial ports
 *  Copyright (C) 2001-2020  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef GBUF
#define GBUF

#include <gensio/gensio.h>

struct gbuf {
    unsigned char *buf;
    gensiods maxsize;
    gensiods cursize;
    gensiods pos;
};

gensiods gbuf_room_left(struct gbuf *buf);

void gbuf_append(struct gbuf *buf, unsigned char *data, gensiods len);

gensiods gbuf_cursize(struct gbuf *buf);

void gbuf_reset(struct gbuf *buf);

int gbuf_init(struct gbuf *buf, gensiods size);

void gbuf_free(struct gbuf *buf);

#endif /* GBUF */
