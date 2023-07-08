/*
 *  ser2net - A program for allowing telnet connection to serial ports
 *  Copyright (C) 2023  Corey Minyard <minyard@acm.org>
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

#ifndef FILEIO_H
#define FILEIO_H

#include <stdio.h>

typedef struct ftypes ftype;

#define DO_READ 1
#define DO_WRITE 2
#define DO_CREATE 4
#define DO_APPEND 8

int f_open(const char *filename, int op, int mode, ftype **f);

int f_stdio_open(FILE *stdf, int op, int mode, ftype **f);

int f_close(ftype *f);

int f_write(ftype *f, const void *buf, unsigned int len, unsigned int *outlen);

int f_read(ftype *f, void *buf, unsigned int len, unsigned int *outlen);

int f_gets(ftype *f, char **buf, unsigned int *len, unsigned int *buflen);

#define SEEK_ABSOLUTE 1

int f_seek(ftype *f, unsigned int pos, int op);

#endif /* FILEIO_H */
