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

#ifndef SER2NET_H
#define SER2NET_H

#include <gensio/selector.h>
#include <gensio/gensio_selector.h>

#include "absout.h"

/* The default rfc2217 signature if none is provided. */
extern char *rfc2217_signature;

extern struct selector_s *ser2net_sel;
extern struct gensio_os_funcs *so;

extern int ser2net_debug;
extern int ser2net_debug_level;

extern int ser2net_wake_sig;

void start_maint_op(void);
void end_maint_op(void);

int init_dataxfer(void);
void shutdown_dataxfer(void);

/* Write the data completely out, return without comment on error. */
void write_ignore_fail(int fd, const char *data, size_t count);

void add_usec_to_timeval(struct timeval *tv, int usec);
int sub_timeval_us(struct timeval *left, struct timeval *right);

/* Scan for a positive integer, and return it.  Return -1 if the
   integer was invalid.  Spaces are not handled. */
int scan_int(const char *str);

#endif /* SER2NET_H */
