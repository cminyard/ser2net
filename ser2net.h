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

#include <gensio/gensio_selector.h>
#include <gensio/gensio.h>

#include "absout.h"

/* The default rfc2217 signature if none is provided. */
extern char *rfc2217_signature;

extern struct gensio_os_funcs *so;

extern int ser2net_debug;
extern int ser2net_debug_level;

extern int ser2net_wake_sig;

void start_maint_op(void);
void end_maint_op(void);
int reread_config_file(const char *reqtype, struct absout *eout);

int init_dataxfer(void);
void shutdown_dataxfer(void);

/* Write the data completely out, return without comment on error. */
void write_ignore_fail(int fd, const char *data, size_t count);

#ifndef gensio_version_major
typedef struct timeval gensio_time;
#endif
void add_usec_to_time(gensio_time *tv, int usec);
int sub_time(gensio_time *left, gensio_time *right);

/* Scan for a positive integer, and return it.  Return -1 if the
   integer was invalid.  Spaces are not handled. */
int scan_int(const char *str);

/*
 * Handle authorization events from accepters.
 */
int handle_acc_auth_event(const char *authdir, int event, void *data);

extern struct absout syslog_absout;

#endif /* SER2NET_H */
