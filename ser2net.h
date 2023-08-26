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

#ifndef SER2NET_H
#define SER2NET_H

#include <gensio/gensio_selector.h>
#include <gensio/gensio.h>
#include <gensio/gensio_list.h>

#include "absout.h"

/* The default rfc2217 signature if none is provided. */
extern char *rfc2217_signature;

extern struct gensio_os_funcs *so;

extern int ser2net_debug;
extern int ser2net_debug_level;

extern int ser2net_wake_sig;

#if (defined(gensio_version_major) && (gensio_version_major > 2 ||	\
     (gensio_version_major == 2 && gensio_version_minor >= 2)))
#define DO_MDNS
#endif

void init_mdns(void);

void start_maint_op(void);
void end_maint_op(void);
int reread_config_file(const char *reqtype, struct absout *eout);

int init_dataxfer(void);
void shutdown_dataxfer(void);

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
int handle_acc_auth_event(const char *authdir, const char *pamauth,
			  const struct gensio_list *allowed_users,
			  int event, void *data);

/*
 * Add to/free the list of allowed users.
 */
int add_allowed_users(struct gensio_list **users, const char *str,
		      struct absout *eout);
void free_user_list(struct gensio_list *users);

/* System err output (syslog on *nix). */
extern struct absout seout;

void do_gensio_log(const char *name, struct gensio_loginfo *i);

#ifdef _WIN32
#define DIRSEP '\\'
#define DIRSEPS "\\"
#else
#define DIRSEP '/'
#define DIRSEPS "/"
#endif

#define S2N_CONFDIR SYSCONFDIR DIRSEPS "ser2net"
#define S2N_AUTHDIR DATAROOT DIRSEPS "ser2net" DIRSEPS "auth"
#define S2N_ADMIN_AUTHDIR SYSCONFDIR DIRSEPS "ser2net" DIRSEPS "auth"
#define S2N_KEYFILE SYSCONFDIR DIRSEPS "ser2net" DIRSEPS "ser2net.key"
#define S2N_CERTFILE SYSCONFDIR DIRSEPS "ser2net" DIRSEPS "ser2net.crt"

#endif /* SER2NET_H */
