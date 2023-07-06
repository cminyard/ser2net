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

#ifndef SER2NET_MDNS
#define SER2NET_MDNS

#include "ser2net.h"

#ifdef DO_MDNS

#include <gensio/gensio.h>
#include <gensio/gensio_mdns.h>
#include <gensio/argvutils.h>

extern struct gensio_mdns *mdns;
extern struct gensio_enum_val mdns_nettypes[];

struct mdns_info {
    struct gensio_accepter *acc;
    bool mdns;
    unsigned int mdns_port;
    int mdns_interface;
    int mdns_nettype;
    char *mdns_name;
    char *mdns_type;
    char *mdns_domain;
    char *mdns_host;
    const char **mdns_txt;
    gensiods mdns_txt_argc;
    gensiods mdns_txt_args;
    struct gensio_mdns_service *mdns_service;
};

void msnd_info_init(struct mdns_info *m);
int mdns_info_getdefaults(struct mdns_info *m, const char *str,
			  struct absout *eout);
int mdns_checkoption(const char *option, struct mdns_info *m,
		     const char *name, struct absout *eout);
void mdns_setup(struct mdns_info *m, const char *name,
		struct gensio_accepter *acc, struct absout *eout);
void mdns_shutdown(struct mdns_info *m);

#endif

#endif /* SER2NET_MDNS */
