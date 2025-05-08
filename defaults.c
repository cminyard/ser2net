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

#include <string.h>
#include <stdlib.h>
#include <gensio/gensio.h>
#include "ser2net.h"
#include "defaults.h"

#define PORT_BUFSIZE	64	/* Default data transfer buffer size */

struct default_data
{
    const char *name;
    enum gensio_default_type type;
    int min;
    int max;
    struct {
	int intval;
	const char *strval;
    } def;
    struct gensio_enum_val *enums;
};

static struct default_data defaults[] = {
    /* All port types */
    { "telnet-brk-on-sync",GENSIO_DEFAULT_BOOL,.def.intval = 0 },
    { "kickolduser",	GENSIO_DEFAULT_BOOL,	.def.intval = 0 },
    { "timeout-on-os-queue", GENSIO_DEFAULT_BOOL, .def.intval = 0 },
    { "chardelay",	GENSIO_DEFAULT_BOOL,	.def.intval = 1 },
    { "chardelay-scale",GENSIO_DEFAULT_INT,	.min = 1, .max = 1000,
					.def.intval = 20 },
    { "chardelay-min",	GENSIO_DEFAULT_INT,	.min = 1, .max = 100000,
					.def.intval = 1000 },
    { "chardelay-max",	GENSIO_DEFAULT_INT,	.min = 1, .max = 1000000,
					.def.intval = 20000 },
    { "dev-to-net-bufsize", GENSIO_DEFAULT_INT,.min = 1, .max = 65536,
					.def.intval = PORT_BUFSIZE },
    { "net-to-dev-bufsize", GENSIO_DEFAULT_INT,.min = 1, .max = 65536,
					.def.intval = PORT_BUFSIZE },
    { "max-connections", GENSIO_DEFAULT_INT,	.min=1, .max=65536,
					.def.intval = 1 },
    { "connector-retry-time", GENSIO_DEFAULT_INT, .min=1, .max=10000000,
					.def.intval = 10 },
    { "accepter-retry-time", GENSIO_DEFAULT_INT, .min=1, .max=10000000,
					.def.intval = 10 },
    { "remaddr",	GENSIO_DEFAULT_STR,	.def.strval = NULL },
    { "connback",	GENSIO_DEFAULT_STR,	.def.strval = NULL },
    { "authdir",	GENSIO_DEFAULT_STR,	.def.strval = NULL },
    { "authdir-admin",	GENSIO_DEFAULT_STR,	.def.strval = NULL },
    { "pamauth",	GENSIO_DEFAULT_STR,	.def.strval = NULL },
    { "pamauth-admin",	GENSIO_DEFAULT_STR,	.def.strval = NULL },
    { "allowed-users",	GENSIO_DEFAULT_STR,	.def.strval = NULL },
    { "signature",	GENSIO_DEFAULT_STR,	.def.strval = "ser2net" },
    { "openstr",	GENSIO_DEFAULT_STR,	.def.strval = NULL },
    { "closestr",	GENSIO_DEFAULT_STR,	.def.strval = NULL },
    { "closeon",	GENSIO_DEFAULT_STR,	.def.strval = NULL },
    { "banner",		GENSIO_DEFAULT_STR,	.def.strval = NULL },
    { "sendon",		GENSIO_DEFAULT_STR,	.def.strval = NULL },
    { "mdns",		GENSIO_DEFAULT_BOOL,	.def.intval = 0 },
    { "mdns-sysattrs",	GENSIO_DEFAULT_BOOL,	.def.intval = 0 },
    { "mdns-type",	GENSIO_DEFAULT_STR,	.def.strval = NULL },
    { "mdns-domain",	GENSIO_DEFAULT_STR,	.def.strval = NULL },
    { "mdns-host",	GENSIO_DEFAULT_STR,	.def.strval = NULL },
    { "mdns-interface",	GENSIO_DEFAULT_INT,	.min=-1, .max=100000,
					.def.intval = -1},
    { NULL }
};

static int
setup_ser2net_defaults(void)
{
    unsigned int i;
    int err;

    for (i = 0; defaults[i].name; i++) {
	err = gensio_set_default(so, NULL, defaults[i].name,
				 defaults[i].def.strval,
				 defaults[i].def.intval);
	if (err)
	    return err;
    }
    err = gensio_set_default(so, NULL, "authdir", authdir, 0);
    if (err)
      return err;
    err = gensio_set_default(so, NULL, "authdir-admin", admin_authdir, 0);
    if (err)
      return err;
    err = gensio_set_default(so, "ssl", "key", keyfile, 0);
    if (err)
	return err;
    err = gensio_set_default(so, "ssl", "cert", certfile, 0);
    if (err)
	return err;
#ifdef gensio_version_ge /* gensio_version_ge came in with 2.2.3 and 2.3.0 */
    /* Print out a message on the socket if tcpd denies a connection. */
    err = gensio_set_default(so, "tcp", "tcpd", "print", 0);
    /* If GE_NOTFOUND is returned, that means gensio doesn't have tcpd. */
    if (err && err != GE_NOTFOUND)
	return err;
#endif
    return 0;
}

int
setup_defaults(void)
{
    unsigned int i;
    int err;
    static bool defaults_added = false;

    if (defaults_added) {
	gensio_reset_defaults(so);
    } else {
	for (i = 0; defaults[i].name; i++) {
	    err = gensio_add_default(so, defaults[i].name,
				     defaults[i].type, defaults[i].def.strval,
				     defaults[i].def.intval, defaults[i].min,
				     defaults[i].max, defaults[i].enums);
	    if (err && err != GE_EXISTS)
		return err;
	}
	defaults_added = true;
    }
    return setup_ser2net_defaults();
}

int
find_default_int(const char *name)
{
    int err, val;

    err = gensio_get_default(so, "ser2net", name, false, GENSIO_DEFAULT_INT,
			     NULL, &val);
    if (err)
	abort();

    return val;
}

bool
find_default_bool(const char *name)
{
    int err;
    int val;

    err = gensio_get_default(so, "ser2net", name, false, GENSIO_DEFAULT_BOOL,
			     NULL, &val);
    if (err)
	abort();

    return val;
}

int
find_default_str(const char *name, char **rstr)
{
    int err;
    char *val;
    char *newstr = NULL;

    err = gensio_get_default(so, "ser2net", name, false, GENSIO_DEFAULT_STR,
			     &val, NULL);
    if (err)
	abort();

    if (val) {
	newstr = strdup(val);
	so->free(so, val);
	if (!newstr)
	    return GE_NOMEM;
    }
    *rstr = newstr;
    return 0;
}
