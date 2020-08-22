/*
 *  ser2net - A program for allowing telnet connection to serial ports
 *  Copyright (C) 2001-2020  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: GPL-2.0-only
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
    { "authdir",	GENSIO_DEFAULT_STR,	.def.strval =
						DATAROOT "/ser2net/auth" },
    { "authdir-admin",	GENSIO_DEFAULT_STR,	.def.strval =
						SYSCONFDIR "/ser2net/auth" },
    { "allowed-users",	GENSIO_DEFAULT_STR,	.def.strval = NULL },
    { "signature",	GENSIO_DEFAULT_STR,	.def.strval = "ser2net" },
    { "openstr",	GENSIO_DEFAULT_STR,	.def.strval = NULL },
    { "closestr",	GENSIO_DEFAULT_STR,	.def.strval = NULL },
    { "closeon",	GENSIO_DEFAULT_STR,	.def.strval = NULL },
    { "banner",		GENSIO_DEFAULT_STR,	.def.strval = NULL },
    { "sendon",		GENSIO_DEFAULT_STR,	.def.strval = NULL },
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
    err = gensio_set_default(so, "ssl", "key",
			     SYSCONFDIR "/ser2net/ser2net.key", 0);
    if (err)
	return err;
    err = gensio_set_default(so, "ssl", "cert",
			     SYSCONFDIR "/ser2net/ser2net.crt", 0);
    if (err)
	return err;
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
