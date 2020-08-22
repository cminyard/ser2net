/*
 *  ser2net - A program for allowing telnet connection to serial ports
 *  Copyright (C) 2001-2020  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef DEFAULTS
#define DEFAULTS

#include <gensio/gensio.h>

int setup_defaults(void);

/* Return the default int/bool value for the given name. */
int find_default_int(const char *name);
bool find_default_bool(const char *name);

/* Return the default string value for the given name.  Return GE_NOMEM if
   out of memory.  The returned value must be freed. */
int find_default_str(const char *name, char **rstr);

#endif /* DEFAULTS */
