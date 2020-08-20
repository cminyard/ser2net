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
