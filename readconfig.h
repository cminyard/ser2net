/*
 *  ser2net - A program for allowing telnet connection to serial ports
 *  Copyright (C) 2001-2020  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef READCONFIG
#define READCONFIG
#include <stdio.h>
#include "absout.h"

/* Handle one line of configuration. */
int handle_config_line(char *inbuf, int len);

/* Initialize for a new config read. */
int readconfig_init(void);

/* Read the specified configuration file and call the routine to
   create the ports. */
int readconfig(FILE *instream);
int yaml_readconfig(FILE *f, char **config_lines,
		    unsigned int num_config_lines,
		    struct absout *errout);

/*
 * Search for a banner/open/close string by name.  Note that the
 * returned value needs to be free-ed when done.
 */
enum str_type { BANNER, OPENSTR, CLOSESTR, SIGNATURE, CLOSEON, DEVNAME };
char *find_str(const char *name, enum str_type *type, unsigned int *len);

/*
 * Clean up longstrings.
 */
void free_longstrs(void);
void free_tracefiles(void);
void free_rs485confs(void);

/*
 * Search for a tracefile by name.  Note that the
 * returned value needs to be free-ed when done.
 */
char *find_tracefile(const char *name);

/* Search for RS485 configuration by name. */
char *find_rs485conf(const char *name);

#endif /* READCONFIG */
