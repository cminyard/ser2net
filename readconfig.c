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

/* This file holds the code that reads the configuration file and
   calls the code in dataxfer to actually create all the ports in the
   configuration file. */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "dataxfer.h"
#include "readconfig.h"

#define MAX_LINE_SIZE 256	/* Maximum line length in the config file. */

/* Read the specified configuration file and call the routine to
   create the ports. */
int
readconfig(char *filename)
{
    FILE *instream;
    char inbuf[MAX_LINE_SIZE];
    int  lineno = 0;
    int  rv = 0;

    instream = fopen(filename, "r");
    if (instream == NULL) {
	fprintf(stderr, "Unable to open config file '%s'\n", filename);
	return -1;
    }

    while (fgets(inbuf, MAX_LINE_SIZE, instream) != NULL) {
	int len = strlen(inbuf);
	char *portnum, *state, *timeout, *devname, *devcfg;
	char *strtok_data;
	char *errstr;

	lineno++;
	if (inbuf[len-1] != '\n') {
	    fprintf(stderr, "line %d is too long in config file\n", lineno);
	    rv = -1;
	    goto out;
	}

	if (inbuf[0] == '#') {
	    /* Ignore comments. */
	    continue;
	}

	inbuf[len-1] = '\0';
	portnum = strtok_r(inbuf, ":", &strtok_data);
	if (portnum == NULL) {
	    /* An empty line is ok. */
	    continue;
	}

	state = strtok_r(NULL, ":", &strtok_data);
	if (state == NULL) {
	    fprintf(stderr, "No state given on line %d\n", lineno);
	    rv = -1;
	    goto out;
	}

	timeout = strtok_r(NULL, ":", &strtok_data);
	if (timeout == NULL) {
	    fprintf(stderr, "No timeout given on line %d\n", lineno);
	    rv = -1;
	    goto out;
	}

	devname = strtok_r(NULL, ":", &strtok_data);
	if (devname == NULL) {
	    fprintf(stderr, "No device name given on line %d\n", lineno);
	    rv = -1;
	    goto out;
	}

	devcfg = strtok_r(NULL, ":", &strtok_data);
	if (devcfg == NULL) {
	    /* An empty device config is ok. */
	    devcfg = "";
	}

	errstr = portconfig(portnum, state, timeout, devname, devcfg);
	if (errstr != NULL) {
	    fprintf(stderr, "Error on line %d, %s\n", lineno, errstr);
	    rv = -1;
	    goto out;
	}
    }

out:
    fclose(instream);
    return rv;
}

