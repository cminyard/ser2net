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

#ifndef DATAXFER
#define DATAXFER

#include "controller.h"

/* Create a port given the criteria. */
char * portconfig(char *portnum,
		  char *state,
		  char *timeout,
		  char *devname,
		  char *devcfg);

/* Initialize the data transfer code. */
void dataxfer_init(void);

/* Show information about a port (or all ports if portspec is NULL).
   The parameters are all strings that the routine will convert to
   integers.  Error output will be generated on invalid data. */
void showports(struct controller_info *cntlr, char *portspec);

/* Set the port's timeout.  The parameters are all strings that the
   routine will convert to integers.  Error output will be generated
   on invalid data. */
void setporttimeout(struct controller_info *cntlr,
		    char *portspec,
		    char *timeout);

/* Set the serial port's configuration.  The parameters are all
   strings that the routine will convert to integers.  Error output
   will be generated on invalid data. */
void setportdevcfg(struct controller_info *cntlr,
		   char *portspec,
		   char *devcfg);

/* Set the enable state of a port (off, raw, telnet).  The parameters
   are all strings that the routine will convert to integers.  Error
   output will be generated on invalid data. */
void setportenable(struct controller_info *cntlr,
		   char *portspec,
		   char *enable);

#endif /* DATAXFER */
