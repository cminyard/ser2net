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

#ifndef CONTROLLER
#define CONTROLLER

#define CONTROLLER_INVALID_TCP_SPEC	-1
#define CONTROLLER_CANT_OPEN_PORT	-2
/* Initialize the controller code, return -1 on error. */
int controller_init(char *controller_port);

/* Disable the control port. */
void controller_shutdown(void);

struct controller_info;

/* Send some output to a controller port.  The data field is the data
   to write, the count field is the number of bytes to write. */
void controller_output(struct controller_info *cntlr, char *data, int count);

/* Write some data directly to the controllers output port. */
void controller_write(struct controller_info *cntlr, char *data, int count);

#endif /* CONTROLLER */
