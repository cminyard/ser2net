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

#ifndef DATAXFER
#define DATAXFER

#include "controller.h"

#ifdef linux

#include <linux/serial.h>

/* Check, if the toolchain provides SER_RS485_RX_DURING_TX macro
 * (introduced in kernel 3.2) */
#if HAVE_DECL_TIOCSRS485
#ifndef SER_RS485_RX_DURING_TX
#define SER_RS485_RX_DURING_TX          (1 << 4)
#endif /* SER_RS485_RX_DURING_TX */
#endif /* HAVE_DECL_TIOCSRS485 */

#endif /* linux */

/* Create a port given the criteria. */
int portconfig(struct absout *eout,
	       const char *name,
	       const char *accstr,
	       const char *state,
	       unsigned int timeout,
	       const char *devname,
	       const char * const *devcfg);
void apply_new_ports(struct absout *eout);

/* Shut down all the ports, and provide a way to check when done. */
void shutdown_ports(void);
int check_ports_shutdown(void);

/* Initialize the data transfer code. */
void dataxfer_init(void);

/* Show information about a port (or all ports if portspec is NULL).
   The parameters are all strings that the routine will convert to
   integers.  Error output will be generated on invalid data. */
void showports(struct controller_info *cntlr, const char *portspec, bool yaml);

/* Show information about a port (as above) but in a one-line format. */
void showshortports(struct controller_info *cntlr, const char *portspec);

/* Set the port's timeout.  The parameters are all strings that the
   routine will convert to integers.  Error output will be generated
   on invalid data. */
void setporttimeout(struct controller_info *cntlr,
		    const char *portspec,
		    const char *timeout);

/* Modify the DTR and RTS lines for the port. */
void setportcontrol(struct controller_info *cntlr,
		    const char *portspec,
		    char * const controls[]);

/* Set the enable state of a port (off, raw, telnet).  The parameters
   are all strings that the routine will convert to integers.  Error
   output will be generated on invalid data. */
void setportenable(struct controller_info *cntlr,
		   const char *portspec,
		   const char *enable);

/* Start data monitoring on the given port, type may be either "tcp" or
   "term" and only one direction may be monitored.  This return NULL if
   the monitor fails.  The monitor output will go to the controller
   via the controller_write() call. */
void *data_monitor_start(struct controller_info *cntlr,
			 const char *type,
			 const char *portspec);

/* Stop monitoring the given id. */
void data_monitor_stop(struct controller_info *cntlr,
		       void   *monitor_id);

/* Shut down the port, if it is connected. */
void disconnect_port(struct controller_info *cntlr,
		     const char *portspec);

struct port_info;

/* When shutting a port down, call this if it's waiting for write output. */
void finish_dev_to_net_write(struct port_info *port);

struct devio;

/* Initialization function for device I/O */
int devcfg_init(struct devio *io, struct absout *eout, const char *instr,
		int (*otherconfig)(void *data, struct absout *eout,
				   const char *item),
		void *data);

int add_rotator(struct absout *eout, const char *name, const char *accstr,
		int portc, const char **ports,
		const char **options, int lineno);

void free_rotators(void);

#endif /* DATAXFER */
