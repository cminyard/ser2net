/*
 *  ser2net - A program for allowing telnet connection to serial ports
 *  Copyright (C) 2001-2020  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef CONTROLLER
#define CONTROLLER

#include <stdarg.h>

#define CONTROLLER_INVALID_TCP_SPEC	-1
#define CONTROLLER_CANT_OPEN_PORT	-2
#define CONTROLLER_OUT_OF_MEMORY	-3
/* Initialize the controller code, return -n (above) on error. */
int controller_init(char *controller_port, const char * const *options,
		    struct absout *eout);

/* Disable the control port. */
void controller_shutdown(void);

/* Clean everything up. */
void free_controllers(void);

struct controller_info;

/* Send some output to a controller port.  The data field is the data
   to write, the count field is the number of bytes to write. */
int controller_outputf(struct controller_info *cntlr,
		       const char *field, const char *str, ...);

/* Send some output to a controller port.  The data field is the data
   to write, the count field is the number of bytes to write. */
int controller_voutputf(struct controller_info *cntlr,
			const char *field, const char *str, va_list ap);

/* Write some data directly to the controllers output port. */
void controller_write(struct controller_info *cntlr,
		      const char *data, gensiods count);

/*  output a string  */
void controller_outs(struct controller_info *cntlr,
		     const char *field, const char *s);

/* increase or decrease the indent with 1, or -1 */
void controller_indent(struct controller_info *cntlr, int amount);

void cntlr_report_conchange(const char *type,
			    const char *con, const char *remaddr);

#endif /* CONTROLLER */
