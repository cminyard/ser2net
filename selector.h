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

#ifndef SELECTOR
#define SELECTOR

/* A function to call when select sees something on a file
   descriptor. */
typedef void (*t_fd_handler)(int fd, void *data);

/* Set the handlers for a file descriptor.  The "data" parameter is
   not used, it is just passed to the exception handlers. */
void set_fd_handlers(int          fd,
		     void         *data,
		     t_fd_handler read_handler,
		     t_fd_handler write_handler,
		     t_fd_handler except_handler);

/* Remove the handlers for a file descriptor.  This will also disable
   the handling of all I/O for the fd. */
void clear_fd_handlers(int fd);

/* Turn on and off handling for I/O from a file descriptor. */
#define FD_HANDLER_ENABLED	0
#define FD_HANDLER_DISABLED	1
void set_fd_read_handler(int fd, int state);
void set_fd_write_handler(int fd, int state);
void set_fd_except_handler(int fd, int state);

/* Called periodically.  No guarantee is made on the time (other than
   it is around a second), so get the time yourself and check what you
   need. */
typedef void (*t_timeout_handler)(void);
void add_timeout_handler(t_timeout_handler handler);
void remove_timeout_handler(t_timeout_handler handler);

/* This is the main loop for the program. */
void select_loop(void);

/* Initialize the select code. */
void selector_init(void);

#endif /* SELECTOR */
