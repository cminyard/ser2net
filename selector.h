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
#include <sys/time.h> /* For timeval */

/* The main data structure used by the selector. */
struct selector_s;
typedef struct selector_s selector_t;

/* You have to create a selector before you can use it. */
int sel_alloc_selector(selector_t **new_selector);

/* Used to destroy a selector. */
int sel_free_selector(selector_t *new_selector);


/* A function to call when select sees something on a file
   descriptor. */
typedef void (*sel_fd_handler_t)(int fd, void *data);

/* Set the handlers for a file descriptor.  The "data" parameter is
   not used, it is just passed to the exception handlers. */
void sel_set_fd_handlers(selector_t       *sel,
			 int              fd,
			 void             *data,
			 sel_fd_handler_t read_handler,
			 sel_fd_handler_t write_handler,
			 sel_fd_handler_t except_handler);

/* Remove the handlers for a file descriptor.  This will also disable
   the handling of all I/O for the fd. */
void sel_clear_fd_handlers(selector_t *sel,
			   int        fd);

/* Turn on and off handling for I/O from a file descriptor. */
#define SEL_FD_HANDLER_ENABLED	0
#define SEL_FD_HANDLER_DISABLED	1
void sel_set_fd_read_handler(selector_t *sel, int fd, int state);
void sel_set_fd_write_handler(selector_t *sel, int fd, int state);
void sel_set_fd_except_handler(selector_t *sel, int fd, int state);

struct sel_timer_s;
typedef struct sel_timer_s sel_timer_t;

typedef void (*sel_timeout_handler_t)(selector_t  *sel,
				      sel_timer_t *timer,
				      void        *data);

int sel_alloc_timer(selector_t            *sel,
		    sel_timeout_handler_t handler,
		    void                  *user_data,
		    sel_timer_t           **new_timer);

int sel_free_timer(sel_timer_t *timer);

int sel_start_timer(sel_timer_t    *timer,
		    struct timeval *timeout);

int sel_stop_timer(sel_timer_t *timer);

/* Set a handler to handle shen signals are sent to the process. */
typedef void (*t_signal_handler)(void);
void set_signal_handler(int sig, t_signal_handler handler);
void setup_signals(void);

/* Run the selector processing once and return */
void sel_select_once(selector_t *sel);

/* This is the main loop for the program. */
void sel_select_loop(selector_t *sel);

#endif /* SELECTOR */
