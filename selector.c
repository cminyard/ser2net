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

/* This file holds code to abstract the "select" call and make it
   easier to use.  The main thread lives here, the rest of the code
   uses a callback interface.  Basically, other parts of the program
   can register file descriptors with this code, when interesting
   things happen on those file descriptors this code will call
   routines registered with it. */

#include "selector.h"

#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>
#include <signal.h>

/* The control structure for each file descriptor. */
typedef struct fd_control
{
    int          in_use;
    void         *data;		/* Operation-specific data */
    t_fd_handler handle_read;
    t_fd_handler handle_write;
    t_fd_handler handle_except;
} t_fd_control;

/* This is an array of all the file descriptors possible.  This is
   moderately wasteful of space, but easy to do.  Hey, memory is
   cheap. */
static t_fd_control fds[FD_SETSIZE];

/* These are the offical fd_sets used to track what file descriptors
   need to be monitored. */
static fd_set read_set;
static fd_set write_set;
static fd_set except_set;

static int maxfd; /* The largest file descriptor registered with this
                     code. */

static int got_sighup = 0; /* Did I get a HUP signal? */

void sighup_handler(int sig)
{
    got_sighup = 1;
}

/* Initialize a single file descriptor. */
static void
init_fd(t_fd_control *fd)
{
    fd->in_use = 0;
    fd->data = NULL;
    fd->handle_read = NULL;
    fd->handle_write = NULL;
    fd->handle_except = NULL;
}

/* Set the handlers for a file descriptor. */
void
set_fd_handlers(int          fd,
		void         *data,
		t_fd_handler read_handler,
		t_fd_handler write_handler,
		t_fd_handler except_handler)
{
    fds[fd].in_use = 1;
    fds[fd].data = data;
    fds[fd].handle_read = read_handler;
    fds[fd].handle_write = write_handler;
    fds[fd].handle_except = except_handler;

    /* Move maxfd up if necessary. */
    if (fd > maxfd) {
	maxfd = fd;
    }
}

/* Clear the handlers for a file descriptor and remove it from
   select's monitoring. */
void
clear_fd_handlers(int fd)
{
    init_fd(&(fds[fd]));
    FD_CLR(fd, &read_set);
    FD_CLR(fd, &write_set);
    FD_CLR(fd, &except_set);

    /* Move maxfd down if necessary. */
    if (fd == maxfd) {
	while ((maxfd >= 0) && (! fds[maxfd].in_use)) {
	    maxfd--;
	}
    }
}

/* Set whether the file descriptor will be monitored for data ready to
   read on the file descriptor. */
void
set_fd_read_handler(int fd, int state)
{
    if (state == FD_HANDLER_ENABLED) {
	FD_SET(fd, &read_set);
    } else if (state == FD_HANDLER_DISABLED) {
	FD_CLR(fd, &read_set);
    }
    /* FIXME - what to do on errors? */
}

/* Set whether the file descriptor will be monitored for when the file
   descriptor can be written to. */
void
set_fd_write_handler(int fd, int state)
{
    if (state == FD_HANDLER_ENABLED) {
	FD_SET(fd, &write_set);
    } else if (state == FD_HANDLER_DISABLED) {
	FD_CLR(fd, &write_set);
    }
    /* FIXME - what to do on errors? */
}

/* Set whether the file descriptor will be monitored for exceptions
   on the file descriptor. */
void
set_fd_except_handler(int fd, int state)
{
    if (state == FD_HANDLER_ENABLED) {
	FD_SET(fd, &except_set);
    } else if (state == FD_HANDLER_DISABLED) {
	FD_CLR(fd, &except_set);
    }
    /* FIXME - what to do on errors? */
}


t_sighup_handler user_sighup_handler = NULL;

void
set_sighup_handler(t_sighup_handler handler)
{
    user_sighup_handler = handler;
}

#define MAX_TIMEOUT_HANDLERS 10 /* How many routines can be registered
                                   to be called periodically. */

/* These are the routines to be called periodically.  If a handler is
   NULL, it is not in use. */
t_timeout_handler handlers[MAX_TIMEOUT_HANDLERS];

/* Add a routine to be called periodically. */
void
add_timeout_handler(t_timeout_handler handler)
{
    int i;

    for (i=0; i<MAX_TIMEOUT_HANDLERS; i++) {
	if (handlers[i] == NULL) {
	    handlers[i] = handler;
	    break;
	}
    }
}

/* Remove a routine to be called periodically. */
void
remove_timeout_handler(t_timeout_handler handler)
{
    int i;

    for (i=0; i<MAX_TIMEOUT_HANDLERS; i++) {
	if (handlers[i] == handler) {
	    handlers[i] = NULL;
	    break;
	}
    }
}

/* Call all the handlers that are registered. */
static void
call_timeouts(void)
{
    int i;

    for (i=0; i<MAX_TIMEOUT_HANDLERS; i++) {
	if (handlers[i] != NULL) {
	    handlers[i]();
	}
    }
}

/* The main loop for the program.  This will select on the various
   sets, then scan for any available I/O to process.  It also monitors
   the time and call the timeout handlers periodically. */
void
select_loop(void)
{
    fd_set tmp_read_set;
    fd_set tmp_write_set;
    fd_set tmp_except_set;
    int    i;
    struct timeval timeout;
    int    err;

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    /* WARNING - this code relies on the Linux semantics of setting
       the timeout value passed to select() to the amount of time
       left.  If porting to another platform, this will need to be
       rewritten to handle time without this nice feature. */
    for (;;) {
	memcpy(&tmp_read_set, &read_set, sizeof(tmp_read_set));
	memcpy(&tmp_write_set, &write_set, sizeof(tmp_write_set));
	memcpy(&tmp_except_set, &except_set, sizeof(tmp_except_set));
	err = select(maxfd+1,
		     &tmp_read_set,
		     &tmp_write_set,
		     &tmp_except_set,
		     &timeout);
	if (err == 0) {
	    /* A timeout occurred. */
	    call_timeouts();
	    timeout.tv_sec = 1;
	    timeout.tv_usec = 0;
	} else if (err < 0) {
	    /* An error occurred. */
	    if (errno == EINTR) {
		/* EINTR is ok, just restart the operation. */
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
	    } else {
		/* An error is bad, we need to abort. */
		syslog(LOG_ERR, "select_loop() - select: %m");
		exit(1);
	    }
	} else {
	    /* We got some I/O. */
	    for (i=0; i<=maxfd; i++) {
		if (FD_ISSET(i, &tmp_read_set)) {
		    if (fds[i].handle_read == NULL) {
			/* Somehow we don't have a handler for this.
                           Just shut it down. */
			set_fd_read_handler(i, FD_HANDLER_DISABLED);
		    } else {
			fds[i].handle_read(i, fds[i].data);
		    }
		}
		if (FD_ISSET(i, &tmp_write_set)) {
		    if (fds[i].handle_write == NULL) {
			/* Somehow we don't have a handler for this.
                           Just shut it down. */
			set_fd_write_handler(i, FD_HANDLER_DISABLED);
		    } else {
			fds[i].handle_write(i, fds[i].data);
		    }
		}
		if (FD_ISSET(i, &tmp_except_set)) {
		    if (fds[i].handle_except == NULL) {
			/* Somehow we don't have a handler for this.
                           Just shut it down. */
			set_fd_except_handler(i, FD_HANDLER_DISABLED);
		    } else {
			fds[i].handle_except(i, fds[i].data);
		    }
		}
	    }
	}

	if (got_sighup) {
	    got_sighup = 0;
	    if (user_sighup_handler != NULL) {
		user_sighup_handler();
	    }
	}
    }
}

/* Initialize the select code. */
void
selector_init(void)
{
    int              i;
    int              err;
    struct sigaction act;

    FD_ZERO(&read_set);
    FD_ZERO(&write_set);
    FD_ZERO(&except_set);

    for (i=0; i<FD_SETSIZE; i++) {
	init_fd(&(fds[i]));
    }

    for (i=0; i<MAX_TIMEOUT_HANDLERS; i++) {
	handlers[i] = NULL;
    }

    act.sa_handler = sighup_handler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_RESTART;
    err = sigaction(SIGHUP, &act, NULL);
    if (err) {
	perror("sigaction");
    }
}
