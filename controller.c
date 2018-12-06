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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>

#include <utils/selector.h>
#include <utils/utils.h>

#include <gensio/gensio.h>

#include "ser2net.h"
#include "controller.h"
#include "dataxfer.h"

/** BASED ON sshd.c FROM openssh.com */
#ifdef HAVE_TCPD_H
#include <tcpd.h>
int allow_severity = LOG_INFO;
int deny_severity = LOG_WARNING;
static char *progname = "ser2net-control";
#endif /* HAVE_TCPD_H */

/* This file holds the code that runs the control port. */

static struct gensio_lock *cntlr_lock;
static struct gensio_accepter *controller_accepter;
static struct gensio_waiter *accept_waiter;

static int max_controller_ports = 4;	/* How many control connections
					   do we allow at a time. */
static int num_controller_ports = 0;	/* How many control connections
					   are currently active. */

#define INBUF_SIZE 255	/* The size of the maximum input command. */

char *prompt = "-> ";

/* This data structure is kept for each control connection. */
typedef struct controller_info {
    struct gensio_lock *lock;
    int in_shutdown;

    struct gensio *net;

    unsigned char inbuf[INBUF_SIZE + 1];/* Buffer to receive command on. */
    int  inbuf_count;			/* The number of bytes currently
					   in the inbuf. */

    char *outbuf;			/* The output buffer, NULL if
					   no output. */
    int  outbufsize;			/* Total size of the memory
					   allocated in outbuf. */
    int  outbuf_pos;			/* The current position in the
					   output buffer. */
    int  outbuf_count;			/* The number of bytes
					   (starting at outbuf_pos)
					   left to transmit. */

    void *monitor_port_id;		/* When port monitoring, this is
					   the id given when the monitoring
					   is started.  It is used to stop
					   monitoring. */

    struct controller_info *next;	/* Used to keep these items in
					   a linked list. */

    void (*shutdown_complete)(void *);
    void *shutdown_complete_cb_data;
} controller_info_t;

static struct gensio_waiter *controller_shutdown_waiter;

/* List of current control connections. */
controller_info_t *controllers = NULL;

static void
controller_close_done(struct gensio *net, void *cb_data)
{
    controller_info_t *cntlr = gensio_get_user_data(net);

    controller_info_t *prev;
    controller_info_t *curr;
    void (*shutdown_complete)(void *);
    void *shutdown_complete_cb_data;

    gensio_free(net);

    so->free_lock(cntlr->lock);

    if (cntlr->outbuf != NULL) {
	free(cntlr->outbuf);
    }
    cntlr->outbuf = NULL;

    /* Remove it from the linked list. */
    prev = NULL;
    so->lock(cntlr_lock);
    curr = controllers;
    while (curr != NULL) {
	if (cntlr == curr) {
	    if (prev == NULL) {
		controllers = controllers->next;
	    } else {
		prev->next = curr->next;
	    }
	    num_controller_ports--;
	    break;
	}

	prev = curr;
	curr = curr->next;
    }
    so->unlock(cntlr_lock);

    shutdown_complete = cntlr->shutdown_complete;
    shutdown_complete_cb_data = cntlr->shutdown_complete_cb_data;

    free(cntlr);

    if (shutdown_complete)
	shutdown_complete(shutdown_complete_cb_data);
}

/* Shut down a control connection and remove it from the list of
   controllers. */
static void
shutdown_controller(controller_info_t *cntlr)
{
    if (cntlr->in_shutdown) {
	so->unlock(cntlr->lock);
	return;
    }

    if (cntlr->monitor_port_id != NULL) {
	data_monitor_stop(cntlr, cntlr->monitor_port_id);
	cntlr->monitor_port_id = NULL;
    }

    cntlr->in_shutdown = 1;
    so->unlock(cntlr->lock);

    gensio_close(cntlr->net, controller_close_done, NULL);
}

/* Send some output to the control connection.  This allocates and
   free a buffer in blocks of 1024 and increases the size of the
   buffer as necessary. */
void
controller_output(struct controller_info *cntlr,
		  const char             *data,
		  int                    count)
{
    if (cntlr->outbuf != NULL) {
	/* Already outputting data, just add more onto it. */
	int  new_size = cntlr->outbuf_count + count;

	if (new_size <= cntlr->outbufsize) {
	    /* It will fit into the current buffer, just move things
	       around and append it. */
	    if (cntlr->outbuf_pos > 0) {
		int i;

		for (i = 0; i < cntlr->outbuf_count; i++) {
		    cntlr->outbuf[i] = cntlr->outbuf[cntlr->outbuf_pos + i];
		}
	    }
	    memcpy(&(cntlr->outbuf[cntlr->outbuf_count]), data, count);
	} else {
	    /* We need to allocate a larger buffer. */
	    char *newbuf;

	    /* Allocate the next even multiple of 1024 bytes. */
	    new_size = ((new_size / 1024) * 1024) + 1024;
	    newbuf = malloc(new_size);

	    if (newbuf == NULL) {
		/* Out of memory, just ignore the request */
		return;
	    }

	    cntlr->outbufsize = new_size;

	    /* Copy all the data into a new buffer. */
	    memcpy(newbuf,
		   &(cntlr->outbuf[cntlr->outbuf_pos]),
		   cntlr->outbuf_count);
	    memcpy(newbuf + cntlr->outbuf_count, data, count);
	    free(cntlr->outbuf);
	    cntlr->outbuf = newbuf;
	}
	cntlr->outbuf_pos = 0;
	cntlr->outbuf_count += count;
    } else {
	/* We are starting a new buffer, just get it. */
	char *newbuf;
	int  new_size = ((count / 1024) * 1024) + 1024;

	newbuf = malloc(new_size);
	if (newbuf == NULL) {
	    /* Out of memory, just ignore thre request */
	    return;
	}

	cntlr->outbufsize = new_size;

	memcpy(newbuf, data, count);
	cntlr->outbuf = newbuf;
	cntlr->outbuf_pos = 0;
	cntlr->outbuf_count = count;
	gensio_set_read_callback_enable(cntlr->net, false);
	gensio_set_write_callback_enable(cntlr->net, true);
    }
}

int
controller_voutputf(struct controller_info *cntlr, const char *str, va_list ap)
{
    char buffer[1024];
    int rv;

    rv = vsnprintf(buffer, sizeof(buffer), str, ap);
    controller_output(cntlr, buffer, rv);
    return rv;
}

int
controller_outputf(struct controller_info *cntlr, const char *str, ...)
{
    va_list ap;
    int rv;

    va_start(ap, str);
    rv = controller_voutputf(cntlr, str, ap);
    va_end(ap);
    return rv;
}

void controller_outs(struct controller_info *cntlr, char *s)
{
    controller_output (cntlr, s, strlen(s));
}


/* Write some data directly to the controllers output port. */
void
controller_write(struct controller_info *cntlr, const char *data,
		 unsigned int count)
{
    gensio_write(cntlr->net, NULL, data, count);
}

static char *help_str =
"exit - leave the program.\r\n"
"help - display this help.\r\n"
"version - display the version of this program.\r\n"
"monitor <type> <tcp port> - display all the input for a given port on\r\n"
"       the calling control port.  Only one direction may be monitored\r\n"
"       at a time.  The type field may be 'tcp' or 'term' and specifies\r\n"
"       whether to monitor data from the TCP port or from the serial port\r\n"
"       Note that data monitoring is best effort, if the controller port\r\n"
"       cannot keep up the data will be silently dropped.  A controller\r\n"
"       may only monitor one thing and a port may only be monitored by\r\n"
"       one controller.\r\n"
"monitor stop - stop the current monitor.\r\n"
"disconnect <tcp port> - disconnect the tcp connection on the port.\r\n"
"showport [<tcp port>] - Show information about a port. If no port is\r\n"
"       given, all ports are displayed.\r\n"
"showshortport [<tcp port>] - Show information about a port in a one-line\r\n"
"       format. If no port is given, all ports are displayed.\r\n"
"setporttimeout <tcp port> <timeout> - Set the amount of time in seconds\r\n"
"       before the port connection will be shut down if no activity\r\n"
"       has been seen on the port.\r\n"
"setportcontrol <tcp port> <controls>\r\n"
"       Dynamically modify the characteristics of the port.  These are\r\n"
"       immedaite and won't live between connections.  Valid controls are\r\n"
"       DTRHI, DTRLO, RTSHI, and RTSLO.\r\n"
"setportenable <tcp port> <enable state> - Sets the port operation state.\r\n"
"       Valid states are:\r\n"
"         off - The port is shut down\r\n"
"         raw - The port is up and all I/O is transferred\r\n"
"         rawlp - The port is up and the input is transferred to dev\r\n"
"         telnet - The port is up and the telnet negotiation protocol\r\n"
"                  runs on the port.\r\n";

/* Process a line of input.  This scans for commands, reads any
   parameters, then calls the actual code to handle the command. */
int
process_input_line(controller_info_t *cntlr)
{
    char *strtok_data;
    char *tok;
    char *str;

    tok = strtok_r((char *) cntlr->inbuf, " \t", &strtok_data);
    if (tok == NULL) {
	/* Empty line, just ignore it. */
    } else if (strcmp(tok, "exit") == 0) {
	shutdown_controller(cntlr);
	return 1; /* We don't want a prompt any more. */
    } else if (strcmp(tok, "quit") == 0) {
	shutdown_controller(cntlr);
	return 1; /* We don't want a prompt any more. */
    } else if (strcmp(tok, "help") == 0) {
	controller_outs(cntlr, help_str);
    } else if (strcmp(tok, "version") == 0) {
	str = "ser2net version ";
	controller_outs(cntlr, str);
	str = VERSION;
	controller_outs(cntlr, str);
	controller_outs(cntlr, "\r\n");
    } else if (strcmp(tok, "showport") == 0) {
	tok = strtok_r(NULL, " \t", &strtok_data);
	start_maint_op();
	showports(cntlr, tok);
	end_maint_op();
    } else if (strcmp(tok, "showshortport") == 0) {
	tok = strtok_r(NULL, " \t", &strtok_data);
	start_maint_op();
	showshortports(cntlr, tok);
	end_maint_op();
    } else if (strcmp(tok, "monitor") == 0) {
	tok = strtok_r(NULL, " \t", &strtok_data);
	if (tok == NULL) {
	    char *err = "No monitor type given\r\n";
	    controller_outs(cntlr, err);
	    goto out;
	}
	if (strcmp(tok, "stop") == 0) {
	    if (cntlr->monitor_port_id != NULL) {
		start_maint_op();
		data_monitor_stop(cntlr, cntlr->monitor_port_id);
		end_maint_op();
		cntlr->monitor_port_id = NULL;
	    }
	} else {
	    if (cntlr->monitor_port_id != NULL) {
		char *err = "Already monitoring a port\r\n";
		controller_outs(cntlr, err);
		goto out;
	    }

	    str = strtok_r(NULL, " \t", &strtok_data);
	    if (str == NULL) {
		char *err = "No tcp port given\r\n";
		controller_outs(cntlr, err);
		goto out;
	    }
	    start_maint_op();
	    cntlr->monitor_port_id = data_monitor_start(cntlr, tok, str);
	    end_maint_op();
	}
    } else if (strcmp(tok, "disconnect") == 0) {
	tok = strtok_r(NULL, " \t", &strtok_data);
	if (tok == NULL) {
	    char *err = "No port given\r\n";
	    controller_outs(cntlr, err);
	    goto out;
	}
	start_maint_op();
	disconnect_port(cntlr, tok);
	end_maint_op();
    } else if (strcmp(tok, "setporttimeout") == 0) {
	tok = strtok_r(NULL, " \t", &strtok_data);
	if (tok == NULL) {
	    char *err = "No port given\r\n";
	    controller_outs(cntlr, err);
	    goto out;
	}
	str = strtok_r(NULL, " \t", &strtok_data);
	if (str == NULL) {
	    char *err = "No timeout given\r\n";
	    controller_outs(cntlr, err);
	    goto out;
	}
	start_maint_op();
	setporttimeout(cntlr, tok, str);
	end_maint_op();
    } else if (strcmp(tok, "setportenable") == 0) {
	tok = strtok_r(NULL, " \t", &strtok_data);
	if (tok == NULL) {
	    char *err = "No port given\r\n";
	    controller_outs(cntlr, err);
	    goto out;
	}
	str = strtok_r(NULL, " \t", &strtok_data);
	if (str == NULL) {
	    char *err = "No timeout given\r\n";
	    controller_outs(cntlr, err);
	    goto out;
	}
	start_maint_op();
	setportenable(cntlr, tok, str);
	end_maint_op();
    } else if (strcmp(tok, "setportcontrol") == 0) {
	tok = strtok_r(NULL, " \t", &strtok_data);
	if (tok == NULL) {
	    char *err = "No port given\r\n";
	    controller_outs(cntlr, err);
	    goto out;
	}

	str = strtok_r(NULL, "", &strtok_data);
	if (str == NULL) {
	    char *err = "No device controls\r\n";
	    controller_outs(cntlr, err);
	    goto out;
	}
	start_maint_op();
	setportcontrol(cntlr, tok, str);
	end_maint_op();
    } else {
	char *err = "Unknown command: ";
	controller_outs(cntlr, err);
	controller_outs(cntlr, tok);
	controller_outs(cntlr, "\r\n");
    }

out:
    controller_outs(cntlr, prompt);
    return 0;
}

/* Removes one or more characters starting at pos and going backwards.
   So, for instance, if inbuf holds "abcde", pos points to d, and
   count is 2, the new inbuf will be "abe".  This is used for
   backspacing. */
static int
remove_chars(controller_info_t *cntlr, int pos, int count) {
    int j;

    for (j = pos-count + 1; j < (cntlr->inbuf_count - count); j++) {
	cntlr->inbuf[j] = cntlr->inbuf[j + count];
    }
    cntlr->inbuf_count -= count;
    pos -= count;

    return pos;
}

/* Data is ready to read on the TCP port. */
static unsigned int
controller_read(struct gensio *net, int err,
		unsigned char *buf, unsigned int buflen)
{
    controller_info_t *cntlr = gensio_get_user_data(net);
    int read_start;
    int i;

    so->lock(cntlr->lock);
    if (cntlr->in_shutdown)
	goto out_unlock;

    if (cntlr->inbuf_count == INBUF_SIZE)
	goto inbuf_overflow;

    if (err) {
	/* Got an error on the read, shut down the port. */
	syslog(LOG_ERR, "read error for controller port: %s",
	       strerror(err));
	shutdown_controller(cntlr); /* Releases the lock */
	goto out;
    }

    read_start = cntlr->inbuf_count;
    if (buflen > INBUF_SIZE - read_start)
	buflen = INBUF_SIZE - read_start;
    memcpy(cntlr->inbuf + read_start, buf, buflen);

    cntlr->inbuf_count += buflen;
    for (i = read_start; i < cntlr->inbuf_count; i++) {
	if (cntlr->inbuf[i] == 0x0) {
	    /* Ignore nulls. */
	    i = remove_chars(cntlr, i, 1);
	} else if (cntlr->inbuf[i] == '\n') {
	    /* Ignore newlines. */
	    i = remove_chars(cntlr, i, 1);
	} else if ((cntlr->inbuf[i] == '\b') || (cntlr->inbuf[i] == 0x7f)) {
	    /* Got a backspace. */

	    if (i == 0) {
		/* We ignore backspaces at the beginning of the line. */
		i = remove_chars(cntlr, i, 1);
	    } else {
		i = remove_chars(cntlr, i, 2);
		controller_outs(cntlr, "\b \b");
	    }
	} else if (cntlr->inbuf[i] == '\r') {
	    /* We got a newline, process the command. */
	    int j;

	    controller_outs(cntlr, "\r\n");

	    cntlr->inbuf[i] ='\0';
	    if (process_input_line(cntlr))
		goto out; /* Controller was shut down. */

	    /* Now copy any leftover data to the beginning of the buffer. */
	    /* Don't use memcpy or strcpy because the memory might
               overlap */
	    i++;
	    cntlr->inbuf_count -= i;
	    for (j = 0; j < cntlr->inbuf_count; i++, j++) {
		cntlr->inbuf[j] = cntlr->inbuf[i];
	    }
	    i = -1;
	} else {
	    /* It's a normal character, just echo it. */
	    controller_output(cntlr, (char *) &(cntlr->inbuf[i]), 1);
	}
    }
 out_unlock:
    so->unlock(cntlr->lock);
 out:
    return buflen;

 inbuf_overflow:
    controller_outs(cntlr, "Input line too long\r\n");
    cntlr->inbuf_count = 0;
    goto out_unlock;
}

/* The TCP port has room to write some data.  This is only activated
   if a write fails to complete, it is deactivated as soon as writing
   is available again. */
static void
controller_write_ready(struct gensio *net)
{
    controller_info_t *cntlr = gensio_get_user_data(net);
    int err;
    unsigned int write_count;

    so->lock(cntlr->lock);
    if (cntlr->in_shutdown)
	goto out;

    err = gensio_write(net, &write_count,
		       &(cntlr->outbuf[cntlr->outbuf_pos]),
		       cntlr->outbuf_count);
    if (err == EAGAIN) {
	/* This again was due to O_NONBso->lock, just ignore it. */
    } else if (err == EPIPE) {
	goto out_fail;
    } else if (err) {
	/* Some other bad error. */
	syslog(LOG_ERR, "The tcp write for controller had error: %m");
	goto out_fail;
    }

    cntlr->outbuf_count -= write_count;
    if (cntlr->outbuf_count != 0) {
	/* We didn't write all the data, continue writing. */
	cntlr->outbuf_pos += write_count;
    } else {
	/* We are done writing, turn the reader back on. */
	free(cntlr->outbuf);
	cntlr->outbuf = NULL;
	gensio_set_read_callback_enable(net, true);
	gensio_set_write_callback_enable(net, false);
    }
 out:
    so->unlock(cntlr->lock);
    return;

 out_fail:
    shutdown_controller(cntlr); /* Releases the lock */
}

static int
controller_io_event(struct gensio *net, int event, int err,
		    unsigned char *buf, unsigned int *buflen, void *auxdata)
{
    switch (event) {
    case GENSIO_EVENT_READ:
	*buflen =  controller_read(net, err, buf, *buflen);
	return 0;

    case GENSIO_EVENT_WRITE_READY:
	controller_write_ready(net);
	return 0;
    }

    return ENOTSUP;
}

/* A connection request has come in for the control port. */
static int
controller_acc_child_event(struct gensio_accepter *accepter, int event,
			   void *data)
{
    controller_info_t *cntlr;
    char              *err = NULL;
    struct gensio *net;

    if (event != GENSIO_ACC_EVENT_NEW_CONNECTION)
	return ENOTSUP;

    net = data;
    so->lock(cntlr_lock);
    if (num_controller_ports >= max_controller_ports) {
	err = "Too many controller ports\r\n";
	goto errout;
    } else {
	cntlr = malloc(sizeof(*cntlr));
	if (cntlr == NULL) {
	    err = "Could not allocate controller port\r\n";
	    goto errout;
	}
	memset(cntlr, 0, sizeof(*cntlr));
    }

    cntlr->lock = so->alloc_lock(so);
    if (!cntlr->lock) {
	free(cntlr);
	err = "Out of memory allocating lock";
	goto errout;
    }

    cntlr->net = net;

    gensio_set_callback(net, controller_io_event, cntlr);

    cntlr->inbuf_count = 0;
    cntlr->outbuf = NULL;
    cntlr->monitor_port_id = NULL;

    controller_outs(cntlr, prompt);

    cntlr->next = controllers;
    controllers = cntlr;
    num_controller_ports++;

    so->unlock(cntlr_lock);
    return 0;

errout:
    so->unlock(cntlr_lock);
    /* We have a problem so refuse this one. */
    gensio_write(net, NULL, err, strlen(err));
    gensio_free(net);
    return 0;
}

static void
controller_shutdown_done(struct gensio_accepter *net, void *cb_data)
{
    so->wake(accept_waiter);
}

/* Set up the controller port to accept connections. */
int
controller_init(char *controller_port)
{
    int rv;

    if (!cntlr_lock) {
	cntlr_lock = so->alloc_lock(so);
	if (!cntlr_lock)
	    return ENOMEM;
    }

    if (!controller_shutdown_waiter) {
	controller_shutdown_waiter = so->alloc_waiter(so);
	if (!controller_shutdown_waiter)
	    return ENOMEM;
    }

    if (!accept_waiter) {
	accept_waiter = so->alloc_waiter(so);
	if (!accept_waiter) {
	    syslog(LOG_ERR, "Unable to allocate controller accept waiter");
	    return CONTROLLER_CANT_OPEN_PORT;
	}
    }

    rv = str_to_gensio_accepter(controller_port, so,
				controller_acc_child_event, NULL,
				&controller_accepter);
    if (rv) {
	if (rv == EINVAL)
	    return CONTROLLER_INVALID_TCP_SPEC;
	else if (rv == ENOMEM)
	    return CONTROLLER_OUT_OF_MEMORY;
	else
	    return -1;
    }

    rv = gensio_acc_startup(controller_accepter);
    if (rv)
	return CONTROLLER_CANT_OPEN_PORT;

    return 0;
}

void
controller_shutdown(void)
{
    if (controller_accepter) {
	gensio_acc_shutdown(controller_accepter, controller_shutdown_done,
			    NULL);
	so->wait(accept_waiter, 1, NULL);
	gensio_acc_free(controller_accepter);
	controller_accepter = NULL;
    }
}

static void
shutdown_controller_done(void *cb_data)
{
    struct gensio_waiter *waiter = cb_data;

    so->wake(waiter);
}

void
free_controllers(void)
{
    while (controllers) {
	controllers->shutdown_complete = shutdown_controller_done;
	controllers->shutdown_complete_cb_data = controller_shutdown_waiter;
	so->lock(controllers->lock);
	shutdown_controller(controllers); /* Releases the lock. */
	so->wait(controller_shutdown_waiter, 1, NULL);
    }
    controller_shutdown();
    if (controller_shutdown_waiter)
	so->free_waiter(controller_shutdown_waiter);
    if (accept_waiter)
	so->free_waiter(accept_waiter);
}
