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

#include <sys/time.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <errno.h>
#include <syslog.h>

#include "ser2net.h"
#include "controller.h"
#include "selector.h"
#include "dataxfer.h"
#include "utils.h"
#include "telnet.h"
#include "locking.h"

/** BASED ON sshd.c FROM openssh.com */
#ifdef HAVE_TCPD_H
#include <tcpd.h>
int allow_severity = LOG_INFO;
int deny_severity = LOG_WARNING;
static char *progname = "ser2net-control";
#endif /* HAVE_TCPD_H */

/* This file holds the code that runs the control port. */

DEFINE_LOCK_INIT(static, cntlr_lock)
static struct addrinfo *cntrl_ai;
static struct opensocks *acceptfds;/* File descriptors for the accept port. */
static unsigned int nr_acceptfds;
static waiter_t *accept_waiter;

static int max_controller_ports = 4;	/* How many control connections
					   do we allow at a time. */
static int num_controller_ports = 0;	/* How many control connections
					   are currently active. */

#define INBUF_SIZE 255	/* The size of the maximum input command. */

char *prompt = "-> ";

/* This data structure is kept for each control connection. */
typedef struct controller_info {
    DEFINE_LOCK(, lock)
    int in_shutdown;

    int            tcpfd;		/* When connected, the file
                                           descriptor for the TCP
                                           port used for I/O. */
    struct sockaddr_storage remote;	/* The socket address of who
					   is connected to this port. */

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

    /* Data used by the telnet processing. */
    telnet_data_t tn_data;

    void (*shutdown_complete)(void *);
    void *shutdown_complete_cb_data;
} controller_info_t;

static waiter_t *controller_shutdown_waiter;

/* List of current control connections. */
controller_info_t *controllers = NULL;

/* Used to initialize the telnet session. */
static unsigned char telnet_init_seq[] = {
    TN_IAC, TN_WILL, TN_OPT_SUPPRESS_GO_AHEAD,
    TN_IAC, TN_WILL, TN_OPT_ECHO,
    TN_IAC, TN_DONT, TN_OPT_ECHO,
};

static struct telnet_cmd telnet_cmds[] =
{
    /*                        I will,  I do,  sent will, sent do */
    { TN_OPT_SUPPRESS_GO_AHEAD,	   0,     1,          1,       0, },
    { TN_OPT_ECHO,		   0,     1,          1,       1, },
    { TN_OPT_BINARY_TRANSMISSION,  1,     1,          0,       1, },
    { 255 }
};

static void
shutdown_controller2(controller_info_t *cntlr)
{
    controller_info_t *prev;
    controller_info_t *curr;
    void (*shutdown_complete)(void *);
    void *shutdown_complete_cb_data;

    FREE_LOCK(cntlr->lock);

    close(cntlr->tcpfd);
    if (cntlr->outbuf != NULL) {
	free(cntlr->outbuf);
    }
    cntlr->outbuf = NULL;

    /* Remove it from the linked list. */
    prev = NULL;
    LOCK(cntlr_lock);
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
    UNLOCK(cntlr_lock);

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
	UNLOCK(cntlr->lock);
	return;
    }

    if (cntlr->monitor_port_id != NULL) {
	data_monitor_stop(cntlr, cntlr->monitor_port_id);
	cntlr->monitor_port_id = NULL;
    }

    cntlr->in_shutdown = 1;
    UNLOCK(cntlr->lock);

    sel_clear_fd_handlers(ser2net_sel, cntlr->tcpfd);
    /* The rest is handled in the done callback, which calls
       shutdown_controller2. */
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
	sel_set_fd_read_handler(ser2net_sel, cntlr->tcpfd,
				SEL_FD_HANDLER_DISABLED);
	sel_set_fd_write_handler(ser2net_sel, cntlr->tcpfd,
				 SEL_FD_HANDLER_ENABLED);
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
controller_write(struct controller_info *cntlr, const char *data, int count)
{
    write_ignore_fail(cntlr->tcpfd, data, count);
}

static void
telnet_output_ready(void *cb_data)
{
    struct controller_info *cntlr = cb_data;

    sel_set_fd_read_handler(ser2net_sel, cntlr->tcpfd,
			    SEL_FD_HANDLER_DISABLED);
    sel_set_fd_write_handler(ser2net_sel, cntlr->tcpfd,
			     SEL_FD_HANDLER_ENABLED);
}

/* Called when a telnet command is received. */
void
telnet_cmd_handler(void *cb_data, unsigned char cmd)
{
    /* These are ignored for now. */
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
"setportconfig <tcp port> <config> - Set the port configuration as in\r\n"
"       the device configuration in the ser2net.conf file.  Valid options\r\n"
"       are: 300, 1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200, \r\n"
"       EVEN, ODD, NONE, 1STOPBIT, 2STOPBITS, 7DATABITS, 8DATABITS, \r\n"
"       LOCAL (ignore modem control), [-]RTSCTS, [-]XONXOFF.\r\n"
"       Note that these will not change until the port is disconnected\r\n"
"       and connected again.\r\n"
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
    } else if (strcmp(tok, "setportconfig") == 0) {
	tok = strtok_r(NULL, " \t", &strtok_data);
	if (tok == NULL) {
	    char *err = "No port given\r\n";
	    controller_outs(cntlr, err);
	    goto out;
	}

	str = strtok_r(NULL, "", &strtok_data);
	if (str == NULL) {
	    char *err = "No device config\r\n";
	    controller_outs(cntlr, err);
	    goto out;
	}
	start_maint_op();
	setportdevcfg(cntlr, tok, str);
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
   backspacing and for removing telnet command characters. */
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
static void
handle_tcp_fd_read(int fd, void *data)
{
    controller_info_t *cntlr = (controller_info_t *) data;
    int read_count;
    int read_start;
    int i;

    LOCK(cntlr->lock);
    if (cntlr->in_shutdown)
	goto out_unlock;

    if (cntlr->inbuf_count == INBUF_SIZE) {
        char *err = "Input line too long\r\n";
	controller_outs(cntlr, err);
	cntlr->inbuf_count = 0;
	goto out_unlock;
    }

    read_count = read(fd,
		      &(cntlr->inbuf[cntlr->inbuf_count]),
		      INBUF_SIZE - cntlr->inbuf_count);

    if (read_count < 0) {
	if (errno == EINTR) {
	    /* EINTR means we were interrupted, just retry by returning. */
	    goto out_unlock;
	}

	if (errno == EAGAIN) {
	    /* EAGAIN, is due to O_NONBLOCK, just ignore it. */
	    goto out_unlock;
	}

	/* Got an error on the read, shut down the port. */
	syslog(LOG_ERR, "read error for controller port: %m");
	shutdown_controller(cntlr); /* Releases the lock */
	goto out;
    } else if (read_count == 0) {
	/* The other end closed the port, shut it down. */
	shutdown_controller(cntlr); /* Releases the lock */
	goto out;
    }
    read_start = cntlr->inbuf_count;
    read_count = process_telnet_data
	(cntlr->inbuf + read_start, read_count, &cntlr->tn_data);
    if (cntlr->tn_data.error) {
	shutdown_controller(cntlr); /* Releases the lock */
	goto out;
    }
    cntlr->inbuf_count += read_count;

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
    UNLOCK(cntlr->lock);
 out:
    return;
}

/* The TCP port has room to write some data.  This is only activated
   if a write fails to complete, it is deactivated as soon as writing
   is available again. */
static void
handle_tcp_fd_write(int fd, void *data)
{
    controller_info_t *cntlr = (controller_info_t *) data;
    telnet_data_t *td;
    int write_count;

    LOCK(cntlr->lock);
    if (cntlr->in_shutdown)
	goto out;

    td = &cntlr->tn_data;
    if (buffer_cursize(&td->out_telnet_cmd) > 0) {
	int buferr, reterr;

	reterr = buffer_write(cntlr->tcpfd, &td->out_telnet_cmd, &buferr);
	if (reterr == -1) {
	    if (buferr == EPIPE) {
		goto out_fail;
	    } else {
		/* Some other bad error. */
		syslog(LOG_ERR, "The tcp write for controller had error: %m");
		goto out_fail;
	    }
	}
	if (buffer_cursize(&td->out_telnet_cmd) > 0)
	    /* Still telnet data left, don't send regular data */
	    goto out;
    }

    write_count = write(cntlr->tcpfd,
			&(cntlr->outbuf[cntlr->outbuf_pos]),
			cntlr->outbuf_count);
    if (write_count == -1) {
	if (errno == EAGAIN) {
	    /* This again was due to O_NONBLOCK, just ignore it. */
	} else if (errno == EPIPE) {
	    goto out_fail;
	} else {
	    /* Some other bad error. */
	    syslog(LOG_ERR, "The tcp write for controller had error: %m");
	    goto out_fail;
	}
    } else {
	cntlr->outbuf_count -= write_count;
	if (cntlr->outbuf_count != 0) {
	    /* We didn't write all the data, continue writing. */
	    cntlr->outbuf_pos += write_count;
	} else {
	    /* We are done writing, turn the reader back on. */
	    free(cntlr->outbuf);
	    cntlr->outbuf = NULL;
	    sel_set_fd_read_handler(ser2net_sel, cntlr->tcpfd,
				    SEL_FD_HANDLER_ENABLED);
	    sel_set_fd_write_handler(ser2net_sel, cntlr->tcpfd,
				     SEL_FD_HANDLER_DISABLED);
	}
    }
 out:
    UNLOCK(cntlr->lock);
    return;

 out_fail:
    shutdown_controller(cntlr); /* Releases the lock */
}

/* Handle an exception from the TCP port. */
static void
handle_tcp_fd_except(int fd, void *data)
{
    controller_info_t *cntlr = (controller_info_t *) data;

    LOCK(cntlr->lock);
    if (cntlr->in_shutdown) {
	UNLOCK(cntlr->lock);
	return;
    }
    syslog(LOG_ERR, "Select exception for controller port");
    shutdown_controller(cntlr); /* Releases the lock */
}

static void
controller_fd_cleared(int fd, void *cb_data)
{
    controller_info_t *cntlr = cb_data;

    shutdown_controller2(cntlr);
}

/* A connection request has come in for the control port. */
static void
handle_accept_port_read(int fd, void *data)
{
    controller_info_t *cntlr;
    socklen_t         len;
    char              *err = NULL;
    int               optval;

    LOCK(cntlr_lock);
    if (num_controller_ports >= max_controller_ports) {
	err = "Too many controller ports\r\n";
	goto errout2;
    } else {
	cntlr = malloc(sizeof(*cntlr));
	if (cntlr == NULL) {
	    err = "Could not allocate controller port\r\n";
	    goto errout2;
	}
	memset(cntlr, 0, sizeof(*cntlr));
    }

    /* From here on, errors must go to errout. */

    INIT_LOCK(cntlr->lock);

    len = sizeof(cntlr->remote);
    cntlr->tcpfd = accept(fd, (struct sockaddr *) &(cntlr->remote), &len);
    if (cntlr->tcpfd == -1) {
	if (errno != EAGAIN && errno != EWOULDBLOCK)
	    syslog(LOG_ERR, "Could not accept on controller port: %m");
	goto errout;
    }

#ifdef HAVE_TCPD_H
    {
	struct request_info req;

	request_init(&req, RQ_DAEMON, progname, RQ_FILE, cntlr->tcpfd, NULL);
	fromhost(&req);

	if (!hosts_access(&req)) {
	    char *err = "Access denied\r\n";
	    write(cntlr->tcpfd, err, strlen(err));
	    close(cntlr->tcpfd);
	    goto errout;
	}
    }
#endif /* HAVE_TCPD_H */

    if (fcntl(cntlr->tcpfd, F_SETFL, O_NONBLOCK) == -1) {
	close(cntlr->tcpfd);
	syslog(LOG_ERR, "Could not fcntl the tcp port: %m");
	goto errout;
    }

    optval = 1;
    if (setsockopt(cntlr->tcpfd, SOL_SOCKET, SO_KEEPALIVE, (void *)&optval,
		   sizeof(optval)) == -1) {
	close(cntlr->tcpfd);
	syslog(LOG_ERR, "Could not enable SO_KEEPALIVE on the tcp port: %m");
	goto errout;
    }

    cntlr->inbuf_count = 0;
    cntlr->outbuf = NULL;
    cntlr->monitor_port_id = NULL;

    sel_set_fd_handlers(ser2net_sel,
			cntlr->tcpfd,
			cntlr,
			handle_tcp_fd_read,
			handle_tcp_fd_write,
			handle_tcp_fd_except,
			controller_fd_cleared);

    cntlr->next = controllers;
    controllers = cntlr;

    /* Send the telnet negotiation string.  We do this by
       putting the data in the dev to tcp buffer and turning
       the tcp write selector on. */

    telnet_init(&cntlr->tn_data, cntlr, telnet_output_ready,
		telnet_cmd_handler,
		telnet_cmds,
		telnet_init_seq, sizeof(telnet_init_seq));
    controller_outs(cntlr, prompt);

    num_controller_ports++;

    UNLOCK(cntlr_lock);
    return;

errout:
    UNLOCK(cntlr_lock);
    free(cntlr);
    return;

errout2:
    UNLOCK(cntlr_lock);
    {
	/* We have a problem so refuse this one. */
	struct sockaddr_storage dummy_sockaddr;
	socklen_t len = sizeof(dummy_sockaddr);
	int new_fd = accept(fd, (struct sockaddr *) &dummy_sockaddr, &len);

	if (new_fd != -1) {
	    write_ignore_fail(new_fd, err, strlen(err));
	    close(new_fd);
	}
    }
}

static void
controller_accept_fd_cleared(int fd, void *cb_data)
{
    wake_waiter(accept_waiter);
}

/* Set up the controller port to accept connections. */
int
controller_init(char *controller_port)
{
    int rv;
    bool is_port_set;

    if (!controller_shutdown_waiter) {
	controller_shutdown_waiter = alloc_waiter();
	if (!controller_shutdown_waiter)
	    return ENOMEM;
    }

    rv = scan_network_port(controller_port, &cntrl_ai, NULL, &is_port_set);
    if (rv) {
	if (rv == EINVAL)
	    return CONTROLLER_INVALID_TCP_SPEC;
	else if (rv == ENOMEM)
	    return CONTROLLER_OUT_OF_MEMORY;
	else
	    return -1;
    }
    if (!is_port_set)
	return CONTROLLER_INVALID_TCP_SPEC;

    if (!accept_waiter) {
	accept_waiter = alloc_waiter();
	if (!accept_waiter) {
	    syslog(LOG_ERR, "Unable to allocate controller accept waiter");
	    return CONTROLLER_CANT_OPEN_PORT;
	}
    }

    acceptfds = open_socket(cntrl_ai, handle_accept_port_read, NULL, NULL,
			    &nr_acceptfds, controller_accept_fd_cleared);
    if (acceptfds == NULL) {
	freeaddrinfo(cntrl_ai);
	syslog(LOG_ERR, "Unable to create TCP socket: %m");
	return CONTROLLER_CANT_OPEN_PORT;
    }

    return 0;
}

void
controller_shutdown(void)
{
    unsigned int i;

    if (acceptfds == NULL)
	return;
    for (i = 0; i < nr_acceptfds; i++) {
	sel_clear_fd_handlers(ser2net_sel, acceptfds[i].fd);
	wait_for_waiter(accept_waiter);
	close(acceptfds[i].fd);
    }
    free(acceptfds);
    freeaddrinfo(cntrl_ai);
    acceptfds = NULL;
}

static void
shutdown_controller_done(void *cb_data)
{
    waiter_t *waiter = cb_data;

    wake_waiter(waiter);
}

void
free_controllers(void)
{
    controller_shutdown();
    while (controllers) {
	controllers->shutdown_complete = shutdown_controller_done;
	controllers->shutdown_complete_cb_data = controller_shutdown_waiter;
	LOCK(controllers->lock);
	shutdown_controller(controllers); /* Releases the lock. */
	wait_for_waiter(controller_shutdown_waiter);
    }
    if (controller_shutdown_waiter)
	free_waiter(controller_shutdown_waiter);
    if (accept_waiter)
	free_waiter(accept_waiter);
}
