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

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <errno.h>
#include <syslog.h>

#include "controller.h"
#include "selector.h"
#include "dataxfer.h"
#include "utils.h"
#include "telnet.h"


extern selector_t *ser2net_sel;

/** BASED ON sshd.c FROM openssh.com */
#ifdef HAVE_TCPD_H
#include <tcpd.h>
int allow_severity = LOG_INFO;
int deny_severity = LOG_WARNING;
static char *progname = "ser2net-control";
#endif /* HAVE_TCPD_H */

/* This file holds the code that runs the control port. */

static int acceptfd;	/* The file descriptor for the accept port. */

static int max_controller_ports = 4;	/* How many control connections
					   do we allow at a time. */
static int num_controller_ports = 0;	/* How many control connections
					   are currently active. */

#define INBUF_SIZE 255	/* The size of the maximum input command. */

char *prompt = "-> ";

/* This data structure is kept for each control connection. */
typedef struct controller_info {
    int            tcpfd;		/* When connected, the file
                                           descriptor for the TCP
                                           port used for I/O. */
    struct sockaddr_storage remote;	/* The socket address of who
					   is connected to this port. */

    unsigned char inbuf[INBUF_SIZE+1];	/* Buffer to receive command on. */
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
} controller_info_t;

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

/* Shut down a control connection and remove it from the list of
   controllers. */
static void
shutdown_controller(controller_info_t *cntlr)
{
    controller_info_t *prev;
    controller_info_t *curr;

    if (cntlr->monitor_port_id != NULL) {
	data_monitor_stop(cntlr, cntlr->monitor_port_id);
	cntlr->monitor_port_id = NULL;
    }

    sel_clear_fd_handlers(ser2net_sel, cntlr->tcpfd);
    close(cntlr->tcpfd);
    if (cntlr->outbuf != NULL) {
	free(cntlr->outbuf);
    }
    cntlr->outbuf = NULL;

    /* Remove it from the linked list. */
    prev = NULL;
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

    free(cntlr);
}

/* Send some output to the control connection.  This allocates and
   free a buffer in blocks of 1024 and increases the size of the
   buffer as necessary. */
void
controller_output(struct controller_info *cntlr,
		  char                   *data,
		  int                    count)
{
    if (cntlr->outbuf != NULL) {
	/* Already outputting data, just add more onto it. */
	int  new_size = cntlr->outbuf_count + count;

	if (new_size <= cntlr->outbufsize) {
	    /* It will fit into the current buffer, just move things
	       around and append it. */
	    int i;

	    if (cntlr->outbuf_pos > 0) {
		for (i=0; i<cntlr->outbuf_count; i++) {
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
		/* Out of memory, just ignore thre request */
		return;
	    }

	    cntlr->outbufsize = new_size;

	    /* Copy all the data into a new buffer. */
	    memcpy(newbuf,
		   &(cntlr->outbuf[cntlr->outbuf_pos]),
		   cntlr->outbuf_count);
	    memcpy(newbuf+cntlr->outbuf_count, data, count);
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

/* Write some data directly to the controllers output port. */
void
controller_write(struct controller_info *cntlr, char *data, int count)
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
"exit - leave the program.\n\r"
"help - display this help.\n\r"
"version - display the version of this program.\n\r"
"monitor <type> <tcp port> - display all the input for a given port on\n\r"
"       the calling control port.  Only one direction may be monitored\n\r"
"       at a time.  The type field may be 'tcp' or 'term' and specifies\n\r"
"       whether to monitor data from the TCP port or from the serial port\n\r"
"       Note that data monitoring is best effort, if the controller port\n\r"
"       cannot keep up the data will be silently dropped.  A controller\n\r"
"       may only monitor one thing and a port may only be monitored by\n\r"
"       one controller.\n\r"
"monitor stop - stop the current monitor.\n\r"
"disconnect <tcp port> - disconnect the tcp connection on the port.\n\r"
"showport [<tcp port>] - Show information about a port. If no port is\n\r"
"       given, all ports are displayed.\n\r"
"showshortport [<tcp port>] - Show information about a port in a one-line\n\r"
"       format. If no port is given, all ports are displayed.\n\r"
"setporttimeout <tcp port> <timeout> - Set the amount of time in seconds\n\r"
"       before the port connection will be shut down if no activity\n\r"
"       has been seen on the port.\n\r"
"setportconfig <tcp port> <config> - Set the port configuration as in\n\r"
"       the device configuration in the ser2net.conf file.  Valid options\n\r"
"       are: 300, 1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200, \n\r"
"       EVEN, ODD, NONE, 1STOPBIT, 2STOPBITS, 7DATABITS, 8DATABITS, \n\r"
"       LOCAL (ignore modem control), [-]RTSCTS, [-]XONXOFF.\n\r"
"       Note that these will not change until the port is disconnected\n\r"
"       and connected again.\n\r"
"setportcontrol <tcp port> <controls>\n\r"
"       Dynamically modify the characteristics of the port.  These are\n\r"
"       immedaite and won't live between connections.  Valid controls are\n\r"
"       DTRHI, DTRLO, RTSHI, and RTSLO.\n\r"
"setportenable <tcp port> <enable state> - Sets the port operation state.\n\r"
"       Valid states are:\n\r"
"         off - The TCP port is shut down\n\r"
"         raw - The TCP port is up and all I/O is transferred\n\r"
"         rawlp - The TCP port is up and the input is transferred to dev\n\r"
"         telnet - The TCP port is up and the telnet negotiation protocol\n\r"
"                  runs on the port.\n\r";

/* Process a line of input.  This scans for commands, reads any
   parameters, then calls the actual code to handle the command. */
void
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
	return; /* We don't want a prompt any more. */
    } else if (strcmp(tok, "quit") == 0) {
	shutdown_controller(cntlr);
	return; /* We don't want a prompt any more. */
    } else if (strcmp(tok, "help") == 0) {
	controller_output(cntlr, help_str, strlen(help_str));
    } else if (strcmp(tok, "version") == 0) {
	str = "ser2net version ";
	controller_output(cntlr, str, strlen(str));
	str = VERSION;
	controller_output(cntlr, str, strlen(str));
	controller_output(cntlr, "\n\r", 2);
    } else if (strcmp(tok, "showport") == 0) {
	tok = strtok_r(NULL, " \t", &strtok_data);
	showports(cntlr, tok);
    } else if (strcmp(tok, "showshortport") == 0) {
	tok = strtok_r(NULL, " \t", &strtok_data);
	showshortports(cntlr, tok);
    } else if (strcmp(tok, "monitor") == 0) {
	tok = strtok_r(NULL, " \t", &strtok_data);
	if (tok == NULL) {
	    char *err = "No monitor type given\n\r";
	    controller_output(cntlr, err, strlen(err));
	    goto out;
	}
	if (strcmp(tok, "stop") == 0) {
	    if (cntlr->monitor_port_id != NULL) {
		data_monitor_stop(cntlr, cntlr->monitor_port_id);
		cntlr->monitor_port_id = NULL;
	    }
	} else {
	    if (cntlr->monitor_port_id != NULL) {
		char *err = "Already monitoring a port\n\r";
		controller_output(cntlr, err, strlen(err));
		goto out;
	    }
		
	    str = strtok_r(NULL, " \t", &strtok_data);
	    if (str == NULL) {
		char *err = "No tcp port given\n\r";
		controller_output(cntlr, err, strlen(err));
		goto out;
	    }
	    cntlr->monitor_port_id = data_monitor_start(cntlr, tok, str);
	}
    } else if (strcmp(tok, "disconnect") == 0) {
	tok = strtok_r(NULL, " \t", &strtok_data);
	if (tok == NULL) {
	    char *err = "No port given\n\r";
	    controller_output(cntlr, err, strlen(err));
	    goto out;
	}
	disconnect_port(cntlr, tok);
    } else if (strcmp(tok, "setporttimeout") == 0) {
	tok = strtok_r(NULL, " \t", &strtok_data);
	if (tok == NULL) {
	    char *err = "No port given\n\r";
	    controller_output(cntlr, err, strlen(err));
	    goto out;
	}
	str = strtok_r(NULL, " \t", &strtok_data);
	if (str == NULL) {
	    char *err = "No timeout given\n\r";
	    controller_output(cntlr, err, strlen(err));
	    goto out;
	}
	setporttimeout(cntlr, tok, str);
    } else if (strcmp(tok, "setportenable") == 0) {
	tok = strtok_r(NULL, " \t", &strtok_data);
	if (tok == NULL) {
	    char *err = "No port given\n\r";
	    controller_output(cntlr, err, strlen(err));
	    goto out;
	}
	str = strtok_r(NULL, " \t", &strtok_data);
	if (str == NULL) {
	    char *err = "No timeout given\n\r";
	    controller_output(cntlr, err, strlen(err));
	    goto out;
	}
	setportenable(cntlr, tok, str);
    } else if (strcmp(tok, "setportconfig") == 0) {
	tok = strtok_r(NULL, " \t", &strtok_data);
	if (tok == NULL) {
	    char *err = "No port given\n\r";
	    controller_output(cntlr, err, strlen(err));
	    goto out;
	}

	str = strtok_r(NULL, "", &strtok_data);
	if (str == NULL) {
	    char *err = "No device config\n\r";
	    controller_output(cntlr, err, strlen(err));
	    goto out;
	}
	setportdevcfg(cntlr, tok, str);
    } else if (strcmp(tok, "setportcontrol") == 0) {
	tok = strtok_r(NULL, " \t", &strtok_data);
	if (tok == NULL) {
	    char *err = "No port given\n\r";
	    controller_output(cntlr, err, strlen(err));
	    goto out;
	}

	str = strtok_r(NULL, "", &strtok_data);
	if (str == NULL) {
	    char *err = "No device controls\n\r";
	    controller_output(cntlr, err, strlen(err));
	    goto out;
	}
	setportcontrol(cntlr, tok, str);
    } else {
	char *err = "Unknown command: ";
	controller_output(cntlr, err, strlen(err));
	controller_output(cntlr, tok, strlen(tok));
	controller_output(cntlr, "\n\r", 2);
    }

out:
    controller_output(cntlr, prompt, strlen(prompt));
}

/* Removes one or more characters starting at pos and going backwards.
   So, for instance, if inbuf holds "abcde", pos points to d, and
   count is 2, the new inbuf will be "abe".  This is used for
   backspacing and for removing telnet command characters. */
static int
remove_chars(controller_info_t *cntlr, int pos, int count) {
    int j;

    for (j=pos-count+1; j<(cntlr->inbuf_count-count); j++) {
	cntlr->inbuf[j] = cntlr->inbuf[j+count];
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

    if (cntlr->inbuf_count == INBUF_SIZE) {
        char *err = "Input line too long\n\r";
	controller_output(cntlr, err, strlen(err));
	cntlr->inbuf_count = 0;
	return;
    }

    read_count = read(fd,
		      &(cntlr->inbuf[cntlr->inbuf_count]),
		      INBUF_SIZE - cntlr->inbuf_count);

    if (read_count < 0) {
	if (errno == EINTR) {
	    /* EINTR means we were interrupted, just retry by returning. */
	    return;
	}

	if (errno == EAGAIN) {
	    /* EAGAIN, is due to O_NONBLOCK, just ignore it. */
	    return;
	}

	/* Got an error on the read, shut down the port. */
	syslog(LOG_ERR, "read error for controller port: %m");
	shutdown_controller(cntlr);
	return;
    } else if (read_count == 0) {
	/* The other end closed the port, shut it down. */
	shutdown_controller(cntlr);
	return;
    }
    read_start = cntlr->inbuf_count;
    read_count = process_telnet_data
	(cntlr->inbuf+read_start, read_count, &cntlr->tn_data);
    if (cntlr->tn_data.error) {
	shutdown_controller(cntlr);
	return;
    }
    cntlr->inbuf_count += read_count;
    
    for (i=read_start; i<cntlr->inbuf_count; i++) {
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
		controller_output(cntlr, "\b \b", 3);
	    }
	} else if (cntlr->inbuf[i] == '\r') {
	    /* We got a newline, process the command. */
	    int j;

	    controller_output(cntlr, "\n\r", 2);

	    cntlr->inbuf[i] ='\0';
	    process_input_line(cntlr);

	    /* Now copy any leftover data to the beginning of the buffer. */
	    /* Don't use memcpy or strcpy because the memory might
               overlap */
	    i++;
	    cntlr->inbuf_count -= i;
	    for (j=0; j<cntlr->inbuf_count; i++,j++) {
		cntlr->inbuf[j] = cntlr->inbuf[i];
	    }
	    i = -1;
	} else {
	    /* It's a normal character, just echo it. */
	    controller_output(cntlr, (char *) &(cntlr->inbuf[i]), 1);
	}
    }
}

/* The TCP port has room to write some data.  This is only activated
   if a write fails to complete, it is deactivated as soon as writing
   is available again. */
static void
handle_tcp_fd_write(int fd, void *data)
{
    controller_info_t *cntlr = (controller_info_t *) data;
    telnet_data_t *td = &cntlr->tn_data;
    int write_count;

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
    return;

 out_fail:
    shutdown_controller(cntlr);
}

/* Handle an exception from the TCP port. */
static void
handle_tcp_fd_except(int fd, void *data)
{
    controller_info_t *cntlr = (controller_info_t *) data;

    syslog(LOG_ERR, "Select exception for controller port");
    shutdown_controller(cntlr);
}

/* A connection request has come in for the control port. */
static void
handle_accept_port_read(int fd, void *data)
{
    controller_info_t *cntlr;
    socklen_t         len;
    char              *err = NULL;
    int               optval;

    if (num_controller_ports >= max_controller_ports) {
	err = "Too many controller ports\n\r";
	goto errout2;
    } else {
	cntlr = malloc(sizeof(*cntlr));
	if (cntlr == NULL) {
	    err = "Could not allocate controller port\n\r";
	    goto errout2;
	}
    }

    /* From here on, errors must go to errout. */

    len = sizeof(cntlr->remote);
    cntlr->tcpfd = accept(fd, (struct sockaddr *) &(cntlr->remote), &len);
    if (cntlr->tcpfd == -1) {
	syslog(LOG_ERR, "Could not accept on controller port: %m");
	goto errout;
    }

#ifdef HAVE_TCPD_H
    {
	struct request_info req;
	
	request_init(&req, RQ_DAEMON, progname, RQ_FILE, cntlr->tcpfd, NULL);
	fromhost(&req);

	if (!hosts_access(&req)) {
	    char *err = "Access denied\n\r";
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
			handle_tcp_fd_except);

    cntlr->next = controllers;
    controllers = cntlr;

    /* Send the telnet negotiation string.  We do this by
       putting the data in the dev to tcp buffer and turning
       the tcp write selector on. */

    telnet_init(&cntlr->tn_data, cntlr, telnet_output_ready,
		telnet_cmd_handler,
		telnet_cmds,
		telnet_init_seq, sizeof(telnet_init_seq));
    controller_output(cntlr, prompt, strlen(prompt));

    num_controller_ports++;

    return;

errout:
    free(cntlr);
    return;

errout2:
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

/* Set up the controller port to accept connections. */
int
controller_init(char *controller_port)
{
    struct sockaddr_storage sock;
    socklen_t sock_len;
    int    optval = 1;

    if (scan_tcp_port(controller_port, AF_UNSPEC, &sock, &sock_len) == -1)
	return CONTROLLER_INVALID_TCP_SPEC;
    
    acceptfd = socket(sock.ss_family, SOCK_STREAM, 0);
    if ((acceptfd == -1) && (errno == EAFNOSUPPORT)) {
	/* Retry IPV4-only */
	if (scan_tcp_port(controller_port, AF_INET, &sock, &sock_len) == -1)
	    return CONTROLLER_INVALID_TCP_SPEC;
	acceptfd = socket(sock.ss_family, SOCK_STREAM, 0);
    }
    if (acceptfd == -1) {
	syslog(LOG_ERR, "Unable to create TCP socket: %m");
	return CONTROLLER_CANT_OPEN_PORT;
    }

    if (fcntl(acceptfd, F_SETFL, O_NONBLOCK) == -1) {
	close(acceptfd);
	acceptfd = -1;
	syslog(LOG_ERR, "Could not fcntl the accept port: %m");
	return CONTROLLER_CANT_OPEN_PORT;
    }

    if (setsockopt(acceptfd,
		   SOL_SOCKET,
		   SO_REUSEADDR,
		   (void *)&optval,
		   sizeof(optval)) == -1) {
	close(acceptfd);
	acceptfd = -1;
	syslog(LOG_ERR, "Unable to set reuseaddress on socket: %m");
	return CONTROLLER_CANT_OPEN_PORT;
    }

    check_ipv6_only(sock.ss_family,
		    ((struct sockaddr *) &sock),
		    acceptfd);

    if (bind(acceptfd, (struct sockaddr *) &sock, sock_len) == -1) {
	close(acceptfd);
	acceptfd = -1;
	syslog(LOG_ERR, "Unable to bind TCP port: %m");
	return CONTROLLER_CANT_OPEN_PORT;
    }

    if (listen(acceptfd, 1) != 0) {
	close(acceptfd);
	acceptfd = -1;
	syslog(LOG_ERR, "Unable to listen to TCP port: %m");
	return CONTROLLER_CANT_OPEN_PORT;
    }

    sel_set_fd_handlers(ser2net_sel,
			acceptfd,
			NULL,
			handle_accept_port_read,
			NULL,
			NULL);
    sel_set_fd_read_handler(ser2net_sel, acceptfd, SEL_FD_HANDLER_ENABLED);
    return 0;
}

void
controller_shutdown(void)
{
    if (acceptfd == -1)
	return;
    sel_clear_fd_handlers(ser2net_sel, acceptfd);
    close(acceptfd);
    acceptfd = -1;
}
