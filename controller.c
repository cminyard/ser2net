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

#include <termios.h>
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

/** BASED ON sshd.c FROM openssh.com */
#ifdef HAVE_TCPD_H
#include <tcpd.h>
int allow_severity = LOG_INFO;
int deny_severity = LOG_WARNING;
static char *progname = "ser2net-control";
#endif /* HAVE_TCPD_H */

/* This file holds the code that runs the control port. */

static int port;	/* The TCP port for the control port. */
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
    struct sockaddr_in remote;		/* The socket address of who
					   is connected to this port. */

    char telnet_cmd[3];			/* An incoming telnet command. */
    int  telnet_cmd_pos;		/* The current position in the
					   telnet command buffer. */

    char inbuf[INBUF_SIZE+1];		/* Buffer to receive command on. */
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
} controller_info_t;

/* List of current control connections. */
controller_info_t *controllers = NULL;

/* Used to initialize the telnet session. */
static char telnet_init[] = {
    0xff, 0xfb, 0x03,  /* command WILL SUPPRESS GO AHEAD */
    0xff, 0xfb, 0x01,  /* command WILL ECHO */
    0xff, 0xfe, 0x01   /* command DON'T ECHO */
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

    clear_fd_handlers(cntlr->tcpfd);
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

	if (new_size < cntlr->outbufsize) {
	    /* It will fit into the current buffer, just move things
	       around and append it. */
	    int i;

	    if (cntlr->outbuf_pos > 0) {
		for (i=0; i<cntlr->outbuf_count; i++) {
		    cntlr->outbuf[i] = cntlr->outbuf[cntlr->outbuf_pos];
		    (cntlr->outbuf_pos)++;
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
	    cntlr->outbuf_pos = 0;
	}
	cntlr->outbuf_count += count;
    } else {
	/* We are starting a new buffer, just get it. */
	char *newbuf;

	newbuf = malloc(1024);
	if (newbuf == NULL) {
	    /* Out of memory, just ignore thre request */
	    return;
	}
	
	cntlr->outbufsize = 1024;

	memcpy(newbuf, data, count);
	cntlr->outbuf = newbuf;
	cntlr->outbuf_pos = 0;
	cntlr->outbuf_count = count;
	set_fd_read_handler(cntlr->tcpfd, FD_HANDLER_DISABLED);
	set_fd_write_handler(cntlr->tcpfd, FD_HANDLER_ENABLED);
    }
}

/* Write some data directly to the controllers output port. */
void
controller_write(struct controller_info *cntlr, char *data, int count)
{
    write(cntlr->tcpfd, data, count);
}

/* Called when a telnet command is received complete. */
void
process_telnet_command(controller_info_t *cntlr)
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
"setporttimeout <tcp port> <timeout> - Set the amount of time in seconds\n\r"
"       before the port connection will be shut down if no activity\n\r"
"       has been seen on the port.\n\r"
"setportconfig <tcp port> <config> - Set the port configuration as in\n\r"
"       the device configuration in the ser2net.conf file.  Valid options\n\r"
"       are: 300, 1200, 2400, 4800, 9600, 19200, 38400, 115200, EVEN, ODD\n\r"
"       NONE, 1STOPBIT, 2STOPBITS, 7DATABITS, 8DATABITS.\n\r"
"       Note that these will not change until the port is disconnected\n\r"
"       and connected again.\n\r"
"setportenable <tcp port> <enable state> - Sets the port operation state.\n\r"
"       Valid states are:\n\r"
"         off - The TCP port is shut down\n\r"
"         raw - The TCP port is up and all I/O is transferred\n\r"
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

    tok = strtok_r(cntlr->inbuf, " \t", &strtok_data);
    if (tok == NULL) {
	/* Empty line, just ignore it. */
    } else if (strcmp(tok, "exit") == 0) {
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
    cntlr->inbuf_count += read_count;

    for (i=read_start; i<cntlr->inbuf_count; i++) {
	if (cntlr->telnet_cmd_pos != 0) {
	    /* In the middle of a telnet command. */
	    cntlr->telnet_cmd[cntlr->telnet_cmd_pos] = cntlr->inbuf[i];
	    cntlr->telnet_cmd_pos++;

	    i = remove_chars(cntlr, i, 1);

	    if (cntlr->telnet_cmd_pos == 3) {
		/* We are done with the telnet command. */
		process_telnet_command(cntlr);
		cntlr->telnet_cmd_pos = 0;
	    }
	} else if (cntlr->inbuf[i] == 0xff) {
	    /* Got a telnet command start. */
	    cntlr->telnet_cmd[cntlr->telnet_cmd_pos] = cntlr->inbuf[i];
	    cntlr->telnet_cmd_pos = 1;
	    i = remove_chars(cntlr, i, 1);
	} else if (cntlr->inbuf[i] == 0x0) {
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
	    controller_output(cntlr, &(cntlr->inbuf[i]), 1);
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
    int write_count;

    write_count = write(cntlr->tcpfd,
			&(cntlr->outbuf[cntlr->outbuf_pos]),
			cntlr->outbuf_count);
    if (write_count == -1) {
	if (errno == EAGAIN) {
	    /* This again was due to O_NONBLOCK, just ignore it. */
	} else if (errno == EPIPE) {
	    shutdown_controller(cntlr);
	} else {
	    /* Some other bad error. */
	    syslog(LOG_ERR, "The tcp write for controller had error: %m");
	    shutdown_controller(cntlr);
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
	    set_fd_read_handler(cntlr->tcpfd, FD_HANDLER_ENABLED);
	    set_fd_write_handler(cntlr->tcpfd, FD_HANDLER_DISABLED);
	}
    }
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

    cntlr = malloc(sizeof(*cntlr));
    if (cntlr == NULL) {
	err = "Could not allocate controller port\n\r";
    }

    if (num_controller_ports >= max_controller_ports) {
	err = "Too many controller ports\n\r";
    }

    if (err != NULL) {
	/* We have a problem so refuse this one. */
	struct sockaddr_in dummy_sockaddr;
	socklen_t len = sizeof(dummy_sockaddr);
	int new_fd = accept(fd, &dummy_sockaddr, &len);

	if (new_fd != -1) {
	    write(new_fd, err, strlen(err));
	    close(new_fd);
	}
	return;
    }

    /* From here on, errors must go to errout. */

    len = sizeof(cntlr->remote);
    cntlr->tcpfd = accept(fd, &(cntlr->remote), &len);
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
	    return;
	}
    }
#endif /* HAVE_TCPD_H */

    if (fcntl(cntlr->tcpfd, F_SETFL, O_NONBLOCK) == -1) {
	close(cntlr->tcpfd);
	syslog(LOG_ERR, "Could not fcntl the tcp port: %m");
	goto errout;
    }

    cntlr->inbuf_count = 0;
    cntlr->telnet_cmd_pos = 0;
    cntlr->outbuf = NULL;

    set_fd_handlers(cntlr->tcpfd,
		    cntlr,
		    handle_tcp_fd_read,
		    handle_tcp_fd_write,
		    handle_tcp_fd_except);

    cntlr->next = controllers;
    controllers = cntlr;

    /* Send the telnet negotiation string.  We do this by
       putting the data in the dev to tcp buffer and turning
       the tcp write selector on. */

    controller_output(cntlr, telnet_init, sizeof(telnet_init));
    controller_output(cntlr, prompt, strlen(prompt));

    num_controller_ports++;

    return;

errout:
    free(cntlr);
    return;
}

/* Set up the controller port to accept connections. */
void
controller_init(int controller_port)
{
    struct sockaddr_in sock;
    int    optval = 1;

    port = controller_port;

    acceptfd = socket(PF_INET, SOCK_STREAM, 0);
    if (acceptfd == -1) {
	syslog(LOG_ERR, "Unable to create TCP socket: %m");
	exit(1);
    }

    if (fcntl(acceptfd, F_SETFL, O_NONBLOCK) == -1) {
	close(acceptfd);
	syslog(LOG_ERR, "Could not fcntl the accept port: %m");
	exit(1);
    }

    if (setsockopt(acceptfd,
		   SOL_SOCKET,
		   SO_REUSEADDR,
		   (void *)&optval,
		   sizeof(optval)) == -1) {
	close(acceptfd);
	syslog(LOG_ERR, "Unable to set reuseaddress on socket: %m");
	exit(1);
    }

    sock.sin_family = AF_INET;
    sock.sin_port = htons(port);
    sock.sin_addr.s_addr = INADDR_ANY;
    if (bind(acceptfd, &sock, sizeof(sock)) == -1) {
	close(acceptfd);
	syslog(LOG_ERR, "Unable to bind TCP port: %m");
	exit(1);
    }

    if (listen(acceptfd, 1) != 0) {
	close(acceptfd);
	syslog(LOG_ERR, "Unable to listen to TCP port: %m");
	exit(1);
    }

    set_fd_handlers(acceptfd,
		    NULL,
		    handle_accept_port_read,
		    NULL,
		    NULL);
    set_fd_read_handler(acceptfd, FD_HANDLER_ENABLED);
}
