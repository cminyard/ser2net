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

/* This code handles the actual transfer of data between the serial
   ports and the TCP ports. */

#include <termios.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <errno.h>
#include <syslog.h>

#include "dataxfer.h"
#include "selector.h"
#include "devcfg.h"
#include "utils.h"

/* FIXME - Add UUCP style device locking. */

/* States for the tcp_to_dev_state and dev_to_tcp_state. */
#define PORT_UNCONNECTED		0 /* The TCP port is not connected
                                             to anything right now. */
#define PORT_WAITING_INPUT		1 /* Waiting for input from the
					     input side. */
#define PORT_WAITING_OUTPUT_CLEAR	2 /* Waiting for output to clear
					     so I can send data. */
char *state_str[] = { "unconnected", "waiting input", "waiting output" };

#define PORT_DISABLED		0 /* The port is not open. */
#define PORT_RAW		1 /* Port will not do telnet negotiation. */
#define PORT_TELNET		2 /* Port will do telnet negotiation. */
char *enabled_str[] = { "off", "raw", "telnet" };

#define PORT_BUFSIZE	1024

typedef struct port_info
{
    int            enabled;		/* If PORT_DISABLED, the port
					   is disabled and the TCP
					   accept port is not
					   operational.  If PORT_RAW,
					   the port is enabled and
					   will not do any telnet
					   negotiations.  If
					   PORT_TELNET, the port is
					   enabled and it will do
					   telnet negotiations. */

    int            timeout;		/* The number of seconds to
					   wait without any I/O before
					   we shut the port down. */
    struct timeval last_io_time;	/* Time that the last I/O
					   operation occurred, used to
					   check if we need to shut
					   the port down. */


    /* Information about the TCP port. */
    int            tcpport;		/* The TCP port to listen on
					   for connections to this
					   terminal device. */
    int            acceptfd;		/* The file descriptor used to
					   accept connections on the
					   TCP port. */
    int            tcpfd;		/* When connected, the file
                                           descriptor for the TCP
                                           port used for I/O. */
    struct sockaddr_in remote;		/* The socket address of who
					   is connected to this port. */

    /* Information about the terminal device. */
    char           *devname;		/* The full path to the device */
    int            devfd;		/* The file descriptor for the
                                           device, only valid if the
                                           TCP port is open. */
    struct termios termctl;		/* The termios information to
					   set for the device. */


    /* Information use when transferring information from the TCP port
       to the terminal device. */
    int            tcp_to_dev_state;		/* State of transferring
						   data from the TCP port
                                                   to the device. */
    unsigned char  tcp_to_dev_buf[PORT_BUFSIZE]; /* Buffer used for
                                                    TCP to device
                                                    transfers. */
    int            tcp_to_dev_buf_start;	/* The first byte in
						   the buffer that is
						   ready to send. */
    int            tcp_to_dev_buf_count;	/* The number of bytes
                                                   in the buffer to
                                                   send. */
    struct controller_info *tcp_monitor; /* If non-null, send any input
					    received from the TCP port
					    to this controller port. */


    char           telnet_cmd[3];	/* Incoming telnet commands. */
    int            telnet_cmd_pos;      /* Current position in the
					   telnet_cmd buffer.  If zero,
					   no telnet command is in
					   progress. */
    /* Information use when transferring information from the terminal
       device to the TCP port. */
    int            dev_to_tcp_state;		/* State of transferring
						   data from the device to
                                                   the TCP port. */
    char           dev_to_tcp_buf[PORT_BUFSIZE]; /* Buffer used for
                                                    device to TCP
                                                    transfers. */
    int            dev_to_tcp_buf_start;	/* The first byte in
						   the buffer that is
						   ready to send. */
    int            dev_to_tcp_buf_count;	/* The number of bytes
                                                   in the buffer to
                                                   send. */
    struct controller_info *dev_monitor; /* If non-null, send any input
					    received from the device
					    to this controller port. */

    struct port_info *next;		/* Used to keep a linked list
					   of these. */
} port_info_t;

port_info_t *ports = NULL; /* Linked list of ports. */

static unsigned char telnet_init[] = {
    0xff, 0xfb, 0x03,  /* command WILL SUPPRESS GO AHEAD */
    0xff, 0xfb, 0x01,  /* command WILL ECHO */
    0xff, 0xfe, 0x01   /* command DON'T ECHO */
};

static void
init_port_data(port_info_t *port)
{
    port->enabled = 0;
    port->tcpport = 0;
    port->acceptfd = 0;
    port->tcpfd = 0;
    port->timeout = 0;
    port->next = NULL;
    
    port->devname = NULL;
    port->devfd = 0;
    memset(&(port->termctl), 0, sizeof(port->termctl));
    memset(&(port->last_io_time), 0, sizeof(port->last_io_time));
    port->tcp_to_dev_state = PORT_UNCONNECTED;
    port->tcp_to_dev_buf_start = 0;
    port->tcp_to_dev_buf_count = 0;
    port->dev_to_tcp_state = PORT_UNCONNECTED;
    port->dev_to_tcp_buf_start = 0;
    port->dev_to_tcp_buf_count = 0;
    port->telnet_cmd_pos = 0;
}

static void
shutdown_port(port_info_t *port)
{
    clear_fd_handlers(port->devfd);
    clear_fd_handlers(port->tcpfd);
    close(port->tcpfd);
    close(port->devfd);
    port->tcp_to_dev_state = PORT_UNCONNECTED;
    port->tcp_to_dev_buf_start = 0;
    port->tcp_to_dev_buf_count = 0;
    port->dev_to_tcp_state = PORT_UNCONNECTED;
    port->dev_to_tcp_buf_start = 0;
    port->dev_to_tcp_buf_count = 0;
    port->telnet_cmd_pos = 0;
}

void
delete_tcp_to_dev_char(port_info_t *port, int pos)
{
    int j;

    for (j=pos; j<port->tcp_to_dev_buf_count-1; j++) {
	port->tcp_to_dev_buf[j] = port->tcp_to_dev_buf[j+1];
    }
    port->tcp_to_dev_buf_count--;
}

static void
handle_telnet_cmd(port_info_t *port)
{
    if (port->telnet_cmd[1] == 243) { /* A BREAK command. */
	printf("Sending break\n");
	tcsendbreak(port->devfd, 0);
    }
}

/* Data is ready to read on the serial port. */
static void
handle_dev_fd_read(int fd, void *data)
{
    port_info_t *port = (port_info_t *) data;
    int write_count;

    port->dev_to_tcp_buf_start = 0;
    port->dev_to_tcp_buf_count = read(fd, port->dev_to_tcp_buf, PORT_BUFSIZE);

    if (port->dev_to_tcp_buf_count < 0) {
	/* Got an error on the read, shut down the port. */
	syslog(LOG_ERR, "dev read error for port %d: %m", port->tcpport);
	shutdown_port(port);
	return;
    } else if (port->dev_to_tcp_buf_count == 0) {
	/* The port got closed somehow, shut it down. */
	shutdown_port(port);
	return;
    }

    write_count = write(port->tcpfd,
			port->dev_to_tcp_buf,
			port->dev_to_tcp_buf_count);
    if (port->dev_monitor != NULL) {
	controller_write(port->dev_monitor,
			 port->dev_to_tcp_buf,
			 port->dev_to_tcp_buf_count);
    }
    if (write_count == -1) {
	if (errno == EINTR) {
	    /* EINTR means we were interrupted, just retry by returning. */
	    return;
	}

	if (errno == EAGAIN) {
	    /* This was due to O_NONBLOCK, we need to shut off the reader
	       and start the writer monitor. */
	    set_fd_read_handler(port->devfd, FD_HANDLER_DISABLED);
	    set_fd_write_handler(port->tcpfd, FD_HANDLER_ENABLED);
	    port->dev_to_tcp_state = PORT_WAITING_OUTPUT_CLEAR;
	} else if (errno == EPIPE) {
	    shutdown_port(port);
	} else {
	    /* Some other bad error. */
	    syslog(LOG_ERR, "The tcp write for port %d had error: %m",
		   port->tcpport);
	    shutdown_port(port);
	}
    } else {
	port->dev_to_tcp_buf_count -= write_count;
	if (port->dev_to_tcp_buf_count != 0) {
	    /* We didn't write all the data, shut off the reader and
               start the write monitor. */
	    port->dev_to_tcp_buf_start += write_count;
	    set_fd_read_handler(port->devfd, FD_HANDLER_DISABLED);
	    set_fd_write_handler(port->tcpfd, FD_HANDLER_ENABLED);
	    port->dev_to_tcp_state = PORT_WAITING_OUTPUT_CLEAR;
	}
    }

    gettimeofday(&(port->last_io_time), NULL);
}

/* The serial port has room to write some data.  This is only activated
   if a write fails to complete, it is deactivated as soon as writing
   is available again. */
static void
handle_dev_fd_write(int fd, void *data)
{
    port_info_t *port = (port_info_t *) data;
    int write_count;

    write_count = write(port->devfd,
			&(port->tcp_to_dev_buf[port->tcp_to_dev_buf_start]),
			port->tcp_to_dev_buf_count);
    if (write_count == -1) {
	if (errno == EINTR) {
	    /* EINTR means we were interrupted, just retry by returning. */
	    return;
	}

	if (errno == EAGAIN) {
	    /* This again was due to O_NONBLOCK, just ignore it. */
	} else {
	    /* Some other bad error. */
	    syslog(LOG_ERR, "The dev write for port %d had error: %m",
		   port->tcpport);
	    shutdown_port(port);
	}
    } else {
	port->tcp_to_dev_buf_count -= write_count;
	if (port->tcp_to_dev_buf_count != 0) {
	    /* We didn't write all the data, continue writing. */
	    port->tcp_to_dev_buf_start += write_count;
	} else {
	    /* We are done writing, turn the reader back on. */
	    set_fd_read_handler(port->tcpfd, FD_HANDLER_ENABLED);
	    set_fd_write_handler(port->devfd, FD_HANDLER_DISABLED);
	    port->tcp_to_dev_state = PORT_WAITING_INPUT;
	}
    }

    gettimeofday(&(port->last_io_time), NULL);
}

/* Handle an exception from the serial port. */
static void
handle_dev_fd_except(int fd, void *data)
{
    port_info_t *port = (port_info_t *) data;

    syslog(LOG_ERR, "Select exception on device for port %d", port->tcpport);
    shutdown_port(port);
}

/* Data is ready to read on the TCP port. */
static void
handle_tcp_fd_read(int fd, void *data)
{
    port_info_t *port = (port_info_t *) data;
    int write_count;

    port->tcp_to_dev_buf_start = 0;
    port->tcp_to_dev_buf_count = read(fd, port->tcp_to_dev_buf, PORT_BUFSIZE);

    if (port->enabled == PORT_TELNET) {
	int i;

	/* If it's a telnet port, get the commands out of the stream. */
	for (i=0; i<port->tcp_to_dev_buf_count;) {
	    if (port->telnet_cmd_pos != 0) {
		if ((port->telnet_cmd_pos == 1)
		    && (port->tcp_to_dev_buf[i] == 255))
		{
		    /* Two IACs in a row causes one IAC to be sent, so
		       just let this one go through. */
		    i++;
		    continue;
		}

		port->telnet_cmd[port->telnet_cmd_pos]
		    = port->tcp_to_dev_buf[i];
		delete_tcp_to_dev_char(port, i);
		port->telnet_cmd_pos++;

		if ((port->telnet_cmd_pos == 2)
		    && (port->telnet_cmd[1] <= 250))
		{
		    /* These are two byte commands, so we have
		       everything we need to handle the command. */
		    handle_telnet_cmd(port);
		    port->telnet_cmd_pos = 0;
		} else if (port->telnet_cmd_pos == 3) {
		    handle_telnet_cmd(port);
		    port->telnet_cmd_pos = 0;
		}
	    } else if (port->tcp_to_dev_buf[i] == 255) {
		port->telnet_cmd[port->telnet_cmd_pos]
		    = port->tcp_to_dev_buf[i];
		delete_tcp_to_dev_char(port, i);
		port->telnet_cmd_pos++;
	    } else {
		i++;
	    }

	    if (port->tcp_to_dev_buf_count == 0) {
		/* We are out of characters but they were all
                   processed.  We don't want to continue with 0,
                   because that will mess up the other processing and
                   it's not necessary. */
		return;
	    }
	}
    }

    if (port->tcp_to_dev_buf_count < 0) {
	/* Got an error on the read, shut down the port. */
	syslog(LOG_ERR, "read error for port %d: %m", port->tcpport);
	shutdown_port(port);
	return;
    } else if (port->tcp_to_dev_buf_count == 0) {
	/* The other end closed the port, shut it down. */
	shutdown_port(port);
	return;
    }

    write_count = write(port->devfd,
			port->tcp_to_dev_buf,
			port->tcp_to_dev_buf_count);
    if (port->tcp_monitor != NULL) {
	controller_write(port->tcp_monitor,
			 port->tcp_to_dev_buf,
			 port->tcp_to_dev_buf_count);
    }
    if (write_count == -1) {
	if (errno == EINTR) {
	    /* EINTR means we were interrupted, just retry by returning. */
	    return;
	}

	if (errno == EAGAIN) {
	    /* This was due to O_NONBLOCK, we need to shut off the reader
	       and start the writer monitor. */
	    set_fd_read_handler(port->tcpfd, FD_HANDLER_DISABLED);
	    set_fd_write_handler(port->devfd, FD_HANDLER_ENABLED);
	    port->tcp_to_dev_state = PORT_WAITING_OUTPUT_CLEAR;
	} else {
	    /* Some other bad error. */
	    syslog(LOG_ERR, "The dev write for port %d had error: %m",
		   port->tcpport);
	    shutdown_port(port);
	}
    } else {
	port->tcp_to_dev_buf_count -= write_count;
	if (port->tcp_to_dev_buf_count != 0) {
	    /* We didn't write all the data, shut off the reader and
               start the write monitor. */
	    port->tcp_to_dev_buf_start += write_count;
	    set_fd_read_handler(port->tcpfd, FD_HANDLER_DISABLED);
	    set_fd_write_handler(port->devfd, FD_HANDLER_ENABLED);
	    port->tcp_to_dev_state = PORT_WAITING_OUTPUT_CLEAR;
	}
    }

    gettimeofday(&(port->last_io_time), NULL);
}

/* The TCP port has room to write some data.  This is only activated
   if a write fails to complete, it is deactivated as soon as writing
   is available again. */
static void
handle_tcp_fd_write(int fd, void *data)
{
    port_info_t *port = (port_info_t *) data;
    int write_count;

    write_count = write(port->tcpfd,
			&(port->dev_to_tcp_buf[port->dev_to_tcp_buf_start]),
			port->dev_to_tcp_buf_count);
    if (write_count == -1) {
	if (errno == EINTR) {
	    /* EINTR means we were interrupted, just retry by returning. */
	    return;
	}

	if (errno == EAGAIN) {
	    /* This again was due to O_NONBLOCK, just ignore it. */
	} else if (errno == EPIPE) {
	    shutdown_port(port);
	} else {
	    /* Some other bad error. */
	    syslog(LOG_ERR, "The tcp write for port %d had error: %m",
		   port->tcpport);
	    shutdown_port(port);
	}
    } else {
	port->dev_to_tcp_buf_count -= write_count;
	if (port->dev_to_tcp_buf_count != 0) {
	    /* We didn't write all the data, continue writing. */
	    port->dev_to_tcp_buf_start += write_count;
	} else {
	    /* We are done writing, turn the reader back on. */
	    set_fd_read_handler(port->devfd, FD_HANDLER_ENABLED);
	    set_fd_write_handler(port->tcpfd, FD_HANDLER_DISABLED);
	    port->dev_to_tcp_state = PORT_WAITING_INPUT;
	}
    }

    gettimeofday(&(port->last_io_time), NULL);
}

/* Handle an exception from the TCP port. */
static void
handle_tcp_fd_except(int fd, void *data)
{
    port_info_t *port = (port_info_t *) data;

    syslog(LOG_ERR, "Select exception on port %d", port->tcpport);
    shutdown_port(port);
}

/* Checks to see if some other port has the same device in use. */
static int
is_device_already_inuse(port_info_t *check_port)
{
    port_info_t *port = ports;

    while (port != NULL) {
	if (port != check_port) {
	    if ((strcmp(port->devname, check_port->devname) == 0) 
		&& (port->tcp_to_dev_state != PORT_UNCONNECTED))
	    {
		return 1;
	    }
	}    
	port = port->next;
    }

    return 0;
}

/* A connection request has come in on a port. */
static void
handle_accept_port_read(int fd, void *data)
{
    port_info_t *port = (port_info_t *) data;
    socklen_t len;
    char *err = NULL;

    if (port->tcp_to_dev_state != PORT_UNCONNECTED) {
	err = "Port already in use\n\r";
    } else if (is_device_already_inuse(port)) {
	err = "Port's device already in use\n\r";
    }

    if (err != NULL) {
	struct sockaddr_in dummy_sockaddr;
	socklen_t len = sizeof(dummy_sockaddr);
	int new_fd = accept(fd, &dummy_sockaddr, &len);

	if (new_fd != -1) {
	    write(new_fd, err, strlen(err));
	    close(new_fd);
	}
	return;
    }

    len = sizeof(port->remote);

    port->tcpfd = accept(fd, &(port->remote), &len);
    if (port->tcpfd == -1) {
	syslog(LOG_ERR, "Could not accept on port %d: %m", port->tcpport);
	return;
    }

    if (fcntl(port->tcpfd, F_SETFL, O_NONBLOCK) == -1) {
	close(port->tcpfd);
	syslog(LOG_ERR, "Could not fcntl the tcp port %d: %m", port->tcpport);
	return;
    }

    port->devfd = open(port->devname, O_RDWR | O_NONBLOCK);
    if (port->devfd == -1) {
	close(port->tcpfd);
	syslog(LOG_ERR, "Could not open device %s for port %d: %m",
	       port->devname,
	       port->tcpport);
	return;
    }

    if (tcsetattr(port->devfd, TCSANOW, &(port->termctl)) == -1) {
	close(port->tcpfd);
	close(port->devfd);
	syslog(LOG_ERR, "Could not set up device %s for port %d: %m",
	       port->devname,
	       port->tcpport);
	return;
    }

    set_fd_handlers(port->devfd,
		    port,
		    handle_dev_fd_read,
		    handle_dev_fd_write,
		    handle_dev_fd_except);
    set_fd_read_handler(port->devfd, FD_HANDLER_ENABLED);
    set_fd_except_handler(port->devfd, FD_HANDLER_ENABLED);
    port->dev_to_tcp_state = PORT_WAITING_INPUT;

    set_fd_handlers(port->tcpfd,
		    port,
		    handle_tcp_fd_read,
		    handle_tcp_fd_write,
		    handle_tcp_fd_except);
    set_fd_read_handler(port->tcpfd, FD_HANDLER_ENABLED);
    set_fd_except_handler(port->tcpfd, FD_HANDLER_ENABLED);
    port->tcp_to_dev_state = PORT_WAITING_INPUT;

    if (port->enabled == PORT_TELNET) {
	/* Send the telnet negotiation string.  We do this by
	   putting the data in the dev to tcp buffer and turning
	   the tcp write selector on. */
	memcpy(port->dev_to_tcp_buf, telnet_init, sizeof(telnet_init));
	port->dev_to_tcp_buf_start = 0;
	port->dev_to_tcp_buf_count = sizeof(telnet_init);
	set_fd_read_handler(port->devfd, FD_HANDLER_DISABLED);
	set_fd_write_handler(port->tcpfd, FD_HANDLER_ENABLED);
    }

    gettimeofday(&(port->last_io_time), NULL);
}

/* Start monitoring for connections on a specific port. */
static char *
startup_port(port_info_t *port)
{
    struct sockaddr_in sock;
    int    optval = 1;
    
    port->acceptfd = socket(PF_INET, SOCK_STREAM, 0);
    if (port->acceptfd == -1) {
	return "Unable to create TCP socket";
    }

    if (fcntl(port->acceptfd, F_SETFL, O_NONBLOCK) == -1) {
	close(port->acceptfd);
	return "Could not fcntl the accept port";
    }

    if (setsockopt(port->acceptfd,
		   SOL_SOCKET,
		   SO_REUSEADDR,
		   (void *)&optval,
		   sizeof(optval)) == -1) {
	close(port->acceptfd);
	return "Unable to set reuseaddress on socket";
    }

    sock.sin_family = AF_INET;
    sock.sin_port = htons(port->tcpport);
    sock.sin_addr.s_addr = INADDR_ANY;
    if (bind(port->acceptfd, &sock, sizeof(sock)) == -1) {
	close(port->acceptfd);
	return "Unable to bind TCP port";
    }

    if (listen(port->acceptfd, 1) != 0) {
	close(port->acceptfd);
	return "Unable to listen to TCP port";
    }

    set_fd_handlers(port->acceptfd,
		    port,
		    handle_accept_port_read,
		    NULL,
		    NULL);
    set_fd_read_handler(port->acceptfd, FD_HANDLER_ENABLED);

    return NULL;
}

/* Create a port based on a set of parameters passed in. */
char *
portconfig(char *portnum,
	   char *state,
	   char *timeout,
	   char *devname,
	   char *devcfg)
{
    port_info_t *new_port;
    char        *rv = NULL;

    new_port = malloc(sizeof(port_info_t));
    if (new_port == NULL) {
	return "Could not allocate a port data structure";
    }

    /* Error from here on out must goto errout. */
    init_port_data(new_port);

    new_port->tcpport = scan_int(portnum);
    if (new_port->tcpport == -1) {
	rv = "port number was invalid";
	goto errout;
    }

    if (strcmp(state, "raw") == 0) {
	new_port->enabled = PORT_RAW;
    } else if (strcmp(state, "telnet") == 0) {
	new_port->enabled = PORT_TELNET;
    } else if (strcmp(state, "off") == 0) {
	new_port->enabled = PORT_DISABLED;
    } else {
	rv = "state was invalid";
	goto errout;
    }

    new_port->timeout = scan_int(timeout);
    if (new_port->timeout == -1) {
	rv = "timeout was invalid";
	goto errout;
    }

    devinit(&(new_port->termctl));

    if (devconfig(devcfg, &(new_port->termctl)) == -1) {
	rv = "device configuration invalid";
	goto errout;
    }

    new_port->devname = malloc(strlen(devname) + 1);
    if (new_port->devname == NULL) {
	rv = "could not allocate device name";
	goto errout;
    }
    strcpy(new_port->devname, devname);

    if (new_port->enabled != PORT_DISABLED) {
	rv = startup_port(new_port);
	if (rv != NULL) {
	    goto errout;
	}
    }

    new_port->next = ports;
    ports = new_port;

    return NULL;

errout:
    free(new_port);
    return rv;
}

/* This is called periodically, it is used to scan for ports that are
   inactive too long and need to be shut down. */
static void
dataxfer_timeout_handler(void)
{
    port_info_t    *port;
    struct timeval curr_time;
    int            time_diff;

    gettimeofday(&curr_time, NULL);
    port = ports;
    while (port != NULL) {
	if ((port->enabled != PORT_DISABLED)
	    && (port->tcp_to_dev_state != PORT_UNCONNECTED)
	    && (port->timeout != 0))
	{
	    /* Calculate how long the port has been inactive. */
	    time_diff = curr_time.tv_sec - port->last_io_time.tv_sec;
	    if (curr_time.tv_usec < port->last_io_time.tv_usec) {
		/* We only count whole seconds, so subtract off a
                   second if we haven't made it all the way there. */
		time_diff--;
	    }

	    if (time_diff > port->timeout) {
		shutdown_port(port);
	    }
	}

	port = port->next;
    }
}

/* Initialize the code in this file. */
void
dataxfer_init(void)
{
    /* Check the ports periodically. */
    add_timeout_handler(dataxfer_timeout_handler);
}

/* Print information about a port to the control port given in cntlr. */
static void
showport(struct controller_info *cntlr, port_info_t *port)
{
    char *str;
    char buffer[128];

    str = "TCP Port ";
    controller_output(cntlr, str, strlen(str));
    sprintf(buffer, "%d", port->tcpport);
    controller_output(cntlr, buffer, strlen(buffer));
    controller_output(cntlr, "\n\r", 2);

    str = "  enable state: ";
    controller_output(cntlr, str, strlen(str));
    str = enabled_str[port->enabled];
    controller_output(cntlr, str, strlen(str));
    controller_output(cntlr, "\n\r", 2);

    str = "  timeout: ";
    controller_output(cntlr, str, strlen(str));
    sprintf(buffer, "%d", port->timeout);
    controller_output(cntlr, buffer, strlen(buffer));
    controller_output(cntlr, "\n\r", 2);

    str = "  connected to (or last connection): ";
    controller_output(cntlr, str, strlen(str));
    inet_ntop(AF_INET, &(port->remote.sin_addr), buffer, sizeof(buffer));
    controller_output(cntlr, buffer, strlen(buffer));
    controller_output(cntlr, ":", 1);
    sprintf(buffer, "%d", ntohs(port->remote.sin_port));
    controller_output(cntlr, buffer, strlen(buffer));
    controller_output(cntlr, "\n\r", 2);

    str = "  device: ";
    controller_output(cntlr, str, strlen(str));
    str = port->devname;
    controller_output(cntlr, str, strlen(str));
    controller_output(cntlr, "\n\r", 2);

    str = "  device config: ";
    controller_output(cntlr, str, strlen(str));
    show_devcfg(cntlr, &(port->termctl));
    controller_output(cntlr, "\n\r", 2);

    str = "  tcp to device state: ";
    controller_output(cntlr, str, strlen(str));
    str = state_str[port->tcp_to_dev_state];
    controller_output(cntlr, str, strlen(str));
    controller_output(cntlr, "\n\r", 2);

    str = "  device to tcp state: ";
    controller_output(cntlr, str, strlen(str));
    str = state_str[port->dev_to_tcp_state];
    controller_output(cntlr, str, strlen(str));
    controller_output(cntlr, "\n\r", 2);
}

/* Find a port data structure given a port number. */
static port_info_t *
find_port_by_num(char *portstr)
{
    port_info_t *port;
    int portnum = scan_int(portstr);


    if (portnum == -1) {
	return NULL;
    }

    port = ports;
    while (port != NULL) {
	if (portnum == port->tcpport) {
	    return port;
	}
	port = port->next;
    }

    return NULL;
}

/* Handle a showport command from the control port. */
void
showports(struct controller_info *cntlr, char *portspec)
{
    port_info_t *port;

    if (portspec == NULL) {
	/* Dump everything. */
	port = ports;
	while (port != NULL) {
	    showport(cntlr, port);
	    port = port->next;
	}
    } else {
	port = find_port_by_num(portspec);
	if (port == NULL) {
	    char *err = "Invalid port number: ";
	    controller_output(cntlr, err, strlen(err));
	    controller_output(cntlr, portspec, strlen(portspec));
	    controller_output(cntlr, "\n\r", 2);
	} else {
	    showport(cntlr, port);	    
	}
    }
}

/* Set the timeout on a port.  The port number and timeout are passed
   in as strings, this code will convert them, return any errors, and
   perform the operation. */
void
setporttimeout(struct controller_info *cntlr, char *portspec, char *timeout)
{
    int timeout_num;
    port_info_t *port;

    port = find_port_by_num(portspec);
    if (port == NULL) {
	char *err = "Invalid port number: ";
	controller_output(cntlr, err, strlen(err));
	controller_output(cntlr, portspec, strlen(portspec));
	controller_output(cntlr, "\n\r", 2);
    } else {
	timeout_num = scan_int(timeout);
	if (timeout_num == -1) {
	    char *err = "Invalid timeout: ";
	    controller_output(cntlr, err, strlen(err));
	    controller_output(cntlr, timeout, strlen(timeout));
	    controller_output(cntlr, "\n\r", 2);
	} else {
	    port->timeout = timeout_num;
	}
    }
}

/* Configure a port.  The port number and configuration are passed in
   as strings, this code will get the port and then call the code to
   configure the device. */
void
setportdevcfg(struct controller_info *cntlr, char *portspec, char *devcfg)
{
    port_info_t *port;

    port = find_port_by_num(portspec);
    if (port == NULL) {
	char *err = "Invalid port number: ";
	controller_output(cntlr, err, strlen(err));
	controller_output(cntlr, portspec, strlen(portspec));
	controller_output(cntlr, "\n\r", 2);
    } else {
	if (devconfig(devcfg, &(port->termctl)) == -1) {
	    char *err = "Invalid device config\n\r";
	    controller_output(cntlr, err, strlen(err));
	}
    }
}

/* Set the enable state of a port. */
void
setportenable(struct controller_info *cntlr, char *portspec, char *enable)
{
    port_info_t *port;

    port = find_port_by_num(portspec);
    if (port == NULL) {
	char *err = "Invalid port number: ";
	controller_output(cntlr, err, strlen(err));
	controller_output(cntlr, portspec, strlen(portspec));
	controller_output(cntlr, "\n\r", 2);
    } else {
	if (strcmp(enable, "off") == 0) {
	    if (port->enabled != PORT_DISABLED) {
		if (port->tcp_to_dev_state != PORT_UNCONNECTED) {
		    shutdown_port(port);
		}
		clear_fd_handlers(port->acceptfd);
		port->enabled = PORT_DISABLED;
		close(port->acceptfd);
	    }
	} else {
	    int newenable;
	    if (strcmp(enable, "raw") == 0) {
		newenable = PORT_RAW;
	    } else if (strcmp(enable, "telnet") == 0) {
		newenable = PORT_TELNET;
	    } else {
		char *err = "Invalid enable: ";
		controller_output(cntlr, err, strlen(err));
		controller_output(cntlr, enable, strlen(enable));
		controller_output(cntlr, "\n\r", 2);
		return;
	    }

	    if (port->enabled == PORT_DISABLED) {
		char *err = startup_port(port);
		if (err != NULL) {
		    controller_output(cntlr, err, strlen(err));
		    controller_output(cntlr, "\n\r", 2);
		    return;
		}
	    }
	    port->enabled = newenable;
	}
    }
}

/* Start data monitoring on the given port, type may be either "tcp" or
   "term" and only one direction may be monitored.  This return NULL if
   the monitor fails.  The monitor output will go to "fd". */
void *
data_monitor_start(struct controller_info *cntlr,
		   char                   *type,
		   char                   *portspec)
{
    port_info_t *port;

    port = find_port_by_num(portspec);
    if (port == NULL) {
	char *err = "Invalid port number: ";
	controller_output(cntlr, err, strlen(err));
	controller_output(cntlr, portspec, strlen(portspec));
	controller_output(cntlr, "\n\r", 2);
	return NULL;
    }

    if ((port->tcp_monitor != NULL) || (port->dev_monitor != NULL)) {
	char *err = "Port is already being monitored";
	controller_output(cntlr, err, strlen(err));
	controller_output(cntlr, "\n\r", 2);
	return NULL;
    }

    if (strcmp(type, "tcp") == 0) {
	port->tcp_monitor = cntlr;
	return port;
    } else if (strcmp(type, "term") == 0) {
	port->dev_monitor = cntlr;
	return port;
    } else {
	char *err = "invalid monitor type: ";
	controller_output(cntlr, err, strlen(err));
	controller_output(cntlr, type, strlen(type));
	controller_output(cntlr, "\n\r", 2);
	return NULL;
    }
}

/* Stop monitoring the given id. */
void
data_monitor_stop(struct controller_info *cntlr,
		  void                   *monitor_id)
{
    port_info_t *port = (port_info_t *) monitor_id;

    port->tcp_monitor = NULL;
    port->dev_monitor = NULL;
}

void
disconnect_port(struct controller_info *cntlr,
		char *portspec)
{
    port_info_t *port;

    port = find_port_by_num(portspec);
    if (port == NULL) {
	char *err = "Invalid port number: ";
	controller_output(cntlr, err, strlen(err));
	controller_output(cntlr, portspec, strlen(portspec));
	controller_output(cntlr, "\n\r", 2);
	return;
    }

    shutdown_port(port);
}
