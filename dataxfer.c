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
#include <sys/stat.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>

#include "dataxfer.h"
#include "selector.h"
#include "devcfg.h"
#include "utils.h"

/** BASED ON sshd.c FROM openssh.com */
#ifdef HAVE_TCPD_H
#include <tcpd.h>
static char *progname = "ser2net";
#endif /* HAVE_TCPD_H */

#ifdef USE_UUCP_LOCKING
static char *uucp_lck_dir = "/var/lock";
#ifndef HAVE_TCPD_H
static char *progname = "ser2net";
#endif
#endif /* USE_UUCP_LOCKING */


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
#define PORT_RAWLP		2 /* Port will not do telnet negotiation and
                                     termios setting, open for output only. */
#define PORT_TELNET		3 /* Port will do telnet negotiation. */
char *enabled_str[] = { "off", "raw", "rawlp", "telnet" };

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
					   PORT_RAWLP, the port is enabled
					   only for output without any
					   termios setting - it allows
					   to redirect /dev/lpX devices If
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
    char               *portname;       /* The name given for the port. */
    struct sockaddr_in tcpport;		/* The TCP port to listen on
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
    unsigned int tcp_bytes_received;    /* Number of bytes read from the
					   TCP port. */
    unsigned int tcp_bytes_sent;        /* Number of bytes written to the
					   TCP port. */

    /* Information about the terminal device. */
    char           *devname;		/* The full path to the device */
    int            devfd;		/* The file descriptor for the
                                           device, only valid if the
                                           TCP port is open. */
    struct termios termctl;		/* The termios information to
					   set for the device. */
    unsigned int dev_bytes_received;    /* Number of bytes read from the
					   device. */
    unsigned int dev_bytes_sent;        /* Number of bytes written to the
					   device. */


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


    unsigned char  telnet_cmd[3];	/* Incoming telnet commands. */
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

    int config_num; /* Keep track of what configuration this was last
		       updated under.  Setting to -1 means to delete
		       the port when the current session is done. */

    struct port_info *new_config; /* If the port is reconfigged while
				     open, this will hold the new
				     configuration that should be
				     loaded when the current session
				     is done. */
} port_info_t;

port_info_t *ports = NULL; /* Linked list of ports. */

static unsigned char telnet_init[] = {
    0xff, 0xfb, 0x03,  /* command WILL SUPPRESS GO AHEAD */
    0xff, 0xfb, 0x01,  /* command WILL ECHO */
    0xff, 0xfe, 0x01,  /* command DON'T ECHO */
    0xff, 0xfd, 0x00   /* command DO BINARY TRANSMISSION */
};

static void shutdown_port(port_info_t *port);

#ifdef USE_UUCP_LOCKING
static int
uucp_fname_lock_size(char *devname)
{
    char *ptr;

    (ptr = strrchr(devname, '/'));
    if (ptr == NULL) {
	ptr = devname;
    } else {
	ptr = ptr + 1;
    }

    return 7 + strlen(uucp_lck_dir) + strlen(ptr);
}

static void
uucp_fname_lock(char *buf, char *devname)
{
    char *ptr;

    (ptr = strrchr(devname, '/'));
    if (ptr == NULL) {
	ptr = devname;
    } else {
	ptr = ptr + 1;
    }
    sprintf(buf, "%s/LCK..%s", uucp_lck_dir, ptr);
}

static void
uucp_rm_lock(char *devname)
{
    char *lck_file;

    if (!uucp_locking_enabled) return;

    lck_file = malloc(uucp_fname_lock_size(devname));
    if (lck_file == NULL) {
	return;
    }
    uucp_fname_lock(lck_file, devname);
    unlink(lck_file);
    free(lck_file);
}

/* return 0=OK, -1=error, 1=locked by other proces */
static int
uucp_mk_lock(char *devname)
{
    struct stat stt;
    int pid=-1;

    if (!uucp_locking_enabled) return 0;

    if( stat(uucp_lck_dir, &stt) == 0 ) { /* is lock file directory present? */
	char *lck_file, buf[64];
	int fd;

	lck_file = malloc(uucp_fname_lock_size(devname));
	if (lck_file == NULL) {
	    return -1;
	}
	uucp_fname_lock(lck_file, devname);

	pid = 0;
	if( (fd = open(lck_file, O_RDONLY)) >= 0 ) {
	    int n;

    	    n = read(fd, buf, sizeof(buf));
	    close(fd);
	    if( n == 4 ) 		/* Kermit-style lockfile. */
		pid = *(int *)buf;
	    else if( n > 0 ) {		/* Ascii lockfile. */
		buf[n] = 0;
		sscanf(buf, "%d", &pid);
	    }

	    if( pid > 0 && kill((pid_t)pid, 0) < 0 && errno == ESRCH ) {
		/* death lockfile - remove it */
		unlink(lck_file);
		sleep(1);
		pid = 0;
	    } else
		pid = 1;

	}

	if( pid == 0 ) {
	    int mask;

	    mask = umask(022);
	    fd = open(lck_file, O_WRONLY | O_CREAT | O_EXCL, 0666);
	    umask(mask);
	    if( fd >= 0 ) {
		snprintf( buf, sizeof(buf), "%10ld\t%s\n",
					     (long)getpid(), progname );
		write( fd, buf, strlen(buf) );
		close(fd);
	    } else {
		pid = 1;
	    }
	}

	free(lck_file);
    }

    return pid;
}
#endif /* USE_UUCP_LOCKING */

static void
init_port_data(port_info_t *port)
{
    port->enabled = PORT_DISABLED;
    port->portname = NULL;
    memset(&(port->tcpport), 0, sizeof(port->tcpport));
    port->acceptfd = -1;
    port->tcpfd = -1;
    port->timeout = 0;
    port->next = NULL;
    port->new_config = NULL;
    port->tcp_monitor = NULL;
    
    port->devname = NULL;
    port->devfd = 0;
    memset(&(port->remote), 0, sizeof(port->remote));
    memset(&(port->termctl), 0, sizeof(port->termctl));
    memset(&(port->last_io_time), 0, sizeof(port->last_io_time));
    port->tcp_to_dev_state = PORT_UNCONNECTED;
    port->tcp_to_dev_buf_start = 0;
    port->tcp_to_dev_buf_count = 0;
    port->tcp_bytes_received = 0;
    port->tcp_bytes_sent = 0;
    port->dev_to_tcp_state = PORT_UNCONNECTED;
    port->dev_to_tcp_buf_start = 0;
    port->dev_to_tcp_buf_count = 0;
    port->dev_bytes_received = 0;
    port->dev_bytes_sent = 0;
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
	syslog(LOG_ERR, "dev read error for port %s: %m", port->portname);
	shutdown_port(port);
	return;
    } else if (port->dev_to_tcp_buf_count == 0) {
	/* The port got closed somehow, shut it down. */
	shutdown_port(port);
	return;
    }

    port->dev_bytes_received += port->dev_to_tcp_buf_count;
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
	    syslog(LOG_ERR, "The tcp write for port %s had error: %m",
		   port->portname);
	    shutdown_port(port);
	}
    } else {
	port->tcp_bytes_sent += write_count;
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
	    syslog(LOG_ERR, "The dev write for port %s had error: %m",
		   port->portname);
	    shutdown_port(port);
	}
    } else {
	port->dev_bytes_sent += write_count;
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

    syslog(LOG_ERR, "Select exception on device for port %s",
	   port->portname);
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

    if (port->tcp_to_dev_buf_count < 0) {
	/* Got an error on the read, shut down the port. */
	syslog(LOG_ERR, "read error for port %s: %m", port->portname);
	shutdown_port(port);
	return;
    } else if (port->tcp_to_dev_buf_count == 0) {
	/* The other end closed the port, shut it down. */
	shutdown_port(port);
	return;
    }

    port->tcp_bytes_received += port->tcp_to_dev_buf_count;

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
	    syslog(LOG_ERR, "The dev write for port %s had error: %m",
		   port->portname);
	    shutdown_port(port);
	}
    } else {
	port->dev_bytes_sent += write_count;
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
	    syslog(LOG_ERR, "The tcp write for port %s had error: %m",
		   port->portname);
	    shutdown_port(port);
	}
    } else {
	port->tcp_bytes_sent += write_count;
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

    syslog(LOG_ERR, "Select exception on port %s", port->portname);
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
    int options;

    if (port->tcp_to_dev_state != PORT_UNCONNECTED) {
	err = "Port already in use\n\r";
    } else if (is_device_already_inuse(port)) {
	err = "Port's device already in use\n\r";
    }

    if (err != NULL) {
	struct sockaddr_in dummy_sockaddr;
	socklen_t len = sizeof(dummy_sockaddr);
	int new_fd = accept(fd, (struct sockaddr *) &dummy_sockaddr, &len);

	if (new_fd != -1) {
	    write(new_fd, err, strlen(err));
	    close(new_fd);
	}
	return;
    }

    len = sizeof(port->remote);

    port->tcpfd = accept(fd, (struct sockaddr *) &(port->remote), &len);
    if (port->tcpfd == -1) {
	syslog(LOG_ERR, "Could not accept on port %s: %m", port->portname);
	return;
    }

    if (fcntl(port->tcpfd, F_SETFL, O_NONBLOCK) == -1) {
	close(port->tcpfd);
	syslog(LOG_ERR, "Could not fcntl the tcp port %s: %m", port->portname);
	return;
    }

#ifdef HAVE_TCPD_H
    {
	struct request_info req;
	
	request_init(&req, RQ_DAEMON, progname, RQ_FILE, port->tcpfd, NULL);
	fromhost(&req);

	if (!hosts_access(&req)) {
	    char *err = "Access denied\n\r";
	    write(port->tcpfd, err, strlen(err));
	    close(port->tcpfd);
	    return;
	}
    }
#endif /* HAVE_TCPD_H */

#ifdef USE_UUCP_LOCKING
    {
	int rv;

	rv = uucp_mk_lock(port->devname);
	if (rv > 0 ) {
	    char *err;
	    char buf[64];

	    err = "Port already in use by another process\n\r";
	    write(port->tcpfd, err, strlen(err));
	    close(port->tcpfd);
	    return;
	} else if (rv < 0) {
	    char *err;

	    err = "Error creating port lock file\n\r";
	    write(port->tcpfd, err, strlen(err));
	    close(port->tcpfd);
	    return;
	}
    }
#endif /* USE_UUCP_LOCKING */

    /* Oct 05 2001 druzus: NOCTTY - don't make 
       device control tty for our process */
    options = O_NONBLOCK | O_NOCTTY;
    if (port->enabled == PORT_RAWLP) {
	options |= O_WRONLY;
    } else {
	options |= O_RDWR;
    }
    port->devfd = open(port->devname, options);
    if (port->devfd == -1) {
	close(port->tcpfd);
	syslog(LOG_ERR, "Could not open device %s for port %s: %m",
	       port->devname,
	       port->portname);
	return;
    }

    if (port->enabled != PORT_RAWLP &&
              tcsetattr(port->devfd, TCSANOW, &(port->termctl)) == -1) {
	close(port->tcpfd);
	close(port->devfd);
	syslog(LOG_ERR, "Could not set up device %s for port %s: %m",
	       port->devname,
	       port->portname);
	return;
    }

    set_fd_handlers(port->devfd,
		    port,
		    port->enabled == PORT_RAWLP ? NULL : handle_dev_fd_read,
		    handle_dev_fd_write,
		    handle_dev_fd_except);
    set_fd_read_handler(port->devfd, port->enabled == PORT_RAWLP ? 
				     FD_HANDLER_DISABLED : FD_HANDLER_ENABLED);
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
    int optval = 1;
    
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

    if (bind(port->acceptfd,
	     (struct sockaddr *) &port->tcpport,
	     sizeof(port->tcpport)) == -1) {
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

char *
change_port_state(port_info_t *port, int state)
{
    char *rv = NULL;

    if (port->enabled == state) {
	return;
    }

    if (state == PORT_DISABLED) {
	set_fd_read_handler(port->acceptfd, FD_HANDLER_DISABLED);
	clear_fd_handlers(port->acceptfd);
	close(port->acceptfd);
	port->acceptfd = -1;
    } else if (port->enabled == PORT_DISABLED) {
	rv = startup_port(port);
    }

    port->enabled = state;

    return rv;
}

static void
free_port(port_info_t *port)
{
    change_port_state(port, PORT_DISABLED);
    if (port->portname != NULL) {
	free(port->portname);
    }
    if (port->devname != NULL) {
	free(port->devname);
    }
    if (port->new_config != NULL) {
	free_port(port->new_config);
    }
    free(port);
}

static void
shutdown_port(port_info_t *port)
{
    clear_fd_handlers(port->devfd);
    clear_fd_handlers(port->tcpfd);
    close(port->tcpfd);
    close(port->devfd);
#ifdef USE_UUCP_LOCKING
    uucp_rm_lock(port->devname);
#endif /* USE_UUCP_LOCKING */
    port->tcp_to_dev_state = PORT_UNCONNECTED;
    port->tcp_to_dev_buf_start = 0;
    port->tcp_to_dev_buf_count = 0;
    port->tcp_bytes_received = 0;
    port->tcp_bytes_sent = 0;
    port->dev_to_tcp_state = PORT_UNCONNECTED;
    port->dev_to_tcp_buf_start = 0;
    port->dev_to_tcp_buf_count = 0;
    port->dev_bytes_received = 0;
    port->dev_bytes_sent = 0;
    port->telnet_cmd_pos = 0;

    /* If the port has been disabled, then delete it.  Check this before
       the new config so the port will be deleted properly and not
       reconfigured on a reconfig. */
    if (port->config_num == -1) {
	port_info_t *curr, *prev;

	prev = NULL;
	curr = ports;
	while ((curr != NULL) && (curr != port)) {
	    prev = curr;
	    curr = curr->next;
	}
	if (curr != NULL) {
	    if (prev == NULL) {
		ports = curr->next;
	    } else {
		prev->next = curr->next;
	    }
	    free_port(curr);
	}

	return; /* We have to return here because we no longer have a port. */
    }

    if (port->new_config != NULL) {
	port_info_t *curr, *prev;

	prev = NULL;
	curr = ports;
	while ((curr != NULL) && (curr != port)) {
	    prev = curr;
	    curr = curr->next;
	}
	if (curr != NULL) {
	    port = curr->new_config;
	    port->acceptfd = curr->acceptfd;
	    set_fd_handlers(port->acceptfd,
			    port,
			    handle_accept_port_read,
			    NULL,
			    NULL);
	    curr->acceptfd = -1;
	    port->next = curr->next;
	    if (prev == NULL) {
		ports = port;
	    } else {
		prev->next = port;
	    }
	    curr->enabled = PORT_DISABLED;
	    curr->new_config = NULL;
	    free_port(curr);
	}
    }
}

/* Create a port based on a set of parameters passed in. */
char *
portconfig(char *portnum,
	   char *state,
	   char *timeout,
	   char *devname,
	   char *devcfg,
	   int  config_num)
{
    port_info_t *new_port, *curr, *prev;
    char        *rv = NULL;

    new_port = malloc(sizeof(port_info_t));
    if (new_port == NULL) {
	return "Could not allocate a port data structure";
    }

    /* Error from here on out must goto errout. */
    init_port_data(new_port);

    new_port->portname = malloc(strlen(portnum)+1);
    if (new_port->portname == NULL) {
	rv = "unable to allocate port name";
	goto errout;
    }
    strcpy(new_port->portname, portnum);

    if (scan_tcp_port(portnum, &(new_port->tcpport)) == -1) {
	rv = "port number was invalid";
	goto errout;
    }

    if (strcmp(state, "raw") == 0) {
	new_port->enabled = PORT_RAW;
    } else if (strcmp(state, "rawlp") == 0) {
	new_port->enabled = PORT_RAWLP;
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

    new_port->config_num = config_num;

    /* See if the port already exists, and reconfigure it if so. */
    curr = ports;
    prev = NULL;
    while (curr != NULL) {
	if (strcmp(curr->portname, new_port->portname) == 0) {
	    /* We are reconfiguring this port. */
	    if (curr->dev_to_tcp_state == PORT_UNCONNECTED) {
		/* Port is disconnected, just remove it. */
		int new_state = new_port->enabled;

		new_port->enabled = curr->enabled;
		new_port->acceptfd = curr->acceptfd;
		curr->enabled = PORT_DISABLED;
		curr->acceptfd = -1;
		set_fd_handlers(new_port->acceptfd,
				new_port,
				handle_accept_port_read,
				NULL,
				NULL);

		/* Just replace with the new data. */
		if (prev == NULL) {
		    ports = new_port;
		} else {
		    prev->next = new_port;
		}
		new_port->next = curr->next;
		free_port(curr);

		change_port_state(new_port, new_state);
	    } else {
		/* Mark it to be replaced later. */
		if (curr->new_config != NULL) {
		    curr->enabled = PORT_DISABLED;
		    free(curr->new_config);
		}
		curr->config_num = config_num;
		curr->new_config = new_port;
	    }
	    return rv;
	} else {
	    prev = curr;
	    curr = curr->next;
	}
    }

    /* If we get here, the port is brand new, so don't do anything that
       would affect a port replacement here. */

    if (new_port->enabled != PORT_DISABLED) {
	rv = startup_port(new_port);
	if (rv != NULL) {
	    goto errout;
	}
    }

    /* Tack it on to the end of the list of ports. */
    new_port->next = NULL;
    if (ports == NULL) {
	ports = new_port;
    } else {
	curr = ports;
	while (curr->next != NULL) {
	    curr = curr->next;
	}
	curr->next = new_port;
    }

    return rv;

errout:
    free_port(new_port);
    return rv;
}

int
clear_old_port_config(int curr_config)
{
    port_info_t *curr, *prev;

    curr = ports;
    prev = NULL;
    while (curr != NULL) {
	if (curr->config_num != curr_config) {
	    /* The port was removed, remove it. */
	    if (curr->dev_to_tcp_state == PORT_UNCONNECTED) {
		if (prev == NULL) {
		    ports = curr->next;
		    free_port(curr);
		    curr = ports;
		} else {
		    prev->next = curr->next;
		    free_port(curr);
		    curr = prev->next;
		}
	    } else {
		curr->config_num = -1;
		prev = curr;
		curr = curr->next;
	    }
	} else {
	    prev = curr;
	    curr = curr->next;
	}
    }
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
showshortport(struct controller_info *cntlr, port_info_t *port)
{
    char buffer[128];
    int  count;
    int  need_space = 0;

    snprintf(buffer, 23, "%-22s", port->portname);
    controller_output(cntlr, buffer, strlen(buffer));

    sprintf(buffer, " %-6s ", enabled_str[port->enabled]);
    controller_output(cntlr, buffer, strlen(buffer));

    sprintf(buffer, "%7d ", port->timeout);
    controller_output(cntlr, buffer, strlen(buffer));

    inet_ntop(AF_INET, &(port->remote.sin_addr), buffer, sizeof(buffer));
    count = strlen(buffer);
    controller_output(cntlr, buffer, count);
    sprintf(buffer, ",%d ", ntohs(port->remote.sin_port));
    count += strlen(buffer);
    controller_output(cntlr, buffer, strlen(buffer));
    while (count < 23) {
	controller_output(cntlr, " ", 1);
	count++;
    }

    snprintf(buffer, 23, "%-22s", port->devname);
    controller_output(cntlr, buffer, strlen(buffer));

    sprintf(buffer, " %-14s ", state_str[port->tcp_to_dev_state]);
    controller_output(cntlr, buffer, strlen(buffer));

    sprintf(buffer, "%-14s ", state_str[port->dev_to_tcp_state]);
    controller_output(cntlr, buffer, strlen(buffer));

    sprintf(buffer, "%9d ", port->tcp_bytes_received);
    controller_output(cntlr, buffer, strlen(buffer));

    sprintf(buffer, "%9d ", port->tcp_bytes_sent);
    controller_output(cntlr, buffer, strlen(buffer));

    sprintf(buffer, "%9d ", port->dev_bytes_received);
    controller_output(cntlr, buffer, strlen(buffer));

    sprintf(buffer, "%9d ", port->dev_bytes_sent);
    controller_output(cntlr, buffer, strlen(buffer));


    if (port->enabled != PORT_RAWLP) {
	show_devcfg(cntlr, &(port->termctl));
	need_space = 1;
    }

    if (port->tcp_to_dev_state != PORT_UNCONNECTED) {
	if (need_space) {
	    controller_output(cntlr, " ", 1);
	}
	    
	show_devcontrol(cntlr, port->devfd);
    }
    controller_output(cntlr, "\n\r", 2);

}

/* Print information about a port to the control port given in cntlr. */
static void
showport(struct controller_info *cntlr, port_info_t *port)
{
    char *str;
    char buffer[128];

    str = "TCP Port ";
    controller_output(cntlr, str, strlen(str));
    sprintf(buffer, "%s", port->portname);
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
    if (port->enabled == PORT_RAWLP) {
	str = "none\n\r";
	controller_output(cntlr, str, strlen(str));
    } else {
	show_devcfg(cntlr, &(port->termctl));
	controller_output(cntlr, "\n\r", 2);
    }

    str = "  device controls: ";
    controller_output(cntlr, str, strlen(str));
    if (port->tcp_to_dev_state == PORT_UNCONNECTED) {
	str = "not currently connected\n\r";
	controller_output(cntlr, str, strlen(str));
    } else {
	show_devcontrol(cntlr, port->devfd);
	controller_output(cntlr, "\n\r", 2);
    }

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

    str = "  bytes read from TCP: ";
    controller_output(cntlr, str, strlen(str));
    sprintf(buffer, "%d", port->tcp_bytes_received);
    controller_output(cntlr, buffer, strlen(buffer));
    controller_output(cntlr, "\n\r", 2);

    str = "  bytes written to TCP: ";
    controller_output(cntlr, str, strlen(str));
    sprintf(buffer, "%d", port->tcp_bytes_sent);
    controller_output(cntlr, buffer, strlen(buffer));
    controller_output(cntlr, "\n\r", 2);

    str = "  bytes read from device: ";
    controller_output(cntlr, str, strlen(str));
    sprintf(buffer, "%d", port->dev_bytes_received);
    controller_output(cntlr, buffer, strlen(buffer));
    controller_output(cntlr, "\n\r", 2);

    str = "  bytes written to device: ";
    controller_output(cntlr, str, strlen(str));
    sprintf(buffer, "%d", port->dev_bytes_sent);
    controller_output(cntlr, buffer, strlen(buffer));
    controller_output(cntlr, "\n\r", 2);

    if (port->config_num == -1) {
	str = "  Port will be deleted when current session closes.\n\r";
	controller_output(cntlr, str, strlen(str));
    } else if (port->new_config != NULL) {
	str = "  Port will be reconfigured when current session closes.\n\r";
	controller_output(cntlr, str, strlen(str));
    }
}

/* Find a port data structure given a port number. */
static port_info_t *
find_port_by_num(char *portstr)
{
    port_info_t *port;

    port = ports;
    while (port != NULL) {
	if (strcmp(portstr, port->portname) == 0) {
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

/* Handle a showport command from the control port. */
void
showshortports(struct controller_info *cntlr, char *portspec)
{
    port_info_t *port;
    char        buffer[512];

    sprintf(buffer,
	    "%-22s %-6s %7s %-22s %-22s %-14s %-14s %9s %9s %9s %9s %s\n\r",
	    "Port name",
	    "Type",
	    "Timeout",
	    "Remote address",
	    "Device",
	    "TCP to device",
	    "Device to TCP",
	    "TCP in",
	    "TCP out",
	    "Dev in",
	    "Dev out",
	    "State");
    controller_output(cntlr, buffer, strlen(buffer));
    if (portspec == NULL) {
	/* Dump everything. */
	port = ports;
	while (port != NULL) {
	    showshortport(cntlr, port);
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
	    showshortport(cntlr, port);	    
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

/* Modify the controls of a port.  The port number and configuration
   are passed in as strings, this code will get the port and then call
   the code to control the device. */
void
setportcontrol(struct controller_info *cntlr, char *portspec, char *controls)
{
    port_info_t *port;

    port = find_port_by_num(portspec);
    if (port == NULL) {
	char *err = "Invalid port number: ";
	controller_output(cntlr, err, strlen(err));
	controller_output(cntlr, portspec, strlen(portspec));
	controller_output(cntlr, "\n\r", 2);
    } else if (port->tcp_to_dev_state == PORT_UNCONNECTED) {
	char *err = "Port is not currently connected: ";
	controller_output(cntlr, err, strlen(err));
	controller_output(cntlr, portspec, strlen(portspec));
	controller_output(cntlr, "\n\r", 2);
    } else {
	if (setdevcontrol(controls, port->devfd) == -1) {
	    char *err = "Invalid device controls\n\r";
	    controller_output(cntlr, err, strlen(err));
	}
    }
}

/* Set the enable state of a port. */
void
setportenable(struct controller_info *cntlr, char *portspec, char *enable)
{
    port_info_t *port;
    int         new_enable;
    char        *err;

    port = find_port_by_num(portspec);
    if (port == NULL) {
	err = "Invalid port number: ";
	controller_output(cntlr, err, strlen(err));
	controller_output(cntlr, portspec, strlen(portspec));
	controller_output(cntlr, "\n\r", 2);
	return;
    }

    if (strcmp(enable, "off") == 0) {
	new_enable = PORT_DISABLED;
    } else if (strcmp(enable, "raw") == 0) {
	new_enable = PORT_RAW;
    } else if (strcmp(enable, "rawlp") == 0) {
	new_enable = PORT_RAWLP;
    } else if (strcmp(enable, "telnet") == 0) {
	new_enable = PORT_TELNET;
    } else {
	err = "Invalid enable: ";
	controller_output(cntlr, err, strlen(err));
	controller_output(cntlr, enable, strlen(enable));
	controller_output(cntlr, "\n\r", 2);
	return;
    }

    err = change_port_state(port, new_enable);
    if (err != NULL) {
	controller_output(cntlr, err, strlen(err));
	controller_output(cntlr, "\n\r", 2);
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
