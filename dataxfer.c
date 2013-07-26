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
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <time.h>

#include "dataxfer.h"
#include "selector.h"
#include "devcfg.h"
#include "utils.h"
#include "telnet.h"

extern selector_t *ser2net_sel;

#define SERIAL "term"
#define NET    "tcp "

/** BASED ON sshd.c FROM openssh.com */
#ifdef HAVE_TCPD_H
#include <tcpd.h>
static char *progname = "ser2net";
#endif /* HAVE_TCPD_H */

#ifdef USE_UUCP_LOCKING
static char *uucp_lck_dir = "/var/lock";
#endif /* USE_UUCP_LOCKING */


/* States for the tcp_to_dev_state and dev_to_tcp_state. */
#define PORT_UNCONNECTED		0 /* The TCP port is not connected
                                             to anything right now. */
#define PORT_WAITING_INPUT		1 /* Waiting for input from the
					     input side. */
#define PORT_WAITING_OUTPUT_CLEAR	2 /* Waiting for output to clear
					     so I can send data. */
#define PORT_CLOSING			3 /* Waiting for output close
					     string to be sent. */
char *state_str[] = { "unconnected", "waiting input", "waiting output",
		      "closing" };

#define PORT_DISABLED		0 /* The port is not open. */
#define PORT_RAW		1 /* Port will not do telnet negotiation. */
#define PORT_RAWLP		2 /* Port will not do telnet negotiation and
                                     termios setting, open for output only. */
#define PORT_TELNET		3 /* Port will do telnet negotiation. */
char *enabled_str[] = { "off", "raw", "rawlp", "telnet" };

#define PORT_BUFSIZE	64

typedef struct trace_s
{
    int            hexdump;     /* output each block as a hexdump */
    int            timestamp;   /* preceed each line with a timestamp */
    int            file;        /* open file.  -1 if not used */
} trace_t;

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

    int            timeout_left;	/* The amount of time left (in
					   seconds) before the timeout
					   goes off. */

    sel_timer_t *timer;			/* Used to timeout when the no
					   I/O has been seen for a
					   certain period of time. */


    /* Information about the TCP port. */
    char               *portname;       /* The name given for the port. */
    struct sockaddr_storage tcpport;	/* The TCP port to listen on
					   for connections to this
					   terminal device. */
    socklen_t      tcpport_len;         /* Length of above */
    int            acceptfd;		/* The file descriptor used to
					   accept connections on the
					   TCP port. */
    int            tcpfd;		/* When connected, the file
                                           descriptor for the TCP
                                           port used for I/O. */
    struct sockaddr_storage remote;	/* The socket address of who
					   is connected to this port. */
    unsigned int tcp_bytes_received;    /* Number of bytes read from the
					   TCP port. */
    unsigned int tcp_bytes_sent;        /* Number of bytes written to the
					   TCP port. */
    struct sbuf *banner;		/* Outgoing banner */

    /* Information about the terminal device. */
    char           *devname;		/* The full path to the device */
    int            devfd;		/* The file descriptor for the
                                           device, only valid if the
                                           TCP port is open. */
    unsigned int dev_bytes_received;    /* Number of bytes read from the
					   device. */
    unsigned int dev_bytes_sent;        /* Number of bytes written to the
					   device. */


    /* Information use when transferring information from the TCP port
       to the terminal device. */
    int            tcp_to_dev_state;		/* State of transferring
						   data from the TCP port
                                                   to the device. */
    struct sbuf    tcp_to_dev;			/* Buffer struct for
						   TCP to device
						   transfers. */
    unsigned char  tcp_to_devbuf[PORT_BUFSIZE]; /* Buffer used for
						   TCP to device
						   transfers. */
    struct controller_info *tcp_monitor; /* If non-null, send any input
					    received from the TCP port
					    to this controller port. */
    struct sbuf *devstr;		 /* Outgoing string */

    char *closestr;			/* Since the close string is
					   processed at shutdown, the
					   conf may have been redone and
					   the data freed.  So keep a
					   copy here. */

    /* Information use when transferring information from the terminal
       device to the TCP port. */
    int            dev_to_tcp_state;		/* State of transferring
						   data from the device to
                                                   the TCP port. */
    struct sbuf    dev_to_tcp;			/* Buffer struct for
						   device to TCP
						   transfers. */
    unsigned char  dev_to_tcpbuf[PORT_BUFSIZE]; /* Buffer used for
						   device to TCP
						   transfers. */
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

    /* Data for the telnet processing */
    telnet_data_t tn_data;

    /* Is RFC 2217 mode enabled? */
    int is_2217;

    /* Holds whether break is on or not. */
    int break_set;

    /* Masks for RFC 2217 */
    unsigned char linestate_mask;
    unsigned char modemstate_mask;
    unsigned char last_modemstate;

    /* Read and write trace information */
    trace_t wt;
    trace_t rt;
    trace_t bt;

    dev_info_t dinfo; /* device configuration information */
} port_info_t;

port_info_t *ports = NULL; /* Linked list of ports. */

static void shutdown_port(port_info_t *port, char *reason);
static void finish_shutdown_port(port_info_t *port);

/* The init sequence we use. */
static unsigned char telnet_init_seq[] = {
    TN_IAC, TN_WILL, TN_OPT_SUPPRESS_GO_AHEAD,
    TN_IAC, TN_WILL, TN_OPT_ECHO,
    TN_IAC, TN_DONT, TN_OPT_ECHO,
    TN_IAC, TN_DO,   TN_OPT_BINARY_TRANSMISSION,
};

/* Our telnet command table. */
static void com_port_handler(void *cb_data, unsigned char *option, int len);
static int com_port_will(void *cb_data);

static struct telnet_cmd telnet_cmds[] = 
{
    /*                        I will,  I do,  sent will, sent do */
    { TN_OPT_SUPPRESS_GO_AHEAD,	   0,     1,          1,       0, },
    { TN_OPT_ECHO,		   0,     1,          1,       1, },
    { TN_OPT_BINARY_TRANSMISSION,  1,     1,          0,       1, },
    { TN_OPT_COM_PORT,		   1,     0,          0,       0, 0, 0,
      com_port_handler, com_port_will },
    { 255 }
};


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
    int pid = -1;

    if (!uucp_locking_enabled)
	return 0;

    if (stat(uucp_lck_dir, &stt) == 0) { /* is lock file directory present? */
	char *lck_file;
	union {
	    uint32_t ival;
	    char     str[64];
	} buf;
	int fd;

	lck_file = malloc(uucp_fname_lock_size(devname));
	if (lck_file == NULL)
	    return -1;

	uucp_fname_lock(lck_file, devname);

	pid = 0;
	if ((fd = open(lck_file, O_RDONLY)) >= 0) {
	    int n;

    	    n = read(fd, &buf, sizeof(buf));
	    close(fd);
	    if( n == 4 ) 		/* Kermit-style lockfile. */
		pid = buf.ival;
	    else if (n > 0) {		/* Ascii lockfile. */
		buf.str[n] = 0;
		sscanf(buf.str, "%d", &pid);
	    }

	    if (pid > 0 && kill((pid_t)pid, 0) < 0 && errno == ESRCH) {
		/* death lockfile - remove it */
		unlink(lck_file);
		sleep(1);
		pid = 0;
	    } else
		pid = 1;

	}

	if (pid == 0) {
	    int mask;
	    size_t rv;

	    mask = umask(022);
	    fd = open(lck_file, O_WRONLY | O_CREAT | O_EXCL, 0666);
	    umask(mask);
	    if (fd >= 0) {
		snprintf(buf.str, sizeof(buf), "%10ld\n",
			 (long)getpid());
		rv = write_full(fd, buf.str, strlen(buf.str));
		close(fd);
		if (rv < 0) {
		    pid = -1;
		    unlink(lck_file);
		}
	    } else {
		pid = -1;
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
    port->tcpport_len = 0;
    port->acceptfd = -1;
    port->tcpfd = -1;
    port->timeout = 0;
    port->next = NULL;
    port->new_config = NULL;
    port->tcp_monitor = NULL;
    
    port->devname = NULL;
    port->devfd = -1;
    memset(&(port->remote), 0, sizeof(port->remote));
    memset(&(port->dinfo.termctl), 0, sizeof(port->dinfo.termctl));
    port->tcp_to_dev_state = PORT_UNCONNECTED;
    buffer_init(&port->tcp_to_dev, port->tcp_to_devbuf,
		sizeof(port->tcp_to_devbuf));
    port->tcp_bytes_received = 0;
    port->tcp_bytes_sent = 0;
    port->banner = NULL;
    port->dev_to_tcp_state = PORT_UNCONNECTED;
    buffer_init(&port->dev_to_tcp, port->dev_to_tcpbuf,
		sizeof(port->dev_to_tcpbuf));
    port->dev_bytes_received = 0;
    port->dev_bytes_sent = 0;
    port->devstr = NULL;
    port->closestr = NULL;
    port->is_2217 = 0;
    port->dev_monitor = NULL;
    port->break_set = 0;
    port->dinfo.disablebreak = 0;
    port->wt.file = -1;
    port->wt.timestamp = 0;
    port->wt.hexdump = 0;
    port->rt.file = -1;
    port->rt.timestamp = 0;
    port->rt.hexdump = 0;
    port->bt.file = -1;
    port->bt.timestamp = 0;
    port->bt.hexdump = 0;
}

static void
reset_timer(port_info_t *port)
{
    port->timeout_left = port->timeout;
}


static int
timestamp(trace_t *tr, char *buf, int size)
{
    time_t result;
    if(!tr->timestamp)
        return 0;
    result = time(NULL);
    return strftime(buf, size, "%Y/%m/%d %H:%M:%S ", localtime(&result));
}

static int
trace_write_end(char *out, int size, unsigned char *start, int col)
{
    int pos=0, w;

    strncat(out, " |", size-pos);
    pos += 2;
    for(w = 0; w < col; w++) {
        pos += snprintf(out + pos, size - pos, "%c",
			isprint(start[w]) ? start[w] : '.');
    }
    strncat(out+pos, "|\n", size-pos);
    pos += 2;
    return pos;
}

int
trace_write(port_info_t *port, trace_t *tr, unsigned char *buf,
	    unsigned int buf_len, char *prefix)
{
    int rv=0, w, col=0, pos, file = tr->file;
    unsigned int q;
    static char out[1024];
    unsigned char *start;

    if( buf_len == 0 ) 
        return 0;

    if(!tr->hexdump)
        return write(file, buf, buf_len);

    pos = timestamp(tr, out, sizeof(out));    
    pos += snprintf(out + pos, sizeof(out) - pos, "%s ", prefix);
        
    start = buf;
    for (q = 0; q < buf_len; q++) {
        pos += snprintf(out + pos, sizeof(out) - pos, "%02x ", buf[q]);
        col++;
        if (col >= 8) {
            pos += trace_write_end(out + pos, sizeof(out) - pos, start, col);
            rv = write(file, out, strlen(out));
            if (rv < 0)
                return rv;           
            pos = timestamp(tr, out, sizeof(out));    
            pos += snprintf(out + pos, sizeof(out) - pos, "%s ", prefix);
            col = 0;
            start = buf + q + 1;
        }
    }
    if ( col > 0 ) {
        for (w = 8; w > col; w--) {
            strncat(out + pos, "   ", sizeof(out) - pos);
            pos += 3;
        }
        pos += trace_write_end(out + pos, sizeof(out) - pos, start, col);
        rv = write(file, out, strlen(out));
        if(rv < 0)
            return rv;
    }
    return buf_len;
}

static void
do_trace(port_info_t *port, trace_t *tr, unsigned char *buf,
	 unsigned int buf_len, char *prefix)
{
    int rv;

    while (buf_len > 0) {
    retry_write:
	rv = trace_write(port, tr, buf, buf_len, prefix);
	if (rv == -1) {
	    char errbuf[128];
	    int err = errno;

	    if (err == EINTR)
		goto retry_write;
	    
	    /* Fatal error writing to the file, log it and close the file. */

	    if (strerror_r(err, errbuf, sizeof(errbuf)) == -1)
		syslog(LOG_ERR, "Unable write to trace file on port %s: %d",
		       port->portname, err);
	    else
		syslog(LOG_ERR, "Unable to write to trace file on port %s: %s",
		       port->portname, errbuf);
	    
	    close(tr->file);
	    tr->file = -1;
	    return;
	}

	/* Handle a partial write */
	buf_len -= rv;
	buf += rv;
    }
}

static void
header_trace(port_info_t *port)
{
    static char buf[1024];
    static trace_t tr = { 1, 1, -1 };
    int len = 0, doneR=-1, doneW=-1;
    char portstr[NI_MAXSERV];

    len += timestamp(&tr, buf, sizeof(buf));
    len += snprintf(buf + len, sizeof(buf) - len, "OPEN (");
    getnameinfo((struct sockaddr *) &(port->remote), sizeof(port->remote),
		buf + len, sizeof(buf) - len,
		portstr, sizeof(portstr), NI_NUMERICHOST);
    len += strlen(buf + len);
    if ((sizeof(buf) - len) > 2) {
	buf[len] = ':';
	len++;
    }
    strncpy(buf + len, portstr, sizeof(buf) - len);
    len += strlen(buf + len);
    len += snprintf(buf + len, sizeof(buf) - len, ")\n");

    if (port->rt.file != -1 && port->rt.timestamp) {
        write_ignore_fail(port->rt.file, buf, len);
        doneR = port->rt.file;
    }
    /* don't output to wt.file if it's the same as rt.file */
    if (port->wt.file != doneR && port->wt.timestamp) {
        write_ignore_fail(port->wt.file, buf, len);
        doneW = port->wt.file;
    }
    /* don't output to bt.file if it's the same as rt.file or wt.file */
    if (port->bt.file != doneR && port->bt.file != doneW 
                && port->bt.timestamp)
        write_ignore_fail(port->bt.file, buf, len);    
}

static void
footer_trace(port_info_t *port, char *reason)
{
    static char buf[1024];
    static trace_t tr = { 1, 1, -1 };
    int len=0, doneR=-1, doneW=-1;

    len += timestamp(&tr, buf, sizeof(buf));
    len += snprintf(buf + len, sizeof(buf), "CLOSE (%s)\n", reason);

    if (port->rt.file != -1 && port->rt.timestamp) {
        write_ignore_fail(port->rt.file, buf, len);
        doneR = port->rt.file;
    }
    /* don't output to wt.file if it's the same as rt.file */
    if (port->wt.file != doneR && port->wt.timestamp) {
        write_ignore_fail(port->wt.file, buf, len);
        doneW = port->wt.file;
    }
    /* don't output to bt.file if it's the same as rt.file or wt.file */
    if (port->bt.file != doneR && port->bt.file != doneW 
                && port->bt.timestamp)
        write_ignore_fail(port->bt.file, buf, len);
}



/* Data is ready to read on the serial port. */
static void
handle_dev_fd_read(int fd, void *data)
{
    port_info_t *port = (port_info_t *) data;
    int count;

    port->dev_to_tcp.pos = 0;
    if (port->enabled == PORT_TELNET) {
	/* Leave room for IACs. */
	count = read(fd, port->dev_to_tcp.buf, port->tcp_to_dev.maxsize/2);
    } else {
	count = read(fd, port->dev_to_tcp.buf, port->tcp_to_dev.maxsize);
    }

    if (port->dev_monitor != NULL) {
	controller_write(port->dev_monitor,
			 (char *) port->dev_to_tcp.buf,
			 count);
    }

    if (count < 0) {
	/* Got an error on the read, shut down the port. */
	syslog(LOG_ERR, "dev read error for port %s: %m", port->portname);
	shutdown_port(port, "dev read error");
	return;
    } else if (count == 0) {
	/* The port got closed somehow, shut it down. */
	shutdown_port(port, "closed port");
	return;
    }

    if (port->rt.file != -1)
	/* Do read tracing, ignore errors. */
	do_trace(port, &port->rt, port->dev_to_tcp.buf, count, SERIAL);
    if (port->bt.file != -1)
	/* Do both tracing, ignore errors. */
	do_trace(port, &port->bt, port->dev_to_tcp.buf, count, SERIAL);

    port->dev_bytes_received += count;

    if (port->enabled == PORT_TELNET) {
	int i, j;

	/* Double the IACs on a telnet stream.  This will fit because
	   we only use half the buffer for telnet connections. */
	for (i=0; i<count; i++) {
	    if (port->dev_to_tcp.buf[i] == 255) {
		for (j=count; j>i; j--)
		    port->dev_to_tcp.buf[j+1] = port->dev_to_tcp.buf[j];
		count++;
		i++;
		port->dev_to_tcp.buf[i] = 255;
	    }
	}
    }

    port->dev_to_tcp.cursize = count;

 retry_write:
    count = write(port->tcpfd, port->dev_to_tcp.buf, port->dev_to_tcp.cursize);
    if (count == -1) {
	if (errno == EINTR) {
	    /* EINTR means we were interrupted, just retry. */
	    goto retry_write;
	}

	if (errno == EAGAIN) {
	    /* This was due to O_NONBLOCK, we need to shut off the reader
	       and start the writer monitor. */
	    sel_set_fd_read_handler(ser2net_sel, port->devfd,
				    SEL_FD_HANDLER_DISABLED);
	    sel_set_fd_write_handler(ser2net_sel, port->tcpfd,
				     SEL_FD_HANDLER_ENABLED);
	    port->dev_to_tcp_state = PORT_WAITING_OUTPUT_CLEAR;
	} else if (errno == EPIPE) {
	    shutdown_port(port, "EPIPE");
	    return;
	} else {
	    /* Some other bad error. */
	    syslog(LOG_ERR, "The tcp write for port %s had error: %m",
		   port->portname);
	    shutdown_port(port, "tcp write error");
	    return;
	}
    } else {
	port->tcp_bytes_sent += count;
	port->dev_to_tcp.cursize -= count;
	if (port->dev_to_tcp.cursize != 0) {
	    /* We didn't write all the data, shut off the reader and
               start the write monitor. */
	    port->dev_to_tcp.pos = count;
	    sel_set_fd_read_handler(ser2net_sel, port->devfd,
				    SEL_FD_HANDLER_DISABLED);
	    sel_set_fd_write_handler(ser2net_sel, port->tcpfd,
				     SEL_FD_HANDLER_ENABLED);
	    port->dev_to_tcp_state = PORT_WAITING_OUTPUT_CLEAR;
	}
    }

    reset_timer(port);
}

/* The serial port has room to write some data.  This is only activated
   if a write fails to complete, it is deactivated as soon as writing
   is available again. */
static void
dev_fd_write(port_info_t *port, struct sbuf *buf)
{
    int reterr, buferr;

    reterr = buffer_write(port->devfd, buf, &buferr);
    if (reterr == -1) {
	syslog(LOG_ERR, "The dev write for port %s had error: %m",
	       port->portname);
	shutdown_port(port, "dev write error");
	return;
    }

    if (buffer_cursize(buf) == 0) {
	/* We are done writing, turn the reader back on. */
	sel_set_fd_read_handler(ser2net_sel, port->tcpfd,
				SEL_FD_HANDLER_ENABLED);
	sel_set_fd_write_handler(ser2net_sel, port->devfd,
				 SEL_FD_HANDLER_DISABLED);
	port->tcp_to_dev_state = PORT_WAITING_INPUT;
    }

    reset_timer(port);
}

static void
handle_dev_fd_write(int fd, void *data)
{
    port_info_t *port = (port_info_t *) data;

    dev_fd_write(port, &port->tcp_to_dev);
}

/* Handle an exception from the serial port. */
static void
handle_dev_fd_except(int fd, void *data)
{
    port_info_t *port = (port_info_t *) data;

    syslog(LOG_ERR, "Select exception on device for port %s",
	   port->portname);
    shutdown_port(port, "fd exception");
}

/* Output the devstr buffer */
static void
handle_dev_fd_devstr_write(int fd, void *data)
{
    port_info_t *port = (port_info_t *) data;

    dev_fd_write(port, port->devstr);
    if (buffer_cursize(port->devstr) == 0) {
	sel_set_fd_handlers(ser2net_sel,
			    port->devfd,
			    port,
			    handle_dev_fd_read,
			    handle_dev_fd_write,
			    handle_dev_fd_except);
	free(port->devstr->buf);
	free(port->devstr);
	port->devstr = NULL;    }
}

/* Output the devstr buffer */
static void
handle_dev_fd_close_write(int fd, void *data)
{
    port_info_t *port = (port_info_t *) data;
    int reterr, buferr;

    reterr = buffer_write(port->devfd, port->devstr, &buferr);
    if (reterr == -1) {
	syslog(LOG_ERR, "The dev write for port %s had error: %m",
	       port->portname);
	goto closeit;
    }

    if (buffer_cursize(port->devstr) != 0)
	return;

closeit:
    finish_shutdown_port(port);
}

/* Data is ready to read on the TCP port. */
static void
handle_tcp_fd_read(int fd, void *data)
{
    port_info_t *port = (port_info_t *) data;
    int count;

    port->tcp_to_dev.pos = 0;
    count = read(fd, port->tcp_to_dev.buf, port->tcp_to_dev.maxsize);
    if (count < 0) {
	/* Got an error on the read, shut down the port. */
	syslog(LOG_ERR, "read error for port %s: %m", port->portname);
	shutdown_port(port, "tcp read error");
	return;
    } else if (count == 0) {
	/* The other end closed the port, shut it down. */
	shutdown_port(port, "tcp read close");
	return;
    }
    port->tcp_to_dev.cursize = count;

    port->tcp_bytes_received += count;

    if (port->enabled == PORT_TELNET) {
	port->tcp_to_dev.cursize = process_telnet_data(port->tcp_to_dev.buf,
						       count,
						       &port->tn_data);
	if (port->tn_data.error) {
	    shutdown_port(port, "telnet output error");
	    return;
	}
	if (port->tcp_to_dev.cursize == 0) {
	    /* We are out of characters; they were all processed.  We
	       don't want to continue with 0, because that will mess
	       up the other processing and it's not necessary. */
	    return;
	}
    }

    if (port->tcp_monitor != NULL) {
	controller_write(port->tcp_monitor,
			 (char *) port->tcp_to_dev.buf,
			 port->tcp_to_dev.cursize);
    }

    if (port->wt.file != -1)
	/* Do write tracing, ignore errors. */
	do_trace(port, &port->wt,
		 port->tcp_to_dev.buf, port->tcp_to_dev.cursize, NET);
    if (port->bt.file != -1)
	/* Do both tracing, ignore errors. */
	do_trace(port, &port->bt,
		 port->tcp_to_dev.buf, port->tcp_to_dev.cursize, NET);

 retry_write:
    count = write(port->devfd, port->tcp_to_dev.buf, port->tcp_to_dev.cursize);
    if (count == -1) {
	if (errno == EINTR) {
	    /* EINTR means we were interrupted, just retry. */
	    goto retry_write;
	}

	if (errno == EAGAIN) {
	    /* This was due to O_NONBLOCK, we need to shut off the reader
	       and start the writer monitor. */
	    sel_set_fd_read_handler(ser2net_sel, port->tcpfd,
				    SEL_FD_HANDLER_DISABLED);
	    sel_set_fd_write_handler(ser2net_sel, port->devfd,
				     SEL_FD_HANDLER_ENABLED);
	    port->tcp_to_dev_state = PORT_WAITING_OUTPUT_CLEAR;
	} else {
	    /* Some other bad error. */
	    syslog(LOG_ERR, "The dev write for port %s had error: %m",
		   port->portname);
	    shutdown_port(port, "dev write error");
	    return;
	}
    } else {
	port->dev_bytes_sent += count;
	port->tcp_to_dev.cursize -= count;
	if (port->tcp_to_dev.cursize != 0) {
	    /* We didn't write all the data, shut off the reader and
               start the write monitor. */
	    port->tcp_to_dev.pos = count;
	    sel_set_fd_read_handler(ser2net_sel, port->tcpfd,
				    SEL_FD_HANDLER_DISABLED);
	    sel_set_fd_write_handler(ser2net_sel, port->devfd,
				     SEL_FD_HANDLER_ENABLED);
	    port->tcp_to_dev_state = PORT_WAITING_OUTPUT_CLEAR;
	}
    }

    reset_timer(port);
}

/* The TCP port has room to write some data.  This is only activated
   if a write fails to complete, it is deactivated as soon as writing
   is available again. */
static void
tcp_fd_write(port_info_t *port, struct sbuf *buf)
{
    telnet_data_t *td = &port->tn_data;
    int buferr, reterr;

    if (buffer_cursize(&td->out_telnet_cmd) > 0) {
	reterr = buffer_write(port->tcpfd, &td->out_telnet_cmd, &buferr);
	if (reterr == -1) {
	    if (buferr == EPIPE) {
		shutdown_port(port, "EPIPE");
	    } else {
		/* Some other bad error. */
		syslog(LOG_ERR, "The tcp write for port %s had error: %m",
		       port->portname);
		shutdown_port(port, "tcp write error");
	    }
	}

	if (buffer_cursize(&td->out_telnet_cmd) > 0) {
	    /* If we have more telnet command data to send, don't
	       send any real data. */
	    return;
	}
    }

    reterr = buffer_write(port->tcpfd, buf, &buferr);
    if (reterr == -1) {
	if (buferr == EPIPE) {
	    shutdown_port(port, "EPIPE");
	} else {
	    /* Some other bad error. */
	    syslog(LOG_ERR, "The tcp write for port %s had error: %m",
		   port->portname);
	    shutdown_port(port, "tcp write error");
	}
	return;
    }
    if (buffer_cursize(buf) == 0) {
	/* We are done writing, turn the reader back on. */
	sel_set_fd_read_handler(ser2net_sel, port->devfd,
				SEL_FD_HANDLER_ENABLED);
	sel_set_fd_write_handler(ser2net_sel, port->tcpfd,
				 SEL_FD_HANDLER_DISABLED);
	port->dev_to_tcp_state = PORT_WAITING_INPUT;
    }

    reset_timer(port);
}

/* The TCP port has room to write some data.  This is only activated
   if a write fails to complete, it is deactivated as soon as writing
   is available again. */
static void
handle_tcp_fd_write(int fd, void *data)
{
    port_info_t *port = (port_info_t *) data;
    tcp_fd_write(port, &port->dev_to_tcp);
}

/* Handle an exception from the TCP port. */
static void
handle_tcp_fd_except(int fd, void *data)
{
    port_info_t *port = (port_info_t *) data;

    syslog(LOG_ERR, "Select exception on port %s", port->portname);
    shutdown_port(port, "tcp fd exception");
}

static void
handle_tcp_fd_banner_write(int fd, void *data)
{
    port_info_t *port = (port_info_t *) data;

    tcp_fd_write(port, port->banner);
    if (buffer_cursize(port->banner) == 0) {
	sel_set_fd_handlers(ser2net_sel,
			    port->tcpfd,
			    port,
			    handle_tcp_fd_read,
			    handle_tcp_fd_write,
			    handle_tcp_fd_except);
	free(port->banner->buf);
	free(port->banner);
	port->banner = NULL;
    }
}

static void
telnet_cmd_handler(void *cb_data, unsigned char cmd)
{
    port_info_t *port = cb_data;

    if (cmd == TN_BREAK)
	tcsendbreak(port->devfd, 0);
}

/* Called when the telnet code has output ready. */
static void
telnet_output_ready(void *cb_data)
{
    port_info_t *port = cb_data;
    sel_set_fd_read_handler(ser2net_sel, port->devfd,
			    SEL_FD_HANDLER_DISABLED);
    sel_set_fd_write_handler(ser2net_sel, port->tcpfd,
			     SEL_FD_HANDLER_ENABLED);
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

static int
from_hex_digit(char c)
{
    if ((c >= '0') && (c <= '9'))
	return c - '0';
    if ((c >= 'A') && (c <= 'F'))
	return c - 'A' + 10;
    if ((c >= 'a') && (c <= 'f'))
	return c - 'a' + 10;
    return 0;
}

static char *smonths[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
			   "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
static char *sdays[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };

static void
process_str(port_info_t *port, struct tm *time, struct timeval *tv, char *s,
	    void (*op)(void *data, char val), void *data, int isfilename)
{
    char val;
    char *t;

    while (*s) {
	if (*s == '\\') {
	    s++;
	    if (!*s)
		return;
	    switch (*s) {
	    /* Standard "C" characters. */
	    case 'a': op(data, 7); break;
	    case 'b': op(data, 8); break;
	    case 'f': op(data, 12); break;
	    case 'n': op(data, 10); break;
	    case 'r': op(data, 13); break;
	    case 't': op(data, 9); break;
	    case 'v': op(data, 11); break;
	    case '\\': op(data, '\\'); break;
	    case '?': op(data, '?'); break;
	    case '\'': op(data, '\''); break;
	    case '"': op(data, '"'); break;

	    case 'd':
		/* ser2net device name. */
		if (isfilename) {
		    /* Can't have '/' in a filename. */
		    t = strrchr(port->devname, '/');
		    if (t)
			t++;
		    else
			t = port->devname;
		} else
		    t = port->devname;
		for (; *t; t++)
		    op(data, *t);
		break;

	    case 'p':
		/* ser2net TCP port. */
		for (t=port->portname; *t; t++)
		    op(data, *t);
		break;

	    case 's':
		if (isfilename)
		    goto seconds;
		goto serparms;

	    case 'B':
	    serparms:
		/* ser2net serial parms. */
		{
		    char str[15];
		    serparm_to_str(str, sizeof(str), &(port->dinfo.termctl));
		    for (t=str; *t; t++)
			op(data, *t);
		}
		break;

	    case '0': case '1': case '2': case '3': case '4': case '5':
	    case '6': case '7':
		/* Octal digit */
		val = (*s) - '0';
		s++;
		if (!*s) {
		    op(data, val);
		    return;
		}
		if (!isdigit(*s)) {
		    continue;
		}
		val = (val * 8) + (*s) - '0';
		s++;
		if (!*s) {
		    op(data, val);
		    return;
		}
		if (!isdigit(*s)) {
		    continue;
		}
		val = (val * 8) + (*s) - '0';
		break;

	    case 'x':
		/* Hex digit */
		s++;
		if (!*s)
		    return;
		if (!isxdigit(*s))
		    continue;
		val = from_hex_digit(*s);
		s++;
		if (!*s) {
		    op(data, val);
		    return;
		}
		if (!isdigit(*s))
		    continue;
		val = (val * 16) + from_hex_digit(*s);
		break;

	    /* \Y -> year */
	    case 'Y':
	    {
		char d[10], *dp;
		snprintf(d, sizeof(d), "%d", time->tm_year + 1900);
		for (dp = d; *dp; dp++)
		    op(data, *dp);
		break;
	    }

	    /* \y -> day of the year (days since Jan 1) */
	    case 'y':
	    {
		char d[10], *dp;
		snprintf(d, sizeof(d), "%d", time->tm_yday);
		for (dp = d; *dp; dp++)
		    op(data, *dp);
		break;
	    }

	    /* \M -> month (Jan, Feb, Mar, etc.) */
	    case 'M':
		if (time->tm_mon >= 12)
		    op(data, '?');
		else {
		    char *dp = smonths[time->tm_mon];
		    for (; *dp; dp++)
			op(data, *dp);
		}
		break;

	    /* \m -> month (as a number) */
	    case 'm':
	    {
		char d[10], *dp;
		snprintf(d, sizeof(d), "%d", time->tm_mon);
		for (dp = d; *dp; dp++)
		    op(data, *dp);
		break;
	    }

	    /* \A -> day of the week (Mon, Tue, etc.) */
	    case 'A':
		if (time->tm_wday >= 7)
		    op(data, '?');
		else {
		    char *dp = sdays[time->tm_wday];
		    for (; *dp; dp++)
			op(data, *dp);
		}
		break;

	    /* \D -> day of the month */
	    case 'D':
	    {
		char d[10], *dp;
		snprintf(d, sizeof(d), "%d", time->tm_mday);
		for (dp = d; *dp; dp++)
		    op(data, *dp);
		break;
	    }

	    /* \H -> hour (24-hour time) */
	    case 'H':
	    {
		char d[10], *dp;
		snprintf(d, sizeof(d), "%2.2d", time->tm_hour);
		for (dp = d; *dp; dp++)
		    op(data, *dp);
		break;
	    }

	    /* \h -> hour (12-hour time) */
	    case 'h':
	    {
		char d[10], *dp;
		int v;

		v = time->tm_hour;
		if (v == 0)
		    v = 12;
		else if (v > 12)
		    v -= 12;
		snprintf(d, sizeof(d), "%2.2d", v);
		for (dp = d; *dp; dp++)
		    op(data, *dp);
		break;
	    }

	    /* \i -> minute */
	    case 'i':
	    {
		char d[10], *dp;
		snprintf(d, sizeof(d), "%2.2d", time->tm_min);
		for (dp = d; *dp; dp++)
		    op(data, *dp);
		break;
	    }

	    /* \S -> second */
	    case 'S':
	    seconds:
	    {
		char d[10], *dp;
		snprintf(d, sizeof(d), "%2.2d", time->tm_sec);
		for (dp = d; *dp; dp++)
		    op(data, *dp);
		break;
	    }

	    /* \q -> am/pm */
	    case 'q':
		if (time->tm_hour < 12) {
		    op(data, 'a');
		} else {
		    op(data, 'p');
		}
		op(data, 'm');
		break;

	    /* \P -> AM/PM */
	    case 'P':
		if (time->tm_hour < 12) {
		    op(data, 'A');
		} else {
		    op(data, 'P');
		}
		op(data, 'M');
		break;

	    /* \T -> time (HH:MM:SS) */
	    case 'T':
	    {
		char d[10], *dp;
		snprintf(d, sizeof(d), "%2.2d:%2.2d:%2.2d",
			 time->tm_hour, time->tm_min, time->tm_sec);
		for (dp = d; *dp; dp++)
		    op(data, *dp);
		break;
	    }

	    /* \e -> epoc (seconds since Jan 1, 1970) */
	    case 'e':
	    {
		char d[30], *dp;
		snprintf(d, sizeof(d), "%ld", tv->tv_sec);
		for (dp = d; *dp; dp++)
		    op(data, *dp);
		break;
	    }

	    /* \U -> microseconds in the current second */
	    case 'U':
	    {
		char d[10], *dp;
		snprintf(d, sizeof(d), "%6.6ld", tv->tv_usec);
		for (dp = d; *dp; dp++)
		    op(data, *dp);
		break;
	    }

	    /* \I -> remote IP address (in dot format) */
	    case 'I':
	    {
		char ip[100], *ipp;
		if (!getnameinfo((struct sockaddr *) &(port->remote),
				 sizeof(port->remote),
				 ip, sizeof(ip), NULL, 0, NI_NUMERICHOST))
		    break;
		for (ipp = ip; *ipp; ipp++)
		    op(data, *ipp);
		break;
	    }

	    default:
		op(data, *s);
	    }
	} else
	    op(data, *s);
	s++;
    }
}

static void
count_op(void *data, char c)
{
    unsigned int *idata = data;

    (*idata)++;
}

struct bufop_data {
    unsigned int pos;
    char *str;
};

static void
buffer_op(void *data, char c)
{
    struct bufop_data *bufop = data;
    bufop->str[bufop->pos] = c;
    (bufop->pos)++;
}

static char *
process_str_to_str(port_info_t *port, char *str, struct timeval *tv,
		   unsigned int *lenrv, int isfilename)
{
    unsigned int len = 0;
    struct tm now;
    struct bufop_data bufop;

    localtime_r(&tv->tv_sec, &now);
    process_str(port, &now, tv, str, count_op, &len, isfilename);
    if (!lenrv)
	/* If we don't return a length, append a nil char. */
	len++;
    bufop.pos = 0;
    if (len == 0)
	/* malloc(0) sometimes return NULL */
	bufop.str = malloc(1);
    else
	bufop.str = malloc(len);
    if (!bufop.str) {
	syslog(LOG_ERR, "Out of memory processing string: %s", port->portname);
	return NULL;
    }
    process_str(port, &now, tv, str, buffer_op, &bufop, isfilename);

    if (lenrv)
	*lenrv = len;
    else
	bufop.str[bufop.pos] = '\0';

    return bufop.str;
}

static struct sbuf *
process_str_to_buf(port_info_t *port, char *str)
{
    char *bstr;
    struct sbuf *buf;
    unsigned int len;
    struct timeval tv;

    if (!str)
	return NULL;
    gettimeofday(&tv, NULL);

    buf = malloc(sizeof(*buf));
    if (!buf) {
	syslog(LOG_ERR, "Out of memory processing string: %s", port->portname);
	return NULL;
    }
    bstr = process_str_to_str(port, str, &tv, &len, 0);
    if (!bstr) {
	free(buf);
	syslog(LOG_ERR, "Error processing string: %s", port->portname);
	return NULL;
    }
    buffer_init(buf, (unsigned char *) bstr, len);
    buf->cursize = len;
    return buf;
}

static void
open_trace_file(port_info_t *port, 
                trace_info_t *in,
                trace_t *out,
                struct timeval *tv)
{
    int rv;
    char *trfilename = in->file;
    char *trfile;

    trfile = process_str_to_str(port, trfilename, tv, NULL, 1);
    if (!trfile) {
	syslog(LOG_ERR, "Unable to translate trace file %s", trfilename);
	out->file = -1;
	return;
    }

    rv = open(trfile, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (rv == -1) {
	char errbuf[128];
	int err = errno;

	if (strerror_r(err, errbuf, sizeof(errbuf)) == -1)
	    syslog(LOG_ERR, "Unable to open trace file %s: %d",
		   trfile, err);
	else
	    syslog(LOG_ERR, "Unable to open trace file %s: %s",
		   trfile, errbuf);
    }
    else {
        out->hexdump = in->hexdump;
        out->timestamp = in->timestamp;
    }

    free(trfile);
    out->file = rv;
}

static void
setup_trace(port_info_t *port)
{
    struct timeval tv;

    /* Only get the time once so all trace files have consistent times. */
    gettimeofday(&tv, NULL);

    if (port->dinfo.trace_write.file)
	open_trace_file(port, &port->dinfo.trace_write, &port->wt, &tv);
    else
	port->wt.file = -1;

    if (port->dinfo.trace_read.file) {
	if (port->dinfo.trace_write.file
	    && (strcmp(port->dinfo.trace_read.file,
		       port->dinfo.trace_write.file) == 0)) {
	    port->rt.file = port->wt.file;
	    port->rt.timestamp = port->wt.timestamp;
	    port->rt.hexdump   = port->wt.hexdump;
	    goto try_both;
	}
	open_trace_file(port, &port->dinfo.trace_read, &port->rt, &tv);
    } else
	port->rt.file = -1;
 try_both:
    if (port->dinfo.trace_both.file) {
	if (port->dinfo.trace_write.file
	    && (strcmp(port->dinfo.trace_both.file,
		       port->dinfo.trace_write.file) == 0)) {
	    port->bt.file = port->wt.file;
	    port->bt.timestamp = port->wt.timestamp;
	    port->bt.hexdump   = port->wt.hexdump;
	    goto out;
	} else if (port->dinfo.trace_read.file
	    && (strcmp(port->dinfo.trace_both.file,
		       port->dinfo.trace_read.file) == 0)) {
	    port->bt.file = port->rt.file;
	    port->bt.timestamp = port->rt.timestamp;
	    port->bt.hexdump   = port->rt.hexdump;
	    goto out;
	}
	open_trace_file(port, &port->dinfo.trace_both, &port->bt, &tv);
    } else
	port->bt.file = -1;
 out:
    return;
}

/* Called to set up a new connection's file descriptor. */
static int
setup_tcp_port(port_info_t *port)
{
    int options;
    struct timeval then;
    sel_fd_handler_t tcp_write_handler;
    sel_fd_handler_t dev_write_handler;

    if (fcntl(port->tcpfd, F_SETFL, O_NONBLOCK) == -1) {
	close(port->tcpfd);
	port->tcpfd = -1;
	syslog(LOG_ERR, "Could not fcntl the tcp port %s: %m", port->portname);
	return -1;
    }
    options = 1;
    if (setsockopt(port->tcpfd, IPPROTO_TCP, TCP_NODELAY,
		   (char *) &options, sizeof(options)) == -1) {
	close(port->tcpfd);
	port->tcpfd = -1;
	syslog(LOG_ERR, "Could not enable TCP_NODELAY tcp port %s: %m",
	       port->portname);
	return -1;
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
	    port->tcpfd = -1;
	    return -1;
	}
    }
#endif /* HAVE_TCPD_H */

#ifdef USE_UUCP_LOCKING
    {
	int rv;

	rv = uucp_mk_lock(port->devname);
	if (rv > 0 ) {
	    char *err;

	    err = "Port already in use by another process\n\r";
	    write_ignore_fail(port->tcpfd, err, strlen(err));
	    close(port->tcpfd);
	    port->tcpfd = -1;
	    return -1;
	} else if (rv < 0) {
	    char *err;

	    err = "Error creating port lock file\n\r";
	    write_ignore_fail(port->tcpfd, err, strlen(err));
	    close(port->tcpfd);
	    port->tcpfd = -1;
	    return -1;
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
	port->tcpfd = -1;
	syslog(LOG_ERR, "Could not open device %s for port %s: %m",
	       port->devname,
	       port->portname);
#ifdef USE_UUCP_LOCKING
	uucp_rm_lock(port->devname);
#endif /* USE_UUCP_LOCKING */
	return -1;
    }

    if (port->enabled != PORT_RAWLP
	&& !port->dinfo.disablebreak
        && tcsetattr(port->devfd, TCSANOW, &(port->dinfo.termctl)) == -1)
    {
	close(port->tcpfd);
	port->tcpfd = -1;
	close(port->devfd);
	port->devfd = -1;
	syslog(LOG_ERR, "Could not set up device %s for port %s: %m",
	       port->devname,
	       port->portname);
#ifdef USE_UUCP_LOCKING
	uucp_rm_lock(port->devname);
#endif /* USE_UUCP_LOCKING */
	return -1;
    }

    /* Turn off BREAK. */
    if (port->enabled != PORT_RAWLP &&
              ioctl(port->devfd, TIOCCBRK) == -1) {
	/* Probably not critical, but we should at least log something. */
	syslog(LOG_ERR, "Could not turn off break for device %s port %s: %m",
	       port->devname,
	       port->portname);
    }
    port->is_2217 = 0;
    port->break_set = 0;

    port->banner = process_str_to_buf(port, port->dinfo.banner);
    if (port->banner)
	tcp_write_handler = handle_tcp_fd_banner_write;
    else
	tcp_write_handler = handle_tcp_fd_write;

    port->devstr = process_str_to_buf(port, port->dinfo.openstr);
    if (port->devstr)
	dev_write_handler = handle_dev_fd_devstr_write;
    else
	dev_write_handler = handle_dev_fd_write;

    if (port->dinfo.closestr)
	port->closestr = strdup(port->dinfo.closestr);
    else
	port->closestr = NULL;

    sel_set_fd_handlers(ser2net_sel,
			port->devfd,
			port,
			port->enabled == PORT_RAWLP
			? NULL
			: handle_dev_fd_read,
			dev_write_handler,
			handle_dev_fd_except);
    sel_set_fd_read_handler(ser2net_sel,
			    port->devfd,
			    ((port->enabled == PORT_RAWLP)
			     ? SEL_FD_HANDLER_DISABLED
			     : SEL_FD_HANDLER_ENABLED));
    sel_set_fd_except_handler(ser2net_sel, port->devfd,
			      SEL_FD_HANDLER_ENABLED);
    if (port->devstr)
	sel_set_fd_write_handler(ser2net_sel, port->devfd,
				 SEL_FD_HANDLER_ENABLED);
    port->dev_to_tcp_state = PORT_WAITING_INPUT;

    sel_set_fd_handlers(ser2net_sel,
			port->tcpfd,
			port,
			handle_tcp_fd_read,
			tcp_write_handler,
			handle_tcp_fd_except);
    sel_set_fd_read_handler(ser2net_sel, port->tcpfd,
			    SEL_FD_HANDLER_ENABLED);
    sel_set_fd_except_handler(ser2net_sel, port->tcpfd,
			      SEL_FD_HANDLER_ENABLED);
    port->tcp_to_dev_state = PORT_WAITING_INPUT;

    if (port->enabled == PORT_TELNET) {
	telnet_init(&port->tn_data, port, telnet_output_ready,
		    telnet_cmd_handler,
		    telnet_cmds,
		    telnet_init_seq, sizeof(telnet_init_seq));
    } else {
	buffer_init(&port->tn_data.out_telnet_cmd, NULL, 0);
	sel_set_fd_read_handler(ser2net_sel, port->devfd,
				SEL_FD_HANDLER_ENABLED);
	if (port->banner)
	    sel_set_fd_write_handler(ser2net_sel, port->tcpfd,
				     SEL_FD_HANDLER_ENABLED);
    }

    setup_trace(port);
    header_trace(port);

    gettimeofday(&then, NULL);
    then.tv_sec += 1;
    sel_start_timer(port->timer, &then);

    reset_timer(port);
    return 0;
}

/* A connection request has come in on a port. */
static void
handle_accept_port_read(int fd, void *data)
{
    port_info_t *port = (port_info_t *) data;
    socklen_t len;
    char *err = NULL;
    int optval;

    if (port->tcp_to_dev_state != PORT_UNCONNECTED) {
	err = "Port already in use\n\r";
    } else if (is_device_already_inuse(port)) {
	err = "Port's device already in use\n\r";
    }

    if (err != NULL) {
	struct sockaddr_storage dummy_sockaddr;
	socklen_t len = sizeof(dummy_sockaddr);
	int new_fd = accept(fd, (struct sockaddr *) &dummy_sockaddr, &len);

	if (new_fd != -1) {
	    write_ignore_fail(new_fd, err, strlen(err));
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

    optval = 1;
    if (setsockopt(port->tcpfd, SOL_SOCKET, SO_KEEPALIVE, (void *)&optval,
		   sizeof(optval)) == -1) {
	close(port->tcpfd);
	syslog(LOG_ERR, "Could not enable SO_KEEPALIVE on tcp port %s: %m",
	       port->portname);
	return;
    }

    /* XXX log port->remote */
    setup_tcp_port(port);
}

/* Start monitoring for connections on a specific port. */
static char *
startup_port(port_info_t *port)
{
    int optval = 1;
    int portnum;

    portnum = port_from_in_addr(port->tcpport.ss_family,
				(struct sockaddr *) &port->tcpport);
    if (portnum == 0) {
	/* A zero port means use stdin/stdout */
	if (is_device_already_inuse(port)) {
	    char *err = "Port's device already in use\n\r";
	    write_ignore_fail(0, err, strlen(err));
	    exit(1);
	} else {
	    port->acceptfd = -1;
	    port->tcpfd = 0; /* stdin */
	    if (setup_tcp_port(port) == -1)
		exit(1);
	}
	return NULL;
    }

    if (scan_tcp_port(port->portname, AF_UNSPEC,
		      &port->tcpport, &port->tcpport_len)
	== -1)
    {
	return "port number was invalid";
    }
    port->acceptfd = socket(port->tcpport.ss_family, SOCK_STREAM, 0);
    if ((port->acceptfd == -1) && (errno == EAFNOSUPPORT)) {
	/* Retry IPV4-only */
	if (scan_tcp_port(port->portname, AF_INET,
			  &port->tcpport, &port->tcpport_len)
	    == -1)
	{
	    return "port number was invalid";
	}
	port->acceptfd = socket(port->tcpport.ss_family, SOCK_STREAM, 0);
    }
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

    check_ipv6_only(port->tcpport.ss_family,
		    (struct sockaddr *) &port->tcpport,
		    port->acceptfd);

    if (bind(port->acceptfd,
	     (struct sockaddr *) &port->tcpport,
	     port->tcpport_len) == -1) {
	close(port->acceptfd);
	return "Unable to bind TCP port";
    }

    if (listen(port->acceptfd, 1) != 0) {
	close(port->acceptfd);
	return "Unable to listen to TCP port";
    }

    sel_set_fd_handlers(ser2net_sel,
			port->acceptfd,
			port,
			handle_accept_port_read,
			NULL,
			NULL);
    sel_set_fd_read_handler(ser2net_sel, port->acceptfd,
			    SEL_FD_HANDLER_ENABLED);

    return NULL;
}

char *
change_port_state(port_info_t *port, int state)
{
    char *rv = NULL;

    if (port->enabled == state) {
	return rv;
    }

    if (state == PORT_DISABLED) {
	if (port->acceptfd != -1) {
	    sel_set_fd_read_handler(ser2net_sel,
				    port->acceptfd,
				    SEL_FD_HANDLER_DISABLED);
	    sel_clear_fd_handlers(ser2net_sel, port->acceptfd);
	    close(port->acceptfd);
	    port->acceptfd = -1;
	}
    } else if (port->enabled == PORT_DISABLED) {
	rv = startup_port(port);
    }

    port->enabled = state;

    return rv;
}

static void
free_port(port_info_t *port)
{
    sel_free_timer(port->timer);
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
finish_shutdown_port(port_info_t *port)
{
    int portnum;

    /* To avoid blocking on close if we have written bytes and are in
       flow-control, we flush the output queue. */
    if (port->devfd != -1) {
	sel_clear_fd_handlers(ser2net_sel, port->devfd);
	tcflush(port->devfd, TCOFLUSH);
	close(port->devfd);
	port->devfd = -1;
    }
#ifdef USE_UUCP_LOCKING
    uucp_rm_lock(port->devname);
#endif /* USE_UUCP_LOCKING */
    port->tcp_to_dev_state = PORT_UNCONNECTED;
    buffer_reset(&port->tcp_to_dev);
    port->tcp_bytes_received = 0;
    port->tcp_bytes_sent = 0;
    if (port->banner) {
	free(port->banner->buf);
	free(port->banner);
	port->banner = NULL;
    }
    if (port->devstr) {
	free(port->devstr->buf);
	free(port->devstr);
	port->devstr = NULL;
    }
    if (port->closestr)
	free(port->closestr);
    port->dev_to_tcp_state = PORT_UNCONNECTED;
    buffer_reset(&port->dev_to_tcp);
    port->dev_bytes_received = 0;
    port->dev_bytes_sent = 0;

    portnum = port_from_in_addr(port->tcpport.ss_family,
				(struct sockaddr *) &port->tcpport);
    if (portnum == 0) {
	/* This was a zero port (for stdin/stdout), this is only
	   allowed with one port at a time, and we shut down when it
	   closes. */
	exit(0);
    }

    /* If the port has been disabled, then delete it.  Check this before
       the new config so the port will be deleted properly and not
       reconfigured on a reconfig. */
    if (port->config_num == -1) {
	port_info_t *curr, *prev;

	change_port_state(port, PORT_DISABLED);
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
	    sel_set_fd_handlers(ser2net_sel,
				port->acceptfd,
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

static void
shutdown_port(port_info_t *port, char *reason)
{
    footer_trace(port, reason);
    
    if (port->wt.file != -1) {
	close(port->wt.file);
	if (port->rt.file == port->wt.file)
	    port->rt.file = -1;
	if (port->bt.file == port->wt.file)
	    port->bt.file = -1;
	port->wt.file = -1;
    }
    if (port->rt.file != -1) {
	close(port->rt.file);
	if (port->bt.file == port->rt.file)
	    port->bt.file = -1;
	port->rt.file = -1;
    }
    if (port->bt.file != -1) {
	close(port->bt.file);
	port->bt.file = -1;
    }
    sel_stop_timer(port->timer);
    if (port->tcpfd != -1) {
	sel_clear_fd_handlers(ser2net_sel, port->tcpfd);
	close(port->tcpfd);
	port->tcpfd = -1;
    }

    if (port->devstr) {
	free(port->devstr->buf);
	free(port->devstr);
    }
    port->devstr = process_str_to_buf(port, port->closestr);
    if (port->devstr && (port->devfd != -1)) {
	port->tcp_to_dev_state = PORT_CLOSING;
	sel_set_fd_read_handler(ser2net_sel, port->devfd,
				SEL_FD_HANDLER_DISABLED);
	sel_set_fd_except_handler(ser2net_sel, port->devfd,
				  SEL_FD_HANDLER_DISABLED);
	sel_set_fd_handlers(ser2net_sel,
			    port->devfd,
			    port,
			    NULL,
			    handle_dev_fd_close_write,
			    NULL);
	sel_set_fd_write_handler(ser2net_sel, port->devfd,
				 SEL_FD_HANDLER_ENABLED);
    } else
	finish_shutdown_port(port);
}

void
got_timeout(selector_t  *sel,
	    sel_timer_t *timer,
	    void        *data)
{
    port_info_t *port = (port_info_t *) data;
    struct timeval then;
    unsigned char modemstate;
    int val;

    if (port->timeout) {
	port->timeout_left--;
	if (port->timeout_left < 0) {
	    shutdown_port(port, "timeout");
	    return;
	}
    }

    if (port->is_2217 && (ioctl(port->devfd, TIOCMGET, &val) != -1)) {
	modemstate = 0;
	if (val & TIOCM_CD)
	    modemstate |= 0x80;
	if (val & TIOCM_RI)
	    modemstate |= 0x40;
	if (val & TIOCM_DSR)
	    modemstate |= 0x20;
	if (val & TIOCM_CTS)
	    modemstate |= 0x10;

	modemstate &= port->modemstate_mask;
	if (modemstate != port->last_modemstate) {
	    unsigned char data[3];
	    data[0] = TN_OPT_COM_PORT;
	    data[1] = 107; /* Notify modemstate */
	    data[2] = modemstate;
	    port->last_modemstate = modemstate;
	    telnet_send_option(&port->tn_data, data, 3);
	}
    }
    
    gettimeofday(&then, NULL);
    then.tv_sec += 1;
    sel_start_timer(port->timer, &then);
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

    if (sel_alloc_timer(ser2net_sel,
			got_timeout, new_port,
			&new_port->timer))
    {
	free(new_port);
	return "Could not allocate timer data";
    }

    /* Errors from here on out must goto errout. */
    init_port_data(new_port);

    new_port->portname = malloc(strlen(portnum)+1);
    if (new_port->portname == NULL) {
	rv = "unable to allocate port name";
	goto errout;
    }
    strcpy(new_port->portname, portnum);

    if (scan_tcp_port(new_port->portname, AF_UNSPEC,
		      &new_port->tcpport, &new_port->tcpport_len)
        == -1)
    {
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

    devinit(&(new_port->dinfo.termctl));

    if (devconfig(devcfg, &new_port->dinfo) == -1) {
	  rv = "device configuration invalid";
	  goto errout;
    }

    /* set default signature, if none provided */
    if (!new_port->dinfo.signature)
        new_port->dinfo.signature = rfc2217_signature;

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
		sel_set_fd_handlers(ser2net_sel,
				    new_port->acceptfd,
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
	if (rv)
	    goto errout;
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

void
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

/* Print information about a port to the control port given in cntlr. */
static void
showshortport(struct controller_info *cntlr, port_info_t *port)
{
    char buffer[NI_MAXHOST], portbuff[NI_MAXSERV];
    int  count;
    int  need_space = 0;

    snprintf(buffer, 23, "%-22s", port->portname);
    controller_output(cntlr, buffer, strlen(buffer));

    sprintf(buffer, " %-6s ", enabled_str[port->enabled]);
    controller_output(cntlr, buffer, strlen(buffer));

    sprintf(buffer, "%7d ", port->timeout);
    controller_output(cntlr, buffer, strlen(buffer));

    getnameinfo((struct sockaddr *) &(port->remote), sizeof(port->remote),
		    buffer, sizeof(buffer),
		    portbuff, sizeof(portbuff),
		    NI_NUMERICHOST | NI_NUMERICSERV);
    count = strlen(buffer);
    controller_output(cntlr, buffer, count);
    sprintf(buffer, ",%s ", portbuff);
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
	show_devcfg(cntlr, &(port->dinfo.termctl));
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
    char buffer[NI_MAXHOST], portbuff[NI_MAXSERV];

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
    getnameinfo((struct sockaddr *) &(port->remote), sizeof(port->remote),
		    buffer, sizeof(buffer),
		    portbuff, sizeof(portbuff),
		    NI_NUMERICHOST | NI_NUMERICSERV);
    controller_output(cntlr, buffer, strlen(buffer));
    controller_output(cntlr, ":", 1);
    sprintf(buffer, ",%s ", portbuff);
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
	show_devcfg(cntlr, &(port->dinfo.termctl));
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
	    if (port->tcpfd != -1) {
		reset_timer(port);
	    }
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
	if (devconfig(devcfg, &port->dinfo) == -1)
	{
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
    } else if (port->tcp_to_dev_state == PORT_UNCONNECTED) {
	char *err = "Port not connected: ";
 	controller_output(cntlr, err, strlen(err));
	controller_output(cntlr, portspec, strlen(portspec));
 	controller_output(cntlr, "\n\r", 2);
 	return;
    }
 
    shutdown_port(port, "disconnect");
}

static struct baud_rates_s {
    int real_rate;
    int val;
    int cisco_ios_val;
} baud_rates[] =
{
    { 50, B50, -1 },
    { 75, B75, -1 },
    { 110, B110, -1 },
    { 134, B134, -1 },
    { 150, B150, -1 },
    { 200, B200, -1 },
    { 300, B300, 3 },
    { 600, B600 , 4},
    { 1200, B1200, 5 },
    { 1800, B1800, -1 },
    { 2400, B2400, 6 },
    { 4800, B4800, 7 },
    { 9600, B9600, 8 },
    /* We don't support 14400 baud */
    { 19200, B19200, 10 },
    /* We don't support 28800 baud */
    { 38400, B38400, 12 },
    { 57600, B57600, 13 },
    { 115200, B115200, 14 },
    { 230400, B230400, 15 },
    /* We don't support 460800 baud */
};
#define BAUD_RATES_LEN ((sizeof(baud_rates) / sizeof(struct baud_rates_s)))

int
get_baud_rate(int rate, int *val)
{
    unsigned int i;
    for (i=0; i<BAUD_RATES_LEN; i++) {
	if (cisco_ios_baud_rates) {
	    if (rate == baud_rates[i].cisco_ios_val) {
		*val = baud_rates[i].val;
		return 1;
	    }
	} else {
	    if (rate == baud_rates[i].real_rate) {
		*val = baud_rates[i].val;
		return 1;
	    }
	}
    }

    return 0;
}

void
get_rate_from_baud_rate(int baud_rate, int *val)
{
    unsigned int i;
    for (i=0; i<BAUD_RATES_LEN; i++) {
	if (baud_rate == baud_rates[i].val) {
	    if (cisco_ios_baud_rates) {
		if (baud_rates[i].cisco_ios_val < 0)
		    /* We are at a baud rate unsupported by the
		       enumeration, just return zero. */
		    *val = 0;
		else
		    *val = baud_rates[i].cisco_ios_val;
	    } else {
		*val = baud_rates[i].real_rate;
	    }
	    return;
	}
    }
}

static int
com_port_will(void *cb_data)
{
    port_info_t *port = cb_data;
    unsigned char data[3];
    int val;

    if (! port->dinfo.allow_2217)
	return 0;

    /* The remote end turned on RFC2217 handling. */
    port->is_2217 = 1;
    port->linestate_mask = 0;
    port->modemstate_mask = 255;
    port->last_modemstate = 0;

    
    /* send a modemstate notify */
    data[0] = TN_OPT_COM_PORT;
    data[1] = 107; /* Notify modemstate */
    data[2] = 0;
    if (ioctl(port->devfd, TIOCMGET, &val) != -1) {
	if (val & TIOCM_CD)
	    data[2] |= 0x80;
	if (val & TIOCM_RI)
	    data[2] |= 0x40;
	if (val & TIOCM_DSR)
	    data[2] |= 0x20;
	if (val & TIOCM_CTS)
	    data[2] |= 0x10;
	port->last_modemstate = data[2];
    }
    telnet_send_option(&port->tn_data, data, 3);
    return 1;
}

static void
com_port_handler(void *cb_data, unsigned char *option, int len)
{
    port_info_t *port = cb_data;
    unsigned char outopt[MAX_TELNET_CMD_XMIT_BUF];
    struct termios termio;
    int val;
    
    if (len < 2) 
	return;

    switch (option[1]) {
    case 0: /* SIGNATURE? */
	{
		/* truncate signature, if it exceeds buffer size */
		int sign_len = strlen(port->dinfo.signature);
		if (sign_len > (MAX_TELNET_CMD_XMIT_BUF - 2))
			sign_len = MAX_TELNET_CMD_XMIT_BUF - 2;

		outopt[0] = 44;
		outopt[1] = 100;
		strncpy((char *) outopt+2, port->dinfo.signature, sign_len);
		telnet_send_option(&port->tn_data, outopt, 2 + sign_len);
	break;
	}

    case 1: /* SET-BAUDRATE */
	if (cisco_ios_baud_rates) {
	    if (len < 3)
		return;
	    val = option[2];
	} else {
	    if (len < 6)
		return;
	    /* Basically the same as:
	     *  val = ntohl(*((uint32_t *) (option+2)));
	     * but handled unaligned cases */
	    val = option[2] << 24;
	    val |= option[3] << 16;
	    val |= option[4] << 8;
	    val |= option[5];
	}

	if (tcgetattr(port->devfd, &termio) != -1) {
	    if ((val != 0) && (get_baud_rate(val, &val))) {
		/* We have a valid baud rate. */
		cfsetispeed(&termio, val);
		cfsetospeed(&termio, val);
		tcsetattr(port->devfd, TCSANOW, &termio);
	    }
	    tcgetattr(port->devfd, &termio);
	    val = cfgetispeed(&termio);
	} else {
	    val = 0;
	}
	get_rate_from_baud_rate(val, &val);
	outopt[0] = 44;
	outopt[1] = 101;
	if (cisco_ios_baud_rates) {
	    outopt[2] = val;
	    telnet_send_option(&port->tn_data, outopt, 3);
	} else {
	    /* Basically the same as:
	     * *((uint32_t *) (outopt+2)) = htonl(val);
	     * but handles unaligned cases */
	    outopt[2] = val >> 24;
	    outopt[3] = val >> 16;
	    outopt[4] = val >> 8;
	    outopt[5] = val;
	    telnet_send_option(&port->tn_data, outopt, 6);
	}
	break;

    case 2: /* SET-DATASIZE */
	if (len < 3)
	    return;

	val = 0;
	if (tcgetattr(port->devfd, &termio) != -1) {
	    if ((option[2] >= 5) && (option[2] <= 8)) {
		val = option[2];
		termio.c_cflag &= ~CSIZE;
		switch (val) {
		case 5: termio.c_cflag |= CS5; break;
		case 6: termio.c_cflag |= CS6; break;
		case 7: termio.c_cflag |= CS7; break;
		case 8: termio.c_cflag |= CS8; break;
		}
		tcsetattr(port->devfd, TCSANOW, &termio);
	    }
	    switch (termio.c_cflag & CSIZE) {
	    case CS5: val = 5; break;
	    case CS6: val = 6; break;
	    case CS7: val = 7; break;
	    case CS8: val = 8; break;
	    }
	}
	outopt[0] = 44;
	outopt[1] = 102;
	outopt[2] = val;
	telnet_send_option(&port->tn_data, outopt, 3);
	break;

    case 3: /* SET-PARITY */
	if (len < 3)
	    return;

	val = 0;
	if (tcgetattr(port->devfd, &termio) != -1) {
	    /* We don't support MARK or SPACE parity. */
	    if ((option[2] >= 1) && (option[2] <= 3)) {
		val = option[2];
		termio.c_cflag &= ~(PARENB | PARODD);
		switch (val) {
		case 1: break; /* NONE */
		case 2: termio.c_cflag |= PARENB | PARODD; break; /* ODD */
		case 3: termio.c_cflag |= PARENB; break; /* EVEN */
		}
		tcsetattr(port->devfd, TCSANOW, &termio);
	    }
	    if (termio.c_cflag & PARENB) {
		if (termio.c_cflag & PARODD)
		    val = 2; /* ODD */
		else
		    val = 3; /* EVEN */
	    } else
		val = 1; /* NONE */
	}
	outopt[0] = 44;
	outopt[1] = 103;
	outopt[2] = val;
	telnet_send_option(&port->tn_data, outopt, 3);
	break;

    case 4: /* SET-STOPSIZE */
	if (len < 3)
	    return;

	val = 0;
	if (tcgetattr(port->devfd, &termio) != -1) {
	    /* We don't support 1.5 stop bits, which is value 3. */
	    if ((option[2] == 1) || (option[2] == 2)) {
		val = option[2];
		termio.c_cflag &= ~CSTOPB;
		switch (val) {
		case 1: break; /* 1 stop bit */
		case 2: termio.c_cflag |= CSTOPB; break; /* 2 stop bits */
		}
		tcsetattr(port->devfd, TCSANOW, &termio);
	    }
	    if (termio.c_cflag & CSTOPB)
		val = 2; /* 2 stop bits. */
	    else
		val = 1; /* 1 stop bit. */
	}
	outopt[0] = 44;
	outopt[1] = 104;
	outopt[2] = val;
	telnet_send_option(&port->tn_data, outopt, 3);
	break;

    case 5: /* SET-CONTROL */
	if (len < 3)
	    return;

	val = 0;

	switch (option[2]) {
	case 0:
	case 1:
	case 2:
	case 3:
	    /* Outbound/both flow control */
	    if (tcgetattr(port->devfd, &termio) != -1) {
		if (option[2] != 0) {
		    val = option[2];
		    termio.c_iflag &= ~(IXON | IXOFF);
		    termio.c_cflag &= ~CRTSCTS;
		    switch (val) {
		    case 1: break; /* NONE */
		    case 2: termio.c_iflag |= IXON | IXOFF; break;
		    case 3: termio.c_cflag |= CRTSCTS; break;
		    }
		    tcsetattr(port->devfd, TCSANOW, &termio);
		}
		if (termio.c_cflag & CRTSCTS)
		    val = 3;
		else if (termio.c_iflag & IXON)
		    val = 2;
		else
		    val = 1;
	    }
	    break;

	case 13:
	case 14:
	case 15:
	case 16:
	case 17:
	case 18:
	case 19:
	    /* Inbound flow-control */
	    if (tcgetattr(port->devfd, &termio) != -1) {
		if (option[2] == 15) {
		    /* We can only set XON/XOFF independently */
		    termio.c_iflag |= IXOFF;
		    tcsetattr(port->devfd, TCSANOW, &termio);
		}
		if (termio.c_cflag & CRTSCTS)
		    val = 16;
		else if (termio.c_iflag & IXOFF)
		    val = 15;
		else
		    val = 14;
	    }
	    break;

	/* Handle BREAK stuff. */
	case 6:
	    if (ioctl(port->devfd, TIOCCBRK) != -1)
		port->break_set = 0;
	    goto read_break_val;

	case 5:
	    if (ioctl(port->devfd, TIOCSBRK) != -1)
		port->break_set = 1;
	    goto read_break_val;
	    
	case 4:
	read_break_val:
	    if (port->break_set)
		val = 5;
	    else
		val = 6;
	    break;

	/* DTR handling */
	case 8:
#ifndef __CYGWIN__
	    val = TIOCM_DTR;
	    ioctl(port->devfd, TIOCMBIS, &val);
#else
	    ioctl(port->devfd, TIOCMGET, &val);
	    val |= TIOCM_DTR;
	    ioctl(port->devfd, TIOCMSET, &val);
#endif
	    goto read_dtr_val;

	case 9:
#ifndef __CYGWIN__
	    val = TIOCM_DTR;
	    ioctl(port->devfd, TIOCMBIC, &val);
#else
	    ioctl(port->devfd, TIOCMGET, &val);
	    val &= ~TIOCM_DTR;
	    ioctl(port->devfd, TIOCMSET, &val);
#endif
	    goto read_dtr_val;
	    
	case 7:
	read_dtr_val:
	    if (ioctl(port->devfd, TIOCMGET, &val) == -1)
		val = 7;
	    else if (val & TIOCM_DTR)
		val = 8;
	    else
		val = 9;
	    break;

	/* RTS handling */
	case 11:
#ifndef __CYGWIN__
	    val = TIOCM_RTS;
	    ioctl(port->devfd, TIOCMBIS, &val);
#else
	    ioctl(port->devfd, TIOCMGET, &val);
	    val |= TIOCM_RTS;
	    ioctl(port->devfd, TIOCMSET, &val);
#endif
	    goto read_rts_val;

	case 12:
#ifndef __CYGWIN__
	    val = TIOCM_RTS;
	    ioctl(port->devfd, TIOCMBIC, &val);
#else
	    ioctl(port->devfd, TIOCMGET, &val);
	    val &= ~TIOCM_RTS;
	    ioctl(port->devfd, TIOCMSET, &val);
#endif
	    goto read_rts_val;
	    
	case 10:
	read_rts_val:
	    if (ioctl(port->devfd, TIOCMGET, &val) == -1)
		val = 10;
	    else if (val & TIOCM_RTS)
		val = 11;
	    else
		val = 12;
	    break;
	}

	outopt[0] = 44;
	outopt[1] = 105;
	outopt[2] = val;
	telnet_send_option(&port->tn_data, outopt, 3);
	break;

    case 8: /* FLOWCONTROL-SUSPEND */
	tcflow(port->devfd, TCIOFF);
	outopt[0] = 44;
	outopt[1] = 108;
	telnet_send_option(&port->tn_data, outopt, 2);
	break;

    case 9: /* FLOWCONTROL-RESUME */
	tcflow(port->devfd, TCION);
	outopt[0] = 44;
	outopt[1] = 109;
	telnet_send_option(&port->tn_data, outopt, 2);
	break;

    case 10: /* SET-LINESTATE-MASK */
	if (len < 3)
	    return;
	port->linestate_mask = option[2];
	outopt[0] = 44;
	outopt[1] = 110;
	outopt[2] = port->linestate_mask;
	telnet_send_option(&port->tn_data, outopt, 3);
	break;

    case 11: /* SET-MODEMSTATE-MASK */
	if (len < 3)
	    return;
	port->modemstate_mask = option[2];
	outopt[0] = 44;
	outopt[1] = 111;
	outopt[2] = port->modemstate_mask;
	telnet_send_option(&port->tn_data, outopt, 3);
	break;

    case 12: /* PURGE_DATA */
	if (len < 3)
	    return;

	switch (option[2]) {
	case 1: val = TCIFLUSH; goto purge_found;
	case 2: val = TCOFLUSH; goto purge_found;
	case 3: val = TCIOFLUSH; goto purge_found;
	}
	break;
    purge_found:
	tcflush(port->devfd, val);
	outopt[0] = 44;
	outopt[1] = 112;
	outopt[2] = option[2];
	telnet_send_option(&port->tn_data, outopt, 3);
	break;

    case 6: /* NOTIFY-LINESTATE */
    case 7: /* NOTIFY-MODEMSTATE */
    default:
	break;
    }
}

void
shutdown_ports(void)
{
    port_info_t *port = ports;
    
    while (port != NULL) {
	port->config_num = -1;
	shutdown_port(port, "program shutdown");
	port = port->next;
    }
}

int
check_ports_shutdown(void)
{
    return ports == NULL;
}
