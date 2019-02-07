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

#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <assert.h>
#include <time.h>

#include <gensio/gensio.h>
#include <gensio/sergensio.h>
#include <gensio/argvutils.h>

#include "ser2net.h"
#include "dataxfer.h"
#include "readconfig.h"
#include "led.h"

#define SERIAL "term"
#define NET    "tcp "

/** BASED ON sshd.c FROM openssh.com */
#ifdef HAVE_TCPD_H
#include <tcpd.h>
static char *progname = "ser2net";
#endif /* HAVE_TCPD_H */

/* States for the net_to_dev_state and dev_to_net_state. */
#define PORT_UNCONNECTED		0 /* The TCP port is not connected
                                             to anything right now. */
#define PORT_OPENING			1 /* The device is being set up
					     but it not yet ready. */
#define PORT_WAITING_INPUT		2 /* Waiting for input from the
					     input side. */
#define PORT_WAITING_OUTPUT_CLEAR	3 /* Waiting for output to clear
					     so I can send data. */
#define PORT_CLOSING			4 /* Waiting for output close
					     string to be sent. */
char *state_str[] = { "unconnected", "waiting input", "waiting output",
		      "closing" };

#define PORT_DISABLED		0 /* The port is not open. */
#define PORT_ON			1 /* Port is open. */
char *enabled_str[] = { "off", "on" };

typedef struct trace_info_s
{
    int  hexdump;     /* output each block as a hexdump */
    int  timestamp;   /* preceed each line with a timestamp */
    char *filename;   /* open file.  NULL if not used */
    int  fd;          /* open file.  -1 if not used */
} trace_info_t;

typedef struct port_info port_info_t;
typedef struct net_info net_info_t;

struct gbuf {
    unsigned char *buf;
    gensiods maxsize;
    gensiods cursize;
    gensiods pos;
};

static gensiods
gbuf_room_left(struct gbuf *buf) {
    return buf->maxsize - buf->cursize;
}

static void
gbuf_append(struct gbuf *buf, unsigned char *data, gensiods len)
{
    memcpy(buf->buf + buf->pos, data, len);
    buf->cursize += len;
    buf->pos += len;
}

static gensiods
gbuf_cursize(struct gbuf *buf)
{
    return buf->cursize;
}

static void
gbuf_reset(struct gbuf *buf)
{
    buf->cursize = 0;
    buf->pos = 0;
}

static int
gbuf_init(struct gbuf *buf, gensiods size)
{
    buf->buf = malloc(size);
    if (!buf->buf)
	return ENOMEM;

    buf->maxsize = size;
    buf->cursize = 0;
    buf->pos = 0;
    return 0;
}

struct net_info {
    port_info_t	   *port;		/* My port. */

    bool	   closing;		/* Is the connection in the process
					   of closing? */

    struct gensio   *net;		/* When connected, the network
					   connection, NULL otherwise. */

    bool remote_fixed;			/* Tells if the remote address was
					   set in the configuration, and
					   cannot be changed. */
    bool connect_back;			/* True if we connect to the remote
					   address when data comes in. */
    const char *remote_str;

    gensiods bytes_received;		/* Number of bytes read from the
					   network port. */
    gensiods bytes_sent;		/* Number of bytes written to the
					   network port. */

    struct gbuf *banner;		/* Outgoing banner */

    gensiods write_pos;			/* Our current position in the
					   output buffer where we need
					   to start writing next. */

    int            timeout_left;	/* The amount of time left (in
					   seconds) before the timeout
					   goes off. */

    struct gensio_runner *runshutdown;	/* Used to run things at the
					   base context.  This way we
					   don't have to worry that we
					   are running inside a
					   handler context that needs
					   to be waited for exit. */

    unsigned char linestate_mask;
    unsigned char modemstate_mask;
    bool modemstate_sent;	/* Has a modemstate been sent? */
    bool linestate_sent;	/* Has a linestate been sent? */

    /*
     * If a user gets kicked, store the information for the new user
     * here since we have already accepted the connection or received
     * the packet, we have to store it someplace.
     */
    struct gensio *new_net;
};

struct port_info
{
    struct gensio_lock *lock;
    int            enabled;		/* If PORT_DISABLED, the port
					   is disabled and the
					   accepter is not
					   operational.  If PORT_ON,
					   the port is enabled and
					   will not do any telnet
					   negotiations. */

    int            timeout;		/* The number of seconds to
					   wait without any I/O before
					   we shut the port down. */

    struct gensio_timer *timer;		/* Used to timeout when the no
					   I/O has been seen for a
					   certain period of time. */

    struct gensio_timer *send_timer;	/* Used to delay a bit when
					   waiting for characters to
					   batch up as many characters
					   as possible. */
    bool send_timer_running;

    unsigned int nocon_read_enable_time_left;
    /* Used if a connect back is requested an no connections could
       be made, to try again. */

    /*
     * Used to count timeouts during a shutdown, to make sure close
     * happens in a reasonable amount of time.  If this is zero, this
     * means that shutdown_port_io() has already been called.
     */
    unsigned int shutdown_timeout_count;

    struct gensio_runner *runshutdown;	/* Used to run things at the
					   base context.  This way we
					   don't have to worry that we
					   are running inside a
					   handler context that needs
					   to be waited for exit. */

    int chardelay;                      /* The amount of time to wait after
					   receiving a character before
					   sending it, unless we receive
					   another character.  Based on
					   bit rate. */

    int bps;				/* Bits per second rate. */
    int bpc;				/* Bits per character. */
    int stopbits;
    int paritybits;

    bool enable_chardelay;

    int  chardelay_scale;		/* The number of character
					   periods to wait for the
					   next character, in tenths of
					   a character period. */
    int  chardelay_min;			/* The minimum chardelay, in
					   microseconds. */
    int  chardelay_max;			/* Maximum amount of time to
					   wait before sending the data. */
    struct timeval send_time;		/* When using chardelay, the
					   time when we will send the
					   data, no matter what, set
					   by chardelay_max. */

    /* Information about the network port. */
    char               *portname;       /* The name given for the port. */
    struct gensio_accepter *accepter;	/* Used to receive new connections. */
    bool               remaddr_set;	/* Did a remote address get set? */
    struct port_remaddr *remaddrs;	/* Remote addresses allowed. */
    bool has_connect_back;		/* We have connect back addresses. */
    unsigned int num_waiting_connect_backs;

    int wait_accepter_shutdown;
    bool accepter_reinit_on_shutdown;

    unsigned int max_connections;	/* Maximum number of TCP connections
					   we can accept at a time for this
					   port. */
    net_info_t *netcons;

    gensiods dev_bytes_received;    /* Number of bytes read from the device. */
    gensiods dev_bytes_sent;        /* Number of bytes written to the device. */

    /* Information use when transferring information from the network port
       to the terminal device. */
    int            net_to_dev_state;		/* State of transferring
						   data from the network port
                                                   to the device. */

    struct gbuf    net_to_dev;			/* Buffer for network
						   to dev transfers. */
    struct controller_info *net_monitor; /* If non-null, send any input
					    received from the network port
					    to this controller port. */
    struct gbuf *devstr;		 /* Outgoing string */

    /* Information use when transferring information from the terminal
       device to the network port. */
    int            dev_to_net_state;		/* State of transferring
						   data from the device to
                                                   the network port. */

    struct gbuf dev_to_net;

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

    char *rs485; /* If not NULL, rs485 was specified. */

    /* For RFC 2217 */
    unsigned char last_modemstate;
    unsigned char last_linestate;

    /* Allow RFC 2217 mode */
    bool allow_2217;

    /* Send a break if we get a sync command? */
    int telnet_brk_on_sync;

    /* kickolduser mode */
    int kickolduser_mode;

    /* Banner to display at startup, or NULL if none. */
    char *bannerstr;

    /* RFC 2217 signature. */
    char *signaturestr;

    /* String to send to device at startup, or NULL if none. */
    char *openstr;

    /* String to send to device at close, or NULL if none. */
    char *closestr;

    /*
     * Close on string to shutdown connection when received from
     * serial side, or NULL if none.
     */
    char *closeon;
    gensiods closeon_pos;
    gensiods closeon_len;

    /*
     * Close the session when all the output has been written to the
     * network port.
     */
    bool close_on_output_done;

    /*
     * File to read/write trace, NULL if none.  If the same, then
     * trace information is in the same file, only one open is done.
     */
    trace_info_t trace_read;
    trace_info_t trace_write;
    trace_info_t trace_both;

    /*
     * Pointers to the above, that way if two are the same file we can just
     * set up one and point both to it.
     */
    trace_info_t *tr;
    trace_info_t *tw;
    trace_info_t *tb;

    char *devname;
    struct gensio *io; /* For handling I/O operation to the device */
    void (*dev_write_handler)(port_info_t *);

    /*
     * devname as specified on the line, not the substituted version.  Only
     * non-null if devname was substituted.
     */
    char *orig_devname;

    /*
     * LED to flash for serial traffic
     */
    struct led_s *led_tx;
    struct led_s *led_rx;
};

static void setup_port(port_info_t *port, net_info_t *netcon);
static int handle_net_event(struct gensio *net, void *user_data,
			    int event, int err,
			    unsigned char *buf, gensiods *buflen,
			    const char *const *auxdata);

/*
 * This infrastructure allows a list of addresses to be kept.  This is
 * for checking remote addresses
 */
struct port_remaddr
{
    char *str;
    struct addrinfo *ai;
    bool is_port_set;
    bool is_connect_back;
    struct port_remaddr *next;
};

/* Add a remaddr to the given list, return 0 on success or errno on fail. */
static int
remaddr_append(struct port_remaddr **list, const char *str)
{
    struct port_remaddr *r, *r2;
    struct addrinfo *ai = NULL;
    bool is_port_set = false, is_connect_back = false;
    int socktype, protocol;
    int err = 0;

    if (*str == '!') {
	str++;
	is_connect_back = true;
    } else {
	err = gensio_scan_network_port(so, str, false, &ai,
				       &socktype, &protocol,
				       &is_port_set, NULL, NULL);
	if (err)
	    return err;
	/* FIXME - We currently ignore the socktype and protocol. */
    }

    r = malloc(sizeof(*r));
    if (!r) {
	err = GE_NOMEM;
	goto out;
    }
    memset(r, 0, sizeof(*r));

    r->str = strdup(str);
    if (!r->str) {
	free(r);
	err = GE_NOMEM;
	goto out;
    }
    r->ai = ai;
    r->is_port_set = is_port_set;
    r->is_connect_back = is_connect_back;
    r->next = NULL;

    r2 = *list;
    if (!r2) {
	*list = r;
    } else {
	while (r2->next)
	    r2 = r2->next;
	r2->next = r;
    }

 out:
    if (err && ai)
	gensio_free_addrinfo(so, ai);

    return err;
}

static bool
ai_check(struct addrinfo *ai, const struct sockaddr *addr, socklen_t len,
	 bool is_port_set)
{
    while (ai) {
	if (gensio_sockaddr_equal(addr, len, ai->ai_addr, ai->ai_addrlen,
				  is_port_set))
	    return true;
	ai = ai->ai_next;
    }

    return false;
}

/* Check that the given address matches something in the list. */
static bool
remaddr_check(const struct port_remaddr *list,
	      const struct sockaddr *addr, socklen_t len)
{
    const struct port_remaddr *r = list;

    if (!r)
	return true;

    while (r) {
	if (ai_check(r->ai, addr, len, r->is_port_set))
	    return true;
	r = r->next;
    }

    return false;
}

#define for_each_connection(port, netcon) \
    for (netcon = port->netcons;				\
	 netcon < &(port->netcons[port->max_connections]);	\
	 netcon++)

static struct gensio_lock *ports_lock;
port_info_t *ports = NULL; /* Linked list of ports. */

static void shutdown_one_netcon(net_info_t *netcon, char *reason);
static void shutdown_port(port_info_t *port, char *reason);

/*
 * Like above but does a new line at the end of the output, generally
 * for error output.
 */
static int
cntrl_abserrout(struct absout *o, const char *str, ...)
{
    va_list ap;
    int rv;

    va_start(ap, str);
    rv = controller_voutputf(o->data, str, ap);
    va_end(ap);
    rv += controller_outputf(o->data, "\r\n");
    return rv;
}

static int
num_connected_net(port_info_t *port)
{
    net_info_t *netcon;
    int count = 0;

    for_each_connection(port, netcon) {
	if (netcon->net)
	    count++;
    }

    return count;
}

static net_info_t *
first_live_net_con(port_info_t *port)
{
    net_info_t *netcon;

    for_each_connection(port, netcon) {
	if (netcon->net)
	    return netcon;
    }

    return NULL;
}

static int
init_port_data(port_info_t *port)
{
    port->enabled = PORT_DISABLED;

    port->net_to_dev_state = PORT_UNCONNECTED;
    port->dev_to_net_state = PORT_UNCONNECTED;
    port->trace_read.fd = -1;
    port->trace_write.fd = -1;
    port->trace_both.fd = -1;

    port->allow_2217 = find_default_int("remctl");
    port->telnet_brk_on_sync = find_default_int("telnet_brk_on_sync");
    port->kickolduser_mode = find_default_int("kickolduser");
    port->enable_chardelay = find_default_int("chardelay");
    port->chardelay_scale = find_default_int("chardelay-scale");
    port->chardelay_min = find_default_int("chardelay-min");
    port->chardelay_max = find_default_int("chardelay-max");
    port->dev_to_net.maxsize = find_default_int("dev-to-net-bufsize");
    port->net_to_dev.maxsize = find_default_int("net-to-dev-bufsize");
    port->max_connections = find_default_int("max-connections");

    port->led_tx = NULL;
    port->led_rx = NULL;

    return 0;
}

static void
reset_timer(net_info_t *netcon)
{
    netcon->timeout_left = netcon->port->timeout;
}


static int
timestamp(trace_info_t *t, char *buf, int size)
{
    time_t result;
    if (!t->timestamp)
        return 0;
    result = time(NULL);
    return strftime(buf, size, "%Y/%m/%d %H:%M:%S ", localtime(&result));
}

static int
trace_write_end(char *out, int size, const unsigned char *start, int col)
{
    int pos = 0, w;

    strncat(out, " |", size - pos);
    pos += 2;
    for(w = 0; w < col; w++) {
        pos += snprintf(out + pos, size - pos, "%c",
			isprint(start[w]) ? start[w] : '.');
    }
    strncat(out + pos, "|\n", size - pos);
    pos += 2;
    return pos;
}

int
trace_write(port_info_t *port, trace_info_t *t, const unsigned char *buf,
	    gensiods buf_len, const char *prefix)
{
    int rv = 0, w, col = 0, pos, file = t->fd;
    gensiods q;
    static char out[1024];
    const unsigned char *start;

    if (buf_len == 0)
        return 0;

    if (!t->hexdump)
        return write(file, buf, buf_len);

    pos = timestamp(t, out, sizeof(out));
    pos += snprintf(out + pos, sizeof(out) - pos, "%s ", prefix);

    start = buf;
    for (q = 0; q < buf_len; q++) {
        pos += snprintf(out + pos, sizeof(out) - pos, "%02x ", buf[q]);
        col++;
        if (col >= 8) {
            trace_write_end(out + pos, sizeof(out) - pos, start, col);
            rv = write(file, out, strlen(out));
            if (rv < 0)
                return rv;
            pos = timestamp(t, out, sizeof(out));
            pos += snprintf(out + pos, sizeof(out) - pos, "%s ", prefix);
            col = 0;
            start = buf + q + 1;
        }
    }
    if (col > 0) {
        for (w = 8; w > col; w--) {
            strncat(out + pos, "   ", sizeof(out) - pos);
            pos += 3;
        }
        trace_write_end(out + pos, sizeof(out) - pos, start, col);
        rv = write(file, out, strlen(out));
        if (rv < 0)
            return rv;
    }
    return buf_len;
}

static void
do_trace(port_info_t *port, trace_info_t *t, const unsigned char *buf,
	 gensiods buf_len, const char *prefix)
{
    int rv;

    while (buf_len > 0) {
    retry_write:
	rv = trace_write(port, t, buf, buf_len, prefix);
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

	    close(t->fd);
	    t->fd = -1;
	    return;
	}

	/* Handle a partial write */
	buf_len -= rv;
	buf += rv;
    }
}

static void
hf_out(port_info_t *port, char *buf, int len)
{
    if (port->tr && port->tr->timestamp)
        write_ignore_fail(port->tr->fd, buf, len);

    /* don't output to write file if it's the same as read file */
    if (port->tw && port->tw != port->tr && port->tw->timestamp)
        write_ignore_fail(port->tw->fd, buf, len);

    /* don't output to both file if it's the same as read or write file */
    if (port->tb && port->tb != port->tr && port->tb != port->tw
		&& port->tb->timestamp)
        write_ignore_fail(port->tb->fd, buf, len);
}

static void
header_trace(port_info_t *port, net_info_t *netcon)
{
    char buf[1024];
    trace_info_t tr = { 1, 1, NULL, -1 };
    gensiods len = 0;

    len += timestamp(&tr, buf, sizeof(buf));
    if (sizeof(buf) > len)
	len += snprintf(buf + len, sizeof(buf) - len, "OPEN (");
    gensio_raddr_to_str(netcon->net, &len, buf, sizeof(buf));
    if (sizeof(buf) > len)
	len += snprintf(buf + len, sizeof(buf) - len, ")\n");

    hf_out(port, buf, len);
}

static void
footer_trace(port_info_t *port, char *type, char *reason)
{
    char buf[1024];
    trace_info_t tr = { 1, 1, NULL, -1 };
    int len = 0;

    len += timestamp(&tr, buf, sizeof(buf));
    if (sizeof(buf) > len)
	len += snprintf(buf + len, sizeof(buf) - len,
			"CLOSE %s (%s)\n", type, reason);

    hf_out(port, buf, len);
}

static bool
any_net_data_to_write(port_info_t *port)
{
    net_info_t *netcon;

    for_each_connection(port, netcon) {
	if (!netcon->net)
	    continue;
	if (netcon->write_pos < port->dev_to_net.cursize)
	    return true;
    }
    return false;
}

static void
start_net_send(port_info_t *port)
{
    net_info_t *netcon;

    if (port->dev_to_net_state == PORT_WAITING_OUTPUT_CLEAR)
	return;

    gensio_set_read_callback_enable(port->io, false);
    for_each_connection(port, netcon) {
	if (!netcon->net)
	    continue;
	netcon->write_pos = 0;
	gensio_set_write_callback_enable(netcon->net, true);
    }
    port->dev_to_net_state = PORT_WAITING_OUTPUT_CLEAR;
}

void
send_timeout(struct gensio_timer *timer, void *data)
{
    port_info_t *port = (port_info_t *) data;

    so->lock(port->lock);

    if (port->dev_to_net_state == PORT_CLOSING) {
	so->unlock(port->lock);
	return;
    }

    port->send_timer_running = false;
    if (port->dev_to_net.cursize)
	start_net_send(port);
    so->unlock(port->lock);
}

static void
disable_all_net_read(port_info_t *port)
{
    net_info_t *netcon;

    for_each_connection(port, netcon) {
	if (netcon->net)
	    gensio_set_read_callback_enable(netcon->net, false);
    }
}

static void
enable_all_net_read(port_info_t *port)
{
    net_info_t *netcon;

    for_each_connection(port, netcon) {
	if (netcon->net)
	    gensio_set_read_callback_enable(netcon->net, true);
    }
}

static void
connect_back_done(struct gensio *net, int err, void *cb_data)
{
    net_info_t *netcon = cb_data;
    port_info_t *port = netcon->port;

    so->lock(port->lock);
    if (err) {
	netcon->net = NULL;
	gensio_free(net);
    } else {
	setup_port(port, netcon);
    }
    assert(port->num_waiting_connect_backs > 0);
    port->num_waiting_connect_backs--;
    if (port->num_waiting_connect_backs == 0) {
	if (num_connected_net(port) == 0)
	    /* No connections could be made. */
	    port->nocon_read_enable_time_left = 10;
	else
	    gensio_set_read_callback_enable(port->io, true);
    }
    so->unlock(port->lock);
}

static int
port_check_connect_backs(port_info_t *port)
{
    net_info_t *netcon;
    bool tried = false;

    if (!port->has_connect_back)
	return 0;

    for_each_connection(port, netcon) {
	if (netcon->connect_back && !netcon->net) {
	    int err;

	    tried = true;
	    err = gensio_acc_str_to_gensio(port->accepter, netcon->remote_str,
					   handle_net_event, netcon,
					   &netcon->net);
	    if (err) {
		syslog(LOG_ERR, "Unable to allocate connect back port %s,"
		       " addr %s: %s\n", port->portname, netcon->remote_str,
		       gensio_err_to_str(err));
		continue;
	    }
	    err = gensio_open(netcon->net, connect_back_done, netcon);
	    if (err) {
		gensio_free(netcon->net);
		netcon->net = NULL;
		syslog(LOG_ERR, "Unable to open connect back port %s,"
		       " addr %s: %s\n", port->portname, netcon->remote_str,
		       gensio_err_to_str(err));
		continue;
	    }
	    port->num_waiting_connect_backs++;
	}
    }

    if (tried && !port->num_waiting_connect_backs && !num_connected_net(port)) {
	/*
	 * This is kind of a bad situation.  We got some data, attempted
	 * connects, but failed.  Shut down the read enable for a while.
	 */
	port->nocon_read_enable_time_left = 10;
	gensio_set_read_callback_enable(port->io, false);
    } else if (port->num_waiting_connect_backs) {
	gensio_set_read_callback_enable(port->io, false);
    }

    return port->num_waiting_connect_backs;
}

/* Data is ready to read on the serial port. */
static int
handle_dev_read(port_info_t *port, int err, unsigned char *buf,
		gensiods buflen)
{
    gensiods count = 0;
    bool send_now = false;
    int nr_handlers = 0;

    so->lock(port->lock);
    if (port->dev_to_net_state != PORT_WAITING_INPUT)
	goto out_unlock;

    if (err) {
	if (port->dev_to_net.cursize) {
	    /* Let the output drain before shutdown. */
	    count = 0;
	    send_now = true;
	    goto do_send;
	}

	/* Got an error on the read, shut down the port. */
	syslog(LOG_ERR, "dev read error for device %s: %m", port->portname);
	shutdown_port(port, "dev read error");
    }

    nr_handlers = port_check_connect_backs(port);
    if (nr_handlers > 0)
	goto out_unlock;

    if (gbuf_room_left(&port->dev_to_net) < buflen)
	buflen = gbuf_room_left(&port->dev_to_net);
    count = buflen;

    if (count == 0) {
	gensio_set_read_callback_enable(port->io, false);
	goto out_unlock;
    }

    if (port->closeon) {
	int i;

	for (i = 0; i < count; i++) {
	    if (buf[i] == port->closeon[port->closeon_pos]) {
		port->closeon_pos++;
		if (port->closeon_pos >= port->closeon_len) {
		    port->close_on_output_done = true;
		    /* Ignore everything after the closeon string */
		    count = i + 1;
		    break;
		}
	    } else {
		port->closeon_pos = 0;
	    }
	}
    }

    if (port->tr)
	/* Do read tracing, ignore errors. */
	do_trace(port, port->tr, buf, count, SERIAL);
    if (port->tb)
	/* Do both tracing, ignore errors. */
	do_trace(port, port->tb, buf, count, SERIAL);

    if (port->led_rx)
	led_flash(port->led_rx);

    if (port->dev_monitor != NULL)
	controller_write(port->dev_monitor, (char *) buf, count);

 do_send:
    if (nr_handlers < 0) /* Nobody to handle the data. */
	goto out_unlock;

    gbuf_append(&port->dev_to_net, buf, count);
    port->dev_bytes_received += count;

    if (send_now || gbuf_room_left(&port->dev_to_net) == 0 ||
		port->chardelay == 0) {
    send_it:
	start_net_send(port);
    } else {
	struct timeval then;
	int delay;

	so->get_monotonic_time(so, &then);
	if (port->send_timer_running) {
	    so->stop_timer(port->send_timer);
	} else {
	    port->send_time = then;
	    add_usec_to_timeval(&port->send_time, port->chardelay_max);
	}
	delay = sub_timeval_us(&port->send_time, &then);
	if (delay > port->chardelay)
	    delay = port->chardelay;
	else if (delay < 0) {
	    port->send_timer_running = false;
	    goto send_it;
	}
	add_usec_to_timeval(&then, delay);
	so->start_timer_abs(port->send_timer, &then);
	port->send_timer_running = true;
    }
 out_unlock:
    so->unlock(port->lock);
    return count;
}

static void
handle_dev_write_ready(port_info_t *port)
{
    so->lock(port->lock);
    port->dev_write_handler(port);
    so->unlock(port->lock);
}

static int
handle_dev_event(struct gensio *io, void *user_data, int event, int err,
		 unsigned char *buf, gensiods *buflen,
		 const char *const *auxdata)
{
    port_info_t *port = user_data;
    net_info_t *netcon;

    switch (event) {
    case GENSIO_EVENT_READ:
	*buflen = handle_dev_read(port, err, buf, *buflen);
	return 0;

    case GENSIO_EVENT_WRITE_READY:
	handle_dev_write_ready(port);
	return 0;

    case GENSIO_EVENT_SER_MODEMSTATE:
	so->lock(port->lock);
	port->last_modemstate = *((unsigned int *) buf);
	for_each_connection(port, netcon) {
	    struct sergensio *sio;

	    if (!netcon->net)
		continue;
	    sio = gensio_to_sergensio(netcon->net);
	    if (!sio)
		continue;

	    /*
	     * The 0xf below is non-standard, but the spec makes no
	     * sense in this case.  From what I can tell, the
	     * modemstate top 4 bits is the settings, and the bottom 4
	     * bits is telling you what changed.  So you don't want to
	     * report a value unless something changed, and only if it
	     * was in the modemstate mask.
	     */
	    if (port->last_modemstate & netcon->modemstate_mask & 0xf)
		sergensio_modemstate(sio, (port->last_modemstate &
					   netcon->modemstate_mask));
	}
	so->unlock(port->lock);
	return 0;

    case GENSIO_EVENT_SER_LINESTATE:
	so->lock(port->lock);
	port->last_linestate = *((unsigned int *) buf);
	for_each_connection(port, netcon) {
	    struct sergensio *sio;

	    if (!netcon->net)
		continue;
	    sio = gensio_to_sergensio(netcon->net);
	    if (!sio)
		continue;

	    if (port->last_linestate & netcon->linestate_mask)
		sergensio_linestate(sio, (port->last_linestate &
					  netcon->linestate_mask));
	}
	so->unlock(port->lock);
	return 0;

    default:
	return ENOTSUP;
    }
}

static int
gbuf_write(port_info_t *port, struct gbuf *buf)
{
    int err;
    gensiods written;

    err = gensio_write(port->io, &written, buf->buf + buf->pos,
		       buf->cursize - buf->pos, NULL);
    if (err)
	return err;

    buf->pos += written;
    port->dev_bytes_sent += written;
    if (buf->pos >= buf->cursize) {
	buf->pos = 0;
	buf->cursize = 0;
    }

    return 0;
}

/* The serial port has room to write some data.  This is only activated
   if a write fails to complete, it is deactivated as soon as writing
   is available again. */
static void
dev_fd_write(port_info_t *port, struct gbuf *buf)
{
    int err;

    err = gbuf_write(port, buf);
    if (err) {
	syslog(LOG_ERR, "The dev write for port %s had error: %s",
	       port->portname, gensio_err_to_str(err));
	shutdown_port(port, "dev write error");
	return;
    }

    if (gbuf_cursize(buf) == 0) {
	/* We are done writing, turn the reader back on. */
	enable_all_net_read(port);
	gensio_set_write_callback_enable(port->io, false);
	port->net_to_dev_state = PORT_WAITING_INPUT;
    }
}

static void
handle_dev_fd_normal_write(port_info_t *port)
{
    dev_fd_write(port, &port->net_to_dev);
}

/* Output the devstr buffer */
static void
handle_dev_fd_devstr_write(port_info_t *port)
{
    dev_fd_write(port, port->devstr);
    if (gbuf_cursize(port->devstr) == 0) {
	port->dev_write_handler = handle_dev_fd_normal_write;
	free(port->devstr->buf);
	free(port->devstr);
	port->devstr = NULL;

	/* Send out any data we got on the TCP port. */
	handle_dev_fd_normal_write(port);
    }
}

/* Data is ready to read on the network port. */
static gensiods
handle_net_fd_read(net_info_t *netcon, struct gensio *net, int readerr,
		   unsigned char *buf, gensiods buflen)
{
    port_info_t *port = netcon->port;
    gensiods rv = 0;
    char *reason;
    int err;

    so->lock(port->lock);
    if (port->net_to_dev_state == PORT_WAITING_OUTPUT_CLEAR)
	/* Catch a race here. */
	goto out_unlock;

    if (readerr) {
	if (readerr == ECONNRESET || readerr == EPIPE) {
	    reason = "network read close";
	} else {
	    /* Got an error on the read, shut down the port. */
	    syslog(LOG_ERR, "read error for port %s: %s", port->portname,
		   gensio_err_to_str(readerr));
	    reason = "network read error";
	}
	goto out_shutdown;
    }

    if (buflen > port->net_to_dev.maxsize)
	buflen = port->net_to_dev.maxsize;

    netcon->bytes_received += buflen;

    if (port->net_monitor != NULL)
	controller_write(port->net_monitor, (char *) buf, buflen);

    if (port->tw)
	/* Do write tracing, ignore errors. */
	do_trace(port, port->tw, buf, buflen, NET);
    if (port->tb)
	/* Do both tracing, ignore errors. */
	do_trace(port, port->tb, buf, buflen, NET);

    memcpy(port->net_to_dev.buf, buf, buflen);
    port->net_to_dev.cursize = buflen;

    port->net_to_dev.pos = 0;


    /*
     * Don't write anything to the device until devstr is written.
     * This can happen on UDP ports, we get the first packet before
     * the port is enabled, so there will be data in the output buffer
     * but there will also possibly be devstr data.  We want the
     * devstr data to go out first.
     */
    if (port->devstr)
	goto stop_read_start_write;

    err = gbuf_write(port, &port->net_to_dev);
    if (err) {
	syslog(LOG_ERR, "The dev write for port %s had error: %m",
	       port->portname);
	shutdown_port(port, "dev write error");
	goto out_unlock;
    } else {
	if (port->led_tx)
	    led_flash(port->led_tx);
    }

    if (gbuf_cursize(&port->net_to_dev)) {
	/* We didn't write all the data, shut off the reader and
	   start the write monitor. */
    stop_read_start_write:
	disable_all_net_read(port);
	gensio_set_write_callback_enable(port->io, true);
	port->net_to_dev_state = PORT_WAITING_OUTPUT_CLEAR;
    }

    reset_timer(netcon);

    rv = buflen;

 out_unlock:
    so->unlock(port->lock);
    return rv;

 out_shutdown:
    shutdown_one_netcon(netcon, reason);
    goto out_unlock;
}

/*
 * Write some network data from a buffer.  Returns -1 on something
 * causing the netcon to shut down, 0 if the write was incomplete, and
 * 1 if the write was completed.
 */
static int
net_fd_write(port_info_t *port, net_info_t *netcon,
	     struct gbuf *buf, gensiods *pos)
{
    int reterr, to_send;
    gensiods count = 0;

    to_send = buf->cursize - *pos;
    if (to_send <= 0)
	/* Don't send empty packets, that can confuse UDP clients. */
	return 1;

    /* Can't use buffer send operation here, multiple writers can send
       from the buffers. */
    reterr = gensio_write(netcon->net, &count, buf->buf + *pos, to_send, NULL);
    if (reterr == EPIPE) {
	shutdown_one_netcon(netcon, "EPIPE");
	return -1;
    } else if (reterr) {
	/* Some other bad error. */
	syslog(LOG_ERR, "The network write for port %s had error: %m",
	       port->portname);
	shutdown_one_netcon(netcon, "network write error");
	return -1;
    }
    *pos += count;
    netcon->bytes_sent += count;

    if (*pos < buf->cursize)
	return 0;

    return 1;
}

static bool
finish_dev_to_net_write(port_info_t *port)
{
    if (any_net_data_to_write(port))
	return false;

    port->dev_to_net.cursize = 0;
    port->dev_to_net.pos = 0;

    /* We are done writing on this port, turn the reader back on. */
    gensio_set_read_callback_enable(port->io, true);
    port->dev_to_net_state = PORT_WAITING_INPUT;

    return true;
}

/* The network fd has room to write some data.  This is only activated
   if a write fails to complete, it is deactivated as soon as writing
   is available again. */
static void
handle_net_fd_write_ready(net_info_t *netcon, struct gensio *net)
{
    port_info_t *port = netcon->port;
    int rv = 1;

    so->lock(port->lock);
    if (netcon->banner) {
	rv = net_fd_write(port, netcon, netcon->banner, &netcon->banner->pos);
	if (rv <= 0)
	    goto out_unlock;

	free(netcon->banner->buf);
	free(netcon->banner);
	netcon->banner = NULL;
    }

    if (port->dev_to_net_state == PORT_WAITING_OUTPUT_CLEAR) {
	rv = net_fd_write(port, netcon,
			  &port->dev_to_net, &netcon->write_pos);

	if (rv <= 0)
	    goto out_unlock;

	if (finish_dev_to_net_write(port)) {
	    if (port->close_on_output_done) {
		shutdown_one_netcon(netcon, "closeon sequence found");
		rv = -1;
		goto out_unlock;
	    }
	}
    }

 out_unlock:
    if (rv > 0)
	gensio_set_write_callback_enable(netcon->net, false);

    if (rv >= 0)
	reset_timer(netcon);
    so->unlock(port->lock);
}

enum s2n_ser_ops {
    S2N_BAUD = 0,
    S2N_DATASIZE,
    S2N_PARITY,
    S2N_STOPBITS,
    S2N_FLOWCONTROL,
    S2N_IFLOWCONTROL,
    S2N_BREAK,
    S2N_DTR,
    S2N_RTS
};

static void
sergensio_val_set(struct sergensio *sio, int err,
		  unsigned int val, void *cb_data)
{
    port_info_t *port = sergensio_get_user_data(sio);
    enum s2n_ser_ops op = (long) cb_data;
    net_info_t *netcon;

    so->lock(port->lock);
    for_each_connection(port, netcon) {
	struct sergensio *rsio;

	if (!netcon->net)
	    continue;
	rsio = gensio_to_sergensio(netcon->net);
	if (!rsio)
	    continue;

	switch (op) {
	case S2N_BAUD:
	    port->bps = val;
	    sergensio_baud(rsio, val, NULL, NULL);
	    break;

	case S2N_DATASIZE:
	    port->bpc = val;
	    sergensio_datasize(rsio, val, NULL, NULL);
	    break;

	case S2N_PARITY:
	    if (val == SERGENSIO_PARITY_NONE)
		port->paritybits = 0;
	    else
		port->paritybits = 1;
	    sergensio_parity(rsio, val, NULL, NULL);
	    break;

	case S2N_STOPBITS:
	    port->stopbits = val;
	    sergensio_stopbits(rsio, val, NULL, NULL);
	    break;

	case S2N_FLOWCONTROL:
	    sergensio_flowcontrol(rsio, val, NULL, NULL);
	    break;

	case S2N_IFLOWCONTROL:
	    sergensio_iflowcontrol(rsio, val, NULL, NULL);
	    break;

	case S2N_BREAK:
	    sergensio_sbreak(rsio, val, NULL, NULL);
	    break;

	case S2N_DTR:
	    sergensio_dtr(rsio, val, NULL, NULL);
	    break;

	case S2N_RTS:
	    sergensio_rts(rsio, val, NULL, NULL);
	    break;
	}
    }
    so->unlock(port->lock);
}

static void
s2n_modemstate(net_info_t *netcon, struct sergensio *sio,
	       unsigned int modemstate)
{
    port_info_t *port = netcon->port;

    netcon->modemstate_mask = modemstate;
    sergensio_modemstate(sio, port->last_modemstate & netcon->modemstate_mask);
}

static void
s2n_linestate(net_info_t *netcon, struct sergensio *sio, unsigned int linestate)
{
    port_info_t *port = netcon->port;

    netcon->linestate_mask = linestate;
    sergensio_linestate(sio, port->last_linestate & netcon->linestate_mask);
}

static void
s2n_flowcontrol_state(net_info_t *netcon, struct sergensio *sio, bool val)
{
    struct sergensio *rsio = gensio_to_sergensio(netcon->port->io);

    if (!rsio)
	return;
    sergensio_flowcontrol_state(rsio, val);
}

static void
s2n_flush(net_info_t *netcon, struct sergensio *sio, int val)
{
    struct sergensio *rsio = gensio_to_sergensio(netcon->port->io);

    if (!rsio)
	return;
    sergensio_flush(rsio, val);
}

static void
s2n_baud(net_info_t *netcon, struct sergensio *sio, int baud)
{
    struct sergensio *rsio = gensio_to_sergensio(netcon->port->io);

    if (!rsio)
	return;
    sergensio_baud(rsio, baud,
		   sergensio_val_set, (void *) (long) S2N_BAUD);
}

static void
s2n_datasize(net_info_t *netcon, struct sergensio *sio, int datasize)
{
    struct sergensio *rsio = gensio_to_sergensio(netcon->port->io);

    if (!rsio)
	return;
    sergensio_datasize(rsio, datasize,
		       sergensio_val_set, (void *) (long) S2N_DATASIZE);
}

static void
s2n_parity(net_info_t *netcon, struct sergensio *sio, int parity)
{
    struct sergensio *rsio = gensio_to_sergensio(netcon->port->io);

    if (!rsio)
	return;
    sergensio_parity(rsio, parity,
		     sergensio_val_set, (void *) (long) S2N_PARITY);
}

static void
s2n_stopbits(net_info_t *netcon, struct sergensio *sio, int stopbits)
{
    struct sergensio *rsio = gensio_to_sergensio(netcon->port->io);

    if (!rsio)
	return;
    sergensio_stopbits(rsio, stopbits,
		       sergensio_val_set, (void *) (long) S2N_STOPBITS);
}

static void
s2n_flowcontrol(net_info_t *netcon, struct sergensio *sio, int flowcontrol)
{
    struct sergensio *rsio = gensio_to_sergensio(netcon->port->io);

    if (!rsio)
	return;
    sergensio_flowcontrol(rsio, flowcontrol,
			  sergensio_val_set, (void *) (long) S2N_FLOWCONTROL);
}

static void
s2n_iflowcontrol(net_info_t *netcon, struct sergensio *sio, int iflowcontrol)
{
    struct sergensio *rsio = gensio_to_sergensio(netcon->port->io);

    if (!rsio)
	return;
    sergensio_iflowcontrol(rsio, iflowcontrol,
			   sergensio_val_set, (void *) (long) S2N_IFLOWCONTROL);
}

static void
s2n_sbreak(net_info_t *netcon, struct sergensio *sio, int breakv)
{
    struct sergensio *rsio = gensio_to_sergensio(netcon->port->io);

    if (!rsio)
	return;
    sergensio_sbreak(rsio, breakv,
		     sergensio_val_set, (void *) (long) S2N_BREAK);
}

static void
s2n_dtr(net_info_t *netcon, struct sergensio *sio, int dtr)
{
    struct sergensio *rsio = gensio_to_sergensio(netcon->port->io);

    if (!rsio)
	return;
    sergensio_dtr(rsio, dtr, sergensio_val_set, (void *) (long) S2N_DTR);
}

static void
s2n_rts(net_info_t *netcon, struct sergensio *sio, int rts)
{
    struct sergensio *rsio = gensio_to_sergensio(netcon->port->io);

    if (!rsio)
	return;
    sergensio_rts(rsio, rts, sergensio_val_set, (void *) (long) S2N_RTS);
}

static void
s2n_signature(net_info_t *netcon, struct sergensio *sio, char *sig,
	      unsigned int sig_len)
{
    port_info_t *port = netcon->port;

    sig = port->signaturestr;
    if (!sig)
	sig = rfc2217_signature;
    sig_len = strlen(sig);

    sergensio_signature(sio, sig, sig_len, NULL, NULL);
}

static void
s2n_sync(net_info_t *netcon, struct sergensio *sio)
{
    struct sergensio *rsio = gensio_to_sergensio(netcon->port->io);

    if (!rsio)
	return;
    sergensio_send_break(rsio);
}

static void
s2n_break(net_info_t *netcon, struct gensio *io)
{
    struct sergensio *rsio = gensio_to_sergensio(netcon->port->io);

    if (!rsio)
	return;
    sergensio_send_break(rsio);
}

static int
handle_net_event(struct gensio *net, void *user_data, int event, int err,
		 unsigned char *buf, gensiods *buflen,
		 const char *const *auxdata)
{
    net_info_t *netcon = user_data;

    switch (event) {
    case GENSIO_EVENT_READ:
	*buflen = handle_net_fd_read(netcon, net, err, buf, *buflen);
	return 0;

    case GENSIO_EVENT_WRITE_READY:
	handle_net_fd_write_ready(netcon, net);
	return 0;

    case GENSIO_EVENT_SEND_BREAK:
	s2n_break(netcon, net);
	return 0;

    case GENSIO_EVENT_SER_MODEMSTATE:
	s2n_modemstate(netcon, gensio_to_sergensio(net),
		       *((unsigned int *) buf));
	return 0;

    case GENSIO_EVENT_SER_LINESTATE:
	s2n_linestate(netcon, gensio_to_sergensio(net), *((unsigned int *) buf));
	return 0;

    case GENSIO_EVENT_SER_SIGNATURE:
	s2n_signature(netcon, gensio_to_sergensio(net), (char *) buf, *buflen);
	return 0;

    case GENSIO_EVENT_SER_FLOW_STATE:
	s2n_flowcontrol_state(netcon, gensio_to_sergensio(net), *((int *) buf));
	return 0;

    case GENSIO_EVENT_SER_FLUSH:
	s2n_flush(netcon, gensio_to_sergensio(net), *((int *) buf));
	return 0;

    case GENSIO_EVENT_SER_SYNC:
	s2n_sync(netcon, gensio_to_sergensio(net));
	return 0;

    case GENSIO_EVENT_SER_BAUD:
	s2n_baud(netcon, gensio_to_sergensio(net), *((int *) buf));
	return 0;

    case GENSIO_EVENT_SER_DATASIZE:
	s2n_datasize(netcon, gensio_to_sergensio(net), *((int *) buf));
	return 0;

    case GENSIO_EVENT_SER_PARITY:
	s2n_parity(netcon, gensio_to_sergensio(net), *((int *) buf));
	return 0;

    case GENSIO_EVENT_SER_STOPBITS:
	s2n_stopbits(netcon, gensio_to_sergensio(net), *((int *) buf));
	return 0;

    case GENSIO_EVENT_SER_FLOWCONTROL:
	s2n_flowcontrol(netcon, gensio_to_sergensio(net), *((int *) buf));
	return 0;

    case GENSIO_EVENT_SER_IFLOWCONTROL:
	s2n_iflowcontrol(netcon, gensio_to_sergensio(net), *((int *) buf));
	return 0;

    case GENSIO_EVENT_SER_SBREAK:
	s2n_sbreak(netcon, gensio_to_sergensio(net), *((int *) buf));
	return 0;

    case GENSIO_EVENT_SER_DTR:
	s2n_dtr(netcon, gensio_to_sergensio(net), *((int *) buf));
	return 0;

    case GENSIO_EVENT_SER_RTS:
	s2n_rts(netcon, gensio_to_sergensio(net), *((int *) buf));
	return 0;

    default:
	return ENOTSUP;
    }
}

static void handle_net_fd_closed(struct gensio *net, void *cb_data);

/* Checks to see if some other port has the same device in use.  Must
   be called with ports_lock held. */
static int
is_device_already_inuse(port_info_t *check_port)
{
    port_info_t *port = ports;

    while (port != NULL) {
	if (port != check_port) {
	    if ((strcmp(port->devname, check_port->devname) == 0)
		&& (port->net_to_dev_state != PORT_UNCONNECTED))
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
process_str(port_info_t *port, net_info_t *netcon,
	    struct tm *time, struct timeval *tv,
	    const char *s,
	    void (*op)(void *data, char val), void *data, int isfilename)
{
    char val;
    char *t, *s2;

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

	    case 'd': /* Actual device name */
	    case 'o': /* Device name on config line */
		/* ser2net device name. */
		if (*s == 'o' && port->orig_devname)
		    s2 = port->orig_devname;
		else
		    s2 = port->devname;

		if (isfilename) {
		    /* Can't have '/' in a filename. */
		    t = strrchr(s2, '/');
		    if (t)
			t++;
		    else
			t = s2;
		} else
		    t = s2;
		for (; *t; t++)
		    op(data, *t);
		break;

	    case 'p':
		/* ser2net network port. */
		for (t = port->portname; *t; t++)
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
		    char str[1024];
		    int err;

		    err = gensio_raddr_to_str(port->io, NULL, str, sizeof(str));
		    if (err)
			break;
		    t = strchr(str, ',');
		    if (!t)
			break;
		    for (; *t && *t != ' '; t++)
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
		op(data, val);
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
		op(data, val);
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

		if (!netcon)
		    netcon = first_live_net_con(port);
		if (!netcon)
		    break;
		if (gensio_raddr_to_str(netcon->net, NULL, ip, sizeof(ip)))
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
    gensiods *idata = data;

    (*idata)++;
}

struct bufop_data {
    gensiods pos;
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
process_str_to_str(port_info_t *port, net_info_t *netcon,
		   const char *str, struct timeval *tv,
		   gensiods *lenrv, int isfilename)
{
    gensiods len = 0;
    struct tm now;
    struct bufop_data bufop;

    localtime_r(&tv->tv_sec, &now);
    process_str(port, netcon, &now, tv, str, count_op, &len, isfilename);
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
    process_str(port, netcon, &now, tv, str, buffer_op, &bufop, isfilename);

    if (lenrv)
	*lenrv = len;
    else
	bufop.str[bufop.pos] = '\0';

    return bufop.str;
}

static struct gbuf *
process_str_to_buf(port_info_t *port, net_info_t *netcon, const char *str)
{
    char *bstr;
    struct gbuf *buf;
    gensiods len;
    struct timeval tv;

    if (!str || *str == '\0')
	return NULL;
    gettimeofday(&tv, NULL);

    buf = malloc(sizeof(*buf));
    if (!buf) {
	syslog(LOG_ERR, "Out of memory processing string: %s", port->portname);
	return NULL;
    }
    bstr = process_str_to_str(port, netcon, str, &tv, &len, 0);
    if (!bstr) {
	free(buf);
	syslog(LOG_ERR, "Error processing string: %s", port->portname);
	return NULL;
    }
    buf->buf = (unsigned char *) bstr;
    buf->maxsize = len;
    buf->pos = 0;
    buf->cursize = len;

    return buf;
}

static void
open_trace_file(port_info_t *port,
                trace_info_t *t,
                struct timeval *tv,
                trace_info_t **out)
{
    int rv;
    char *trfile;

    trfile = process_str_to_str(port, NULL, t->filename, tv, NULL, 1);
    if (!trfile) {
	syslog(LOG_ERR, "Unable to translate trace file %s", t->filename);
	t->fd = -1;
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

    free(trfile);
    t->fd = rv;
    *out = t;
}

static void
setup_trace(port_info_t *port)
{
    struct timeval tv;

    /* Only get the time once so all trace files have consistent times. */
    gettimeofday(&tv, NULL);

    port->tw = NULL;
    if (port->trace_write.filename)
	open_trace_file(port, &port->trace_write, &tv, &port->tw);

    port->tr = NULL;
    if (port->trace_read.filename) {
	trace_info_t *np = &port->trace_read;
	if (port->tw && (strcmp(np->filename, port->tw->filename) == 0))
	    port->tr = port->tw;
	else
	    open_trace_file(port, np, &tv, &port->tr);
    }

    port->tb = NULL;
    if (port->trace_both.filename) {
	trace_info_t *np = &port->trace_both;
	if (port->tw && (strcmp(np->filename, port->tw->filename) == 0))
	    port->tb = port->tw;
	else if (port->tr && (strcmp(np->filename, port->tr->filename) == 0))
	    port->tb = port->tr;
	else
	    open_trace_file(port, np, &tv, &port->tb);
    }

    return;
}

static void
recalc_port_chardelay(port_info_t *port)
{
    int bpc = port->bpc + port->stopbits + port->paritybits + 1;

    /* delay is (((1 / bps) * bpc) * scale) seconds */
    if (!port->enable_chardelay) {
	port->chardelay = 0;
	return;
    }

    /* We are working in microseconds here. */
    port->chardelay = (bpc * 100000 * port->chardelay_scale) / port->bps;
    if (port->chardelay < port->chardelay_min)
	port->chardelay = port->chardelay_min;
}

static void
finish_setup_net(port_info_t *port, net_info_t *netcon)
{
    gensio_set_callback(netcon->net, handle_net_event, netcon);

    gensio_set_read_callback_enable(netcon->net, true);
    port->net_to_dev_state = PORT_WAITING_INPUT;

    gensio_set_write_callback_enable(netcon->net, true);

    header_trace(port, netcon);

    reset_timer(netcon);
}

static void
extract_bps_bpc(port_info_t *port)
{
    int err;
    char buf[1024], *s, *speed;

    err = gensio_raddr_to_str(port->io, NULL, buf, sizeof(buf));
    if (err)
	goto out_broken;

    s = strchr(buf, ',');
    if (!s)
	goto out_broken;

    speed = s;
    while (isdigit(*s))
	s++;
    if (s == speed)
	goto out_broken;
    port->bps = strtoul(speed, NULL, 10);

    if (*s == 'N')
	port->paritybits = 0;
    else
	port->paritybits = 1;
    if (*s)
	s++;

    if (isdigit(*s))
	port->bpc = *s = '0';
    else
	port->bpc = 8;
    if (*s)
	s++;

    if (*s == '2')
	port->stopbits = 2;
    else
	port->stopbits = 1;
    return;

 out_broken:
    port->bps = 9600;
    port->paritybits = 0;
    port->stopbits = 1;
    port->bpc = 8;
}

static void
port_dev_open_done(struct gensio *io, int err, void *cb_data)
{
    port_info_t *port = cb_data;
    net_info_t *netcon;
    struct timeval timeout;

    so->lock(port->lock);
    if (err) {
	const char *errstr = gensio_err_to_str(err);

	for_each_connection(port, netcon) {
	    if (!netcon->net)
		continue;
	    gensio_write(netcon->net, NULL, errstr, strlen(errstr), NULL);
	    gensio_free(netcon->net);
	    netcon->net = NULL;
	}
	port->dev_to_net_state = PORT_UNCONNECTED;
	goto out_unlock;
    }

    extract_bps_bpc(port);
    recalc_port_chardelay(port);

    if (port->devstr) {
	free(port->devstr->buf);
	free(port->devstr);
    }
    port->devstr = process_str_to_buf(port, NULL, port->openstr);
    if (port->devstr)
	port->dev_write_handler = handle_dev_fd_devstr_write;
    else
	port->dev_write_handler = handle_dev_fd_normal_write;

    if (port->devstr)
	gensio_set_write_callback_enable(port->io, true);
    gensio_set_read_callback_enable(port->io, true);
    port->dev_to_net_state = PORT_WAITING_INPUT;

    setup_trace(port);

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    so->start_timer(port->timer, &timeout);

    for_each_connection(port, netcon) {
	if (!netcon->net)
	    continue;
	finish_setup_net(port, netcon);
    }
 out_unlock:
    so->unlock(port->lock);
}

static int
port_dev_enable(port_info_t *port)
{
    int err;
    char auxdata[2] = "1";

    err = gensio_open(port->io, port_dev_open_done, port);
    if (err)
	return err;

    err = gensio_control(port->io, GENSIO_CONTROL_DEPTH_ALL, false,
			 GENSIO_CONTROL_NODELAY, auxdata, NULL);
    if (err)
	syslog(LOG_ERR, "Could not enable NODELAY on port %s: %m",
	       port->portname);

    port->dev_to_net_state = PORT_OPENING;
    return 0;
}

/* Called when a new user is added to the port. */
static void
setup_port(port_info_t *port, net_info_t *netcon)
{
    int err;
    char auxdata[2] = "1";

    err = gensio_control(netcon->net, GENSIO_CONTROL_DEPTH_ALL, false,
			 GENSIO_CONTROL_NODELAY, auxdata, NULL);
    if (err)
	syslog(LOG_ERR, "Could not enable NODELAY on socket %s: %m",
	       port->portname);

    if (netcon->banner) {
	free(netcon->banner->buf);
	free(netcon->banner);
    }
    netcon->banner = process_str_to_buf(port, netcon, port->bannerstr);

    if (port->dev_to_net_state == PORT_OPENING)
	/* Nothing to do, after the port is open it will finish. */
	return;

    if (num_connected_net(port) == 1 && !port->has_connect_back) {
	/* We are first, set things up on the device. */
	err = port_dev_enable(port);
	if (err) {
	    const char *errstr = gensio_err_to_str(err);

	    gensio_write(netcon->net, NULL, errstr, strlen(errstr), NULL);
	    gensio_free(netcon->net);
	    netcon->net = NULL;
	}
	return;
    }

    finish_setup_net(port, netcon);
}

/* Returns with the port locked, if non-NULL. */
static port_info_t *
find_rotator_port(const char *portname, struct gensio *net,
		  unsigned int *netconnum)
{
    port_info_t *port = ports;

    while (port) {
	if (strcmp(port->portname, portname) == 0) {
	    unsigned int i;
	    struct sockaddr_storage addr;
	    gensiods socklen;
	    int err;

	    so->lock(port->lock);
	    if (port->enabled == PORT_DISABLED)
		goto next;
	    if (port->dev_to_net_state == PORT_CLOSING)
		goto next;
	    socklen = sizeof(addr);
	    err = gensio_get_raddr(net, &addr, &socklen);
	    if (err)
		goto next;
	    if (!remaddr_check(port->remaddrs,
			       (struct sockaddr *) &addr, socklen))
		goto next;
	    if (port->net_to_dev_state == PORT_UNCONNECTED &&
		is_device_already_inuse(port))
		goto next;

	    for (i = 0; i < port->max_connections; i++) {
		if (!port->netcons[i].net) {
		    *netconnum = i;
		    return port;
		}
	    }
	next:
	    so->unlock(port->lock);
	}
	port = port->next;
    }

    return NULL;
}

static void
handle_new_net(port_info_t *port, struct gensio *net, net_info_t *netcon)
{
    netcon->net = net;

    /* XXX log netcon->remote */
    setup_port(port, netcon);
}

int gensio_log_level_to_syslog(int gloglevel)
{
    switch (gloglevel) {
    case GENSIO_LOG_FATAL:
	return LOG_EMERG;
    case GENSIO_LOG_ERR:
	return LOG_ERR;
    case GENSIO_LOG_WARNING:
	return LOG_WARNING;
    case GENSIO_LOG_INFO:
	return LOG_INFO;
    }
    return LOG_ERR;
}

static void
do_gensio_log(const char *name, struct gensio_loginfo *i)
{
    char buf[256];

    vsnprintf(buf, sizeof(buf), i->str, i->args);
    syslog(gensio_log_level_to_syslog(i->level), "%s: %s", name, buf);
}

typedef struct rotator
{
    /* Rotators use the ports_lock for mutex. */
    int curr_port;
    const char **portv;
    int portc;

    char *portname;

    struct gensio_accepter *accepter;

    struct rotator *next;
} rotator_t;

static rotator_t *rotators = NULL;

/* A connection request has come in on a port. */
static int
handle_rot_child_event(struct gensio_accepter *accepter, void *user_data,
		       int event, void *data)
{
    rotator_t *rot = user_data;
    int i;
    const char *err;
    struct gensio *net;

    if (event == GENSIO_ACC_EVENT_LOG) {
	do_gensio_log(rot->portname, data);
	return 0;
    }

    if (event != GENSIO_ACC_EVENT_NEW_CONNECTION)
	return ENOTSUP;

    net = data;
    so->lock(ports_lock);
    i = rot->curr_port;
    do {
	unsigned int netconnum = 0;
	port_info_t *port = find_rotator_port(rot->portv[i], net, &netconnum);

	if (++i >= rot->portc)
	    i = 0;
	if (port) {
	    rot->curr_port = i;
	    so->unlock(ports_lock);
	    handle_new_net(port, net, &port->netcons[netconnum]);
	    so->unlock(port->lock);
	    return 0;
	}
    } while (i != rot->curr_port);
    so->unlock(ports_lock);

    err = "No free port found\r\n";
    gensio_write(net, NULL, err, strlen(err), NULL);
    gensio_free(net);
    return 0;
}

static struct gensio_waiter *rotator_shutdown_wait;

static void
handle_rot_shutdown_done(struct gensio_accepter *accepter, void *cb_data)
{
    so->wake(rotator_shutdown_wait);
}

static void
free_rotator(rotator_t *rot)
{
    if (rot->accepter) {
	gensio_acc_shutdown(rot->accepter, handle_rot_shutdown_done, NULL);
	so->wait(rotator_shutdown_wait, 1, NULL);
	gensio_acc_free(rot->accepter);
    }
    if (rot->portname)
	free(rot->portname);
    if (rot->portv)
	gensio_argv_free(so, rot->portv);
    free(rot);
}

void
free_rotators(void)
{
    rotator_t *rot, *next;

    rot = rotators;
    while (rot) {
	next = rot->next;
	free_rotator(rot);
	rot = next;
    }
    rotators = NULL;
}

int
add_rotator(char *portname, char *ports, int lineno)
{
    rotator_t *rot;
    int rv;

    rot = malloc(sizeof(*rot));
    if (!rot)
	return ENOMEM;
    memset(rot, 0, sizeof(*rot));

    rot->portname = strdup(portname);
    if (!rot->portname) {
	free_rotator(rot);
	return ENOMEM;
    }

    rv = gensio_str_to_argv(so, ports, &rot->portc, &rot->portv, NULL);
    if (rv)
	goto out;

    rv = str_to_gensio_accepter(rot->portname, so,
				handle_rot_child_event, rot, &rot->accepter);
    if (rv) {
	syslog(LOG_ERR, "port was invalid on line %d", lineno);
	goto out;
    }

    rot->next = rotators;
    rotators = rot;

    rv = gensio_acc_startup(rot->accepter);
    if (rv) {
	syslog(LOG_ERR, "Failed to start rotator on line %d: %s", lineno,
	       gensio_err_to_str(rv));
	goto out;
    }

 out:
    if (rv)
	free_rotator(rot);
    return rv;
}

static void
kick_old_user(port_info_t *port, net_info_t *netcon, struct gensio *new_net)
{
    char *err = "kicked off, new user is coming\r\n";

    /* If another user is waiting for a kick, kick that user. */
    if (netcon->new_net) {
	gensio_write(netcon->new_net, NULL, err, strlen(err), NULL);
	gensio_free(netcon->new_net);
    }

    /* Wait it to be unconnected and clean, restart the process. */
    netcon->new_net = new_net;

    shutdown_one_netcon(netcon, err);
}

static void
check_port_new_net(port_info_t *port, net_info_t *netcon)
{
    struct gensio *net;

    if (!netcon->new_net)
	return;

    if (!netcon->net) {
	/* Something snuck in before, kick this one out. */
	char *err = "kicked off, new user is coming\r\n";

	gensio_write(netcon->new_net, NULL, err, strlen(err), NULL);
	gensio_free(netcon->new_net);
	netcon->new_net = NULL;
	return;
    }

    net = netcon->new_net;
    netcon->new_net = NULL;
    handle_new_net(port, net, netcon);
}

/* A connection request has come in on a port. */
static int
handle_port_child_event(struct gensio_accepter *accepter, void *user_data,
			int event, void *data)
{
    port_info_t *port = user_data;
    const char *err = NULL;
    unsigned int i, j;
    struct sockaddr_storage addr;
    gensiods socklen;
    struct gensio *net;

    if (event == GENSIO_ACC_EVENT_LOG) {
	do_gensio_log(port->portname, data);
	return 0;
    }

    if (event != GENSIO_ACC_EVENT_NEW_CONNECTION)
	return ENOTSUP;

    net = data;
    so->lock(ports_lock); /* For is_device_already_inuse() */
    so->lock(port->lock);

    if (port->enabled == PORT_DISABLED) {
	err = "Port disabled\r\n";
	goto out_err;
    }

    /* We raced, the shutdown should disable the accept read
       until the shutdown is complete. */
    if (port->dev_to_net_state == PORT_CLOSING) {
	err = "Port closing\r\n";
	goto out_err;
    }

    socklen = sizeof(addr);
    if (!gensio_get_raddr(net, &addr, &socklen)) {
	if (!remaddr_check(port->remaddrs,
			   (struct sockaddr *) &addr, socklen)) {
	    err = "Accessed denied due to your net address\r\n";
	    goto out_err;
	}
    }

    for (j = port->max_connections, i = 0; i < port->max_connections; i++) {
	if (!port->netcons[i].net && !port->netcons[i].remote_fixed)
	    break;
	if (!port->netcons[i].remote_fixed)
	    j = i;
    }

    if (i == port->max_connections) {
	if (port->kickolduser_mode && j < port->max_connections) {
	    /* Kick off the first non-fixed user. */
	    kick_old_user(port, &port->netcons[j], net);
	    goto out;
	}

	err = "Port already in use\r\n";
    }

    if (!err && is_device_already_inuse(port))
	err = "Port's device already in use\r\n";

    if (err) {
    out_err:
	so->unlock(port->lock);
	so->unlock(ports_lock);
	gensio_write(net, NULL, err, strlen(err), NULL);
	gensio_free(net);
	return 0;
    }

    /* We have to hold the ports_lock until after this call so the
       device won't get used (from is_device_already_inuse()). */
    handle_new_net(port, net, &(port->netcons[i]));
 out:
    so->unlock(port->lock);
    so->unlock(ports_lock);
    return 0;
}

static void
process_remaddr(struct absout *eout, port_info_t *port, struct port_remaddr *r,
                bool is_reconfig)
{
    net_info_t *netcon;

    if (!r->is_connect_back)
	return;

    for_each_connection(port, netcon) {
        if (netcon->remote_fixed)
            continue;

	netcon->remote_fixed = true;
	netcon->remote_str = r->str;
	port->has_connect_back = true;
	netcon->connect_back = true;
	return;
    }

    if (eout)
	eout->out(eout, "Too many remote addresses specified for the"
		  " max-connections given");
}

static int
startup_port(struct absout *eout, port_info_t *port, bool is_reconfig)
{
    int err = gensio_acc_startup(port->accepter);
    struct port_remaddr *r;

    if (err && eout) {
	eout->out(eout, "Unable to startup network port %s: %s",
		  port->portname, gensio_err_to_str(err));
	return err;
    }

    for (r = port->remaddrs; r; r = r->next)
	process_remaddr(eout, port, r, is_reconfig);

    if (port->has_connect_back) {
	err = port_dev_enable(port);
	if (err && eout)
	    eout->out(eout, "Unable to enable port device %s: %s",
		      port->portname, gensio_err_to_str(err));
	if (err)
	    gensio_acc_shutdown(port->accepter, NULL, NULL);
    }

    return err;
}

static void
port_reinit_now(port_info_t *port)
{
    if (port->enabled != PORT_DISABLED) {
	net_info_t *netcon;

	port->dev_to_net_state = PORT_UNCONNECTED;
	gensio_acc_set_accept_callback_enable(port->accepter, true);
	for_each_connection(port, netcon)
	    check_port_new_net(port, netcon);
    }
}

static struct gensio_waiter *accepter_shutdown_wait;

static void
handle_port_shutdown_done(struct gensio_accepter *accepter, void *cb_data)
{
    port_info_t *port = gensio_acc_get_user_data(accepter);

    so->lock(port->lock);
    while (port->wait_accepter_shutdown--)
	so->wake(accepter_shutdown_wait);

    if (port->accepter_reinit_on_shutdown) {
	port->accepter_reinit_on_shutdown = false;
	port_reinit_now(port);
    }
    so->unlock(port->lock);
}

static bool
change_port_state(struct absout *eout, port_info_t *port, int state,
		  bool is_reconfig)
{
    if (port->enabled == state)
	return false;

    if (state == PORT_DISABLED) {
	port->enabled = PORT_DISABLED; /* Stop accepts */
	if (port->wait_accepter_shutdown || port->accepter_reinit_on_shutdown)
	    /* Shutdown is already running. */
	    return true;
	return gensio_acc_shutdown(port->accepter,
				  handle_port_shutdown_done, NULL) == 0;
    } else {
	if (port->enabled == PORT_DISABLED) {
	    int rv = startup_port(eout, port, is_reconfig);
	    if (!rv)
		port->enabled = state;
	}
    }

    return false;
}

static void
wait_for_port_shutdown(port_info_t *port, unsigned int *count)
{
    port->wait_accepter_shutdown++;
    (*count)++;
}

static void
free_port(port_info_t *port)
{
    net_info_t *netcon;
    struct port_remaddr *r;

    if (port->netcons) {
	for_each_connection(port, netcon) {
	    char *err = "Port was deleted\n\r";
	    if (netcon->new_net) {
		gensio_write(netcon->new_net, NULL, err, strlen(err), NULL);
		gensio_free(netcon->new_net);
	    }
	    if (netcon->runshutdown)
		so->free_runner(netcon->runshutdown);
	}
    }

    so->free_lock(port->lock);
    while (port->remaddrs) {
	r = port->remaddrs;
	port->remaddrs = r->next;
	gensio_free_addrinfo(so, r->ai);
	free(r->str);
	free(r);
    }
    if (port->accepter)
	gensio_acc_free(port->accepter);
    if (port->dev_to_net.buf)
	free(port->dev_to_net.buf);
    if (port->net_to_dev.buf)
	free(port->net_to_dev.buf);
    if (port->timer)
	so->free_timer(port->timer);
    if (port->send_timer)
	so->free_timer(port->send_timer);
    if (port->runshutdown)
	so->free_runner(port->runshutdown);
    if (port->io)
	gensio_free(port->io);
    if (port->trace_read.filename)
	free(port->trace_read.filename);
    if (port->trace_write.filename)
	free(port->trace_write.filename);
    if (port->trace_both.filename)
	free(port->trace_both.filename);
    if (port->devname)
	free(port->devname);
    if (port->portname)
	free(port->portname);
    if (port->new_config)
	free_port(port->new_config);
    if (port->bannerstr)
	free(port->bannerstr);
    if (port->signaturestr)
	free(port->signaturestr);
    if (port->openstr)
	free(port->openstr);
    if (port->closestr)
	free(port->closestr);
    if (port->closeon)
	free(port->closeon);
    if (port->netcons)
	free(port->netcons);
    if (port->orig_devname)
	free(port->orig_devname);
    free(port);
}

/*
 * Returns true if this requested a net shutdown, false if not.
 */
static bool
switchout_port(struct absout *eout, port_info_t *new_port,
	       port_info_t *curr, port_info_t *prev)
{
    int new_state = new_port->enabled;
    struct gensio_accepter *tmp_accepter;
    int i;

    new_port->enabled = curr->enabled;

    /* Keep the same accepter structure. */
    tmp_accepter = new_port->accepter;
    new_port->accepter = curr->accepter;
    curr->accepter = tmp_accepter;
    gensio_acc_set_user_data(curr->accepter, curr);
    gensio_acc_set_user_data(new_port->accepter, new_port);

    for (i = 0; i < new_port->max_connections; i++) {
	if (i >= curr->max_connections)
	    break;
	if (!curr->netcons[i].net)
	    continue;
	new_port->netcons[i].net = curr->netcons[i].net;
    }

    if (prev == NULL) {
	ports = new_port;
    } else {
	prev->next = new_port;
    }
    new_port->next = curr->next;
    so->unlock(curr->lock);
    free_port(curr);

    return change_port_state(eout, new_port, new_state, true);
}

static void
finish_shutdown_port(port_info_t *port)
{
    bool reinit_now = true;

    /*
     * At this point nothing can happen on the port, so no need for a
     * lock over the data.  However, we need to make sure the process
     * that caused the port shutdown has released it's lock because we
     * might free the port.
     */
    so->lock(port->lock);
    so->unlock(port->lock);

    port->net_to_dev_state = PORT_UNCONNECTED;
    gbuf_reset(&port->net_to_dev);
    if (port->devstr) {
	free(port->devstr->buf);
	free(port->devstr);
	port->devstr = NULL;
    }
    gbuf_reset(&port->dev_to_net);
    port->dev_bytes_received = 0;
    port->dev_bytes_sent = 0;

    if (gensio_acc_exit_on_close(port->accepter))
	/* This was a zero port (for stdin/stdout), this is only
	   allowed with one port at a time, and we shut down when it
	   closes. */
	exit(0);

    /* If the port has been disabled, then delete it.  Check this before
       the new config so the port will be deleted properly and not
       reconfigured on a reconfig. */
    if (port->config_num == -1) {
	port_info_t *curr, *prev;

	prev = NULL;
	so->lock(ports_lock);
	curr = ports;
	while ((curr != NULL) && (curr != port)) {
	    prev = curr;
	    curr = curr->next;
	}
	if (curr != NULL) {
	    if (prev == NULL)
		ports = curr->next;
	    else
		prev->next = curr->next;
	}
	so->unlock(ports_lock);
	free_port(port);
	return; /* We have to return here because we no longer have a port. */
    }

    /*
     * The configuration for this port has changed, install it now that
     * the user has closed the connection.
     */
    if (port->new_config != NULL) {
	port_info_t *curr, *prev;

	prev = NULL;
	so->lock(ports_lock);
	curr = ports;
	while ((curr != NULL) && (curr != port)) {
	    prev = curr;
	    curr = curr->next;
	}
	if (curr != NULL) {
	    port = curr->new_config;
	    curr->new_config = NULL;
	    so->lock(curr->lock);
	    so->lock(port->lock);
	    /* Releases curr->lock */
	    if (switchout_port(NULL, port, curr, prev)) {
		/*
		 * This is an unusual case.  We have switched out the
		 * port and it requested a shutdown, but we really
		 * can't wait here in this thread for the shutdown to
		 * complete.  So we mark that we are waiting and do
		 * the startup later in the callback.
		 */
		port->accepter_reinit_on_shutdown = true;
		reinit_now = false;
		so->unlock(port->lock);
	    } else {
		so->unlock(ports_lock);
		goto reinit_port;
	    }
	}
	so->unlock(ports_lock);
    }

    if (reinit_now) {
	so->lock(port->lock);
    reinit_port:
	port_reinit_now(port);
	so->unlock(port->lock);
    }
}

static void call_finish_shutdown_port(struct gensio_runner *runner,
				      void *cb_data)
{
    port_info_t *port = cb_data;

    finish_shutdown_port(port);
}

static void
io_shutdown_done(struct gensio *io, void *cb_data)
{
    port_info_t *port = cb_data;

    so->run(port->runshutdown);
}

static void
shutdown_port_io(port_info_t *port)
{
    int err = 1;

    if (port->io)
	err = gensio_close(port->io, io_shutdown_done, port);

    if (err)
	so->run(port->runshutdown);
}

static void
timer_shutdown_done(struct gensio_timer *timer, void *cb_data)
{
    shutdown_port_io(cb_data);
}

/* Output any pending data and the devstr buffer. */
static void
handle_dev_fd_close_write(port_info_t *port)
{
    int err;

    if (gbuf_cursize(&port->net_to_dev) != 0)
	err = gbuf_write(port, &port->net_to_dev);
    else if (port->devstr)
	err = gbuf_write(port, port->devstr);
    else
	goto closeit;

    if (err) {
	syslog(LOG_ERR, "The dev write for port %s had error: %s",
	       port->portname, gensio_err_to_str(err));
	goto closeit;
    }

    if (gbuf_cursize(&port->net_to_dev) ||
		(port->devstr && gbuf_cursize(port->devstr)))
	return;

closeit:
    if (port->shutdown_timeout_count) {
	port->shutdown_timeout_count = 0;
	gensio_set_write_callback_enable(port->io, false);
	if (so->stop_timer_with_done(port->timer, timer_shutdown_done, port))
	    shutdown_port_io(port);
    }
}

static void
start_shutdown_port_io(port_info_t *port)
{
    if (port->devstr) {
	free(port->devstr->buf);
	free(port->devstr);
    }
    port->devstr = process_str_to_buf(port, NULL, port->closestr);
    if (port->net_to_dev_state != PORT_UNCONNECTED) {
	gensio_set_read_callback_enable(port->io, false);
	port->dev_write_handler = handle_dev_fd_close_write;
	gensio_set_write_callback_enable(port->io, true);
    } else {
	shutdown_port_io(port);
    }
}

static void
start_shutdown_port(port_info_t *port, char *reason)
{
    if (port->dev_to_net_state == PORT_CLOSING ||
		port->dev_to_net_state == PORT_UNCONNECTED)
	return;

    port->close_on_output_done = false;

    gensio_set_read_callback_enable(port->io, false);
    gensio_acc_set_accept_callback_enable(port->accepter, false);

    footer_trace(port, "port", reason);

    if (port->trace_write.fd != -1) {
	close(port->trace_write.fd);
	port->trace_write.fd = -1;
    }
    if (port->trace_read.fd != -1) {
	close(port->trace_read.fd);
	port->trace_read.fd = -1;
    }
    if (port->trace_both.fd != -1) {
	close(port->trace_both.fd);
	port->trace_both.fd = -1;
    }
    port->tw = port->tr = port->tb = NULL;

    /* FIXME - this should be calculated somehow, not a raw number .*/
    port->shutdown_timeout_count = 4;
    port->dev_to_net_state = PORT_CLOSING;
}

static void
netcon_finish_shutdown(net_info_t *netcon)
{
    port_info_t *port = netcon->port;

    so->lock(port->lock);
    netcon->closing = false;
    netcon->bytes_received = 0;
    netcon->bytes_sent = 0;
    netcon->write_pos = 0;
    if (netcon->banner) {
	free(netcon->banner->buf);
	free(netcon->banner);
	netcon->banner = NULL;
    }

    if (num_connected_net(port) == 0) {
	if (!port->has_connect_back) {
	    start_shutdown_port(port, "All network connections free");
	    start_shutdown_port_io(port);
	}
    } else {
	check_port_new_net(port, netcon);
    }
    so->unlock(port->lock);
}

static void
handle_net_fd_closed(struct gensio *net, void *cb_data)
{
    net_info_t *netcon = gensio_get_user_data(net);
    port_info_t *port = netcon->port;

    gensio_free(netcon->net);
    netcon->net = NULL;

    so->lock(port->lock);
    if (port->dev_to_net_state == PORT_WAITING_OUTPUT_CLEAR)
	finish_dev_to_net_write(port);
    so->unlock(port->lock);

    netcon_finish_shutdown(netcon);
}

static void shutdown_netcon_clear(struct gensio_runner *runner, void *cb_data)
{
    net_info_t *netcon = cb_data;

    if (netcon->net) {
	int err = gensio_close(netcon->net, handle_net_fd_closed, NULL);
	if (err)
	    handle_net_fd_closed(netcon->net, NULL);
    } else {
	netcon_finish_shutdown(netcon);
    }
}

static void
shutdown_one_netcon(net_info_t *netcon, char *reason)
{
    if (netcon->closing)
	return;

    footer_trace(netcon->port, "netcon", reason);

    netcon->closing = true;
    /* shutdown_netcon_clear() may clain the port lock, run it elsewhere. */
    so->run(netcon->runshutdown);
}

static void
shutdown_port(port_info_t *port, char *reason)
{
    net_info_t *netcon;
    bool some_to_close = false;

    start_shutdown_port(port, reason);

    for_each_connection(port, netcon) {
	if (netcon->net) {
	    some_to_close = true;
	    shutdown_one_netcon(netcon, "Port closing");
	}
    }

    if (!some_to_close)
	start_shutdown_port_io(port);
}

void
got_timeout(struct gensio_timer *timer, void *data)
{
    port_info_t *port = (port_info_t *) data;
    struct timeval timeout;
    net_info_t *netcon;

    so->lock(port->lock);

    if (port->dev_to_net_state == PORT_CLOSING) {
	if (port->shutdown_timeout_count <= 1) {
	    int count = port->shutdown_timeout_count;

	    port->shutdown_timeout_count = 0;
	    so->unlock(port->lock);
	    if (count == 1)
		shutdown_port_io(port);
	    return;
	} else {
	    port->shutdown_timeout_count--;
	    goto out;
	}
    }

    if (port->nocon_read_enable_time_left) {
	port->nocon_read_enable_time_left--;
	if (port->nocon_read_enable_time_left == 0)
	    gensio_set_read_callback_enable(port->io, true);
	goto out;
    }

    if (port->timeout && port->net_to_dev_state != PORT_UNCONNECTED) {
	for_each_connection(port, netcon) {
	    if (!netcon->net)
		continue;
	    netcon->timeout_left--;
	    if (netcon->timeout_left < 0)
		shutdown_one_netcon(netcon, "timeout");
	}
    }

 out:
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    so->start_timer(port->timer, &timeout);
    so->unlock(port->lock);
}

int
cmpstrval(const char *s, const char *prefix, const char **val)
{
    int len = strlen(prefix);

    if (strncmp(s, prefix, len))
	return 0;
    *val = s + len;

    return 1;
}

static int cmpstrint(const char *s, const char *prefix, int *rval,
		     struct absout *eout)
{
    const char *val;
    char *endpos;

    if (!cmpstrval(s, prefix, &val))
	return 0;

    *rval = strtoul(val, &endpos, 10);
    if (endpos == val || *endpos != '\0') {
	eout->out(eout, "Invalid number for %s: %s\n", prefix, val);
	return -1;
    }
    return 1;
}

static int
port_add_remaddr(struct absout *eout, port_info_t *port, const char *istr)
{
    char *str;
    char *strtok_data;
    char *remstr;
    int err = 0;

    str = strdup(istr);
    if (!str) {
	eout->out(eout, "Out of memory handling remote address '%s'", istr);
	return ENOMEM;
    }

    remstr = strtok_r(str, ";", &strtok_data);
    /* Note that we ignore an empty remaddr. */
    while (remstr && *remstr) {
	err = remaddr_append(&port->remaddrs, remstr);
	if (err) {
	    eout->out(eout, "Error adding remote address '%s': %s\n", remstr,
		      gensio_err_to_str(err));
	    break;
	}
	remstr = strtok_r(NULL, ";", &strtok_data);
    }
    free(str);
    return err;
}

static int
strdupcat(char **str, const char *cat)
{
    char *s = malloc(strlen(*str) + strlen(cat) + 2);

    if (!s)
	return ENOMEM;
    strcpy(s, *str);
    strcat(s, ",");
    strcat(s, cat);
    free(*str);
    *str = s;
    return 0;
}

static const char *serialdev_parms[] = {
    "XONXOFF",
    "-XONXOFF",
    "RTSCTS",
    "-RTSCTS",
    "LOCAL",
    "-LOCAL",
    "HANGUP_WHEN_DONE",
    "-HANGUP_WHEN_DONE",
    "NOBREAK",
    "-NOBREAK",
    NULL
};

static bool
matchstr(const char *parms[], const char *c)
{
    unsigned int i;

    for (i = 0; parms[i]; i++) {
	if (strcmp(parms[i], c) == 0)
	    return true;
    }
    return false;
}

static int
myconfig(port_info_t *port, struct absout *eout, const char *pos)
{
    enum str_type stype;
    char *s;
    const char *val;
    unsigned int len;
    int rv, ival;

    /*
     * This is a hack for backwards compatibility, if we see a config
     * item meant for the device, we stick it onto the device name.
     */
    if (isdigit(pos[0]) || matchstr(serialdev_parms, pos)) {
	int err = strdupcat(&port->devname, pos);

	if (err) {
	    eout->out(eout, "Out of memory appending to devname");
	    return -1;
	}
    } else if (strcmp(pos, "remctl") == 0) {
	port->allow_2217 = true;
    } else if (strcmp(pos, "-remctl") == 0) {
	port->allow_2217 = false;
    } else if (strcmp(pos, "kickolduser") == 0) {
        port->kickolduser_mode = 1;
    } else if (strcmp(pos, "-kickolduser") == 0) {
        port->kickolduser_mode = 0;
    } else if (strcmp(pos, "hexdump") == 0 ||
	       strcmp(pos, "-hexdump") == 0) {
	port->trace_read.hexdump = (*pos != '-');
	port->trace_write.hexdump = (*pos != '-');
	port->trace_both.hexdump = (*pos != '-');
    } else if (strcmp(pos, "timestamp") == 0 ||
	       strcmp(pos, "-timestamp") == 0) {
	port->trace_read.timestamp = (*pos != '-');
	port->trace_write.timestamp = (*pos != '-');
	port->trace_both.timestamp = (*pos != '-');
    } else if (strcmp(pos, "tr-hexdump") == 0 ||
	       strcmp(pos, "-tr-hexdump") == 0) {
	port->trace_read.hexdump = (*pos != '-');
    } else if (strcmp(pos, "tr-timestamp") == 0 ||
	       strcmp(pos, "-tr-timestamp") == 0) {
	port->trace_read.timestamp = (*pos != '-');
    } else if (strcmp(pos, "tw-hexdump") == 0 ||
	       strcmp(pos, "-tw-hexdump") == 0) {
	port->trace_write.hexdump = (*pos != '-');
    } else if (strcmp(pos, "tw-timestamp") == 0 ||
	       strcmp(pos, "-tw-timestamp") == 0) {
	port->trace_write.timestamp = (*pos != '-');
    } else if (strcmp(pos, "tb-hexdump") == 0 ||
	       strcmp(pos, "-tb-hexdump") == 0) {
	port->trace_both.hexdump = (*pos != '-');
    } else if (strcmp(pos, "tb-timestamp") == 0 ||
	       strcmp(pos, "-tb-timestamp") == 0) {
	port->trace_both.timestamp = (*pos != '-');
    } else if (cmpstrval(pos, "tr=", &val)) {
	/* trace read, data from the port to the socket */
	port->trace_read.filename = find_tracefile(val);
    } else if (cmpstrval(pos, "tw=", &val)) {
	/* trace write, data from the socket to the port */
	port->trace_write.filename = find_tracefile(val);
    } else if (cmpstrval(pos, "tb=", &val)) {
	/* trace both directions. */
	port->trace_both.filename = find_tracefile(val);
    } else if (cmpstrval(pos, "led-rx=", &val)) {
	/* LED for UART RX traffic */
	port->led_rx = find_led(val);
    } else if (cmpstrval(pos, "led-tx=", &val)) {
	/* LED for UART TX traffic */
	port->led_tx = find_led(val);
    } else if (strcmp(pos, "telnet_brk_on_sync") == 0) {
	port->telnet_brk_on_sync = 1;
    } else if (strcmp(pos, "-telnet_brk_on_sync") == 0) {
	port->telnet_brk_on_sync = 0;
    } else if (strcmp(pos, "chardelay") == 0) {
	port->enable_chardelay = true;
    } else if (strcmp(pos, "-chardelay") == 0) {
	port->enable_chardelay = false;
    } else if ((rv = cmpstrint(pos, "chardelay-scale=", &ival, eout))) {
	if (rv == -1)
	    return -1;
	port->chardelay_scale = ival;
    } else if ((rv = cmpstrint(pos, "chardelay-min=", &ival, eout))) {
	if (rv == -1)
	    return -1;
	port->chardelay_min = ival;
    } else if ((rv = cmpstrint(pos, "chardelay-max=", &ival, eout))) {
	if (rv == -1)
	    return -1;
	port->chardelay_max = ival;
    } else if ((rv = cmpstrint(pos, "dev-to-net-bufsize=", &ival, eout))) {
	if (rv == -1)
	    return -1;
	if (ival < 2)
	    ival = 2;
	port->dev_to_net.maxsize = ival;
    } else if ((rv = cmpstrint(pos, "net-to-dev-bufsize=", &ival, eout))) {
	if (rv == -1)
	    return -1;
	if (ival < 2)
	    ival = 2;
	port->net_to_dev.maxsize = ival;
    } else if ((rv = cmpstrint(pos, "dev-to-tcp-bufsize=", &ival, eout))) {
	/* deprecated */
	if (rv == -1)
	    return -1;
	if (ival < 2)
	    ival = 2;
	port->dev_to_net.maxsize = ival;
    } else if ((rv = cmpstrint(pos, "tcp-to-dev-bufsize=", &ival, eout))) {
	/* deprecated */
	if (rv == -1)
	    return -1;
	if (ival < 2)
	    ival = 2;
	port->net_to_dev.maxsize = ival;
    } else if ((rv = cmpstrint(pos, "max-connections=", &ival, eout))) {
	if (rv == -1)
	    return -1;
	if (ival < 1)
	    ival = 1;
	port->max_connections = ival;
    } else if (cmpstrval(pos, "remaddr=", &val)) {
	rv = port_add_remaddr(eout, port, val);
	if (rv)
	    return -1;
	port->remaddr_set = true;
    } else if (cmpstrval(pos, "rs485=", &val)) {
	port->rs485 = find_rs485conf(val);
    } else if ((s = find_str(pos, &stype, &len))) {
	/* It's a startup banner, signature or open/close string, it's
	   already set. */
	switch (stype) {
	case BANNER: port->bannerstr = s; break;
	case SIGNATURE: port->signaturestr = s; break;
	case OPENSTR: port->openstr = s; break;
	case CLOSESTR: port->closestr = s; break;
	case CLOSEON: port->closeon = s; port->closeon_len = len; break;
	default: free(s); goto unknown;
	}
    } else {
    unknown:
	eout->out(eout, "Unknown config item: %s", pos);
	return -1;
    }

    return 0;
}

static int
myconfigs(port_info_t *port, struct absout *eout, const char *istr)
{
    char *pos, *str, *strtok_data;
    int rv = 0;

    str = strdup(istr);
    if (!str) {
	eout->out(eout, "Out of memory handling config");
	return -1;
    }

    for (pos = strtok_r(str, " \t", &strtok_data); pos != NULL;
		pos = strtok_r(NULL, " \t", &strtok_data)) {
	rv = myconfig(port, eout, pos);
	if (rv)
	    break;
    }

    free(str);
    return rv;
}

/* Create a port based on a set of parameters passed in. */
int
portconfig(struct absout *eout,
	   char *portnum,
	   char *state,
	   char *timeout,
	   char *devname,
	   char *devcfg,
	   int  config_num)
{
    port_info_t *new_port, *curr, *prev;
    net_info_t *netcon;
    enum str_type str_type;
    int err;
    unsigned int shutdown_count = 0;
    bool do_telnet = false;
    bool write_only = false;

    new_port = malloc(sizeof(port_info_t));
    if (new_port == NULL) {
	eout->out(eout, "Could not allocate a port data structure");
	return -1;
    }
    memset(new_port, 0, sizeof(*new_port));

    new_port->lock = so->alloc_lock(so);
    if (!new_port->lock) {
	eout->out(eout, "Could not allocate lock");
	goto errout;
    }

    new_port->timer = so->alloc_timer(so, got_timeout, new_port);
    if (!new_port->timer) {
	eout->out(eout, "Could not allocate timer data");
	goto errout;
    }

    new_port->send_timer = so->alloc_timer(so, send_timeout, new_port);
    if (!new_port->send_timer) {
	eout->out(eout, "Could not allocate timer data");
	goto errout;
    }

    new_port->runshutdown = so->alloc_runner(so, call_finish_shutdown_port,
					     new_port);
    if (!new_port->runshutdown)
	goto errout;

    new_port->devname = find_str(devname, &str_type, NULL);
    if (new_port->devname) {
	if (str_type != DEVNAME) {
	    free(new_port->devname);
	    new_port->devname = NULL;
	} else {
	    new_port->orig_devname = strdup(devname);
	    if (!new_port->orig_devname) {
		eout->out(eout, "unable to allocate original device name");
		goto errout;
	    }
	}
    }
    if (!new_port->devname)
	new_port->devname = strdup(devname);
    if (!new_port->devname) {
	eout->out(eout, "unable to allocate device name");
	goto errout;
    }

    /* Errors from here on out must goto errout. */
    init_port_data(new_port);

    if (!new_port->portname) {
	new_port->portname = strdup(portnum);
	if (!new_port->portname)
	    goto errout;
    }

    if (strcmp(state, "on") == 0) {
	new_port->enabled = PORT_ON;
    } else if (strcmp(state, "raw") == 0) {
	new_port->enabled = PORT_ON;
    } else if (strcmp(state, "rawlp") == 0) {
	/* FIXME - remove this someday. */
	new_port->enabled = PORT_ON;
	write_only = true;
    } else if (strcmp(state, "telnet") == 0) {
	/* FIXME - remove this someday. */
	new_port->enabled = PORT_ON;
	do_telnet = true;
    } else if (strcmp(state, "off") == 0) {
	new_port->enabled = PORT_DISABLED;
    } else {
	eout->out(eout, "state was invalid");
	goto errout;
    }

    new_port->timeout = scan_int(timeout);
    if (new_port->timeout == -1) {
	eout->out(eout, "timeout was invalid");
	goto errout;
    }

    err = myconfigs(new_port, eout, devcfg);
    if (err)
	goto errout;

    if (write_only) {
	err = strdupcat(&new_port->devname, "wronly");
	if (err) {
	    eout->out(eout, "Out of memory appending to devname");
	    goto errout;
	}
    }

    if (new_port->rs485) {
	err = strdupcat(&new_port->devname, "rs485=");
	if (!err)
	    err = strdupcat(&new_port->devname, new_port->rs485);
	if (err) {
	    eout->out(eout, "Out of memory appending to devname");
	    goto errout;
	}
    }

    err = str_to_gensio(new_port->devname, so, handle_dev_event, new_port,
			&new_port->io);
    if (err) {
	eout->out(eout, "device configuration %s invalid: %s",
		  new_port->devname, gensio_err_to_str(err));
	goto errout;
    }

    err = str_to_gensio_accepter(new_port->portname, so,
				handle_port_child_event, new_port,
				&new_port->accepter);
    if (err) {
	eout->out(eout, "Invalid port name/number: %s", gensio_err_to_str(err));
	goto errout;
    }

    if (new_port->enabled == PORT_ON && do_telnet) {
	const char *args[] = { NULL, NULL };
	struct gensio_accepter *parent;

	if (new_port->allow_2217)
	    args[0] = "rfc2217=true";
	err = telnet_gensio_accepter_alloc(new_port->accepter, args,
					   so,
					   handle_port_child_event,
					   new_port, &parent);
	if (err)
	    goto errout;
	new_port->accepter = parent;
    }

    if (gbuf_init(&new_port->dev_to_net, new_port->dev_to_net.maxsize))
    {
	eout->out(eout, "Could not allocate dev to net buffer");
	goto errout;
    }

    if (gbuf_init(&new_port->net_to_dev, new_port->net_to_dev.maxsize))
    {
	eout->out(eout, "Could not allocate net to dev buffer");
	goto errout;
    }

    /*
     * Don't handle the remaddr default until here, we don't want to
     * mess with it if the user has set it, because the user may set
     * it to an empty string.
     */
    if (!new_port->remaddr_set) {
	char *remaddr;
	if (find_default_str("remaddr", &remaddr)) {
	    eout->out(eout, "Out of memory processing default remote address");
	} else if (remaddr) {
	    err = port_add_remaddr(eout, new_port, remaddr);
	    free(remaddr);
	    if (err)
		goto errout;
	}
    }

    new_port->netcons = malloc(sizeof(net_info_t) * new_port->max_connections);
    if (new_port->netcons == NULL) {
	eout->out(eout, "Could not allocate a port data structure");
	goto errout;
    }
    memset(new_port->netcons, 0,
	   sizeof(net_info_t) * new_port->max_connections);
    for_each_connection(new_port, netcon) {
	netcon->runshutdown = so->alloc_runner(so, shutdown_netcon_clear,
					       netcon);
	if (!netcon->runshutdown) {
	    eout->out(eout, "Could not allocate a netcon shutdown handler");
	    goto errout;
	}

	netcon->port = new_port;
    }

    new_port->config_num = config_num;

    /* See if the port already exists, and reconfigure it if so. */
    prev = NULL;
    so->lock(ports_lock);
    curr = ports;
    while (curr != NULL) {
	if (strcmp(curr->portname, new_port->portname) == 0) {
	    /* We are reconfiguring this port. */
	    so->lock(curr->lock);
	    if (curr->dev_to_net_state == PORT_UNCONNECTED) {
		/* Port is disconnected, switch it now. */
		so->lock(new_port->lock);
		/* releases curr->lock */
		if (switchout_port(eout, new_port, curr, prev))
		    wait_for_port_shutdown(new_port, &shutdown_count);
		so->unlock(new_port->lock);
	    } else {
		/* Mark it to be replaced later. */
		if (curr->new_config != NULL)
		    free_port(curr->new_config);
		curr->config_num = config_num;
		curr->new_config = new_port;
		so->unlock(curr->lock);
	    }
	    goto out;
	} else {
	    prev = curr;
	    curr = curr->next;
	}
    }

    /* If we get here, the port is brand new, so don't do anything that
       would affect a port replacement here. */

    if (new_port->enabled != PORT_DISABLED) {
	int rv;

	so->lock(new_port->lock);
	rv = startup_port(eout, new_port, false);
	so->unlock(new_port->lock);
	if (rv == -1)
	    goto errout_unlock;
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
 out:
    so->unlock(ports_lock);

    so->wait(accepter_shutdown_wait, shutdown_count, NULL);

    return 0;

errout_unlock:
    so->unlock(ports_lock);
errout:
    free_port(new_port);
    return -1;
}

void
clear_old_port_config(int curr_config)
{
    port_info_t *curr, *prev;
    unsigned int shutdown_count = 0;

    prev = NULL;
    curr = ports;
    so->lock(ports_lock);
    while (curr != NULL) {
	if (curr->config_num != curr_config) {
	    /* The port was removed, remove it. */
	    so->lock(curr->lock);
	    if (curr->dev_to_net_state == PORT_UNCONNECTED) {
		if (change_port_state(NULL, curr, PORT_DISABLED, false))
		    wait_for_port_shutdown(curr, &shutdown_count);
		so->unlock(curr->lock);
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
		if (change_port_state(NULL, curr, PORT_DISABLED, false))
		    wait_for_port_shutdown(curr, &shutdown_count);
		so->unlock(curr->lock);
		prev = curr;
		curr = curr->next;
	    }
	} else {
	    prev = curr;
	    curr = curr->next;
	}
    }
    so->unlock(ports_lock);

    so->wait(accepter_shutdown_wait, shutdown_count, NULL);
}

#define REMOTEADDR_COLUMN_WIDTH \
    (INET6_ADDRSTRLEN - 1 /* terminating NUL */ + 1 /* comma */ + 5 /* strlen("65535") */)

/* Print information about a port to the control port given in cntlr. */
static void
showshortport(struct controller_info *cntlr, port_info_t *port)
{
    char buffer[NI_MAXHOST + NI_MAXSERV + 2];
    int count;
    int err;
    net_info_t *netcon = NULL;
    unsigned int bytes_recv = 0, bytes_sent = 0;

    controller_outputf(cntlr, "%-22s ", port->portname);
    if (port->config_num == -1)
	controller_outputf(cntlr, "%-6s ", "DEL");
    else
	controller_outputf(cntlr, "%-6s ", enabled_str[port->enabled]);
    controller_outputf(cntlr, "%7d ", port->timeout);

    netcon = first_live_net_con(port);
    if (!netcon)
	netcon = &(port->netcons[0]);

    if (port->net_to_dev_state != PORT_UNCONNECTED) {
	gensio_raddr_to_str(netcon->net, NULL, buffer, sizeof(buffer));
	count = controller_outputf(cntlr, "%s", buffer);
    } else {
	count = controller_outputf(cntlr, "unconnected");
    }

    while (count < REMOTEADDR_COLUMN_WIDTH + 1) {
	controller_outs(cntlr, " ");
	count++;
    }

    bytes_recv = netcon->bytes_received;
    bytes_sent = netcon->bytes_sent;

    controller_outputf(cntlr, "%-22s ", port->devname);
    controller_outputf(cntlr, "%-14s ", state_str[port->net_to_dev_state]);
    controller_outputf(cntlr, "%-14s ", state_str[port->dev_to_net_state]);
    controller_outputf(cntlr, "%9d ", bytes_recv);
    controller_outputf(cntlr, "%9d ", bytes_sent);
    controller_outputf(cntlr, "%9d ", port->dev_bytes_received);
    controller_outputf(cntlr, "%9d ", port->dev_bytes_sent);

    err = gensio_raddr_to_str(port->io, NULL, buffer, sizeof(buffer));
    if (!err)
	controller_outputf(cntlr, "%s", buffer);

    controller_outs(cntlr, "\r\n");
}

/* Print information about a port to the control port given in cntlr. */
static void
showport(struct controller_info *cntlr, port_info_t *port)
{
    char buffer[NI_MAXHOST + NI_MAXSERV + 2], *cfg, *oth = NULL;
    net_info_t *netcon;
    int err;

    controller_outputf(cntlr, "Port %s\r\n", port->portname);
    controller_outputf(cntlr, "  enable state: %s\r\n",
		       enabled_str[port->enabled]);
    controller_outputf(cntlr, "  timeout: %d\r\n", port->timeout);

    for_each_connection(port, netcon) {
	if (netcon->net) {
	    gensio_raddr_to_str(netcon->net, NULL, buffer, sizeof(buffer));
	    controller_outputf(cntlr, "  connected to: %s\r\n", buffer);
	    controller_outputf(cntlr, "    bytes read from TCP: %d\r\n",
			       netcon->bytes_received);
	    controller_outputf(cntlr, "    bytes written to TCP: %d\r\n",
			       netcon->bytes_sent);
	} else {
	    controller_outputf(cntlr, "  unconnected\r\n");
	}
    }

    if (port->orig_devname)
	controller_outputf(cntlr, "  device: %s (%s)\r\n", port->devname,
			   port->orig_devname);
    else
	controller_outputf(cntlr, "  device: %s\r\n", port->devname);

    err = gensio_raddr_to_str(port->io, NULL, buffer, sizeof(buffer));
    if (!err) {
	cfg = strchr(buffer, ',');
	if (cfg) {
	    cfg++;
	    oth = strchr(cfg, ' ');
	} else {
	    cfg = "";
	    oth = strchr(buffer, ' ');
	}
	if (oth) {
	    *oth = '\0';
	    oth++;
	} else {
	    oth = "";
	}

	controller_outputf(cntlr, "  device config: %s\r\n", cfg);
	controller_outputf(cntlr, "  device controls: %s\r\n", oth);
    } else {
	controller_outputf(cntlr, "  device config: ?\r\n");
	controller_outputf(cntlr, "  device controls: ?\r\n");
    }

    controller_outputf(cntlr, "  tcp to device state: %s\r\n",
		      state_str[port->net_to_dev_state]);

    controller_outputf(cntlr, "  device to tcp state: %s\r\n",
		      state_str[port->dev_to_net_state]);

    controller_outputf(cntlr, "  bytes read from device: %d\r\n",
		      port->dev_bytes_received);

    controller_outputf(cntlr, "  bytes written to device: %d\r\n",
		      port->dev_bytes_sent);

    if (port->config_num == -1) {
	controller_outputf(cntlr, "  Port will be deleted when current"
			   " session closes.\r\n");
    } else if (port->new_config != NULL) {
	controller_outputf(cntlr, "  Port will be reconfigured when current"
			   " session closes.\r\n");
    }
}

/*
 * Find a port data structure given a port number.  Returns with port->lock
 * held, if it returns a non-NULL port.
 */
static port_info_t *
find_port_by_num(char *portstr, bool allow_deleted)
{
    port_info_t *port;

    so->lock(ports_lock);
    port = ports;
    while (port != NULL) {
	if (strcmp(portstr, port->portname) == 0) {
	    so->lock(port->lock);
	    so->unlock(ports_lock);
	    if (port->config_num == -1 && !allow_deleted) {
		so->unlock(port->lock);
		return NULL;
	    }
	    return port;
	}
	port = port->next;
    }

    so->unlock(ports_lock);
    return NULL;
}

/* Handle a showport command from the control port. */
void
showports(struct controller_info *cntlr, char *portspec)
{
    port_info_t *port;

    if (portspec == NULL) {
	so->lock(ports_lock);
	/* Dump everything. */
	port = ports;
	while (port != NULL) {
	    so->lock(port->lock);
	    showport(cntlr, port);
	    so->unlock(port->lock);
	    port = port->next;
	}
	so->unlock(ports_lock);
    } else {
	port = find_port_by_num(portspec, true);
	if (port == NULL) {
	    controller_outputf(cntlr, "Invalid port number: %s\r\n", portspec);
	} else {
	    showport(cntlr, port);
	    so->unlock(port->lock);
	}
    }
}

/* Handle a showport command from the control port. */
void
showshortports(struct controller_info *cntlr, char *portspec)
{
    port_info_t *port;

    controller_outputf(cntlr,
	    "%-22s %-6s %7s %-*s %-22s %-14s %-14s %9s %9s %9s %9s %s\r\n",
	    "Port name",
	    "Type",
	    "Timeout",
	    REMOTEADDR_COLUMN_WIDTH,
	    "Remote address",
	    "Device",
	    "TCP to device",
	    "Device to TCP",
	    "TCP in",
	    "TCP out",
	    "Dev in",
	    "Dev out",
	    "State");
    if (portspec == NULL) {
	so->lock(ports_lock);
	/* Dump everything. */
	port = ports;
	while (port != NULL) {
	    so->lock(port->lock);
	    showshortport(cntlr, port);
	    so->unlock(port->lock);
	    port = port->next;
	}
	so->unlock(ports_lock);
    } else {
	port = find_port_by_num(portspec, true);
	if (port == NULL) {
	    controller_outputf(cntlr, "Invalid port number: %s\r\n", portspec);
	} else {
	    showshortport(cntlr, port);
	    so->unlock(port->lock);
	}
    }
}

/* Set the timeout on a port.  The port number and timeout are passed
   in as strings, this code will convert them, return any errors, and
   perform the operation. */
void
setporttimeout(struct controller_info *cntlr, char *portspec, char *timeout)
{
    port_info_t *port;
    net_info_t *netcon;

    port = find_port_by_num(portspec, true);
    if (port == NULL) {
	controller_outputf(cntlr, "Invalid port number: %s\r\n", portspec);
    } else {
	int timeout_num = scan_int(timeout);

	if (timeout_num == -1) {
	    controller_outputf(cntlr, "Invalid timeout: %s\r\n", timeout);
	} else {
	    port->timeout = timeout_num;

	    for_each_connection(port, netcon) {
		if (netcon->net)
		    reset_timer(netcon);
	    }
	}
	so->unlock(port->lock);
    }
}

/* Modify the controls of a port.  The port number and configuration
   are passed in as strings, this code will get the port and then call
   the code to control the device. */
void
setportcontrol(struct controller_info *cntlr, char *portspec, char *controls)
{
    port_info_t *port;

    port = find_port_by_num(portspec, false);
    if (port == NULL) {
	controller_outputf(cntlr, "Invalid port number: %s\r\n", portspec);
	goto out;
    } else if (port->net_to_dev_state == PORT_UNCONNECTED) {
	controller_outputf(cntlr, "Port is not currently connected: %s\r\n",
			   portspec);
    } else {
	char *pos, *strtok_data;
	struct sergensio *sio = gensio_to_sergensio(port->io);

	if (!sio)
	    goto out_unlock;
	pos = strtok_r(controls, " \t", &strtok_data);
	while (pos) {
	    if (strcmp(pos, "RTSHI") == 0)
		sergensio_rts(sio, SERGENSIO_RTS_ON, NULL, NULL);
	    else if (strcmp(pos, "RTSLO") == 0)
		sergensio_rts(sio, SERGENSIO_RTS_OFF, NULL, NULL);
	    else if (strcmp(pos, "DTRHI") == 0)
		sergensio_rts(sio, SERGENSIO_DTR_ON, NULL, NULL);
	    else if (strcmp(pos, "DTRLO") == 0)
		sergensio_rts(sio, SERGENSIO_DTR_OFF, NULL, NULL);
	    else
		controller_outputf(cntlr, "Invalid device control: %s\r\n",
				   pos);
	    pos = strtok_r(NULL, " \t", &strtok_data);
	}
    }
 out_unlock:
    so->unlock(port->lock);
 out:
    return;
}

/* Set the enable state of a port. */
void
setportenable(struct controller_info *cntlr, char *portspec, char *enable)
{
    port_info_t *port;
    int         new_enable;
    struct absout eout = { .out = cntrl_abserrout, .data = cntlr };
    unsigned int shutdown_count = 0;

    port = find_port_by_num(portspec, false);
    if (port == NULL) {
	controller_outputf(cntlr, "Invalid port number: %s\r\n", portspec);
	return;
    }

    if (strcmp(enable, "off") == 0) {
	new_enable = PORT_DISABLED;
    } else if (strcmp(enable, "on") == 0) {
	new_enable = PORT_ON;
    } else if (strcmp(enable, "raw") == 0) {
	new_enable = PORT_ON;
    } else {
	controller_outputf(cntlr, "Invalid enable: %s\r\n", enable);
	goto out_unlock;
    }

    if (change_port_state(&eout, port, new_enable, false))
	wait_for_port_shutdown(port, &shutdown_count);

 out_unlock:
    so->unlock(port->lock);

    so->wait(accepter_shutdown_wait, shutdown_count, NULL);
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

    port = find_port_by_num(portspec, true);
    if (port == NULL) {
	char *err = "Invalid port number: ";
	controller_outs(cntlr, err);
	controller_outs(cntlr, portspec);
	controller_outs(cntlr, "\r\n");
	goto out;
    }

    if ((port->net_monitor != NULL) || (port->dev_monitor != NULL)) {
	char *err = "Port is already being monitored";
	controller_outs(cntlr, err);
	controller_outs(cntlr, "\r\n");
	goto out_unlock;
    }

    if (strcmp(type, "tcp") == 0) {
	port->net_monitor = cntlr;
    } else if (strcmp(type, "term") == 0) {
	port->dev_monitor = cntlr;
    } else {
	char *err = "invalid monitor type: ";
	controller_outs(cntlr, err);
	controller_outs(cntlr, type);
	controller_outs(cntlr, "\r\n");
	so->unlock(port->lock);
	port = NULL;
	goto out;
    }
 out_unlock:
    so->unlock(port->lock);
 out:
    return port;
}

/* Stop monitoring the given id. */
void
data_monitor_stop(struct controller_info *cntlr,
		  void                   *monitor_id)
{
    port_info_t *port = (port_info_t *) monitor_id;
    port_info_t *curr;

    so->lock(ports_lock);
    curr = ports;
    while (curr) {
	if (curr == port) {
	    so->lock(port->lock);
	    port->net_monitor = NULL;
	    port->dev_monitor = NULL;
	    so->unlock(port->lock);
	    break;
	}
	curr = curr->next;
    }
    so->unlock(ports_lock);
}

void
disconnect_port(struct controller_info *cntlr,
		char *portspec)
{
    port_info_t *port;

    port = find_port_by_num(portspec, true);
    if (port == NULL) {
	char *err = "Invalid port number: ";
	controller_outs(cntlr, err);
	controller_outs(cntlr, portspec);
	controller_outs(cntlr, "\r\n");
	goto out;
    } else if (port->net_to_dev_state == PORT_UNCONNECTED) {
	char *err = "Port not connected: ";
	controller_outs(cntlr, err);
	controller_outs(cntlr, portspec);
	controller_outs(cntlr, "\r\n");
	goto out_unlock;
    }

    shutdown_port(port, "disconnect");
 out_unlock:
    so->unlock(port->lock);
 out:
    return;
}

void
shutdown_ports(void)
{
    port_info_t *port = ports, *next;
    unsigned int shutdown_count = 0;

    /* No need for a lock here, nothing can reconfigure the port list at
       this point. */
    while (port != NULL) {
	port->config_num = -1;
	next = port->next;
	so->lock(port->lock);
	if (change_port_state(NULL, port, PORT_DISABLED, false))
	    wait_for_port_shutdown(port, &shutdown_count);
	so->unlock(port->lock);
	port = next;
    }

    so->wait(accepter_shutdown_wait, shutdown_count, NULL);

    port = ports;
    while (port != NULL) {
	next = port->next;
	shutdown_port(port, "program shutdown");
	port = next;
    }
}

int
check_ports_shutdown(void)
{
    return ports == NULL;
}

void
shutdown_dataxfer(void)
{
    if (rotator_shutdown_wait)
	so->free_waiter(rotator_shutdown_wait);
    if (accepter_shutdown_wait)
	so->free_waiter(accepter_shutdown_wait);
    if (ports_lock)
	so->free_lock(ports_lock);
}

int
init_dataxfer(void)
{
    ports_lock = so->alloc_lock(so);
    if (!ports_lock)
	goto out_nomem;

    accepter_shutdown_wait = so->alloc_waiter(so);
    if (!accepter_shutdown_wait)
	goto out_nomem;

    rotator_shutdown_wait = so->alloc_waiter(so);
    if (!rotator_shutdown_wait)
	goto out_nomem;

    return 0;

 out_nomem:
    shutdown_dataxfer();
    return ENOMEM;
}
