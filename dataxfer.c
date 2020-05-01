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
#include <limits.h>
#include <sys/time.h>

#include <gensio/gensio.h>
#include <gensio/sergensio.h>
#include <gensio/argvutils.h>

#include "ser2net.h"
#include "dataxfer.h"
#include "readconfig.h"
#include "led.h"

#ifdef gensio_version_major
/* When the version info was added, the type was changed. */
typedef struct gensio_addr gaddrinfo;
#define gensio_free_addrinfo(o, a) gensio_addr_free(a)
#include <sys/socket.h>
#include <netdb.h>
#else
typedef struct addrinfo gaddrinfo;
#endif

#define SERIAL "term"
#define NET    "tcp "

/** BASED ON sshd.c FROM openssh.com */
#ifdef HAVE_TCPD_H
#include <tcpd.h>
static char *progname = "ser2net";
#endif /* HAVE_TCPD_H */

/* States for the net_to_dev_state and dev_to_net_state. */
#define PORT_CLOSED			0 /* The accepter is disabled. */
#define PORT_UNCONNECTED		1 /* The TCP port is not connected
                                             to anything right now. */
#define PORT_WAITING_INPUT		2 /* Waiting for input from the
					     input side. */
#define PORT_WAITING_OUTPUT_CLEAR	3 /* Waiting for output to clear
					     so I can send data. */
#define PORT_CLOSING			4 /* Waiting for output close
					     string to be sent. */
char *state_str[] = { "closed", "unconnected", "waiting input",
		      "waiting output", "closing" };

char *enabled_str[] = { "off", "on" };

typedef struct trace_info_s
{
    bool hexdump;     /* output each block as a hexdump */
    bool timestamp;   /* preceed each line with a timestamp */
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

    /*
     * Close the session when all the output has been written to the
     * network port.
     */
    bool close_on_output_done;

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

    /* If false, port is not accepting, if true it is. */
    bool enabled;

    const char *shutdown_reason;

    /* The port has been deleted, but still has connections in use. */
    bool deleted;

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

    unsigned int chardelay;             /* The amount of time to wait after
					   receiving a character before
					   sending it, unless we receive
					   another character.  Based on
					   bit rate. */

    unsigned int bps;			/* Bits per second rate. */
    unsigned int bpc;			/* Bits per character. */
    unsigned int stopbits;
    unsigned int paritybits;

    bool enable_chardelay;

    unsigned int chardelay_scale;	/* The number of character
					   periods to wait for the
					   next character, in tenths of
					   a character period. */
    unsigned int chardelay_min;		/* The minimum chardelay, in
					   microseconds. */
    unsigned int chardelay_max;		/* Maximum amount of time to
					   wait before sending the data. */
    gensio_time send_time;		/* When using chardelay, the
					   time when we will send the
					   data, no matter what, set
					   by chardelay_max. */

    /* Information about the network port. */
    char               *name;           /* The name given for the port. */
    char               *accstr;         /* The accepter string. */
    struct gensio_accepter *accepter;	/* Used to receive new connections. */
    bool accepter_stopped;

    struct port_remaddr *remaddrs;	/* Remote addresses allowed. */
    struct port_remaddr *connbacks;	/* Connect back addresses */
    unsigned int num_waiting_connect_backs;

    unsigned int max_connections;	/* Maximum number of connections
					   we can accept at a time for this
					   port. */
    net_info_t *netcons;

    gensiods dev_bytes_received;    /* Number of bytes read from the device. */
    gensiods dev_bytes_sent;        /* Number of bytes written to the device. */

    /*
     * Informationd use when transferring information from the network
     * port to the terminal device.
     */
    int            net_to_dev_state;		/* State of transferring
						   data from the network port
                                                   to the device. */

    struct gbuf    net_to_dev;			/* Buffer for network
						   to dev transfers. */
    struct controller_info *net_monitor; /* If non-null, send any input
					    received from the network port
					    to this controller port. */
    struct gbuf *devstr;		 /* Outgoing string */

    /*
     * Information used when transferring information from the
     * terminal device to the network port.
     */
    int            dev_to_net_state;		/* State of transferring
						   data from the device to
                                                   the network port. */

    struct gbuf dev_to_net;

    /*
     * We have called shutdown_port but the accepter has not yet been
     * read disabled.
     */
    bool shutdown_started;

    struct controller_info *dev_monitor; /* If non-null, send any input
					    received from the device
					    to this controller port. */

    struct port_info *next;		/* Used to keep a linked list
					   of these. */

    /*
     * The port was reconfigured but had pending users.  This holds the
     * new config until the pending users have finished.
     */
    struct port_info *new_config;

    char *rs485; /* If not NULL, rs485 was specified. */

    /* For RFC 2217 */
    unsigned char last_modemstate;
    unsigned char last_linestate;

    /* Allow RFC 2217 mode */
    bool allow_2217;

    /* Send a break if we get a sync command? */
    bool telnet_brk_on_sync;

    /* kickolduser mode */
    bool kickolduser_mode;

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
    bool io_open;
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

    /*
     * Directory that has authentication info.
     */
    char *authdir;

    /*
     * Delimiter for sending.
     */
    char *sendon;
    gensiods sendon_pos;
    gensiods sendon_len;
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
    gaddrinfo *ai;
    bool is_port_set;
    struct port_remaddr *next;
};

/* Add a remaddr to the given list, return 0 on success or errno on fail. */
static int
remaddr_append(struct port_remaddr **list, struct port_remaddr **cblist,
	       const char *str, bool is_connect_back)
{
    struct port_remaddr *r = NULL, *r2, *rcb = NULL;
    gaddrinfo *ai = NULL;
    bool is_port_set = false;
    int err = 0;

    if (!is_connect_back) {
	if (*str == '!') {
	    str++;
	    is_connect_back = true;
	}

#ifdef gensio_version_major
	err = gensio_scan_network_port(so, str, false, &ai, NULL,
				       &is_port_set, NULL, NULL);
#else
	int socktype, protocol;
	err = gensio_scan_network_port(so, str, false, &ai,
				       &socktype, &protocol,
				       &is_port_set, NULL, NULL);
#endif
	if (err)
	    return err;
	/* FIXME - We currently ignore the protocol. */

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
	ai = NULL;
	r->is_port_set = is_port_set;
	r->next = NULL;

	r2 = *list;
	if (!r2) {
	    *list = r;
	} else {
	    while (r2->next)
		r2 = r2->next;
	    r2->next = r;
	}
    }

    if (is_connect_back) {
	rcb = malloc(sizeof(*rcb));
	if (!rcb) {
	    err = GE_NOMEM;
	    goto out;
	}
	memset(rcb, 0, sizeof(*rcb));

	rcb->str = strdup(str);
	if (!rcb->str) {
	    free(rcb);
	    err = GE_NOMEM;
	    goto out;
	}
	rcb->next = NULL;

	r2 = *cblist;
	if (!r2) {
	    *cblist = rcb;
	} else {
	    while (r2->next)
		r2 = r2->next;
	    r2->next = rcb;
	}
    }
 out:
    if (err) {
	if (r) {
	    if (r->str)
		free(r->str);
	    if (r->ai)
		gensio_free_addrinfo(so, r->ai);
	    free(r);
	}
	if (rcb) {
	    if (rcb->str)
		free(rcb->str);
	    free(rcb);
	}
	if (ai)
	    gensio_free_addrinfo(so, ai);
    }
    return err;
}

static bool
ai_check(gaddrinfo *ai, const struct sockaddr *addr, socklen_t len,
	 bool is_port_set)
{
#ifdef gensio_version_major
    return gensio_addr_addr_present(ai, addr, len, is_port_set);
#else
    while (ai) {
	if (gensio_sockaddr_equal(addr, len, ai->ai_addr, ai->ai_addrlen,
				  is_port_set))
	    return true;
	ai = ai->ai_next;
    }

    return false;
#endif
}

/* Check that the given address matches something in the list. */
static bool
remaddr_check(const struct port_remaddr *list,
	      const struct sockaddr *addr, socklen_t len)
{
    const struct port_remaddr *r = list;

    if (!r)
	return true;

    for (; r; r = r->next) {
	if (ai_check(r->ai, addr, len, r->is_port_set))
	    return true;
    }

    return false;
}

#define for_each_connection(port, netcon) \
    for (netcon = port->netcons;				\
	 netcon < &(port->netcons[port->max_connections]);	\
	 netcon++)

static struct gensio_lock *ports_lock;
static port_info_t *ports = NULL; /* Linked list of ports. */
static port_info_t *new_ports = NULL; /* New ports during config/reconfig. */
static port_info_t *new_ports_end = NULL;

static void shutdown_one_netcon(net_info_t *netcon, const char *reason);
static int shutdown_port(port_info_t *port, const char *errreason);

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
    port->enabled = false;

    port->net_to_dev_state = PORT_CLOSED;
    port->dev_to_net_state = PORT_CLOSED;
    port->trace_read.fd = -1;
    port->trace_write.fd = -1;
    port->trace_both.fd = -1;

    port->telnet_brk_on_sync = find_default_bool("telnet-brk-on-sync");
    port->kickolduser_mode = find_default_bool("kickolduser");
    port->enable_chardelay = find_default_int("chardelay");
    port->chardelay_scale = find_default_int("chardelay-scale");
    port->chardelay_min = find_default_int("chardelay-min");
    port->chardelay_max = find_default_int("chardelay-max");
    port->dev_to_net.maxsize = find_default_int("dev-to-net-bufsize");
    port->net_to_dev.maxsize = find_default_int("net-to-dev-bufsize");
    port->max_connections = find_default_int("max-connections");
    if (find_default_str("authdir", &port->authdir))
	return ENOMEM;
    if (find_default_str("signature", &port->signaturestr))
	return ENOMEM;
    if (find_default_str("banner", &port->bannerstr))
	return ENOMEM;
    if (find_default_str("openstr", &port->openstr))
	return ENOMEM;
    if (find_default_str("closestr", &port->closestr))
	return ENOMEM;
    if (find_default_str("closeon", &port->closeon))
	return ENOMEM;
    if (find_default_str("sendon", &port->sendon))
	return ENOMEM;

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
		       port->name, err);
	    else
		syslog(LOG_ERR, "Unable to write to trace file on port %s: %s",
		       port->name, errbuf);

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
footer_trace(port_info_t *port, char *type, const char *reason)
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

    if (!port->connbacks)
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
		       " addr %s: %s\n", port->name, netcon->remote_str,
		       gensio_err_to_str(err));
		continue;
	    }
	    err = gensio_open(netcon->net, connect_back_done, netcon);
	    if (err) {
		gensio_free(netcon->net);
		netcon->net = NULL;
		syslog(LOG_ERR, "Unable to open connect back port %s,"
		       " addr %s: %s\n", port->name, netcon->remote_str,
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
    if (port->dev_to_net_state != PORT_WAITING_INPUT) {
	gensio_set_read_callback_enable(port->io, false);
	goto out_unlock;
    }

    if (err) {
	if (port->dev_to_net.cursize) {
	    /* Let the output drain before shutdown. */
	    count = 0;
	    send_now = true;
	    goto do_send;
	}

	/* Got an error on the read, shut down the port. */
	syslog(LOG_ERR, "dev read error for device on port %s: %s",
	       port->name, gensio_err_to_str(err));
	if (port->connbacks)
	    port->enabled = false;
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
		    net_info_t *netcon;

		    for_each_connection(port, netcon)
			netcon->close_on_output_done = true;
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

    if (port->sendon_len != 0) {
	int i;

	for (i = 0; i < count; i++) {
	    if (buf[i] == port->sendon[port->sendon_pos]) {
		port->sendon_pos++;
		if (port->sendon_pos >= port->sendon_len) {
		    count = i + 1;
		    send_now = true;
		    port->sendon_pos = 0;
		    break;
		}
	    } else {
		port->sendon_pos = 0;
	    }
	}
    }

    gbuf_append(&port->dev_to_net, buf, count);
    port->dev_bytes_received += count;

    if (send_now || gbuf_room_left(&port->dev_to_net) == 0 ||
		port->chardelay == 0) {
    send_it:
	start_net_send(port);
    } else {
	gensio_time then;
	int delay;

	so->get_monotonic_time(so, &then);
	if (port->send_timer_running) {
	    so->stop_timer(port->send_timer);
	} else {
	    port->send_time = then;
	    add_usec_to_time(&port->send_time, port->chardelay_max);
	}
	delay = sub_time(&port->send_time, &then);
	if (delay > port->chardelay)
	    delay = port->chardelay;
	else if (delay < 0) {
	    port->send_timer_running = false;
	    goto send_it;
	}
	add_usec_to_time(&then, delay);
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
    gensiods len = 0;

    if (buflen)
	len = *buflen;

    switch (event) {
    case GENSIO_EVENT_READ:
	if (gensio_str_in_auxdata(auxdata, "oob"))
	    /* Ignore out of bound data. */
	    return 0;
	len = handle_dev_read(port, err, buf, len);
	if (buflen)
	    *buflen = len;
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
	return GE_NOTSUP;
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
	       port->name, gensio_err_to_str(err));
	if (port->connbacks)
	    port->enabled = false;
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
	if (readerr == GE_REMCLOSE) {
	    reason = "network read close";
	} else {
	    /* Got an error on the read, shut down the port. */
	    syslog(LOG_ERR, "read error for port %s: %s", port->name,
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
	syslog(LOG_ERR, "The dev write for port %s had error: %s",
	       port->name, gensio_err_to_str(err));
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
    if (reterr == GE_REMCLOSE) {
	shutdown_one_netcon(netcon, "Remote closed");
	return -1;
    } else if (reterr) {
	/* Some other bad error. */
	syslog(LOG_ERR, "The network write for port %s had error: %s",
	       port->name, gensio_err_to_str(reterr));
	shutdown_one_netcon(netcon, "network write error");
	return -1;
    }
    *pos += count;
    netcon->bytes_sent += count;

    if (*pos < buf->cursize)
	return 0;

    return 1;
}

static void
finish_dev_to_net_write(port_info_t *port)
{
    if (any_net_data_to_write(port))
	return;

    port->dev_to_net.cursize = 0;
    port->dev_to_net.pos = 0;

    if (port->net_to_dev_state != PORT_CLOSING) {
	/* We are done writing on this port, turn the reader back on. */
	gensio_set_read_callback_enable(port->io, true);
	port->dev_to_net_state = PORT_WAITING_INPUT;
    }
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

	if (rv == 0)
	    goto out_unlock;

	if (netcon->close_on_output_done) {
	    netcon->close_on_output_done = false;
	    shutdown_one_netcon(netcon, "port closing");
	    rv = -1;
	}
	finish_dev_to_net_write(port);
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
    gensiods len= 0;

    if (buflen)
	len = *buflen;

    switch (event) {
    case GENSIO_EVENT_READ:
	len = handle_net_fd_read(netcon, net, err, buf, len);
	if (buflen)
	    *buflen = len;
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
	s2n_signature(netcon, gensio_to_sergensio(net), (char *) buf, len);
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
	return GE_NOTSUP;
    }
}

static void handle_net_fd_closed(struct gensio *net, void *cb_data);

static bool
port_in_use(port_info_t *port)
{
    return (port->net_to_dev_state != PORT_UNCONNECTED &&
	    port->net_to_dev_state != PORT_CLOSED);
}

/* Checks to see if some other port has the same device in use.  Must
   be called with ports_lock held. */
static int
is_device_already_inuse(port_info_t *check_port)
{
    port_info_t *port = ports;

    while (port != NULL) {
	if (port != check_port) {
	    if ((strcmp(port->devname, check_port->devname) == 0)
				&& port_in_use(port)) {
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
		else if (*s == 'o')
		    s2 = port->name;
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

	    /* Port's name. */
	    case 'N':
		for (t = port->name; *t; t++)
		    op(data, *t);
		break;

	    case 'p':
		/* ser2net network port. */
		for (t = port->accstr; *t; t++)
		    op(data, *t);
		break;

	    case 'B':
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
		char d[12], *dp;
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
		if (v <= 0 || v >= 24)
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
	bufop.str = malloc(1);
    else
	bufop.str = malloc(len + 1);
    if (!bufop.str) {
	syslog(LOG_ERR, "Out of memory processing string: %s", port->name);
	return NULL;
    }
    process_str(port, netcon, &now, tv, str, buffer_op, &bufop, isfilename);
    bufop.str[len] = '\0';

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
	syslog(LOG_ERR, "Out of memory processing string: %s", port->name);
	return NULL;
    }
    bstr = process_str_to_str(port, netcon, str, &tv, &len, 0);
    if (!bstr) {
	free(buf);
	syslog(LOG_ERR, "Error processing string: %s", port->name);
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
    unsigned int bpc = port->bpc + port->stopbits + port->paritybits + 1;

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
    gensio_time timeout;

    so->lock(port->lock);
    if (err) {
	char errstr[200];

	snprintf(errstr, sizeof(errstr), "Device open failure: %s\r\n",
		 gensio_err_to_str(err));
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

#ifdef gensio_version_major
    timeout.secs = 1;
    timeout.nsecs = 0;
#else
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
#endif
    so->start_timer(port->timer, &timeout);

    for_each_connection(port, netcon) {
	if (!netcon->net)
	    continue;
	finish_setup_net(port, netcon);
    }
    port->net_to_dev_state = PORT_WAITING_INPUT;
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
    port->io_open = true;

    err = gensio_control(port->io, GENSIO_CONTROL_DEPTH_ALL, false,
			 GENSIO_CONTROL_NODELAY, auxdata, NULL);
    if (err)
	syslog(LOG_ERR, "Could not enable NODELAY on port %s: %s",
	       port->name, gensio_err_to_str(err));

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
	syslog(LOG_ERR, "Could not enable NODELAY on socket %s: %s",
	       port->name, gensio_err_to_str(err));

    if (netcon->banner) {
	free(netcon->banner->buf);
	free(netcon->banner);
    }
    netcon->banner = process_str_to_buf(port, netcon, port->bannerstr);

    if (num_connected_net(port) == 1 && !port->connbacks) {
	/* We are first, set things up on the device. */
	err = port_dev_enable(port);
	if (err) {
	    char errstr[200];

	    snprintf(errstr, sizeof(errstr), "Device open failure: %s\r\n",
		     gensio_err_to_str(err));
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
	if (strcmp(port->name, portname) == 0) {
	    unsigned int i;
	    struct sockaddr_storage addr;
	    gensiods socklen;
	    int err;

	    so->lock(port->lock);
	    if (!port->enabled)
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

    char *name;
    char *accstr;

    struct gensio_accepter *accepter;

    char *authdir;

    struct rotator *next;
} rotator_t;

static rotator_t *rotators = NULL;

/* A connection request has come in on a port. */
static int
rot_new_con(rotator_t *rot, struct gensio *net)
{
    int i;
    const char *err;

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

static int
handle_rot_child_event(struct gensio_accepter *accepter, void *user_data,
		       int event, void *data)
{
    rotator_t *rot = user_data;

    if (event == GENSIO_ACC_EVENT_LOG) {
	do_gensio_log(rot->accstr, data);
	return 0;
    }

    switch (event) {
    case GENSIO_ACC_EVENT_NEW_CONNECTION:
	return rot_new_con(rot, data);

    default:
	return handle_acc_auth_event(rot->authdir, event, data);
    }
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
    if (rot->authdir)
	free(rot->authdir);
    if (rot->name)
	free(rot->name);
    if (rot->accstr)
	free(rot->accstr);
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
add_rotator(const char *name, const char *accstr, int portc, const char **ports,
	    const char **options, int lineno)
{
    rotator_t *rot;
    int rv;

    rot = malloc(sizeof(*rot));
    if (!rot)
	return ENOMEM;
    memset(rot, 0, sizeof(*rot));

    rot->name = strdup(name);
    if (!rot->name) {
	free_rotator(rot);
	return ENOMEM;
    }

    rot->accstr = strdup(accstr);
    if (!rot->accstr) {
	free_rotator(rot);
	return ENOMEM;
    }

    if (find_default_str("authdir", &rot->authdir)) {
	free_rotator(rot);
	return ENOMEM;
    }

    if (options) {
	unsigned int i;
	const char *str;

	for (i = 0; options[i]; i++) {
	    if (gensio_check_keyvalue(options[i], "authdir", &str) > 0) {
		if (rot->authdir)
		    free(rot->authdir);
		rot->authdir = strdup(str);
		if (!rot->authdir) {
		    free_rotator(rot);
		    syslog(LOG_ERR, "Out of memory allocating rotator"
			   " authdir on line %d\n", lineno);
		    return ENOMEM;
		}
		continue;
	    }
	    free_rotator(rot);
	    syslog(LOG_ERR, "Invalid option %s for rotator on line %d\n",
		   options[i], lineno);
	    return EINVAL;
	}
    }

    rot->portc = portc;
    rot->portv = ports;

    rv = str_to_gensio_accepter(rot->accstr, so,
				handle_rot_child_event, rot, &rot->accepter);
    if (rv) {
	syslog(LOG_ERR, "accepter was invalid on line %d", lineno);
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
    if (rv) {
	rot->portc = 0;
	rot->portv = NULL;
	free_rotator(rot);
    }
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

    if (netcon->net) {
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

static int
port_new_con(port_info_t *port, struct gensio *net)
{
    const char *err = NULL;
    unsigned int i, j;
    struct sockaddr_storage addr;
    gensiods socklen;

    so->lock(ports_lock); /* For is_device_already_inuse() */
    so->lock(port->lock);

    if (port->net_to_dev_state == PORT_CLOSING) {
	/* Can happen on a race with the callback disable. */

	if (!port->enabled) {
	    err = "Port closing\r\n";
	    goto out_err;
	}
	/* We hold off new connections during a close */
	goto out;
    }

    if (!port->enabled) {
	err = "Port disabled\r\n";
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

/* A connection request has come in on a port. */
static int
handle_port_child_event(struct gensio_accepter *accepter, void *user_data,
			int event, void *data)
{
    port_info_t *port = user_data;

    if (event == GENSIO_ACC_EVENT_LOG) {
	do_gensio_log(port->name, data);
	return 0;
    }

    switch (event) {
    case GENSIO_ACC_EVENT_NEW_CONNECTION:
	return port_new_con(port, data);

    default:
	return handle_acc_auth_event(port->authdir, event, data);
    }
}

static void
finish_startup_port_err(struct gensio_accepter *acc, void *cb_data)
{
    port_info_t *port = cb_data;

    so->lock(port->lock);
    port->dev_to_net_state = PORT_CLOSED;
    port->net_to_dev_state = PORT_CLOSED;
    so->unlock(port->lock);
}

static int
startup_port(struct absout *eout, port_info_t *port)
{
    int err;

    if (port->dev_to_net_state != PORT_CLOSED)
	return GE_INUSE;

    err = gensio_acc_startup(port->accepter);
    if (err) {
	eout->out(eout, "Unable to startup network port %s: %s",
		  port->name, gensio_err_to_str(err));
	return err;
    }
    port->dev_to_net_state = PORT_UNCONNECTED;
    port->net_to_dev_state = PORT_UNCONNECTED;

    if (port->connbacks) {
	err = port_dev_enable(port);
	if (err) {
	    port->dev_to_net_state = PORT_CLOSING;
	    port->net_to_dev_state = PORT_CLOSING;
	    eout->out(eout, "Unable to enable port device %s: %s",
		      port->name, gensio_err_to_str(err));
	    if (gensio_acc_shutdown(port->accepter, finish_startup_port_err,
				    port))
		/* Shouldn't happen, but just in case... */
		finish_startup_port_err(NULL, port);
	}
    }

    return err;
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
    while (port->connbacks) {
	r = port->connbacks;
	port->connbacks = r->next;
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
    if (port->name)
	free(port->name);
    if (port->accstr)
	free(port->accstr);
    if (port->new_config)
	free_port(port->new_config);
    if (port->bannerstr)
	free(port->bannerstr);
    if (port->signaturestr)
	free(port->signaturestr);
    if (port->authdir)
	free(port->authdir);
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
    if (port->sendon)
	free(port->sendon);
    free(port);
}

static void
finish_shutdown_port(struct gensio_runner *runner, void *cb_data)
{
    port_info_t *port = cb_data;

    so->lock(ports_lock);
    so->lock(port->lock);

    if (port->enabled) {
	port->net_to_dev_state = PORT_UNCONNECTED;
	port->dev_to_net_state = PORT_UNCONNECTED;
    } else {
	port->net_to_dev_state = PORT_CLOSED;
	port->dev_to_net_state = PORT_CLOSED;
    }
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

    /* If the port has been deleted, then finish the job. */
    if (port->deleted) {
	port_info_t *curr, *prev, *new;

	new = port->new_config;
	port->new_config = NULL;

	prev = NULL;
	for (curr = ports; curr && curr != port; curr = curr->next)
	    prev = curr;
	if (curr) {
	    if (prev == NULL)
		ports = curr->next;
	    else
		prev->next = curr->next;
	}
	so->unlock(port->lock);

	free_port(port);

	/* Start the replacement port if it was set. */
	if (new) {
	    int err;

	    so->lock(new->lock);
	    if (prev) {
		new->next = prev->next;
		prev->next = new;
	    } else {
		new->next = ports;
		ports = new;
	    }
	    if (new->enabled) {
		err = startup_port(&syslog_absout, new);
		if (err)
		    new->enabled = false;
	    }
	    so->unlock(new->lock);
	}
	so->unlock(ports_lock);
	return; /* We have to return here because we no longer have a port. */
    } else {
	net_info_t *netcon;

	gensio_acc_set_accept_callback_enable(port->accepter, true);
	for_each_connection(port, netcon)
	    check_port_new_net(port, netcon);
    }
    so->unlock(port->lock);
    so->unlock(ports_lock);
}

static void
io_shutdown_done(struct gensio *io, void *cb_data)
{
    port_info_t *port = cb_data;

    port->io_open = false;
    so->run(port->runshutdown);
}

static void
shutdown_port_io(port_info_t *port)
{
    int err = 1;

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

    if (port->io)
	err = gensio_close(port->io, io_shutdown_done, port);

    if (err) {
	port->io_open = false;
	so->run(port->runshutdown);
    }
}

static void
timer_shutdown_done(struct gensio_timer *timer, void *cb_data)
{
    port_info_t *port = cb_data;

    so->lock(port->lock);
    gensio_set_write_callback_enable(port->io, false);
    shutdown_port_io(port);
    so->unlock(port->lock);
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
	       port->name, gensio_err_to_str(err));
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
    if (!port->io_open) {
	so->run(port->runshutdown);
	return;
    }

    if (port->devstr) {
	free(port->devstr->buf);
	free(port->devstr);
    }
    port->devstr = process_str_to_buf(port, NULL, port->closestr);
    port->dev_write_handler = handle_dev_fd_close_write;
    gensio_set_write_callback_enable(port->io, true);
}

static void
netcon_finish_shutdown(net_info_t *netcon)
{
    port_info_t *port = netcon->port;

    if (netcon->net) {
	gensio_free(netcon->net);
	netcon->net = NULL;
    }

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
	if (port->net_to_dev_state == PORT_CLOSING) {
	    start_shutdown_port_io(port);
	} else if (port->connbacks && port->enabled) {
	    /* Leave the device open for connect backs. */
	    gensio_set_write_callback_enable(port->io, true);
	    port->dev_to_net_state = PORT_WAITING_INPUT;
	    port->net_to_dev_state = PORT_UNCONNECTED;
	    check_port_new_net(port, netcon);
	} else {
	    shutdown_port(port, NULL);
	}
    } else {
	check_port_new_net(port, netcon);
    }
}

static void
handle_net_fd_closed(struct gensio *net, void *cb_data)
{
    net_info_t *netcon = cb_data;
    port_info_t *port = netcon->port;

    so->lock(port->lock);
    netcon_finish_shutdown(netcon);
    so->unlock(port->lock);
}

static void
shutdown_one_netcon(net_info_t *netcon, const char *reason)
{
    int err;

    if (netcon->closing)
	return;

    netcon->write_pos = 0;
    footer_trace(netcon->port, "netcon", reason);

    netcon->closing = true;
    err = gensio_close(netcon->net, handle_net_fd_closed, netcon);
    if (err)
	netcon_finish_shutdown(netcon);
}

static bool
shutdown_all_netcons(port_info_t *port)
{
    net_info_t *netcon;
    bool some_to_close = false;

    for_each_connection(port, netcon) {
	if (netcon->net) {
	    some_to_close = true;
	    netcon->close_on_output_done = false;
	    netcon->write_pos = port->dev_to_net.cursize;
	    shutdown_one_netcon(netcon, "port closing");
	}
    }

    return some_to_close;
}

static bool
handle_shutdown_timeout(port_info_t *port)
{
    /* Something wasn't able to do any writes and locked up the shutdown. */

    /* Check the network connections first. */
    if (shutdown_all_netcons(port))
	return true;

    shutdown_port_io(port);
    return false;
}

static void
accept_read_disabled(struct gensio_accepter *acc, void *cb_data)
{
    port_info_t *port = cb_data;
    net_info_t *netcon;
    bool some_to_close = false;

    so->lock(port->lock);
    port->shutdown_started = false;

    /*
     * At this point we won't receive any more accepts until we re-enable it,
     * go into closing state unless it wasn't an error and a new net came in.
     */
    if (port->net_to_dev_state != PORT_CLOSING &&
		num_connected_net(port) > 0) {
	/*
	 * It wasn't an error close and a new connection came in.  Just
	 * ignore the shutdown.
	 */
	gensio_acc_set_accept_callback_enable(port->accepter, true);
	for_each_connection(port, netcon) {
	    if (netcon->net)
		gensio_set_read_callback_enable(netcon->net, true);
	}
	gensio_set_read_callback_enable(port->io, true);
	goto out_unlock;
    }

    /* After this point we will shut down the port completely. */

    /* FIXME - this should be calculated somehow, not a raw number .*/
    port->shutdown_timeout_count = 4;

    if (port->shutdown_reason)
	footer_trace(port, "port", port->shutdown_reason);
    else
	footer_trace(port, "port", "All users disconnected");

    /*
     * If close_on_output_done is already set, the netcons are all set to
     * close, anyway.  No need to kick that off.
     */
    for_each_connection(port, netcon) {
	if (netcon->net) {
	    some_to_close = true;
	    if (netcon->new_net) {
		/* Something is waiting for a kick. */
		char *err = "port is shutting down\r\n";

		gensio_write(netcon->new_net, NULL, err, strlen(err), NULL);
		gensio_free(netcon->new_net);
		netcon->new_net = NULL;
	    }

	    if (port->dev_to_net_state == PORT_WAITING_OUTPUT_CLEAR &&
			netcon->write_pos < port->dev_to_net.cursize)
		/* Net has data to send, wait until it's done. */
		netcon->close_on_output_done = true;
	    else
		shutdown_one_netcon(netcon, "port closing");
	}
    }

    if (!some_to_close) {
	if (port->connbacks && port->enabled) {
	    /* Leave the device open for connect backs. */
	    port->dev_to_net_state = PORT_UNCONNECTED;
	    port->net_to_dev_state = PORT_UNCONNECTED;
	    goto out_unlock;
	} else {
	    start_shutdown_port_io(port);
	}
    }

    port->dev_to_net_state = PORT_CLOSING;
    port->net_to_dev_state = PORT_CLOSING;

 out_unlock:
    so->unlock(port->lock);
}

static int
shutdown_port(port_info_t *port, const char *errreason)
{
    net_info_t *netcon;
    int err;

    if (port->shutdown_started && port->net_to_dev_state != PORT_CLOSING
		&& errreason) {
	/* An error occurred and we are in a non-err shutdown.  Convert it. */
	port->shutdown_reason = errreason;
	port->net_to_dev_state = PORT_CLOSING;
	return 0;
    }

    if (port->net_to_dev_state == PORT_CLOSING ||
		port->net_to_dev_state == PORT_CLOSED ||
		(port->enabled && port->dev_to_net_state == PORT_UNCONNECTED) ||
		port->shutdown_started)
	return GE_INUSE;

    port->shutdown_reason = errreason;
    if (errreason)
	/* It's an error, force a shutdown.  Don't set dev_to_net_state yet. */
	port->net_to_dev_state = PORT_CLOSING;

    port->shutdown_started = true;

    err = gensio_acc_set_accept_callback_enable_cb(port->accepter, false,
						   accept_read_disabled, port);
    /* This is bad, it's an out of memory condition. Abort. */
    assert(err == 0);

    for_each_connection(port, netcon) {
	if (netcon->net)
	    gensio_set_read_callback_enable(netcon->net, false);
    }
    gensio_set_read_callback_enable(port->io, false);
    return 0;
}

void
got_timeout(struct gensio_timer *timer, void *data)
{
    port_info_t *port = (port_info_t *) data;
    gensio_time timeout;
    net_info_t *netcon;

    so->lock(port->lock);

    if (port->dev_to_net_state == PORT_CLOSING) {
	if (port->shutdown_timeout_count <= 1) {
	    int count = port->shutdown_timeout_count;
	    bool dotimer = false;

	    port->shutdown_timeout_count = 0;
	    if (count == 1)
		dotimer = handle_shutdown_timeout(port);
	    so->unlock(port->lock);
	    if (dotimer)
		goto out;
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

    if (port->timeout && port_in_use(port)) {
	for_each_connection(port, netcon) {
	    if (!netcon->net)
		continue;
	    netcon->timeout_left--;
	    if (netcon->timeout_left < 0)
		shutdown_one_netcon(netcon, "timeout");
	}
    }

 out:
#ifdef gensio_version_major
    timeout.secs = 1;
    timeout.nsecs = 0;
#else
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
#endif
    so->start_timer(port->timer, &timeout);
    so->unlock(port->lock);
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
	err = remaddr_append(&port->remaddrs, &port->connbacks, remstr, false);
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
port_add_connback(struct absout *eout, port_info_t *port, const char *istr)
{
    char *str;
    char *strtok_data;
    char *remstr;
    int err = 0;

    str = strdup(istr);
    if (!str) {
	eout->out(eout, "Out of memory handling connect back address '%s'",
		  istr);
	return ENOMEM;
    }

    remstr = strtok_r(str, ";", &strtok_data);
    /* Note that we ignore an empty remaddr. */
    while (remstr && *remstr) {
	err = remaddr_append(NULL, &port->connbacks, remstr, true);
	if (err) {
	    eout->out(eout, "Error adding connect back address '%s': %s\n",
		      remstr, gensio_err_to_str(err));
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
    "XONXOFF", NULL,
    "-XONXOFF", "xonxoff=false",
    "RTSCTS", NULL,
    "-RTSCTS", "rtscts=false",
    "LOCAL", NULL,
    "-LOCAL", "local=false",
    "HANGUP_WHEN_DONE", "hangup-when-done",
    "-HANGUP_WHEN_DONE", "hangup-when-done=false",
    "NOBREAK", NULL,
    "-NOBREAK", "nobreak=false",
    "NONE", NULL,
    "EVEN", NULL,
    "ODD", NULL,
    "MARK", NULL,
    "SPACE", NULL,
    NULL
};

static bool
matchstr(const char *parms[], const char *c, const char **newval)
{
    unsigned int i;

    for (i = 0; parms[i]; i += 2) {
	if (strcmp(parms[i], c) == 0) {
	    if (parms[i + 1])
		*newval = parms[i + 1];
	    else
		*newval = parms[i];
	    return true;
	}
    }
    return false;
}

static int
check_keyvalue_default(const char *str, const char *name, const char **value,
		       const char *def)
{
    if (strcmp(str, name) == 0)
	*value = def;
    else
	return gensio_check_keyvalue(str, name, value);
    return 1;
}

static int
update_str_val(const char *str, char **outstr, const char *name,
	       struct absout *eout)
{
    char *fval = strdup(str);

    if (!fval) {
	eout->out(eout, "Out of memory allocating %s", name);
	return -1;
    }
    if (*outstr)
	free(*outstr);
    *outstr = fval;
    return 0;
}

static int
myconfig(port_info_t *port, struct absout *eout, const char *pos)
{
    enum str_type stype;
    char *s, *fval;
    const char *val, *newval = pos;
    unsigned int len;
    int rv;

    /*
     * This is a hack for backwards compatibility, if we see a config
     * item meant for the device, we stick it onto the device name.
     */
    if (isdigit(pos[0]) || matchstr(serialdev_parms, pos, &newval)) {
	int err = strdupcat(&port->devname, newval);

	if (err) {
	    eout->out(eout, "Out of memory appending to devname");
	    return -1;
	}
    } else if (gensio_check_keybool(pos, "kickolduser",
				    &port->kickolduser_mode) > 0) {
    } else if (gensio_check_keybool(pos, "trace-hexdump",
				    &port->trace_read.hexdump) > 0) {
	port->trace_write.hexdump = port->trace_read.hexdump;
	port->trace_both.hexdump = port->trace_read.hexdump;
    } else if (gensio_check_keybool(pos, "trace-timestamp",
				    &port->trace_read.timestamp) > 0) {
	port->trace_write.timestamp = port->trace_read.timestamp;
	port->trace_both.timestamp = port->trace_read.timestamp;
    } else if (gensio_check_keybool(pos, "trace-read-hexdump",
				    &port->trace_read.hexdump) > 0) {
    } else if (gensio_check_keybool(pos, "trace-read-timestamp",
				    &port->trace_read.timestamp) > 0) {
    } else if (gensio_check_keybool(pos, "trace-write-hexdump",
				    &port->trace_write.hexdump) > 0) {
    } else if (gensio_check_keybool(pos, "trace-write-timestamp",
				    &port->trace_write.timestamp) > 0) {
    } else if (gensio_check_keybool(pos, "trace-both-hexdump",
				    &port->trace_both.hexdump) > 0) {
    } else if (gensio_check_keybool(pos, "trace-both-timestamp",
				    &port->trace_both.timestamp) > 0) {
    } else if (gensio_check_keyvalue(pos, "trace-read", &val) > 0) {
	/* trace read, data from the port to the socket */
	if (update_str_val(val, &port->trace_read.filename, "trace-read", eout))
	    return -1;
    } else if (gensio_check_keyvalue(pos, "trace-write", &val) > 0) {
	/* trace write, data from the socket to the port */
	if (update_str_val(val, &port->trace_write.filename, "trace-write",
			   eout))
	    return -1;
    } else if (gensio_check_keyvalue(pos, "trace-both", &val) > 0) {
	/* trace both directions. */
	if (update_str_val(val, &port->trace_both.filename, "trace-both", eout))
	    return -1;
    } else if (gensio_check_keyvalue(pos, "led-rx", &val) > 0) {
	/* LED for UART RX traffic */
	port->led_rx = find_led(val);
	if (!port->led_rx) {
	    eout->out(eout, "Could not find led-rx LED: %s", val);
	    return -1;
	}
    } else if (gensio_check_keyvalue(pos, "led-tx", &val) > 0) {
	/* LED for UART TX traffic */
	port->led_tx = find_led(val);
	if (!port->led_tx) {
	    eout->out(eout, "Could not find led-tx LED: %s", val);
	    return -1;
	}
    } else if (gensio_check_keybool(pos, "telnet-brk-on-sync",
				    &port->telnet_brk_on_sync) > 0) {
    } else if (gensio_check_keybool(pos, "chardelay",
				    &port->enable_chardelay) > 0) {
    } else if (gensio_check_keyuint(pos, "chardelay-scale",
				   &port->chardelay_scale) > 0) {
    } else if (gensio_check_keyuint(pos, "chardelay-min",
				   &port->chardelay_min) > 0) {
    } else if (gensio_check_keyuint(pos, "chardelay-max",
				   &port->chardelay_max) > 0) {
    } else if (gensio_check_keyds(pos, "dev-to-net-bufsize",
				  &port->dev_to_net.maxsize) > 0) {
	if (port->dev_to_net.maxsize < 2)
	    port->dev_to_net.maxsize = 2;
    } else if (gensio_check_keyds(pos, "net-to-dev-bufsize",
				  &port->net_to_dev.maxsize) > 0) {
	if (port->net_to_dev.maxsize < 2)
	    port->net_to_dev.maxsize = 2;
    } else if (gensio_check_keyuint(pos, "max-connections",
				   &port->max_connections) > 0) {
	if (port->max_connections < 1)
	    port->max_connections = 1;
    } else if (gensio_check_keyvalue(pos, "authdir", &val) > 0) {
	fval = strdup(val);
	if (!fval) {
	    eout->out(eout, "Out of memory allocating authdir");
	    return -1;
	}
	if (port->authdir)
	    free(port->authdir);
	port->authdir = fval;
    } else if (gensio_check_keyvalue(pos, "remaddr", &val) > 0) {
	rv = port_add_remaddr(eout, port, val);
	if (rv)
	    return -1;
    } else if (gensio_check_keyvalue(pos, "connback", &val) > 0) {
	rv = port_add_connback(eout, port, val);
	if (rv)
	    return -1;
    } else if (check_keyvalue_default(pos, "banner", &val, "") > 0) {
	fval = strdup(val);
	if (!fval) {
	    eout->out(eout, "Out of memory allocating banner");
	    return -1;
	}
	if (port->bannerstr)
	    free(port->bannerstr);
	port->bannerstr = fval;
    } else if (check_keyvalue_default(pos, "openstr", &val, "") > 0) {
	fval = strdup(val);
	if (!fval) {
	    eout->out(eout, "Out of memory allocating openstr");
	    return -1;
	}
	if (port->openstr)
	    free(port->openstr);
	port->openstr = fval;
    } else if (check_keyvalue_default(pos, "closestr", &val, "") > 0) {
	fval = strdup(val);
	if (!fval) {
	    eout->out(eout, "Out of memory allocating closestr");
	    return -1;
	}
	if (port->closestr)
	    free(port->closestr);
	port->closestr = fval;
    } else if (gensio_check_keyvalue(pos, "closeon", &val) > 0) {
	struct timeval tv = { 0, 0 };
	gensiods len;

	fval = process_str_to_str(port, NULL, val, &tv, &len, false);
	if (!fval) {
	    eout->out(eout, "Out of memory allocating closeon");
	    return -1;
	}
	if (port->closeon)
	    free(port->closeon);
	port->closeon = fval;
	port->closeon_len = len;
    } else if (check_keyvalue_default(pos, "signature", &val, "") > 0) {
	fval = strdup(val);
	if (!fval) {
	    eout->out(eout, "Out of memory banner");
	    return -1;
	}
	if (port->signaturestr)
	    free(port->signaturestr);
	port->signaturestr = fval;
    } else if (gensio_check_keyvalue(pos, "sendon", &val) > 0) {
	struct timeval tv =  { 0, 0 };
	gensiods len;

	fval= process_str_to_str(port, NULL, val, &tv, &len, false);
	if (!fval) {
	    eout->out(eout, "Out of memory allocating sendon");
	    return -1;
	}
	if (port->sendon)
	    free(port->sendon);
	port->sendon = fval;
	port->sendon_len = len;

    /* Everything from here down to the banner, etc is deprecated. */
    } else if (strcmp(pos, "remctl") == 0) {
	port->allow_2217 = true;
    } else if (strcmp(pos, "-remctl") == 0) {
	port->allow_2217 = false;
    } else if (strcmp(pos, "-kickolduser") == 0) {
        port->kickolduser_mode = 0;
    } else if (strcmp(pos, "-hexdump") == 0) {
	port->trace_read.hexdump = false;
	port->trace_write.hexdump = false;
	port->trace_both.hexdump = false;
    } else if (strcmp(pos, "-timestamp") == 0) {
	port->trace_read.timestamp = false;
	port->trace_write.timestamp = false;
	port->trace_both.timestamp = false;
    } else if (strcmp(pos, "-tr-hexdump") == 0) {
	port->trace_read.hexdump = false;
    } else if (strcmp(pos, "-tr-timestamp") == 0) {
	port->trace_read.timestamp = false;
    } else if (strcmp(pos, "-tw-hexdump") == 0) {
	port->trace_write.hexdump = false;
    } else if (strcmp(pos, "-tw-timestamp") == 0) {
	port->trace_write.timestamp = false;
    } else if (strcmp(pos, "-tb-hexdump") == 0) {
	port->trace_both.hexdump = false;
    } else if (strcmp(pos, "-tb-timestamp") == 0) {
	port->trace_both.timestamp = false;
    } else if (gensio_check_keyvalue(pos, "tr", &val) > 0) {
	/* trace read, data from the port to the socket */
	port->trace_read.filename = find_tracefile(val);
    } else if (gensio_check_keyvalue(pos, "tw", &val) > 0) {
	/* trace write, data from the socket to the port */
	port->trace_write.filename = find_tracefile(val);
    } else if (gensio_check_keyvalue(pos, "tb", &val) > 0) {
	/* trace both directions. */
	port->trace_both.filename = find_tracefile(val);
    } else if (gensio_check_keyvalue(pos, "rs485", &val) > 0) {
	port->rs485 = find_rs485conf(val);
    } else if (strcmp(pos, "telnet_brk_on_sync") == 0) {
	port->telnet_brk_on_sync = 1;
    } else if (strcmp(pos, "-telnet_brk_on_sync") == 0) {
	port->telnet_brk_on_sync = 0;
    } else if (strcmp(pos, "-chardelay") == 0) {
	port->enable_chardelay = false;

    /* Banner and friend handling. */
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

static void
process_connect_back(struct absout *eout, port_info_t *port,
		     struct port_remaddr *r)
{
    net_info_t *netcon;

    for_each_connection(port, netcon) {
        if (netcon->remote_fixed)
            continue;

	netcon->remote_fixed = true;
	netcon->remote_str = r->str;
	netcon->connect_back = true;
	return;
    }

    if (eout)
	eout->out(eout, "Too many connect back remote addresses specified"
		  " for the max-connections given");
}

/* Create a port based on a set of parameters passed in. */
int
portconfig(struct absout *eout,
	   const char *name,
	   const char *accstr,
	   const char *state,
	   unsigned int timeout,
	   const char *devname,
	   const char * const *devcfg)
{
    port_info_t *new_port, *curr;
    net_info_t *netcon;
    enum str_type str_type;
    int err;
    bool do_telnet = false;
    bool write_only = false;
    unsigned int i;
    struct port_remaddr *r;

    so->lock(ports_lock);
    curr = new_ports;
    while (curr) {
	if (strcmp(curr->name, name) == 0) {
	    /* We don't allow duplicate names. */
	    so->unlock(ports_lock);
	    eout->out(eout, "Duplicate connection name: %s", name);
	    return -1;
	}
	curr = curr->next;
    }
    so->unlock(ports_lock);

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

    new_port->runshutdown = so->alloc_runner(so, finish_shutdown_port,
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

    init_port_data(new_port);

    if (!new_port->name) {
	new_port->name = strdup(name);
	if (!new_port->name) {
	    eout->out(eout, "unable to allocate port name");
	    goto errout;
	}
    }

    if (!new_port->accstr) {
	new_port->accstr = strdup(accstr);
	if (!new_port->accstr) {
	    eout->out(eout, "unable to allocate port accepter string");
	    goto errout;
	}
    }

    if (strcmp(state, "on") == 0) {
	new_port->enabled = true;
    } else if (strcmp(state, "raw") == 0) {
	new_port->enabled = true;
    } else if (strcmp(state, "rawlp") == 0) {
	/* FIXME - remove this someday. */
	new_port->enabled = true;
	write_only = true;
    } else if (strcmp(state, "telnet") == 0) {
	/* FIXME - remove this someday. */
	new_port->enabled = true;
	do_telnet = true;
    } else if (strcmp(state, "off") == 0) {
	new_port->enabled = false;
    } else {
	eout->out(eout, "state was invalid");
	goto errout;
    }

    new_port->timeout = timeout;

    for (i = 0; devcfg[i]; i++) {
	err = myconfig(new_port, eout, devcfg[i]);
	if (err)
	    goto errout;
    }

    if (write_only) {
	err = strdupcat(&new_port->devname, "WRONLY");
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

    err = str_to_gensio_accepter(new_port->accstr, so,
				handle_port_child_event, new_port,
				&new_port->accepter);
    if (err) {
	eout->out(eout, "Invalid port name/number: %s", gensio_err_to_str(err));
	goto errout;
    }

    if (new_port->enabled && do_telnet) {
	const char *str = "telnet";
	struct gensio_accepter *parent;

	if (new_port->allow_2217)
	    str = "telnet(rfc2217=true)";
	err = str_to_gensio_accepter_child(new_port->accepter, str,
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
     * Don't handle the remaddr/connect back defaults until here, we
     * don't want to mess with it if the user has set it, because the
     * user may set it to an empty string.
     */
    if (!new_port->remaddrs) {
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
    if (!new_port->connbacks) {
	char *remaddr;
	if (find_default_str("connback", &remaddr)) {
	    eout->out(eout, "Out of memory processing default connect back "
		      "address");
	} else if (remaddr) {
	    err = port_add_connback(eout, new_port, remaddr);
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
    for_each_connection(new_port, netcon)
	netcon->port = new_port;

    for (r = new_port->connbacks; r; r = r->next)
	process_connect_back(eout, new_port, r);

    /* Link it on the end of new_ports for now. */
    if (new_ports_end)
	new_ports_end->next = new_port;
    else
	new_ports = new_port;
    new_ports_end = new_port;

    return 0;

errout:
    free_port(new_port);
    return -1;
}

void
apply_new_ports(struct absout *eout)
{
    port_info_t *new, *curr, *next, *prev, *new_prev;
    int err;

    so->lock(ports_lock);
    /* First turn off all the accepters. */
    for (curr = ports; curr; curr = curr->next) {
	int err;

	if (curr->deleted)
	    continue;

	if (curr->enabled) {
	    /*
	     * This unlock is a little strange, but we don't want to
	     * do any waiting while holding the ports lock, otherwise
	     * we might deadlock on a deletion in finish_shutdown_port().
	     * This is save as long as curr is not deleted, because curr
	     * will not go away, though curr->next may change, that
	     * shouldn't matter.
	     */
	    so->unlock(ports_lock);
	    err = gensio_acc_set_accept_callback_enable_s(curr->accepter,
							  false);
	    /* Errors only happen on out of memory. */
	    assert(err == 0);
	    so->lock(ports_lock);
	    curr->accepter_stopped = true;
	}
    }

    /* At this point we can't get any new accepts. */

    /*
     * See if the port already exists, and link it to this port.  We
     * put the old port in the new port's place for now.
     */
    for (new_prev = NULL, new = new_ports; new;
			new_prev = new, new = new->next) {
	so->lock(new->lock);
	for (prev = NULL, curr = ports; curr; prev = curr, curr = curr->next) {
	    so->lock(curr->lock);
	    if (strcmp(curr->name, new->name) == 0) {
		if (port_in_use(curr)) {
		    /* If we are disabling, kick off old users. */
		    if (!new->enabled && curr->enabled)
			shutdown_all_netcons(curr);
		} else {
		    if (strcmp(curr->accstr, new->accstr) == 0 &&
					curr->enabled) {
			/*
			 * Accepter didn't change and was on, just
			 * move it over.  This avoid issues with a
			 * connection coming in during a reconfig.
			 */
			struct gensio_accepter *tmp;
			tmp = new->accepter;
			new->accepter = curr->accepter;
			new->accepter_stopped = true;
			curr->accepter = tmp;
			curr->accepter_stopped = false;
			gensio_acc_set_user_data(curr->accepter, curr);
			gensio_acc_set_user_data(new->accepter, new);
		    }
		    /* Just let the old one get deleted. */
		    so->unlock(curr->lock);
		    break;
		}

		/* We are reconfiguring this port. */
		if (curr->new_config)
		    free_port(curr->new_config);
		curr->new_config = new;

		/*
		 * Put the current entry into the place of the new entry
		 * in the new_ports array.
		 */
		if (prev)
		    prev->next = curr->next;
		else
		    ports = curr->next;

		curr->next = new->next;
		if (new_prev)
		    new_prev->next = curr;
		else
		    new_ports = curr;

		if (new_ports_end == new)
		    new_ports_end = curr;

		gensio_acc_disable(curr->accepter);
		curr->deleted = true;
		so->unlock(new->lock);
		new = curr;
		break;
	    }
	    so->unlock(curr->lock);
	}
	so->unlock(new->lock);
    }

    /*
     * We nuke any old port without a new config.  Do this first so
     * new ports can use the given port numbers that might be in these.
     */
    for (curr = ports; curr; curr = next) {
	next = curr->next;
	so->lock(curr->lock);
	if (curr->accepter_stopped && curr->enabled)
	    gensio_acc_disable(curr->accepter);
	curr->deleted = true;
	curr->enabled = false;
	if (!port_in_use(curr)) {
	    so->unlock(curr->lock);
	    free_port(curr);
	} else {
	    /* Leave it in the new ports for shutdown when the user closes. */
	    if (new_ports_end)
		new_ports_end->next = curr;
	    curr->next = NULL;
	    new_ports_end = curr;
	    so->unlock(curr->lock);
	}
    }

    /* Now start up the new ports. */
    ports = new_ports;
    new_ports = NULL;
    new_ports_end = NULL;

    for (curr = ports; curr; curr = curr->next) {
	so->lock(curr->lock);
	if (!curr->deleted) {
	    curr->dev_to_net_state = PORT_CLOSED;
	    curr->net_to_dev_state = PORT_CLOSED;
	    if (curr->accepter_stopped) {
		curr->accepter_stopped = false;
		if (curr->enabled) {
		    gensio_acc_set_accept_callback_enable(curr->accepter, true);
		    curr->dev_to_net_state = PORT_UNCONNECTED;
		    curr->net_to_dev_state = PORT_UNCONNECTED;
		} else {
		    gensio_acc_disable(curr->accepter);
		}
	    } else {
		if (curr->enabled) {
		    err = startup_port(eout, curr);
		    if (err)
			curr->enabled = false;
		}
	    }
	}
	so->unlock(curr->lock);
    }
    so->unlock(ports_lock);
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

    controller_outputf(cntlr, "%-22s ", port->name);
    if (port->deleted)
	controller_outputf(cntlr, "%-6s ", "DEL");
    else
	controller_outputf(cntlr, "%-6s ", enabled_str[port->enabled]);
    controller_outputf(cntlr, "%7d ", port->timeout);

    netcon = first_live_net_con(port);
    if (!netcon)
	netcon = &(port->netcons[0]);

    if (port_in_use(port)) {
	gensio_raddr_to_str(netcon->net, NULL, buffer, sizeof(buffer));
	count = controller_outputf(cntlr, "%s", buffer);
    } else {
	count = controller_outputf(cntlr, "unconnected");
    }

    while (count < REMOTEADDR_COLUMN_WIDTH + 1) {
	controller_outs(cntlr, " ");
	count++;
    }

    controller_outputf(cntlr, "%-22s ", port->accstr);
    controller_outputf(cntlr, "%-22s ", port->devname);
    controller_outputf(cntlr, "%-14s ", state_str[port->net_to_dev_state]);
    controller_outputf(cntlr, "%-14s ", state_str[port->dev_to_net_state]);
    controller_outputf(cntlr, "%9lu ", (unsigned long) netcon->bytes_received);
    controller_outputf(cntlr, "%9lu ", (unsigned long) netcon->bytes_sent);
    controller_outputf(cntlr, "%9lu ", (unsigned long)port->dev_bytes_received);
    controller_outputf(cntlr, "%9lu ", (unsigned long) port->dev_bytes_sent);

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

    controller_outputf(cntlr, "Port %s\r\n", port->name);
    controller_outputf(cntlr, "  accepter: %s\r\n", port->accstr);
    controller_outputf(cntlr, "  enable state: %s\r\n",
		       enabled_str[port->enabled]);
    controller_outputf(cntlr, "  timeout: %d\r\n", port->timeout);

    for_each_connection(port, netcon) {
	if (netcon->net) {
	    gensio_raddr_to_str(netcon->net, NULL, buffer, sizeof(buffer));
	    controller_outputf(cntlr, "  connected to: %s\r\n", buffer);
	    controller_outputf(cntlr, "    bytes read from TCP: %lu\r\n",
			       (unsigned long) netcon->bytes_received);
	    controller_outputf(cntlr, "    bytes written to TCP: %lu\r\n",
			       (unsigned long) netcon->bytes_sent);
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

    controller_outputf(cntlr, "  bytes read from device: %u\r\n",
		       (unsigned long) port->dev_bytes_received);

    controller_outputf(cntlr, "  bytes written to device: %lu\r\n",
		       (unsigned long) port->dev_bytes_sent);

    if (port->new_config != NULL) {
	controller_outputf(cntlr, "  Port will be reconfigured when current"
			   " session closes.\r\n");
    } else if (port->deleted) {
	controller_outputf(cntlr, "  Port will be deleted when current"
			   " session closes.\r\n");
    }
}

/*
 * Find a port data structure given a port name.  Returns with port->lock
 * held, if it returns a non-NULL port.
 */
static port_info_t *
find_port_by_name(char *name, bool allow_deleted)
{
    port_info_t *port;

    so->lock(ports_lock);
    port = ports;
    while (port != NULL) {
	if (strcmp(name, port->name) == 0) {
	    so->lock(port->lock);
	    so->unlock(ports_lock);
	    if (port->deleted && !allow_deleted) {
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
	port = find_port_by_name(portspec, true);
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
	    "%-22s %-6s %7s %-*s %-22s %-22s %-14s %-14s %9s %9s %9s %9s %s\r\n",
	    "Port name",
	    "Type",
	    "Timeout",
	    REMOTEADDR_COLUMN_WIDTH,
	    "Remote address",
	    "Accepter",
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
	port = find_port_by_name(portspec, true);
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

    port = find_port_by_name(portspec, true);
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

    port = find_port_by_name(portspec, false);
    if (port == NULL) {
	controller_outputf(cntlr, "Invalid port number: %s\r\n", portspec);
	goto out;
    } else if (!port_in_use(port)) {
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
    bool new_enable;
    struct absout eout = { .out = cntrl_abserrout, .data = cntlr };
    int rv;

    port = find_port_by_name(portspec, false);
    if (port == NULL) {
	controller_outputf(cntlr, "Invalid port: %s\r\n", portspec);
	return;
    }

    if (strcmp(enable, "off") == 0) {
	new_enable = false;
    } else if (strcmp(enable, "on") == 0) {
	new_enable = true;
    } else if (strcmp(enable, "raw") == 0) {
	new_enable = true;
    } else {
	controller_outputf(cntlr, "Invalid enable: %s\r\n", enable);
	goto out_unlock;
    }


    if (port->enabled == new_enable) {
	controller_outputf(cntlr, "port was already in the given state");
	goto out_unlock;
    }

    port->enabled = new_enable;
    if (!new_enable) {
	rv = shutdown_port(port, "admin disable");
	if (rv)
	    controller_outputf(cntlr, "Error disabling port: %s",
			       gensio_err_to_str(rv));
    } else {
	rv = startup_port(&eout, port);
    }
    if (rv)
	port->enabled = !new_enable;

 out_unlock:
    so->unlock(port->lock);
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

    port = find_port_by_name(portspec, true);
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

    port = find_port_by_name(portspec, true);
    if (port == NULL) {
	char *err = "Invalid port number: ";
	controller_outs(cntlr, err);
	controller_outs(cntlr, portspec);
	controller_outs(cntlr, "\r\n");
	goto out;
    } else if (!port_in_use(port)) {
	char *err = "Port not connected: ";
	controller_outs(cntlr, err);
	controller_outs(cntlr, portspec);
	controller_outs(cntlr, "\r\n");
	goto out_unlock;
    }

    shutdown_port(port, "admin disconnect");
 out_unlock:
    so->unlock(port->lock);
 out:
    return;
}

void
shutdown_ports(void)
{
    port_info_t *port, *next, *prev;

    so->lock(ports_lock);
    prev = NULL;
    for (port = ports; port; port = next) {
	next = port->next;
	so->lock(port->lock);
	if (port->enabled) {
	    if (port->new_config) {
		free_port(port->new_config);
		port->new_config = NULL;
	    }
	    port->deleted = true;
	    port->enabled = false;
	    shutdown_port(port, "program shutdown");
	    so->unlock(port->lock);
	    prev = port;
	} else {
	    if (prev)
		prev->next = port->next;
	    else
		ports = port->next;
	    free_port(port);
	}
    }
    so->unlock(ports_lock);
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
    if (ports_lock)
	so->free_lock(ports_lock);
}

int
init_dataxfer(void)
{
    ports_lock = so->alloc_lock(so);
    if (!ports_lock)
	goto out_nomem;

    rotator_shutdown_wait = so->alloc_waiter(so);
    if (!rotator_shutdown_wait)
	goto out_nomem;

    return 0;

 out_nomem:
    shutdown_dataxfer();
    return ENOMEM;
}
