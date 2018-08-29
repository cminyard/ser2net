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

#include "utils/utils.h"
#include "genio/genio.h"
#include "utils/locking.h"
#include "ser2net.h"
#include "devio.h"
#include "dataxfer.h"
#include "readconfig.h"
#include "utils/telnet.h"
#include "utils/buffer.h"
#include "utils/waiter.h"
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

typedef struct trace_info_s
{
    int  hexdump;     /* output each block as a hexdump */
    int  timestamp;   /* preceed each line with a timestamp */
    char *filename;   /* open file.  NULL if not used */
    int  fd;          /* open file.  -1 if not used */
} trace_info_t;

typedef struct port_info port_info_t;
typedef struct net_info net_info_t;

struct net_info {
    port_info_t	   *port;		/* My port. */

    bool	   closing;		/* Is the connection in the process
					   of closing? */

    struct genio   *net;		/* When connected, the network
					   connection, NULL otherwise. */

    bool remote_fixed;			/* Tells if the remote address was
					   set in the configuration, and
					   cannot be changed. */
    bool connect_back;			/* True if we connect to the remote
					   address when data comes in. */
    struct addrinfo *remote_ai;

    unsigned int bytes_received;	/* Number of bytes read from the
					   network port. */
    unsigned int bytes_sent;		/* Number of bytes written to the
					   network port. */

    struct sbuf *banner;		/* Outgoing banner */

    unsigned int write_pos;		/* Our current position in the
					   output buffer where we need
					   to start writing next. */

    /* Data for the telnet processing */
    telnet_data_t tn_data;
    bool sending_tn_data; /* Are we sending tn data at the moment? */
    int in_urgent;       /* Looking for TN_DATA_MARK, and position. */

    int            timeout_left;	/* The amount of time left (in
					   seconds) before the timeout
					   goes off. */

    sel_runner_t *runshutdown;		/* Used to run things at the
					   base context.  This way we
					   don't have to worry that we
					   are running inside a
					   handler context that needs
					   to be waited for exit. */

    /*
     * If a user gets kicked, store the information for the new user
     * here since we have already accepted the connection or received
     * the packet, we have to store it someplace.
     */
    struct genio *new_net;
};

struct port_info
{
    DEFINE_LOCK(, lock)
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

    sel_timer_t *timer;			/* Used to timeout when the no
					   I/O has been seen for a
					   certain period of time. */

    sel_timer_t *send_timer;		/* Used to delay a bit when
					   waiting for characters to
					   batch up as many characters
					   as possible. */
    bool send_timer_running;

    unsigned int nocon_read_enable_time_left;
    /* Used if a connect back is requested an no connections could
       be made, to try again. */

    sel_runner_t *runshutdown;		/* Used to run things at the
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
    struct genio_acceptor *acceptor;	/* Used to receive new connections. */
    bool               remaddr_set;	/* Did a remote address get set? */
    struct port_remaddr *remaddrs;	/* Remote addresses allowed. */
    bool has_connect_back;		/* We have connect back addresses. */
    unsigned int num_waiting_connect_backs;

    int wait_acceptor_shutdown;
    bool acceptor_reinit_on_shutdown;

    unsigned int max_connections;	/* Maximum number of TCP connections
					   we can accept at a time for this
					   port. */
    net_info_t *netcons;

    unsigned int dev_bytes_received;    /* Number of bytes read from the
					   device. */
    unsigned int dev_bytes_sent;        /* Number of bytes written to the
					   device. */
    /* Information use when transferring information from the network port
       to the terminal device. */
    int            net_to_dev_state;		/* State of transferring
						   data from the network port
                                                   to the device. */

    struct sbuf    net_to_dev;			/* Buffer for network
						   to dev transfers. */
    struct controller_info *net_monitor; /* If non-null, send any input
					    received from the network port
					    to this controller port. */
    struct sbuf *devstr;		 /* Outgoing string */

    /* Information use when transferring information from the terminal
       device to the network port. */
    int            dev_to_net_state;		/* State of transferring
						   data from the device to
                                                   the network port. */

    struct sbuf    dev_to_net;			/* Buffer struct for
						   device to network
						   transfers. */
    unsigned char  *telnet_dev_to_net;		/* Used to read data
						   to do telnet
						   processing on
						   before going into
						   dev_to_net. */
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

    /* Is RFC 2217 mode enabled? */
    bool is_2217;

    /* Masks for RFC 2217 */
    unsigned char linestate_mask;
    unsigned char modemstate_mask;
    unsigned char last_modemstate;

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
    unsigned int closeon_pos;
    unsigned int closeon_len;

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

    struct devio io; /* For handling I/O operation to the device */
    void (*dev_write_handler)(port_info_t *);

    /*
     * devname as specified on the line, not the substituted version.  Only
     *non-null if devname was substituted.
     */
    char *orig_devname;

    /*
     * LED to flash for serial traffic
     */
    struct led_s *led_tx;
    struct led_s *led_rx;
};

static int setup_port(port_info_t *port, net_info_t *netcon, bool is_reconfig);

/*
 * This infrastructure allows a list of addresses to be kept.  This is
 * for checking remote addresses
 */
struct port_remaddr
{
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
    bool is_port_set, is_connect_back = false;
    bool is_dgram;
    int err;

    if (*str == '!') {
	str++;
	is_connect_back = true;
    }

    err = scan_network_port(str, &ai, &is_dgram, &is_port_set);
    if (err)
	return err;

    if (is_connect_back && !is_port_set)
	return EINVAL;

    /* We don't care about is_dgram, but we want to allow it. */

    r = malloc(sizeof(*r));
    if (!r) {
	err = ENOMEM;
	goto out;
    }
    memset(r, 0, sizeof(*r));

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
	freeaddrinfo(ai);

    return err;
}

static bool
ai_check(struct addrinfo *ai, const struct sockaddr *addr, socklen_t len,
	 bool is_port_set)
{
    while (ai) {
	if (sockaddr_equal(addr, len, ai->ai_addr, ai->ai_addrlen,
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

DEFINE_LOCK_INIT(static, ports_lock)
port_info_t *ports = NULL; /* Linked list of ports. */

static void shutdown_one_netcon(net_info_t *netcon, char *reason);
static void shutdown_port(port_info_t *port, char *reason);

/* The init sequence we use. */
static unsigned char telnet_init_seq[] = {
    TN_IAC, TN_WILL, TN_OPT_SUPPRESS_GO_AHEAD,
    TN_IAC, TN_WILL, TN_OPT_ECHO,
    TN_IAC, TN_DONT, TN_OPT_ECHO,
    TN_IAC, TN_DO,   TN_OPT_BINARY_TRANSMISSION,
    TN_IAC, TN_DO,   TN_OPT_COM_PORT,
};

/* Our telnet command table. */
static void com_port_handler(void *cb_data, unsigned char *option, int len);
static int com_port_will_do(void *cb_data, unsigned char cmd);

static struct telnet_cmd telnet_cmds_2217[] =
{
    /*                        I will,  I do,  sent will, sent do */
    { TN_OPT_SUPPRESS_GO_AHEAD,	   0,     1,          1,       0, },
    { TN_OPT_ECHO,		   0,     1,          1,       1, },
    { TN_OPT_BINARY_TRANSMISSION,  1,     1,          0,       1, },
    { TN_OPT_COM_PORT,		   1,     0,          0,       1,
      .option_handler = com_port_handler, .will_do_handler = com_port_will_do },
    { TELNET_CMD_END_OPTION }
};

static struct telnet_cmd telnet_cmds[] =
{
    /*                        I will,  I do,  sent will, sent do */
    { TN_OPT_SUPPRESS_GO_AHEAD,	   0,     1,          1,       0, },
    { TN_OPT_ECHO,		   0,     1,          1,       1, },
    { TN_OPT_BINARY_TRANSMISSION,  1,     1,          0,       1, },
    { TN_OPT_COM_PORT,		   0,     0,          0,       0,
      .option_handler = com_port_handler, .will_do_handler = com_port_will_do },
    { TELNET_CMD_END_OPTION }
};


/*
 * Generic output function for using a controller output for
 * abstract I/O.
 */
static int
cntrl_absout(struct absout *o, const char *str, ...)
{
    va_list ap;
    int rv;

    va_start(ap, str);
    rv = controller_voutputf(o->data, str, ap);
    va_end(ap);
    return rv;
}

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
    port->dev_to_net.maxsize = find_default_int("dev-to-tcp-bufsize");
    port->net_to_dev.maxsize = find_default_int("tcp-to-dev-bufsize");
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
	    unsigned int buf_len, const char *prefix)
{
    int rv = 0, w, col = 0, pos, file = t->fd;
    unsigned int q;
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
	 unsigned int buf_len, const char *prefix)
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
    int len = 0;

    len += timestamp(&tr, buf, sizeof(buf));
    len += snprintf(buf + len, sizeof(buf) - len, "OPEN (");
    genio_raddr_to_str(netcon->net, &len, buf, sizeof(buf));
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
    len += snprintf(buf + len, sizeof(buf), "CLOSE %s (%s)\n", type, reason);

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

    port->io.f->read_handler_enable(&port->io, 0);
    for_each_connection(port, netcon) {
	if (!netcon->net)
	    continue;
	netcon->write_pos = 0;
	genio_set_write_callback_enable(netcon->net, true);
    }
    port->dev_to_net_state = PORT_WAITING_OUTPUT_CLEAR;
}

void
send_timeout(struct selector_s  *sel,
	     sel_timer_t *timer,
	     void        *data)
{
    port_info_t *port = (port_info_t *) data;

    LOCK(port->lock);

    if (port->dev_to_net_state == PORT_CLOSING) {
	UNLOCK(port->lock);
	return;
    }

    port->send_timer_running = false;
    if (port->dev_to_net.cursize > 0)
	start_net_send(port);
    UNLOCK(port->lock);
}

static void
disable_all_net_read(port_info_t *port)
{
    net_info_t *netcon;

    for_each_connection(port, netcon) {
	if (netcon->net)
	    genio_set_read_callback_enable(netcon->net, false);
    }
}

static void
enable_all_net_read(port_info_t *port)
{
    net_info_t *netcon;

    for_each_connection(port, netcon) {
	if (netcon->net)
	    genio_set_read_callback_enable(netcon->net, true);
    }
}

static void
connect_back_done(struct genio *net, int err, void *cb_data)
{
    net_info_t *netcon = cb_data;
    port_info_t *port = netcon->port;

    LOCK(port->lock);
    if (err) {
	netcon->net = NULL;
	genio_free(net);
    } else {
	setup_port(port, netcon, false);
    }
    assert(port->num_waiting_connect_backs > 0);
    port->num_waiting_connect_backs--;
    if (port->num_waiting_connect_backs == 0) {
	if (num_connected_net(port) == 0)
	    /* No connections could be made. */
	    port->nocon_read_enable_time_left = 10;
	else
	    port->io.f->read_handler_enable(&port->io, 1);
    }
    UNLOCK(port->lock);
}

static int
port_check_connect_backs(port_info_t *port)
{
    net_info_t *netcon;
    bool tried = false;

    if (!port->has_connect_back)
	return false;

    for_each_connection(port, netcon) {
	if (netcon->connect_back && !netcon->net) {
	    int err;

	    tried = true;
	    err = genio_acc_connect(port->acceptor, netcon->remote_ai,
				    connect_back_done, netcon, &netcon->net);
	    if (err) {
		syslog(LOG_ERR, "Unable to start connect on connect "
		       "back port %s: %s\n", port->portname, strerror(err));
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
	port->io.f->read_handler_enable(&port->io, 0);
    } else if (port->num_waiting_connect_backs) {
	port->io.f->read_handler_enable(&port->io, 0);
    }

    return port->num_waiting_connect_backs;
}

/* Data is ready to read on the serial port. */
static void
handle_dev_fd_read(struct devio *io)
{
    port_info_t *port = (port_info_t *) io->user_data;
    int count;
    int curend;
    bool send_now = false;
    unsigned int readcount, oreadcount;
    const unsigned char *readbuf;
    int nr_handlers;

    LOCK(port->lock);
    if (port->dev_to_net_state != PORT_WAITING_INPUT)
	goto out_unlock;
    nr_handlers = port_check_connect_backs(port);
    if (nr_handlers > 0)
	goto out_unlock;

    curend = port->dev_to_net.cursize;
    oreadcount = port->dev_to_net.maxsize - curend;
    readcount = oreadcount;
    if (port->enabled == PORT_TELNET) {
	readbuf = port->telnet_dev_to_net;
	readcount /= 2; /* Leave room for IACs. */

	if (readcount == 0) {
	    /* We don't want a zero read, so just ignore this, as we have
	       data to send. */
	    send_now = true;
	    count = 0;
	    goto do_send;
	}
	count = port->io.f->read(&port->io, port->telnet_dev_to_net,
				 readcount);
    } else {
	count = port->io.f->read(&port->io, port->dev_to_net.buf + curend,
				 readcount);
	readbuf = port->dev_to_net.buf + curend;
    }

    if (count <= 0) {
	if (curend != 0) {
	    /* We still have data to send. */
	    send_now = true;
	    count = 0;
	    goto do_send;
	}

	if (count < 0) {
	    if (errno == EAGAIN || errno == EWOULDBLOCK)
		/* Nothing to read, just return. */
		goto out_unlock;

	    /* Got an error on the read, shut down the port. */
	    syslog(LOG_ERR, "dev read error for device %s: %m", port->portname);
	    shutdown_port(port, "dev read error");
	} else if (count == 0) {
	    /* The port got closed somehow, shut it down. */
	    shutdown_port(port, "closed port");
	}
	goto out_unlock;
    }

    if (port->dev_monitor != NULL && count > 0)
	controller_write(port->dev_monitor, (char *) readbuf, count);

 do_send:
    if (port->closeon) {
	int i;

	for (i = 0; i < count; i++) {
	    if (readbuf[i] == port->closeon[port->closeon_pos]) {
		port->closeon_pos++;
		if (port->closeon_pos >= port->closeon_len) {
		    port->close_on_output_done = true;
		    /* Ignore everything after the closeon string */
		    count = i - curend + 1;
		    break;
		}
	    } else {
		port->closeon_pos = 0;
	    }
	}
    }

    if (port->tr)
	/* Do read tracing, ignore errors. */
	do_trace(port, port->tr, readbuf, count, SERIAL);
    if (port->tb)
	/* Do both tracing, ignore errors. */
	do_trace(port, port->tb, readbuf, count, SERIAL);

    if (port->led_rx)
	led_flash(port->led_rx);

    if (nr_handlers < 0) /* Nobody to handle the data. */
	goto out_unlock;

    port->dev_bytes_received += count;

    if (port->enabled == PORT_TELNET) {
	unsigned int curcount = count;

	count = process_telnet_xmit(port->dev_to_net.buf + curend, oreadcount,
				    &readbuf, &curcount);
	assert(curcount == 0);
    }

    port->dev_to_net.cursize += count;

    if (send_now || port->dev_to_net.cursize == port->dev_to_net.maxsize ||
		port->chardelay == 0) {
    send_it:
	start_net_send(port);
    } else {
	struct timeval then;
	int delay;

	sel_get_monotonic_time(&then);
	if (port->send_timer_running) {
	    sel_stop_timer(port->send_timer);
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
	sel_start_timer(port->send_timer, &then);
	port->send_timer_running = true;
    }
 out_unlock:
    UNLOCK(port->lock);
}

static int
io_do_write(void *cb_data, void  *buf, size_t buflen, size_t *written)
{
    struct devio *io = cb_data;
    ssize_t write_count;
    int err = 0;

    write_count = io->f->write(io, buf, buflen);
    if (write_count == -1)
	err = errno;
    else
	*written = write_count;

    return err;
}

/* The serial port has room to write some data.  This is only activated
   if a write fails to complete, it is deactivated as soon as writing
   is available again. */
static void
dev_fd_write(port_info_t *port, struct sbuf *buf)
{
    int reterr, buferr;

    reterr = buffer_write(io_do_write, &port->io, buf, &buferr);
    if (reterr == -1) {
	syslog(LOG_ERR, "The dev write for port %s had error: %s",
	       port->portname, strerror(buferr));
	shutdown_port(port, "dev write error");
	return;
    }

    if (buffer_cursize(buf) == 0) {
	/* We are done writing, turn the reader back on. */
	enable_all_net_read(port);
	port->io.f->write_handler_enable(&port->io, 0);
	port->net_to_dev_state = PORT_WAITING_INPUT;
    }
}

static void
handle_dev_fd_normal_write(port_info_t *port)
{
    dev_fd_write(port, &port->net_to_dev);
}

static void
handle_dev_fd_write(struct devio *io)
{
    port_info_t *port = (port_info_t *) io->user_data;

    LOCK(port->lock);
    port->dev_write_handler(port);
    UNLOCK(port->lock);
}

/* Handle an exception from the serial port. */
static void
handle_dev_fd_except(struct devio *io)
{
    port_info_t *port = (port_info_t *) io->user_data;

    LOCK(port->lock);
    syslog(LOG_ERR, "Select exception on device for port %s",
	   port->portname);
    shutdown_port(port, "fd exception");
    UNLOCK(port->lock);
}

/* Output the devstr buffer */
static void
handle_dev_fd_devstr_write(port_info_t *port)
{
    dev_fd_write(port, port->devstr);
    if (buffer_cursize(port->devstr) == 0) {
	port->dev_write_handler = handle_dev_fd_normal_write;
	free(port->devstr->buf);
	free(port->devstr);
	port->devstr = NULL;

	/* Send out any data we got on the TCP port. */
	handle_dev_fd_normal_write(port);
    }
}

/* Data is ready to read on the network port. */
static unsigned int
handle_net_fd_read(struct genio *net, int readerr,
		   unsigned char *buf, unsigned int buflen, unsigned int flags)
{
    net_info_t *netcon = genio_get_user_data(net);
    port_info_t *port = netcon->port;
    unsigned int bufpos = 0;
    unsigned int rv = 0;
    char *reason;
    int count;

    LOCK(port->lock);
    if (port->net_to_dev_state == PORT_WAITING_OUTPUT_CLEAR)
	/* Catch a race here. */
	goto out_unlock;

    if (readerr) {
	if (readerr == ECONNRESET || readerr == EPIPE) {
	    reason = "network read close";
	} else {
	    /* Got an error on the read, shut down the port. */
	    syslog(LOG_ERR, "read error for port %s: %s", port->portname,
		   strerror(readerr));
	    reason = "network read error";
	}
	goto out_shutdown;
    }

    netcon->bytes_received += buflen;

    if (port->net_monitor != NULL)
	controller_write(port->net_monitor, (char *) buf, buflen);

    if (port->tw)
	/* Do write tracing, ignore errors. */
	do_trace(port, port->tw, buf, buflen, NET);
    if (port->tb)
	/* Do both tracing, ignore errors. */
	do_trace(port, port->tb, buf, buflen, NET);

    if (netcon->in_urgent) {
	/* We are in urgent data, just read until we get a mark. */
	for (; bufpos < buflen; bufpos++) {
	    if (netcon->in_urgent == 2) {
		if (buf[bufpos] == TN_DATA_MARK) {
		    /* Found it. */
		    if (port->telnet_brk_on_sync)
			port->io.f->send_break(&port->io);
		    netcon->in_urgent = 0;
		    break;
		}
		netcon->in_urgent = 1;
	    } else if (buf[bufpos] == TN_IAC) {
		netcon->in_urgent = 2;
	    }
	}
    }

    if (buflen <= bufpos)
	goto out_data_handled;

    if (port->enabled == PORT_TELNET) {
	unsigned int bytesleft = buflen - bufpos;
	unsigned char *cbuf = buf + bufpos;

	port->net_to_dev.cursize = process_telnet_data(port->net_to_dev.buf,
						       port->net_to_dev.maxsize,
						       &cbuf, &bytesleft,
						       &netcon->tn_data);

	if (netcon->tn_data.error) {
	    shutdown_one_netcon(netcon, "telnet output error");
	    goto out_unlock;
	}
	if (port->net_to_dev.cursize == 0)
	    /* We are out of characters; they were all processed.  We
	       don't want to continue with 0, because that will mess
	       up the other processing and it's not necessary. */
	    goto out_data_handled;

	assert(bytesleft == 0);
    } else {
	assert(buflen - bufpos <= port->net_to_dev.maxsize);
	memcpy(port->net_to_dev.buf, buf + bufpos, buflen - bufpos);
	port->net_to_dev.cursize = buflen - bufpos;
    }

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

 retry_write:
    count = port->io.f->write(&port->io, buffer_curptr(&port->net_to_dev),
			      port->net_to_dev.cursize);
    if (count == -1) {
	if (errno == EINTR) {
	    /* EINTR means we were interrupted, just retry. */
	    goto retry_write;
	}

	if (errno == EAGAIN || errno == EWOULDBLOCK) {
	    /* This was due to O_NONBLOCK, we need to shut off the reader
	       and start the writer monitor.  Just ignore it, code later
	       will enable the write handler. */
	} else {
	    /* Some other bad error. */
	    syslog(LOG_ERR, "The dev write for port %s had error: %m",
		   port->portname);
	    shutdown_port(port, "dev write error");
	    goto out_unlock;
	}
    } else {
	if (port->led_tx)
	    led_flash(port->led_tx);
	port->dev_bytes_sent += count;
	port->net_to_dev.cursize -= count;
	port->net_to_dev.pos += count;
    }

    if (port->net_to_dev.cursize != 0) {
	/* We didn't write all the data, shut off the reader and
	   start the write monitor. */
    stop_read_start_write:
	disable_all_net_read(port);
	port->io.f->write_handler_enable(&port->io, 1);
	port->net_to_dev_state = PORT_WAITING_OUTPUT_CLEAR;
    }

    reset_timer(netcon);

 out_data_handled:
    rv = buflen;

 out_unlock:
    UNLOCK(port->lock);
    return rv;

 out_shutdown:
    shutdown_one_netcon(netcon, reason);
    goto out_unlock;
}

void io_enable_read_handler(port_info_t *port)
{
    port->io.f->read_handler_enable(&port->io,
				    port->enabled != PORT_RAWLP);
}

/*
 * Returns -1 on something causing the netcon to shut down, 0 if the
 * write was incomplete, and 1 if the write was completed.
 */
static int
send_telnet_data(port_info_t *port, net_info_t *netcon)
{
    telnet_data_t *td = &netcon->tn_data;
    int reterr, buferr;

    if (!netcon->sending_tn_data)
	return 1;

    reterr = buffer_write(genio_buffer_do_write, netcon->net,
			  &td->out_telnet_cmd, &buferr);
    /* Returns 0 on EAGAIN */
    if (reterr == -1) {
	if (buferr == EPIPE) {
	    shutdown_one_netcon(netcon, "EPIPE");
	    return -1;
	} else {
	    /* Some other bad error. */
	    syslog(LOG_ERR, "The network write for port %s had error: %s",
		   port->portname, strerror(buferr));
	    shutdown_one_netcon(netcon, "network write error");
	    return -1;
	}
    }

    if (buffer_cursize(&td->out_telnet_cmd) > 0)
	/* If we have more telnet command data to send, don't
	   send any real data. */
	return 0;

    netcon->sending_tn_data = false;
    return 1;
}

/*
 * Write some network data from a buffer.  Returns -1 on something
 * causing the netcon to shut down, 0 if the write was incomplete, and
 * 1 if the write was completed.
 */
static int
net_fd_write(port_info_t *port, net_info_t *netcon,
	     struct sbuf *buf, unsigned int *pos)
{
    int reterr, to_send;
    unsigned int count = 0;

    to_send = buf->cursize - *pos;
    if (to_send <= 0)
	/* Don't send empty packets, that can confuse UDP clients. */
	return 1;

    /* Can't use buffer send operation here, multiple writers can send
       from the buffers. */
    reterr = genio_write(netcon->net, &count, buf->buf + *pos, to_send);
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

    /* We are done writing on this port, turn the reader back on. */
    io_enable_read_handler(port);
    port->dev_to_net_state = PORT_WAITING_INPUT;

    return true;
}

/* The network fd has room to write some data.  This is only activated
   if a write fails to complete, it is deactivated as soon as writing
   is available again. */
static void
handle_net_fd_write(struct genio *net)
{
    net_info_t *netcon = genio_get_user_data(net);
    port_info_t *port = netcon->port;
    int rv;

    LOCK(port->lock);
 send_tn_data:
    rv = send_telnet_data(port, netcon);
    if (rv <= 0)
	goto out_unlock;

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

	/* Start telnet data write when the data write is done. */
	if (buffer_cursize(&netcon->tn_data.out_telnet_cmd) > 0) {
	    netcon->sending_tn_data = true;
	    goto send_tn_data;
	}

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
	genio_set_write_callback_enable(netcon->net, false);

    if (rv >= 0)
	reset_timer(netcon);
    UNLOCK(port->lock);
}

/* Handle an exception from the network port. */
static void
handle_net_fd_urgent(struct genio *net)
{
    net_info_t *netcon = genio_get_user_data(net);
    port_info_t *port = netcon->port;
    int val;
    int cmd_pos;

    /* We should have urgent data, a DATA MARK in the stream.  The calling
       code should have already read the data mark. */

    LOCK(port->lock);

    if (port->enabled != PORT_TELNET)
	goto out;

    /* Flush the data in the local and device queue. */
    port->net_to_dev.cursize = 0;
    val = 0;
    port->io.f->flush(&port->io, &val);

    /* Store it if we last got an IAC, and abort any current
       telnet processing. */
    cmd_pos = netcon->tn_data.telnet_cmd_pos;
    netcon->tn_data.telnet_cmd_pos = 0;
    netcon->tn_data.suboption_iac = 0;

    if (cmd_pos != 1)
	netcon->in_urgent = 1;
    else
	netcon->in_urgent = 2;

 out:
    UNLOCK(port->lock);
}

static void handle_net_fd_closed(struct genio *net, void *cb_data);

static void
telnet_cmd_handler(void *cb_data, unsigned char cmd)
{
    net_info_t *netcon = cb_data;
    port_info_t *port = netcon->port;

    if ((cmd == TN_BREAK) || (port->telnet_brk_on_sync && cmd == TN_DATA_MARK))
	port->io.f->send_break(&port->io);
}

/* Called when the telnet code has output ready. */
static void
telnet_output_ready(void *cb_data)
{
    net_info_t *netcon = cb_data;
    port_info_t *port = netcon->port;

    /* If we are currently sending some data, wait until it is done.
       It might have IACs in it, and we don't want to split those. */
    if (buffer_cursize(&port->dev_to_net) != 0)
	return;

    netcon->sending_tn_data = true;
    genio_set_write_callback_enable(netcon->net, true);
}

/* Checks to see if some other port has the same device in use.  Must
   be called with ports_lock held. */
static int
is_device_already_inuse(port_info_t *check_port)
{
    port_info_t *port = ports;

    while (port != NULL) {
	if (port != check_port) {
	    if ((strcmp(port->io.devname, check_port->io.devname) == 0)
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
		    s2 = port->io.devname;

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
		    char str[15];
		    port->io.f->serparm_to_str(&port->io, str, sizeof(str));
		    for (t = str; *t; t++)
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
		if (genio_raddr_to_str(netcon->net, NULL, ip, sizeof(ip)))
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
process_str_to_str(port_info_t *port, net_info_t *netcon,
		   const char *str, struct timeval *tv,
		   unsigned int *lenrv, int isfilename)
{
    unsigned int len = 0;
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

static struct sbuf *
process_str_to_buf(port_info_t *port, net_info_t *netcon, const char *str)
{
    const char *bstr;
    struct sbuf *buf;
    unsigned int len;
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
    buffer_init(buf, (unsigned char *) bstr, len);
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
    /* delay is (((1 / bps) * bpc) * scale) seconds */
    if (!port->enable_chardelay) {
	port->chardelay = 0;
	return;
    }

    /* We are working in microseconds here. */
    port->chardelay = (port->bpc * 100000 * port->chardelay_scale) / port->bps;
    if (port->chardelay < port->chardelay_min)
	port->chardelay = port->chardelay_min;
}

static const struct genio_callbacks port_callbacks = {
    .read_callback = handle_net_fd_read,
    .write_callback = handle_net_fd_write,
    .urgent_callback = handle_net_fd_urgent
};

static int
port_dev_enable(port_info_t *port, net_info_t *netcon,
		bool is_reconfig, const char **errstr)
{
    struct timeval then;

    if (port->io.f->setup(&port->io, port->portname, errstr,
			  &port->bps, &port->bpc) == -1)
	    return -1;

    recalc_port_chardelay(port);
    port->is_2217 = false;

    if (!is_reconfig) {
	if (port->devstr) {
	    free(port->devstr->buf);
	    free(port->devstr);
	}
	port->devstr = process_str_to_buf(port, netcon, port->openstr);
    }
    if (port->devstr)
	port->dev_write_handler = handle_dev_fd_devstr_write;
    else
	port->dev_write_handler = handle_dev_fd_normal_write;

    port->io.read_handler = (port->enabled == PORT_RAWLP
			     ? NULL
			     : handle_dev_fd_read);
    port->io.write_handler = handle_dev_fd_write;
    port->io.except_handler = handle_dev_fd_except;
    port->io.f->except_handler_enable(&port->io, 1);
    if (port->devstr)
	port->io.f->write_handler_enable(&port->io, 1);
    io_enable_read_handler(port);
    port->dev_to_net_state = PORT_WAITING_INPUT;

    setup_trace(port);

    sel_get_monotonic_time(&then);
    then.tv_sec += 1;
    sel_start_timer(port->timer, &then);

    return 0;
}

/* Called to set up a new connection's file descriptor. */
static int
setup_port(port_info_t *port, net_info_t *netcon, bool is_reconfig)
{
    int err;

    if (!is_reconfig) {
	if (netcon->banner) {
	    free(netcon->banner->buf);
	    free(netcon->banner);
	}
	netcon->banner = process_str_to_buf(port, netcon, port->bannerstr);
    }

    if (port->enabled == PORT_TELNET) {
	err = telnet_init(&netcon->tn_data, netcon, telnet_output_ready,
			  telnet_cmd_handler,
			  port->allow_2217 ? telnet_cmds_2217 : telnet_cmds,
			  telnet_init_seq,
			  port->allow_2217 ? sizeof(telnet_init_seq)
			      : sizeof(telnet_init_seq) - 3);
	if (err) {
	    char *errstr = "Out of memory\r\n";

	    genio_write(netcon->net, NULL, errstr, strlen(errstr));
	    genio_free(netcon->net);
	    netcon->net = NULL;
	    return -1;
	}
    }

    if (num_connected_net(port) == 1 && !port->has_connect_back) {
	/* We are first, set things up on the device. */
	const char *errstr = NULL;

	err = port_dev_enable(port, netcon, is_reconfig, &errstr);
	if (err) {
	    if (errstr)
		genio_write(netcon->net, NULL, errstr, strlen(errstr));
	    genio_free(netcon->net);
	    netcon->net = NULL;
	    return -1;
	}
    }

    genio_set_callbacks(netcon->net, &port_callbacks, netcon);

    genio_set_read_callback_enable(netcon->net, true);
    port->net_to_dev_state = PORT_WAITING_INPUT;

    if (port->enabled == PORT_TELNET) {
	genio_set_write_callback_enable(netcon->net, true);
    } else {
	buffer_init(&netcon->tn_data.out_telnet_cmd,
		    netcon->tn_data.out_telnet_cmdbuf, 0);
	if (netcon->banner)
	    genio_set_write_callback_enable(netcon->net, true);
    }

    header_trace(port, netcon);

    reset_timer(netcon);

    return 0;
}

/* Returns with the port locked, if non-NULL. */
static port_info_t *
find_rotator_port(char *portname, struct genio *net, unsigned int *netconnum)
{
    port_info_t *port = ports;

    while (port) {
	if (strcmp(port->portname, portname) == 0) {
	    unsigned int i;
	    struct sockaddr_storage addr;
	    socklen_t socklen;

	    LOCK(port->lock);
	    if (port->enabled == PORT_DISABLED)
		goto next;
	    if (port->dev_to_net_state == PORT_CLOSING)
		goto next;
	    socklen = genio_get_raddr(net, (struct sockaddr *) &addr,
				      sizeof(addr));
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
	    UNLOCK(port->lock);
	}
	port = port->next;
    }

    return NULL;
}

static void
handle_new_net(port_info_t *port, struct genio *net, net_info_t *netcon)
{
    netcon->net = net;

    /* XXX log netcon->remote */
    setup_port(port, netcon, false);
}

typedef struct rotator
{
    /* Rotators use the ports_lock for mutex. */
    int curr_port;
    char **portv;
    int portc;

    char *portname;

    struct genio_acceptor *acceptor;

    struct rotator *next;
} rotator_t;

static rotator_t *rotators = NULL;

/* A connection request has come in on a port. */
static void
handle_rot_accept(struct genio_acceptor *acceptor, struct genio *net)
{
    rotator_t *rot = genio_acc_get_user_data(acceptor);
    int i;
    const char *err;

    LOCK(ports_lock);
    i = rot->curr_port;
    do {
	unsigned int netconnum;
	port_info_t *port = find_rotator_port(rot->portv[i], net, &netconnum);

	if (++i >= rot->portc)
	    i = 0;
	if (port) {
	    rot->curr_port = i;
	    UNLOCK(ports_lock);
	    handle_new_net(port, net, &port->netcons[netconnum]);
	    UNLOCK(port->lock);
	    return;
	}
    } while (i != rot->curr_port);
    UNLOCK(ports_lock);

    err = "No free port found\r\n";
    genio_write(net, NULL, err, strlen(err));
    genio_free(net);
}

static waiter_t *rotator_shutdown_wait;

static void
handle_rot_shutdown_done(struct genio_acceptor *acceptor, void *cb_data)
{
    wake_waiter(rotator_shutdown_wait);
}

static void
free_rotator(rotator_t *rot)
{
    if (rot->acceptor) {
	genio_acc_shutdown(rot->acceptor, handle_rot_shutdown_done, NULL);
	wait_for_waiter(rotator_shutdown_wait, 1);
	genio_acc_free(rot->acceptor);
    }
    if (rot->portname)
	free(rot->portname);
    if (rot->portv)
	str_to_argv_free(rot->portc, rot->portv);
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

static const struct genio_acceptor_callbacks rotator_cbs = {
    .new_connection = handle_rot_accept,
};

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

    rv = str_to_argv(ports, &rot->portc, &rot->portv, NULL);
    if (rv)
	goto out;

    rv = str_to_genio_acceptor(rot->portname, ser2net_o, 64,
			       &rotator_cbs, rot, &rot->acceptor);
    if (rv) {
	syslog(LOG_ERR, "port was invalid on line %d", lineno);
	goto out;
    }

    rot->next = rotators;
    rotators = rot;

    rv = genio_acc_startup(rot->acceptor);
    if (rv) {
	syslog(LOG_ERR, "Failed to start rotator on line %d: %s", lineno,
	       strerror(rv));
	goto out;
    }

 out:
    if (rv)
	free_rotator(rot);
    return rv;
}

static void
kick_old_user(port_info_t *port, net_info_t *netcon, struct genio *new_net)
{
    char *err = "kicked off, new user is coming\r\n";

    /* If another user is waiting for a kick, kick that user. */
    if (netcon->new_net) {
	genio_write(netcon->new_net, NULL, err, strlen(err));
	genio_free(netcon->new_net);
    }

    /* Wait it to be unconnected and clean, restart the process. */
    netcon->new_net = new_net;

    shutdown_one_netcon(netcon, err);
}

static void
check_port_new_net(port_info_t *port, net_info_t *netcon)
{
    struct genio *net;

    if (!netcon->new_net)
	return;

    if (!netcon->net) {
	/* Something snuck in before, kick this one out. */
	char *err = "kicked off, new user is coming\r\n";

	genio_write(netcon->new_net, NULL, err, strlen(err));
	genio_free(netcon->new_net);
	netcon->new_net = NULL;
	return;
    }

    net = netcon->new_net;
    netcon->new_net = NULL;
    handle_new_net(port, net, netcon);
}

/* A connection request has come in on a port. */
static void
handle_port_accept(struct genio_acceptor *acceptor, struct genio *net)
{
    port_info_t *port = genio_acc_get_user_data(acceptor);
    const char *err = NULL;
    unsigned int i, j;
    struct sockaddr_storage addr;
    socklen_t socklen;

    LOCK(ports_lock); /* For is_device_already_inuse() */
    LOCK(port->lock);

    if (port->enabled == PORT_DISABLED)
	goto out;

    /* We raced, the shutdown should disable the accept read
       until the shutdown is complete. */
    if (port->dev_to_net_state == PORT_CLOSING)
	goto out;

    socklen = genio_get_raddr(net, (struct sockaddr *) &addr,
			      sizeof(addr));
    if (!remaddr_check(port->remaddrs,
		       (struct sockaddr *) &addr, socklen)) {
	err = "Accessed denied due to your net address\r\n";
	goto out_err;
    }

    for (j = port->max_connections, i = 0; i < port->max_connections; i++) {
	if (!port->netcons[i].net) {
	    if (port->netcons[i].remote_fixed) {
		if (ai_check(port->netcons[i].remote_ai,
			     (struct sockaddr *) &addr, socklen, true)) {
		    break;
		}
	    } else {
		break;
	    }
	}
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
	UNLOCK(port->lock);
	UNLOCK(ports_lock);
	genio_write(net, NULL, err, strlen(err));
	genio_free(net);
	return;
    }

    /* We have to hold the ports_lock until after this call so the
       device won't get used (from is_device_already_inuse()). */
    handle_new_net(port, net, &(port->netcons[i]));
 out:
    UNLOCK(port->lock);
    UNLOCK(ports_lock);
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
	netcon->remote_ai = r->ai;
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
    int err = genio_acc_startup(port->acceptor);
    struct port_remaddr *r;

    if (err && eout) {
	eout->out(eout, "Unable to startup network port %s: %s",
		  port->portname, strerror(err));
	return err;
    }

    for (r = port->remaddrs; r; r = r->next)
	process_remaddr(eout, port, r, is_reconfig);

    if (port->has_connect_back) {
	const char *errstr;

	err = port_dev_enable(port, NULL, false, &errstr);
	if (err && eout)
	    eout->out(eout, "Unable to enable port device %s: %s",
		      port->portname, strerror(err));
	if (err)
	    genio_acc_shutdown(port->acceptor, NULL, NULL);
    }

    return err;
}

static void
port_reinit_now(port_info_t *port)
{
    if (port->enabled != PORT_DISABLED) {
	net_info_t *netcon;

	port->dev_to_net_state = PORT_UNCONNECTED;
	genio_acc_set_accept_callback_enable(port->acceptor, true);
	for_each_connection(port, netcon)
	    check_port_new_net(port, netcon);
    }
}

static waiter_t *acceptor_shutdown_wait;

static void
handle_port_shutdown_done(struct genio_acceptor *acceptor, void *cb_data)
{
    port_info_t *port = genio_acc_get_user_data(acceptor);

    LOCK(port->lock);
    while (port->wait_acceptor_shutdown--)
	wake_waiter(acceptor_shutdown_wait);

    if (port->acceptor_reinit_on_shutdown) {
	port->acceptor_reinit_on_shutdown = false;
	port_reinit_now(port);
    }
    UNLOCK(port->lock);
}

static bool
change_port_state(struct absout *eout, port_info_t *port, int state,
		  bool is_reconfig)
{
    if (port->enabled == state)
	return false;

    if (state == PORT_DISABLED) {
	port->enabled = PORT_DISABLED; /* Stop accepts */
	if (port->wait_acceptor_shutdown || port->acceptor_reinit_on_shutdown)
	    /* Shutdown is already running. */
	    return true;
	return genio_acc_shutdown(port->acceptor,
				  handle_port_shutdown_done, NULL) == 0;
    } else {
	if (port->enabled == PORT_DISABLED) {
	    int rv = startup_port(eout, port, is_reconfig);
	    if (!rv) {
		if (state == PORT_RAWLP)
		    port->io.read_disabled = 1;
		else
		    port->io.read_disabled = 0;
		port->enabled = state;
	    }
	}
    }

    return false;
}

static void
wait_for_port_shutdown(port_info_t *port, unsigned int *count)
{
    port->wait_acceptor_shutdown++;
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
		genio_write(netcon->new_net, NULL, err, strlen(err));
		genio_free(netcon->new_net);
	    }
	    if (netcon->runshutdown)
		sel_free_runner(netcon->runshutdown);
	}
    }

    FREE_LOCK(port->lock);
    while (port->remaddrs) {
	r = port->remaddrs;
	port->remaddrs = r->next;
	freeaddrinfo(r->ai);
	free(r);
    }
    if (port->acceptor)
	genio_acc_free(port->acceptor);
    if (port->dev_to_net.buf)
	free(port->dev_to_net.buf);
    if (port->telnet_dev_to_net)
	free(port->telnet_dev_to_net);
    if (port->net_to_dev.buf)
	free(port->net_to_dev.buf);
    if (port->timer)
	sel_free_timer(port->timer);
    if (port->send_timer)
	sel_free_timer(port->send_timer);
    if (port->runshutdown)
	sel_free_runner(port->runshutdown);
    if (port->io.f)
	port->io.f->free(&port->io);
    if (port->trace_read.filename)
	free(port->trace_read.filename);
    if (port->trace_write.filename)
	free(port->trace_write.filename);
    if (port->trace_both.filename)
	free(port->trace_both.filename);
    if (port->io.devname)
	free(port->io.devname);
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
    struct genio_acceptor *tmp_acceptor;
    int i;

    new_port->enabled = curr->enabled;

    /* Keep the same acceptor structure. */
    tmp_acceptor = new_port->acceptor;
    new_port->acceptor = curr->acceptor;
    curr->acceptor = tmp_acceptor;
    genio_acc_set_user_data(curr->acceptor, curr);
    genio_acc_set_user_data(new_port->acceptor, new_port);

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
    UNLOCK(curr->lock);
    free_port(curr);

    return change_port_state(eout, new_port, new_state, true);
}

static void
finish_shutdown_port(port_info_t *port)
{
    bool reinit_now = true;

    /* At this point nothing can happen on the port, so no need for a lock */

    port->net_to_dev_state = PORT_UNCONNECTED;
    buffer_reset(&port->net_to_dev);
    if (port->devstr) {
	free(port->devstr->buf);
	free(port->devstr);
	port->devstr = NULL;
    }
    buffer_reset(&port->dev_to_net);
    port->dev_bytes_received = 0;
    port->dev_bytes_sent = 0;

    if (genio_acc_exit_on_close(port->acceptor))
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
	LOCK(ports_lock);
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
	UNLOCK(ports_lock);
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
	LOCK(ports_lock);
	curr = ports;
	while ((curr != NULL) && (curr != port)) {
	    prev = curr;
	    curr = curr->next;
	}
	if (curr != NULL) {
	    port = curr->new_config;
	    curr->new_config = NULL;
	    LOCK(curr->lock);
	    LOCK(port->lock);
	    /* Releases curr->lock */
	    if (switchout_port(NULL, port, curr, prev)) {
		/*
		 * This is an unusual case.  We have switched out the
		 * port and it requested a shutdown, but we really
		 * can't wait here in this thread for the shutdown to
		 * complete.  So we mark that we are waiting and do
		 * the startup later in the callback.
		 */
		port->acceptor_reinit_on_shutdown = true;
		reinit_now = false;
		UNLOCK(port->lock);
	    } else {
		UNLOCK(ports_lock);
		goto reinit_port;
	    }
	}
	UNLOCK(ports_lock);
    }

    if (reinit_now) {
	LOCK(port->lock);
    reinit_port:
	port_reinit_now(port);
	UNLOCK(port->lock);
    }
}

static void
io_shutdown_done(struct devio *io)
{
    port_info_t *port = io->user_data;

    finish_shutdown_port(port);
}

static void
shutdown_port_io(sel_runner_t *runner, void *cb_data)
{
    port_info_t *port = cb_data;

    if (port->io.f)
	port->io.f->shutdown(&port->io, io_shutdown_done);
    else
	finish_shutdown_port(port);
}

/* Output the devstr buffer */
static void
handle_dev_fd_close_write(port_info_t *port)
{
    int reterr, buferr;

    reterr = buffer_write(io_do_write, &port->io, port->devstr, &buferr);
    if (reterr == -1) {
	syslog(LOG_ERR, "The dev write for port %s had error: %s",
	       port->portname, strerror(buferr));
	goto closeit;
    }

    if (buffer_cursize(port->devstr) != 0)
	return;

closeit:
    sel_run(port->runshutdown, shutdown_port_io, port);
}

static void
start_shutdown_port_io(sel_runner_t *runner, void *cb_data)
{
    port_info_t *port = cb_data;

    LOCK(port->lock);
    if (port->devstr) {
	free(port->devstr->buf);
	free(port->devstr);
    }
    port->devstr = process_str_to_buf(port, NULL, port->closestr);
    if (port->devstr && (port->net_to_dev_state != PORT_UNCONNECTED)) {
	port->io.f->read_handler_enable(&port->io, 0);
	port->io.f->except_handler_enable(&port->io, 0);
	port->dev_write_handler = handle_dev_fd_close_write;
	port->io.f->write_handler_enable(&port->io, 1);
	UNLOCK(port->lock);
    } else {
	UNLOCK(port->lock);
	shutdown_port_io(NULL, port);
    }
}

static void
timer_shutdown_done(struct selector_s *sel, sel_timer_t *timer, void *cb_data)
{
    start_shutdown_port_io(NULL, cb_data);
}

static void
start_shutdown_port(port_info_t *port, char *reason)
{
    if (port->dev_to_net_state == PORT_CLOSING ||
		port->dev_to_net_state == PORT_UNCONNECTED)
	return;

    port->close_on_output_done = false;

    port->io.f->read_handler_enable(&port->io, false);
    genio_acc_set_accept_callback_enable(port->acceptor, false);

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

    port->dev_to_net_state = PORT_CLOSING;
}

static void
netcon_finish_shutdown(net_info_t *netcon)
{
    port_info_t *port = netcon->port;

    LOCK(port->lock);
    netcon->closing = false;
    netcon->bytes_received = 0;
    netcon->bytes_sent = 0;
    netcon->sending_tn_data = false;
    netcon->write_pos = 0;
    if (netcon->banner) {
	free(netcon->banner->buf);
	free(netcon->banner);
	netcon->banner = NULL;
    }
    telnet_cleanup(&netcon->tn_data);

    if (num_connected_net(port) == 0) {
	if (!port->has_connect_back) {
	    start_shutdown_port(port, "All network connections free");
	    if (sel_stop_timer_with_done(port->timer, timer_shutdown_done,
					 port))
		sel_run(port->runshutdown, start_shutdown_port_io, port);
	}
    } else {
	check_port_new_net(port, netcon);
    }
    UNLOCK(port->lock);
}

static void
handle_net_fd_closed(struct genio *net, void *cb_data)
{
    net_info_t *netcon = genio_get_user_data(net);
    port_info_t *port = netcon->port;

    genio_free(netcon->net);
    netcon->net = NULL;

    LOCK(port->lock);
    if (port->dev_to_net_state == PORT_WAITING_OUTPUT_CLEAR)
	finish_dev_to_net_write(port);
    UNLOCK(port->lock);

    netcon_finish_shutdown(netcon);
}

static void shutdown_netcon_clear(sel_runner_t *runner, void *cb_data)
{
    net_info_t *netcon = cb_data;

    if (netcon->net) {
	int err = genio_close(netcon->net, handle_net_fd_closed, NULL);
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
    sel_run(netcon->runshutdown, shutdown_netcon_clear, netcon);
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

    if (!some_to_close) {
	if (sel_stop_timer_with_done(port->timer, timer_shutdown_done, port))
	    sel_run(port->runshutdown, start_shutdown_port_io, port);
    }
}

void
got_timeout(struct selector_s *sel,
	    sel_timer_t *timer,
	    void        *data)
{
    port_info_t *port = (port_info_t *) data;
    struct timeval then;
    unsigned char modemstate;
    net_info_t *netcon;

    LOCK(port->lock);

    if (port->dev_to_net_state == PORT_CLOSING) {
	UNLOCK(port->lock);
	return;
    }

    if (port->nocon_read_enable_time_left) {
	port->nocon_read_enable_time_left--;
	if (port->nocon_read_enable_time_left == 0)
	    port->io.f->read_handler_enable(&port->io, 1);
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

    if (port->is_2217 &&
		(port->io.f->get_modem_state(&port->io, &modemstate) != -1)) {
	modemstate &= port->modemstate_mask;
	if (modemstate != port->last_modemstate) {
	    unsigned char data[3];
	    data[0] = TN_OPT_COM_PORT;
	    data[1] = 107; /* Notify modemstate */
	    data[2] = modemstate;
	    port->last_modemstate = modemstate;
	    for_each_connection(port, netcon) {
		if (!netcon->net)
		    continue;
		telnet_send_option(&netcon->tn_data, data, 3);
	    }
	}
    }

 out:
    sel_get_monotonic_time(&then);
    then.tv_sec += 1;
    sel_start_timer(port->timer, &then);
    UNLOCK(port->lock);
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
		      strerror(err));
	    break;
	}
	remstr = strtok_r(NULL, ";", &strtok_data);
    }
    free(str);
    return err;
}

static int
myconfig(void *data, struct absout *eout, const char *pos)
{
    port_info_t *port = data;
    enum str_type stype;
    char *s;
    const char *val;
    unsigned int len;
    int rv, ival;

    if (strcmp(pos, "remctl") == 0) {
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

static const struct genio_acceptor_callbacks port_acceptor_cbs = {
    .new_connection = handle_port_accept,
};

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

    new_port = malloc(sizeof(port_info_t));
    if (new_port == NULL) {
	eout->out(eout, "Could not allocate a port data structure");
	return -1;
    }
    memset(new_port, 0, sizeof(*new_port));

    INIT_LOCK(new_port->lock);

    if (sel_alloc_timer(ser2net_sel,
			got_timeout, new_port,
			&new_port->timer))
    {
	eout->out(eout, "Could not allocate timer data");
	goto errout;
    }

    if (sel_alloc_timer(ser2net_sel,
			send_timeout, new_port,
			&new_port->send_timer))
    {
	eout->out(eout, "Could not allocate timer data");
	goto errout;
    }

    if (sel_alloc_runner(ser2net_sel, &new_port->runshutdown)) {
	goto errout;
    }

    new_port->io.devname = find_str(devname, &str_type, NULL);
    if (new_port->io.devname) {
	if (str_type != DEVNAME) {
	    free(new_port->io.devname);
	    new_port->io.devname = NULL;
	} else {
	    new_port->orig_devname = strdup(devname);
	    if (!new_port->orig_devname) {
		eout->out(eout, "unable to allocate original device name");
		goto errout;
	    }
	}
    }
    if (!new_port->io.devname)
	new_port->io.devname = strdup(devname);
    if (!new_port->io.devname) {
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

    if (strcmp(state, "raw") == 0) {
	new_port->enabled = PORT_RAW;
    } else if (strcmp(state, "rawlp") == 0) {
	new_port->enabled = PORT_RAWLP;
	new_port->io.read_disabled = 1;
    } else if (strcmp(state, "telnet") == 0) {
	new_port->enabled = PORT_TELNET;
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

    new_port->io.user_data = new_port;

    if (strncmp(new_port->io.devname, "sol.", 4) == 0) {
	if (solcfg_init(&new_port->io, eout, devcfg, myconfig,
			new_port) == -1) {
	    eout->out(eout, "device configuration invalid");
	    goto errout;
	}
    } else {
	if (devcfg_init(&new_port->io, eout, devcfg, myconfig,
			new_port) == -1) {
	    eout->out(eout, "device configuration invalid");
	    goto errout;
	}
    }

    err = str_to_genio_acceptor(new_port->portname, ser2net_o,
				new_port->net_to_dev.maxsize,
				&port_acceptor_cbs, new_port,
				&new_port->acceptor);
    if (err) {
	eout->out(eout, "Invalid port name/number");
	goto errout;
    }

    if (buffer_init(&new_port->dev_to_net, NULL, new_port->dev_to_net.maxsize))
    {
	eout->out(eout, "Could not allocate dev to net buffer");
	goto errout;
    }

    new_port->telnet_dev_to_net = malloc(new_port->dev_to_net.maxsize / 2);
    if (!new_port->telnet_dev_to_net) {
	eout->out(eout, "Could not allocate telnet dev_to_net buf");
	goto errout;
    }

    if (buffer_init(&new_port->net_to_dev, NULL, new_port->net_to_dev.maxsize))
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
	char *remaddr = find_default_str("remaddr");
	if (!remaddr) {
	    eout->out(eout, "Out of memory processing default remote address");
	} else {
	    err = port_add_remaddr(eout, new_port, remaddr);
	    free(remaddr);
	    if (err)
		goto errout;
	}
    }

    new_port->netcons = malloc(sizeof(*(new_port->netcons)) *
			       new_port->max_connections);
    if (new_port->netcons == NULL) {
	eout->out(eout, "Could not allocate a port data structure");
	goto errout;
    }
    memset(new_port->netcons, 0,
	   sizeof(*(new_port->netcons)) * new_port->max_connections);
    for_each_connection(new_port, netcon) {
	if (sel_alloc_runner(ser2net_sel, &netcon->runshutdown)) {
	    eout->out(eout, "Could not allocate a netcon shutdown handler");
	    goto errout;
	}

	netcon->port = new_port;
    }

    new_port->config_num = config_num;

    /* See if the port already exists, and reconfigure it if so. */
    prev = NULL;
    LOCK(ports_lock);
    curr = ports;
    while (curr != NULL) {
	if (strcmp(curr->portname, new_port->portname) == 0) {
	    /* We are reconfiguring this port. */
	    LOCK(curr->lock);
	    if (curr->dev_to_net_state == PORT_UNCONNECTED) {
		/* Port is disconnected, switch it now. */
		LOCK(new_port->lock);
		/* releases curr->lock */
		if (switchout_port(eout, new_port, curr, prev))
		    wait_for_port_shutdown(new_port, &shutdown_count);
		UNLOCK(new_port->lock);
	    } else {
		/* Mark it to be replaced later. */
		if (curr->new_config != NULL)
		    free_port(curr->new_config);
		curr->config_num = config_num;
		curr->new_config = new_port;
		UNLOCK(curr->lock);
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

	LOCK(new_port->lock);
	rv = startup_port(eout, new_port, false);
	UNLOCK(new_port->lock);
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
    UNLOCK(ports_lock);

    wait_for_waiter(acceptor_shutdown_wait, shutdown_count);

    return 0;

errout_unlock:
    UNLOCK(ports_lock);
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
    LOCK(ports_lock);
    while (curr != NULL) {
	if (curr->config_num != curr_config) {
	    /* The port was removed, remove it. */
	    LOCK(curr->lock);
	    if (curr->dev_to_net_state == PORT_UNCONNECTED) {
		if (change_port_state(NULL, curr, PORT_DISABLED, false))
		    wait_for_port_shutdown(curr, &shutdown_count);
		UNLOCK(curr->lock);
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
		UNLOCK(curr->lock);
		prev = curr;
		curr = curr->next;
	    }
	} else {
	    prev = curr;
	    curr = curr->next;
	}
    }
    UNLOCK(ports_lock);

    wait_for_waiter(acceptor_shutdown_wait, shutdown_count);
}

#define REMOTEADDR_COLUMN_WIDTH \
    (INET6_ADDRSTRLEN - 1 /* terminating NUL */ + 1 /* comma */ + 5 /* strlen("65535") */)

/* Print information about a port to the control port given in cntlr. */
static void
showshortport(struct controller_info *cntlr, port_info_t *port)
{
    char buffer[NI_MAXHOST + NI_MAXSERV + 2];
    int  count;
    int  need_space = 0;
    struct absout out = { .out = cntrl_absout, .data = cntlr };
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
	genio_raddr_to_str(netcon->net, NULL, buffer, sizeof(buffer));
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

    controller_outputf(cntlr, "%-22s ", port->io.devname);
    controller_outputf(cntlr, "%-14s ", state_str[port->net_to_dev_state]);
    controller_outputf(cntlr, "%-14s ", state_str[port->dev_to_net_state]);
    controller_outputf(cntlr, "%9d ", bytes_recv);
    controller_outputf(cntlr, "%9d ", bytes_sent);
    controller_outputf(cntlr, "%9d ", port->dev_bytes_received);
    controller_outputf(cntlr, "%9d ", port->dev_bytes_sent);

    if (port->enabled != PORT_RAWLP) {
	port->io.f->show_devcfg(&port->io, &out);
	need_space = 1;
    }

    if (port->net_to_dev_state != PORT_UNCONNECTED) {
	if (need_space) {
	    controller_outs(cntlr, " ");
	}

	port->io.f->show_devcontrol(&port->io, &out);
    }
    controller_outs(cntlr, "\r\n");

}

/* Print information about a port to the control port given in cntlr. */
static void
showport(struct controller_info *cntlr, port_info_t *port)
{
    char buffer[NI_MAXHOST + NI_MAXSERV + 2];
    struct absout out = { .out = cntrl_absout, .data = cntlr };
    net_info_t *netcon;

    controller_outputf(cntlr, "TCP Port %s\r\n", port->portname);
    controller_outputf(cntlr, "  enable state: %s\r\n",
		       enabled_str[port->enabled]);
    controller_outputf(cntlr, "  timeout: %d\r\n", port->timeout);

    for_each_connection(port, netcon) {
	if (netcon->net) {
	    genio_raddr_to_str(netcon->net, NULL, buffer, sizeof(buffer));
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
	controller_outputf(cntlr, "  device: %s (%s)\r\n", port->io.devname,
			   port->orig_devname);
    else
	controller_outputf(cntlr, "  device: %s\r\n", port->io.devname);

    controller_outputf(cntlr, "  device config: ");
    if (port->enabled == PORT_RAWLP) {
	controller_outputf(cntlr, "none\r\n");
    } else {
	port->io.f->show_devcfg(&port->io, &out);
	controller_outputf(cntlr, "\r\n");
    }

    controller_outputf(cntlr, "  device controls: ");
    if (port->net_to_dev_state == PORT_UNCONNECTED) {
	controller_outputf(cntlr, "not currently connected\r\n");
    } else {
	port->io.f->show_devcontrol(&port->io, &out);
	controller_outputf(cntlr, "\r\n");
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

    LOCK(ports_lock);
    port = ports;
    while (port != NULL) {
	if (strcmp(portstr, port->portname) == 0) {
	    LOCK(port->lock);
	    UNLOCK(ports_lock);
	    if (port->config_num == -1 && !allow_deleted) {
		UNLOCK(port->lock);
		return NULL;
	    }
	    return port;
	}
	port = port->next;
    }

    UNLOCK(ports_lock);
    return NULL;
}

/* Handle a showport command from the control port. */
void
showports(struct controller_info *cntlr, char *portspec)
{
    port_info_t *port;

    if (portspec == NULL) {
	LOCK(ports_lock);
	/* Dump everything. */
	port = ports;
	while (port != NULL) {
	    LOCK(port->lock);
	    showport(cntlr, port);
	    UNLOCK(port->lock);
	    port = port->next;
	}
	UNLOCK(ports_lock);
    } else {
	port = find_port_by_num(portspec, true);
	if (port == NULL) {
	    controller_outputf(cntlr, "Invalid port number: %s\r\n", portspec);
	} else {
	    showport(cntlr, port);
	    UNLOCK(port->lock);
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
	LOCK(ports_lock);
	/* Dump everything. */
	port = ports;
	while (port != NULL) {
	    LOCK(port->lock);
	    showshortport(cntlr, port);
	    UNLOCK(port->lock);
	    port = port->next;
	}
	UNLOCK(ports_lock);
    } else {
	port = find_port_by_num(portspec, true);
	if (port == NULL) {
	    controller_outputf(cntlr, "Invalid port number: %s\r\n", portspec);
	} else {
	    showshortport(cntlr, port);
	    UNLOCK(port->lock);
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
	UNLOCK(port->lock);
    }
}

/* Configure a port.  The port number and configuration are passed in
   as strings, this code will get the port and then call the code to
   configure the device. */
void
setportdevcfg(struct controller_info *cntlr, char *portspec, char *devcfg)
{
    port_info_t *port;
    struct absout out = { .out = cntrl_abserrout, .data = cntlr };

    port = find_port_by_num(portspec, false);
    if (port == NULL) {
	controller_outputf(cntlr, "Invalid port number: %s\r\n", portspec);
    } else {
	if (port->io.f->reconfig(&port->io, &out, devcfg, myconfig, port) == -1)
	{
	    controller_outputf(cntlr, "Invalid device config\r\n");
	}
	UNLOCK(port->lock);
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
	if (port->io.f->set_devcontrol(&port->io, controls) == -1) {
	    controller_outputf(cntlr, "Invalid device controls\r\n");
	}
    }
    UNLOCK(port->lock);
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
    } else if (strcmp(enable, "raw") == 0) {
	new_enable = PORT_RAW;
    } else if (strcmp(enable, "rawlp") == 0) {
	new_enable = PORT_RAWLP;
    } else if (strcmp(enable, "telnet") == 0) {
	new_enable = PORT_TELNET;
    } else {
	controller_outputf(cntlr, "Invalid enable: %s\r\n", enable);
	goto out_unlock;
    }

    if (change_port_state(&eout, port, new_enable, false))
	wait_for_port_shutdown(port, &shutdown_count);

 out_unlock:
    UNLOCK(port->lock);

    wait_for_waiter(acceptor_shutdown_wait, shutdown_count);
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
	UNLOCK(port->lock);
	port = NULL;
	goto out;
    }
 out_unlock:
    UNLOCK(port->lock);
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

    LOCK(ports_lock);
    curr = ports;
    while (curr) {
	if (curr == port) {
	    LOCK(port->lock);
	    port->net_monitor = NULL;
	    port->dev_monitor = NULL;
	    UNLOCK(port->lock);
	    break;
	}
    }
    UNLOCK(ports_lock);
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
    UNLOCK(port->lock);
 out:
    return;
}

static int
com_port_will_do(void *cb_data, unsigned char cmd)
{
    net_info_t *netcon = cb_data;
    port_info_t *port = netcon->port;
    unsigned char data[3];

    if (!port->allow_2217)
	return 0;

    if (cmd != TN_WILL && cmd != TN_WONT)
	/* We only handle these. */
	return 0;

    if (cmd == TN_WONT) {
	/* The remote end turned off RFC2217 handling. */
	port->is_2217 = false;
	return 0;
    }

    port->is_2217 = true;

    /* Set up modem state mask. */
    port->linestate_mask = 0;
    port->modemstate_mask = 255;
    port->last_modemstate = 0;

    /* send a modemstate notify */
    data[0] = TN_OPT_COM_PORT;
    data[1] = 107; /* Notify modemstate */
    data[2] = 0;
    if (port->io.f->get_modem_state(&port->io, data + 2) != -1) {
	port->last_modemstate = data[2];
    }
    telnet_send_option(&netcon->tn_data, data, 3);
    return 1;
}

static void
com_port_handler(void *cb_data, unsigned char *option, int len)
{
    net_info_t *netcon = cb_data;
    port_info_t *port = netcon->port;
    unsigned char outopt[MAX_TELNET_CMD_XMIT_BUF];
    int val;
    unsigned char ucval;
    int cisco_ios_baud_rates = 0;

    if (!port->is_2217)
	return;

    if (len < 2)
	return;

    switch (option[1]) {
    case 0: /* SIGNATURE? */
    {
	/* truncate signature, if it exceeds buffer size */
	char *sig = port->signaturestr;
	int sign_len;

	if (!sig)
	    /* If not set, use a default. */
	    sig = rfc2217_signature;

	sign_len = strlen(sig);
	if (sign_len > (MAX_TELNET_CMD_XMIT_BUF - 2))
	    sign_len = MAX_TELNET_CMD_XMIT_BUF - 2;

	outopt[0] = 44;
	outopt[1] = 100;
	strncpy((char *) outopt + 2, sig, sign_len);
	telnet_send_option(&netcon->tn_data, outopt, 2 + sign_len);
	break;
    }

    case 1: /* SET-BAUDRATE */
	if (len == 3) {
	    cisco_ios_baud_rates = 1;
	    val = cisco_baud_to_baud(option[2]);
	} else {
	    if (len < 6)
		return;
	    /* Basically the same as:
	     *  val = ntohl(*((uint32_t *) (option + 2)));
	     * but handled unaligned cases */
	    val = option[2] << 24;
	    val |= option[3] << 16;
	    val |= option[4] << 8;
	    val |= option[5];
	}

	port->io.f->baud_rate(&port->io, &val);
	port->bps = val;
	recalc_port_chardelay(port);
	outopt[0] = 44;
	outopt[1] = 101;
	if (cisco_ios_baud_rates) {
	    outopt[2] = baud_to_cisco_baud(val);
	    telnet_send_option(&netcon->tn_data, outopt, 3);
	} else {
	    /* Basically the same as:
	     * *((uint32_t *) (outopt + 2)) = htonl(val);
	     * but handles unaligned cases */
	    outopt[2] = val >> 24;
	    outopt[3] = val >> 16;
	    outopt[4] = val >> 8;
	    outopt[5] = val;
	    telnet_send_option(&netcon->tn_data, outopt, 6);
	}
	break;

    case 2: /* SET-DATASIZE */
	if (len < 3)
	    return;

	ucval = option[2];
	port->io.f->data_size(&port->io, &ucval, &port->bpc);
	recalc_port_chardelay(port);
	outopt[0] = 44;
	outopt[1] = 102;
	outopt[2] = ucval;
	telnet_send_option(&netcon->tn_data, outopt, 3);
	break;

    case 3: /* SET-PARITY */
	if (len < 3)
	    return;

	ucval = option[2];
	port->io.f->parity(&port->io, &ucval, &port->bpc);
	recalc_port_chardelay(port);
	outopt[0] = 44;
	outopt[1] = 103;
	outopt[2] = ucval;
	telnet_send_option(&netcon->tn_data, outopt, 3);
	break;

    case 4: /* SET-STOPSIZE */
	if (len < 3)
	    return;

	ucval = option[2];
	port->io.f->stop_size(&port->io, &ucval, &port->bpc);
	recalc_port_chardelay(port);
	outopt[0] = 44;
	outopt[1] = 104;
	outopt[2] = ucval;
	telnet_send_option(&netcon->tn_data, outopt, 3);
	break;

    case 5: /* SET-CONTROL */
	if (len < 3)
	    return;

	ucval = option[2];
	port->io.f->control(&port->io, &ucval);
	outopt[0] = 44;
	outopt[1] = 105;
	outopt[2] = ucval;
	telnet_send_option(&netcon->tn_data, outopt, 3);
	break;

    case 8: /* FLOWCONTROL-SUSPEND */
	port->io.f->flow_control(&port->io, 1);
	outopt[0] = 44;
	outopt[1] = 108;
	telnet_send_option(&netcon->tn_data, outopt, 2);
	break;

    case 9: /* FLOWCONTROL-RESUME */
	port->io.f->flow_control(&port->io, 0);
	outopt[0] = 44;
	outopt[1] = 109;
	telnet_send_option(&netcon->tn_data, outopt, 2);
	break;

    case 10: /* SET-LINESTATE-MASK */
	if (len < 3)
	    return;
	port->linestate_mask = option[2];
	outopt[0] = 44;
	outopt[1] = 110;
	outopt[2] = port->linestate_mask;
	telnet_send_option(&netcon->tn_data, outopt, 3);
	break;

    case 11: /* SET-MODEMSTATE-MASK */
	if (len < 3)
	    return;
	port->modemstate_mask = option[2];
	outopt[0] = 44;
	outopt[1] = 111;
	outopt[2] = port->modemstate_mask;
	telnet_send_option(&netcon->tn_data, outopt, 3);
	break;

    case 12: /* PURGE_DATA */
	if (len < 3)
	    return;
	val = option[2];
	port->io.f->flush(&port->io, &val);
	outopt[0] = 44;
	outopt[1] = 112;
	outopt[2] = val;
	telnet_send_option(&netcon->tn_data, outopt, 3);
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
    port_info_t *port = ports, *next;
    unsigned int shutdown_count = 0;

    /* No need for a lock here, nothing can reconfigure the port list at
       this point. */
    while (port != NULL) {
	port->config_num = -1;
	next = port->next;
	LOCK(port->lock);
	if (change_port_state(NULL, port, PORT_DISABLED, false))
	    wait_for_port_shutdown(port, &shutdown_count);
	UNLOCK(port->lock);
	shutdown_port(port, "program shutdown");
	UNLOCK(port->lock);
	port = next;
    }

    wait_for_waiter(acceptor_shutdown_wait, shutdown_count);
}

int
check_ports_shutdown(void)
{
    return ports == NULL;
}

int
init_dataxfer(void)
{
    acceptor_shutdown_wait = alloc_waiter(ser2net_sel, ser2net_wake_sig);
    if (!acceptor_shutdown_wait)
	return ENOMEM;

    rotator_shutdown_wait = alloc_waiter(ser2net_sel, ser2net_wake_sig);
    if (!rotator_shutdown_wait) {
	free_waiter(rotator_shutdown_wait);
	return ENOMEM;
    }

    return 0;
}

void
shutdown_dataxfer(void)
{
    free_waiter(rotator_shutdown_wait);
    free_waiter(acceptor_shutdown_wait);
}
