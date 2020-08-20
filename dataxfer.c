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

#include "port.h"
#include "ser2net.h"
#include "dataxfer.h"
#include "readconfig.h"
#include "led.h"

/* For tracing. */
#define SERIAL "term"
#define NET    "tcp "

static void setup_port(port_info_t *port, net_info_t *netcon);
static int handle_net_event(struct gensio *net, void *user_data,
			    int event, int err,
			    unsigned char *buf, gensiods *buflen,
			    const char *const *auxdata);

struct gensio_lock *ports_lock;
port_info_t *ports = NULL; /* Linked list of ports. */
port_info_t *new_ports = NULL; /* New ports during config/reconfig. */
port_info_t *new_ports_end = NULL;

static void shutdown_one_netcon(net_info_t *netcon, const char *reason);

static int
all_net_connectbacks_done(port_info_t *port)
{
    net_info_t *netcon;

    for_each_connection(port, netcon) {
	if (netcon->connect_back && !netcon->net)
	    return false;
    }

    return true;
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

net_info_t *
first_live_net_con(port_info_t *port)
{
    net_info_t *netcon;

    for_each_connection(port, netcon) {
	if (netcon->net)
	    return netcon;
    }

    return NULL;
}

gensiods
net_raddr(struct gensio *io, struct sockaddr_storage *addr, gensiods *socklen)
{
    *socklen = sizeof(*addr);
#if (defined(gensio_version_major) && (gensio_version_major > 2 || \
	       (gensio_version_major == 2 && gensio_version_minor > 0)))
    return gensio_control(io, GENSIO_CONTROL_DEPTH_FIRST, true,
			  GENSIO_CONTROL_RADDR_BIN,
			  (char *) addr, socklen);
#else
    return gensio_get_raddr(io, (char *) addr, socklen);
#endif
}

void
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

static int
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
    if (sizeof(buf) > len)
	len += net_raddr_str(netcon->net, buf + len, sizeof(buf) - len);
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

static void
send_timeout(struct gensio_timer *timer, void *data)
{
    port_info_t *port = (port_info_t *) data;

    so->lock(port->lock);

    port->send_timer_running = false;
    if (port->dev_to_net_state == PORT_CLOSING ||
		port->dev_to_net_state == PORT_CLOSED) {
	so->unlock(port->lock);
	return;
    }

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
report_newcon(port_info_t *port, net_info_t *netcon)
{
    if (!net_raddr_str(netcon->net, netcon->remaddr, sizeof(netcon->remaddr)))
	strcpy(netcon->remaddr, "*unknown*");
    cntlr_report_conchange("new connection", port->name, netcon->remaddr);
}

static void
report_disconnect(port_info_t *port, net_info_t *netcon)
{
    cntlr_report_conchange("disconnect", port->name, netcon->remaddr);
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
	report_newcon(port, netcon);
	setup_port(port, netcon);
    }
    assert(port->num_waiting_connect_backs > 0);
    port->num_waiting_connect_backs--;
    if (port->num_waiting_connect_backs == 0) {
	if (!all_net_connectbacks_done(port))
	    /* Not all connections back could be made. */
	    port->nocon_read_enable_time_left = port->accepter_retry_time;
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

    if (port->net_to_dev_state == PORT_CLOSING) {
	/*
	 * Some data came in while we were shutting down the port.
	 * Just ignore it for now, when the port is opened back up we
	 * wills tart the connections.
	 */
	return 1;
    }

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
	port->nocon_read_enable_time_left = port->accepter_retry_time;
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
	shutdown_port(port, "dev read error");
    }

    nr_handlers = port_check_connect_backs(port);
    if (nr_handlers > 0) {
	gensio_set_read_callback_enable(port->io, false);
	goto out_unlock;
    }

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
    if (buf->pos >= buf->cursize)
	gbuf_reset(buf);

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
	syslog(LOG_ERR, "The dev write(2) for port %s had error: %s",
	       port->name, gensio_err_to_str(err));
	shutdown_port(port, "dev write error");
	rv = buflen;
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

    if (!sio)
	return;
    netcon->modemstate_mask = modemstate;
    sergensio_modemstate(sio, port->last_modemstate & netcon->modemstate_mask);
}

static void
s2n_linestate(net_info_t *netcon, struct sergensio *sio, unsigned int linestate)
{
    port_info_t *port = netcon->port;

    if (!sio)
	return;
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

    if (!sio)
	return;
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

bool
port_in_use(port_info_t *port)
{
    return (port->net_to_dev_state != PORT_UNCONNECTED &&
	    port->net_to_dev_state != PORT_CLOSED);
}

/* Checks to see if some other port has the same device in use.  Must
   be called with ports_lock held. */
int
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
    char buf[1024], *s, *speed;

    if (net_raddr_str(port->io, buf, sizeof(buf)) == 0)
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
port_start_timer(port_info_t *port)
{
    gensio_time timeout;
    unsigned int timeout_sec = 1;

    if (port->dev_to_net_state == PORT_UNCONNECTED)
	timeout_sec = port->connector_retry_time;

    if (port->dev_to_net_state == PORT_CLOSED)
	timeout_sec = port->accepter_retry_time;

#ifdef gensio_version_major
    timeout.secs = timeout_sec;
    timeout.nsecs = 0;
#else
    timeout.tv_sec = timeout_sec;
    timeout.tv_usec = 0;
#endif
    so->start_timer(port->timer, &timeout);
}

static void
port_dev_open_done(struct gensio *io, int err, void *cb_data)
{
    port_info_t *port = cb_data;
    net_info_t *netcon;

    so->lock(port->lock);
    if (err) {
	char errstr[200];

	port->io_open = false;
	snprintf(errstr, sizeof(errstr), "Device open failure: %s\r\n",
		 gensio_err_to_str(err));
	for_each_connection(port, netcon) {
	    if (!netcon->net)
		continue;
	    gensio_write(netcon->net, NULL, errstr, strlen(errstr), NULL);
	    report_disconnect(port, netcon);
	    gensio_free(netcon->net);
	    netcon->net = NULL;
	}
	shutdown_port(port, "Device open failure");
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

    setup_trace(port);

    port_start_timer(port);

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
    port->dev_to_net_state = PORT_WAITING_INPUT;
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

    if (num_connected_net(port) == 1 && (!port->connbacks || !port->io_open)) {
	/* We are first, set things up on the device. */
	err = port_dev_enable(port);
	if (err) {
	    char errstr[200];

	    snprintf(errstr, sizeof(errstr), "Device open failure: %s\r\n",
		     gensio_err_to_str(err));
	    gensio_write(netcon->net, NULL, errstr, strlen(errstr), NULL);
	    report_disconnect(port, netcon);
	    gensio_free(netcon->net);
	    netcon->net = NULL;
	}
	return;
    }

    finish_setup_net(port, netcon);
}

void
handle_new_net(port_info_t *port, struct gensio *net, net_info_t *netcon)
{
    netcon->net = net;

    report_newcon(port, netcon);

    /* XXX log netcon->remote */
    setup_port(port, netcon);
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

    if (!net_raddr(net, &addr, &socklen)) {
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

    if (port->connbacks && !port->io_open)
	err = "Port's device failed open\r\n";

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
	return handle_acc_auth_event(port->authdir, port->allowed_users,
				     event, data);
    }
}

int
startup_port(struct absout *eout, port_info_t *port)
{
    int err;

    if (port->dev_to_net_state != PORT_CLOSED)
	return GE_INUSE;

    err = gensio_acc_startup(port->accepter);
    if (err) {
	eout->out(eout, "Unable to startup network port %s: %s",
		  port->name, gensio_err_to_str(err));
	/* Retry in a bit. */
	port_start_timer(port);
	return err;
    }
    port->dev_to_net_state = PORT_UNCONNECTED;
    port->net_to_dev_state = PORT_UNCONNECTED;

    if (port->connbacks) {
	err = port_dev_enable(port);
	if (err) {
	    eout->out(eout, "Unable to enable port device %s: %s",
		      port->name, gensio_err_to_str(err));
	    shutdown_port(port, "Error enabling port connector");
	    err = 0; /* Don't report an error here, let the shutdown run. */
	}
    }

    return err;
}

static void
call_port_op_done(port_info_t *port)
{
    void (*port_op_done)(struct port_info *, void *) = port->port_op_done;

    if (port_op_done) {
	port->port_op_done = NULL;
	port_op_done(port, port->port_op_data);
    }
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
	if (port->connbacks)
	    port_start_timer(port);
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
	    so->lock(new->lock);
	    if (prev) {
		new->next = prev->next;
		prev->next = new;
	    } else {
		new->next = ports;
		ports = new;
	    }
	    if (new->enabled)
		startup_port(&syslog_absout, new);
	    so->unlock(new->lock);
	}
	so->unlock(ports_lock);
	return; /* We have to return here because we no longer have a port. */
    } else if (port->enabled) {
	net_info_t *netcon;

	gensio_acc_set_accept_callback_enable(port->accepter, true);
	for_each_connection(port, netcon)
	    check_port_new_net(port, netcon);
    } else {
	/* Port was disabled, shut it down. */
	gensio_acc_shutdown(port->accepter, NULL, NULL);
	call_port_op_done(port);
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

void
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
	syslog(LOG_ERR, "The dev write(3) for port %s had error: %s",
	       port->name, gensio_err_to_str(err));
	goto closeit;
    }

    if (gbuf_cursize(&port->net_to_dev) ||
		(port->devstr && gbuf_cursize(port->devstr)))
	return;

closeit:
    if (port->shutdown_timeout_count) {
	gensio_set_write_callback_enable(port->io, false);
	err = so->stop_timer_with_done(port->timer, timer_shutdown_done, port);
	if (err == GE_TIMEDOUT) {
	    port->shutdown_timeout_count = 0;
	    shutdown_port_io(port);
	}
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
	report_disconnect(port, netcon);
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

    netcon->close_on_output_done = false;
    netcon->closing = true;
    err = gensio_close(netcon->net, handle_net_fd_closed, netcon);
    if (err)
	netcon_finish_shutdown(netcon);
}

static bool
shutdown_all_netcons(port_info_t *port, bool close_on_output_only)
{
    net_info_t *netcon;
    bool some_to_close = false;

    for_each_connection(port, netcon) {
	if (netcon->net) {
	    if (close_on_output_only && !netcon->close_on_output_done)
		continue;
	    some_to_close = true;
	    netcon->write_pos = port->dev_to_net.cursize;
	    shutdown_one_netcon(netcon, "port closing");
	}
    }

    return some_to_close;
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

    footer_trace(port, "port", port->shutdown_reason);

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

    port->dev_to_net_state = PORT_CLOSING;
    port->net_to_dev_state = PORT_CLOSING;

    if (!some_to_close)
	start_shutdown_port_io(port);

 out_unlock:
    so->unlock(port->lock);
}

int
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

    if (errreason) {
	/* It's an error, force a shutdown.  Don't set dev_to_net_state yet. */
	port->shutdown_reason = errreason;
	port->net_to_dev_state = PORT_CLOSING;
    } else {
	port->shutdown_reason = "All users disconnected";
    }

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

static bool
handle_shutdown_timeout(port_info_t *port)
{
    /* Something wasn't able to do any writes and locked up the shutdown. */

    /* Check the network connections first. */
    if (shutdown_all_netcons(port, true))
	return true;

    shutdown_port_io(port);
    return false;
}

static void
port_timeout(struct gensio_timer *timer, void *data)
{
    port_info_t *port = (port_info_t *) data;
    net_info_t *netcon;
    int err;

    so->lock(port->lock);
    if (port->dev_to_net_state == PORT_CLOSED) {
	if (port->enabled)
	    startup_port(&syslog_absout, port);
	goto out_unlock;
    }

    if (port->dev_to_net_state == PORT_UNCONNECTED) {
	if (port->connbacks && !port->io_open) {
	    err = port_dev_enable(port);
	    if (err)
		goto out;
	}
	goto out_unlock;
    }

    if (port->dev_to_net_state == PORT_CLOSING) {
	if (port->shutdown_timeout_count <= 1) {
	    bool dotimer = false;

	    port->shutdown_timeout_count = 0;
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
    port_start_timer(port);
 out_unlock:
    so->unlock(port->lock);
}

void
apply_new_ports(struct absout *eout)
{
    port_info_t *new, *curr, *next, *prev, *new_prev;

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
			shutdown_all_netcons(curr, false);
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
		if (curr->enabled)
		    startup_port(eout, curr);
	    }
	}
	so->unlock(curr->lock);
    }
    so->unlock(ports_lock);
}

int
dataxfer_setup_port(port_info_t *new_port, struct absout *eout,
		    bool do_telnet)
{
    int err;

    new_port->timer = so->alloc_timer(so, port_timeout, new_port);
    if (!new_port->timer) {
	eout->out(eout, "Could not allocate timer data");
	return -1;
    }

    new_port->send_timer = so->alloc_timer(so, send_timeout, new_port);
    if (!new_port->send_timer) {
	eout->out(eout, "Could not allocate timer data");
	return -1;
    }

    new_port->runshutdown = so->alloc_runner(so, finish_shutdown_port,
					     new_port);
    if (!new_port->runshutdown) {
	eout->out(eout, "Could not allocate shutdown runner");
	return -1;
    }

    err = str_to_gensio(new_port->devname, so, handle_dev_event, new_port,
			&new_port->io);
    if (err) {
	eout->out(eout, "device configuration %s invalid: %s",
		  new_port->devname, gensio_err_to_str(err));
	return -1;
    }

    err = str_to_gensio_accepter(new_port->accstr, so,
				handle_port_child_event, new_port,
				&new_port->accepter);
    if (err) {
	eout->out(eout, "Invalid port name/number: %s", gensio_err_to_str(err));
	return -1;
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
	if (err) {
	    eout->out(eout, "Could not allocate telnet gensio: %s",
		      gensio_err_to_str(err));
	    return -1;
	}
	new_port->accepter = parent;
    }

    return 0;
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
	    so->unlock(port->lock);
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
    shutdown_rotators();
    if (ports_lock)
	so->free_lock(ports_lock);
}

int
init_dataxfer(void)
{
    int rv;

    ports_lock = so->alloc_lock(so);
    if (!ports_lock) {
	rv = ENOMEM;
	goto out;
    }

    rv = init_rotators();

 out:
    if (rv)
	shutdown_dataxfer();
    return rv;
}
