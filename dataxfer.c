/*
 *  ser2net - A program for allowing telnet connection to serial ports
 *  Copyright (C) 2001-2020  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: GPL-2.0-only
 *
 *  In addition, as a special exception, the copyright holders of
 *  ser2net give you permission to combine ser2net with free software
 *  programs or libraries that are released under the GNU LGPL and
 *  with code included in the standard release of OpenSSL under the
 *  OpenSSL license (or modified versions of such code, with unchanged
 *  license). You may copy and distribute such a system following the
 *  terms of the GNU GPL for ser2net and the licenses of the other code
 *  concerned, provided that you include the source code of that
 *  other code when and as the GNU GPL requires distribution of source
 *  code.
 *
 *  Note that people who make modified versions of ser2net are not
 *  obligated to grant this special exception for their modified
 *  versions; it is their choice whether to do so. The GNU General
 *  Public License gives permission to release a modified version
 *  without this exception; this exception also makes it possible to
 *  release a modified version which carries forward this exception.
 */

/* This code handles the actual transfer of data between the serial
   ports and the TCP ports. */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <stdint.h>

#include <gensio/gensio.h>
#include <gensio/sergensio.h>

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

void
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
		seout.out(&seout, "Unable to allocate connect back port %s,"
			  " addr %s: %s\n", port->name, netcon->remote_str,
			  gensio_err_to_str(err));
		continue;
	    }
	    err = gensio_open(netcon->net, connect_back_done, netcon);
	    if (err) {
		gensio_free(netcon->net);
		netcon->net = NULL;
		seout.out(&seout, "Unable to open connect back port %s,"
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
	seout.out(&seout, "dev read error for device on port %s: %s",
		  port->name, gensio_err_to_str(err));
	shutdown_port(port, "dev read error");
    }

    nr_handlers = port_check_connect_backs(port);
    if (nr_handlers > 0) {
	gensio_set_read_callback_enable(port->io, false);
	goto out_unlock;
    }

    if (port->no_dev_to_net) {
	count = buflen;
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

static void handle_ser_modemstate(port_info_t *port, net_info_t *netcon);
static void handle_ser_linestate(port_info_t *port, net_info_t *netcon);

int
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
	for_each_connection(port, netcon)
	    handle_ser_modemstate(port, netcon);
	so->unlock(port->lock);
	return 0;

    case GENSIO_EVENT_SER_LINESTATE:
	so->lock(port->lock);
	port->last_linestate = *((unsigned int *) buf);
	for_each_connection(port, netcon)
	    handle_ser_linestate(port, netcon);
	so->unlock(port->lock);
	return 0;

#ifdef GENSIO_EVENT_PARMLOG
    case GENSIO_EVENT_PARMLOG: {
	struct gensio_parmlog_data *d = (struct gensio_parmlog_data *) buf;
	seout.vout(&seout, d->log, d->args);
	return 0;
    }
#endif

    default:
	return GE_NOTSUP;
    }
}

void
port_send_timeout(struct gensio_timer *timer, void *data)
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

int
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
	seout.out(&seout, "The dev write for port %s had error: %s",
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
	gbuf_free(port->devstr);
	port->devstr = NULL;

	/* Send out any data we got on the TCP port. */
	handle_dev_fd_normal_write(port);
    }
}

/* Data is ready to read on the network port. */
static gensiods
handle_net_fd_read(net_info_t *netcon, int readerr,
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
	    seout.out(&seout, "read error for port %s: %s", port->name,
		      gensio_err_to_str(readerr));
	    reason = "network read error";
	}
	goto out_shutdown;
    }

    if (port->no_net_to_dev) {
	rv = buflen;
	goto out_unlock;
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
	seout.out(&seout, "The dev write(2) for port %s had error: %s",
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
	seout.out(&seout, "The network write for port %s had error: %s",
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
handle_net_fd_write_ready(net_info_t *netcon)
{
    port_info_t *port = netcon->port;
    int rv = 1;

    so->lock(port->lock);
    if (netcon->banner) {
	rv = net_fd_write(port, netcon, netcon->banner, &netcon->banner->pos);
	if (rv <= 0)
	    goto out_unlock;

	gbuf_free(netcon->banner);
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
    if (rv != 0)
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
handle_ser_modemstate(port_info_t *port, net_info_t *netcon)
{
    struct sergensio *sio;

    if (!netcon->net)
	return;
    sio = gensio_to_sergensio(netcon->net);
    if (!sio)
	return;

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

static void
handle_ser_linestate(port_info_t *port, net_info_t *netcon)
{
    struct sergensio *sio;

    if (!netcon->net)
	return;
    sio = gensio_to_sergensio(netcon->net);
    if (!sio)
	return;

    if (port->last_linestate & netcon->linestate_mask)
	sergensio_linestate(sio, (port->last_linestate &
				  netcon->linestate_mask));
}

static void
sergensio_val_set(struct sergensio *sio, int err,
		  unsigned int val, void *cb_data)
{
    port_info_t *port = sergensio_get_user_data(sio);
    enum s2n_ser_ops op = (intptr_t) cb_data;
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
s2n_modemstate(net_info_t *netcon, struct gensio *io,unsigned int modemstate)
{
    struct sergensio *sio = gensio_to_sergensio(io);
    port_info_t *port = netcon->port;

    if (!sio)
	return;
    netcon->modemstate_mask = modemstate;
    sergensio_modemstate(sio, port->last_modemstate & netcon->modemstate_mask);
}

static void
s2n_linestate(net_info_t *netcon, struct gensio *io, unsigned int linestate)
{
    struct sergensio *sio = gensio_to_sergensio(io);
    port_info_t *port = netcon->port;

    if (!sio)
	return;
    netcon->linestate_mask = linestate;
    sergensio_linestate(sio, port->last_linestate & netcon->linestate_mask);
}

static void
s2n_flowcontrol_state(net_info_t *netcon, bool val)
{
    struct sergensio *rsio = gensio_to_sergensio(netcon->port->io);

    if (!rsio)
	return;
    sergensio_flowcontrol_state(rsio, val);
}

static void
s2n_flush(net_info_t *netcon, int val)
{
    struct sergensio *port_rsio = gensio_to_sergensio(netcon->port->io);
    struct sergensio *net_rsio = gensio_to_sergensio(netcon->net);

    if (port_rsio)
        sergensio_flush(port_rsio, val);

    if (net_rsio)
        sergensio_flush(net_rsio, val);
}

static void
s2n_baud(net_info_t *netcon, int baud)
{
    struct sergensio *rsio = gensio_to_sergensio(netcon->port->io);

    if (!rsio)
	return;
    sergensio_baud(rsio, baud,
		   sergensio_val_set, (void *) (long) S2N_BAUD);
}

static void
s2n_datasize(net_info_t *netcon, int datasize)
{
    struct sergensio *rsio = gensio_to_sergensio(netcon->port->io);

    if (!rsio)
	return;
    sergensio_datasize(rsio, datasize,
		       sergensio_val_set, (void *) (long) S2N_DATASIZE);
}

static void
s2n_parity(net_info_t *netcon, int parity)
{
    struct sergensio *rsio = gensio_to_sergensio(netcon->port->io);

    if (!rsio)
	return;
    sergensio_parity(rsio, parity,
		     sergensio_val_set, (void *) (long) S2N_PARITY);
}

static void
s2n_stopbits(net_info_t *netcon, int stopbits)
{
    struct sergensio *rsio = gensio_to_sergensio(netcon->port->io);

    if (!rsio)
	return;
    sergensio_stopbits(rsio, stopbits,
		       sergensio_val_set, (void *) (long) S2N_STOPBITS);
}

static void
s2n_flowcontrol(net_info_t *netcon, int flowcontrol)
{
    struct sergensio *rsio = gensio_to_sergensio(netcon->port->io);

    if (!rsio)
	return;
    sergensio_flowcontrol(rsio, flowcontrol,
			  sergensio_val_set, (void *) (long) S2N_FLOWCONTROL);
}

static void
s2n_iflowcontrol(net_info_t *netcon, int iflowcontrol)
{
    struct sergensio *rsio = gensio_to_sergensio(netcon->port->io);

    if (!rsio)
	return;
    sergensio_iflowcontrol(rsio, iflowcontrol,
			   sergensio_val_set, (void *) (long) S2N_IFLOWCONTROL);
}

static void
s2n_sbreak(net_info_t *netcon, int breakv)
{
    struct sergensio *rsio = gensio_to_sergensio(netcon->port->io);

    if (!rsio)
	return;
    sergensio_sbreak(rsio, breakv,
		     sergensio_val_set, (void *) (long) S2N_BREAK);
}

static void
s2n_dtr(net_info_t *netcon, int dtr)
{
    struct sergensio *rsio = gensio_to_sergensio(netcon->port->io);

    if (!rsio)
	return;
    sergensio_dtr(rsio, dtr, sergensio_val_set, (void *) (long) S2N_DTR);
}

static void
s2n_rts(net_info_t *netcon, int rts)
{
    struct sergensio *rsio = gensio_to_sergensio(netcon->port->io);

    if (!rsio)
	return;
    sergensio_rts(rsio, rts, sergensio_val_set, (void *) (long) S2N_RTS);
}

static void
s2n_signature(net_info_t *netcon, struct gensio *io, char *sig,
	      unsigned int sig_len)
{
    struct sergensio *sio = gensio_to_sergensio(io);
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
s2n_sync(net_info_t *netcon)
{
    struct sergensio *rsio = gensio_to_sergensio(netcon->port->io);
    port_info_t *port = netcon->port;

    if (!rsio)
	return;
    if (port->telnet_brk_on_sync)
	sergensio_send_break(rsio);
}

static void
s2n_break(net_info_t *netcon)
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
    gensiods len = 0;

    if (buflen)
	len = *buflen;

    switch (event) {
    case GENSIO_EVENT_READ:
	len = handle_net_fd_read(netcon, err, buf, len);
	if (buflen)
	    *buflen = len;
	return 0;

    case GENSIO_EVENT_WRITE_READY:
	handle_net_fd_write_ready(netcon);
	return 0;

    case GENSIO_EVENT_SEND_BREAK:
	s2n_break(netcon);
	return 0;

#ifdef GENSIO_EVENT_SER_MODEMSTATE_MASK
    case GENSIO_EVENT_SER_MODEMSTATE_MASK:
#else
    case GENSIO_EVENT_SER_MODEMSTATE:
#endif
	s2n_modemstate(netcon, net, *((unsigned int *) buf));
	return 0;

#ifdef GENSIO_EVENT_SER_LINESTATE_MASK
    case GENSIO_EVENT_SER_LINESTATE_MASK:
#else
    case GENSIO_EVENT_SER_LINESTATE:
#endif
	s2n_linestate(netcon, net, *((unsigned int *) buf));
	return 0;

    case GENSIO_EVENT_SER_SIGNATURE:
	s2n_signature(netcon, net, (char *) buf, len);
	return 0;

    case GENSIO_EVENT_SER_FLOW_STATE:
	s2n_flowcontrol_state(netcon, *((int *) buf));
	return 0;

    case GENSIO_EVENT_SER_FLUSH:
	s2n_flush(netcon, *((int *) buf));
	return 0;

    case GENSIO_EVENT_SER_SYNC:
	s2n_sync(netcon);
	return 0;

    case GENSIO_EVENT_SER_BAUD:
	s2n_baud(netcon, *((int *) buf));
	return 0;

    case GENSIO_EVENT_SER_DATASIZE:
	s2n_datasize(netcon, *((int *) buf));
	return 0;

    case GENSIO_EVENT_SER_PARITY:
	s2n_parity(netcon, *((int *) buf));
	return 0;

    case GENSIO_EVENT_SER_STOPBITS:
	s2n_stopbits(netcon, *((int *) buf));
	return 0;

    case GENSIO_EVENT_SER_FLOWCONTROL:
	s2n_flowcontrol(netcon, *((int *) buf));
	return 0;

    case GENSIO_EVENT_SER_IFLOWCONTROL:
	s2n_iflowcontrol(netcon, *((int *) buf));
	return 0;

    case GENSIO_EVENT_SER_SBREAK:
	s2n_sbreak(netcon, *((int *) buf));
	return 0;

    case GENSIO_EVENT_SER_DTR:
	s2n_dtr(netcon, *((int *) buf));
	return 0;

    case GENSIO_EVENT_SER_RTS:
	s2n_rts(netcon, *((int *) buf));
	return 0;

#ifdef GENSIO_EVENT_PARMLOG
    case GENSIO_EVENT_PARMLOG: {
	struct gensio_parmlog_data *d = (struct gensio_parmlog_data *) buf;
	seout.vout(&seout, d->log, d->args);
	return 0;
    }
#endif

    default:
	return GE_NOTSUP;
    }
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

    if (port->devstr)
	gbuf_free(port->devstr);
    port->devstr = process_str_to_buf(port, NULL, port->openstr, &seout);
    if (port->devstr)
	port->dev_write_handler = handle_dev_fd_devstr_write;
    else
	port->dev_write_handler = handle_dev_fd_normal_write;

    if (port->devstr)
	gensio_set_write_callback_enable(port->io, true);
    gensio_set_read_callback_enable(port->io, true);

    setup_trace(port, &seout);

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

int
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
	seout.out(&seout, "Could not enable NODELAY on port %s: %s",
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
	seout.out(&seout, "Could not enable NODELAY on socket %s: %s",
		  port->name, gensio_err_to_str(err));

    if (netcon->banner)
	gbuf_free(netcon->banner);
    netcon->banner = process_str_to_buf(port, netcon, port->bannerstr, &seout);

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
