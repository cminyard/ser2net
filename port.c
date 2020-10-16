/*
 *  ser2net - A program for allowing telnet connection to serial ports
 *  Copyright (C) 2020  Corey Minyard <minyard@acm.org>
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <syslog.h>
#include <assert.h>
#include "ser2net.h"
#include "port.h"
#include "gbuf.h"
#include <gensio/gensio_mdns.h>
#include <gensio/argvutils.h>
#include <gensio/gensio_err.h>
#include <gensio/sergensio.h>

struct gensio_lock *ports_lock;
port_info_t *ports = NULL; /* Linked list of ports. */
port_info_t *new_ports = NULL; /* New ports during config/reconfig. */
port_info_t *new_ports_end = NULL;

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

int
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

void
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

#ifdef DO_MDNS
static struct gensio_mdns *mdns;

static char *
derive_mdns_type(port_info_t *port)
{
    /* Get a mdns type based on the gensio. */
    unsigned int i;
    const char *type, *ntype = "_iostream._tcp";

    type = gensio_acc_get_type(port->accepter, 0);
    for (i = 1; type; i++) {
	if (strcmp(type, "tcp") == 0)
	    break;
	if (strcmp(type, "udp") == 0) {
	    ntype = "_iostream._udp";
	    break;
	}
	type = gensio_acc_get_type(port->accepter, i);
    }
    return strdup(ntype);
}

static void
mdns_addprovider(struct absout *eout, port_info_t *port)
{
    gensiods i;
    static char *provstr = "provider=";
    char *tmps = NULL;

    for (i = 0; i < port->mdns_txt_argc; i++) {
	if (strncmp(port->mdns_txt[i], provstr, strlen(provstr)) == 0)
	    /* User already specified it, don't override. */
	    return;
    }

    tmps = gensio_alloc_sprintf(so, "%s%s", provstr, "ser2net");
    if (!tmps)
	goto out_nomem;

    if (gensio_argv_append(so, &port->mdns_txt, tmps,
			   &port->mdns_txt_args, &port->mdns_txt_argc,
			   false))
	goto out_nomem;
    return;

 out_nomem:
    eout->out(eout, "Error allocation mdns provider for %s: out of memory",
	      port->name);
    if (tmps)
	so->free(so, tmps);
}

static void
mdns_addstack(struct absout *eout, port_info_t *port)
{
    gensiods i;
    static char *stackstr = "gensiostack=";
    const char *type;
    char *stack = NULL, *tmps = NULL;

    for (i = 0; i < port->mdns_txt_argc; i++) {
	if (strncmp(port->mdns_txt[i], stackstr, strlen(stackstr)) == 0)
	    /* User already specified it, don't override. */
	    return;
    }

    for (i = 0; ; i++) {
	type = gensio_acc_get_type(port->accepter, i);
	if (!type)
	    break;

	if (strcmp(type, "telnet") == 0) {
	    struct gensio_accepter *telnet_acc =
		gensio_acc_get_child(port->accepter, i);
	    const char *rfc2217 = "";

	    if (gensio_acc_to_sergensio_acc(telnet_acc))
		rfc2217 = "(rfc2217)";

	    tmps = gensio_alloc_sprintf(so, "%s%s%s%s",
					stack ? stack : "", stack ? "," : "",
					type, rfc2217);
	} else {
	    tmps = gensio_alloc_sprintf(so, "%s%s%s",
					stack ? stack : "", stack ? "," : "",
					type);
	}
	if (!tmps)
	    goto out_nomem;
	if (stack)
	    so->free(so, stack);
	stack = tmps;
    }

    if (!stack)
	return;

    tmps = gensio_alloc_sprintf(so, "%s%s", stackstr, stack);
    if (!tmps)
	goto out_nomem;
    stack = tmps;

    if (gensio_argv_append(so, &port->mdns_txt, stack,
			   &port->mdns_txt_args, &port->mdns_txt_argc,
			   false))
	goto out_nomem;
    return;

 out_nomem:
    eout->out(eout, "Error allocation mdns stack for %s: out of memory",
	      port->name);
    if (stack)
	so->free(so, stack);
}

static void
mdns_setup(struct absout *eout, port_info_t *port)
{
    int err;
    char portnum_str[20];
    gensiods portnum_len = sizeof(portnum_str);

    if (!mdns || !port->mdns)
	return;

    if (!port->mdns_port) {
	strcpy(portnum_str, "0");
	err = gensio_acc_control(port->accepter, GENSIO_CONTROL_DEPTH_FIRST,
				 true, GENSIO_ACC_CONTROL_LPORT, portnum_str,
				 &portnum_len);
	if (err) {
	    eout->out(eout, "Can't get mdns port for device %s: %s",
		      port->name, gensio_err_to_str(err));
	    return;
	}
	port->mdns_port = strtoul(portnum_str, NULL, 0);
    }

    if (!port->mdns_type) {
	port->mdns_type = derive_mdns_type(port);
	if (!port->mdns_type) {
	    eout->out(eout, "Can't alloc mdns type for %s: out of memory",
		      port->name);
	    return;
	}
    }

    if (!port->mdns_name) {
	port->mdns_name = strdup(port->name);
	if (!port->mdns_name) {
	    eout->out(eout, "Can't alloc mdns name for %s: out of memory",
		      port->name);
	    return;
	}
    }

    mdns_addprovider(eout, port);
    mdns_addstack(eout, port);

    /*
     * Always stick on the NULL, that doesn't update argc so it's safe,
     * a new txt will just write over the NULL we added.
     */
    err = gensio_argv_append(so, &port->mdns_txt, NULL,
			     &port->mdns_txt_args, &port->mdns_txt_argc, true);
    if (err) {
	eout->out(eout, "Error terminating mdns-txt for %s: %s",
		  port->name, gensio_err_to_str(err));
	return;
    }

    err = gensio_mdns_add_service(mdns, port->mdns_interface,
				  port->mdns_nettype,
				  port->mdns_name, port->mdns_type,
				  port->mdns_domain, port->mdns_host,
				  port->mdns_port, port->mdns_txt,
				  &port->mdns_service);
    if (err)
	eout->out(eout, "Can't add mdns service for device %s: %s",
		  port->name, gensio_err_to_str(err));
}

static void
mdns_shutdown(port_info_t *port)
{
    if (port->mdns_service)
	gensio_mdns_remove_service(port->mdns_service);
    port->mdns_service = NULL;
}

#else

static void
mdns_setup(struct absout *eout, port_info_t *port)
{
}

static void
mdns_shutdown(port_info_t *port)
{
}
#endif /* DO_MDNS */

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

    mdns_setup(eout, port);

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
	gbuf_free(port->devstr);
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
	mdns_shutdown(port);
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

    shutdown_trace(port);

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

    if (port->devstr)
	gbuf_free(port->devstr);
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
	gbuf_free(netcon->banner);
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

void
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

    new_port->send_timer = so->alloc_timer(so, port_send_timeout, new_port);
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

#ifdef DO_MDNS
    rv = gensio_alloc_mdns(so, &mdns);
    if (rv)
	/* Not fatal */
	fprintf(stderr, "Unable to start mdns: %s\n", gensio_err_to_str(rv));
#endif /* DO_MDNS */

    rv = init_rotators();

 out:
    if (rv)
	shutdown_dataxfer();
    return rv;
}
