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

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <gensio/gensio.h>
#include <gensio/sergensio.h>
#include "ser2net.h"
#include "dataxfer.h"
#include "port.h"

static int
cntrl_abserrout(struct absout *e, const char *str, ...)
{
    struct controller_info *cntlr = e->data;
    va_list ap;
    char buf[1024];

    va_start(ap, str);
    vsnprintf(buf, sizeof(buf), str, ap);
    va_end(ap);
    return controller_outputf(cntlr, "error", "%s", buf);
}

#define REMOTEADDR_COLUMN_WIDTH						\
    (INET6_ADDRSTRLEN - 1 /* terminating NUL */ + 1 /* comma */ + 5 /* strlen("65535") */)

char *state_str[] = { "closed", "unconnected", "waiting input",
		      "waiting output", "closing" };

char *enabled_str[] = { "off", "on" };

/* Print information about a port to the control port given in cntlr. */
static void
showshortport(struct controller_info *cntlr, port_info_t *port)
{
    char buffer[NI_MAXHOST + NI_MAXSERV + 2];
    int count = 0;
    net_info_t *netcon = NULL;

    controller_outputf(cntlr, NULL, "%-22s ", port->name);
    if (port->deleted)
	controller_outputf(cntlr, NULL, "%-6s ", "DEL");
    else
	controller_outputf(cntlr, NULL, "%-6s ", enabled_str[port->enabled]);
    controller_outputf(cntlr, NULL, "%7d ", port->timeout);

    netcon = first_live_net_con(port);
    if (!netcon)
	netcon = &(port->netcons[0]);

    if (port_in_use(port)) {
	if (net_raddr_str(netcon->net, buffer, sizeof(buffer)) != 0)
	    count = controller_outputf(cntlr, NULL, "%s", buffer);
    } else {
	count = controller_outputf(cntlr, NULL, "unconnected");
    }

    while (count < REMOTEADDR_COLUMN_WIDTH + 1) {
	controller_outs(cntlr, NULL, " ");
	count++;
    }

    controller_outputf(cntlr, NULL, "%-22s ", port->accstr);
    controller_outputf(cntlr, NULL, "%-22s ", port->devname);
    controller_outputf(cntlr, NULL, "%-14s ",
		       state_str[port->net_to_dev_state]);
    controller_outputf(cntlr, NULL, "%-14s ",
		       state_str[port->dev_to_net_state]);
    controller_outputf(cntlr, NULL, "%9lu ",
		       (unsigned long) netcon->bytes_received);
    controller_outputf(cntlr, NULL, "%9lu ",
		       (unsigned long) netcon->bytes_sent);
    controller_outputf(cntlr, NULL, "%9lu ",
		       (unsigned long)port->dev_bytes_received);
    controller_outputf(cntlr, NULL, "%9lu ",
		       (unsigned long) port->dev_bytes_sent);

    if (net_raddr_str(port->io, buffer, sizeof(buffer)) != 0)
	controller_outputf(cntlr, NULL, "%s", buffer);

    controller_outs(cntlr, NULL, "\r\n");
}

/* Print information about a port to the control port given in cntlr. */
static void
showport(struct controller_info *cntlr, port_info_t *port, bool yaml)
{
    char buffer[NI_MAXHOST + NI_MAXSERV + 2], *cfg, *oth = NULL, *tstr;
    net_info_t *netcon;

    if (yaml) {
	controller_outs(cntlr, "port", NULL);
	controller_indent(cntlr, 1);
	controller_outputf(cntlr, "name", "%s", port->name);
    } else {
	controller_outputf(cntlr, "port", "%s", port->name);
	controller_indent(cntlr, 1);
    }
    controller_outputf(cntlr, "accepter", "%s", port->accstr);
    controller_outputf(cntlr, "enable state", "%s", enabled_str[port->enabled]);
    controller_outputf(cntlr, "timeout", "%d", port->timeout);

    for_each_connection(port, netcon) {
	if (netcon->net) {
	    buffer[0] = '\0';
	    net_raddr_str(netcon->net, buffer, sizeof(buffer));
	    if (yaml) {
		controller_outs(cntlr, "connected", NULL);
		controller_indent(cntlr, 1);
		controller_outputf(cntlr, "name", "%s", buffer);
	    } else {
		controller_outputf(cntlr, "connected to", "%s", buffer);
		controller_indent(cntlr, 1);
	    }
	    controller_outputf(cntlr, "bytes read from TCP", "%lu",
			       (unsigned long) netcon->bytes_received);
	    controller_outputf(cntlr, "bytes written to TCP", "%lu",
			       (unsigned long) netcon->bytes_sent);
	    controller_indent(cntlr, -1);
	}
    }

    if (port->orig_devname)
	controller_outputf(cntlr, "device", "%s (%s)", port->devname,
			   port->orig_devname);
    else
	controller_outputf(cntlr, "device", "%s", port->devname);

    if (net_raddr_str(port->io, buffer, sizeof(buffer)) != 0) {
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
	    tstr = oth;
	    while (*tstr) {
		if (*tstr == ' ')
		    *tstr = ',';
		tstr++;
	    }
	} else {
	    oth = "";
	}

	if (cfg[0])
	    controller_outputf(cntlr, "device config", "%s", cfg);
	if (oth[0] && strcmp(oth, "offline") != 0) {
	    if (yaml)
		controller_outputf(cntlr, "device controls", "[ %s ]", oth);
	    else
		controller_outputf(cntlr, "device controls", "%s", oth);
	}
    } else {
	controller_outputf(cntlr, "device config", "?");
	controller_outputf(cntlr, "device controls", "?");
    }

    controller_outputf(cntlr, "tcp to device state", "%s",
		       state_str[port->net_to_dev_state]);

    controller_outputf(cntlr, "device to tcp state", "%s",
		       state_str[port->dev_to_net_state]);

    controller_outputf(cntlr, "bytes read from device", "%lu",
		       (unsigned long) port->dev_bytes_received);

    controller_outputf(cntlr, "bytes written to device", "%lu",
		       (unsigned long) port->dev_bytes_sent);

    if (!yaml) {
	if (port->new_config != NULL) {
	    controller_outputf(cntlr, NULL,
			       "Port will be reconfigured when current"
			       " session closes.\r\n");
	} else if (port->deleted) {
	    controller_outputf(cntlr, NULL, "Port will be deleted when current"
			       " session closes.\r\n");
	}
    } else {
	char *infostr = "retained";
	if (port->new_config != NULL)
	    infostr = "reconfigured";
	else if (port->deleted)
	    infostr = "deleted";
	controller_outputf(cntlr, "close state", "%s", infostr);
    }
    controller_indent(cntlr, -1);
}

/*
 * Find a port data structure given a port name.  Returns with port->lock
 * held, if it returns a non-NULL port.
 */
static port_info_t *
find_port_by_name(const char *name, bool allow_deleted)
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
showports(struct controller_info *cntlr, const char *portspec, bool yaml)
{
    port_info_t *port;

    if (portspec == NULL) {
	so->lock(ports_lock);
	/* Dump everything. */
	port = ports;
	while (port != NULL) {
	    so->lock(port->lock);
	    showport(cntlr, port, yaml);
	    so->unlock(port->lock);
	    port = port->next;
	}
	so->unlock(ports_lock);
    } else {
	port = find_port_by_name(portspec, true);
	if (port == NULL) {
	    controller_outputf(cntlr, "error", "Invalid port number - %s",
			       portspec);
	} else {
	    showport(cntlr, port, yaml);
	    so->unlock(port->lock);
	}
    }
}

/* Handle a showport command from the control port. */
void
showshortports(struct controller_info *cntlr, const char *portspec)
{
    port_info_t *port;

    controller_outputf(cntlr, NULL,
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
	    controller_outputf(cntlr, "error", "Invalid port number: %s",
			       portspec);
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
setporttimeout(struct controller_info *cntlr, const char *portspec,
	       const char *timeout)
{
    port_info_t *port;
    net_info_t *netcon;

    port = find_port_by_name(portspec, true);
    if (port == NULL) {
	controller_outputf(cntlr, "error", "Invalid port number - %s", portspec);
    } else {
	int timeout_num = scan_int(timeout);

	if (timeout_num == -1) {
	    controller_outputf(cntlr, "error", "Invalid timeout - %s", timeout);
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
setportcontrol(struct controller_info *cntlr, const char *portspec,
	       char * const controls[])
{
    port_info_t *port;
    unsigned int i;

    port = find_port_by_name(portspec, false);
    if (port == NULL) {
	controller_outputf(cntlr, "error", "Invalid port number - %s",
			   portspec);
	goto out;
    } else if (!port_in_use(port)) {
	controller_outputf(cntlr, "error",
			   "Port is not currently connected - %s", portspec);
    } else {
	struct sergensio *sio = gensio_to_sergensio(port->io);

	if (!sio)
	    goto out_unlock;

	for (i = 0; controls[i]; i++) {
	    if (strcmp(controls[i], "RTSHI") == 0)
		sergensio_rts(sio, SERGENSIO_RTS_ON, NULL, NULL);
	    else if (strcmp(controls[i], "RTSLO") == 0)
		sergensio_rts(sio, SERGENSIO_RTS_OFF, NULL, NULL);
	    else if (strcmp(controls[i], "DTRHI") == 0)
		sergensio_dtr(sio, SERGENSIO_DTR_ON, NULL, NULL);
	    else if (strcmp(controls[i], "DTRLO") == 0)
		sergensio_dtr(sio, SERGENSIO_DTR_OFF, NULL, NULL);
	    else
		controller_outputf(cntlr, "error",
				   "Invalid device control - %s", controls[i]);
	}
    }
 out_unlock:
    so->unlock(port->lock);
 out:
    return;
}

static void
port_op_finished(struct port_info *port, void *data)
{
    struct gensio_waiter *waiter = data;

    so->wake(waiter);
}

/* Set the enable state of a port. */
void
setportenable(struct controller_info *cntlr, const char *portspec,
	      const char *enable)
{
    port_info_t *port;
    bool new_enable;
    struct absout eout = { .out = cntrl_abserrout, .data = cntlr };
    int rv;
    struct gensio_waiter *waiter = NULL;

    port = find_port_by_name(portspec, false);
    if (port == NULL) {
	controller_outputf(cntlr, "error", "Invalid port - %s", portspec);
	return;
    }

    if (strcmp(enable, "off") == 0) {
	new_enable = false;
    } else if (strcmp(enable, "on") == 0) {
	new_enable = true;
    } else if (strcmp(enable, "raw") == 0) {
	new_enable = true;
    } else {
	controller_outputf(cntlr, "error", "Invalid enable - %s", enable);
	goto out_unlock;
    }


    if (port->enabled == new_enable) {
	controller_outputf(cntlr, "error",
			   "port was already in the given state");
	goto out_unlock;
    }

    port->enabled = new_enable;
    if (!new_enable) {
	waiter = so->alloc_waiter(so);
	if (!waiter) {
	    controller_outputf(cntlr, "error", "Out of memory");
	    rv = ENOMEM;
	} else {
	    port->port_op_done = port_op_finished;
	    port->port_op_data = waiter;
	    rv = shutdown_port(port, "admin disable");
	    if (rv) {
		controller_outputf(cntlr, "error", "disabling port: %s",
				   gensio_err_to_str(rv));
		so->free_waiter(waiter);
		waiter = NULL;
	    }
	}
    } else {
	rv = startup_port(&eout, port);
    }
    if (rv)
	port->enabled = !new_enable;

 out_unlock:
    so->unlock(port->lock);

    if (waiter) {
	so->wait(waiter, 1, NULL);
	so->free_waiter(waiter);
    }
}

/* Start data monitoring on the given port, type may be either "tcp" or
   "term" and only one direction may be monitored.  This return NULL if
   the monitor fails.  The monitor output will go to "fd". */
void *
data_monitor_start(struct controller_info *cntlr, const char *type,
		   const char *portspec)
{
    port_info_t *port;

    port = find_port_by_name(portspec, true);
    if (port == NULL) {
	controller_outputf(cntlr, "error", "Invalid port number - %s",
			   portspec);
	goto out;
    }

    if ((port->net_monitor != NULL) || (port->dev_monitor != NULL)) {
	controller_outputf(cntlr, "error", "Port is already being monitored");
	goto out_unlock;
    }

    if (strcmp(type, "tcp") == 0) {
	port->net_monitor = cntlr;
    } else if (strcmp(type, "term") == 0) {
	port->dev_monitor = cntlr;
    } else {
	controller_outs(cntlr, "invalid monitor type - %s", type);
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
disconnect_port(struct controller_info *cntlr, const char *portspec)
{
    port_info_t *port;

    port = find_port_by_name(portspec, true);
    if (port == NULL) {
	controller_outputf(cntlr, "error", "Invalid port number - %s",
			   portspec);
	goto out;
    } else if (!port_in_use(port)) {
	controller_outputf(cntlr, "error", "Port not connected - %s",
			   portspec);
	goto out_unlock;
    }

    shutdown_port(port, "admin disconnect");
 out_unlock:
    so->unlock(port->lock);
 out:
    return;
}
