/*
 *  ser2net - A program for allowing telnet connection to serial ports
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
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

/* This code handles UDP network I/O. */

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <errno.h>

#include "netio.h"
#include "selector.h"
#include "ser2net.h"
#include "locking.h"
#include "utils.h"

struct udpna_data;

struct udpn_data {
    struct udpna_data *na;

    struct sockaddr_storage remote;	/* The socket address of who
					   is connected to this port. */
    struct sockaddr *raddr;		/* Points to remote, for convenience. */
    socklen_t raddrlen;

    /* For a new UDP connection, temporarily hold the received data here. */
    unsigned char *new_buf;
    int new_buf_len;

    struct udpn_data *next;
};

struct port_remaddr
{
    char *name;
    struct sockaddr_storage addr;
    socklen_t addrlen;
    bool is_port_set;
    struct port_remaddr *next;
};

struct udpna_data {
    DEFINE_LOCK(, lock);

    int            fd;			/* When connected, the file
                                           descriptor for the network
                                           port used for I/O. */
    struct addrinfo    *ai;		/* The address list for the portname. */
    struct opensocks   *acceptfds;	/* The file descriptor used to
					   accept connections on the
					   TCP port. */
    unsigned int   nr_acceptfds;
    waiter_t       *accept_waiter;      /* Wait for accept changes. */

    struct port_remaddr *remaddrs;

    struct udpn_data *udpns;
};

static int
udpn_startup(struct netio *net)
{
    return 0;
}

static int
udpn_write(struct netio *net, int *count,
	   const void *buf, unsigned int buflen)
{
    return 0;
}

static int
udpn_raddr_to_str(struct netio *net, int *pos,
		  char *buf, unsigned int buflen)
{
    return 0;
}

static void
udpn_close(struct netio *net)
{
}

static void
udpn_set_read_callback_enable(struct netio *net, bool enabled)
{
}

static void
udpn_set_write_callback_enable(struct netio *net, bool enabled)
{
}


static int
udpna_add_remaddr(struct netio_acceptor *acceptor, const char *str)
{
    return 0;
}

static int
udpna_startup(struct netio_acceptor *acceptor)
{
    return 0;
}

static int
udpna_shutdown(struct netio_acceptor *acceptor)
{
    return 0;
}

static void
udpna_set_accept_callback_enable(struct netio_acceptor *net, bool enabled)
{
}

static void
udpna_free(struct netio_acceptor *acceptor)
{
}

int
udp_netio_acceptor_alloc(const char *name,
			 struct addrinfo *ai,
			 unsigned int max_read_size,
			 struct netio_acceptor **acceptor)
{
    int err = 0;
    struct netio_acceptor *acc = NULL;
    struct udpna_data *ndata = NULL;

    acc = malloc(sizeof(*acc));
    if (!acc) {
	err = ENOMEM;
	goto out;
    }
    memset(acc, 0, sizeof(*acc));

    ndata = malloc(sizeof(*ndata));
    if (!ndata) {
	err = ENOMEM;
	goto out;
    }
    memset(ndata, 0, sizeof(*ndata));

    ndata->accept_waiter = alloc_waiter();
    if (!ndata->accept_waiter) {
	err = ENOMEM;
	goto out;
    }

    acc->internal_data = ndata;
    acc->add_remaddr = udpna_add_remaddr;
    acc->startup = udpna_startup;
    acc->shutdown = udpna_shutdown;
    acc->set_accept_callback_enable = udpna_set_accept_callback_enable;
    acc->free = udpna_free;

    INIT_LOCK(ndata->lock);
    ndata->ai = ai;

 out:
    if (err) {
	if (acc)
	    free(acc);
	if (ndata)
	    free(ndata);
    } else {
	*acceptor = acc;
    }
    return err;
}

#if 0
int options;
    if (fcntl(netcon->fd, F_SETFL, O_NONBLOCK) == -1) {
	close(netcon->fd);
	netcon->fd = -1;
	syslog(LOG_ERR, "Could not fcntl the tcp port %s: %m", port->portname);
	return -1;
    }

    if (!port->dgram) {
	options = 1;
	if (setsockopt(netcon->fd, IPPROTO_TCP, TCP_NODELAY,
		       (char *) &options, sizeof(options)) == -1) {
	    if (port->is_stdio)
		/* Ignore this error on stdio ports. */
		goto end_net_config;

	    close(netcon->fd);
	    netcon->fd = -1;
	    syslog(LOG_ERR, "Could not enable TCP_NODELAY tcp port %s: %m",
		   port->portname);
	    return -1;
	}

    }
 end_net_config:

    sel_set_fd_handlers(ser2net_sel,
			netcon->fd,
			netcon,
			handle_net_fd_read,
			handle_net_fd_write_mux,
			handle_net_fd_except,
			port_net_fd_cleared);
    

accept() {
      /* FIXME - handle remote address interactions? */
    new_fd = accept(fd, (struct sockaddr *) &addr, &addrlen);
    if (new_fd == -1) {
	if (errno != EAGAIN && errno != EWOULDBLOCK)
	    syslog(LOG_ERR, "Could not accept on rotator %s: %m",
		   rot->portname);
	return;
    }

    err = check_tcpd_ok(new_fd);
    if (err)
	goto out_err;

    optval = 1;
    if (setsockopt(netcon->fd, SOL_SOCKET, SO_KEEPALIVE,
		   (void *)&optval, sizeof(optval)) == -1) {
	close(netcon->fd);
	syslog(LOG_ERR, "Could not enable SO_KEEPALIVE on tcp port %s: %m",
	       port->portname);
	netcon->fd = -1;
	return;
    }

    memcpy(port->netcons[i].raddr, &addr, addrlen);
    port->netcons[i].raddrlen = addrlen;
    if (port->dgram)
	port->netcons[i].udpraddrlen = addrlen;

 }

static bool
port_remaddr_ok(port_info_t *port, struct netio *net)
{
    struct port_remaddr *r = port->remaddrs;

    if (!r)
	return true;

    while (r) {
	if (sockaddr_equal(addr, addrlen,
			   (struct sockaddr *) &r->addr, r->addrlen,
			   r->is_port_set))
	    break;
	r = r->next;
    }

    return r != NULL;
}

struct port_remaddr
{
    char *name;
    struct sockaddr_storage addr;
    socklen_t addrlen;
    bool is_port_set;
    struct port_remaddr *next;
};

static const char *
check_tcpd_ok(int new_fd)
{
#ifdef HAVE_TCPD_H
    struct request_info req;

    request_init(&req, RQ_DAEMON, progname, RQ_FILE, new_fd, NULL);
    fromhost(&req);

    if (!hosts_access(&req))
	return "Access denied\r\n";
#endif

    return NULL;
}


static int
tcp_port_read(int fd, port_info_t *port, int *readerr, net_info_t **rnetcon)
{
    int rv;

    rv = read(fd, port->net_to_dev.buf, port->net_to_dev.maxsize);
    if (rv < 0)
	*readerr = errno;
    return rv;
}

static int
udp_port_read(int fd, port_info_t *port, int *readerr, net_info_t **rnetcon)
{
    struct sockaddr_storage remaddr;
    socklen_t remaddrlen;
    int i, rv;
    net_info_t *netcon;
    char *err = NULL;

    remaddrlen = sizeof(remaddr);
    rv = recvfrom(fd, port->net_to_dev.buf, port->net_to_dev.maxsize, 0,
		  (struct sockaddr *) &remaddr, &remaddrlen);
    if (rv < 0) {
	*readerr = errno;
	return rv;
    }

    for (i = 0; i < port->max_connections; i++) {
	if (port->netcons[i].fd == -1)
	    continue;
	if (!sockaddr_equal((struct sockaddr *) &remaddr, remaddrlen,
			    port->netcons[i].raddr, port->netcons[i].raddrlen,
			    true))
	    continue;

	/* We found a matching port. */
	*rnetcon = &(port->netcons[i]);
	goto out;
    }

    /* No matching port, try a new connection. */
    if (port->remaddrs) {
	struct port_remaddr *r = port->remaddrs;

	while (r) {
	    if (sockaddr_equal((struct sockaddr *) &remaddr, remaddrlen,
			       (struct sockaddr *) &r->addr, r->addrlen,
			       r->is_port_set))
		break;
	    r = r->next;
	}
	if (!r) {
	    err = "Access denied\r\n";
	    goto out_err;
	}
    }

    if (i == port->max_connections) {
	for (i = 0; i < port->max_connections; i++) {
	    if (port->netcons[i].fd == -1)
		break;
	}
    }

    if (i == port->max_connections && port->kickolduser_mode) {
	for (i = 0; i < port->max_connections; i++) {
	    if (!port->netcons[i].remote_fixed)
		break;
	}
    }

    if (i == port->max_connections)
	err = "Port already in use\r\n";

    if (!err && is_device_already_inuse(port))
	err = "Port's device already in use\r\n";

    if (!err) {
	int new_fd = dup(fd);

	if (new_fd == -1)
	    err = "Unable to dup port fd\r\n";
	netcon = &(port->netcons[i]);
	if (netcon->fd == -1) {
	    netcon->fd = new_fd;
	} else {
	    kick_old_user(port, netcon, new_fd, rv, &remaddr, remaddrlen);
	    goto out_ignore;
	}
    }

    if (err) {
    out_err:
	net_write(fd, err, strlen(err), 0,
		  (struct sockaddr *) &remaddr, remaddrlen);
	goto out_ignore;
    }

    memcpy(netcon->raddr, &remaddr, remaddrlen);
    netcon->raddrlen = remaddrlen;
    if (port->dgram)
	netcon->udpraddrlen = remaddrlen;

    if (setup_port(port, netcon, false))
	goto out_ignore;

    *rnetcon = netcon;

 out:
    if (rv == 0)
	/* zero-length packet. */
	goto out_ignore;

    return rv;

 out_ignore:
    *readerr = EAGAIN;
    return -1;
}

static void
process_remaddr(struct absout *eout, port_info_t *port, struct port_remaddr *r,
		bool is_reconfig)
{
    net_info_t *netcon;

    if (!r->is_port_set || !port->dgram)
	return;

    for_each_connection(port, netcon) {
	int i = 0;

	if (netcon->remote_fixed)
	    continue;

	/* Search for a UDP port that matches the remote address family. */
	for (i = 0; i < port->nr_acceptfds; i++) {
	    if (port->acceptfds[i].family == r->addr.ss_family)
		break;
	}
	if (i == port->nr_acceptfds) {
	    eout->out(eout, "remote address '%s' had no socket with"
		      " a matching family", r->name);
	    return;
	}

	netcon->remote_fixed = true;
	memcpy(netcon->raddr, &r->addr, r->addrlen);
	netcon->raddrlen = r->addrlen;
	if (port->dgram)
	    netcon->udpraddrlen = r->addrlen;

	netcon->fd = dup(port->acceptfds[i].fd);
	if (netcon->fd == -1) {
	    eout->out(eout,
		      "Unable to duplicate fd for remote address '%s'",
		      r->name);
	    return;
	}

	if (setup_port(port, netcon, is_reconfig)) {
	    netcon->remote_fixed = false;
	    close(netcon->fd);
	    netcon->fd = -1;
	    eout->out(eout, "Unable to set up port for remote address '%s'",
		      r->name);
	}

	return;
    }

    eout->out(eout, "Too many fixed UDP remote addresses specified for the"
	      " max-connections given");
}

/* Start monitoring for connections on a specific port. */
static int
startup_port(struct absout *eout, port_info_t *port, bool is_reconfig)
{
    void (*readhandler)(int, void *) = handle_accept_port_read;
    struct port_remaddr *r;

    port->acceptfds = open_socket(port->ai, readhandler, NULL, port,
				  &port->nr_acceptfds, port_accept_fd_cleared);
    if (port->acceptfds == NULL) {
	if (eout)
	    eout->out(eout, "Unable to create network socket(s)");
	else
	    syslog(LOG_ERR, "Unable to create network socket for port %s: %s",
		   port->portname, strerror(errno));

	return -1;
    }

    for (r = port->remaddrs; r; r = r->next)
	process_remaddr(eout, port, r, is_reconfig);

    return 0;
}

    while (port->remaddrs) {
	struct port_remaddr *r = port->remaddrs;

	port->remaddrs = r->next;
	free(r->name);
	free(r);
    }

    if (port->accept_waiter)
	free_waiter(port->accept_waiter);
    if (port->acceptfds)
	free(port->acceptfds);

}

static void
port_add_one_remaddr(struct absout *eout, port_info_t *port, char *str)
{
    struct port_remaddr *r, *r2;
    struct addrinfo *ai = NULL;
    bool is_dgram, is_port_set;
    int rv;

    rv = scan_network_port(str, &ai, &is_dgram, &is_port_set);
    if (rv) {
	eout->out(eout, "Invalid remote address '%s'", str);
	goto out;
    }

    if (port->dgram != is_dgram) {
	eout->out(eout, "Remote address '%s' does not match the port"
		  " type, one cannot be UDP while the other is UDP.", str);
	goto out;
    }

    r = malloc(sizeof(*r));
    if (!r) {
	eout->out(eout, "Out of memory allocation remote address");
	goto out;
    }

    r->name = strdup(str);
    if (!r->name) {
	eout->out(eout, "Out of memory allocation remote address string");
	free(r);
	goto out;
    }

    memcpy(&r->addr, ai->ai_addr, ai->ai_addrlen);
    r->addrlen = ai->ai_addrlen;
    r->is_port_set = is_port_set;
    r->next = NULL;

    r2 = port->remaddrs;
    if (!r2) {
	port->remaddrs = r;
    } else {
	while (r2->next)
	    r2 = r2->next;
	r2->next = r;
    }

 out:
    if (ai)
	freeaddrinfo(ai);
}



raddr_to_str()
{
	err = getnameinfo(netcon->raddr, netcon->raddrlen,
		      buf + len, sizeof(buf) - len,
		      portstr, sizeof(portstr), NI_NUMERICHOST);
	if (err) {
		    "unknown:%s\n", gai_strerror(err));
	} else {
	len += strlen(buf + len);
	if ((sizeof(buf) - len) > 2) {
	    buf[len] = ':';
	    len++;
	}
	strncpy(buf + len, portstr, sizeof(buf) - len);
	len += strlen(buf + len);
 }
}
#endif
