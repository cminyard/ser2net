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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <assert.h>

#include "netio.h"
#include "selector.h"
#include "ser2net.h"
#include "locking.h"
#include "utils.h"

struct udpna_data;

#define MAX_NUM_UNREPORTED 10

struct udpn_data {
    struct netio *net;
    struct udpna_data *nadata;

    /*
     * When in a read callback or when there is pending data, we
     * cannot directly set the read settings for a net because the
     * read callback must remain disabled.  So save the current state.
     */
    bool user_set_read_enabled;
    bool user_read_enabled_setting;

    int myfd; /* fd the original request came in on, for sending. */

    bool reported;	/* This net has been reported as a new connection. */
    bool read_enabled;	/* Read callbacks are enabled. */
    bool write_enabled;	/* Write callbacks are enabled. */
    bool in_read;	/* Currently in a read callback. */
    bool in_write;	/* Currently in a write callback. */

    bool closed;	/* Has this net been closed? */

    struct sockaddr_storage remote;	/* The socket address of who
					   is connected to this port. */
    struct sockaddr *raddr;		/* Points to remote, for convenience. */
    socklen_t raddrlen;

    struct udpn_data *next;
};

struct port_remaddr
{
    struct sockaddr_storage addr;
    socklen_t addrlen;
    bool is_port_set;
    struct port_remaddr *next;
};

struct udpna_data {
    struct netio_acceptor *acceptor;
    struct udpn_data *udpns;

    DEFINE_LOCK(, lock);

    char *name;

    unsigned int max_read_size;

    unsigned char *read_data;

    bool data_pending;
    unsigned int data_pending_len;
    unsigned int data_pos;
    struct udpn_data *pending_data_owner;
    struct udpn_data *pending_data_ndata;

    struct udpn_data *pending_close_ndata; /* Linked list. */

    unsigned int num_unreported;

    /*
     * Used to run read callbacks from the selector to avoid running
     * it directly from user calls.
     */
    bool deferred_op_pending;
    sel_runner_t *deferred_op_runner;

    bool in_new_connection;

    bool setup;
    bool enabled;
    bool closed;

    struct addrinfo    *ai;		/* The address list for the portname. */
    struct opensocks   *fds;		/* The file descriptor used for
					   the UDP ports. */
    unsigned int   nr_fds;
    waiter_t       *accept_waiter;      /* Wait for accept changes. */

    unsigned int read_disable_count;
    unsigned int write_disable_count;

    struct port_remaddr *remaddrs;
};

static void udpna_deferred_op(sel_runner_t *runner, void *cbdata);

static void
udpna_fd_read_enable(struct udpna_data *nadata) {
    unsigned int i;

    assert(nadata->read_disable_count > 0);
    nadata->read_disable_count--;
    if (nadata->read_disable_count == 0) {
	for (i = 0; i < nadata->nr_fds; i++)
	    sel_set_fd_read_handler(ser2net_sel, nadata->fds[i].fd,
				    SEL_FD_HANDLER_ENABLED);
    }
}

static void
udpna_fd_read_disable(struct udpna_data *nadata) {
    unsigned int i;

    if (nadata->read_disable_count == 0) {
	for (i = 0; i < nadata->nr_fds; i++)
	    sel_set_fd_read_handler(ser2net_sel, nadata->fds[i].fd,
				    SEL_FD_HANDLER_DISABLED);
    }
    nadata->read_disable_count++;
}

static void
udpna_disable_write(struct udpna_data *nadata)
{
    unsigned int i;

    for (i = 0; i < nadata->nr_fds; i++)
	sel_set_fd_write_handler(ser2net_sel, nadata->fds[i].fd,
				 SEL_FD_HANDLER_DISABLED);
}

static void
udpna_fd_write_disable(struct udpna_data *nadata) {
    if (nadata->write_disable_count == 0)
	udpna_disable_write(nadata);
    nadata->write_disable_count++;
}

static void
udpna_fd_write_enable(struct udpna_data *nadata) {
    unsigned int i;

    assert(nadata->write_disable_count > 0);
    nadata->write_disable_count--;
    if (nadata->write_disable_count == 0 && nadata->udpns) {
	for (i = 0; i < nadata->nr_fds; i++)
	    sel_set_fd_write_handler(ser2net_sel, nadata->fds[i].fd,
				     SEL_FD_HANDLER_ENABLED);
    }
}

static void udpna_do_free(struct udpna_data *nadata)
{
    unsigned int i;

    UNLOCK(nadata->lock);

    for (i = 0; i < nadata->nr_fds; i++) {
	sel_clear_fd_handlers(ser2net_sel, nadata->fds[i].fd);
	wait_for_waiter(nadata->accept_waiter);
	close(nadata->fds[i].fd);
    }

    while (nadata->remaddrs) {
	struct port_remaddr *r;

	r = nadata->remaddrs;
	nadata->remaddrs = r->next;
	free(r);
    }

    if (nadata->deferred_op_runner)
	sel_free_runner(nadata->deferred_op_runner);
    if (nadata->accept_waiter)
	free_waiter(nadata->accept_waiter);
    if (nadata->name)
	free(nadata->name);
    if (nadata->ai)
	freeaddrinfo(nadata->ai);
    if (nadata->fds)
	free(nadata->fds);
    if (nadata->read_data)
	free(nadata->read_data);
    if (nadata->acceptor)
	free(nadata->acceptor);
    free(nadata);
}

static void udpna_check_finish_free(struct udpna_data *nadata)
{
    if (!nadata->closed || nadata->in_new_connection || nadata->udpns ||
		nadata->pending_close_ndata)
	return;

    if (!nadata->deferred_op_pending) {
	/* Call the read from the selector to avoid lock nesting issues. */
	nadata->deferred_op_pending = true;
	sel_run(nadata->deferred_op_runner, udpna_deferred_op, nadata);
    }
}

static int
udpn_write(struct netio *net, int *count,
	   const void *buf, unsigned int buflen)
{
    struct udpn_data *ndata = net->internal_data;
    int rv, err = 0;

 retry:
    rv = sendto(ndata->myfd, buf, buflen, 0, ndata->raddr, ndata->raddrlen);
    if (rv < 0) {
	if (errno == EINTR)
	    goto retry;
	if (errno == EWOULDBLOCK || errno == EAGAIN)
	    rv = 0; /* Handle like a zero-byte write. */
	else
	    err = errno;
    } else if (rv == 0) {
	err = EPIPE;
    }

    if (!err && count)
	*count = rv;

    return err;
}

static int
udpn_raddr_to_str(struct netio *net, int *epos,
		  char *buf, unsigned int buflen)
{
    struct udpn_data *ndata = net->internal_data;
    char portstr[NI_MAXSERV];
    int err, pos = 0;

    if (epos)
	pos = *epos;

    err = getnameinfo(ndata->raddr, ndata->raddrlen,
		      buf + pos, buflen - pos,
		      portstr, sizeof(portstr), NI_NUMERICHOST);
    if (err) {
	snprintf(buf + pos, buflen - pos,
		 "unknown:%s\n", gai_strerror(err));
	return EINVAL;
    }

    pos += strlen(buf + pos);
    if (buflen - pos > 2) {
	buf[pos] = ':';
	pos++;
    }
    strncpy(buf + pos, portstr, buflen - pos);
    pos += strlen(buf + pos);

    if (epos)
	*epos = pos;

    return 0;
}

static void
udpn_finish_close(struct udpna_data *nadata, struct udpn_data *ndata)
{
    struct netio *net = ndata->net;

    if (net->close_done) {
	UNLOCK(nadata->lock);
	net->close_done(net);
	LOCK(nadata->lock);
    }

    if (nadata->data_pending && nadata->pending_data_owner == ndata)
	nadata->data_pending = false;
    
    udpna_check_finish_free(nadata);
    UNLOCK(nadata->lock);

    free(ndata);
    free(net);
}

static void
udpn_add_to_closed(struct udpna_data *nadata, struct udpn_data *ndata)
{
    struct udpn_data *tndata;

    if (!ndata->read_enabled)
	udpna_fd_read_enable(nadata);
    if (!ndata->write_enabled)
	udpna_fd_write_enable(nadata);

    /* Remove it from the main list. */
    if (nadata->udpns == ndata) {
	nadata->udpns = nadata->udpns->next;
    } else {
	struct udpn_data *tndata = nadata->udpns;

	while (tndata->next != ndata)
	    tndata = tndata->next;
	tndata->next = tndata->next->next;
    }

    /* Add to the close list. */
    ndata->next = NULL;
    tndata = nadata->pending_close_ndata;
    if (!tndata)
	nadata->pending_close_ndata = ndata;
    else {
	while (tndata->next)
	    tndata = tndata->next;
	tndata->next = ndata;
    }

    if (!nadata->deferred_op_pending) {
	nadata->deferred_op_pending = true;
	sel_run(nadata->deferred_op_runner, udpna_deferred_op, nadata);
    }
}

static void
udpn_finish_read(struct udpn_data *ndata, unsigned int count)
{
    struct udpna_data *nadata = ndata->nadata;

    ndata->in_read = false;

    if (ndata->closed)
	udpn_add_to_closed(nadata, ndata);

    nadata->data_pending = false;
    nadata->pending_data_owner = NULL;

    if (count < nadata->data_pending_len) {
	/* If the user doesn't consume all the data, disable
	   automatically. */
	nadata->data_pending = true;
	nadata->data_pending_len -= count;
	nadata->data_pos += count;
	ndata->user_set_read_enabled = true;
	ndata->user_read_enabled_setting = false;
    }

    if (ndata->user_set_read_enabled)
	ndata->read_enabled = ndata->user_read_enabled_setting;
    else
	ndata->read_enabled = true;

    if (ndata->read_enabled)
	udpna_fd_read_enable(nadata);
}

static void
udpna_deferred_op(sel_runner_t *runner, void *cbdata)
{
    struct udpna_data *nadata = cbdata;
    struct udpn_data *ndata;
    unsigned int count;

    LOCK(nadata->lock);
 retry:
    ndata = nadata->pending_data_ndata;
    nadata->pending_data_ndata = NULL;
    UNLOCK(nadata->lock);

    if (ndata) {
	struct netio *net = ndata->net;

	count = net->read_callback(net, 0, nadata->read_data + nadata->data_pos,
				   nadata->data_pending_len);
    }

    LOCK(nadata->lock);
    if (ndata)
	udpn_finish_read(ndata, count);

    while (nadata->pending_close_ndata) {
	ndata = nadata->pending_close_ndata;
	nadata->pending_close_ndata = ndata->next;
	udpn_finish_close(nadata, ndata);
    }

    if (nadata->pending_data_ndata)
	goto retry;

    if (nadata->closed) {
	udpna_do_free(nadata); /* Releases the lock */
    } else {
	nadata->deferred_op_pending = false;
	UNLOCK(nadata->lock);
    }
}

static void
udpn_close(struct netio *net)
{
    struct udpn_data *ndata = net->internal_data;
    struct udpna_data *nadata = ndata->nadata;

    LOCK(nadata->lock);
    if (!ndata->closed) {
	ndata->closed = true;
	if (!ndata->in_read && !ndata->in_write)
	    udpn_add_to_closed(nadata, ndata);
    }
    UNLOCK(nadata->lock);
}

static void
udpn_set_read_callback_enable(struct netio *net, bool enabled)
{
    struct udpn_data *ndata = net->internal_data;
    struct udpna_data *nadata = ndata->nadata;
    bool my_data_pending;

    LOCK(nadata->lock);
    my_data_pending = (nadata->data_pending &&
		       nadata->pending_data_owner == ndata);
    if (ndata->in_read || (my_data_pending && !enabled)) {
	ndata->user_set_read_enabled = true;
	ndata->user_read_enabled_setting = enabled;
    } else if (my_data_pending) {
	nadata->pending_data_ndata = ndata;
	ndata->in_read = true;
	if (!nadata->deferred_op_pending) {
	    /* Call the read from the selector to avoid lock nesting issues. */
	    nadata->deferred_op_pending = true;
	    sel_run(nadata->deferred_op_runner, udpna_deferred_op, nadata);
	}
    } else {
	ndata->read_enabled = enabled;
	if (enabled)
	    udpna_fd_read_enable(ndata->nadata);
	else
	    udpna_fd_read_disable(ndata->nadata);
    }
    UNLOCK(nadata->lock);
}

static void
udpn_set_write_callback_enable(struct netio *net, bool enabled)
{
    struct udpn_data *ndata = net->internal_data;
    struct udpna_data *nadata = ndata->nadata;

    LOCK(nadata->lock);
    if (ndata->write_enabled != enabled) {
	ndata->write_enabled = enabled;
	if (enabled)
	    udpna_fd_write_enable(ndata->nadata);
	else
	    udpna_fd_write_disable(ndata->nadata);
    }
    UNLOCK(nadata->lock);
}

static void
udpn_handle_read_incoming(struct udpna_data *nadata, struct udpn_data *ndata)
{
    struct netio *net = ndata->net;
    unsigned int count;

    if (!ndata->read_enabled)
	return;

    ndata->read_enabled = false;
    ndata->in_read = true;
    ndata->user_set_read_enabled = false;
    UNLOCK(nadata->lock);

    count = net->read_callback(net, 0, nadata->read_data,
			       nadata->data_pending_len);

    LOCK(nadata->lock);
    udpn_finish_read(ndata, count);
    UNLOCK(nadata->lock);
}

static void
udpn_handle_write_incoming(struct udpna_data *nadata, struct udpn_data *ndata)
{
    struct netio *net = ndata->net;

    ndata->in_write = true;
    UNLOCK(nadata->lock);
    net->write_callback(net);
    LOCK(nadata->lock);
    ndata->in_write = false;

    if (ndata->closed)
	udpn_add_to_closed(nadata, ndata);
}

static int
udpna_add_remaddr(struct netio_acceptor *acceptor, const char *str)
{
    struct udpna_data *nadata = acceptor->internal_data;
    struct port_remaddr *r, *r2;
    struct addrinfo *ai;
    bool is_port_set;
    int err;

    err = scan_network_port(str, &ai, NULL, &is_port_set);
    if (err)
	return err;

    r = malloc(sizeof(*r));
    if (!r) {
	err = ENOMEM;
	goto out;
    }

    memcpy(&r->addr, ai->ai_addr, ai->ai_addrlen);
    r->addrlen = ai->ai_addrlen;
    r->is_port_set = is_port_set;
    r->next = NULL;

    r2 = nadata->remaddrs;
    if (!r2) {
	nadata->remaddrs = r;
    } else {
	while (r2->next)
	    r2 = r2->next;
	r2->next = r;
    }

 out:
    if (ai)
	freeaddrinfo(ai);
    
    return 0;
}

static void
udpna_writehandler(int fd, void *cbdata)
{
    struct udpna_data *nadata = cbdata;
    struct udpn_data *ndata;

    LOCK(nadata->lock);
    udpna_fd_write_disable(nadata);
    ndata = nadata->udpns;
    while (ndata && nadata->write_disable_count == 1) {
	if (ndata->write_enabled)
	    udpn_handle_write_incoming(nadata, ndata);
	ndata = ndata->next;
    }
    udpna_fd_write_enable(nadata);

    if (!nadata->udpns)
	udpna_disable_write(nadata);
    UNLOCK(nadata->lock);
}

static void
udpna_readhandler(int fd, void *cbdata)
{
    struct udpna_data *nadata = cbdata;
    struct netio *net = NULL;
    struct udpn_data *ndata, *tndata;
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);

    int datalen;

    LOCK(nadata->lock);
    if (nadata->data_pending)
	goto out_unlock;

    datalen = recvfrom(fd, nadata->read_data, nadata->max_read_size, 0,
		       (struct sockaddr *) &addr, &addrlen);
    if (datalen == -1) {
	/* FIXME = handle error properly */
	if (errno != EAGAIN && errno != EWOULDBLOCK)
	    syslog(LOG_ERR, "Could not accept on %s: %m", nadata->name);
	return;
    }

    udpna_fd_read_disable(nadata);

    nadata->data_pending_len = datalen;
    nadata->data_pos = 0;

    ndata = nadata->udpns;
    while (ndata) {
	if (sockaddr_equal(ndata->raddr, ndata->raddrlen,
			   (struct sockaddr *) &addr, addrlen, true))
	    break;
	ndata = ndata->next;
    }
    if (ndata) {
	/* Data belongs to an existing connection. */
	if (!ndata->closed) {
	    ndata->myfd = fd; /* Reset this on every read. */
	    nadata->data_pending = true;
	    nadata->pending_data_owner = ndata;
	    udpn_handle_read_incoming(nadata, ndata);
	    UNLOCK(nadata->lock);
	    return;
	}
    }

    if (nadata->closed || nadata->num_unreported >= MAX_NUM_UNREPORTED) {
	nadata->data_pending = false;
	goto out_unlock;
    }

    if (ndata) { /* Reuse an existing connection? */
	ndata->closed = false;
	ndata->read_enabled = false;
	ndata->in_read = false;
	ndata->in_write = false;
	ndata->user_set_read_enabled = false;
	net = ndata->net;
	net->user_data = NULL;
	net->read_callback = NULL;
	net->write_callback = NULL;
	net->urgent_callback = NULL;
	net->close_done = NULL;
	goto restart_net;
    }

    /* New connection. */
    net = malloc(sizeof(*net));
    if (!net)
	goto out_nomem;
    memset(net, 0, sizeof(*net));

    ndata = malloc(sizeof(*ndata));
    if (!ndata)
	goto out_nomem;
    memset(ndata, 0, sizeof(*ndata));

    ndata->net = net;
    ndata->nadata = nadata;
    ndata->raddr = (struct sockaddr *) &ndata->remote;

    net->internal_data = ndata;
    net->write = udpn_write;
    net->raddr_to_str = udpn_raddr_to_str;
    net->close = udpn_close;
    net->set_read_callback_enable = udpn_set_read_callback_enable;
    net->set_write_callback_enable = udpn_set_write_callback_enable;

    /* Stick it on the end of the list. */
    tndata = nadata->udpns;
    if (!tndata) {
       nadata->udpns = ndata;
    } else {
       while (tndata->next)
           tndata = tndata->next;
       tndata->next = ndata;
    }

 restart_net:
    ndata->myfd = fd;
    ndata->raddrlen = addrlen;
    memcpy(ndata->raddr, &addr, addrlen);

    if (!nadata->enabled) {
	ndata->reported = false;
	nadata->num_unreported++;
	goto out_unlock;
    }

    udpna_fd_write_disable(nadata);
    nadata->data_pending = true;
    nadata->pending_data_owner = ndata;
    nadata->in_new_connection = true;
    ndata->reported = true;
    UNLOCK(nadata->lock);

    nadata->acceptor->new_connection(nadata->acceptor, net);

    LOCK(nadata->lock);
    nadata->in_new_connection = false;
    udpna_check_finish_free(nadata);

 out_unlock:
    UNLOCK(nadata->lock);
    return;

 out_nomem:
    if (ndata)
	free(ndata);
    if (net)
	free(net);

    syslog(LOG_ERR, "Out of memory allocating for udp port %s", nadata->name);
}

static void udpna_fd_cleared(int fd, void *cbdata)
{
    struct udpna_data *nadata = cbdata;

    wake_waiter(nadata->accept_waiter);
}

static int
udpna_startup(struct netio_acceptor *acceptor)
{
    struct udpna_data *nadata = acceptor->internal_data;

    LOCK(nadata->lock);
    nadata->setup = true;
    nadata->enabled = true;
    UNLOCK(nadata->lock);

    return 0;
}

static int
udpna_shutdown(struct netio_acceptor *acceptor)
{
    struct udpna_data *nadata = acceptor->internal_data;

    LOCK(nadata->lock);
    nadata->enabled = false;
    nadata->setup = false;
    UNLOCK(nadata->lock);
	
    return 0;
}

static void
udpna_set_accept_callback_enable(struct netio_acceptor *acceptor, bool enabled)
{
    struct udpna_data *nadata = acceptor->internal_data;
    struct udpn_data *ndata;

    LOCK(nadata->lock);
    nadata->enabled = true;

    ndata = nadata->udpns;
    while (nadata->num_unreported) {
	if (!ndata->reported) {
	    nadata->num_unreported--;
	    udpna_fd_write_disable(nadata);
	    ndata->reported = true;
	    UNLOCK(nadata->lock);
	    nadata->acceptor->new_connection(nadata->acceptor, ndata->net);
	    LOCK(nadata->lock);
	}
	ndata = ndata->next;
    }

    UNLOCK(nadata->lock);
}

static void
udpna_free(struct netio_acceptor *acceptor)
{
    struct udpna_data *nadata = acceptor->internal_data;
    struct udpn_data *ndata;

    LOCK(nadata->lock);

    ndata = nadata->udpns;
    while (nadata->num_unreported) {
	if (!ndata->reported) {
	    udpn_finish_close(nadata, ndata);
	    nadata->num_unreported--;
	}
	ndata = ndata->next;
    }

    nadata->enabled = false;
    nadata->setup = false;
    nadata->closed = true;

    udpna_check_finish_free(nadata);
    UNLOCK(nadata->lock);
}

int
udp_netio_acceptor_alloc(const char *name,
			 struct addrinfo *ai,
			 unsigned int max_read_size,
			 struct netio_acceptor **acceptor)
{
    int err = ENOMEM;
    struct netio_acceptor *acc = NULL;
    struct udpna_data *nadata = NULL;

    acc = malloc(sizeof(*acc));
    if (!acc)
	goto out_err;
    memset(acc, 0, sizeof(*acc));

    nadata = malloc(sizeof(*nadata));
    if (!nadata)
	goto out_err;
    memset(nadata, 0, sizeof(*nadata));

    nadata->name = strdup(name);
    if (!nadata->name)
	goto out_err;

    nadata->accept_waiter = alloc_waiter();
    if (!nadata->accept_waiter)
	goto out_err;

    nadata->read_data = malloc(max_read_size);
    if (!nadata->read_data)
	goto out_err;

    err = sel_alloc_runner(ser2net_sel, &nadata->deferred_op_runner);
    if (err)
	goto out_err;

    acc->internal_data = nadata;
    acc->add_remaddr = udpna_add_remaddr;
    acc->startup = udpna_startup;
    acc->shutdown = udpna_shutdown;
    acc->set_accept_callback_enable = udpna_set_accept_callback_enable;
    acc->free = udpna_free;

    INIT_LOCK(nadata->lock);
    nadata->acceptor = acc;
    nadata->ai = ai;
    nadata->max_read_size = max_read_size;

    /* FIXME - write handling */
    nadata->fds = open_socket(nadata->ai, udpna_readhandler, udpna_writehandler,
			      nadata, &nadata->nr_fds, udpna_fd_cleared);
    if (nadata->fds == NULL)
	goto out_err;

    *acceptor = acc;
    return 0;

 out_err:
    if (acc)
	free(acc);
    if (nadata) {
	if (nadata->name)
	    free(nadata->name);
	if (nadata->read_data)
		free(nadata->read_data);
	if (nadata->deferred_op_runner)
	    sel_free_runner(nadata->deferred_op_runner);
	free(nadata);
    }

    return err;
}
