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

/* This code handles TCP network I/O. */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>

#include "netio.h"
#include "selector.h"
#include "ser2net.h"
#include "locking.h"
#include "utils.h"

struct tcpn_data {
    struct netio *net;

    DEFINE_LOCK(, lock);

    int fd;
    bool read_enabled;
    bool in_read;
    bool in_write;

    bool user_set_read_enabled;
    bool user_read_enabled_setting;

    bool data_pending;
    unsigned int data_pending_len;
    unsigned int data_pos;

    /* User should set to the maximum value that read_callback may
       return.  Set before startup() is called and do not change
       afterwards.  This must be at least the size of read_data. */
    unsigned int max_read_size;

    /* The buffer used by read, supplied by the user. */
    unsigned char *read_data;

    /*
     * Used to run read callbacks from the selector to avoid running
     * it directly from user calls.
     */
    bool deferred_read_pending;
    sel_runner_t *deferred_read_runner;
    bool deferred_close; /* A close is pending the running running. */

    struct sockaddr_storage remote;	/* The socket address of who
					   is connected to this port. */
    struct sockaddr *raddr;		/* Points to remote, for convenience. */
    socklen_t raddrlen;

    struct tcpn_data *next;
};

struct port_remaddr
{
    struct sockaddr_storage addr;
    socklen_t addrlen;
    bool is_port_set;
    struct port_remaddr *next;
};

struct tcpna_data {
    struct netio_acceptor *acceptor;

    char *name;

    unsigned int max_read_size;

    DEFINE_LOCK(, lock);

    bool setup;
    bool enabled;

    struct addrinfo    *ai;		/* The address list for the portname. */
    struct opensocks   *acceptfds;	/* The file descriptor used to
					   accept connections on the
					   TCP port. */
    unsigned int   nr_acceptfds;
    waiter_t       *accept_waiter;      /* Wait for accept changes. */

    struct port_remaddr *remaddrs;
};

static int
tcpn_write(struct netio *net, int *count,
	   const void *buf, unsigned int buflen)
{
    struct tcpn_data *ndata = net->internal_data;
    int rv = write(ndata->fd, buf, buflen);

    if (rv < 0)
	return errno;

    if (count)
	*count = rv;
    return 0;
}

static int
tcpn_raddr_to_str(struct netio *net, int *pos,
		  char *buf, unsigned int buflen)
{
    struct tcpn_data *ndata = net->internal_data;
    char portstr[NI_MAXSERV];
    int err;

    err = getnameinfo(ndata->raddr, ndata->raddrlen,
		      buf + *pos, buflen - *pos,
		      portstr, sizeof(portstr), NI_NUMERICHOST);
    if (err) {
	snprintf(buf + *pos, buflen - *pos, 
		 "unknown:%s\n", gai_strerror(err));
	return EINVAL;
    }

    *pos += strlen(buf + *pos);
    if (buflen - *pos > 2) {
	buf[*pos] = ':';
	(*pos)++;
    }
    strncpy(buf + *pos, portstr, buflen - *pos);
    *pos += strlen(buf + *pos);

    return 0;
}

static void
tcpn_finish_close(struct tcpn_data *ndata)
{
    struct netio *net = ndata->net;

    close(ndata->fd);

    if (net->close_done)
	net->close_done(net);

    sel_free_runner(ndata->deferred_read_runner);
    free(ndata->read_data);
    free(ndata);
    free(net);
}

static void
tcpn_fd_cleared(int fd, void *cbdata)
{
    struct tcpn_data *ndata = cbdata;

    LOCK(ndata->lock);
    if (ndata->deferred_read_pending || ndata->in_write) {
	ndata->deferred_close = true;
	UNLOCK(ndata->lock);
    } else {
	UNLOCK(ndata->lock);
	tcpn_finish_close(ndata);
    }
}

static void
tcpn_close(struct netio *net)
{
    struct tcpn_data *ndata = net->internal_data;

    sel_clear_fd_handlers(ser2net_sel, ndata->fd);
}

/* Must be called with ndata->lock held */
static void
tcpn_finish_read(struct tcpn_data *ndata, int err, unsigned int count)
{
    ndata->data_pending = false;
    if (err < 0) {
	ndata->user_set_read_enabled = true;
	ndata->user_read_enabled_setting = false;
    } else if (count < ndata->data_pending_len) {
	/* If the user doesn't consume all the data, disable
	   automatically. */
	ndata->data_pending = true;
	ndata->data_pending_len -= count;
	ndata->data_pos += count;
	ndata->user_set_read_enabled = true;
	ndata->user_read_enabled_setting = false;
    }

    ndata->in_read = false;

    if (ndata->user_set_read_enabled)
	ndata->read_enabled = ndata->user_read_enabled_setting;
    else
	ndata->read_enabled = true;

    if (ndata->read_enabled) {
	sel_set_fd_read_handler(ser2net_sel, ndata->fd,
				SEL_FD_HANDLER_ENABLED);
	sel_set_fd_except_handler(ser2net_sel, ndata->fd,
				  SEL_FD_HANDLER_ENABLED);
    }
}

static void
tcpn_deferred_read(sel_runner_t *runner, void *cbdata)
{
    struct tcpn_data *ndata = cbdata;
    struct netio *net = ndata->net;
    unsigned int count;

    /* No lock needed, this data cannot be changed here. */
    count = net->read_callback(net, 0, ndata->read_data + ndata->data_pos,
			       ndata->data_pending_len);
    LOCK(ndata->lock);
    ndata->deferred_read_pending = false;
    if (ndata->deferred_close) {
	UNLOCK(ndata->lock);
	tcpn_finish_close(ndata);
	return;
    }
    tcpn_finish_read(ndata, 0, count);
    UNLOCK(ndata->lock);
}

static void
tcpn_set_read_callback_enable(struct netio *net, bool enabled)
{
    struct tcpn_data *ndata = net->internal_data;

    LOCK(ndata->lock);
    if (ndata->in_read || (ndata->data_pending && !enabled)) {
	ndata->user_set_read_enabled = true;
	ndata->user_read_enabled_setting = enabled;
    } else if (ndata->data_pending) {
	if (!ndata->deferred_read_pending) {
	    /* Call the read from the selector to avoid lock nesting issues. */
	    ndata->in_read = true;
	    ndata->deferred_read_pending = true;
	    sel_run(ndata->deferred_read_runner, tcpn_deferred_read, ndata);
	}
    } else {
	int op;

	if (enabled)
	    op = SEL_FD_HANDLER_ENABLED;
	else
	    op = SEL_FD_HANDLER_DISABLED;

	ndata->read_enabled = enabled;
	sel_set_fd_read_handler(ser2net_sel, ndata->fd, op);
    }
    UNLOCK(ndata->lock);
}

static void
tcpn_set_write_callback_enable(struct netio *net, bool enabled)
{
    struct tcpn_data *ndata = net->internal_data;
    int op;

    if (enabled)
	op = SEL_FD_HANDLER_ENABLED;
    else
	op = SEL_FD_HANDLER_DISABLED;

    sel_set_fd_write_handler(ser2net_sel, ndata->fd, op);
}

static void
tcpn_handle_incoming(int fd, void *cbdata, bool urgent)
{
    struct tcpn_data *ndata = cbdata;
    struct netio *net = ndata->net;
    unsigned int count = 0;
    int c;
    int rv;

    LOCK(ndata->lock);
    if (!ndata->read_enabled)
	goto out_unlock;
    ndata->read_enabled = false;
    sel_set_fd_read_handler(ser2net_sel, ndata->fd, SEL_FD_HANDLER_DISABLED);
    sel_set_fd_except_handler(ser2net_sel, ndata->fd, SEL_FD_HANDLER_DISABLED);
    ndata->in_read = true;
    ndata->user_set_read_enabled = false;
    ndata->data_pos = 0;
    UNLOCK(ndata->lock);

    if (urgent) {
	/* We should have urgent data, a DATA MARK in the stream.  Read
	   the urgent data (whose contents are irrelevant) then inform
	   the user. */
	for (;;) {
	    rv = recv(fd, &c, 1, MSG_OOB);
	    if (rv == 0 || (rv < 0 && errno != EINTR))
		break;
	}
	net->urgent_callback(net);
    }

 retry:
    rv = read(fd, ndata->read_data, ndata->max_read_size);
    if (rv < 0) {
	if (errno == EINTR)
	    goto retry;
	if (errno == EAGAIN || errno == EWOULDBLOCK)
	    rv = 0; /* Pretend like nothing happened. */
	else
	    net->read_callback(net, errno, NULL, 0);
    } else if (rv == 0) {
	net->read_callback(net, EPIPE, NULL, 0);
	rv = -1;
    } else {
	ndata->data_pending_len = rv;
	count = net->read_callback(net, 0, ndata->read_data, rv);
    }

    LOCK(ndata->lock);
    tcpn_finish_read(ndata, rv, count);
 out_unlock:
    UNLOCK(ndata->lock);
}

static void
tcpn_read_ready(int fd, void *cbdata)
{
    tcpn_handle_incoming(fd, cbdata, false);
}

static void
tcpn_write_ready(int fd, void *cbdata)
{
    struct tcpn_data *ndata = cbdata;
    struct netio *net = ndata->net;

    LOCK(ndata->lock);
    ndata->in_write = true;
    UNLOCK(ndata->lock);

    net->write_callback(net);

    LOCK(ndata->lock);
    ndata->in_write = false;
    if (ndata->deferred_close && !ndata->deferred_read_pending) {
	UNLOCK(ndata->lock);
	tcpn_finish_close(ndata);
	return;
    }
    UNLOCK(ndata->lock);
}

static void
tcpn_except_ready(int fd, void *cbdata)
{
    tcpn_handle_incoming(fd, cbdata, true);
}

static int
tcpna_add_remaddr(struct netio_acceptor *acceptor, const char *str)
{
    struct tcpna_data *nadata = acceptor->internal_data;
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

static void
tcpna_readhandler(int fd, void *cbdata)
{
    struct tcpna_data *nadata = cbdata;
    int new_fd;
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    struct netio *net = NULL;
    struct tcpn_data *ndata = NULL;
    const char *errstr;
    int optval, err;

    new_fd = accept(fd, (struct sockaddr *) &addr, &addrlen);
    if (new_fd == -1) {
	if (errno != EAGAIN && errno != EWOULDBLOCK)
	    syslog(LOG_ERR, "Could not accept on rotator %s: %m",
		   nadata->name);
	return;
    }

    errstr = check_tcpd_ok(new_fd);
    if (errstr) {
	write_ignore_fail(new_fd, errstr, strlen(errstr));
	close(new_fd);
	return;
    }

    optval = 1;
    if (setsockopt(new_fd, SOL_SOCKET, SO_KEEPALIVE,
		   (void *)&optval, sizeof(optval)) == -1) {
	close(new_fd);
	syslog(LOG_ERR, "Could not enable SO_KEEPALIVE on tcp port %s: %m",
	       nadata->name);
	return;
    }

    net = malloc(sizeof(*net));
    if (!net)
	goto out_nomem;
    memset(net, 0, sizeof(*net));

    ndata = malloc(sizeof(*ndata));
    if (!ndata)
	goto out_nomem;
    memset(ndata, 0, sizeof(*ndata));

    err = sel_alloc_runner(ser2net_sel, &ndata->deferred_read_runner);
    if (err)
	goto out_nomem;

    INIT_LOCK(ndata->lock);
    ndata->net = net;
    ndata->fd = new_fd;
    ndata->raddr = (struct sockaddr *) &ndata->remote;
    ndata->raddrlen = addrlen;
    memcpy(ndata->raddr, &addr, addrlen);

    ndata->max_read_size = nadata->max_read_size;
    ndata->read_data = malloc(ndata->max_read_size);
    if (!ndata->read_data)
	goto out_nomem;
    net->internal_data = ndata;
    net->write = tcpn_write;
    net->raddr_to_str = tcpn_raddr_to_str;
    net->close = tcpn_close;
    net->set_read_callback_enable = tcpn_set_read_callback_enable;
    net->set_write_callback_enable = tcpn_set_write_callback_enable;

    sel_set_fd_handlers(ser2net_sel, new_fd, ndata, tcpn_read_ready,
			tcpn_write_ready, tcpn_except_ready, tcpn_fd_cleared);

    nadata->acceptor->new_connection(nadata->acceptor, net);
    return;

 out_nomem:
    close(new_fd);
    if (ndata) {
	if (ndata->deferred_read_runner)
	    sel_free_runner(ndata->deferred_read_runner);
	if (ndata->read_data)
	    free(ndata->read_data);
	free(ndata);
    }
    if (net)
	free(net);

    syslog(LOG_ERR, "Out of memory allocating for tcp port %s", nadata->name);
}

static void tcpna_fd_cleared(int fd, void *cbdata)
{
    struct tcpna_data *nadata = cbdata;

    wake_waiter(nadata->accept_waiter);
}

static int
tcpna_startup(struct netio_acceptor *acceptor)
{
    struct tcpna_data *nadata = acceptor->internal_data;
    int rv = 0;

    LOCK(nadata->lock);
    if (nadata->setup) {
	goto out_unlock;
    }
    nadata->acceptfds = open_socket(nadata->ai, tcpna_readhandler, NULL, nadata,
				    &nadata->nr_acceptfds, tcpna_fd_cleared);
    if (nadata->acceptfds == NULL) {
	rv = errno;
    } else {
	nadata->setup = true;
	nadata->enabled = true;
    }

 out_unlock:
    UNLOCK(nadata->lock);
    return rv;
}

static int
tcpna_shutdown(struct netio_acceptor *acceptor)
{
    struct tcpna_data *nadata = acceptor->internal_data;
    unsigned int i;

    LOCK(nadata->lock);
    if (nadata->setup) {
	for (i = 0; i < nadata->nr_acceptfds; i++) {
	    sel_clear_fd_handlers(ser2net_sel, nadata->acceptfds[i].fd);
	    wait_for_waiter(nadata->accept_waiter);
	    close(nadata->acceptfds[i].fd);
	}
	nadata->setup = false;
	nadata->enabled = false;
    }
    UNLOCK(nadata->lock);
	
    return 0;
}

static void
tcpna_set_accept_callback_enable(struct netio_acceptor *acceptor, bool enabled)
{
    struct tcpna_data *nadata = acceptor->internal_data;
    unsigned int i;
    int op;

    if (enabled)
	op = SEL_FD_HANDLER_ENABLED;
    else
	op = SEL_FD_HANDLER_DISABLED;

    LOCK(nadata->lock);
    if (nadata->enabled != enabled) {
	for (i = 0; i < nadata->nr_acceptfds; i++)
	    sel_set_fd_read_handler(ser2net_sel, nadata->acceptfds[i].fd, op);
	nadata->enabled = enabled;
    }
    UNLOCK(nadata->lock);
}

static void
tcpna_free(struct netio_acceptor *acceptor)
{
    struct tcpna_data *nadata = acceptor->internal_data;

    tcpna_shutdown(acceptor);

    while (nadata->remaddrs) {
	struct port_remaddr *r;

	r = nadata->remaddrs;
	nadata->remaddrs = r->next;
	free(r);
    }

    if (nadata->accept_waiter)
	free_waiter(nadata->accept_waiter);
    if (nadata->name)
	free(nadata->name);
    if (nadata->ai)
	freeaddrinfo(nadata->ai);
    if (nadata->acceptfds)
	free(nadata->acceptfds);
    free(nadata);
    free(acceptor);
}

int
tcp_netio_acceptor_alloc(const char *name,
			 struct addrinfo *ai,
			 unsigned int max_read_size,
			 struct netio_acceptor **acceptor)
{
    int err = 0;
    struct netio_acceptor *acc = NULL;
    struct tcpna_data *nadata = NULL;

    acc = malloc(sizeof(*acc));
    if (!acc) {
	err = ENOMEM;
	goto out;
    }
    memset(acc, 0, sizeof(*acc));

    nadata = malloc(sizeof(*nadata));
    if (!nadata) {
	err = ENOMEM;
	goto out;
    }
    memset(nadata, 0, sizeof(*nadata));

    nadata->name = strdup(name);
    if (!nadata->name) {
	err = ENOMEM;
	goto out;
    }

    nadata->accept_waiter = alloc_waiter();
    if (!nadata->accept_waiter) {
	err = ENOMEM;
	goto out;
    }

    acc->internal_data = nadata;
    acc->add_remaddr = tcpna_add_remaddr;
    acc->startup = tcpna_startup;
    acc->shutdown = tcpna_shutdown;
    acc->set_accept_callback_enable = tcpna_set_accept_callback_enable;
    acc->free = tcpna_free;

    INIT_LOCK(nadata->lock);
    nadata->acceptor = acc;
    nadata->ai = ai;
    nadata->max_read_size = max_read_size;

 out:
    if (err) {
	if (acc)
	    free(acc);
	if (nadata) {
	    if (nadata->name)
		free(nadata->name);
	    free(nadata);
	}
    } else {
	*acceptor = acc;
    }
    return err;
}
