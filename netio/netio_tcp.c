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
#include "netio_internal.h"
#include "utils/selector.h"
#include "utils/locking.h"

struct tcpn_data {
    struct netio net;

    struct selector_s *sel;

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

#define net_to_ndata(net) container_of(net, struct tcpn_data, net);

struct tcpna_data {
    struct netio_acceptor acceptor;

    struct selector_s *sel;

    char *name;

    unsigned int max_read_size;

    DEFINE_LOCK(, lock);

    bool setup;			/* Network sockets are allocated. */
    bool enabled;		/* Accepts are being handled. */
    bool in_free;		/* Currently being freed. */
    bool in_shutdown;		/* Currently being shut down. */
    bool report_shutdown;	/* call shutdown_done() when shutdown ends. */

    struct addrinfo    *ai;		/* The address list for the portname. */
    struct opensocks   *acceptfds;	/* The file descriptor used to
					   accept connections on the
					   TCP port. */
    unsigned int   nr_acceptfds;
    unsigned int   nr_accept_close_waiting;
};

#define acc_to_nadata(acc) container_of(acc, struct tcpna_data, acceptor);

static int
tcpn_write(struct netio *net, int *count,
	   const void *buf, unsigned int buflen)
{
    struct tcpn_data *ndata = net_to_ndata(net);
    int rv, err = 0;

 retry:
    rv = write(ndata->fd, buf, buflen);
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
tcpn_raddr_to_str(struct netio *net, int *epos,
		  char *buf, unsigned int buflen)
{
    struct tcpn_data *ndata = net_to_ndata(net);
    char portstr[NI_MAXSERV];
    int err;
    int pos = 0;

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

static socklen_t
tcpn_get_raddr(struct netio *net,
	       struct sockaddr *addr, socklen_t addrlen)
{
    struct tcpn_data *ndata = net_to_ndata(net);

    if (addrlen > ndata->raddrlen)
	addrlen = ndata->raddrlen;

    memcpy(addr, ndata->raddr, addrlen);
    return addrlen;
}

static void
tcpn_finish_close(struct tcpn_data *ndata)
{
    struct netio *net = &ndata->net;

    close(ndata->fd);

    if (net->cbs && net->cbs->close_done)
	net->cbs->close_done(net);

    sel_free_runner(ndata->deferred_read_runner);
    free(ndata->read_data);
    free(ndata);
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
    struct tcpn_data *ndata = net_to_ndata(net);

    sel_clear_fd_handlers(ndata->sel, ndata->fd);
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
	sel_set_fd_read_handler(ndata->sel, ndata->fd,
				SEL_FD_HANDLER_ENABLED);
	sel_set_fd_except_handler(ndata->sel, ndata->fd,
				  SEL_FD_HANDLER_ENABLED);
    }
}

static void
tcpn_deferred_read(sel_runner_t *runner, void *cbdata)
{
    struct tcpn_data *ndata = cbdata;
    struct netio *net = &ndata->net;
    unsigned int count;

    /* No lock needed, this data cannot be changed here. */
    count = net->cbs->read_callback(net, 0, ndata->read_data + ndata->data_pos,
				    ndata->data_pending_len, 0);
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
    struct tcpn_data *ndata = net_to_ndata(net);

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
	sel_set_fd_read_handler(ndata->sel, ndata->fd, op);
    }
    UNLOCK(ndata->lock);
}

static void
tcpn_set_write_callback_enable(struct netio *net, bool enabled)
{
    struct tcpn_data *ndata = net_to_ndata(net);
    int op;

    if (enabled)
	op = SEL_FD_HANDLER_ENABLED;
    else
	op = SEL_FD_HANDLER_DISABLED;

    sel_set_fd_write_handler(ndata->sel, ndata->fd, op);
}

static void
tcpn_handle_incoming(int fd, void *cbdata, bool urgent)
{
    struct tcpn_data *ndata = cbdata;
    struct netio *net = &ndata->net;
    unsigned int count = 0;
    int c;
    int rv;

    LOCK(ndata->lock);
    if (!ndata->read_enabled)
	goto out_unlock;
    ndata->read_enabled = false;
    sel_set_fd_read_handler(ndata->sel, ndata->fd, SEL_FD_HANDLER_DISABLED);
    sel_set_fd_except_handler(ndata->sel, ndata->fd, SEL_FD_HANDLER_DISABLED);
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
	if (net->cbs->urgent_callback)
	    net->cbs->urgent_callback(net);
    }

 retry:
    rv = read(fd, ndata->read_data, ndata->max_read_size);
    if (rv < 0) {
	if (errno == EINTR)
	    goto retry;
	if (errno == EAGAIN || errno == EWOULDBLOCK)
	    rv = 0; /* Pretend like nothing happened. */
	else
	    net->cbs->read_callback(net, errno, NULL, 0, 0);
    } else if (rv == 0) {
	net->cbs->read_callback(net, EPIPE, NULL, 0, 0);
	rv = -1;
    } else {
	ndata->data_pending_len = rv;
	count = net->cbs->read_callback(net, 0, ndata->read_data, rv, 0);
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
    struct netio *net = &ndata->net;

    LOCK(ndata->lock);
    ndata->in_write = true;
    UNLOCK(ndata->lock);

    net->cbs->write_callback(net);

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

static const struct netio_functions netio_tcp_funcs = {
    .write = tcpn_write,
    .raddr_to_str = tcpn_raddr_to_str,
    .get_raddr = tcpn_get_raddr,
    .close = tcpn_close,
    .set_read_callback_enable = tcpn_set_read_callback_enable,
    .set_write_callback_enable = tcpn_set_write_callback_enable
};

static int 
tcpn_finish_setup(int new_fd, struct selector_s *sel,
		  struct sockaddr *addr, socklen_t addrlen,
		  unsigned int max_read_size,
		  struct tcpn_data **new_ndata)
{
    struct tcpn_data *ndata;
    int err = 0, optval;

    if (fcntl(new_fd, F_SETFL, O_NONBLOCK) == -1)
	return errno;

    optval = 1;
    if (setsockopt(new_fd, SOL_SOCKET, SO_KEEPALIVE,
		   (void *)&optval, sizeof(optval)) == -1)
	return errno;

    ndata = malloc(sizeof(*ndata));
    if (!ndata)
	goto out_nomem;
    memset(ndata, 0, sizeof(*ndata));
    ndata->sel = sel;

    err = sel_alloc_runner(ndata->sel, &ndata->deferred_read_runner);
    if (err)
	goto out_nomem;

    INIT_LOCK(ndata->lock);
    ndata->fd = new_fd;
    ndata->raddr = (struct sockaddr *) &ndata->remote;
    ndata->raddrlen = addrlen;
    memcpy(ndata->raddr, addr, addrlen);

    ndata->max_read_size = max_read_size;
    ndata->read_data = malloc(ndata->max_read_size);
    if (!ndata->read_data)
	goto out_nomem;

    ndata->net.funcs = &netio_tcp_funcs;
    ndata->net.type = NETIO_TYPE_TCP;

    if (sel_set_fd_handlers(ndata->sel, new_fd, ndata, tcpn_read_ready,
			    tcpn_write_ready, tcpn_except_ready,
			    tcpn_fd_cleared))
	goto out_nomem;

    *new_ndata = ndata;
    return 0;

 out_nomem:
    if (ndata) {
	if (ndata->deferred_read_runner)
	    sel_free_runner(ndata->deferred_read_runner);
	if (ndata->read_data)
	    free(ndata->read_data);
	free(ndata);
    }
    return ENOMEM;
}

static void
write_nofail(int fd, const char *data, size_t count)
{
    ssize_t written;

    while ((written = write(fd, data, count)) > 0) {
	data += written;
	count -= written;
    }
}

static void
tcpna_readhandler(int fd, void *cbdata)
{
    struct tcpna_data *nadata = cbdata;
    int new_fd;
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    struct tcpn_data *ndata = NULL;
    const char *errstr;
    int err;

    new_fd = accept(fd, (struct sockaddr *) &addr, &addrlen);
    if (new_fd == -1) {
	if (errno != EAGAIN && errno != EWOULDBLOCK)
	    syslog(LOG_ERR, "Could not accept on %s: %m", nadata->name);
	return;
    }

    errstr = check_tcpd_ok(new_fd);
    if (errstr) {
	write_nofail(new_fd, errstr, strlen(errstr));
	close(new_fd);
	return;
    }

    err = tcpn_finish_setup(new_fd, nadata->sel,
			    (struct sockaddr *) &addr, addrlen,
			    nadata->max_read_size, &ndata);
    if (err) {
	syslog(LOG_ERR, "Error setting up tcp port %s: %s", nadata->name,
	       strerror(err));
	close(new_fd);
	return;
    }

    nadata->acceptor.cbs->new_connection(&nadata->acceptor, &ndata->net);
}

static void
tcpna_finish_free(struct tcpna_data *nadata)
{
    if (nadata->name)
	free(nadata->name);
    if (nadata->ai)
	freeaddrinfo(nadata->ai);
    if (nadata->acceptfds)
	free(nadata->acceptfds);
    free(nadata);
}

static void
tcpna_fd_cleared(int fd, void *cbdata)
{
    struct tcpna_data *nadata = cbdata;
    struct netio_acceptor *acceptor = &nadata->acceptor;
    unsigned int num_left;

    close(fd);

    LOCK(nadata->lock);
    num_left = --nadata->nr_accept_close_waiting;
    UNLOCK(nadata->lock);

    if (num_left == 0) {
	nadata->in_shutdown = false;
	if (acceptor->cbs->shutdown_done && nadata->report_shutdown)
	    acceptor->cbs->shutdown_done(acceptor);
	if (nadata->in_free)
	    tcpna_finish_free(nadata);
    }
}

static int
tcpna_startup(struct netio_acceptor *acceptor)
{
    struct tcpna_data *nadata = acc_to_nadata(acceptor);
    int rv = 0;

    LOCK(nadata->lock);
    if (nadata->in_shutdown) {
	rv = EAGAIN;
	goto out_unlock;
    }

    if (nadata->setup)
	goto out_unlock;

    nadata->acceptfds = open_socket(nadata->sel,
				    nadata->ai, tcpna_readhandler, NULL, nadata,
				    &nadata->nr_acceptfds, tcpna_fd_cleared);
    if (nadata->acceptfds == NULL) {
	rv = errno;
    } else {
	nadata->setup = true;
	nadata->enabled = true;
	nadata->report_shutdown = false;
    }

 out_unlock:
    UNLOCK(nadata->lock);
    return rv;
}

static int
_tcpna_shutdown(struct tcpna_data *nadata)
{
    unsigned int i;
    int rv = 0;

    if (nadata->setup) {
	nadata->in_shutdown = true;
	nadata->nr_accept_close_waiting = nadata->nr_acceptfds;
	for (i = 0; i < nadata->nr_acceptfds; i++)
	    sel_clear_fd_handlers(nadata->sel, nadata->acceptfds[i].fd);
	nadata->setup = false;
	nadata->enabled = false;
    } else {
	rv = EAGAIN;
    }
	
    return rv;
}

static int
tcpna_shutdown(struct netio_acceptor *acceptor)
{
    struct tcpna_data *nadata = acc_to_nadata(acceptor);
    int rv;

    LOCK(nadata->lock);
    rv = _tcpna_shutdown(nadata);
    if (!rv)
	nadata->report_shutdown = true;
    UNLOCK(nadata->lock);
	
    return rv;
}

static void
tcpna_set_accept_callback_enable(struct netio_acceptor *acceptor, bool enabled)
{
    struct tcpna_data *nadata = acc_to_nadata(acceptor);
    unsigned int i;
    int op;

    if (enabled)
	op = SEL_FD_HANDLER_ENABLED;
    else
	op = SEL_FD_HANDLER_DISABLED;

    LOCK(nadata->lock);
    if (nadata->enabled != enabled) {
	for (i = 0; i < nadata->nr_acceptfds; i++)
	    sel_set_fd_read_handler(nadata->sel, nadata->acceptfds[i].fd, op);
	nadata->enabled = enabled;
    }
    UNLOCK(nadata->lock);
}

static void
tcpna_free(struct netio_acceptor *acceptor)
{
    struct tcpna_data *nadata = acc_to_nadata(acceptor);

    LOCK(nadata->lock);
    nadata->in_free = true;
    if (!nadata->in_shutdown && _tcpna_shutdown(nadata)) {
	if (nadata->nr_accept_close_waiting == 0) {
	    UNLOCK(nadata->lock);
	    tcpna_finish_free(nadata);
	    return;
	}
    }
    UNLOCK(nadata->lock);
}

static const struct netio_acceptor_functions netio_acc_tcp_funcs = {
    .startup = tcpna_startup,
    .shutdown = tcpna_shutdown,
    .set_accept_callback_enable = tcpna_set_accept_callback_enable,
    .free = tcpna_free
};

int
tcp_netio_acceptor_alloc(const char *name,
			 struct selector_s *sel,
			 struct addrinfo *ai,
			 unsigned int max_read_size,
			 const struct netio_acceptor_callbacks *cbs,
			 void *user_data,
			 struct netio_acceptor **acceptor)
{
    struct netio_acceptor *acc;
    struct tcpna_data *nadata;

    nadata = malloc(sizeof(*nadata));
    if (!nadata)
	goto out_nomem;
    memset(nadata, 0, sizeof(*nadata));

    nadata->sel = sel;

    nadata->name = strdup(name);
    if (!nadata->name)
	goto out_nomem;

    acc = &nadata->acceptor;

    acc->cbs = cbs;
    acc->user_data = user_data;
    acc->funcs = &netio_acc_tcp_funcs;
    acc->type = NETIO_TYPE_TCP;

    INIT_LOCK(nadata->lock);
    nadata->ai = ai;
    nadata->max_read_size = max_read_size;

    *acceptor = acc;
    return 0;

 out_nomem:
    if (nadata) {
	if (nadata->name)
	    free(nadata->name);
	free(nadata);
    }
    return ENOMEM;
}

int
tcp_netio_alloc(struct addrinfo *ai,
		struct selector_s *sel,
		unsigned int max_read_size,
		const struct netio_callbacks *cbs,
		void *user_data,
		struct netio **new_netio)
{
    struct tcpn_data *ndata = NULL;
    int err;
    int new_fd;

    new_fd = socket(ai->ai_family, SOCK_STREAM, 0);
    if (ndata->fd == -1)
	return errno;

 retry:
    err = connect(new_fd, ai->ai_addr, ai->ai_addrlen);
    if (err == -1) {
	ai = ai->ai_next;
	if (ai)
	    goto retry;
	close(new_fd);
	return errno;
    }

    if (ai->ai_addrlen > sizeof(struct sockaddr_storage)) {
	/* How can this happen? */
	close(new_fd);
	return E2BIG;
    }

    err = tcpn_finish_setup(new_fd, sel, ai->ai_addr, ai->ai_addrlen,
			    max_read_size, &ndata);
    if (err)
	return err;

    *new_netio = &ndata->net;
    return 0;
}
