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
#include "netio_internal.h"
#include "utils/selector.h"
#include "utils/locking.h"
#include "utils/utils.h"

struct udpna_data;

struct udpn_data {
    struct netio net;
    struct udpna_data *nadata;

    /*
     * When in a read callback or when there is pending data, we
     * cannot directly set the read settings for a net because the
     * read callback must remain disabled.  So save the current state.
     */
    bool user_set_read_enabled;
    bool user_read_enabled_setting;

    int myfd; /* fd the original request came in on, for sending. */

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

#define net_to_ndata(net) container_of(net, struct udpn_data, net);

struct udpna_data {
    struct netio_acceptor acceptor;
    struct udpn_data *udpns;

    struct selector_s *sel;

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
    bool in_shutdown;

    struct addrinfo    *ai;		/* The address list for the portname. */
    struct opensocks   *fds;		/* The file descriptor used for
					   the UDP ports. */
    unsigned int   nr_fds;
    unsigned int   nr_accept_close_waiting;

    unsigned int read_disable_count;
    unsigned int write_disable_count;
};

#define acc_to_nadata(acc) container_of(acc, struct udpna_data, acceptor);

static void udpna_deferred_op(sel_runner_t *runner, void *cbdata);

static void
udpna_fd_read_enable(struct udpna_data *nadata) {
    unsigned int i;

    assert(nadata->read_disable_count > 0);
    nadata->read_disable_count--;
    if (nadata->read_disable_count == 0) {
	for (i = 0; i < nadata->nr_fds; i++)
	    sel_set_fd_read_handler(nadata->sel, nadata->fds[i].fd,
				    SEL_FD_HANDLER_ENABLED);
    }
}

static void
udpna_fd_read_disable(struct udpna_data *nadata) {
    unsigned int i;

    if (nadata->read_disable_count == 0) {
	for (i = 0; i < nadata->nr_fds; i++)
	    sel_set_fd_read_handler(nadata->sel, nadata->fds[i].fd,
				    SEL_FD_HANDLER_DISABLED);
    }
    nadata->read_disable_count++;
}

static void
udpna_disable_write(struct udpna_data *nadata)
{
    unsigned int i;

    for (i = 0; i < nadata->nr_fds; i++)
	sel_set_fd_write_handler(nadata->sel, nadata->fds[i].fd,
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
	    sel_set_fd_write_handler(nadata->sel, nadata->fds[i].fd,
				     SEL_FD_HANDLER_ENABLED);
    }
}

static void udpna_do_free(struct udpna_data *nadata)
{
    unsigned int i;

    UNLOCK(nadata->lock);

    for (i = 0; i < nadata->nr_fds; i++)
	close(nadata->fds[i].fd);

    if (nadata->deferred_op_runner)
	sel_free_runner(nadata->deferred_op_runner);
    if (nadata->name)
	free(nadata->name);
    if (nadata->ai)
	freeaddrinfo(nadata->ai);
    if (nadata->fds)
	free(nadata->fds);
    if (nadata->read_data)
	free(nadata->read_data);
    free(nadata);
}

static void udpna_fd_cleared(int fd, void *cbdata)
{
    struct udpna_data *nadata = cbdata;

    LOCK(nadata->lock);
    if (--nadata->nr_accept_close_waiting == 0) {
	if (!nadata->deferred_op_pending) {
	    UNLOCK(nadata->lock);
	    udpna_do_free(nadata);
	    return;
	}
    }
    UNLOCK(nadata->lock);
}

static void udpna_check_finish_free(struct udpna_data *nadata)
{
    unsigned int i;

    if (!nadata->closed || nadata->in_new_connection || nadata->udpns ||
		nadata->pending_close_ndata || nadata->in_shutdown)
	return;

    nadata->nr_accept_close_waiting = nadata->nr_fds;
    for (i = 0; i < nadata->nr_fds; i++)
	sel_clear_fd_handlers(nadata->sel, nadata->fds[i].fd);
}

static int
udpn_write(struct netio *net, int *count,
	   const void *buf, unsigned int buflen)
{
    struct udpn_data *ndata = net_to_ndata(net);
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
    struct udpn_data *ndata = net_to_ndata(net);
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

static socklen_t
udpn_get_raddr(struct netio *net,
	       struct sockaddr *addr, socklen_t addrlen)
{
    struct udpn_data *ndata = net_to_ndata(net);

    if (addrlen > ndata->raddrlen)
	addrlen = ndata->raddrlen;

    memcpy(addr, ndata->raddr, addrlen);
    return addrlen;
}

static void
udpn_finish_close(struct udpna_data *nadata, struct udpn_data *ndata)
{
    struct netio *net = &ndata->net;

    if (net->cbs && net->cbs->close_done) {
	UNLOCK(nadata->lock);
	net->cbs->close_done(net);
	LOCK(nadata->lock);
    }

    if (nadata->data_pending && nadata->pending_data_owner == ndata)
	nadata->data_pending = false;
    
    udpna_check_finish_free(nadata);
    UNLOCK(nadata->lock);

    free(ndata);
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
	struct netio *net = &ndata->net;

	count = net->cbs->read_callback(net, 0,
					nadata->read_data + nadata->data_pos,
					nadata->data_pending_len, 0);
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

    if (nadata->in_shutdown && !nadata->in_new_connection) {
	struct netio_acceptor *acceptor = &nadata->acceptor;

	nadata->in_shutdown = false;
	if (acceptor->cbs->shutdown_done)
	    acceptor->cbs->shutdown_done(acceptor);
    }

    if (nadata->closed && nadata->nr_accept_close_waiting == 0) {
	udpna_do_free(nadata); /* Releases the lock */
    } else {
	nadata->deferred_op_pending = false;
	UNLOCK(nadata->lock);
    }
}

static void
udpn_close(struct netio *net)
{
    struct udpn_data *ndata = net_to_ndata(net);
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
    struct udpn_data *ndata = net_to_ndata(net);
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
  struct udpn_data *ndata = net_to_ndata(net);
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
    struct netio *net = &ndata->net;
    unsigned int count;

    if (!ndata->read_enabled)
	return;

    ndata->read_enabled = false;
    ndata->in_read = true;
    ndata->user_set_read_enabled = false;
    UNLOCK(nadata->lock);

    count = net->cbs->read_callback(net, 0, nadata->read_data,
				    nadata->data_pending_len, 0);

    LOCK(nadata->lock);
    udpn_finish_read(ndata, count);
}

static void
udpn_handle_write_incoming(struct udpna_data *nadata, struct udpn_data *ndata)
{
    struct netio *net = &ndata->net;

    ndata->in_write = true;
    UNLOCK(nadata->lock);
    net->cbs->write_callback(net);
    LOCK(nadata->lock);
    ndata->in_write = false;

    if (ndata->closed)
	udpn_add_to_closed(nadata, ndata);
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

static const struct netio_functions netio_udp_funcs = {
    .write = udpn_write,
    .raddr_to_str = udpn_raddr_to_str,
    .get_raddr = udpn_get_raddr,
    .close = udpn_close,
    .set_read_callback_enable = udpn_set_read_callback_enable,
    .set_write_callback_enable = udpn_set_write_callback_enable
};

static void
udpna_readhandler(int fd, void *cbdata)
{
    struct udpna_data *nadata = cbdata;
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
	/* FIXME - There is no really good way to report this error. */
	if (errno != EAGAIN && errno != EWOULDBLOCK)
	    syslog(LOG_ERR, "Could not accept on %s: %m", nadata->name);
	goto out_unlock;
    }
    if (addrlen > sizeof(struct sockaddr_storage)) {
	/* Shouldn't happen. */
	syslog(LOG_ERR, "Address too long on %s: %d", nadata->name, addrlen);
	goto out_unlock;
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
	    goto out_unlock;
	}
    }

    if (nadata->closed || !nadata->enabled) {
	nadata->data_pending = false;
	goto out_unlock_enable;
    }

    if (ndata) { /* Reuse an existing connection? */
	ndata->closed = false;
	ndata->read_enabled = false;
	ndata->in_read = false;
	ndata->in_write = false;
	ndata->user_set_read_enabled = false;
	ndata->net.cbs = NULL;
	ndata->net.user_data = NULL;
	goto restart_net;
    }

    /* New connection. */
    ndata = malloc(sizeof(*ndata));
    if (!ndata)
	goto out_nomem;
    memset(ndata, 0, sizeof(*ndata));

    ndata->nadata = nadata;
    ndata->raddr = (struct sockaddr *) &ndata->remote;

    ndata->net.funcs = &netio_udp_funcs;
    ndata->net.type = NETIO_TYPE_UDP;

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

    udpna_fd_write_disable(nadata);
    nadata->data_pending = true;
    nadata->pending_data_owner = ndata;
    nadata->in_new_connection = true;
    UNLOCK(nadata->lock);

    nadata->acceptor.cbs->new_connection(&nadata->acceptor, &ndata->net);

    LOCK(nadata->lock);
    nadata->in_new_connection = false;

    if (nadata->in_shutdown) {
	struct netio_acceptor *acceptor = &nadata->acceptor;

	nadata->in_shutdown = false;
	if (acceptor->cbs->shutdown_done)
	    acceptor->cbs->shutdown_done(acceptor);
    }
    udpna_check_finish_free(nadata);
    goto out_unlock;

 out_nomem:
    if (ndata)
	free(ndata);
    syslog(LOG_ERR, "Out of memory allocating for udp port %s", nadata->name);
 out_unlock_enable:
    udpna_fd_read_enable(nadata);
 out_unlock:
    UNLOCK(nadata->lock);
    return;

}

static int
udpna_startup(struct netio_acceptor *acceptor)
{
    struct udpna_data *nadata = acc_to_nadata(acceptor);
    int rv = 0;

    LOCK(nadata->lock);
    if (!nadata->fds) {
	nadata->fds = open_socket(nadata->sel, nadata->ai, udpna_readhandler,
				  udpna_writehandler,
				  nadata, &nadata->nr_fds, udpna_fd_cleared);
	if (nadata->fds == NULL) {
	    rv = errno;
	    goto out_unlock;
	}
    }

    nadata->setup = true;
    nadata->enabled = true;
 out_unlock:
    UNLOCK(nadata->lock);

    return rv;
}

static int
udpna_shutdown(struct netio_acceptor *acceptor)
{
    struct udpna_data *nadata = acc_to_nadata(acceptor);
    int rv = 0;

    LOCK(nadata->lock);
    if (nadata->enabled) {
	nadata->enabled = false;
	nadata->setup = false;
	nadata->in_shutdown = true;
	if (!nadata->in_new_connection && !nadata->deferred_op_pending) {
	    nadata->deferred_op_pending = true;
	    sel_run(nadata->deferred_op_runner, udpna_deferred_op, nadata);
	}
    } else {
	rv = EAGAIN;
    }
    UNLOCK(nadata->lock);
	
    return rv;
}

static void
udpna_set_accept_callback_enable(struct netio_acceptor *acceptor, bool enabled)
{
    struct udpna_data *nadata = acc_to_nadata(acceptor);

    LOCK(nadata->lock);
    nadata->enabled = true;
    UNLOCK(nadata->lock);
}

static void
udpna_free(struct netio_acceptor *acceptor)
{
    struct udpna_data *nadata = acc_to_nadata(acceptor);

    LOCK(nadata->lock);

    nadata->enabled = false;
    nadata->setup = false;
    nadata->closed = true;

    udpna_check_finish_free(nadata);
    UNLOCK(nadata->lock);
}

static const struct netio_acceptor_functions netio_acc_udp_funcs = {
    .startup = udpna_startup,
    .shutdown = udpna_shutdown,
    .set_accept_callback_enable = udpna_set_accept_callback_enable,
    .free = udpna_free
};

int
udp_netio_acceptor_alloc(const char *name,
			 struct selector_s *sel,
			 struct addrinfo *ai,
			 unsigned int max_read_size,
			 const struct netio_acceptor_callbacks *cbs,
			 void *user_data,
			 struct netio_acceptor **acceptor)
{
    int err = ENOMEM;
    struct netio_acceptor *acc;
    struct udpna_data *nadata;

    nadata = malloc(sizeof(*nadata));
    if (!nadata)
	goto out_err;
    memset(nadata, 0, sizeof(*nadata));
    nadata->sel = sel;

    nadata->name = strdup(name);
    if (!nadata->name)
	goto out_err;

    nadata->read_data = malloc(max_read_size);
    if (!nadata->read_data)
	goto out_err;

    err = sel_alloc_runner(nadata->sel, &nadata->deferred_op_runner);
    if (err)
	goto out_err;

    acc = &nadata->acceptor;
    acc->cbs = cbs;
    acc->user_data = user_data;
    acc->funcs = &netio_acc_udp_funcs;
    acc->type = NETIO_TYPE_UDP;

    INIT_LOCK(nadata->lock);
    nadata->ai = ai;
    nadata->max_read_size = max_read_size;

    *acceptor = acc;
    return 0;

 out_err:
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

int
udp_netio_alloc(struct addrinfo *ai,
		struct selector_s *sel,
		unsigned int max_read_size,
		const struct netio_callbacks *cbs,
		void *user_data,
		struct netio **new_netio)
{
    struct udpn_data *ndata = NULL;
    struct netio_acceptor *acceptor;
    struct udpna_data *nadata = NULL;
    int err;
    int new_fd;

    if (ai->ai_addrlen > sizeof(struct sockaddr_storage))
	return EINVAL;

    new_fd = socket(ai->ai_family, SOCK_DGRAM, 0);
    if (new_fd == -1)
	return errno;

    if (fcntl(new_fd, F_SETFL, O_NONBLOCK) == -1) {
	err = errno;
	close(new_fd);
	return err;
    }

    ndata = malloc(sizeof(*ndata));
    if (!ndata)
	return ENOMEM;
    memset(ndata, 0, sizeof(*ndata));

    /* Allocate a dummy network acceptor. */
    err = udp_netio_acceptor_alloc("dummy", sel, NULL, max_read_size,
				   NULL, NULL, &acceptor);
    if (err) {
	close(new_fd);
	free(ndata);
	return err;
    }
    nadata = acc_to_nadata(acceptor);

    nadata->fds = malloc(sizeof(*nadata->fds));
    if (!nadata->fds) {
	close(new_fd);
	free(ndata);
	udpna_do_free(nadata);
	return ENOMEM;
    }
    nadata->fds->family = ai->ai_family;
    nadata->fds->fd = new_fd;
    nadata->nr_fds = 1;

    nadata->closed = true; /* Free nadata when ndata is closed. */

    ndata->nadata = nadata;
    nadata->udpns = ndata;

    ndata->raddr = (struct sockaddr *) &ndata->remote;
    memcpy(ndata->raddr, ai->ai_addr, ai->ai_addrlen);
    ndata->raddrlen = ai->ai_addrlen;

    ndata->net.funcs = &netio_udp_funcs;
    ndata->net.type = NETIO_TYPE_UDP;

    ndata->myfd = new_fd;

    err = sel_set_fd_handlers(nadata->sel, new_fd, nadata,
			      udpna_readhandler, udpna_writehandler, NULL,
			      udpna_fd_cleared);
    if (err) {
	close(new_fd);
	free(ndata);
	udpna_do_free(nadata);
    } else {
	*new_netio = &ndata->net;
    }

    return err;
}
