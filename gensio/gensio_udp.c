/*
 *  gensio - A library for abstracting stream I/O
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
#include <assert.h>

#include <gensio/gensio.h>
#include <gensio/gensio_internal.h>

struct udpna_data;

struct udpn_data {
    struct gensio net;
    struct udpna_data *nadata;

    struct gensio_os_funcs *o;

    unsigned int refcount;

    int myfd; /* fd the original request came in on, for sending. */

    bool read_enabled;	/* Read callbacks are enabled. */
    bool write_enabled;	/* Write callbacks are enabled. */
    bool in_read;	/* Currently in a read callback. */
    bool in_write;	/* Currently in a write callback. */

    bool in_open;
    void (*open_done)(struct gensio *io, int err, void *open_data);
    void *open_data;

    bool in_close;	/* In the closing process, close_done is not called. */
    void (*close_done)(struct gensio *net, void *close_data);
    void *close_data;
    bool closed;	/* Has this net been closed? */
    bool in_free;	/* Free the data when closed? */

    bool deferred_op_pending;
    struct gensio_runner *deferred_op_runner;	/* NULL if not a client. */

    struct sockaddr_storage remote;	/* The socket address of who
					   is connected to this port. */
    struct sockaddr *raddr;		/* Points to remote, for convenience. */
    socklen_t raddrlen;

    struct udpn_data *next;
};

#define net_to_ndata(net) container_of(net, struct udpn_data, net);

struct udpna_data {
    struct gensio_acceptor acceptor;
    struct udpn_data *udpns;
    unsigned int udpn_count;

    struct gensio_os_funcs *o;

    struct gensio_lock *lock;

    unsigned int max_read_size;

    unsigned char *read_data;

    unsigned int data_pending_len;
    unsigned int data_pos;
    struct udpn_data *pending_data_owner;

    struct udpn_data *pending_close_ndata; /* Linked list. */
    struct udpn_data *closed_udpns;

    /*
     * Used to run read callbacks from the selector to avoid running
     * it directly from user calls.
     */
    bool deferred_op_pending;
    struct gensio_runner *deferred_op_runner;

    bool in_new_connection;

    bool setup;
    bool enabled;
    bool closed;
    bool in_shutdown;
    void (*shutdown_done)(struct gensio_acceptor *acceptor,
			  void *shutdown_data);
    void *shutdown_data;

    struct addrinfo    *ai;		/* The address list for the portname. */
    struct opensocks   *fds;		/* The file descriptor used for
					   the UDP ports. */
    unsigned int   nr_fds;
    unsigned int   nr_accept_close_waiting;

    bool in_write;
    unsigned int read_disable_count;
    unsigned int write_enable_count;
};

#define acc_to_nadata(acc) container_of(acc, struct udpna_data, acceptor);

static void
udpna_lock(struct udpna_data *nadata)
{
    nadata->o->lock(nadata->lock);
}

static void
udpna_unlock(struct udpna_data *nadata)
{
    nadata->o->unlock(nadata->lock);
}

static void udpna_deferred_op(struct gensio_runner *runner, void *cbdata);

static void udpna_start_deferred_op(struct udpna_data *nadata)
{
    if (!nadata->deferred_op_pending) {
	nadata->deferred_op_pending = true;
	nadata->o->run(nadata->deferred_op_runner);
    }
}

static void
udpn_remove_from_list(struct udpn_data **list, struct udpn_data *ndata)
{
    if (*list == ndata) {
	*list = ndata->next;
    } else {
	struct udpn_data *tndata = *list;

	while (tndata->next != ndata)
	    tndata = tndata->next;
	tndata->next = tndata->next->next;
    }
}

static struct udpn_data *
udpn_find(struct udpn_data **list,
	  struct sockaddr *addr, socklen_t addrlen,
	  bool remove)
{
    struct udpn_data *ndata = *list, *prev = NULL;

    while (ndata) {
	if (sockaddr_equal(ndata->raddr, ndata->raddrlen,
			   (struct sockaddr *) addr, addrlen, true)) {
	    if (remove) {
		if (!prev)
		    *list = ndata->next;
		else
		    prev->next = ndata->next;
	    }
	    break;
	}
	prev = ndata;
	ndata = ndata->next;
    }

    return ndata;
}

static void udpn_add_to_list(struct udpn_data **list, struct udpn_data *ndata)
{
    struct udpn_data *tndata;

    ndata->next = NULL;
    tndata = *list;
    if (!tndata)
	*list = ndata;
    else {
	while (tndata->next)
	    tndata = tndata->next;
	tndata->next = ndata;
    }
}

static void
udpna_enable_read(struct udpna_data *nadata)
{
    unsigned int i;

    for (i = 0; i < nadata->nr_fds; i++)
	nadata->o->set_read_handler(nadata->o, nadata->fds[i].fd, true);
}

static void
udpna_fd_read_enable(struct udpna_data *nadata)
{
    assert(nadata->read_disable_count > 0);
    nadata->read_disable_count--;
    if (nadata->read_disable_count == 0)
	udpna_enable_read(nadata);
}

static void
udpna_disable_read(struct udpna_data *nadata)
{
    unsigned int i;

    for (i = 0; i < nadata->nr_fds; i++)
	nadata->o->set_read_handler(nadata->o, nadata->fds[i].fd, false);
}

static void
udpna_fd_read_disable(struct udpna_data *nadata)
{
    if (nadata->read_disable_count == 0)
	udpna_disable_read(nadata);
    nadata->read_disable_count++;
}

static void
udpna_disable_write(struct udpna_data *nadata)
{
    unsigned int i;

    for (i = 0; i < nadata->nr_fds; i++)
	nadata->o->set_write_handler(nadata->o, nadata->fds[i].fd, false);
}

static void
udpna_fd_write_disable(struct udpna_data *nadata)
{
    assert(nadata->write_enable_count > 0);
    nadata->write_enable_count--;
    if (nadata->write_enable_count == 0 && !nadata->in_write)
	udpna_disable_write(nadata);
}

static void
udpna_enable_write(struct udpna_data *nadata)
{
    unsigned int i;

    for (i = 0; i < nadata->nr_fds; i++)
	nadata->o->set_write_handler(nadata->o, nadata->fds[i].fd, true);
}

static void
udpna_fd_write_enable(struct udpna_data *nadata)
{
    if (nadata->write_enable_count == 0 && !nadata->in_write)
	udpna_enable_write(nadata);
    nadata->write_enable_count++;
}

static void udpna_do_free(struct udpna_data *nadata)
{
    unsigned int i;

    for (i = 0; i < nadata->nr_fds; i++)
	close(nadata->fds[i].fd);

    if (nadata->deferred_op_runner)
	nadata->o->free_runner(nadata->deferred_op_runner);
    if (nadata->ai)
	gensio_free_addrinfo(nadata->o, nadata->ai);
    if (nadata->fds)
	nadata->o->free(nadata->o, nadata->fds);
    if (nadata->read_data)
	nadata->o->free(nadata->o, nadata->read_data);
    if (nadata->lock)
	nadata->o->free_lock(nadata->lock);
    nadata->o->free(nadata->o, nadata);
}

static void udpna_fd_cleared(int fd, void *cbdata)
{
    struct udpna_data *nadata = cbdata;

    udpna_lock(nadata);
    if (--nadata->nr_accept_close_waiting == 0) {
	if (!nadata->deferred_op_pending) {
	    udpna_unlock(nadata);
	    udpna_do_free(nadata);
	    return;
	}
    }
    udpna_unlock(nadata);
}

static void udpna_check_finish_free(struct udpna_data *nadata)
{
    unsigned int i;

    if (!nadata->closed || nadata->in_new_connection || nadata->udpn_count ||
		nadata->pending_close_ndata || nadata->in_shutdown)
	return;

    for (i = 0; i < nadata->nr_fds; i++)
	nadata->o->clear_fd_handlers(nadata->o, nadata->fds[i].fd);
}

static void udpn_finish_free(struct udpn_data *ndata)
{
    struct udpna_data *nadata = ndata->nadata;

    udpn_remove_from_list(&nadata->closed_udpns, ndata);
    nadata->udpn_count--;
    if (ndata->deferred_op_runner)
	ndata->o->free_runner(ndata->deferred_op_runner);
    ndata->o->free(ndata->o, ndata);
    udpna_check_finish_free(nadata);
}

static int
udpn_write(struct gensio *net, unsigned int *count,
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
udpn_raddr_to_str(struct gensio *net, int *epos,
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

static int
udpn_get_raddr(struct gensio *net,
	       struct sockaddr *addr, socklen_t *addrlen)
{
    struct udpn_data *ndata = net_to_ndata(net);

    if (*addrlen > ndata->raddrlen)
	*addrlen = ndata->raddrlen;

    memcpy(addr, ndata->raddr, *addrlen);
    return 0;
}

static void
udpn_finish_close(struct udpna_data *nadata, struct udpn_data *ndata)
{
    udpn_add_to_list(&nadata->closed_udpns, ndata);
    if (ndata->close_done) {
	void (*close_done)(struct gensio *net, void *close_data) =
	    ndata->close_done;
	void *close_data = ndata->close_data;

	ndata->close_done = NULL;
	udpna_unlock(nadata);
	close_done(&ndata->net, close_data);
	udpna_lock(nadata);
    }

    ndata->in_close = false;

    if (nadata->pending_data_owner == ndata) {
	nadata->pending_data_owner = NULL;
	nadata->data_pending_len = 0;
    }

    if (ndata->in_free)
	udpn_finish_free(ndata);
}

static void
udpn_add_to_closed(struct udpna_data *nadata, struct udpn_data *ndata)
{
    ndata->in_close = false;
    if (!ndata->read_enabled) {
	udpna_fd_read_enable(nadata);
    }
    if (ndata->write_enabled) {
	ndata->write_enabled = false;
	udpna_fd_write_disable(nadata);
    }

    udpn_remove_from_list(&nadata->udpns, ndata);
    udpn_add_to_list(&nadata->pending_close_ndata, ndata);

    udpna_start_deferred_op(nadata);
}

static void
udpn_finish_read(struct udpn_data *ndata)
{
    struct udpna_data *nadata = ndata->nadata;
    struct gensio *net = &ndata->net;
    unsigned int count;

 retry:
    udpna_unlock(nadata);
    count = nadata->data_pending_len;
    net->cb(net, GENSIO_EVENT_READ, 0, nadata->read_data, &count, 0, NULL);
    udpna_lock(nadata);

    if (ndata->closed)
	udpn_add_to_closed(nadata, ndata);

    nadata->pending_data_owner = NULL;

    if (count < nadata->data_pending_len) {
	/* The user didn't comsume all the data */
	nadata->data_pending_len -= count;
	nadata->data_pos += count;
	if (!ndata->closed && ndata->read_enabled)
	    goto retry;
    } else {
	nadata->data_pending_len = 0;
    }
    ndata->in_read = false;
}

static void
udpna_deferred_op(struct gensio_runner *runner, void *cbdata)
{
    struct udpna_data *nadata = cbdata;
    struct udpn_data *ndata = NULL;

    udpna_lock(nadata);

    while (nadata->pending_data_owner &&
			nadata->pending_data_owner->read_enabled)
	udpn_finish_read(nadata->pending_data_owner);

    while (nadata->pending_close_ndata) {
	ndata = nadata->pending_close_ndata;
	nadata->pending_close_ndata = ndata->next;
	udpn_finish_close(nadata, ndata);
    }

    if (nadata->in_shutdown && !nadata->in_new_connection) {
	struct gensio_acceptor *acceptor = &nadata->acceptor;

	if (nadata->shutdown_done) {
	    udpna_unlock(nadata);
	    nadata->shutdown_done(acceptor, nadata->shutdown_data);
	    udpna_lock(nadata);
	}
	nadata->in_shutdown = false;
	udpna_check_finish_free(nadata);
    }

    if (nadata->closed && nadata->nr_accept_close_waiting == 0) {
	udpna_unlock(nadata);
	udpna_do_free(nadata);
    } else {
	nadata->deferred_op_pending = false;
	udpna_unlock(nadata);
    }
}

static void
udpn_deferred_op(struct gensio_runner *runner, void *cbdata)
{
    struct udpn_data *ndata = cbdata;
    struct udpna_data *nadata = ndata->nadata;

    udpna_lock(nadata);
    if (ndata->in_open) {
	if (ndata->open_done) {
	    udpna_unlock(nadata);
	    ndata->open_done(&ndata->net, 0, ndata->open_data);
	    udpna_lock(nadata);
	}
	ndata->in_open = false;
	if (ndata->closed) {
	    udpn_add_to_closed(nadata, ndata);
	} else {
	    if (ndata->read_enabled && nadata->read_disable_count == 0)
		udpna_enable_read(nadata);
	    if (ndata->write_enabled)
		udpna_fd_write_enable(nadata);
	}
    }
    udpna_unlock(nadata);
}

static void udpn_start_deferred_op(struct udpn_data *ndata)
{
    if (!ndata->deferred_op_pending) {
	ndata->deferred_op_pending = true;
	ndata->o->run(ndata->deferred_op_runner);
    }
}

static int
udpn_open(struct gensio *net, void (*open_done)(struct gensio *net,
						int err,
						void *open_data),
	  void *open_data)
{
    struct udpn_data *ndata = net_to_ndata(net);
    struct udpna_data *nadata = ndata->nadata;
    int err = EBUSY;

    udpna_lock(nadata);
    if (!ndata->net.is_client) {
	err = ENOTTY;
    } else if (ndata->closed && !ndata->in_close) {
	udpn_remove_from_list(&nadata->closed_udpns, ndata);
	udpn_add_to_list(&nadata->udpns, ndata);
	ndata->closed = false;
	ndata->in_free = false;
	ndata->in_open = true;
	ndata->open_done = open_done;
	ndata->open_data = open_data;
	udpn_start_deferred_op(ndata);
	err = 0;
    }
    udpna_unlock(nadata);

    return err;
}

static void
udpn_start_close(struct udpn_data *ndata,
		 void (*close_done)(struct gensio *net, void *close_data),
		 void *close_data)
{
    struct udpna_data *nadata = ndata->nadata;

    if (nadata->pending_data_owner == ndata) {
	nadata->pending_data_owner = NULL;
	nadata->data_pending_len = 0;
    }
    ndata->in_close = true;
    ndata->closed = true;
    ndata->close_done = close_done;
    ndata->close_data = close_data;
    if (!ndata->in_read && !ndata->in_write && !ndata->in_open)
	udpn_add_to_closed(nadata, ndata);
}

static int
udpn_close(struct gensio *net, void (*close_done)(struct gensio *net,
						  void *close_data),
	   void *close_data)
{
    struct udpn_data *ndata = net_to_ndata(net);
    struct udpna_data *nadata = ndata->nadata;
    int err = EBUSY;

    udpna_lock(nadata);
    if (!ndata->closed) {
	udpn_start_close(ndata, close_done, close_data);
	err = 0;
    }
    udpna_unlock(nadata);

    return err;
}

static void
udpn_free(struct gensio *net)
{
    struct udpn_data *ndata = net_to_ndata(net);
    struct udpna_data *nadata = ndata->nadata;

    udpna_lock(nadata);
    assert(ndata->refcount > 0);
    if (--ndata->refcount > 0)
	goto out_unlock;

    if (ndata->in_close) {
	ndata->in_free = true;
	ndata->close_done = NULL;
    } else if (!ndata->closed) {
	ndata->in_free = true;
	udpn_start_close(ndata, NULL, NULL);
    } else {
	udpn_finish_free(ndata);
    }
 out_unlock:
    udpna_unlock(nadata);
}

static void
udpn_ref(struct gensio *net)
{
    struct udpn_data *ndata = net_to_ndata(net);
    struct udpna_data *nadata = ndata->nadata;

    udpna_lock(nadata);
    ndata->refcount++;
    udpna_unlock(nadata);
}

static void
udpn_set_read_callback_enable(struct gensio *net, bool enabled)
{
    struct udpn_data *ndata = net_to_ndata(net);
    struct udpna_data *nadata = ndata->nadata;
    bool my_data_pending;

    udpna_lock(nadata);
    if (ndata->closed || ndata->read_enabled == enabled)
	goto out_unlock;

    my_data_pending = (nadata->data_pending_len &&
		       nadata->pending_data_owner == ndata);
    if (enabled) {
	assert(nadata->read_disable_count > 0);
	nadata->read_disable_count--;
    } else {
	nadata->read_disable_count++;
    }
    ndata->read_enabled = enabled;
    if (ndata->in_read || ndata->in_open || (my_data_pending && !enabled)) {
	/* Nothing to do. */
    } else if (enabled && my_data_pending) {
	ndata->in_read = true;
	/* Call the read from the selector to avoid lock nesting issues. */
	udpna_start_deferred_op(nadata);
    } else {
	if (enabled && nadata->read_disable_count == 0)
	    udpna_enable_read(ndata->nadata);
	else if (!enabled && nadata->read_disable_count == 1)
	    udpna_disable_read(ndata->nadata);
    }
 out_unlock:
    udpna_unlock(nadata);
}

static void
udpn_set_write_callback_enable(struct gensio *net, bool enabled)
{
    struct udpn_data *ndata = net_to_ndata(net);
    struct udpna_data *nadata = ndata->nadata;

    udpna_lock(nadata);
    if (ndata->closed)
	goto out_unlock;
    if (ndata->write_enabled != enabled) {
	ndata->write_enabled = enabled;
	if (ndata->in_open)
	    goto out_unlock;
	if (enabled)
	    udpna_fd_write_enable(ndata->nadata);
	else
	    udpna_fd_write_disable(ndata->nadata);
    }
 out_unlock:
    udpna_unlock(nadata);
}

static void
udpn_handle_read_incoming(struct udpna_data *nadata, struct udpn_data *ndata)
{
    if (!ndata->read_enabled || ndata->in_read)
	return;

    ndata->in_read = true;
    udpn_finish_read(ndata);
}

static void
udpn_handle_write_incoming(struct udpna_data *nadata, struct udpn_data *ndata)
{
    struct gensio *net = &ndata->net;

    ndata->in_write = true;
    udpna_unlock(nadata);
    net->cb(net, GENSIO_EVENT_WRITE_READY, 0, NULL, NULL, 0, NULL);
    udpna_lock(nadata);
    ndata->in_write = false;

    if (ndata->closed)
	udpn_add_to_closed(nadata, ndata);
}

static void
udpna_writehandler(int fd, void *cbdata)
{
    struct udpna_data *nadata = cbdata;
    struct udpn_data *ndata;

    udpna_lock(nadata);
    if (nadata->in_write)
	goto out_unlock;

    udpna_disable_write(nadata);
    ndata = nadata->udpns;
    while (ndata) {
	if (ndata->write_enabled) {
	    udpn_handle_write_incoming(nadata, ndata);
	    /*
	     * Only handle one per callback, the above call releases
	     * the lock and can result in the list changing.
	     */
	    break;
	}
	ndata = ndata->next;
    }
    if (nadata->write_enable_count > 0)
	udpna_enable_write(nadata);
 out_unlock:
    udpna_unlock(nadata);
}

static const struct gensio_functions gensio_udp_funcs = {
    .write = udpn_write,
    .raddr_to_str = udpn_raddr_to_str,
    .get_raddr = udpn_get_raddr,
    .open = udpn_open,
    .close = udpn_close,
    .free = udpn_free,
    .ref = udpn_ref,
    .set_read_callback_enable = udpn_set_read_callback_enable,
    .set_write_callback_enable = udpn_set_write_callback_enable
};

static void
udpna_readhandler(int fd, void *cbdata)
{
    struct udpna_data *nadata = cbdata;
    struct udpn_data *ndata;
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);

    int datalen;

    udpna_lock(nadata);
    if (nadata->data_pending_len)
	goto out_unlock;

    datalen = recvfrom(fd, nadata->read_data, nadata->max_read_size, 0,
		       (struct sockaddr *) &addr, &addrlen);
    if (datalen == -1) {
	/* FIXME - There is no really good way to report this error. */
	if (errno != EAGAIN && errno != EWOULDBLOCK)
	    gensio_acc_log(&nadata->acceptor, GENSIO_LOG_ERR,
			   "Could not accept: %s", strerror(errno));
	goto out_unlock;
    }
    if (addrlen > sizeof(struct sockaddr_storage)) {
	/* Shouldn't happen. */
	gensio_acc_log(&nadata->acceptor, GENSIO_LOG_ERR,
		       "Address too long: %d", addrlen);
	goto out_unlock;
    }

    udpna_fd_read_disable(nadata);

    nadata->data_pending_len = datalen;
    nadata->data_pos = 0;

    ndata = udpn_find(&nadata->udpns,
		      (struct sockaddr *) &addr, addrlen, false);
    if (ndata) {
	/*
	 * Data belongs to an existing connection.
	 *
	 * The closed flag can be set here while the gensio is still
	 * in udpns, in that case it hasn't been shut down, but we
	 * will restart it.
	 */
	if (!ndata->closed) {
	    ndata->myfd = fd; /* Reset this on every read. */
	    nadata->pending_data_owner = ndata;
	    udpn_handle_read_incoming(nadata, ndata);
	    goto out_unlock_enable;
	}
    }

    if (nadata->closed || !nadata->enabled) {
	nadata->data_pending_len = 0;
	goto out_unlock_enable;
    }

    if (!ndata) {
	ndata = udpn_find(&nadata->pending_close_ndata,
			  (struct sockaddr *) &addr, addrlen, true);
	if (ndata) {
	    if (ndata->close_done) {
		void (*close_done)(struct gensio *net, void *close_data) =
		    ndata->close_done;
		void *close_data = ndata->close_data;

		ndata->close_done = NULL;
		udpna_unlock(nadata);
		close_done(&ndata->net, close_data);
		udpna_lock(nadata);
	    }
	} else {
	    ndata = udpn_find(&nadata->closed_udpns,
			      (struct sockaddr *) &addr, addrlen, true);
	}
	if (ndata)
	    udpn_add_to_list(&nadata->udpns, ndata);
    }

    if (ndata) { /* Reuse an existing connection? */
	ndata->in_free = false;
	ndata->in_close = false;
	ndata->closed = false;
	ndata->in_read = false;
	ndata->in_open = false;
	ndata->in_write = false;
	ndata->net.cb = NULL;
	ndata->net.user_data = NULL;
	goto restart_net;
    }

    /* New connection. */
    ndata = nadata->o->zalloc(nadata->o, sizeof(*ndata));
    if (!ndata)
	goto out_nomem;

    ndata->o = nadata->o;
    ndata->refcount = 1;
    ndata->nadata = nadata;
    ndata->raddr = (struct sockaddr *) &ndata->remote;

    ndata->net.funcs = &gensio_udp_funcs;
    ndata->net.typename = "udp";
    ndata->net.is_packet = false;
    ndata->net.is_reliable = true;

    /* Stick it on the end of the list. */
    udpn_add_to_list(&nadata->udpns, ndata);
    nadata->udpn_count++;

 restart_net:
    ndata->read_enabled = false;
    nadata->read_disable_count++;
    ndata->myfd = fd;
    ndata->raddrlen = addrlen;
    memcpy(ndata->raddr, &addr, addrlen);

    nadata->pending_data_owner = ndata;
    nadata->in_new_connection = true;
    ndata->in_read = true;
    udpna_unlock(nadata);

    nadata->acceptor.cb(&nadata->acceptor, GENSIO_ACC_EVENT_NEW_CONNECTION,
			&ndata->net);

    udpna_lock(nadata);
    ndata->in_read = false;
    nadata->in_new_connection = false;

    if (ndata->closed)
	udpn_add_to_closed(nadata, ndata);
    else
	udpn_handle_read_incoming(nadata, ndata);

    if (nadata->in_shutdown) {
	struct gensio_acceptor *acceptor = &nadata->acceptor;

	if (nadata->shutdown_done)
	    nadata->shutdown_done(acceptor, nadata->shutdown_data);
	nadata->in_shutdown = false;
    }
    udpna_check_finish_free(nadata);
    goto out_unlock_enable;

 out_nomem:
    nadata->data_pending_len = 0;
    gensio_acc_log(&nadata->acceptor, GENSIO_LOG_ERR,
		   "Out of memory allocating for udp port");
 out_unlock_enable:
    udpna_fd_read_enable(nadata);
 out_unlock:
    udpna_unlock(nadata);
    return;
}

static int
udpna_startup(struct gensio_acceptor *acceptor)
{
    struct udpna_data *nadata = acc_to_nadata(acceptor);
    int rv = 0;

    udpna_lock(nadata);
    if (!nadata->fds) {
	nadata->fds = gensio_open_socket(nadata->o, nadata->ai,
					 udpna_readhandler,
					 udpna_writehandler,
					 nadata, &nadata->nr_fds,
					 udpna_fd_cleared);
	if (nadata->fds == NULL) {
	    rv = errno;
	    goto out_unlock;
	}
	nadata->nr_accept_close_waiting = nadata->nr_fds;
    }

    nadata->setup = true;
    nadata->enabled = true;
    udpna_enable_read(nadata);
 out_unlock:
    udpna_unlock(nadata);

    return rv;
}

static int
udpna_shutdown(struct gensio_acceptor *acceptor,
	       void (*shutdown_done)(struct gensio_acceptor *acceptor,
				     void *shutdown_data),
	       void *shutdown_data)
{
    struct udpna_data *nadata = acc_to_nadata(acceptor);
    int rv = 0;

    udpna_lock(nadata);
    if (nadata->enabled) {
	nadata->enabled = false;
	nadata->setup = false;
	nadata->in_shutdown = true;
	nadata->shutdown_done = shutdown_done;
	nadata->shutdown_data = shutdown_data;
	if (!nadata->in_new_connection)
	    udpna_start_deferred_op(nadata);
    } else {
	rv = EAGAIN;
    }
    udpna_unlock(nadata);

    return rv;
}

static void
udpna_set_accept_callback_enable(struct gensio_acceptor *acceptor, bool enabled)
{
    struct udpna_data *nadata = acc_to_nadata(acceptor);

    udpna_lock(nadata);
    nadata->enabled = true;
    udpna_unlock(nadata);
}

static void
udpna_free(struct gensio_acceptor *acceptor)
{
    struct udpna_data *nadata = acc_to_nadata(acceptor);

    udpna_lock(nadata);

    nadata->enabled = false;
    nadata->setup = false;
    nadata->closed = true;

    udpna_check_finish_free(nadata);
    udpna_unlock(nadata);
}

int
udpna_connect(struct gensio_acceptor *acceptor, void *addr,
	      void (*connect_done)(struct gensio *net, int err,
				   void *cb_data),
	      void *cb_data, struct gensio **new_net)
{
    struct udpna_data *nadata = acc_to_nadata(acceptor);
    struct udpn_data *ndata;
    struct addrinfo *ai = gensio_dup_addrinfo(nadata->o, addr);
    unsigned int fdi;

    if (!ai)
	return ENOMEM;

    while (ai) {
	for (fdi = 0; fdi < nadata->nr_fds; fdi++) {
	    if (nadata->fds[fdi].family == ai->ai_addr->sa_family)
		goto found;
	}
	ai = ai->ai_next;
    }
    gensio_free_addrinfo(nadata->o, ai);
    return EINVAL;

 found:
    if (ai->ai_addrlen > sizeof(struct sockaddr_storage)) {
	gensio_free_addrinfo(nadata->o, ai);
	return EINVAL;
    }

    ndata = nadata->o->zalloc(nadata->o, sizeof(*ndata));
    if (!ndata) {
	gensio_free_addrinfo(nadata->o, ai);
	return ENOMEM;
    }
    ndata->o = nadata->o;
    ndata->refcount = 1;
    ndata->nadata = nadata;

    ndata->deferred_op_runner = ndata->o->alloc_runner(ndata->o,
						       udpn_deferred_op, ndata);
    if (!ndata->deferred_op_runner) {
	gensio_free_addrinfo(nadata->o, ai);
	return ENOMEM;
    }

    ndata->raddr = (struct sockaddr *) &ndata->remote;
    memcpy(ndata->raddr, ai->ai_addr, ai->ai_addrlen);
    ndata->raddrlen = ai->ai_addrlen;

    ndata->net.funcs = &gensio_udp_funcs;
    ndata->net.typename = "udp";
    ndata->myfd = nadata->fds[fdi].fd;
    ndata->net.is_packet = false;
    ndata->net.is_reliable = true;

    ndata->in_open = true;
    ndata->open_done = connect_done;
    ndata->open_data = cb_data;

    udpna_lock(nadata);
    udpn_add_to_list(&nadata->udpns, ndata);
    nadata->udpn_count++;
    udpn_start_deferred_op(ndata);
    nadata->read_disable_count++;
    udpna_unlock(nadata);

    *new_net = &ndata->net;

    return 0;
}

static const struct gensio_acceptor_functions gensio_acc_udp_funcs = {
    .startup = udpna_startup,
    .shutdown = udpna_shutdown,
    .set_accept_callback_enable = udpna_set_accept_callback_enable,
    .free = udpna_free,
    .connect = udpna_connect
};

int
udp_gensio_acceptor_alloc(struct addrinfo *iai, char *args[],
			  struct gensio_os_funcs *o,
			  gensio_acceptor_event cb, void *user_data,
			  struct gensio_acceptor **acceptor)
{
    int err = ENOMEM;
    struct gensio_acceptor *acc;
    struct udpna_data *nadata;
    struct addrinfo *ai;
    unsigned int max_read_size = GENSIO_DEFAULT_UDP_BUF_SIZE;
    int i;

    for (i = 0; args[i]; i++) {
	if (gensio_check_keyuint(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	return EINVAL;
    }

    ai = gensio_dup_addrinfo(o, iai);
    if (!ai && iai) /* Allow a null ai if it was passed in. */
	return ENOMEM;

    nadata = o->zalloc(o, sizeof(*nadata));
    if (!nadata)
	goto out_err;
    nadata->o = o;

    nadata->read_data = o->zalloc(o, max_read_size);
    if (!nadata->read_data)
	goto out_err;

    nadata->deferred_op_runner = o->alloc_runner(o, udpna_deferred_op, nadata);
    if (!nadata->deferred_op_runner)
	goto out_err;

    nadata->lock = o->alloc_lock(o);
    if (!nadata->lock)
	goto out_err;

    acc = &nadata->acceptor;
    acc->cb = cb;
    acc->user_data = user_data;
    acc->funcs = &gensio_acc_udp_funcs;
    acc->typename = "udp";
    acc->is_packet = true;
    acc->is_reliable = false;

    nadata->ai = ai;
    nadata->max_read_size = max_read_size;

    *acceptor = acc;
    return 0;

 out_err:
    if (ai)
	gensio_free_addrinfo(nadata->o, ai);
    if (nadata) {
	if (nadata->read_data)
	    o->free(o, nadata->read_data);
	if (nadata->deferred_op_runner)
	    nadata->o->free_runner(nadata->deferred_op_runner);
	if (nadata->lock)
	    nadata->o->free_lock(nadata->lock);
	o->free(o, nadata);
    }

    return err;
}

int
str_to_udp_gensio_acceptor(const char *str, char *args[],
			   struct gensio_os_funcs *o,
			   gensio_acceptor_event cb,
			   void *user_data,
			   struct gensio_acceptor **acc)
{
    int err;
    struct addrinfo *ai;

    err = gensio_scan_netaddr(str, true, &ai);
    if (err)
	return err;

    err = udp_gensio_acceptor_alloc(ai, args, o, cb, user_data, acc);
    freeaddrinfo(ai);

    return err;
}

int
udp_gensio_alloc(struct addrinfo *ai, char *args[],
		struct gensio_os_funcs *o,
		gensio_event cb, void *user_data,
		struct gensio **new_gensio)
{
    struct udpn_data *ndata = NULL;
    struct gensio_acceptor *acceptor;
    struct udpna_data *nadata = NULL;
    int err;
    int new_fd;
    unsigned int max_read_size = GENSIO_DEFAULT_UDP_BUF_SIZE;
    int i;

    for (i = 0; args[i]; i++) {
	if (gensio_check_keyuint(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	return EINVAL;
    }

    if (ai->ai_addrlen > sizeof(struct sockaddr_storage))
	return E2BIG;

    new_fd = socket(ai->ai_family, SOCK_DGRAM, 0);
    if (new_fd == -1)
	return errno;

    if (fcntl(new_fd, F_SETFL, O_NONBLOCK) == -1) {
	err = errno;
	close(new_fd);
	return err;
    }

    ndata = o->zalloc(o, sizeof(*ndata));
    if (!ndata)
	return ENOMEM;

    ndata->o = o;
    ndata->refcount = 1;

    /* Allocate a dummy network acceptor. */
    err = udp_gensio_acceptor_alloc(NULL, args, o,
				    NULL, NULL, &acceptor);
    if (err) {
	close(new_fd);
	o->free(o, ndata);
	return err;
    }
    nadata = acc_to_nadata(acceptor);

    nadata->fds = o->zalloc(o, sizeof(*nadata->fds));
    if (!nadata->fds) {
	close(new_fd);
	o->free(o, ndata);
	udpna_do_free(nadata);
	return ENOMEM;
    }
    nadata->fds->family = ai->ai_family;
    nadata->fds->fd = new_fd;
    nadata->nr_fds = 1;
    nadata->read_disable_count = 1;

    nadata->closed = true; /* Free nadata when ndata is freed. */

    ndata->nadata = nadata;
    ndata->closed = true; /* Start closed. */
    nadata->closed_udpns = ndata;
    nadata->udpn_count = 1;

    ndata->raddr = (struct sockaddr *) &ndata->remote;
    memcpy(ndata->raddr, ai->ai_addr, ai->ai_addrlen);
    ndata->raddrlen = ai->ai_addrlen;

    ndata->net.funcs = &gensio_udp_funcs;
    ndata->net.typename = "udp";
    ndata->net.is_client = true;
    ndata->net.is_packet = true;
    ndata->net.is_reliable = false;
    ndata->net.cb = cb;
    ndata->net.user_data = user_data;

    ndata->myfd = new_fd;

    err = ENOMEM;
    ndata->deferred_op_runner = o->alloc_runner(o, udpn_deferred_op, ndata);
    if (ndata->deferred_op_runner)
	err = o->set_fd_handlers(o, new_fd, nadata,
				 udpna_readhandler, udpna_writehandler, NULL,
				 udpna_fd_cleared);
    if (err) {
	close(new_fd);
	if (ndata->deferred_op_runner)
	    o->free_runner(ndata->deferred_op_runner);
	o->free(o, ndata);
	udpna_do_free(nadata);
    } else {
	nadata->nr_accept_close_waiting = 1;
	*new_gensio = &ndata->net;
    }

    return err;
}

int
str_to_udp_gensio(const char *str, char *args[],
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio **new_gensio)
{
    struct addrinfo *ai;
    int err;

    err = gensio_scan_netaddr(str, true, &ai);
    if (err)
	return err;

    err = udp_gensio_alloc(ai, args, o, cb, user_data, new_gensio);
    freeaddrinfo(ai);
    return err;
}
