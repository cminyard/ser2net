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
#include <assert.h>

#include "genio.h"
#include "genio_internal.h"
#include "utils/locking.h"

struct tcpn_data {
    struct genio net;

    struct genio_os_funcs *o;

    struct genio_lock *lock;

    int fd;
    bool write_enabled;
    bool read_enabled;
    bool in_read;
    unsigned int refcount;

    bool in_open;
    void (*open_done)(struct genio *io, int err, void *open_data);
    void *open_data;

    bool open;
    int open_err;
    bool in_close;
    bool close_ready;
    void (*close_done)(struct genio *net, void *close_data);
    void *close_data;

    unsigned int data_pending_len;
    unsigned int data_pos;

    /* Maximum value of the read buffer, set by the user at alloc time. */
    unsigned int max_read_size;

    /* The buffer used by read, allocated to max_read_size. */
    unsigned char *read_data;

    /*
     * Used to run read callbacks from the selector to avoid running
     * it directly from user calls.
     */
    bool deferred_op_pending;
    struct genio_runner *deferred_op_runner;

    struct sockaddr_storage remote;	/* The socket address of who
					   is connected to this port. */
    struct sockaddr *raddr;		/* Points to remote, for convenience. */
    socklen_t raddrlen;

    struct addrinfo *ai;
    struct addrinfo *curr_ai;
};

#define net_to_ndata(net) container_of(net, struct tcpn_data, net);

static void
tcpn_finish_free(struct tcpn_data *ndata)
{
    if (ndata->deferred_op_runner)
	ndata->o->free_runner(ndata->deferred_op_runner);
    if (ndata->read_data)
	ndata->o->free(ndata->o, ndata->read_data);
    if (ndata->ai)
	genio_free_addrinfo(ndata->o, ndata->ai);
    if (ndata->lock)
	ndata->o->free_lock(ndata->lock);
    ndata->o->free(ndata->o, ndata);
}

static void
tcpn_lock(struct tcpn_data *ndata)
{
    ndata->o->lock(ndata->lock);
}

static void
tcpn_unlock(struct tcpn_data *ndata)
{
    ndata->o->unlock(ndata->lock);
}

static void
tcpn_ref(struct tcpn_data *ndata)
{
    ndata->refcount++;
}

static void
tcpn_lock_and_ref(struct tcpn_data *ndata)
{
    tcpn_lock(ndata);
    ndata->refcount++;
}

static void
tcpn_deref_and_unlock(struct tcpn_data *ndata)
{
    unsigned int count;

    assert(ndata->refcount > 0);
    count = --ndata->refcount;
    tcpn_unlock(ndata);
    if (count == 0)
	tcpn_finish_free(ndata);
}

static void
tcpn_start_close(struct tcpn_data *ndata)
{
    ndata->open = false;
    ndata->in_close = true;
    ndata->o->clear_fd_handlers(ndata->o, ndata->fd);
}

static void
tcpn_finish_open(struct tcpn_data *ndata, int err)
{
    if (err) {
	ndata->open_err = err;
	tcpn_start_close(ndata);
	return;
    }

    if (ndata->open_done) {
	tcpn_unlock(ndata);
	ndata->open_done(&ndata->net, 0, ndata->open_data);
	tcpn_lock(ndata);
    }
    ndata->in_open = false;

    if (ndata->open) {
	if (ndata->read_enabled) {
	    ndata->o->set_read_handler(ndata->o, ndata->fd, true);
	    ndata->o->set_except_handler(ndata->o, ndata->fd, true);
	}
	if (ndata->write_enabled)
	    ndata->o->set_write_handler(ndata->o, ndata->fd, true);
    }
}

static void tcpn_finish_close(struct tcpn_data *ndata)
{
    ndata->in_close = false;
    if (ndata->close_done) {
	tcpn_unlock(ndata);
	ndata->close_done(&ndata->net, ndata->close_data);
	tcpn_lock(ndata);
	ndata->close_done = NULL;
    }
}

/* Must be called with ndata->lock held */
static void
tcpn_finish_read(struct tcpn_data *ndata, int err)
{
    struct genio *net = &ndata->net;
    unsigned int count;

    if (err)
	/*
	 * Change this here, not later, so the user can modify it.
	 */
	ndata->read_enabled = false;

    if (ndata->open) {
	tcpn_unlock(ndata);
	count = net->cbs->read_callback(net, err,
					ndata->read_data + ndata->data_pos,
					ndata->data_pending_len, 0);
	tcpn_lock(ndata);
	if (!err && count < ndata->data_pending_len) {
	    /* If the user doesn't consume all the data, disable
	       automatically. */
	    ndata->data_pending_len -= count;
	    ndata->data_pos += count;
	    ndata->read_enabled = false;
	} else {
	    ndata->data_pending_len = 0;
	}
    }

    ndata->in_read = false;

    if (ndata->close_ready) {
	ndata->close_ready = false;
	tcpn_finish_close(ndata);
    } else if (ndata->open && ndata->read_enabled) {
	ndata->o->set_read_handler(ndata->o, ndata->fd, true);
	ndata->o->set_except_handler(ndata->o, ndata->fd, true);
    }
}

static void
tcpn_deferred_op(struct genio_runner *runner, void *cbdata)
{
    struct tcpn_data *ndata = cbdata;

    tcpn_lock(ndata);
    ndata->deferred_op_pending = false;

    if (ndata->in_read)
	tcpn_finish_read(ndata, 0);

    tcpn_deref_and_unlock(ndata);
}

static void
tcpn_start_deferred_op(struct tcpn_data *ndata)
{
    if (!ndata->deferred_op_pending) {
	tcpn_ref(ndata);
	ndata->deferred_op_pending = true;
	ndata->o->run(ndata->deferred_op_runner);
    }
}

static int
tcpn_write(struct genio *net, unsigned int *count,
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
tcpn_raddr_to_str(struct genio *net, int *epos,
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
tcpn_get_raddr(struct genio *net,
	       struct sockaddr *addr, socklen_t addrlen)
{
    struct tcpn_data *ndata = net_to_ndata(net);

    if (addrlen > ndata->raddrlen)
	addrlen = ndata->raddrlen;

    memcpy(addr, ndata->raddr, addrlen);
    return addrlen;
}

static void
tcpn_handle_incoming(int fd, void *cbdata, bool urgent)
{
    struct tcpn_data *ndata = cbdata;
    struct genio *net = &ndata->net;
    int c;
    int rv, err = 0;

    tcpn_lock(ndata);
    if (!ndata->read_enabled || ndata->in_read || ndata->data_pending_len) {
	/* We can race here, just giving up should be fine. */
	tcpn_unlock(ndata);
	return;
    }
    tcpn_ref(ndata);
    ndata->o->set_read_handler(ndata->o, ndata->fd, false);
    ndata->o->set_except_handler(ndata->o, ndata->fd, false);
    ndata->in_read = true;
    ndata->data_pos = 0;
    tcpn_unlock(ndata);

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
	    err = errno;
    } else if (rv == 0) {
	err = EPIPE;
    } else {
	ndata->data_pending_len = rv;
    }

    tcpn_lock(ndata);
    tcpn_finish_read(ndata, err);
    tcpn_deref_and_unlock(ndata);
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
    struct genio *net = &ndata->net;

    tcpn_lock_and_ref(ndata);
    if (ndata->in_open) {
	int optval, err;
	socklen_t len = sizeof(optval);

	err = getsockopt(fd, SOL_SOCKET, SO_ERROR, &optval, &len);
	if (err) {
	    tcpn_finish_open(ndata, errno);
	    goto out_unlock;
	}

	err = optval;
	if (err) {
	retry:
	    ndata->curr_ai = ndata->curr_ai->ai_next;
	    if (ndata->curr_ai) {
		struct addrinfo *ai = ndata->curr_ai;

		err = connect(ndata->fd, ai->ai_addr, ai->ai_addrlen);
		if (err == 0)
		    goto connected;
		if (errno != EINPROGRESS)
		    goto retry;
		goto out_unlock;
	    }
	}
    connected:
	tcpn_finish_open(ndata, err);
	goto out_unlock;
    }

    tcpn_unlock(ndata);
    net->cbs->write_callback(net);
    tcpn_lock(ndata);

 out_unlock:
    tcpn_deref_and_unlock(ndata);
}

static void
tcpn_except_ready(int fd, void *cbdata)
{
    tcpn_handle_incoming(fd, cbdata, true);
}

static void
tcpn_fd_cleared(int fd, void *cbdata)
{
    struct tcpn_data *ndata = cbdata;

    tcpn_lock_and_ref(ndata);
    close(ndata->fd);
    if (ndata->in_open) {
	/* If an open fails, it comes to here. */
	ndata->in_open = false;
	if (ndata->open_done) {
	    tcpn_unlock(ndata);
	    ndata->open_done(&ndata->net, ndata->open_err, ndata->open_data);
	    tcpn_lock(ndata);
	    ndata->open_done = NULL;
	}
    }

    if (ndata->in_read)
	/* Call it from the read handler. */
	ndata->close_ready = true;
    else
	tcpn_finish_close(ndata);

    tcpn_deref_and_unlock(ndata);
}

static int
tcpn_finish_setup(struct tcpn_data *ndata, int new_fd,
		  struct sockaddr *addr, socklen_t addrlen)
{
    int optval;

    if (fcntl(new_fd, F_SETFL, O_NONBLOCK) == -1)
	return errno;

    optval = 1;
    if (setsockopt(new_fd, SOL_SOCKET, SO_KEEPALIVE,
		   (void *)&optval, sizeof(optval)) == -1)
	return errno;

    if (ndata->o->set_fd_handlers(ndata->o, new_fd, ndata, tcpn_read_ready,
				  tcpn_write_ready, tcpn_except_ready,
				  tcpn_fd_cleared))
	return ENOMEM;

    ndata->raddr = (struct sockaddr *) &ndata->remote;
    ndata->raddrlen = addrlen;
    memcpy(ndata->raddr, addr, addrlen);

    ndata->fd = new_fd;
    ndata->open = true;

    return 0;
}

static int
tcpn_open(struct genio *net, void (*open_done)(struct genio *net,
					       int err,
					       void *open_data),
	  void *open_data)
{
    struct tcpn_data *ndata = net_to_ndata(net);
    struct addrinfo *ai = ndata->ai;
    int new_fd;
    int err = EBUSY;

    if (!ndata->net.is_client)
	/* Only allow opens on client sockets. */
	return ENOTSUP;

    tcpn_lock(ndata);
    if (ndata->open || ndata->in_close)
	goto out_unlock;

    new_fd = socket(ai->ai_family, SOCK_STREAM, 0);
    if (new_fd == -1) {
	err = errno;
	goto out_unlock;
    }

    err = tcpn_finish_setup(ndata, new_fd, ai->ai_addr, ai->ai_addrlen);
    if (err)
	goto out_unlock;

 retry:
    ndata->curr_ai = ai;
    err = connect(new_fd, ai->ai_addr, ai->ai_addrlen);
    if (err == -1) {
	err = errno;
	if (err == EINPROGRESS)
	    err = 0;
    } else {
	err = 0;
    }

    if (err) {
	ai = ai->ai_next;
	if (ai)
	    goto retry;
	ndata->o->clear_fd_handlers_imm(ndata->o, new_fd);
	goto out_unlock;
    }

    memcpy(ndata->raddr, ai->ai_addr, ai->ai_addrlen);
    ndata->raddrlen = ai->ai_addrlen;
 out_unlock:
    if (err) {
	if (new_fd != -1) {
	    close(new_fd);
	    ndata->fd = -1;
	}
    } else {
	ndata->in_open = true;
	ndata->open_done = open_done;
	ndata->open_data = open_data;
	/* Report the open from the write callback handler. */
	ndata->o->set_write_handler(ndata->o, ndata->fd, true);
    }
    tcpn_unlock(ndata);

    return err;
}

static int
tcpn_close(struct genio *net, void (*close_done)(struct genio *net,
						 void *close_data),
	   void *close_data)
{
    struct tcpn_data *ndata = net_to_ndata(net);
    int err = EBUSY;

    tcpn_lock(ndata);
    if (ndata->open) {
	ndata->close_done = close_done;
	ndata->close_data = close_data;
	tcpn_start_close(ndata);
	err = 0;
    }
    tcpn_unlock(ndata);

    return err;
}

static void
tcpn_free(struct genio *net)
{
    struct tcpn_data *ndata = net_to_ndata(net);

    tcpn_lock(ndata);
    if (ndata->open) {
	tcpn_ref(ndata);
	tcpn_start_close(ndata);
    }
    tcpn_deref_and_unlock(ndata);
}

static void
tcpn_set_read_callback_enable(struct genio *net, bool enabled)
{
    struct tcpn_data *ndata = net_to_ndata(net);

    tcpn_lock(ndata);
    ndata->read_enabled = enabled;

    if (!ndata->open || ndata->in_read || ndata->in_open ||
			(ndata->data_pending_len && !enabled)) {
	/* It will be handled in finish_read or open finish. */
    } else if (ndata->data_pending_len) {
	ndata->in_read = true;
	/* Call the read from the selector to avoid lock nesting issues. */
	tcpn_start_deferred_op(ndata);
    } else {
	ndata->o->set_read_handler(ndata->o, ndata->fd, enabled);
    }
    tcpn_unlock(ndata);
}

static void
tcpn_set_write_callback_enable(struct genio *net, bool enabled)
{
    struct tcpn_data *ndata = net_to_ndata(net);

    tcpn_lock(ndata);
    ndata->write_enabled = enabled;
    if (!ndata->open || ndata->in_open)
	goto out_unlock;
    ndata->o->set_write_handler(ndata->o, ndata->fd, enabled);
 out_unlock:
    tcpn_unlock(ndata);
}

static const struct genio_functions genio_tcp_funcs = {
    .write = tcpn_write,
    .raddr_to_str = tcpn_raddr_to_str,
    .get_raddr = tcpn_get_raddr,
    .open = tcpn_open,
    .close = tcpn_close,
    .free = tcpn_free,
    .set_read_callback_enable = tcpn_set_read_callback_enable,
    .set_write_callback_enable = tcpn_set_write_callback_enable
};

static int
tcpn_alloc(struct genio_os_funcs *o,
	   unsigned int max_read_size,
	   struct tcpn_data **new_ndata)
{
    struct tcpn_data *ndata;

    ndata = o->zalloc(o, sizeof(*ndata));
    if (!ndata)
	goto out_nomem;
    ndata->o = o;

    ndata->deferred_op_runner = ndata->o->alloc_runner(ndata->o,
						       tcpn_deferred_op, ndata);
    if (!ndata->deferred_op_runner)
	goto out_nomem;

    ndata->lock = o->alloc_lock(o);
    if (!ndata->lock)
	goto out_nomem;
    tcpn_ref(ndata);

    ndata->max_read_size = max_read_size;
    ndata->read_data = o->zalloc(o, ndata->max_read_size);
    if (!ndata->read_data)
	goto out_nomem;

    ndata->net.funcs = &genio_tcp_funcs;
    ndata->net.type = GENIO_TYPE_TCP;

    *new_ndata = ndata;
    return 0;

 out_nomem:
    if (ndata)
	tcpn_finish_free(ndata);
    return ENOMEM;
}

struct tcpna_data {
    struct genio_acceptor acceptor;

    struct genio_os_funcs *o;

    char *name;

    unsigned int max_read_size;

    struct genio_lock *lock;

    bool setup;			/* Network sockets are allocated. */
    bool enabled;		/* Accepts are being handled. */
    bool in_shutdown;		/* Currently being shut down. */

    unsigned int refcount;

    void (*shutdown_done)(struct genio_acceptor *acceptor,
			  void *shutdown_data);
    void *shutdown_data;

    struct addrinfo    *ai;		/* The address list for the portname. */
    struct opensocks   *acceptfds;	/* The file descriptor used to
					   accept connections on the
					   TCP port. */
    unsigned int   nr_acceptfds;
    unsigned int   nr_accept_close_waiting;
};

#define acc_to_nadata(acc) container_of(acc, struct tcpna_data, acceptor);

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
tcpna_finish_free(struct tcpna_data *nadata)
{
    if (nadata->lock)
	nadata->o->free_lock(nadata->lock);
    if (nadata->name)
	nadata->o->free(nadata->o, nadata->name);
    if (nadata->ai)
	genio_free_addrinfo(nadata->o, nadata->ai);
    if (nadata->acceptfds)
	nadata->o->free(nadata->o, nadata->acceptfds);
    nadata->o->free(nadata->o, nadata);
}

static void
tcpna_lock(struct tcpna_data *nadata)
{
    nadata->o->lock(nadata->lock);
}

static void
tcpna_unlock(struct tcpna_data *nadata)
{
    nadata->o->unlock(nadata->lock);
}

static void
tcpna_ref(struct tcpna_data *nadata)
{
    nadata->refcount++;
}

static void
tcpna_deref_and_unlock(struct tcpna_data *nadata)
{
    unsigned int count;

    assert(nadata->refcount > 0);
    count = --nadata->refcount;
    tcpna_unlock(nadata);
    if (count == 0)
	tcpna_finish_free(nadata);
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

    errstr = genio_check_tcpd_ok(new_fd);
    if (errstr) {
	write_nofail(new_fd, errstr, strlen(errstr));
	close(new_fd);
	return;
    }

    err = tcpn_alloc(nadata->o, nadata->max_read_size, &ndata);
    if (err) {
	syslog(LOG_ERR, "Error allocating tcp port %s: %s", nadata->name,
	       strerror(err));
	close(new_fd);
    }

    err = tcpn_finish_setup(ndata, new_fd, (struct sockaddr *) &addr, addrlen);
    if (err) {
	syslog(LOG_ERR, "Error setting up tcp port %s: %s", nadata->name,
	       strerror(err));
	close(new_fd);
	tcpn_finish_free(ndata);
	return;
    }

    nadata->acceptor.cbs->new_connection(&nadata->acceptor, &ndata->net);
}

static void
tcpna_fd_cleared(int fd, void *cbdata)
{
    struct tcpna_data *nadata = cbdata;
    struct genio_acceptor *acceptor = &nadata->acceptor;
    unsigned int num_left;

    close(fd);

    tcpna_lock(nadata);
    num_left = --nadata->nr_accept_close_waiting;
    tcpna_unlock(nadata);

    if (num_left == 0) {
	if (nadata->shutdown_done)
	    nadata->shutdown_done(acceptor, nadata->shutdown_data);
	tcpna_lock(nadata);
	nadata->in_shutdown = false;
	tcpna_deref_and_unlock(nadata);
    }
}

static void
tcpna_set_fd_enables(struct tcpna_data *nadata, bool enable)
{
    unsigned int i;

    for (i = 0; i < nadata->nr_acceptfds; i++)
	nadata->o->set_read_handler(nadata->o, nadata->acceptfds[i].fd, enable);
}

static int
tcpna_startup(struct genio_acceptor *acceptor)
{
    struct tcpna_data *nadata = acc_to_nadata(acceptor);
    int rv = 0;

    tcpna_lock(nadata);
    if (nadata->in_shutdown || nadata->setup) {
	rv = EBUSY;
	goto out_unlock;
    }

    nadata->acceptfds = open_socket(nadata->o,
				    nadata->ai, tcpna_readhandler, NULL, nadata,
				    &nadata->nr_acceptfds, tcpna_fd_cleared);
    if (nadata->acceptfds == NULL) {
	rv = errno;
    } else {
	nadata->setup = true;
	tcpna_set_fd_enables(nadata, true);
	nadata->enabled = true;
	nadata->shutdown_done = NULL;
	tcpna_ref(nadata);
    }

 out_unlock:
    tcpna_unlock(nadata);
    return rv;
}

static void
_tcpna_shutdown(struct tcpna_data *nadata,
		void (*shutdown_done)(struct genio_acceptor *acceptor,
				      void *shutdown_data),
		void *shutdown_data)
{
    unsigned int i;

    nadata->in_shutdown = true;
    nadata->shutdown_done = shutdown_done;
    nadata->shutdown_data = shutdown_data;
    nadata->nr_accept_close_waiting = nadata->nr_acceptfds;
    for (i = 0; i < nadata->nr_acceptfds; i++)
	nadata->o->clear_fd_handlers(nadata->o, nadata->acceptfds[i].fd);
    nadata->setup = false;
    nadata->enabled = false;
}

static int
tcpna_shutdown(struct genio_acceptor *acceptor,
	       void (*shutdown_done)(struct genio_acceptor *acceptor,
				     void *shutdown_data),
	       void *shutdown_data)
{
    struct tcpna_data *nadata = acc_to_nadata(acceptor);
    int rv = 0;

    tcpna_lock(nadata);
    if (nadata->setup)
	_tcpna_shutdown(nadata, shutdown_done, shutdown_data);
    else
	rv = EBUSY;
    tcpna_unlock(nadata);

    return rv;
}

static void
tcpna_set_accept_callback_enable(struct genio_acceptor *acceptor, bool enabled)
{
    struct tcpna_data *nadata = acc_to_nadata(acceptor);

    tcpna_lock(nadata);
    if (nadata->enabled != enabled) {
	tcpna_set_fd_enables(nadata, enabled);
	nadata->enabled = enabled;
    }
    tcpna_unlock(nadata);
}

static void
tcpna_free(struct genio_acceptor *acceptor)
{
    struct tcpna_data *nadata = acc_to_nadata(acceptor);

    tcpna_lock(nadata);
    if (nadata->setup)
	_tcpna_shutdown(nadata, NULL, NULL);
    tcpna_deref_and_unlock(nadata);
}

int
tcpna_connect(struct genio_acceptor *acceptor, void *addr,
	      void (*connect_done)(struct genio *net, int err,
				   void *cb_data),
	      void *cb_data, struct genio **new_net)
{
    struct tcpna_data *nadata = acc_to_nadata(acceptor);
    struct genio *net;
    int err;

    err = tcp_genio_alloc(addr, nadata->o, nadata->max_read_size,
			  NULL, NULL, &net);
    if (err)
	return err;
    err = genio_open(net, connect_done, cb_data);
    if (!err)
	*new_net = net;
    return err;
}

static const struct genio_acceptor_functions genio_acc_tcp_funcs = {
    .startup = tcpna_startup,
    .shutdown = tcpna_shutdown,
    .set_accept_callback_enable = tcpna_set_accept_callback_enable,
    .free = tcpna_free,
    .connect = tcpna_connect
};

int
tcp_genio_acceptor_alloc(const char *name,
			 struct genio_os_funcs *o,
			 struct addrinfo *iai,
			 unsigned int max_read_size,
			 const struct genio_acceptor_callbacks *cbs,
			 void *user_data,
			 struct genio_acceptor **acceptor)
{
    struct genio_acceptor *acc;
    struct tcpna_data *nadata;
    struct addrinfo *ai = genio_dup_addrinfo(o, iai);

    if (!ai)
	return ENOMEM;

    nadata = o->zalloc(o, sizeof(*nadata));
    if (!nadata)
	goto out_nomem;

    nadata->o = o;
    tcpna_ref(nadata);

    nadata->lock = o->alloc_lock(o);
    if (!nadata->lock)
	goto out_nomem;

    nadata->name = genio_strdup(o, name);
    if (!nadata->name)
	goto out_nomem;

    acc = &nadata->acceptor;

    acc->cbs = cbs;
    acc->user_data = user_data;
    acc->funcs = &genio_acc_tcp_funcs;
    acc->type = GENIO_TYPE_TCP;

    nadata->ai = ai;
    nadata->max_read_size = max_read_size;

    *acceptor = acc;
    return 0;

 out_nomem:
    if (ai)
	genio_free_addrinfo(o, ai);
    if (nadata->lock)
	o->free_lock(nadata->lock);
    if (nadata) {
	if (nadata->name)
	    free(nadata->name);
	free(nadata);
    }
    return ENOMEM;
}

int
tcp_genio_alloc(struct addrinfo *iai,
		struct genio_os_funcs *o,
		unsigned int max_read_size,
		const struct genio_callbacks *cbs,
		void *user_data,
		struct genio **new_genio)
{
    struct tcpn_data *ndata = NULL;
    int err;
    struct addrinfo *ai;

    for (ai = iai; ai; ai = ai->ai_next) {
	if (ai->ai_addrlen > sizeof(struct sockaddr_storage))
	    return E2BIG;
    }

    ai = genio_dup_addrinfo(o, iai);
    if (!ai)
	return ENOMEM;

    err = tcpn_alloc(o, max_read_size, &ndata);
    if (err) {
	genio_free_addrinfo(o, ai);
	return err;
    }

    ndata->ai = ai;
    ndata->net.cbs = cbs;
    ndata->net.user_data = user_data;
    ndata->net.funcs = &genio_tcp_funcs;
    ndata->net.type = GENIO_TYPE_TCP;
    ndata->net.is_client = true;

    *new_genio = &ndata->net;
    return 0;
}
