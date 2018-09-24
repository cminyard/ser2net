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

/* This code handles TCP network I/O. */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

#include <utils/locking.h>

#include <gensio/gensio.h>
#include <gensio/gensio_internal.h>
#include <gensio/gensio_base.h>

struct tcp_data {
    struct gensio_os_funcs *o;

    struct sockaddr_storage remote;	/* The socket address of who
					   is connected to this port. */
    struct sockaddr *raddr;		/* Points to remote, for convenience. */
    socklen_t raddrlen;

    struct addrinfo *ai;
    struct addrinfo *curr_ai;
};

static int tcp_check_open(void *handler_data, int fd)
{
    int optval, err;
    socklen_t len = sizeof(optval);

    err = getsockopt(fd, SOL_SOCKET, SO_ERROR, &optval, &len);
    if (err)
	return errno;
    return 0;
}

static int
tcp_socket_setup(struct tcp_data *tdata, int fd)
{
    int optval = 1;

    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1)
	return errno;

    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,
		   (void *)&optval, sizeof(optval)) == -1)
	return errno;

    return 0;
}

static int
tcp_try_open(struct tcp_data *tdata, int *fd)
{
    int new_fd, err = EBUSY;
    struct addrinfo *ai = tdata->curr_ai;

    new_fd = socket(ai->ai_family, SOCK_STREAM, 0);
    if (new_fd == -1) {
	err = errno;
	goto out;
    }

    err = tcp_socket_setup(tdata, new_fd);
    if (err)
	goto out;

 retry:
    err = connect(new_fd, ai->ai_addr, ai->ai_addrlen);
    if (err == -1) {
	err = errno;
	if (err == EINPROGRESS) {
	    tdata->curr_ai = ai;
	    *fd = new_fd;
	    goto out_return;
	}
    } else {
	err = 0;
    }

    if (err) {
	ai = ai->ai_next;
	if (ai)
	    goto retry;
    } else {
	memcpy(tdata->raddr, ai->ai_addr, ai->ai_addrlen);
	tdata->raddrlen = ai->ai_addrlen;
    }
 out:
    if (err) {
	if (new_fd != -1)
	    close(new_fd);
    } else {
	*fd = new_fd;
    }

 out_return:
    return err;
}

static int
tcp_retry_open(void *handler_data, int *fd)
{
    struct tcp_data *tdata = handler_data;

    tdata->curr_ai = tdata->curr_ai->ai_next;
    return tcp_try_open(tdata, fd);
}

static int
tcp_sub_open(void *handler_data,
	     int (**check_open)(void *handler_data, int fd),
	     int (**retry_open)(void *handler_data, int *fd),
	     int *fd)
{
    struct tcp_data *tdata = handler_data;

    *check_open = tcp_check_open;
    *retry_open = tcp_retry_open;
    tdata->curr_ai = tdata->ai;
    return tcp_try_open(tdata, fd);
}

static int
tcp_raddr_to_str(void *handler_data, int *epos,
		 char *buf, unsigned int buflen)
{
    struct tcp_data *tdata = handler_data;
    char portstr[NI_MAXSERV];
    int err;
    int pos = 0;

    if (epos)
	pos = *epos;

    err = getnameinfo(tdata->raddr, tdata->raddrlen,
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
tcp_get_raddr(void *handler_data,
	      struct sockaddr *addr, socklen_t *addrlen)
{
    struct tcp_data *tdata = handler_data;

    if (*addrlen > tdata->raddrlen)
	*addrlen = tdata->raddrlen;

    memcpy(addr, tdata->raddr, *addrlen);
    return 0;
}

static void
tcp_free(void *handler_data)
{
    struct tcp_data *tdata = handler_data;

    if (tdata->ai)
	gensio_free_addrinfo(tdata->o, tdata->ai);
    tdata->o->free(tdata->o, tdata);
}

static const struct gensio_fd_ll_ops tcp_fd_ll_ops = {
    .sub_open = tcp_sub_open,
    .raddr_to_str = tcp_raddr_to_str,
    .get_raddr = tcp_get_raddr,
    .free = tcp_free
};

int
tcp_gensio_alloc(struct addrinfo *iai, char *args[],
		 struct gensio_os_funcs *o,
		 gensio_event cb, void *user_data,
		 struct gensio **new_gensio)
{
    struct tcp_data *tdata = NULL;
    struct addrinfo *ai;
    struct gensio_ll *ll;
    struct gensio *io;
    unsigned int max_read_size = GENSIO_DEFAULT_BUF_SIZE;
    int i;

    for (i = 0; args[i]; i++) {
	if (gensio_check_keyuint(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	return EINVAL;
    }

    for (ai = iai; ai; ai = ai->ai_next) {
	if (ai->ai_addrlen > sizeof(struct sockaddr_storage))
	    return E2BIG;
    }

    tdata = o->zalloc(o, sizeof(*tdata));
    if (!tdata)
	return ENOMEM;

    ai = gensio_dup_addrinfo(o, iai);
    if (!ai) {
	o->free(o, tdata);
	return ENOMEM;
    }

    tdata->o = o;
    tdata->ai = ai;
    tdata->raddr = (struct sockaddr *) &tdata->remote;

    ll = fd_gensio_ll_alloc(o, -1, &tcp_fd_ll_ops, tdata, max_read_size);
    if (!ll) {
	gensio_free_addrinfo(o, ai);
	o->free(o, tdata);
	return ENOMEM;
    }

    io = base_gensio_alloc(o, ll, NULL, "tcp", cb, user_data);
    if (!io) {
	ll->ops->free(ll);
	gensio_free_addrinfo(o, ai);
	o->free(o, tdata);
	return ENOMEM;
    }
    gensio_set_is_reliable(io, true);

    *new_gensio = io;
    return 0;
}

int
str_to_tcp_gensio(const char *str, char *args[],
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio **new_gensio)
{
    struct addrinfo *ai;
    int err;

    err = gensio_scan_netaddr(str, false, &ai);
    if (err)
	return err;

    err = tcp_gensio_alloc(ai, args, o, cb, user_data, new_gensio);
    freeaddrinfo(ai);

    return err;
}

struct tcpna_data {
    struct gensio_acceptor acceptor;

    struct gensio_os_funcs *o;

    unsigned int max_read_size;

    struct gensio_lock *lock;

    bool setup;			/* Network sockets are allocated. */
    bool enabled;		/* Accepts are being handled. */
    bool in_shutdown;		/* Currently being shut down. */

    unsigned int refcount;

    void (*shutdown_done)(struct gensio_acceptor *acceptor,
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
    if (nadata->ai)
	gensio_free_addrinfo(nadata->o, nadata->ai);
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

static const struct gensio_fd_ll_ops tcp_server_fd_ll_ops = {
    .raddr_to_str = tcp_raddr_to_str,
    .get_raddr = tcp_get_raddr,
    .free = tcp_free
};

static void
tcpna_readhandler(int fd, void *cbdata)
{
    struct tcpna_data *nadata = cbdata;
    int new_fd;
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    struct tcp_data *tdata = NULL;
    struct gensio_ll *ll;
    struct gensio *io;
    const char *errstr;
    int err;

    new_fd = accept(fd, (struct sockaddr *) &addr, &addrlen);
    if (new_fd == -1) {
	if (errno != EAGAIN && errno != EWOULDBLOCK)
	    gensio_acc_log(&nadata->acceptor, GENSIO_LOG_ERR,
			   "Could not accept: %s", strerror(errno));
	return;
    }

    errstr = gensio_check_tcpd_ok(new_fd);
    if (errstr) {
	write_nofail(new_fd, errstr, strlen(errstr));
	close(new_fd);
	return;
    }

    tdata = nadata->o->zalloc(nadata->o, sizeof(*tdata));
    if (!tdata) {
	errstr = "Out of memory\r\n";
	write_nofail(new_fd, errstr, strlen(errstr));
	close(new_fd);
	return;
    }

    tdata->o = nadata->o;
    tdata->raddr = (struct sockaddr *) &tdata->remote;
    memcpy(tdata->raddr, &addr, addrlen);
    tdata->raddrlen = addrlen;
    
    err = tcp_socket_setup(tdata, new_fd);
    if (err) {
	gensio_acc_log(&nadata->acceptor, GENSIO_LOG_ERR,
		       "Error setting up tcp port: %s", strerror(err));
	close(new_fd);
	tcp_free(tdata);
	return;
    }

    ll = fd_gensio_ll_alloc(nadata->o, new_fd, &tcp_server_fd_ll_ops, tdata,
			    nadata->max_read_size);
    if (!ll) {
	gensio_acc_log(&nadata->acceptor, GENSIO_LOG_ERR,
		       "Out of memory allocating tcp ll");
	close(new_fd);
	tcp_free(tdata);
	return;
    }

    io = base_gensio_server_alloc(nadata->o, ll, NULL, "tcp", NULL, NULL);
    if (!io) {
	gensio_acc_log(&nadata->acceptor, GENSIO_LOG_ERR,
		       "Out of memory allocating tcp base");
	ll->ops->free(ll);
	close(new_fd);
	tcp_free(tdata);
	return;
    }
    gensio_set_is_reliable(io, true);
    
    nadata->acceptor.cb(&nadata->acceptor, GENSIO_ACC_EVENT_NEW_CONNECTION, io);
}

static void
tcpna_fd_cleared(int fd, void *cbdata)
{
    struct tcpna_data *nadata = cbdata;
    struct gensio_acceptor *acceptor = &nadata->acceptor;
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
tcpna_startup(struct gensio_acceptor *acceptor)
{
    struct tcpna_data *nadata = acc_to_nadata(acceptor);
    int rv = 0;

    tcpna_lock(nadata);
    if (nadata->in_shutdown || nadata->setup) {
	rv = EBUSY;
	goto out_unlock;
    }

    nadata->acceptfds = gensio_open_socket(nadata->o,
					   nadata->ai,
					   tcpna_readhandler, NULL, nadata,
					   &nadata->nr_acceptfds,
					   tcpna_fd_cleared);
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
		void (*shutdown_done)(struct gensio_acceptor *acceptor,
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
tcpna_shutdown(struct gensio_acceptor *acceptor,
	       void (*shutdown_done)(struct gensio_acceptor *acceptor,
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
tcpna_set_accept_callback_enable(struct gensio_acceptor *acceptor, bool enabled)
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
tcpna_free(struct gensio_acceptor *acceptor)
{
    struct tcpna_data *nadata = acc_to_nadata(acceptor);

    tcpna_lock(nadata);
    if (nadata->setup)
	_tcpna_shutdown(nadata, NULL, NULL);
    tcpna_deref_and_unlock(nadata);
}

int
tcpna_connect(struct gensio_acceptor *acceptor, void *addr,
	      void (*connect_done)(struct gensio *net, int err,
				   void *cb_data),
	      void *cb_data, struct gensio **new_net)
{
    struct tcpna_data *nadata = acc_to_nadata(acceptor);
    struct gensio *net;
    int err;
    char *args[2] = { NULL, NULL };
    char buf[100];

    if (nadata->max_read_size != GENSIO_DEFAULT_BUF_SIZE) {
	snprintf(buf, 100, "readbuf=%d", nadata->max_read_size);
	args[0] = buf;
    }
    err = tcp_gensio_alloc(addr, args, nadata->o, NULL, NULL, &net);
    if (err)
	return err;
    err = gensio_open(net, connect_done, cb_data);
    if (!err)
	*new_net = net;
    return err;
}

static const struct gensio_acceptor_functions gensio_acc_tcp_funcs = {
    .startup = tcpna_startup,
    .shutdown = tcpna_shutdown,
    .set_accept_callback_enable = tcpna_set_accept_callback_enable,
    .free = tcpna_free,
    .connect = tcpna_connect
};

int
tcp_gensio_acceptor_alloc(struct addrinfo *iai,
			  char *args[],
			  struct gensio_os_funcs *o,
			  gensio_acceptor_event cb, void *user_data,
			  struct gensio_acceptor **acceptor)
{
    struct gensio_acceptor *acc;
    struct tcpna_data *nadata;
    struct addrinfo *ai;
    unsigned int max_read_size = GENSIO_DEFAULT_BUF_SIZE;
    int i;

    for (i = 0; args[i]; i++) {
	if (gensio_check_keyuint(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	return EINVAL;
    }

    ai = gensio_dup_addrinfo(o, iai);
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

    acc = &nadata->acceptor;

    acc->cb = cb;
    acc->user_data = user_data;
    acc->funcs = &gensio_acc_tcp_funcs;
    acc->typename = "tcp";
    gensio_acc_set_is_reliable(&nadata->acceptor, true);


    nadata->ai = ai;
    nadata->max_read_size = max_read_size;

    *acceptor = acc;
    return 0;

 out_nomem:
    if (ai)
	gensio_free_addrinfo(o, ai);
    if (nadata->lock)
	o->free_lock(nadata->lock);
    if (nadata)
	free(nadata);
    return ENOMEM;
}

int
str_to_tcp_gensio_acceptor(const char *str, char *args[],
			   struct gensio_os_funcs *o,
			   gensio_acceptor_event cb,
			   void *user_data,
			   struct gensio_acceptor **acc)
{
    int err;
    struct addrinfo *ai;

    err = gensio_scan_netaddr(str, false, &ai);
    if (err)
	return err;

    err = tcp_gensio_acceptor_alloc(ai, args, o, cb, user_data, acc);
    freeaddrinfo(ai);

    return err;
}
