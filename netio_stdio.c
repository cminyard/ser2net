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

/* This code handles stdio network I/O. */

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include "ser2net.h"

#include "netio.h"
#include "netio_internal.h"
#include "utils.h"
#include "locking.h"
#include "selector.h"

struct stdiona_data;

struct stdiona_data {
    DEFINE_LOCK(, lock);

    sel_runner_t *connect_runner;

    bool enabled;

    bool read_enabled;
    bool in_read;
    bool in_free;
    bool in_shutdown;
    bool report_shutdown;

    bool user_set_read_enabled;
    bool user_read_enabled_setting;

    unsigned int max_read_size;
    unsigned char *read_data;

    bool data_pending;
    unsigned int data_pending_len;
    unsigned int data_pos;

    /*
     * Used to run read callbacks from the selector to avoid running
     * it directly from user calls.
     */
    bool deferred_op_pending;
    sel_runner_t *deferred_op_runner;
    bool deferred_close; /* A close is pending the running running. */

    struct netio *net;
    struct netio_acceptor *acceptor;
};

static int
stdion_write(struct netio *net, int *count,
	     const void *buf, unsigned int buflen)
{
    int rv, err = 0;

 retry:
    rv = write(0, buf, buflen);
    if (rv < 0) {
	if (errno == EINTR)
	    goto retry;
	if (errno == EWOULDBLOCK || errno == EAGAIN)
	    rv = 0; /* Handle like a it wrote zero bytes. */
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
stdion_raddr_to_str(struct netio *net, int *epos,
		    char *buf, unsigned int buflen)
{
    int pos = 0;

    if (epos)
	pos = *epos;

    strncpy(buf + pos, "stdio", buflen - pos - 1);
    /* Fix stupid no-nil issue with strncpy. */
    buf[buflen - 1] = '\0';
    pos += strlen(buf + pos);

    if (epos)
	*epos = pos;

    return 0;
}

static void
stdion_finish_close(struct stdiona_data *nadata)
{
    struct netio *net = nadata->net;

    if (net->cbs->close_done)
	net->cbs->close_done(net);
}

/* Must be called with ndata->lock held */
static void
stdion_finish_read(struct stdiona_data *nadata, int err, unsigned int count)
{
    nadata->data_pending = false;
    if (err < 0) {
	nadata->user_set_read_enabled = true;
	nadata->user_read_enabled_setting = false;
    } else if (count < nadata->data_pending_len) {
	/* If the user doesn't consume all the data, disable
	   automatically. */
	nadata->data_pending = true;
	nadata->data_pending_len -= count;
	nadata->data_pos += count;
	nadata->user_set_read_enabled = true;
	nadata->user_read_enabled_setting = false;
    }

    nadata->in_read = false;

    if (nadata->user_set_read_enabled)
	nadata->read_enabled = nadata->user_read_enabled_setting;
    else
	nadata->read_enabled = true;

    if (nadata->read_enabled)
	sel_set_fd_read_handler(ser2net_sel, 0, SEL_FD_HANDLER_ENABLED);
}

static void
stdion_deferred_op(sel_runner_t *runner, void *cbdata)
{
    struct stdiona_data *nadata = cbdata;
    struct netio *net = nadata->net;
    unsigned int count;
    bool in_read;

    /* No lock needed, this data cannot be changed here. */
    LOCK(nadata->lock);
    in_read = nadata->in_read;
    UNLOCK(nadata->lock);

    if (in_read)
	count = net->cbs->read_callback(net, 0,
					nadata->read_data + nadata->data_pos,
					nadata->data_pending_len);
    LOCK(nadata->lock);
    nadata->deferred_op_pending = false;
    if (nadata->deferred_close) {
	UNLOCK(nadata->lock);
	stdion_finish_close(nadata);
	return;
    }
    if (in_read)
	stdion_finish_read(nadata, 0, count);
    UNLOCK(nadata->lock);
}

static void
stdion_close(struct netio *net)
{
    struct stdiona_data *nadata = net->internal_data;

    LOCK(nadata->lock);
    nadata->deferred_close = true;
    if (!nadata->deferred_op_pending) {
	nadata->deferred_op_pending = true;
	sel_run(nadata->deferred_op_runner, stdion_deferred_op, nadata);
    }
    UNLOCK(nadata->lock);
}

static void
stdion_set_read_callback_enable(struct netio *net, bool enabled)
{
    struct stdiona_data *nadata = net->internal_data;

    LOCK(nadata->lock);
    if (nadata->in_read || (nadata->data_pending && !enabled)) {
	nadata->user_set_read_enabled = true;
	nadata->user_read_enabled_setting = enabled;
    } else if (nadata->data_pending) {
	if (!nadata->deferred_op_pending) {
	    /* Call the read from the selector to avoid lock nesting issues. */
	    nadata->in_read = true;
	    nadata->deferred_op_pending = true;
	    sel_run(nadata->deferred_op_runner, stdion_deferred_op, nadata);
	}
    } else {
	int op;

	if (enabled)
	    op = SEL_FD_HANDLER_ENABLED;
	else
	    op = SEL_FD_HANDLER_DISABLED;

	nadata->read_enabled = true;
	sel_set_fd_read_handler(ser2net_sel, 0, op);
    }
    UNLOCK(nadata->lock);
}

static void
stdion_set_write_callback_enable(struct netio *net, bool enabled)
{
    int op;

    if (enabled)
	op = SEL_FD_HANDLER_ENABLED;
    else
	op = SEL_FD_HANDLER_DISABLED;

    sel_set_fd_write_handler(ser2net_sel, 0, op);
}

static void
stdion_read_ready(int fd, void *cbdata)
{
    struct stdiona_data *nadata = cbdata;
    struct netio *net = nadata->net;
    int rv;
    unsigned int count = 0;

    LOCK(nadata->lock);
    if (!nadata->read_enabled)
	goto out_unlock;
    nadata->read_enabled = false;
    sel_set_fd_read_handler(ser2net_sel, 0, SEL_FD_HANDLER_DISABLED);
    nadata->in_read = true;
    nadata->user_set_read_enabled = false;
    nadata->data_pos = 0;
    UNLOCK(nadata->lock);

 retry:
    rv = read(0, nadata->read_data, nadata->max_read_size);
    if (rv < 0) {
	if (errno == EINTR)
	    goto retry;
	if (errno == EAGAIN || errno == EWOULDBLOCK)
	    rv = 0; /* Pretend like nothing happened. */
	else
	    net->cbs->read_callback(net, errno, 0, 0);
    } else if (rv == 0) {
	net->cbs->read_callback(net, EPIPE, 0, 0);
	rv = -1;
    } else {
	nadata->data_pending_len = rv;
	count = net->cbs->read_callback(net, 0, nadata->read_data, rv);
    }

    LOCK(nadata->lock);
    stdion_finish_read(nadata, rv, count);
 out_unlock:
    UNLOCK(nadata->lock);
}

static void
stdion_write_ready(int fd, void *cbdata)
{
    struct stdiona_data *nadata = cbdata;
    struct netio *net = nadata->net;

    net->cbs->write_callback(net);
}

static int
stdiona_add_remaddr(struct netio_acceptor *acceptor, const char *str)
{
    return ENOTSUP;
}

static void
stdiona_do_connect(sel_runner_t *runner, void *cbdata)
{
    struct stdiona_data *nadata = cbdata;

    nadata->acceptor->cbs->new_connection(nadata->acceptor, nadata->net);
}

static void
stdiona_finish_free(struct stdiona_data *nadata)
{
    sel_free_runner(nadata->deferred_op_runner);
    sel_free_runner(nadata->connect_runner);

    free(nadata->net);
    free(nadata->read_data);
    free(nadata->acceptor);
    free(nadata);
}

static void stdiona_fd_cleared(int fd, void *cbdata)
{
    struct stdiona_data *nadata = cbdata;
    struct netio_acceptor *acceptor = nadata->acceptor;

    nadata->in_shutdown = false;
    if (acceptor->cbs->shutdown_done && nadata->report_shutdown)
	acceptor->cbs->shutdown_done(acceptor);

    if (nadata->in_free)
	stdiona_finish_free(nadata);
}


static int
stdiona_startup(struct netio_acceptor *acceptor)
{
    struct stdiona_data *nadata = acceptor->internal_data;
    int rv = 0;

    LOCK(nadata->lock);
    if (nadata->in_shutdown) {
	rv = EAGAIN;
	goto out_unlock;
    }
    if (!nadata->enabled) {
	rv = sel_set_fd_handlers(ser2net_sel, 0, nadata, stdion_read_ready,
				 stdion_write_ready, NULL, stdiona_fd_cleared);
	if (rv)
	    goto out_unlock;
	nadata->enabled = true;
	sel_run(nadata->connect_runner, stdiona_do_connect,
		acceptor->internal_data);
    }
 out_unlock:
    UNLOCK(nadata->lock);

    return rv;
}

static int
stdiona_shutdown(struct netio_acceptor *acceptor)
{
    struct stdiona_data *nadata = acceptor->internal_data;
    int rv = 0;

    LOCK(nadata->lock);
    if (nadata->enabled) {
	nadata->enabled = false;
	nadata->report_shutdown = true;
	nadata->in_shutdown = true;
	sel_clear_fd_handlers(ser2net_sel, 0);
    } else {
	rv = EAGAIN;
    }
    UNLOCK(nadata->lock);
    
    return rv;
}

static void
stdiona_set_accept_callback_enable(struct netio_acceptor *acceptor,
				   bool enabled)
{
}

static void
stdiona_free(struct netio_acceptor *acceptor)
{
    struct stdiona_data *nadata = acceptor->internal_data;

    LOCK(nadata->lock);
    nadata->in_free = true;
    if (nadata->enabled) {
	nadata->enabled = false;
	sel_clear_fd_handlers(ser2net_sel, 0);
    } else {
	UNLOCK(nadata->lock);
	stdiona_finish_free(nadata);
	return;
    }
    UNLOCK(nadata->lock);
}

int
stdio_netio_acceptor_alloc(unsigned int max_read_size,
			   const struct netio_acceptor_callbacks *cbs,
			   void *user_data,
			   struct netio_acceptor **acceptor)
{
    int err = 0;
    struct netio_acceptor *acc = NULL;
    struct stdiona_data *nadata = NULL;
    struct netio *net = NULL;

    acc = malloc(sizeof(*acc));
    if (!acc)
	goto out_nomem;
    memset(acc, 0, sizeof(*acc));

    nadata = malloc(sizeof(*nadata));
    if (!nadata)
	goto out_nomem;
    memset(nadata, 0, sizeof(*nadata));

    net = malloc(sizeof(*net));
    if (!net)
	goto out_nomem;
    memset(net, 0, sizeof(*net));

    nadata->max_read_size = max_read_size;
    nadata->read_data = malloc(max_read_size);
    if (!nadata->read_data)
	goto out_nomem;

    err = sel_alloc_runner(ser2net_sel, &nadata->deferred_op_runner);
    if (err)
	goto out;

    err = sel_alloc_runner(ser2net_sel, &nadata->connect_runner);
    if (err)
	goto out;

    acc->cbs = cbs;
    acc->user_data = user_data;

    acc->internal_data = nadata;
    acc->add_remaddr = stdiona_add_remaddr;
    acc->startup = stdiona_startup;
    acc->shutdown = stdiona_shutdown;
    acc->set_accept_callback_enable = stdiona_set_accept_callback_enable;
    acc->free = stdiona_free;

    INIT_LOCK(nadata->lock);
    nadata->acceptor = acc;

    nadata->net = net;
    net->internal_data = nadata;
    net->write = stdion_write;
    net->raddr_to_str = stdion_raddr_to_str;
    net->close = stdion_close;
    net->set_read_callback_enable = stdion_set_read_callback_enable;
    net->set_write_callback_enable = stdion_set_write_callback_enable;

    acc->exit_on_close = true;

 out:
    if (err) {
	if (acc)
	    free(acc);
	if (nadata) {
	    if (nadata->deferred_op_runner)
		sel_free_runner(nadata->deferred_op_runner);
	    if (nadata->connect_runner)
		sel_free_runner(nadata->connect_runner);
	    if (nadata->read_data)
		free(nadata->read_data);
	    free(nadata);
	}
	if (net)
	    free(net);
    } else {
	*acceptor = acc;
    }
    return err;

 out_nomem:
    err = ENOMEM;
    goto out;
}

#if 0
    if (port->is_stdio) {
	if (is_device_already_inuse(port)) {
	    if (eout)
		eout->out(eout, "Port's device already in use");
	    return -1;
	} else {
	    port->acceptfds = NULL;
	    port->netcons[0].fd = 0; /* stdin */
	    if (setup_port(port, &(port->netcons[0]), false) == -1)
		return -1;
	}
	return 0;
    }
#endif
