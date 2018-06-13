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
#include <fcntl.h>
#include "ser2net.h"

#include "netio.h"
#include "netio_internal.h"
#include "utils.h"
#include "locking.h"
#include "selector.h"

struct stdiona_data {
    DEFINE_LOCK(, lock);

    sel_runner_t *connect_runner;

    bool enabled;
    int old_flags;

    bool read_enabled;
    bool in_read;
    bool in_free;
    bool in_shutdown;
    bool report_shutdown;

    bool user_set_read_enabled;
    bool user_read_enabled_setting;

    /*
     * If non-zero, this is the PID of the other process and we are
     * in client mode.
     */
    int opid;

    /* In client mode, the other end of the stdio pipes from the client. */
    int ostdin;
    int ostdout;
    int ostderr;
    unsigned int oio_count;

    unsigned int max_read_size;
    unsigned char *read_data;
    unsigned int read_flags;

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

    struct netio net;
    struct netio_acceptor acceptor;
};

#define net_to_nadata(net) container_of(net, struct stdiona_data, net);
#define acc_to_nadata(acc) container_of(acc, struct stdiona_data, acceptor);

static int
stdion_write(struct netio *net, int *count,
	     const void *buf, unsigned int buflen)
{
    struct stdiona_data *nadata = net_to_nadata(net);
    int rv, err = 0;

 retry:
    rv = write(nadata->ostdin, buf, buflen);
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

static socklen_t
stdion_get_raddr(struct netio *net,
		 struct sockaddr *addr, socklen_t addrlen)
{
    return 0;
}

static void
stdion_finish_close(struct stdiona_data *nadata)
{
    struct netio *net = &nadata->net;

    if (net->cbs && net->cbs->close_done)
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

    if (nadata->read_enabled) {
	sel_set_fd_read_handler(ser2net_sel, nadata->ostdout,
				SEL_FD_HANDLER_ENABLED);
	if (nadata->ostderr != -1)
	    sel_set_fd_read_handler(ser2net_sel, nadata->ostderr,
				    SEL_FD_HANDLER_ENABLED);
    }
}

static void
stdion_deferred_op(sel_runner_t *runner, void *cbdata)
{
    struct stdiona_data *nadata = cbdata;
    struct netio *net = &nadata->net;
    unsigned int count;
    bool in_read;

    /* No lock needed, this data cannot be changed here. */
    LOCK(nadata->lock);
    in_read = nadata->in_read;
    UNLOCK(nadata->lock);

    if (in_read)
	count = net->cbs->read_callback(net, 0,
					nadata->read_data + nadata->data_pos,
					nadata->data_pending_len,
					nadata->read_flags);
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
    struct stdiona_data *nadata = net_to_nadata(net);

    LOCK(nadata->lock);
    nadata->deferred_close = true;
    if (nadata->opid) {
	sel_clear_fd_handlers(ser2net_sel, nadata->ostdin);
	sel_clear_fd_handlers(ser2net_sel, nadata->ostdout);
	sel_clear_fd_handlers(ser2net_sel, nadata->ostderr);
    } else if (!nadata->deferred_op_pending) {
	nadata->deferred_op_pending = true;
	sel_run(nadata->deferred_op_runner, stdion_deferred_op, nadata);
    }
    UNLOCK(nadata->lock);
}

static void
stdion_set_read_callback_enable(struct netio *net, bool enabled)
{
    struct stdiona_data *nadata = net_to_nadata(net);

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
	sel_set_fd_read_handler(ser2net_sel, nadata->ostdout, op);
	if (nadata->ostderr != -1)
	    sel_set_fd_read_handler(ser2net_sel, nadata->ostderr, op);
    }
    UNLOCK(nadata->lock);
}

static void
stdion_set_write_callback_enable(struct netio *net, bool enabled)
{
    struct stdiona_data *nadata = net_to_nadata(net);
    int op;

    if (enabled)
	op = SEL_FD_HANDLER_ENABLED;
    else
	op = SEL_FD_HANDLER_DISABLED;

    sel_set_fd_write_handler(ser2net_sel, nadata->ostdin, op);
}

static void
stdion_read_ready(int fd, void *cbdata)
{
    struct stdiona_data *nadata = cbdata;
    struct netio *net = &nadata->net;
    int rv;
    unsigned int count = 0;

    LOCK(nadata->lock);
    if (!nadata->read_enabled)
	goto out_unlock;
    nadata->read_enabled = false;
    sel_set_fd_read_handler(ser2net_sel, nadata->ostdout,
			    SEL_FD_HANDLER_DISABLED);
    if (nadata->ostderr != -1)
	sel_set_fd_read_handler(ser2net_sel, nadata->ostderr,
				SEL_FD_HANDLER_DISABLED);
    if (fd == nadata->ostderr)
	nadata->read_flags = NETIO_ERR_OUTPUT;
    else
	nadata->read_flags = 0;
    nadata->in_read = true;
    nadata->user_set_read_enabled = false;
    nadata->data_pos = 0;
    UNLOCK(nadata->lock);

 retry:
    rv = read(fd, nadata->read_data, nadata->max_read_size);
    if (rv < 0) {
	if (errno == EINTR)
	    goto retry;
	if (errno == EAGAIN || errno == EWOULDBLOCK)
	    rv = 0; /* Pretend like nothing happened. */
	else
	    net->cbs->read_callback(net, errno, 0, 0, nadata->read_flags);
    } else if (rv == 0) {
	net->cbs->read_callback(net, EPIPE, 0, 0, nadata->read_flags);
	rv = -1;
    } else {
	nadata->data_pending_len = rv;
	count = net->cbs->read_callback(net, 0, nadata->read_data, rv,
					nadata->read_flags);
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
    struct netio *net = &nadata->net;

    net->cbs->write_callback(net);
}

static void
stdiona_do_connect(sel_runner_t *runner, void *cbdata)
{
    struct stdiona_data *nadata = cbdata;

    nadata->acceptor.cbs->new_connection(&nadata->acceptor, &nadata->net);
}

static void
stdiona_finish_free(struct stdiona_data *nadata)
{
    if (nadata->deferred_op_runner)
	sel_free_runner(nadata->deferred_op_runner);
    if (nadata->connect_runner)
	sel_free_runner(nadata->connect_runner);
    if (nadata->read_data)
	free(nadata->read_data);
    free(nadata);
}

static void
stdiona_fd_cleared(int fd, void *cbdata)
{
    struct stdiona_data *nadata = cbdata;
    struct netio_acceptor *acceptor = &nadata->acceptor;

    fcntl(0, F_SETFL, nadata->old_flags);

    nadata->in_shutdown = false;
    if (acceptor->cbs->shutdown_done && nadata->report_shutdown)
	acceptor->cbs->shutdown_done(acceptor);

    if (nadata->in_free)
	stdiona_finish_free(nadata);
}


static int
stdiona_startup(struct netio_acceptor *acceptor)
{
    struct stdiona_data *nadata = acc_to_nadata(acceptor);
    int rv = 0;

    LOCK(nadata->lock);
    if (nadata->in_shutdown) {
	rv = EAGAIN;
	goto out_unlock;
    }
    if (!nadata->enabled) {
	rv = fcntl(0, F_GETFL, 0);
	if (rv == -1) {
	    rv = errno;
	    goto out_unlock;
	}
	nadata->old_flags = rv;
	if (fcntl(0, F_SETFL, O_NONBLOCK) == -1) {
	    rv = errno;
	    goto out_unlock;
	}

	rv = sel_set_fd_handlers(ser2net_sel, 0, nadata, stdion_read_ready,
				 stdion_write_ready, NULL, stdiona_fd_cleared);
	if (rv)
	    goto out_unlock;
	nadata->enabled = true;
	sel_run(nadata->connect_runner, stdiona_do_connect, nadata);
    }
 out_unlock:
    UNLOCK(nadata->lock);

    return rv;
}

static int
stdiona_shutdown(struct netio_acceptor *acceptor)
{
    struct stdiona_data *nadata = acc_to_nadata(acceptor);
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
    struct stdiona_data *nadata = acc_to_nadata(acceptor);

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

static const struct netio_functions netio_stdio_funcs = {
    .write = stdion_write,
    .raddr_to_str = stdion_raddr_to_str,
    .get_raddr = stdion_get_raddr,
    .close = stdion_close,
    .set_read_callback_enable = stdion_set_read_callback_enable,
    .set_write_callback_enable = stdion_set_write_callback_enable
};

static const struct netio_acceptor_functions netio_acc_stdio_funcs = {
    .startup = stdiona_startup,
    .shutdown = stdiona_shutdown,
    .set_accept_callback_enable = stdiona_set_accept_callback_enable,
    .free = stdiona_free
};

static int
stdio_nadata_setup(unsigned int max_read_size, struct stdiona_data **new_nadata)
{
    int err = 0;
    struct stdiona_data *nadata;

    nadata = malloc(sizeof(*nadata));
    if (!nadata)
	goto out_nomem;
    memset(nadata, 0, sizeof(*nadata));

    nadata->max_read_size = max_read_size;
    nadata->read_data = malloc(max_read_size);
    if (!nadata->read_data)
	goto out_nomem;

    err = sel_alloc_runner(ser2net_sel, &nadata->deferred_op_runner);
    if (err)
	goto out_err;

    err = sel_alloc_runner(ser2net_sel, &nadata->connect_runner);
    if (err)
	goto out_err;

    INIT_LOCK(nadata->lock);

    nadata->net.funcs = &netio_stdio_funcs;
    nadata->net.type = NETIO_TYPE_STDIO;

    *new_nadata = nadata;

    return 0;

 out_nomem:
    err = ENOMEM;

 out_err:
    if (nadata)
	stdiona_finish_free(nadata);

    return err;
}

int
stdio_netio_acceptor_alloc(unsigned int max_read_size,
			   const struct netio_acceptor_callbacks *cbs,
			   void *user_data,
			   struct netio_acceptor **acceptor)
{
    int err;
    struct netio_acceptor *acc;
    struct stdiona_data *nadata = NULL;

    err = stdio_nadata_setup(max_read_size, &nadata);
    if (err)
	return err;

    nadata->ostdin = 0;
    nadata->ostdout = 0;
    nadata->ostderr = -1;

    acc = &nadata->acceptor;
    acc->type = NETIO_TYPE_STDIO;

    acc->cbs = cbs;
    acc->user_data = user_data;
    acc->funcs = &netio_acc_stdio_funcs;

    *acceptor = acc;
    return 0;
}

static void
stdio_client_fd_cleared(int fd, void *cbdata)
{
    struct stdiona_data *nadata = cbdata;

    LOCK(nadata->lock);
    nadata->oio_count--;
    if (nadata->oio_count == 0) {
	UNLOCK(nadata->lock);
	stdion_finish_close(nadata);
	close(nadata->ostdin);
	close(nadata->ostdout);
	close(nadata->ostderr);
	stdiona_finish_free(nadata);
    } else {
	UNLOCK(nadata->lock);
    }
}

int
stdio_netio_alloc(char *const argv[],
		  unsigned int max_read_size,
		  const struct netio_callbacks *cbs,
		  void *user_data,
		  struct netio **new_netio)
{
    int err;
    struct stdiona_data *nadata = NULL;
    int stdinpipe[2] = {-1, -1};
    int stdoutpipe[2] = {-1, -1};
    int stderrpipe[2] = {-1, -1};

    err = stdio_nadata_setup(max_read_size, &nadata);
    if (err)
	return err;

    err = pipe(stdinpipe);
    if (err) {
	err = errno;
	goto out_err;
    }

    err = pipe(stdoutpipe);
    if (err) {
	err = errno;
	goto out_err;
    }

    err = pipe(stderrpipe);
    if (err) {
	err = errno;
	goto out_err;
    }

    nadata->ostdin = stdinpipe[1];
    nadata->ostdout = stdoutpipe[0];
    nadata->ostderr = stderrpipe[0];
    err = sel_set_fd_handlers(ser2net_sel, nadata->ostdout, nadata,
			      stdion_read_ready, NULL, NULL,
			      stdio_client_fd_cleared);
    if (err)
	goto out_err;
    nadata->oio_count++;

    err = sel_set_fd_handlers(ser2net_sel, nadata->ostderr, nadata,
			      stdion_read_ready, NULL, NULL,
			      stdio_client_fd_cleared);
    if (err)
	goto out_err;
    nadata->oio_count++;

    err = sel_set_fd_handlers(ser2net_sel, nadata->ostdin, nadata,
			      NULL, stdion_write_ready, NULL,
			      stdio_client_fd_cleared);
    if (err)
	goto out_err;
    nadata->oio_count++;

    nadata->net.cbs = cbs;
    nadata->net.user_data = user_data;
    nadata->net.funcs = &netio_stdio_funcs;
    nadata->net.type = NETIO_TYPE_STDIO;

    nadata->opid = fork();
    if (nadata->opid < 0) {
	err = errno;
	goto out_err;
    }
    if (nadata->opid == 0) {
	close(stdinpipe[1]);
	close(stdoutpipe[0]);
	close(stderrpipe[0]);
	dup2(stdinpipe[0], 0);
	dup2(stdoutpipe[1], 1);
	dup2(stderrpipe[1], 2);

	execvp(argv[0], argv);
	exit(1); /* Only reached on error. */
    }

    close(stdinpipe[0]);
    close(stdoutpipe[1]);
    close(stderrpipe[1]);

    *new_netio = &nadata->net;

    return 0;

 out_err:
    if (stdinpipe[0] != -1)
	close(stdinpipe[0]);
    if (stdoutpipe[1] != -1)
	close(stdoutpipe[1]);
    if (stderrpipe[1] != -1)
	close(stderrpipe[1]);

    if (nadata->oio_count) {
	LOCK(nadata->lock);
	if (nadata->oio_count > 0)
	    sel_clear_fd_handlers(ser2net_sel, nadata->ostdout);
	if (nadata->oio_count > 1)
	    sel_clear_fd_handlers(ser2net_sel, nadata->ostderr);
	if (nadata->oio_count > 2)
	    sel_clear_fd_handlers(ser2net_sel, nadata->ostdin);
	UNLOCK(nadata->lock);
    } else {
	if (stdinpipe[1] != -1)
	    close(stdinpipe[1]);
	if (stdoutpipe[0] != -1)
	    close(stdoutpipe[0]);
	if (stderrpipe[0] != -1)
	    close(stderrpipe[0]);
	stdiona_finish_free(nadata);
    }
    return err;
}
