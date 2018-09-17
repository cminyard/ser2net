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

/* This code handles stdio network I/O. */

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <fcntl.h>
#include <stdio.h>
#include <assert.h>

#include <utils/locking.h>

#include <gensio/gensio.h>
#include <gensio/gensio_internal.h>

struct stdiona_data {
    struct gensio_lock *lock;

    struct gensio_os_funcs *o;

    unsigned int refcount;

    int argc;
    char **argv;

    struct gensio_runner *connect_runner;

    bool enabled;
    int old_flags_ostdin;
    int old_flags_ostdout;

    /* For the acceptor only. */
    bool in_free;
    bool in_shutdown;
    void (*shutdown_done)(struct gensio_acceptor *acceptor,
			  void *shutdown_data);
    void *shutdown_data;

    bool read_enabled;
    bool xmit_enabled;
    bool in_read;
    bool deferred_read;

    bool in_open;
    void (*open_done)(struct gensio *io, int err, void *open_data);
    void *open_data;

    /* For the client only. */
    bool in_close; /* A close is pending the running running. */
    bool closed;
    void (*close_done)(struct gensio *net, void *close_data);
    void *close_data;

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

    unsigned int data_pending_len;
    unsigned int data_pos;

    /*
     * Used to run read callbacks from the selector to avoid running
     * it directly from user calls.
     */
    bool deferred_op_pending;
    struct gensio_runner *deferred_op_runner;

    struct gensio net;
    struct gensio_acceptor acceptor;
};

#define net_to_nadata(net) container_of(net, struct stdiona_data, net);
#define acc_to_nadata(acc) container_of(acc, struct stdiona_data, acceptor);

static void
stdiona_lock(struct stdiona_data *nadata)
{
    nadata->o->lock(nadata->lock);
}

static void
stdiona_unlock(struct stdiona_data *nadata)
{
    nadata->o->unlock(nadata->lock);
}

static int
stdion_write(struct gensio *net, unsigned int *count,
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
stdion_raddr_to_str(struct gensio *net, int *epos,
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

static int
stdion_remote_id(struct gensio *net, int *id)
{
    struct stdiona_data *nadata = net_to_nadata(net);

    if (!nadata->argv)
	return ENOTSUP;
    *id = nadata->opid;
    return 0;
}

/* Must be called with nadata->lock held */
static void
stdion_finish_read(struct stdiona_data *nadata, int err)
{
    struct gensio *net = &nadata->net;
    unsigned int count;

    if (err) {
	/* Do this here so the user can modify it. */
	stdiona_lock(nadata);
	nadata->read_enabled = false;
	stdiona_unlock(nadata);
    }

 retry:
    count = net->cbs->read_callback(net, err,
				    nadata->read_data + nadata->data_pos,
				    nadata->data_pending_len,
				    nadata->read_flags);
    stdiona_lock(nadata);
    if (!err && count < nadata->data_pending_len) {
	/* The user didn't consume all the data. */
	nadata->data_pending_len -= count;
	nadata->data_pos += count;
	if (!nadata->closed && nadata->read_enabled) {
	    stdiona_unlock(nadata);
	    goto retry;
	}
    } else {
	nadata->data_pending_len = 0;
    }

    nadata->in_read = false;

    if (nadata->read_enabled) {
	nadata->o->set_read_handler(nadata->o, nadata->ostdout, true);
	if (nadata->ostderr != -1)
	    nadata->o->set_read_handler(nadata->o, nadata->ostderr, true);
    }
    stdiona_unlock(nadata);
}

static void
stdion_deferred_op(struct gensio_runner *runner, void *cbdata)
{
    struct stdiona_data *nadata = cbdata;
    struct gensio *net = &nadata->net;

    stdiona_lock(nadata);
 restart:
    if (nadata->in_open) {
	if (nadata->open_done) {
	    stdiona_unlock(nadata);
	    nadata->open_done(&nadata->net, 0, nadata->open_data);
	    stdiona_lock(nadata);
	}
	nadata->in_open = false;
	nadata->o->set_read_handler(nadata->o, nadata->ostdout,
				    nadata->read_enabled);
	if (nadata->ostderr != -1)
	    nadata->o->set_read_handler(nadata->o, nadata->ostderr,
					nadata->read_enabled);
	nadata->o->set_write_handler(nadata->o, nadata->ostdout,
				     nadata->xmit_enabled);
    }

    if (nadata->deferred_read) {
	nadata->deferred_read = false;
	stdiona_unlock(nadata);
	stdion_finish_read(nadata, 0);
	stdiona_lock(nadata);
    }

    if (nadata->deferred_read)
	goto restart;

    nadata->deferred_op_pending = false;

    if (nadata->in_close) {
	nadata->in_close = false;
	nadata->in_open = false;
	stdiona_unlock(nadata);
	if (nadata->close_done)
	    nadata->close_done(net, nadata->close_data);
	return;
    }
    stdiona_unlock(nadata);
}

static void
stdion_start_deferred_op(struct stdiona_data *nadata)
{
    if (!nadata->deferred_op_pending) {
	/* Call the read from the selector to avoid lock nesting issues. */
	nadata->deferred_op_pending = true;
	nadata->o->run(nadata->deferred_op_runner);
    }
}

static void
stdiona_finish_free(struct stdiona_data *nadata)
{
    if (nadata->argv) {
	int i;

	for (i = 0; nadata->argv[i]; i++)
	    nadata->o->free(nadata->o, nadata->argv[i]);
	nadata->o->free(nadata->o, nadata->argv);
    }
    if (nadata->deferred_op_runner)
	nadata->o->free_runner(nadata->deferred_op_runner);
    if (nadata->connect_runner)
	nadata->o->free_runner(nadata->connect_runner);
    if (nadata->read_data)
	nadata->o->free(nadata->o, nadata->read_data);
    if (nadata->lock)
	nadata->o->free_lock(nadata->lock);
    nadata->o->free(nadata->o, nadata);
}

static void
stdio_client_fd_cleared(int fd, void *cbdata)
{
    struct stdiona_data *nadata = cbdata;

    stdiona_lock(nadata);
    nadata->oio_count--;
    if (nadata->oio_count == 0) {
	close(nadata->ostdin);
	close(nadata->ostdout);
	close(nadata->ostderr);
	stdiona_unlock(nadata);
	if (nadata->close_done)
	    nadata->close_done(&nadata->net, nadata->close_data);
	stdiona_lock(nadata);
	nadata->in_close = false;
	nadata->in_open = false;
	if (nadata->in_free) {
	    stdiona_finish_free(nadata);
	    return;
	}
    }
    stdiona_unlock(nadata);
}

static void
stdion_set_read_callback_enable(struct gensio *net, bool enabled)
{
    struct stdiona_data *nadata = net_to_nadata(net);

    stdiona_lock(nadata);
    if (nadata->closed)
	goto out_unlock;
    nadata->read_enabled = enabled;
    if (nadata->in_read || nadata->in_open ||
			(nadata->data_pending_len && !enabled)) {
	/* Nothing to do, let the read handling wake things up. */
    } else if (nadata->data_pending_len) {
	nadata->deferred_read = true;
	nadata->in_read = true;
	stdion_start_deferred_op(nadata);
    } else {
	nadata->o->set_read_handler(nadata->o, nadata->ostdout, enabled);
	if (nadata->ostderr != -1)
	    nadata->o->set_read_handler(nadata->o, nadata->ostderr, enabled);
    }
 out_unlock:
    stdiona_unlock(nadata);
}

static void
stdion_set_write_callback_enable(struct gensio *net, bool enabled)
{
    struct stdiona_data *nadata = net_to_nadata(net);

    stdiona_lock(nadata);
    if (nadata->closed)
	goto out_unlock;
    nadata->xmit_enabled = enabled;
    if (nadata->in_open)
	goto out_unlock;
    nadata->o->set_write_handler(nadata->o, nadata->ostdin, enabled);
 out_unlock:
    stdiona_unlock(nadata);
}

static void
stdion_read_ready(int fd, void *cbdata)
{
    struct stdiona_data *nadata = cbdata;
    int rv, err = 0;

    stdiona_lock(nadata);
    if (!nadata->read_enabled || nadata->in_read) {
	stdiona_unlock(nadata);
	return;
    }
    nadata->o->set_read_handler(nadata->o, nadata->ostdout, false);
    if (nadata->ostderr != -1)
	nadata->o->set_read_handler(nadata->o, nadata->ostderr, false);
    if (fd == nadata->ostderr)
	nadata->read_flags = GENSIO_ERR_OUTPUT;
    else
	nadata->read_flags = 0;
    nadata->in_read = true;
    nadata->data_pos = 0;
    stdiona_unlock(nadata);

 retry:
    rv = read(fd, nadata->read_data, nadata->max_read_size);
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
	nadata->data_pending_len = rv;
    }

    stdion_finish_read(nadata, err);
}

static void
stdion_write_ready(int fd, void *cbdata)
{
    struct stdiona_data *nadata = cbdata;
    struct gensio *net = &nadata->net;

    net->cbs->write_callback(net);
}

static int
stdion_open(struct gensio *net, void (*open_done)(struct gensio *net,
						  int err,
						  void *open_data),
	    void *open_data)
{
    struct stdiona_data *nadata = net_to_nadata(net);
    int err;
    int stdinpipe[2] = {-1, -1};
    int stdoutpipe[2] = {-1, -1};
    int stderrpipe[2] = {-1, -1};

    stdiona_lock(nadata);

    if (!nadata->closed || nadata->in_close) {
	err = EBUSY;
	goto out_unlock;
    }

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

    if (fcntl(nadata->ostdin, F_SETFL, O_NONBLOCK) == -1) {
	err = errno;
	goto out_err;
    }
    if (fcntl(nadata->ostdout, F_SETFL, O_NONBLOCK) == -1) {
	err = errno;
	goto out_err;
    }
    if (fcntl(nadata->ostderr, F_SETFL, O_NONBLOCK) == -1) {
	err = errno;
	goto out_err;
    }

    err = nadata->o->set_fd_handlers(nadata->o, nadata->ostdout, nadata,
				     stdion_read_ready, NULL, NULL,
				     stdio_client_fd_cleared);
    if (err)
	goto out_err;
    nadata->oio_count++;

    err = nadata->o->set_fd_handlers(nadata->o, nadata->ostderr, nadata,
				     stdion_read_ready, NULL, NULL,
				     stdio_client_fd_cleared);
    if (err)
	goto out_err;
    nadata->oio_count++;

    err = nadata->o->set_fd_handlers(nadata->o, nadata->ostdin, nadata,
				     NULL, stdion_write_ready, NULL,
				     stdio_client_fd_cleared);
    if (err)
	goto out_err;
    nadata->oio_count++;

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

	execvp(nadata->argv[0], nadata->argv);
	{
	    char buff[1024];

	    fprintf(stderr, "Err: %s %s\n", nadata->argv[0], strerror(errno));
	    fprintf(stderr, "  pwd = '%s'\n", getcwd(buff, sizeof(buff)));
	}
	exit(1); /* Only reached on error. */
    }

    close(stdinpipe[0]);
    close(stdoutpipe[1]);
    close(stderrpipe[1]);

    nadata->closed = false;
    nadata->in_open = true;
    nadata->open_done = open_done;
    nadata->open_data = open_data;
    stdion_start_deferred_op(nadata);
    stdiona_unlock(nadata);

    return 0;

 out_err:
    if (stdinpipe[0] != -1)
	close(stdinpipe[0]);
    if (stdoutpipe[1] != -1)
	close(stdoutpipe[1]);
    if (stderrpipe[1] != -1)
	close(stderrpipe[1]);

    if (nadata->oio_count) {
	if (nadata->oio_count > 0)
	    nadata->o->clear_fd_handlers(nadata->o, nadata->ostdout);
	if (nadata->oio_count > 1)
	    nadata->o->clear_fd_handlers(nadata->o, nadata->ostderr);
	if (nadata->oio_count > 2)
	    nadata->o->clear_fd_handlers(nadata->o, nadata->ostdin);
    } else {
	if (stdinpipe[1] != -1)
	    close(stdinpipe[1]);
	if (stdoutpipe[0] != -1)
	    close(stdoutpipe[0]);
	if (stderrpipe[0] != -1)
	    close(stderrpipe[0]);
    }
 out_unlock:
    stdiona_unlock(nadata);

    return err;
}

static void
__stdion_close(struct stdiona_data *nadata,
	       void (*close_done)(struct gensio *net, void *close_data),
	       void *close_data)
{
    nadata->closed = true;
    nadata->in_close = true;
    nadata->close_done = close_done;
    nadata->close_data = close_data;
    if (nadata->argv) {
	nadata->o->clear_fd_handlers(nadata->o, nadata->ostdin);
	nadata->o->clear_fd_handlers(nadata->o, nadata->ostdout);
	if (nadata->ostderr != -1)
	    nadata->o->clear_fd_handlers(nadata->o, nadata->ostderr);
    } else {
	stdion_start_deferred_op(nadata);
    }
}

static int
stdion_close(struct gensio *net, void (*close_done)(struct gensio *net,
						    void *close_data),
	     void *close_data)
{
    struct stdiona_data *nadata = net_to_nadata(net);
    int err = 0;

    stdiona_lock(nadata);
    if (nadata->closed || nadata->in_close)
	err = EBUSY;
    else
	__stdion_close(nadata, close_done, close_data);
    stdiona_unlock(nadata);

    return err;
}

static void
stdion_free(struct gensio *net)
{
    struct stdiona_data *nadata = net_to_nadata(net);

    stdiona_lock(nadata);
    assert(nadata->refcount > 0);
    if (--nadata->refcount > 0) {
	stdiona_unlock(nadata);
	return;
    }
	
    nadata->in_free = true;
    if (nadata->in_close) {
	nadata->close_done = NULL;
	stdiona_unlock(nadata);
    } else if (nadata->closed) {
	stdiona_unlock(nadata);
	stdiona_finish_free(nadata);
    } else {
	__stdion_close(nadata, NULL, NULL);
	stdiona_unlock(nadata);
    }
}

static void
stdion_ref(struct gensio *net)
{
    struct stdiona_data *nadata = net_to_nadata(net);

    stdiona_lock(nadata);
    nadata->refcount++;
    stdiona_unlock(nadata);
}

static void
stdiona_do_connect(struct gensio_runner *runner, void *cbdata)
{
    struct stdiona_data *nadata = cbdata;

    nadata->acceptor.cbs->new_connection(&nadata->acceptor, &nadata->net);
}

static void
stdiona_fd_cleared(int fd, void *cbdata)
{
    struct stdiona_data *nadata = cbdata;
    struct gensio_acceptor *acceptor = &nadata->acceptor;

    stdiona_lock(nadata);
    nadata->oio_count--;
    fcntl(nadata->ostdin, F_SETFL, nadata->old_flags_ostdin);
    fcntl(nadata->ostdout, F_SETFL, nadata->old_flags_ostdout);

    if (nadata->shutdown_done)
	nadata->shutdown_done(acceptor, nadata->shutdown_data);

    stdiona_lock(nadata);
    nadata->in_shutdown = false;
    if (nadata->in_free) {
	stdiona_unlock(nadata);
	stdiona_finish_free(nadata);
    } else {
	stdiona_unlock(nadata);
    }
}

static int
stdiona_startup(struct gensio_acceptor *acceptor)
{
    struct stdiona_data *nadata = acc_to_nadata(acceptor);
    int rv = 0;

    stdiona_lock(nadata);
    if (nadata->in_shutdown) {
	rv = EAGAIN;
	goto out_unlock;
    }
    if (!nadata->enabled) {
	rv = fcntl(nadata->ostdin, F_GETFL, 0);
	if (rv == -1) {
	    rv = errno;
	    goto out_unlock;
	}
	nadata->old_flags_ostdin = rv;

	rv = fcntl(nadata->ostdout, F_GETFL, 0);
	if (rv == -1) {
	    rv = errno;
	    fcntl(nadata->ostdin, F_SETFL, O_NONBLOCK);
	    goto out_unlock;
	}
	nadata->old_flags_ostdout = rv;

	if (fcntl(nadata->ostdin, F_SETFL, O_NONBLOCK) == -1) {
	    rv = errno;
	    goto out_err;
	}

	if (fcntl(nadata->ostdout, F_SETFL, O_NONBLOCK) == -1) {
	    rv = errno;
	    goto out_err;
	}

	rv = nadata->o->set_fd_handlers(nadata->o, nadata->ostdin,
					nadata, NULL, stdion_write_ready, NULL,
					stdiona_fd_cleared);
	if (rv)
	    goto out_err;
	nadata->oio_count++;

	rv = nadata->o->set_fd_handlers(nadata->o, nadata->ostdout,
					nadata, stdion_read_ready, NULL, NULL,
					stdiona_fd_cleared);
	if (rv)
	    goto out_err;
	nadata->oio_count++;

	nadata->enabled = true;
	nadata->o->run(nadata->connect_runner);
    }
 out_unlock:
    stdiona_unlock(nadata);
    return rv;

 out_err:
    if (nadata->oio_count) {
	if (nadata->oio_count > 1)
	    nadata->o->clear_fd_handlers(nadata->o, nadata->ostdin);
	if (nadata->oio_count > 2)
	    nadata->o->clear_fd_handlers(nadata->o, nadata->ostdout);
    } else {
	fcntl(nadata->ostdin, F_SETFL, nadata->old_flags_ostdin);
	fcntl(nadata->ostdout, F_SETFL, nadata->old_flags_ostdout);
    }
    goto out_unlock;
}

static int
stdiona_shutdown(struct gensio_acceptor *acceptor,
		 void (*shutdown_done)(struct gensio_acceptor *acceptor,
				       void *shutdown_data),
		 void *shutdown_data)
{
    struct stdiona_data *nadata = acc_to_nadata(acceptor);
    int rv = 0;

    stdiona_lock(nadata);
    if (nadata->enabled) {
	nadata->enabled = false;
	nadata->in_shutdown = true;
	nadata->shutdown_done = shutdown_done;
	nadata->shutdown_data = shutdown_data;
	nadata->o->clear_fd_handlers(nadata->o, nadata->ostdin);
	nadata->o->clear_fd_handlers(nadata->o, nadata->ostdout);
    } else {
	rv = EAGAIN;
    }
    stdiona_unlock(nadata);

    return rv;
}

static void
stdiona_set_accept_callback_enable(struct gensio_acceptor *acceptor,
				   bool enabled)
{
}

static void
stdiona_free(struct gensio_acceptor *acceptor)
{
    struct stdiona_data *nadata = acc_to_nadata(acceptor);

    stdiona_lock(nadata);
    nadata->in_free = true;
    if (nadata->enabled) {
	nadata->enabled = false;
	nadata->o->clear_fd_handlers(nadata->o, nadata->ostdin);
	nadata->o->clear_fd_handlers(nadata->o, nadata->ostdout);
    } else {
	stdiona_unlock(nadata);
	stdiona_finish_free(nadata);
	return;
    }
    stdiona_unlock(nadata);
}

static const struct gensio_functions gensio_stdio_funcs = {
    .write = stdion_write,
    .raddr_to_str = stdion_raddr_to_str,
    .remote_id = stdion_remote_id,
    .open = stdion_open,
    .close = stdion_close,
    .free = stdion_free,
    .ref = stdion_ref,
    .set_read_callback_enable = stdion_set_read_callback_enable,
    .set_write_callback_enable = stdion_set_write_callback_enable
};

static const struct gensio_acceptor_functions gensio_acc_stdio_funcs = {
    .startup = stdiona_startup,
    .shutdown = stdiona_shutdown,
    .set_accept_callback_enable = stdiona_set_accept_callback_enable,
    .free = stdiona_free
};

static int
stdio_nadata_setup(struct gensio_os_funcs *o, unsigned int max_read_size,
		   struct stdiona_data **new_nadata)
{
    int err = 0;
    struct stdiona_data *nadata;

    nadata = o->zalloc(o, sizeof(*nadata));
    if (!nadata)
	goto out_nomem;
    nadata->o = o;
    nadata->refcount = 1;

    nadata->max_read_size = max_read_size;
    nadata->read_data = o->zalloc(o, max_read_size);
    if (!nadata->read_data)
	goto out_nomem;

    nadata->deferred_op_runner = o->alloc_runner(o, stdion_deferred_op, nadata);
    if (!nadata->deferred_op_runner)
	goto out_err;

    nadata->connect_runner = o->alloc_runner(o, stdiona_do_connect, nadata);
    if (err)
	goto out_err;

    nadata->lock = o->alloc_lock(o);
    if (!nadata->lock)
	goto out_err;

    nadata->net.funcs = &gensio_stdio_funcs;
    nadata->net.type = GENSIO_TYPE_STDIO;

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
stdio_gensio_acceptor_alloc(char *args[], struct gensio_os_funcs *o,
			    const struct gensio_acceptor_callbacks *cbs,
			    void *user_data,
			    struct gensio_acceptor **acceptor)
{
    int err;
    struct gensio_acceptor *acc;
    struct stdiona_data *nadata = NULL;
    unsigned int max_read_size = GENSIO_DEFAULT_BUF_SIZE;
    int i;

    for (i = 0; args[i]; i++) {
	if (gensio_check_keyuint(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	return EINVAL;
    }

    err = stdio_nadata_setup(o, max_read_size, &nadata);
    if (err)
	return err;

    nadata->ostdin = 1;
    nadata->ostdout = 0;
    nadata->ostderr = -1;

    acc = &nadata->acceptor;
    acc->type = GENSIO_TYPE_STDIO;

    acc->cbs = cbs;
    acc->user_data = user_data;
    acc->funcs = &gensio_acc_stdio_funcs;

    *acceptor = acc;
    return 0;
}

int
stdio_gensio_alloc(char *const argv[], char *args[],
		   struct gensio_os_funcs *o,
		   const struct gensio_callbacks *cbs,
		   void *user_data,
		   struct gensio **new_gensio)
{
    int err;
    struct stdiona_data *nadata = NULL;
    int i, argc;
    unsigned int max_read_size = GENSIO_DEFAULT_BUF_SIZE;

    for (i = 0; args[i]; i++) {
	if (gensio_check_keyuint(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	return EINVAL;
    }

    err = stdio_nadata_setup(o, max_read_size, &nadata);
    if (err)
	return err;

    for (argc = 0; argv[argc]; argc++)
	;
    nadata->argv = o->zalloc(o, (argc + 1) * sizeof(*nadata->argv));
    if (!nadata->argv)
	goto out_nomem;
    for (i = 0; i < argc; i++) {
	nadata->argv[i] = gensio_strdup(o, argv[i]);
	if (!nadata->argv[i])
	    goto out_nomem;
    }
    nadata->closed = true;
    nadata->net.cbs = cbs;
    nadata->net.user_data = user_data;
    nadata->net.funcs = &gensio_stdio_funcs;
    nadata->net.type = GENSIO_TYPE_STDIO;
    nadata->net.is_client = true;

    *new_gensio = &nadata->net;

    return 0;

 out_nomem:
    stdiona_finish_free(nadata);
    return ENOMEM;
}
