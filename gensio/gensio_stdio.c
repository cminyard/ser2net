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

/* This code handles stdio stream I/O. */

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <assert.h>

#include <gensio/gensio.h>
#include <gensio/gensio_class.h>

#include "utils.h"

static int gensio_stdio_func(struct gensio *io, int func, unsigned int *count,
			     const void *buf, unsigned int buflen,
			     void *auxdata);

struct stdiona_data;

struct stdion_channel {
    struct stdiona_data *nadata;

    int infd;
    int outfd;
    bool in_handler_set;
    bool out_handler_set;

    unsigned int refcount;

    struct gensio *io;

    unsigned int max_read_size;
    unsigned char *read_data;
    unsigned int data_pending_len;
    unsigned int data_pos;

    struct stdiona_data *stdiona;

    bool read_enabled;
    bool xmit_enabled;
    bool in_read;
    bool deferred_read;

    bool in_open;
    gensio_done_err open_done;
    void *open_data;

    /* For the client only. */
    bool in_close; /* A close is pending the running running. */
    bool deferred_close;
    bool closed;
    gensio_done close_done;
    void *close_data;

    bool in_free;

    /*
     * Used to run read callbacks from the selector to avoid running
     * it directly from user calls.
     */
    bool deferred_op_pending;
    struct gensio_runner *deferred_op_runner;
};

struct stdiona_data {
    struct gensio_lock *lock;

    struct gensio_os_funcs *o;

    unsigned int refcount;

    int argc;
    char **argv;

    struct gensio_runner *connect_runner;
    bool in_connect_runner;

    int old_flags_ostdin;
    int old_flags_ostdout;

    /* For the accepter only. */
    bool in_free;
    bool in_shutdown;
    bool enabled;
    bool in_startup;
    gensio_acc_done shutdown_done;
    void *shutdown_data;

    /*
     * If non-zero, this is the PID of the other process and we are
     * in client mode.
     */
    int opid;

    struct stdion_channel io; /* stdin, stdout */
    struct stdion_channel err; /* stderr */

    struct gensio_accepter *acc;
};

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

static void
stdiona_finish_free(struct stdiona_data *nadata)
{
    if (nadata->argv) {
	int i;

	for (i = 0; nadata->argv[i]; i++)
	    nadata->o->free(nadata->o, nadata->argv[i]);
	nadata->o->free(nadata->o, nadata->argv);
    }
    if (nadata->io.deferred_op_runner)
	nadata->o->free_runner(nadata->io.deferred_op_runner);
    if (nadata->err.deferred_op_runner)
	nadata->o->free_runner(nadata->err.deferred_op_runner);
    if (nadata->connect_runner)
	nadata->o->free_runner(nadata->connect_runner);
    if (nadata->io.read_data)
	nadata->o->free(nadata->o, nadata->io.read_data);
    if (nadata->err.read_data)
	nadata->o->free(nadata->o, nadata->err.read_data);
    if (nadata->lock)
	nadata->o->free_lock(nadata->lock);
    if (nadata->io.io)
	gensio_data_free(nadata->io.io);
    if (nadata->err.io)
	gensio_data_free(nadata->err.io);
    nadata->o->free(nadata->o, nadata);
}

static void
stdiona_deref(struct stdiona_data *nadata)
{
    assert(nadata->refcount > 0);
    if (--nadata->refcount == 0) {
	stdiona_unlock(nadata);
	stdiona_finish_free(nadata);
    } else {
	stdiona_unlock(nadata);
    }	
}

static int
stdion_write(struct gensio *io, unsigned int *count,
	     const void *buf, unsigned int buflen)
{
    struct stdion_channel *schan = gensio_get_gensio_data(io);
    int rv, err = 0;

 retry:
    rv = write(schan->infd, buf, buflen);
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
stdion_raddr_to_str(struct gensio *io, unsigned int *epos,
		    char *buf, unsigned int buflen)
{
    struct stdion_channel *schan = gensio_get_gensio_data(io);
    struct stdiona_data *nadata = schan->nadata;
    unsigned int pos = 0;

    if (epos)
	pos = *epos;

    if (io == nadata->io.io)
	strncpy(buf + pos, "stdio", buflen - pos - 1);
    else
	strncpy(buf + pos, "stderr", buflen - pos - 1);
    /* Fix stupid no-nil issue with strncpy. */
    buf[buflen - 1] = '\0';
    pos += strlen(buf + pos);

    if (epos)
	*epos = pos;

    return 0;
}

static int
stdion_remote_id(struct gensio *io, int *id)
{
    struct stdion_channel *schan = gensio_get_gensio_data(io);
    struct stdiona_data *nadata = schan->nadata;

    if (!nadata->argv)
	return ENOTSUP;
    *id = nadata->opid;
    return 0;
}

/* Must be called with nadata->lock held */
static void
stdion_finish_read(struct stdion_channel *schan, int err)
{
    struct stdiona_data *nadata = schan->nadata;
    struct gensio *io = schan->io;
    unsigned int count;

    if (err) {
	/* Do this here so the user can modify it. */
	stdiona_lock(nadata);
	schan->read_enabled = false;
	stdiona_unlock(nadata);
    }

 retry:
    count = schan->data_pending_len;
    gensio_cb(io, GENSIO_EVENT_READ, err,
	      schan->read_data + schan->data_pos, &count, NULL);
    stdiona_lock(nadata);
    if (!err && count < schan->data_pending_len) {
	/* The user didn't consume all the data. */
	schan->data_pending_len -= count;
	schan->data_pos += count;
	if (!schan->closed && schan->read_enabled) {
	    stdiona_unlock(nadata);
	    goto retry;
	}
    } else {
	schan->data_pending_len = 0;
    }

    schan->in_read = false;

    if (schan->read_enabled)
	nadata->o->set_read_handler(nadata->o, schan->outfd, true);
    stdiona_unlock(nadata);
}

static void
stdion_deferred_op(struct gensio_runner *runner, void *cbdata)
{
    struct stdion_channel *schan = cbdata;
    struct stdiona_data *nadata = schan->nadata;
    struct gensio *io = schan->io;

    stdiona_lock(nadata);
 restart:
    if (schan->in_open) {
	schan->in_open = false;
	if (schan->open_done) {
	    stdiona_unlock(nadata);
	    schan->open_done(io, 0, schan->open_data);
	    stdiona_lock(nadata);
	}
	nadata->o->set_read_handler(nadata->o, schan->outfd,
				    schan->read_enabled);
	if (schan->infd != -1)
	    nadata->o->set_write_handler(nadata->o, schan->infd,
					 schan->xmit_enabled);
    }

    if (schan->deferred_read) {
	schan->deferred_read = false;
	stdiona_unlock(nadata);
	stdion_finish_read(schan, 0);
	stdiona_lock(nadata);
    }

    if (schan->deferred_read || schan->in_open)
	goto restart;

    schan->deferred_op_pending = false;

    if (schan->deferred_close) {
	schan->in_close = false;
	schan->deferred_close = false;
	if (schan->close_done) {
	    stdiona_unlock(nadata);
	    schan->close_done(schan->io, schan->close_data);
	    stdiona_lock(nadata);
	}
	if (schan->in_free) {
	    gensio_data_free(schan->io);
	    schan->io = NULL;
	}
    }

    stdiona_deref(nadata);
}

static void
stdion_start_deferred_op(struct stdion_channel *schan)
{
    if (!schan->deferred_op_pending) {
	/* Call the read from the selector to avoid lock nesting issues. */
	schan->deferred_op_pending = true;
	schan->nadata->o->run(schan->deferred_op_runner);
	schan->nadata->refcount++;
    }
}

static void
stdio_client_fd_cleared(int fd, void *cbdata)
{
    struct stdion_channel *schan = cbdata;
    struct stdiona_data *nadata = schan->nadata;

    stdiona_lock(nadata);
    if (fd == schan->infd)
	schan->in_handler_set = false;
    else
	schan->out_handler_set = false;

    if (!nadata->io.in_handler_set && !nadata->io.out_handler_set &&
		!nadata->err.out_handler_set) {
	close(nadata->io.infd);
	close(nadata->io.outfd);
	close(nadata->err.outfd);
    }

    if (!schan->in_handler_set && !schan->out_handler_set && schan->in_close) {
	schan->deferred_close = true;
	stdion_start_deferred_op(schan);
    }

    stdiona_deref(nadata);
}

static void
stdion_set_read_callback_enable(struct gensio *io, bool enabled)
{
    struct stdion_channel *schan = gensio_get_gensio_data(io);
    struct stdiona_data *nadata = schan->nadata;

    stdiona_lock(nadata);
    if (schan->closed || !schan->io)
	goto out_unlock;
    schan->read_enabled = enabled;
    if (schan->in_read || schan->in_open ||
			(schan->data_pending_len && !enabled)) {
	/* Nothing to do, let the read handling wake things up. */
    } else if (schan->data_pending_len) {
	schan->deferred_read = true;
	schan->in_read = true;
	stdion_start_deferred_op(schan);
    } else {
	nadata->o->set_read_handler(nadata->o, schan->outfd, enabled);
    }
 out_unlock:
    stdiona_unlock(nadata);
}

static void
stdion_set_write_callback_enable(struct gensio *io, bool enabled)
{
    struct stdion_channel *schan = gensio_get_gensio_data(io);
    struct stdiona_data *nadata = schan->nadata;

    stdiona_lock(nadata);
    if (schan->closed || schan->infd == -1)
	goto out_unlock;
    schan->xmit_enabled = enabled;
    if (schan->in_open)
	goto out_unlock;
    nadata->o->set_write_handler(nadata->o, schan->infd, enabled);
 out_unlock:
    stdiona_unlock(nadata);
}

static void
stdion_read_ready(int fd, void *cbdata)
{
    struct stdion_channel *schan = cbdata;
    struct stdiona_data *nadata = schan->nadata;
    int rv, err = 0;

    stdiona_lock(nadata);
    if (!schan->read_enabled || schan->in_read) {
	stdiona_unlock(nadata);
	return;
    }
    nadata->o->set_read_handler(nadata->o, schan->outfd, false);
    schan->in_read = true;
    schan->data_pos = 0;
    stdiona_unlock(nadata);

 retry:
    rv = read(fd, schan->read_data, schan->max_read_size);
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
	schan->data_pending_len = rv;
    }

    stdion_finish_read(schan, err);
}

static void
stdion_write_ready(int fd, void *cbdata)
{
    struct stdion_channel *schan = cbdata;

    gensio_cb(schan->io, GENSIO_EVENT_WRITE_READY, 0, NULL, NULL, NULL);
}

static int
stdion_open(struct gensio *io, gensio_done_err open_done, void *open_data)
{
    struct stdion_channel *schan = gensio_get_gensio_data(io);
    struct stdiona_data *nadata = schan->nadata;
    int err;
    int stdinpipe[2] = {-1, -1};
    int stdoutpipe[2] = {-1, -1};
    int stderrpipe[2] = {-1, -1};

    stdiona_lock(nadata);

    if (!schan->closed || schan->in_close || nadata->err.io) {
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

    nadata->io.infd = stdinpipe[1];
    nadata->io.outfd = stdoutpipe[0];
    nadata->err.infd = -1;
    nadata->err.outfd = stderrpipe[0];

    if (fcntl(nadata->io.infd, F_SETFL, O_NONBLOCK) == -1) {
	err = errno;
	goto out_err;
    }
    if (fcntl(nadata->io.outfd, F_SETFL, O_NONBLOCK) == -1) {
	err = errno;
	goto out_err;
    }
    if (fcntl(nadata->err.outfd, F_SETFL, O_NONBLOCK) == -1) {
	err = errno;
	goto out_err;
    }

    err = nadata->o->set_fd_handlers(nadata->o, nadata->io.outfd, &nadata->io,
				     stdion_read_ready, NULL, NULL,
				     stdio_client_fd_cleared);
    if (err)
	goto out_err;
    nadata->io.out_handler_set = true;
    nadata->refcount++;

    err = nadata->o->set_fd_handlers(nadata->o, nadata->io.infd, &nadata->io,
				     NULL, stdion_write_ready, NULL,
				     stdio_client_fd_cleared);
    if (err)
	goto out_err;
    nadata->io.in_handler_set = true;
    nadata->refcount++;

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

    schan->closed = false;
    schan->in_open = true;
    schan->open_done = open_done;
    schan->open_data = open_data;
    stdion_start_deferred_op(schan);
    nadata->refcount++;
    stdiona_unlock(nadata);

    return 0;

 out_err:
    if (stdinpipe[0] != -1)
	close(stdinpipe[0]);
    if (stdoutpipe[1] != -1)
	close(stdoutpipe[1]);
    if (stderrpipe[1] != -1)
	close(stderrpipe[1]);
    if (stderrpipe[0] != -1)
	close(stderrpipe[0]);

    if (nadata->io.out_handler_set)
	nadata->o->clear_fd_handlers_norpt(nadata->o, nadata->io.outfd);
    nadata->io.out_handler_set = false;
    if (nadata->io.in_handler_set)
	nadata->o->clear_fd_handlers_norpt(nadata->o, nadata->io.infd);
    nadata->io.in_handler_set = false;
    if (stdinpipe[1] != -1)
	close(stdinpipe[1]);
    if (stdoutpipe[0] != -1)
	close(stdoutpipe[0]);
 out_unlock:
    stdiona_unlock(nadata);

    return err;
}

static int
stdion_open_channel(struct gensio *io, char *args[],
		    gensio_event cb, void *user_data,
		    gensio_done_err open_done, void *open_data,
		    struct gensio **new_io)
{
    struct stdion_channel *schan = gensio_get_gensio_data(io);
    struct stdiona_data *nadata = schan->nadata;
    int rv = 0;
    unsigned int i, max_read_size = nadata->io.max_read_size;

    for (i = 0; args[i]; i++) {
	if (gensio_check_keyuint(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	return EINVAL;
    }

    stdiona_lock(nadata);
    if (io != nadata->io.io) {
	rv = EINVAL;
	goto out_err;
    }
    if (nadata->err.outfd == -1) {
	rv = ENOENT;
	goto out_err;
    }
    if (nadata->err.io) {
	rv = EBUSY;
	goto out_err;
    }

    nadata->err.max_read_size = max_read_size;
    nadata->err.read_data = nadata->o->zalloc(nadata->o, max_read_size);
    if (!nadata->err.read_data) {
	rv = ENOMEM;
	goto out_err;
    }
    nadata->err.data_pending_len = 0;
    nadata->err.data_pos = 0;
    nadata->err.read_enabled = false;
    nadata->err.xmit_enabled = false;

    nadata->err.io = gensio_data_alloc(nadata->o, cb, user_data,
				       gensio_stdio_func,
				       NULL, "stderr", &nadata->err);
    if (!nadata->err.io) {
	nadata->o->free(nadata->o, nadata->err.read_data);
	nadata->err.read_data = NULL;
	rv = ENOMEM;
	goto out_err;
    }

    rv = nadata->o->set_fd_handlers(nadata->o, nadata->err.outfd, &nadata->err,
				    stdion_read_ready, NULL, NULL,
				    stdio_client_fd_cleared);
    if (!rv) {
	nadata->err.out_handler_set = true;
    } else {
	nadata->o->free(nadata->o, nadata->err.read_data);
	nadata->err.read_data = NULL;
    }

    nadata->err.closed = false;
    nadata->err.in_open = true;
    nadata->err.open_done = open_done;
    nadata->err.open_data = open_data;
    stdion_start_deferred_op(&nadata->err);
    nadata->refcount++;
    *new_io = nadata->err.io;

 out_err:
    stdiona_unlock(nadata);

    return rv;
}

static void
__stdion_close(struct stdion_channel *schan,
	       gensio_done close_done, void *close_data)
{
    struct stdiona_data *nadata = schan->nadata;

    schan->closed = true;
    schan->in_close = true;
    schan->in_open = false; /* In case we get closed before the open is done. */
    schan->close_done = close_done;
    schan->close_data = close_data;
    nadata->o->clear_fd_handlers(nadata->o, schan->outfd);
    if (schan->infd != -1)
	nadata->o->clear_fd_handlers(nadata->o, schan->infd);
}

static int
stdion_close(struct gensio *io, gensio_done close_done, void *close_data)
{
    struct stdion_channel *schan = gensio_get_gensio_data(io);
    struct stdiona_data *nadata = schan->nadata;
    int err = 0;

    stdiona_lock(nadata);
    if (schan->closed || schan->in_close)
	err = EBUSY;
    else
	__stdion_close(schan, close_done, close_data);
    stdiona_unlock(nadata);

    return err;
}

static void
stdion_free(struct gensio *io)
{
    struct stdion_channel *schan = gensio_get_gensio_data(io);
    struct stdiona_data *nadata = schan->nadata;

    stdiona_lock(nadata);
    assert(schan->refcount > 0);
    if (--schan->refcount > 0) {
	stdiona_unlock(nadata);
	return;
    }
    schan->in_free = true;
    if (schan->in_close) {
	schan->close_done = NULL;
	stdiona_unlock(nadata);
    } else if (schan->closed) {
	gensio_data_free(schan->io);
	schan->io = NULL;
	stdiona_deref(nadata);
    } else {
	__stdion_close(schan, NULL, NULL);
	stdiona_unlock(nadata);
    }
}

static void
stdion_ref(struct gensio *io)
{
    struct stdion_channel *schan = gensio_get_gensio_data(io);
    struct stdiona_data *nadata = schan->nadata;

    stdiona_lock(nadata);
    schan->refcount++;
    stdiona_unlock(nadata);
}

static int
gensio_stdio_func(struct gensio *io, int func, unsigned int *count,
		  const void *buf, unsigned int buflen,
		  void *auxdata)
{
    switch (func) {
    case GENSIO_FUNC_WRITE:
	return stdion_write(io, count, buf, buflen);

    case GENSIO_FUNC_RADDR_TO_STR:
	return stdion_raddr_to_str(io, count, auxdata, buflen);

    case GENSIO_FUNC_OPEN:
	return stdion_open(io, buf, auxdata);

    case GENSIO_FUNC_CLOSE:
	return stdion_close(io, buf, auxdata);

    case GENSIO_FUNC_FREE:
	stdion_free(io);
	return 0;

    case GENSIO_FUNC_REF:
	stdion_ref(io);
	return 0;

    case GENSIO_FUNC_SET_READ_CALLBACK:
	stdion_set_read_callback_enable(io, buflen);
	return 0;

    case GENSIO_FUNC_SET_WRITE_CALLBACK:
	stdion_set_write_callback_enable(io, buflen);
	return 0;

    case GENSIO_FUNC_REMOTE_ID:
	return stdion_remote_id(io, auxdata);

    case GENSIO_FUNC_OPEN_CHANNEL:
    {
	struct gensio_func_open_channel_data *d = auxdata;
	return stdion_open_channel(io, d->args, d->cb, d->user_data,
				   d->open_done, d->open_data, &d->new_io);
    }

    case GENSIO_FUNC_GET_RADDR:
    default:
	return ENOTSUP;
    }
}

static int
stdio_nadata_setup(struct gensio_os_funcs *o, unsigned int max_read_size,
		   struct stdiona_data **new_nadata)
{
    struct stdiona_data *nadata;

    nadata = o->zalloc(o, sizeof(*nadata));
    if (!nadata)
	return ENOMEM;
    nadata->o = o;
    nadata->refcount = 1;
    nadata->io.refcount = 1;
    nadata->err.refcount = 1;
    nadata->io.closed = true;
    nadata->err.closed = true;
    nadata->io.nadata = nadata;
    nadata->err.nadata = nadata;

    nadata->io.max_read_size = max_read_size;
    nadata->io.read_data = o->zalloc(o, max_read_size);
    if (!nadata->io.read_data)
	goto out_nomem;

    nadata->io.deferred_op_runner = o->alloc_runner(o, stdion_deferred_op,
						    &nadata->io);
    if (!nadata->io.deferred_op_runner)
	goto out_nomem;

    nadata->err.deferred_op_runner = o->alloc_runner(o, stdion_deferred_op,
						     &nadata->err);
    if (!nadata->err.deferred_op_runner)
	goto out_nomem;

    nadata->lock = o->alloc_lock(o);
    if (!nadata->lock)
	goto out_nomem;

    *new_nadata = nadata;

    return 0;

 out_nomem:
    stdiona_finish_free(nadata);

    return ENOMEM;
}

int
stdio_gensio_alloc(char *const argv[], char *args[],
		   struct gensio_os_funcs *o,
		   gensio_event cb, void *user_data,
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
    nadata->io.io = gensio_data_alloc(nadata->o, cb, user_data,
				      gensio_stdio_func, NULL, "stdio",
				      &nadata->io);
    if (!nadata->io.io)
	goto out_nomem;
    gensio_set_is_client(nadata->io.io, true);
    gensio_set_is_reliable(nadata->io.io, true);

    *new_gensio = nadata->io.io;

    return 0;

 out_nomem:
    stdiona_finish_free(nadata);
    return ENOMEM;
}

int
str_to_stdio_gensio(const char *str, char *args[],
		    struct gensio_os_funcs *o,
		    gensio_event cb, void *user_data,
		    struct gensio **new_gensio)
{
    int err, argc;
    char **argv;

    err = str_to_argv(str, &argc, &argv, NULL);
    if (!err) {
	err = stdio_gensio_alloc(argv, args, o, cb, user_data, new_gensio);
	str_to_argv_free(argc, argv);
    }
    return err;
}

static void
stdiona_do_connect(struct gensio_runner *runner, void *cbdata)
{
    struct stdiona_data *nadata = cbdata;

    stdiona_lock(nadata);
 retry:
    if (nadata->in_startup) {
	nadata->in_startup = false;
	stdiona_unlock(nadata);
	gensio_acc_cb(nadata->acc, GENSIO_ACC_EVENT_NEW_CONNECTION,
		      nadata->io.io);
	stdiona_lock(nadata);
    }

    if (nadata->in_shutdown) {
	nadata->in_shutdown = false;
	stdiona_unlock(nadata);
	if (nadata->shutdown_done)
	    nadata->shutdown_done(nadata->acc, nadata->shutdown_data);
	stdiona_lock(nadata);
    }

    if (nadata->in_startup || nadata->in_shutdown)
	goto retry;

    nadata->in_connect_runner = false;
    stdiona_deref(nadata); /* unlocks */
}

/*
 * fd cleared for a gensio from an acceptor only.
 */
static void
stdiona_fd_cleared(int fd, void *cbdata)
{
    struct stdion_channel *schan = cbdata;
    struct stdiona_data *nadata = schan->nadata;

    stdiona_lock(nadata);
    if (fd == schan->infd)
	schan->in_handler_set = false;
    else
	schan->out_handler_set = false;

    if (!nadata->io.in_handler_set && !nadata->io.out_handler_set) {
	/* We came from an acceptor, set stdio back to original values. */
	fcntl(nadata->io.infd, F_SETFL, nadata->old_flags_ostdin);
	fcntl(nadata->io.outfd, F_SETFL, nadata->old_flags_ostdout);
    }

    if (!schan->in_handler_set && !schan->out_handler_set && schan->in_close) {
	schan->in_close = false;
	if (schan->close_done) {
	    gensio_done close_done = schan->close_done;
	    void *close_data = schan->close_data;

	    stdiona_unlock(nadata);
	    close_done(schan->io, close_data);
	    stdiona_lock(nadata);
	}
    }

    /* Lose the refcount we got when we added the fd handler. */
    stdiona_deref(nadata); /* unlocks */
}

static int
stdiona_startup(struct gensio_accepter *accepter)
{
    struct stdiona_data *nadata = gensio_acc_get_gensio_data(accepter);
    int rv = 0;
    bool io_allocated = false, infd_nb_set = false, outfd_nb_set = false;

    stdiona_lock(nadata);
    if (nadata->in_free) {
	rv = EBADFD;
	goto out_unlock;
    }

    if (nadata->in_shutdown) {
	rv = EAGAIN;
	goto out_unlock;
    }

    if (nadata->io.io) {
	rv = EBUSY;
	goto out_unlock;
    }

    nadata->io.io = gensio_data_alloc(nadata->o, NULL, NULL, gensio_stdio_func,
				      NULL, "stdio", &nadata->io);
    if (!nadata->io.io) {
	rv = ENOMEM;
	goto out_unlock;
    }
    io_allocated = true;

    rv = fcntl(nadata->io.infd, F_GETFL, 0);
    if (rv == -1) {
	rv = errno;
	goto out_unlock;
    }
    nadata->old_flags_ostdin = rv;

    rv = fcntl(nadata->io.outfd, F_GETFL, 0);
    if (rv == -1) {
	rv = errno;
	fcntl(nadata->io.infd, F_SETFL, nadata->old_flags_ostdin);
	goto out_unlock;
    }
    nadata->old_flags_ostdout = rv;

    if (fcntl(nadata->io.infd, F_SETFL, O_NONBLOCK) == -1) {
	rv = errno;
	goto out_err;
    }
    infd_nb_set = true;
    if (fcntl(nadata->io.outfd, F_SETFL, O_NONBLOCK) == -1) {
	rv = errno;
	goto out_err;
    }
    outfd_nb_set = true;

    rv = nadata->o->set_fd_handlers(nadata->o, nadata->io.infd,
				    &nadata->io, NULL, stdion_write_ready, NULL,
				    stdiona_fd_cleared);
    if (rv)
	goto out_err;
    nadata->io.in_handler_set = true;
    nadata->refcount++;

    rv = nadata->o->set_fd_handlers(nadata->o, nadata->io.outfd,
				    &nadata->io, stdion_read_ready, NULL, NULL,
				    stdiona_fd_cleared);
    if (rv)
	goto out_err;
    nadata->io.out_handler_set = true;
    nadata->refcount++;

    nadata->io.closed = false;
    nadata->in_startup = true;
    nadata->enabled = true;
    if (!nadata->in_connect_runner) {
	nadata->refcount++;
	nadata->in_connect_runner = true;
	nadata->o->run(nadata->connect_runner);
    }

 out_unlock:
    stdiona_unlock(nadata);
    return rv;

 out_err:
    if (io_allocated) {
	gensio_data_free(nadata->io.io);
	nadata->io.io = NULL;
    }
    if (nadata->io.in_handler_set)
	nadata->o->clear_fd_handlers_norpt(nadata->o, nadata->io.infd);
    nadata->io.in_handler_set = false;
    if (nadata->io.out_handler_set)
	nadata->o->clear_fd_handlers_norpt(nadata->o, nadata->io.outfd);
    nadata->io.out_handler_set = false;
    if (infd_nb_set)
	fcntl(nadata->io.infd, F_SETFL, nadata->old_flags_ostdin);
    if (outfd_nb_set)
	fcntl(nadata->io.outfd, F_SETFL, nadata->old_flags_ostdout);
    goto out_unlock;
}

static int
stdiona_shutdown(struct gensio_accepter *accepter,
		 gensio_acc_done shutdown_done, void *shutdown_data)
{
    struct stdiona_data *nadata = gensio_acc_get_gensio_data(accepter);
    int rv = 0;

    stdiona_lock(nadata);
    if (nadata->in_free) {
	rv = EBADFD;
    } else if (nadata->in_shutdown || !nadata->enabled) {
	rv = EAGAIN;
    } else {
	nadata->in_shutdown = true;
	nadata->enabled = false;
	nadata->shutdown_done = shutdown_done;
	nadata->shutdown_data = shutdown_data;
	if (!nadata->in_connect_runner) {
	    nadata->refcount++;
	    nadata->in_connect_runner = true;
	    nadata->o->run(nadata->connect_runner);
	}
    }
    stdiona_unlock(nadata);

    return rv;
}

static void
stdiona_set_accept_callback_enable(struct gensio_accepter *accepter,
				   bool enabled)
{
}

static void
stdiona_free(struct gensio_accepter *accepter)
{
    struct stdiona_data *nadata = gensio_acc_get_gensio_data(accepter);

    stdiona_lock(nadata);
    nadata->in_free = true;
    stdiona_deref(nadata);
}

static int
gensio_acc_stdio_func(struct gensio_accepter *acc, int func, int val,
		      void *addr, void *done, void *data,
		      void *ret)
{
    switch (func) {
    case GENSIO_ACC_FUNC_STARTUP:
	return stdiona_startup(acc);

    case GENSIO_ACC_FUNC_SHUTDOWN:
	return stdiona_shutdown(acc, done, data);

    case GENSIO_ACC_FUNC_SET_ACCEPT_CALLBACK:
	stdiona_set_accept_callback_enable(acc, val);
	return 0;

    case GENSIO_ACC_FUNC_FREE:
	stdiona_free(acc);
	return 0;

    case GENSIO_ACC_FUNC_CONNECT:
    default:
	return ENOTSUP;
    }
}

int
stdio_gensio_accepter_alloc(char *args[], struct gensio_os_funcs *o,
			    gensio_accepter_event cb, void *user_data,
			    struct gensio_accepter **accepter)
{
    int err;
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

    nadata->connect_runner = o->alloc_runner(o, stdiona_do_connect, nadata);
    if (!nadata->connect_runner) {
	stdiona_finish_free(nadata);
	return ENOMEM;
    }

    nadata->io.infd = 1;
    nadata->io.outfd = 0;
    nadata->err.infd = -1;
    nadata->err.outfd = -1;

    nadata->acc = gensio_acc_data_alloc(o, cb, user_data, gensio_acc_stdio_func,
					NULL, "stdio", nadata);
    if (!nadata->acc) {
	stdiona_finish_free(nadata);
	return ENOMEM;
    }
    gensio_acc_set_is_reliable(nadata->acc, true);

    *accepter = nadata->acc;
    return 0;
}

int
str_to_stdio_gensio_accepter(const char *str, char *args[],
			     struct gensio_os_funcs *o,
			     gensio_accepter_event cb,
			     void *user_data,
			     struct gensio_accepter **acc)
{
    return stdio_gensio_accepter_alloc(args, o, cb, user_data, acc);
}
