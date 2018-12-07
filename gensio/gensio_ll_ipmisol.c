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

#include <errno.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

/* For open(). */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <gensio/gensio_class.h>
#include <gensio/sergensio_class.h>

#include "gensio_ll_ipmisol.h"
#include "buffer.h"
#include "utils.h"

#ifdef HAVE_OPENIPMI

#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_smi.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_auth.h>
#include <OpenIPMI/ipmi_lan.h>

#include <OpenIPMI/ipmi_sol.h>
#include <OpenIPMI/ipmi_debug.h>

struct igensio_info
{
    struct gensio_os_funcs *o;
    os_vlog_t log_handler;
};


static void *
gio_mem_alloc(int size)
{
    return malloc(size);
}

static void
gio_mem_free(void *data)
{
    free(data);
}

struct os_hnd_fd_id_s
{
    int             fd;
    void            *cb_data;
    os_data_ready_t data_ready;
    os_data_ready_t write_ready;
    os_data_ready_t except_ready;
    os_handler_t    *handler;
    os_fd_data_freed_t freed;
};

static void
fd_read_handler(int fd, void *data)
{
    os_hnd_fd_id_t *fd_data = (os_hnd_fd_id_t *) data;

    fd_data->data_ready(fd, fd_data->cb_data, fd_data);
}

static void
fd_write_handler(int fd, void *data)
{
    os_hnd_fd_id_t *fd_data = (os_hnd_fd_id_t *) data;

    fd_data->write_ready(fd, fd_data->cb_data, fd_data);
}

static void
fd_except_handler(int fd, void *data)
{
    os_hnd_fd_id_t *fd_data = (os_hnd_fd_id_t *) data;

    fd_data->except_ready(fd, fd_data->cb_data, fd_data);
}

static void
free_fd_data(int fd, void *data)
{
    os_hnd_fd_id_t *fd_data = data;

    if (fd_data->freed)
        fd_data->freed(fd, fd_data->cb_data);
    free(data);
}

static int
gio_add_fd_to_wait_for(os_handler_t       *handler,
		       int                fd,
		       os_data_ready_t    data_ready,
		       void               *cb_data,
		       os_fd_data_freed_t freed,
		       os_hnd_fd_id_t     **id)
{
    os_hnd_fd_id_t *fd_data;
    int rv;
    struct igensio_info *info = handler->internal_data;
    struct gensio_os_funcs *o = info->o;


    fd_data = malloc(sizeof(*fd_data));
    if (!fd_data)
	return ENOMEM;

    fd_data->fd = fd;
    fd_data->cb_data = cb_data;
    fd_data->data_ready = data_ready;
    fd_data->handler = handler;
    fd_data->freed = freed;
    rv = o->set_fd_handlers(o, fd, fd_data, fd_read_handler, fd_write_handler,
			    fd_except_handler, free_fd_data);
    if (rv) {
	free(fd_data);
	return rv;
    }
    o->set_write_handler(o, fd, false);
    o->set_except_handler(o, fd, false);
    o->set_read_handler(o, fd, true);

    *id = fd_data;
    return 0;
}

static int
gio_remove_fd_to_wait_for(os_handler_t   *handler,
			  os_hnd_fd_id_t *id)
{
    struct igensio_info *info = handler->internal_data;
    struct gensio_os_funcs *o = info->o;

    o->set_read_handler(o, id->fd, false);
    o->clear_fd_handlers(o, id->fd);
    return 0;
}

struct os_hnd_timer_id_s
{
    void           *cb_data;
    os_timed_out_t timed_out;
    struct gensio_timer *timer;
    bool running;
    os_handler_t *handler;
    struct gensio_lock *lock;
};

static void
timer_handler(struct gensio_timer *t, void *data)
{
    os_hnd_timer_id_t *timer = (os_hnd_timer_id_t *) data;
    os_handler_t *handler = timer->handler;
    struct igensio_info *info = handler->internal_data;
    struct gensio_os_funcs *o = info->o;
    void              *cb_data;
    os_timed_out_t    timed_out;

    o->lock(timer->lock);
    timed_out = timer->timed_out;
    cb_data = timer->cb_data;
    timer->running = false;
    o->unlock(timer->lock);
    timed_out(cb_data, timer);
}

static int
gio_alloc_timer(os_handler_t      *handler,
		os_hnd_timer_id_t **rtimer)
{
    os_hnd_timer_id_t *timer;
    struct igensio_info *info = handler->internal_data;
    struct gensio_os_funcs *o = info->o;

    timer = malloc(sizeof(*timer));
    if (!timer)
	return ENOMEM;

    timer->lock = o->alloc_lock(o);
    if (!timer->lock) {
	free(timer);
	return ENOMEM;
    }

    timer->running = false;
    timer->timed_out = NULL;
    timer->handler = handler;

    timer->timer = o->alloc_timer(o, timer_handler, timer);
    if (!timer->timer) {
	o->free_lock(timer->lock);
	free(timer);
	return ENOMEM;
    }

    *rtimer = timer;
    return 0;
}

static int
gio_free_timer(os_handler_t      *handler,
	       os_hnd_timer_id_t *timer)
{
    struct igensio_info *info = handler->internal_data;
    struct gensio_os_funcs *o = info->o;

    o->free_timer(timer->timer);
    o->free_lock(timer->lock);
    free(timer);
    return 0;
}

static int
gio_start_timer(os_handler_t      *handler,
		os_hnd_timer_id_t *timer,
		struct timeval    *timeout,
		os_timed_out_t    timed_out,
		void              *cb_data)
{
    struct igensio_info *info = handler->internal_data;
    struct gensio_os_funcs *o = info->o;
    int rv = 0;

    o->lock(timer->lock);
    if (timer->running) {
	rv = EBUSY;
	goto out_unlock;
    }

    timer->running = true;
    timer->cb_data = cb_data;
    timer->timed_out = timed_out;

    rv = o->start_timer(timer->timer, timeout);
    if (rv)
	timer->running = false;
    
 out_unlock:
    o->unlock(timer->lock);

    return rv;
}

static int
gio_stop_timer(os_handler_t *handler,
	       os_hnd_timer_id_t *timer)
{
    struct igensio_info *info = handler->internal_data;
    struct gensio_os_funcs *o = info->o;
    int rv = 0;

    o->lock(timer->lock);
    if (timer->running) {
	timer->running = 0;
	o->stop_timer(timer->timer);
    } else {
	rv = ETIMEDOUT;
    }
    o->unlock(timer->lock);

    return rv;
}

struct os_hnd_lock_s
{
    struct gensio_lock *lock;
};

static int
gio_create_lock(os_handler_t  *handler,
		os_hnd_lock_t **rlock)
{
    struct igensio_info *info = handler->internal_data;
    struct gensio_os_funcs *o = info->o;
    os_hnd_lock_t *lock;

    lock = malloc(sizeof(*lock));
    if (!lock)
	return ENOMEM;

    lock->lock = o->alloc_lock(o);
    if (!lock->lock) {
	free(lock);
	return ENOMEM;
    }

    *rlock = lock;

    return 0;
}

static int
gio_destroy_lock(os_handler_t  *handler,
		 os_hnd_lock_t *lock)
{
    struct igensio_info *info = handler->internal_data;
    struct gensio_os_funcs *o = info->o;

    o->free_lock(lock->lock);
    free(lock);
    return 0;
}

static int
gio_lock(os_handler_t  *handler,
	 os_hnd_lock_t *lock)
{
    struct igensio_info *info = handler->internal_data;
    struct gensio_os_funcs *o = info->o;

    o->lock(lock->lock);
    return 0;
}

static int
gio_unlock(os_handler_t  *handler,
	   os_hnd_lock_t *lock)
{
    struct igensio_info *info = handler->internal_data;
    struct gensio_os_funcs *o = info->o;

    o->unlock(lock->lock);
    return 0;
}

static int
gio_get_random(os_handler_t  *handler,
	       void          *data,
	       unsigned int  len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    int rv;

    if (fd == -1)
	return errno;

    while (len > 0) {
	rv = read(fd, data, len);
	if (rv < 0) {
	    rv = errno;
	    goto out;
	}
	len -= rv;
	data += rv;
    }

    rv = 0;

 out:
    close(fd);
    return rv;
}

static void
gio_vlog(os_handler_t         *handler,
	 enum ipmi_log_type_e log_type, 
	 const char           *format,
	 va_list              ap)
{
    struct igensio_info *info = handler->internal_data;
    os_vlog_t log_handler = info->log_handler;
    enum gensio_log_levels level;

    switch(log_type) {
    case IPMI_LOG_INFO:
    default:
	level = GENSIO_LOG_INFO;
	break;

    case IPMI_LOG_WARNING:
    case IPMI_LOG_ERR_INFO:
	level = GENSIO_LOG_WARNING;
	break;

    case IPMI_LOG_SEVERE:
	level = GENSIO_LOG_ERR;
	break;

    case IPMI_LOG_FATAL:
	level = GENSIO_LOG_FATAL;
	break;

    case IPMI_LOG_DEBUG:
    case IPMI_LOG_DEBUG_START:
    case IPMI_LOG_DEBUG_CONT:
    case IPMI_LOG_DEBUG_END:
	level = GENSIO_LOG_DEBUG;
	break;
    }

    if (log_handler) {
	log_handler(handler, format, log_type, ap);
    } else if (info->o->vlog) {
	gensio_vlog(info->o, level, format, ap);
    } else if (gensio_log_mask & (1 << level)) {
	vprintf(format, ap);
	putc('\n', stdout);
    }
}

static void
gio_log(os_handler_t         *handler,
	enum ipmi_log_type_e log_type, 
	const char           *format,
	...)
{
    va_list ap;

    va_start(ap, format);
    gio_vlog(handler, log_type, format, ap);
    va_end(ap);
}

static void
gio_set_log_handler(os_handler_t *handler,
		    os_vlog_t    log_handler)
{
    struct igensio_info *info = handler->internal_data;

    info->log_handler = log_handler;
}

static void
gio_set_fd_handlers(os_handler_t *handler, os_hnd_fd_id_t *id,
		    os_data_ready_t write_ready,
		    os_data_ready_t except_ready)
{
    id->write_ready = write_ready;
    id->except_ready = except_ready;
}

static int
gio_set_fd_enables(os_handler_t *handler, os_hnd_fd_id_t *id,
		   int read, int write, int except)
{
    struct igensio_info *info = handler->internal_data;
    struct gensio_os_funcs *o = info->o;

    o->set_read_handler(o, id->fd, read);
    o->set_write_handler(o, id->fd, write);
    o->set_except_handler(o, id->fd, except);
    return 0;
}

int
gio_get_monotonic_time(os_handler_t *handler, struct timeval *tv)
{
    struct igensio_info *info = handler->internal_data;
    struct gensio_os_funcs *o = info->o;

    o->get_monotonic_time(o, tv);
    return 0;
}

int
gio_get_real_time(os_handler_t *handler, struct timeval *tv)
{
    gettimeofday(tv, NULL);
    return 0;
}

void
gio_free(os_handler_t *gio)
{
    struct igensio_info *info = gio->internal_data;

    free(info);
    free(gio);
}

void ipmi_malloc_init(os_handler_t *oshandler);
void ipmi_malloc_shutdown(void);

os_handler_t *
gio_alloc(struct gensio_os_funcs *o)
{
    struct igensio_info *info;
    os_handler_t *handler;
    os_handler_t dummyh;

    info = malloc(sizeof(*info));
    if (!info)
	return NULL;
    info->o = o;
    info->log_handler = NULL;

    memset(&dummyh, 0, sizeof(dummyh));
    dummyh.mem_alloc = gio_mem_alloc;
    dummyh.mem_free = gio_mem_free;
    ipmi_malloc_init(&dummyh);

    handler = ipmi_alloc_os_handler();
    if (!handler) {
	free(info);
	return NULL;
    }

    ipmi_malloc_shutdown();

    handler->mem_alloc = gio_mem_alloc;
    handler->mem_free = gio_mem_free;
    handler->add_fd_to_wait_for = gio_add_fd_to_wait_for;
    handler->remove_fd_to_wait_for = gio_remove_fd_to_wait_for;
    handler->alloc_timer = gio_alloc_timer;
    handler->free_timer = gio_free_timer;
    handler->start_timer = gio_start_timer;
    handler->stop_timer = gio_stop_timer;
    handler->create_lock = gio_create_lock;
    handler->destroy_lock = gio_destroy_lock;
    handler->lock = gio_lock;
    handler->unlock = gio_unlock;
    handler->get_random = gio_get_random;
    handler->log = gio_log;
    handler->vlog = gio_vlog;
    handler->set_log_handler = gio_set_log_handler;
    handler->set_fd_handlers = gio_set_fd_handlers;
    handler->set_fd_enables = gio_set_fd_enables;
    handler->get_monotonic_time = gio_get_monotonic_time;
    handler->get_real_time = gio_get_real_time;

    handler->internal_data = info;
    return handler;
};

enum sol_state {
    SOL_CLOSED,
    SOL_IN_OPEN,
    SOL_IN_SOL_OPEN,
    SOL_OPEN,
    SOL_IN_CLOSE
};

struct sol_ll {
    struct gensio_ll ll;
    struct gensio_os_funcs *o;

    struct gensio_lock *lock;

    unsigned int refcount;

    /* Callbacks set by gensio_base. */
    gensio_ll_cb cb;
    void *cb_data;

    /* Serial callbacks. */
    gensio_ll_ipmisol_cb ser_cbs;
    void *ser_cbs_data;

    char *devname;

    ipmi_args_t *args;
    ipmi_con_t *ipmi;
    ipmi_sol_conn_t *sol;

    enum sol_state state;

    bool read_enabled;
    bool write_enabled;

    gensio_ll_open_done open_done;
    void *open_data;
    int open_err;

    gensio_ll_close_done close_done;
    void *close_data;

    struct sbuf read_data;
    unsigned int max_write_size;

    /*
     * If the connection is closed or goes down from the remote end,
     * this hold the error to return (if non-zero);
     */
    int read_err;

    bool in_read;
    bool in_write;
    unsigned int write_outstanding;

    bool deferred_op_pending;
    struct gensio_runner *deferred_op_runner;

    bool deferred_read;
    bool deferred_write;

    /* The last report from the SOL connection whether it's up or not. */
    int last_any_port_up;

    unsigned int nacks_sent;

    /* SOL parms */
    int speed;
    int authenticated;
    int disablebreak;
    int encrypted;
    int ack_timeout;
    int ack_retries;
    int deassert_CTS_DCD_DSR_on_connect;
    int shared_serial_alert_behavior;
};

os_handler_t *gensio_os_handler;

#define ll_to_sol(v) container_of(v, struct sol_ll, ll)

static void
sol_lock(struct sol_ll *solll)
{
    solll->o->lock(solll->lock);
}

static void
sol_unlock(struct sol_ll *solll)
{
    solll->o->unlock(solll->lock);
}

static void
sol_ref(struct sol_ll *solll)
{
    solll->refcount++;
}

static void sol_finish_free(struct sol_ll *solll)
{
    if (solll->lock)
	solll->o->free_lock(solll->lock);
    if (solll->read_data.buf)
	solll->o->free(solll->o, solll->read_data.buf);
    if (solll->deferred_op_runner)
	solll->o->free_runner(solll->deferred_op_runner);
    if (solll->ser_cbs)
	solll->ser_cbs(solll->ser_cbs_data, GENSIO_SOL_LL_FREE, NULL);
    if (solll->args)
	ipmi_free_args(solll->args);
    if (solll->devname)
	solll->o->free(solll->o, solll->devname);
    solll->o->free(solll->o, solll);
}

static void
sol_deref_and_unlock(struct sol_ll *solll)
{
    unsigned int count;

    assert(solll->refcount > 0);
    count = --solll->refcount;
    sol_unlock(solll);
    if (count == 0)
	sol_finish_free(solll);
}

static int sol_xlat_ipmi_err(int err)
{
    if (err == IPMI_SOL_DISCONNECTED)
	err = ECONNRESET;
    else if (err == IPMI_SOL_NOT_AVAILABLE)
	err = ECOMM;
    else if (err == IPMI_RMCPP_INVALID_PAYLOAD_TYPE)
	err = ECONNREFUSED;
    else if (err == IPMI_SOL_DEACTIVATED)
	err = EHOSTUNREACH;
    else if (IPMI_IS_OS_ERR(err))
	err = IPMI_GET_OS_ERR(err);
    else
	err = ECOMM;
    return err;
}

static int
sol_do_read_send(void *cb_data, void *buf, unsigned int buflen,
		 unsigned int *written)
{
    struct sol_ll *solll = cb_data;
    unsigned int count;

    solll->in_read = true;
    sol_unlock(solll);
    count = solll->cb(solll->cb_data, GENSIO_LL_CB_READ, 0, buf, buflen, NULL);
    sol_lock(solll);
    solll->in_read = false;
    *written = count;
    return 0;
}

static void
check_for_read_delivery(struct sol_ll *solll)
{
    while (solll->read_enabled &&
	   (buffer_cursize(&solll->read_data) || solll->read_err) &&
	   !solll->in_read) {
	if (solll->read_err) {
	    sol_unlock(solll);
	    solll->cb(solll->cb_data, GENSIO_LL_CB_READ, solll->read_err,
		      NULL, 0, NULL);
	    sol_lock(solll);
	} else {
	    buffer_write(sol_do_read_send, solll, &solll->read_data);

	    /* Maybe we consumed some data, let the other end send if so. */
	    while (solll->nacks_sent > 0 &&
		   buffer_left(&solll->read_data) > 128) { /* FIXME - magic */
		if (ipmi_sol_release_nack(solll->sol))
		    break;
		solll->nacks_sent--;
	    }
	}
    }
}

static void
check_for_write_ready(struct sol_ll *solll)
{
    while (!solll->in_write &&
	   solll->write_enabled &&
	   solll->write_outstanding < solll->max_write_size) {
	solll->in_write = true;
	sol_unlock(solll);
	solll->cb(solll->cb_data, GENSIO_LL_CB_WRITE_READY, 0, NULL, 0, NULL);
	sol_lock(solll);
	solll->in_write = false;
    }
}

static void
sol_deferred_op(struct gensio_runner *runner, void *cbdata)
{
    struct sol_ll *solll = cbdata;

    sol_lock(solll);
    while (solll->deferred_op_pending) {
	solll->deferred_op_pending = false;

	while (solll->deferred_read) {
	    solll->deferred_read = false;
	    check_for_read_delivery(solll);
	}

	while (solll->deferred_write) {
	    solll->deferred_write = false;
	    check_for_write_ready(solll);
	}
    }

    sol_deref_and_unlock(solll);
}

static void
sol_sched_deferred_op(struct sol_ll *solll)
{
    if (!solll->deferred_op_pending) {
	/* Call the read from the selector to avoid lock nesting issues. */
	sol_ref(solll);
	solll->deferred_op_pending = true;
	solll->o->run(solll->deferred_op_runner);
    }
}

static void
sol_set_callbacks(struct gensio_ll *ll, gensio_ll_cb cb, void *cb_data)
{
    struct sol_ll *solll = ll_to_sol(ll);

    solll->cb = cb;
    solll->cb_data = cb_data;
}

struct sol_tc {
    unsigned int size;
    struct sol_ll *solll;
};

static void connection_closed(ipmi_con_t *ipmi, void *cb_data);

static void
transmit_complete(ipmi_sol_conn_t *conn,
		  int             err,
		  void            *cb_data)
{
    struct sol_tc *tc = cb_data;
    struct sol_ll *solll = tc->solll;

    if (err)
	err = sol_xlat_ipmi_err(err);

    sol_lock(solll);
    if (err && solll->state != SOL_IN_CLOSE) {
	solll->read_err = err;
	check_for_read_delivery(solll);
    } else {
	solll->write_outstanding -= tc->size;
	if (solll->state == SOL_IN_CLOSE) {
	    if (solll->write_outstanding == 0) {
		err = ipmi_sol_close(solll->sol);
		if (err)
		    err = solll->ipmi->close_connection_done(solll->ipmi,
							     connection_closed,
							     solll);
		if (err) {
		    solll->state = SOL_CLOSED;
		    solll->ipmi = NULL;
		    if (solll->close_done)
			solll->close_done(solll->cb_data, solll->open_data);
		}
	    }
	} else {
	    check_for_write_ready(solll);
	}
    }
    solll->o->free(solll->o, tc);
    sol_deref_and_unlock(solll);
}

static int
sol_write(struct gensio_ll *ll, unsigned int *rcount,
	  const unsigned char *buf, unsigned int buflen)
{
    struct sol_ll *solll = ll_to_sol(ll);
    int err = 0;
    struct sol_tc *tc;
    unsigned int left;

    sol_lock(solll);
    if (solll->state != SOL_OPEN) {
	err = EBADF;
	goto out_unlock;
    }

    left = solll->max_write_size - solll->write_outstanding;
    if (left < buflen)
	buflen = left;

    if (buflen == 0)
	goto out_finish;

    tc = solll->o->zalloc(solll->o, sizeof(*tc));
    if (!tc) {
	err = ENOMEM;
	goto out_unlock;
    }

    tc->size = buflen;
    tc->solll = solll;
    err = ipmi_sol_write(solll->sol, buf, buflen, transmit_complete, tc);
    if (err) {
	err = sol_xlat_ipmi_err(err);
	free(tc);
	goto out_unlock;
    } else {
	solll->write_outstanding += buflen;
	sol_ref(solll);
    }
    
 out_finish:
    *rcount = buflen;
 out_unlock:
    sol_unlock(solll);

    return err;
}

static int
sol_raddr_to_str(struct gensio_ll *ll, unsigned int *pos,
		char *buf, unsigned int buflen)
{
    /* FIXME - do something here. */
    return ENOTSUP;
}

static int
sol_get_raddr(struct gensio_ll *ll, void *addr, unsigned int *addrlen)
{
    return ENOTSUP;
}

static int
sol_remote_id(struct gensio_ll *ll, int *id)
{
    return ENOTSUP;
}

static int
sol_data_received(ipmi_sol_conn_t *conn,
		  const void *idata, size_t count, void *user_data)
{
    struct sol_ll *solll = user_data;
    int rv = 0;

    sol_lock(solll);
    if (count <= buffer_left(&solll->read_data)) {
	buffer_output(&solll->read_data, idata, count);
	check_for_read_delivery(solll);
    } else {
	solll->nacks_sent++;
	rv = 1;
    }
    sol_unlock(solll);
    return rv;
}

static void
sol_break_detected(ipmi_sol_conn_t *conn, void *user_data)
{
}

static void
bmc_transmit_overrun(ipmi_sol_conn_t *conn, void *user_data)
{
}

static void
connection_closed(ipmi_con_t *ipmi, void *cb_data)
{
    struct sol_ll *solll = cb_data;
    enum sol_state old_state;

    sol_lock(solll);
    old_state = solll->state;
    solll->state = SOL_CLOSED;
    solll->ipmi = NULL;
    sol_unlock(solll);

    if (old_state == SOL_IN_SOL_OPEN) {
	if (solll->open_done)
	    solll->open_done(solll->cb_data, solll->read_err, solll->open_data);
    } else {
	if (solll->close_done)
	    solll->close_done(solll->cb_data, solll->open_data);
    }
}

static void
sol_connection_state(ipmi_sol_conn_t *conn, ipmi_sol_state state,
		     int err, void *cb_data)
{
    struct sol_ll *solll = cb_data;

    
    if (err)
	err = sol_xlat_ipmi_err(err);

    sol_lock(solll);
    switch (state) {
    case ipmi_sol_state_closed:
	if (solll->state == SOL_IN_SOL_OPEN) {
	    solll->read_err = ECONNREFUSED;
	    if (solll->sol) {
		ipmi_sol_free(solll->sol);
		solll->sol = NULL;
		sol_unlock(solll);
		solll->ipmi->close_connection_done(solll->ipmi,
						   connection_closed,
						   solll);
		return;
	    }
	} else if (solll->state == SOL_IN_CLOSE) {
	    if (solll->sol) {
		ipmi_sol_free(solll->sol);
		solll->sol = NULL;
		sol_unlock(solll);
		solll->ipmi->close_connection_done(solll->ipmi,
						   connection_closed,
						   solll);
		return;
	    }
	} else if (solll->state == SOL_OPEN && !solll->read_err) {
	    if (err)
		solll->read_err = err;
	    else
		solll->read_err = EBADF;
	    check_for_read_delivery(solll);
	}
	break;

    case ipmi_sol_state_connecting:
	break;

    case ipmi_sol_state_connected:
	if (solll->state == SOL_IN_SOL_OPEN) {
	    solll->state = SOL_OPEN;
	    sol_unlock(solll);
	    solll->open_done(solll->cb_data, err, solll->open_data);
	    sol_lock(solll);
	}
	break;

    case ipmi_sol_state_connected_ctu:
	break;

    case ipmi_sol_state_closing:
	break;
    }
    sol_unlock(solll);
}

static void
conn_changed(ipmi_con_t   *ipmi,
	     int          err,
	     unsigned int port_num,
	     int          any_port_up,
	     void         *cb_data)
{
    struct sol_ll *solll = cb_data;

    if (err)
	err = sol_xlat_ipmi_err(err);

    sol_lock(solll);
    if (any_port_up == solll->last_any_port_up)
	goto out_unlock;

    solll->last_any_port_up = any_port_up;

    if (solll->state == SOL_IN_OPEN || solll->state == SOL_IN_SOL_OPEN) {
	if (any_port_up && solll->state == SOL_IN_OPEN) {
	    solll->state = SOL_IN_SOL_OPEN;
	    sol_unlock(solll);
	    ipmi_sol_open(solll->sol);
	    return;
	} else if (!any_port_up && (err || solll->read_err)) {
	    solll->state = SOL_CLOSED;
	    if (solll->read_err)
		err = solll->read_err; /* Prefer the first error we got. */
	    sol_unlock(solll);
	    solll->open_done(solll->cb_data, err, solll->open_data);
	    return;
	}
    } else if (solll->state == SOL_IN_CLOSE) {
	if (!any_port_up) {
	    solll->state = SOL_CLOSED;
	    sol_unlock(solll);
	    solll->close_done(solll->cb_data, solll->open_data);
	    return;
	}
    } else if (err) {
	solll->read_err = err;
    } else if (!any_port_up) {
	solll->read_err = EBADF;
    }
	
 out_unlock:
    sol_unlock(solll);
}

static int
sol_open(struct gensio_ll *ll, gensio_ll_open_done done, void *open_data)
{
    struct sol_ll *solll = ll_to_sol(ll);
    int err;

    sol_lock(solll);
    if (solll->state != SOL_CLOSED) {
	err = EBUSY;
	goto out_unlock;
    }

    solll->in_read = false;
    solll->write_outstanding = 0;
    solll->read_err = 0;
    solll->deferred_read = false;
    solll->deferred_write = false;
    buffer_reset(&solll->read_data);
    solll->nacks_sent = 0;

    err = ipmi_args_setup_con(solll->args, gensio_os_handler, NULL,
			      &solll->ipmi);
    if (err)
	return err;

    err = ipmi_sol_create(solll->ipmi, &solll->sol);
    if (err)
	goto out_err;

    err = ipmi_sol_register_data_received_callback(solll->sol,
						   sol_data_received, solll);
    if (err)
	goto out_err;

    err = ipmi_sol_register_break_detected_callback(solll->sol,
						    sol_break_detected, solll);
    if (err)
	goto out_err;

    err = ipmi_sol_register_bmc_transmit_overrun_callback(solll->sol,
							  bmc_transmit_overrun,
							  solll);
    if (err)
	goto out_err;

    err = ipmi_sol_register_connection_state_callback(solll->sol,
						      sol_connection_state,
						      solll);
    if (err)
	goto out_err;

    ipmi_sol_set_ACK_retries(solll->sol, solll->ack_retries);
    ipmi_sol_set_ACK_timeout(solll->sol, solll->ack_timeout);
    ipmi_sol_set_use_authentication(solll->sol, solll->authenticated);
    ipmi_sol_set_use_encryption(solll->sol, solll->encrypted);
    ipmi_sol_set_shared_serial_alert_behavior(solll->sol,
				solll->shared_serial_alert_behavior);
    ipmi_sol_set_deassert_CTS_DCD_DSR_on_connect(solll->sol,
				solll->deassert_CTS_DCD_DSR_on_connect);

    ipmi_sol_set_bit_rate(solll->sol, solll->speed);

    err = solll->ipmi->add_con_change_handler(solll->ipmi, conn_changed, solll);
    if (err)
	goto out_err;

    solll->last_any_port_up = 0;
    solll->state = SOL_IN_OPEN;
    solll->open_done = done;
    solll->open_data = open_data;

    solll->ipmi->start_con(solll->ipmi);

    sol_unlock(solll);
    return EINPROGRESS;

 out_err:
    if (solll->sol) {
	ipmi_sol_close(solll->sol);
	ipmi_sol_free(solll->sol);
	solll->sol = NULL;
    }
    if (solll->ipmi) {
	solll->ipmi->close_connection(solll->ipmi);
	solll->ipmi = NULL;
    }
 out_unlock:
    sol_unlock(solll);
    return err;
}

static int sol_close(struct gensio_ll *ll, gensio_ll_close_done done,
		    void *close_data)
{
    struct sol_ll *solll = ll_to_sol(ll);
    int err = EBUSY;

    sol_lock(solll);
    if (solll->state == SOL_OPEN || solll->state == SOL_IN_OPEN ||
		solll->state == SOL_IN_SOL_OPEN) {
	solll->read_enabled = false;
	solll->write_enabled = false;
	solll->close_done = done;
	solll->close_data = close_data;
	solll->state = SOL_IN_CLOSE;
	if (solll->sol) {
	    if (solll->write_outstanding == 0)
		err = ipmi_sol_close(solll->sol);
	    else
		err = 0;
	} else {
	    err = solll->ipmi->close_connection_done(solll->ipmi,
						     connection_closed,
						     solll);
	}

	if (err)
	    err = sol_xlat_ipmi_err(err);
	else
	    err = EINPROGRESS;
    }
    sol_unlock(solll);

    return err;
}

static void
sol_set_read_callback_enable(struct gensio_ll *ll, bool enabled)
{
    struct sol_ll *solll = ll_to_sol(ll);

    sol_lock(solll);
    if (solll->read_enabled != enabled) {
	solll->read_enabled = enabled;

	if (enabled && solll->state == SOL_OPEN) {
	    solll->deferred_read = true;
	    sol_sched_deferred_op(solll);
	}
    }
    sol_unlock(solll);
}

static void
sol_set_write_callback_enable(struct gensio_ll *ll, bool enabled)
{
    struct sol_ll *solll = ll_to_sol(ll);

    sol_lock(solll);
    if (solll->write_enabled != enabled) {
	solll->write_enabled = enabled;

	if (enabled && solll->state == SOL_OPEN &&
		solll->write_outstanding < solll->max_write_size) {
	    solll->deferred_write = true;
	    sol_sched_deferred_op(solll);
	}
    }
    sol_unlock(solll);
}

static void sol_free(struct gensio_ll *ll)
{
    struct sol_ll *solll = ll_to_sol(ll);

    sol_lock(solll);
    sol_deref_and_unlock(solll);
}

static int
gensio_ll_sol_func(struct gensio_ll *ll, int op, int val,
		  const void *func, void *data,
		  unsigned int *count,
		  void *buf, const void *cbuf,
		  unsigned int buflen)
{
    switch (op) {
    case GENSIO_LL_FUNC_SET_CALLBACK:
	sol_set_callbacks(ll, func, data);
	return 0;

    case GENSIO_LL_FUNC_WRITE:
	return sol_write(ll, count, cbuf, buflen);

    case GENSIO_LL_FUNC_RADDR_TO_STR:
	return sol_raddr_to_str(ll, count, buf, buflen);

    case GENSIO_LL_FUNC_GET_RADDR:
	return sol_get_raddr(ll, buf, count);

    case GENSIO_LL_FUNC_REMOTE_ID:
	return sol_remote_id(ll, data);

    case GENSIO_LL_FUNC_OPEN:
	return sol_open(ll, func, data);

    case GENSIO_LL_FUNC_CLOSE:
	return sol_close(ll, func, data);

    case GENSIO_LL_FUNC_SET_READ_CALLBACK:
	sol_set_read_callback_enable(ll, val);
	return 0;

    case GENSIO_LL_FUNC_SET_WRITE_CALLBACK:
	sol_set_write_callback_enable(ll, val);
	return 0;

    case GENSIO_LL_FUNC_FREE:
	sol_free(ll);
	return 0;

    default:
	return ENOTSUP;
    }
}

static int
ipmisol_ser_ops(struct gensio_ll *ll, int op,
		int val, char *buf,
		void *done, void *cb_data)
{
    switch (op) {
    case SERGENSIO_FUNC_FLUSH:
    break;

    case SERGENSIO_FUNC_SEND_BREAK:
    break;

    /* You really can't set much on a SOL connection once it's up. */
    case SERGENSIO_FUNC_BAUD:
    case SERGENSIO_FUNC_DATASIZE:
    case SERGENSIO_FUNC_PARITY:
    case SERGENSIO_FUNC_STOPBITS:
    case SERGENSIO_FUNC_FLOWCONTROL:
    case SERGENSIO_FUNC_IFLOWCONTROL:
    case SERGENSIO_FUNC_SBREAK:
    case SERGENSIO_FUNC_DTR:
    case SERGENSIO_FUNC_RTS:
    case SERGENSIO_FUNC_MODEMSTATE:
    case SERGENSIO_FUNC_LINESTATE:
    case SERGENSIO_FUNC_FLOWCONTROL_STATE:
    case SERGENSIO_FUNC_SIGNATURE:
    default:
	return ENOTSUP;
    }

    return 0;
}

static int
sol_get_defaults(struct sol_ll *solll)
{
    struct gensio_os_funcs *o = solll->o;
    int speed;

    gensio_get_default(o, "sol", "speed", false,
		       GENSIO_DEFAULT_INT, NULL, &speed);
    switch (speed) {
    case 9600: solll->speed = IPMI_SOL_BIT_RATE_9600; break;
    case 19200: solll->speed = IPMI_SOL_BIT_RATE_19200; break;
    case 38400: solll->speed = IPMI_SOL_BIT_RATE_38400; break;
    case 57600: solll->speed = IPMI_SOL_BIT_RATE_57600; break;
    case 115200: solll->speed = IPMI_SOL_BIT_RATE_115200; break;
    default:
	gensio_log(o, GENSIO_LOG_WARNING,
		   "Invalid default speed for SOL %s: %d.  Defaulting to 9600",
		   solll->devname, speed);
	solll->speed = IPMI_SOL_BIT_RATE_9600;
	break;
    }

    /* Enable authentication and encryption by default. */
    gensio_get_default(o, "sol", "authenticated", false,
		       GENSIO_DEFAULT_INT, NULL, &solll->authenticated);
    gensio_get_default(o, "sol", "encrypted", false,
		       GENSIO_DEFAULT_INT, NULL, &solll->encrypted);
    gensio_get_default(o, "sol", "nobreak", false,
		       GENSIO_DEFAULT_INT, NULL, &solll->disablebreak);
    gensio_get_default(o, "sol", "ack-timeout", false,
		       GENSIO_DEFAULT_INT, NULL, &solll->ack_timeout);
    gensio_get_default(o, "sol", "ack-retries", false,
		       GENSIO_DEFAULT_INT, NULL, &solll->ack_retries);
    gensio_get_default(o, "sol", "shared-serial-alert", false,
		       GENSIO_DEFAULT_INT, NULL,
		       &solll->shared_serial_alert_behavior);
    gensio_get_default(o, "sol", "deassert_CTS_DCD_DSR_on_connect", false,
		       GENSIO_DEFAULT_INT, NULL,
		       &solll->deassert_CTS_DCD_DSR_on_connect);

    return 0;
}

static int
sol_process_parm(struct sol_ll *solll, char *arg)
{
    char *endpos;

    if (strcmp(arg, "9600") == 0) {
	solll->speed = IPMI_SOL_BIT_RATE_9600;
    } else if (strcmp(arg, "19200") == 0) {
	solll->speed = IPMI_SOL_BIT_RATE_19200;
    } else if (strcmp(arg, "38400") == 0) {
	solll->speed = IPMI_SOL_BIT_RATE_38400;
    } else if (strcmp(arg, "57600") == 0) {
	solll->speed = IPMI_SOL_BIT_RATE_57600;
    } else if (strcmp(arg, "115200") == 0) {
	solll->speed = IPMI_SOL_BIT_RATE_115200;
    } else if (strcmp(arg, "-NOBREAK") == 0) {
	solll->disablebreak = 0;
    } else if (strcmp(arg, "NOBREAK") == 0) {
	solll->disablebreak = 1;
    } else if (strcmp(arg, "-authenticated") == 0) {
	solll->authenticated = 0;
    } else if (strcmp(arg, "authenticated") == 0) {
	solll->authenticated = 1;
    } else if (strcmp(arg, "-encrypted") == 0) {
	solll->encrypted = 0;
    } else if (strcmp(arg, "encrypted") == 0) {
	solll->encrypted = 1;
    } else if (strcmp(arg, "-deassert_CTS_DCD_DSR_on_connect") == 0) {
	solll->deassert_CTS_DCD_DSR_on_connect = 0;
    } else if (strcmp(arg, "deassert_CTS_DCD_DSR_on_connect") == 0) {
	solll->deassert_CTS_DCD_DSR_on_connect = 1;
    } else if (strcmp(arg, "shared_serial_alert_fail") == 0) {
	solll->shared_serial_alert_behavior = ipmi_sol_serial_alerts_fail;
    } else if (strcmp(arg, "shared_serial_alert_deferred") == 0) {
	solll->shared_serial_alert_behavior = ipmi_sol_serial_alerts_deferred;
    } else if (strcmp(arg, "shared_serial_alert_succeed") == 0) {
	solll->shared_serial_alert_behavior = ipmi_sol_serial_alerts_succeed;
    } else if (strncmp(arg, "ack-timeout=", 12) == 0) {
	solll->ack_timeout = strtoul(arg + 12, &endpos, 10);
	if (endpos == arg + 12 || *endpos != '\0')
	    return EINVAL;
    } else if (strncmp(arg, "ack-retries=", 12) == 0) {
	solll->ack_retries = strtoul(arg + 12, &endpos, 10);
	if (endpos == arg + 12 || *endpos != '\0')
	    return EINVAL;
    } else {
	return EINVAL;
    }

    return 0;
}

static int
sol_process_parms(struct sol_ll *solll)
{
    char *pos, *strtok_data;
    int err;

    pos = strchr(solll->devname, ',');
    if (!pos)
	return 0;

    *pos++ = '\0';
    for (pos = strtok_r(pos, ",", &strtok_data); pos;
	 pos = strtok_r(NULL, ",", &strtok_data)) {
	err = sol_process_parm(solll, pos);
	if (err)
	    return err;
    }

    return 0;
}

struct gensio_once gensio_ipmi_initialized;

static void
gensio_ipmi_init(void *cb_data)
{
    struct gensio_os_funcs *o = cb_data;

    gensio_os_handler = gio_alloc(o);
    if (!gensio_os_handler)
	abort();
    ipmi_init(gensio_os_handler);
}

int
ipmisol_gensio_ll_alloc(struct gensio_os_funcs *o,
			const char *devname,
			gensio_ll_ipmisol_cb ser_cbs,
			void *ser_cbs_data,
			unsigned int max_read_size,
			unsigned int max_write_size,
			gensio_ll_ipmisol_ops *rops,
			struct gensio_ll **rll)
{
    struct sol_ll *solll;
    int err, argc, curr_arg = 0;
    char **argv;

    o->call_once(o, &gensio_ipmi_initialized, gensio_ipmi_init, o);

    solll = o->zalloc(o, sizeof(*solll));
    if (!solll)
	return ENOMEM;

    solll->o = o;
    solll->refcount = 1;
    solll->state = SOL_CLOSED;

    solll->devname = strdup(devname);
    if (!solll->devname)
	goto out_nomem;

    err = sol_get_defaults(solll);
    if (!err)
	err = sol_process_parms(solll);
    if (err)
	goto out_err;

    err = str_to_argv(solll->devname, &argc, &argv, NULL);
    if (err)
	goto out_err;
    if (argc == 0) {
	err = EINVAL;
	goto out_err;
    }

    err = ipmi_parse_args2(&curr_arg, argc, argv, &solll->args);
    if (err) {
	str_to_argv_free(argc, argv);
	goto out_err;
    }

    if (curr_arg != argc) {
	gensio_log(o, GENSIO_LOG_WARNING,
		   "Extra SOL arguments starting with %s\n", argv[curr_arg]);
	err = EINVAL;
	str_to_argv_free(argc, argv);
	goto out_err;
    }
    str_to_argv_free(argc, argv);

    solll->deferred_op_runner = o->alloc_runner(o, sol_deferred_op, solll);
    if (!solll->deferred_op_runner)
	goto out_nomem;

    solll->lock = o->alloc_lock(o);
    if (!solll->lock)
	goto out_nomem;

    solll->read_data.maxsize = max_read_size;
    solll->read_data.buf = o->zalloc(o, max_read_size);
    if (!solll->read_data.buf)
	goto out_nomem;

    /* Don't set these until here lest a failure call the free operation. */
    solll->ser_cbs = ser_cbs;
    solll->ser_cbs_data = ser_cbs_data;

    solll->max_write_size = max_write_size;

    solll->ll.func = gensio_ll_sol_func;

    *rops = ipmisol_ser_ops;
    *rll = &solll->ll;
    return 0;

 out_nomem:
    err = ENOMEM;
 out_err:
    sol_finish_free(solll);
    return err;
}

#else

int
ipmisol_gensio_ll_alloc(struct gensio_os_funcs *o,
			const char *devname,
			gensio_ll_ipmisol_cb ser_cbs,
			void *ser_cbs_data,
			unsigned int max_read_size,
			unsigned int max_write_size,
			gensio_ll_ipmisol_ops *rops,
			struct gensio_ll **rll)
{
    return ENOTSUP;
}

#endif
