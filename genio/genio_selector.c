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

#include <malloc.h>
#include <string.h>
#include <errno.h>
#include "utils/locking.h"
#include "utils/utils.h"
#include "utils/waiter.h"
#include "genio/genio_selector.h"

struct genio_data {
    struct selector_s *sel;
    int wake_sig;
};

static void *
genio_sel_zalloc(struct genio_os_funcs *f, unsigned int size)
{
    void *d = malloc(size);

    if (d)
	memset(d, 0, size);
    return d;
}

static void
genio_sel_free(struct genio_os_funcs *f, void *data)
{
    free(data);
}

struct genio_lock {
    struct genio_os_funcs *f;
    DEFINE_LOCK(, lock);
};

static struct genio_lock *
genio_sel_alloc_lock(struct genio_os_funcs *f)
{
    struct genio_lock *lock = f->zalloc(f, sizeof(*lock));

    if (lock) {
	lock->f = f;
	INIT_LOCK(lock->lock);
    }

    return lock;
}

static void
genio_sel_free_lock(struct genio_lock *lock)
{
    lock->f->free(lock->f, lock);
}

static void
genio_sel_lock(struct genio_lock *lock)
{
    LOCK(lock->lock);
}

static void
genio_sel_unlock(struct genio_lock *lock)
{
    UNLOCK(lock->lock);
}

static int
genio_sel_set_fd_handlers(struct genio_os_funcs *f,
			  int fd,
			  void *cb_data,
			  void (*read_handler)(int fd, void *cb_data),
			  void (*write_handler)(int fd, void *cb_data),
			  void (*except_handler)(int fd, void *cb_data),
			  void (*cleared_handler)(int fd, void *cb_data))
{
    struct genio_data *d = f->user_data;

    return sel_set_fd_handlers(d->sel, fd, cb_data, read_handler, write_handler,
			       except_handler, cleared_handler);
}


static void
genio_sel_clear_fd_handlers(struct genio_os_funcs *f, int fd)
{
    struct genio_data *d = f->user_data;

    return sel_clear_fd_handlers(d->sel, fd);
}

static void
genio_sel_clear_fd_handlers_imm(struct genio_os_funcs *f, int fd)
{
    struct genio_data *d = f->user_data;

    return sel_clear_fd_handlers_imm(d->sel, fd);
}

static void
genio_sel_set_read_handler(struct genio_os_funcs *f, int fd, bool enable)
{
    struct genio_data *d = f->user_data;
    int op;

    if (enable)
	op = SEL_FD_HANDLER_ENABLED;
    else
	op = SEL_FD_HANDLER_DISABLED;

    return sel_set_fd_read_handler(d->sel, fd, op);
}

static void
genio_sel_set_write_handler(struct genio_os_funcs *f, int fd, bool enable)
{
    struct genio_data *d = f->user_data;
    int op;

    if (enable)
	op = SEL_FD_HANDLER_ENABLED;
    else
	op = SEL_FD_HANDLER_DISABLED;

    return sel_set_fd_write_handler(d->sel, fd, op);
}

static void
genio_sel_set_except_handler(struct genio_os_funcs *f, int fd, bool enable)
{
    struct genio_data *d = f->user_data;
    int op;

    if (enable)
	op = SEL_FD_HANDLER_ENABLED;
    else
	op = SEL_FD_HANDLER_DISABLED;

    return sel_set_fd_except_handler(d->sel, fd, op);
}

struct genio_timer {
    struct genio_os_funcs *f;
    void (*handler)(struct genio_timer *t, void *cb_data);
    void *cb_data;
    sel_timer_t *sel_timer;
    DEFINE_LOCK(, lock);

    void (*done_handler)(struct genio_timer *t, void *cb_data);
    void *done_cb_data;
};

static void
genio_timeout_handler(struct selector_s *sel,
		      struct sel_timer_s *sel_timer, void *cb_data)
{
    struct genio_timer *timer = cb_data;

    timer->handler(timer, timer->cb_data);
}

static struct genio_timer *
genio_sel_alloc_timer(struct genio_os_funcs *f,
		      void (*handler)(struct genio_timer *t, void *cb_data),
		      void *cb_data)
{
    struct genio_data *d = f->user_data;
    struct genio_timer *timer;
    int rv;

    timer = f->zalloc(f, sizeof(*timer));
    if (!timer)
	return NULL;

    timer->f = f;
    timer->handler = handler;
    timer->cb_data = cb_data;
    INIT_LOCK(timer->lock);

    rv = sel_alloc_timer(d->sel, genio_timeout_handler, timer,
			 &timer->sel_timer);
    if (rv) {
	f->free(f, timer);
	return NULL;
    }

    return timer;
}

static void
genio_sel_free_timer(struct genio_timer *timer)
{
    sel_free_timer(timer->sel_timer);
    timer->f->free(timer->f, timer);
}

static int
genio_sel_start_timer(struct genio_timer *timer, struct timeval *timeout)
{
    struct timeval tv;

    sel_get_monotonic_time(&tv);
    add_to_timeval(&tv, timeout);
    return sel_start_timer(timer->sel_timer, &tv);
}

static int
genio_sel_stop_timer(struct genio_timer *timer)
{
    return sel_stop_timer(timer->sel_timer);
}

static void
genio_stop_timer_done(struct selector_s *sel,
		      struct sel_timer_s *sel_timer, void *cb_data)
{
    struct genio_timer *timer = cb_data;
    void (*done_handler)(struct genio_timer *t, void *cb_data);
    void *done_cb_data;

    LOCK(timer->lock);
    done_handler = timer->done_handler;
    done_cb_data = timer->done_cb_data;
    UNLOCK(timer->lock);
    done_handler(timer, done_cb_data);
}

static int
genio_sel_stop_timer_with_done(struct genio_timer *timer,
			       void (*done_handler)(struct genio_timer *t,
						    void *cb_data),
			       void *cb_data)
{
    int rv;

    LOCK(timer->lock);
    rv = sel_stop_timer_with_done(timer->sel_timer, genio_stop_timer_done,
				  timer);
    if (!rv) {
	timer->done_handler = done_handler;
	timer->done_cb_data = cb_data;
    }
    UNLOCK(timer->lock);
    return rv;
}

struct genio_runner {
    struct genio_os_funcs *f;
    struct sel_runner_s *sel_runner;
    void (*handler)(struct genio_runner *r, void *cb_data);
    void *cb_data;
};

static struct genio_runner *
genio_sel_alloc_runner(struct genio_os_funcs *f,
		       void (*handler)(struct genio_runner *r,
				       void *cb_data),
		       void *cb_data)
{
    struct genio_data *d = f->user_data;
    struct genio_runner *runner;
    int rv;

    runner = f->zalloc(f, sizeof(*runner));
    if (!runner)
	return NULL;

    runner->f = f;
    runner->handler = handler;
    runner->cb_data = cb_data;

    rv = sel_alloc_runner(d->sel, &runner->sel_runner);
    if (rv) {
	f->free(f, runner);
	return NULL;
    }

    return runner;
}

static void
genio_sel_free_runner(struct genio_runner *runner)
{
    sel_free_runner(runner->sel_runner);
    runner->f->free(runner->f, runner);
}

static void
genio_runner_handler(sel_runner_t *sel_runner, void *cb_data)
{
    struct genio_runner *runner = cb_data;

    runner->handler(runner, runner->cb_data);
}

static int
genio_sel_run(struct genio_runner *runner)
{
    return sel_run(runner->sel_runner, genio_runner_handler, runner);
}

struct genio_waiter {
    struct genio_os_funcs *f;
    struct waiter_s *sel_waiter;
};

static struct genio_waiter *
genio_sel_alloc_waiter(struct genio_os_funcs *f)
{
    struct genio_data *d = f->user_data;
    struct genio_waiter *waiter = f->zalloc(f, sizeof(*waiter));

    if (!waiter)
	return NULL;

    waiter->f = f;

    waiter->sel_waiter = alloc_waiter(d->sel, d->wake_sig);
    if (!waiter->sel_waiter) {
	f->free(f, waiter);
	return NULL;
    }

    return waiter;
}

static void
genio_sel_free_waiter(struct genio_waiter *waiter)
{
    free_waiter(waiter->sel_waiter);
    waiter->f->free(waiter->f, waiter);
}

static int
genio_sel_wait(struct genio_waiter *waiter, struct timeval *timeout)
{
    return wait_for_waiter_timeout(waiter->sel_waiter, 1, timeout);
}


static int
genio_sel_wait_intr(struct genio_waiter *waiter, struct timeval *timeout)
{
    return wait_for_waiter_timeout_intr(waiter->sel_waiter, 1, timeout);
}

static void
genio_sel_wake(struct genio_waiter *waiter)
{
    wake_waiter(waiter->sel_waiter);
}

#ifdef USE_PTHREADS
#include <pthread.h>
#include <signal.h>

struct wait_data {
    pthread_t id;
    int wake_sig;
};

static void
wake_thread_send_sig(long thread_id, void *cb_data)
{
    struct wait_data *w = cb_data;

    pthread_kill(w->id, w->wake_sig);
}

static int
genio_sel_service(struct genio_os_funcs *f, struct timeval *timeout)
{
    struct genio_data *d = f->user_data;
    struct wait_data w;
    int err;

    w.id = pthread_self();
    w.wake_sig = d->wake_sig;
    err = sel_select_intr(d->sel, wake_thread_send_sig, w.id, &w, timeout);
    if (err < 0)
	err = errno;
    else if (err == 0)
	err = ETIMEDOUT;
    else
	err = 0;

    return err;
}
#else
static int
genio_sel_service(struct genio_os_funcs *f, struct timeval *timeout)
{
    struct genio_data *d = f->user_data;
    int err;

    err = sel_select_intr(d->sel, NULL, 0, NULL, timeout);
    if (err < 0)
	err = errno;
    else if (err == 0)
	err = ETIMEDOUT;
    else
	err = 0;

    return err;
}
#endif

static void
genio_sel_free_funcs(struct genio_os_funcs *f)
{
    free(f->user_data);
    free(f);
}

struct genio_os_funcs *
genio_selector_alloc(struct selector_s *sel, int wake_sig)
{
    struct genio_data *d;
    struct genio_os_funcs *o;

    o = malloc(sizeof(*o));
    if (!o)
	return NULL;
    memset(o, 0, sizeof(*o));

    d = malloc(sizeof(*d));
    if (!d) {
	free(o);
	return NULL;
    }
    memset(d, 0, sizeof(*d));

    o->user_data = d;
    d->sel = sel;
    d->wake_sig = wake_sig;

    o->zalloc = genio_sel_zalloc;
    o->free = genio_sel_free;
    o->alloc_lock = genio_sel_alloc_lock;
    o->free_lock = genio_sel_free_lock;
    o->lock = genio_sel_lock;
    o->unlock = genio_sel_unlock;
    o->set_fd_handlers = genio_sel_set_fd_handlers;
    o->clear_fd_handlers = genio_sel_clear_fd_handlers;
    o->clear_fd_handlers_imm = genio_sel_clear_fd_handlers_imm;
    o->set_read_handler = genio_sel_set_read_handler;
    o->set_write_handler = genio_sel_set_write_handler;
    o->set_except_handler = genio_sel_set_except_handler;
    o->alloc_timer = genio_sel_alloc_timer;
    o->free_timer = genio_sel_free_timer;
    o->start_timer = genio_sel_start_timer;
    o->stop_timer = genio_sel_stop_timer;
    o->stop_timer_with_done = genio_sel_stop_timer_with_done;
    o->alloc_runner = genio_sel_alloc_runner;
    o->free_runner = genio_sel_free_runner;
    o->run = genio_sel_run;
    o->alloc_waiter = genio_sel_alloc_waiter;
    o->free_waiter = genio_sel_free_waiter;
    o->wait = genio_sel_wait;
    o->wait_intr = genio_sel_wait_intr;
    o->wake = genio_sel_wake;
    o->service = genio_sel_service;
    o->free_funcs = genio_sel_free_funcs;

    return o;
}
