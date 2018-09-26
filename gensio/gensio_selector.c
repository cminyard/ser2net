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

#include <malloc.h>
#include <string.h>
#include <errno.h>

#ifdef USE_PTHREADS
#include <pthread.h>
#else
#define pthread_mutex_t int
#define pthread_mutex_lock(l) do { } while (0)
#define pthread_mutex_unlock(l) do { } while (0)
#define pthread_mutex_init(l, n) do { } while (0)
#define pthread_mutex_destroy(l, n) do { } while (0)
#endif

#include <utils/utils.h>
#include "waiter.h"

#include <gensio/gensio_selector.h>

struct gensio_data {
    struct selector_s *sel;
    int wake_sig;
};

static void *
gensio_sel_zalloc(struct gensio_os_funcs *f, unsigned int size)
{
    void *d = malloc(size);

    if (d)
	memset(d, 0, size);
    return d;
}

static void
gensio_sel_free(struct gensio_os_funcs *f, void *data)
{
    free(data);
}

struct gensio_lock {
    struct gensio_os_funcs *f;
    pthread_mutex_t lock;
};

static struct gensio_lock *
gensio_sel_alloc_lock(struct gensio_os_funcs *f)
{
    struct gensio_lock *lock = f->zalloc(f, sizeof(*lock));

    if (lock) {
	lock->f = f;
	pthread_mutex_init(&lock->lock, NULL);
    }

    return lock;
}

static void
gensio_sel_free_lock(struct gensio_lock *lock)
{
    pthread_mutex_destroy(&lock->lock);
    lock->f->free(lock->f, lock);
}

static void
gensio_sel_lock(struct gensio_lock *lock)
{
    pthread_mutex_lock(&lock->lock);
}

static void
gensio_sel_unlock(struct gensio_lock *lock)
{
    pthread_mutex_unlock(&lock->lock);
}

static int
gensio_sel_set_fd_handlers(struct gensio_os_funcs *f,
			   int fd,
			   void *cb_data,
			   void (*read_handler)(int fd, void *cb_data),
			   void (*write_handler)(int fd, void *cb_data),
			   void (*except_handler)(int fd, void *cb_data),
			   void (*cleared_handler)(int fd, void *cb_data))
{
    struct gensio_data *d = f->user_data;

    return sel_set_fd_handlers(d->sel, fd, cb_data, read_handler, write_handler,
			       except_handler, cleared_handler);
}


static void
gensio_sel_clear_fd_handlers(struct gensio_os_funcs *f, int fd)
{
    struct gensio_data *d = f->user_data;

    return sel_clear_fd_handlers(d->sel, fd);
}

static void
gensio_sel_clear_fd_handlers_norpt(struct gensio_os_funcs *f, int fd)
{
    struct gensio_data *d = f->user_data;

    return sel_clear_fd_handlers_norpt(d->sel, fd);
}

static void
gensio_sel_set_read_handler(struct gensio_os_funcs *f, int fd, bool enable)
{
    struct gensio_data *d = f->user_data;
    int op;

    if (enable)
	op = SEL_FD_HANDLER_ENABLED;
    else
	op = SEL_FD_HANDLER_DISABLED;

    return sel_set_fd_read_handler(d->sel, fd, op);
}

static void
gensio_sel_set_write_handler(struct gensio_os_funcs *f, int fd, bool enable)
{
    struct gensio_data *d = f->user_data;
    int op;

    if (enable)
	op = SEL_FD_HANDLER_ENABLED;
    else
	op = SEL_FD_HANDLER_DISABLED;

    return sel_set_fd_write_handler(d->sel, fd, op);
}

static void
gensio_sel_set_except_handler(struct gensio_os_funcs *f, int fd, bool enable)
{
    struct gensio_data *d = f->user_data;
    int op;

    if (enable)
	op = SEL_FD_HANDLER_ENABLED;
    else
	op = SEL_FD_HANDLER_DISABLED;

    return sel_set_fd_except_handler(d->sel, fd, op);
}

struct gensio_timer {
    struct gensio_os_funcs *f;
    void (*handler)(struct gensio_timer *t, void *cb_data);
    void *cb_data;
    sel_timer_t *sel_timer;
    pthread_mutex_t lock;

    void (*done_handler)(struct gensio_timer *t, void *cb_data);
    void *done_cb_data;
};

static void
gensio_timeout_handler(struct selector_s *sel,
		       struct sel_timer_s *sel_timer, void *cb_data)
{
    struct gensio_timer *timer = cb_data;

    timer->handler(timer, timer->cb_data);
}

static struct gensio_timer *
gensio_sel_alloc_timer(struct gensio_os_funcs *f,
		       void (*handler)(struct gensio_timer *t, void *cb_data),
		       void *cb_data)
{
    struct gensio_data *d = f->user_data;
    struct gensio_timer *timer;
    int rv;

    timer = f->zalloc(f, sizeof(*timer));
    if (!timer)
	return NULL;

    timer->f = f;
    timer->handler = handler;
    timer->cb_data = cb_data;
    pthread_mutex_init(&timer->lock, NULL);

    rv = sel_alloc_timer(d->sel, gensio_timeout_handler, timer,
			 &timer->sel_timer);
    if (rv) {
	f->free(f, timer);
	return NULL;
    }

    return timer;
}

static void
gensio_sel_free_timer(struct gensio_timer *timer)
{
    sel_free_timer(timer->sel_timer);
    timer->f->free(timer->f, timer);
}

static int
gensio_sel_start_timer(struct gensio_timer *timer, struct timeval *timeout)
{
    struct timeval tv;

    sel_get_monotonic_time(&tv);
    add_to_timeval(&tv, timeout);
    return sel_start_timer(timer->sel_timer, &tv);
}

static int
gensio_sel_stop_timer(struct gensio_timer *timer)
{
    return sel_stop_timer(timer->sel_timer);
}

static void
gensio_stop_timer_done(struct selector_s *sel,
		       struct sel_timer_s *sel_timer, void *cb_data)
{
    struct gensio_timer *timer = cb_data;
    void (*done_handler)(struct gensio_timer *t, void *cb_data);
    void *done_cb_data;

    pthread_mutex_lock(&timer->lock);
    done_handler = timer->done_handler;
    done_cb_data = timer->done_cb_data;
    pthread_mutex_unlock(&timer->lock);
    done_handler(timer, done_cb_data);
}

static int
gensio_sel_stop_timer_with_done(struct gensio_timer *timer,
				void (*done_handler)(struct gensio_timer *t,
						     void *cb_data),
				void *cb_data)
{
    int rv;

    pthread_mutex_lock(&timer->lock);
    rv = sel_stop_timer_with_done(timer->sel_timer, gensio_stop_timer_done,
				  timer);
    if (!rv) {
	timer->done_handler = done_handler;
	timer->done_cb_data = cb_data;
    }
    pthread_mutex_unlock(&timer->lock);
    return rv;
}

struct gensio_runner {
    struct gensio_os_funcs *f;
    struct sel_runner_s *sel_runner;
    void (*handler)(struct gensio_runner *r, void *cb_data);
    void *cb_data;
};

static struct gensio_runner *
gensio_sel_alloc_runner(struct gensio_os_funcs *f,
			void (*handler)(struct gensio_runner *r,
					void *cb_data),
			void *cb_data)
{
    struct gensio_data *d = f->user_data;
    struct gensio_runner *runner;
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
gensio_sel_free_runner(struct gensio_runner *runner)
{
    sel_free_runner(runner->sel_runner);
    runner->f->free(runner->f, runner);
}

static void
gensio_runner_handler(sel_runner_t *sel_runner, void *cb_data)
{
    struct gensio_runner *runner = cb_data;

    runner->handler(runner, runner->cb_data);
}

static int
gensio_sel_run(struct gensio_runner *runner)
{
    return sel_run(runner->sel_runner, gensio_runner_handler, runner);
}

struct gensio_waiter {
    struct gensio_os_funcs *f;
    struct waiter_s *sel_waiter;
};

static struct gensio_waiter *
gensio_sel_alloc_waiter(struct gensio_os_funcs *f)
{
    struct gensio_data *d = f->user_data;
    struct gensio_waiter *waiter = f->zalloc(f, sizeof(*waiter));

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
gensio_sel_free_waiter(struct gensio_waiter *waiter)
{
    free_waiter(waiter->sel_waiter);
    waiter->f->free(waiter->f, waiter);
}

static int
gensio_sel_wait(struct gensio_waiter *waiter, unsigned int count,
		struct timeval *timeout)
{
    return wait_for_waiter_timeout(waiter->sel_waiter, count, timeout);
}


static int
gensio_sel_wait_intr(struct gensio_waiter *waiter, unsigned int count,
		     struct timeval *timeout)
{
    return wait_for_waiter_timeout_intr(waiter->sel_waiter, count, timeout);
}

static void
gensio_sel_wake(struct gensio_waiter *waiter)
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
gensio_sel_service(struct gensio_os_funcs *f, struct timeval *timeout)
{
    struct gensio_data *d = f->user_data;
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
gensio_sel_service(struct gensio_os_funcs *f, struct timeval *timeout)
{
    struct gensio_data *d = f->user_data;
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
gensio_sel_free_funcs(struct gensio_os_funcs *f)
{
    free(f->user_data);
    free(f);
}

static pthread_mutex_t once_lock = PTHREAD_MUTEX_INITIALIZER;

static void
gensio_sel_call_once(struct gensio_os_funcs *f, struct gensio_once *once,
		     void (*func)(void *cb_data), void *cb_data)
{
    if (once->called)
	return;
    pthread_mutex_lock(&once_lock);
    if (!once->called) {
	once->called = true;
	pthread_mutex_unlock(&once_lock);
	func(cb_data);
    } else {
	pthread_mutex_unlock(&once_lock);
    }
}

static void
gensio_sel_get_monotonic_time(struct gensio_os_funcs *f, struct timeval *time)
{
    sel_get_monotonic_time(time);
}

struct gensio_os_funcs *
gensio_selector_alloc(struct selector_s *sel, int wake_sig)
{
    struct gensio_data *d;
    struct gensio_os_funcs *o;

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

    o->zalloc = gensio_sel_zalloc;
    o->free = gensio_sel_free;
    o->alloc_lock = gensio_sel_alloc_lock;
    o->free_lock = gensio_sel_free_lock;
    o->lock = gensio_sel_lock;
    o->unlock = gensio_sel_unlock;
    o->set_fd_handlers = gensio_sel_set_fd_handlers;
    o->clear_fd_handlers = gensio_sel_clear_fd_handlers;
    o->clear_fd_handlers_norpt = gensio_sel_clear_fd_handlers_norpt;
    o->set_read_handler = gensio_sel_set_read_handler;
    o->set_write_handler = gensio_sel_set_write_handler;
    o->set_except_handler = gensio_sel_set_except_handler;
    o->alloc_timer = gensio_sel_alloc_timer;
    o->free_timer = gensio_sel_free_timer;
    o->start_timer = gensio_sel_start_timer;
    o->stop_timer = gensio_sel_stop_timer;
    o->stop_timer_with_done = gensio_sel_stop_timer_with_done;
    o->alloc_runner = gensio_sel_alloc_runner;
    o->free_runner = gensio_sel_free_runner;
    o->run = gensio_sel_run;
    o->alloc_waiter = gensio_sel_alloc_waiter;
    o->free_waiter = gensio_sel_free_waiter;
    o->wait = gensio_sel_wait;
    o->wait_intr = gensio_sel_wait_intr;
    o->wake = gensio_sel_wake;
    o->service = gensio_sel_service;
    o->free_funcs = gensio_sel_free_funcs;
    o->call_once = gensio_sel_call_once;
    o->get_monotonic_time = gensio_sel_get_monotonic_time;

    return o;
}
