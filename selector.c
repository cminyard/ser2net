/*
 * selector.c
 *
 * Code for abstracting select for files and timers.
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2002,2003 MontaVista Software Inc.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public License
 *  as published by the Free Software Foundation; either version 2 of
 *  the License, or (at your option) any later version.
 *
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 *  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 *  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 *  OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 *  TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 *  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this program; if not, write to the Free
 *  Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/* This file holds code to abstract the "select" call and make it
   easier to use.  The main thread lives here, the rest of the code
   uses a callback interface.  Basically, other parts of the program
   can register file descriptors with this code, when interesting
   things happen on those file descriptors this code will call
   routines registered with it. */

#include "selector.h"

#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <syslog.h>
#include <signal.h>
#include <string.h>
#ifdef HAVE_EPOLL_PWAIT
#include <sys/epoll.h>
#else
#define EPOLL_CTL_ADD 0
#define EPOLL_CTL_DEL 0
#define EPOLL_CTL_MOD 0
#endif

typedef struct fd_state_s
{
    int               deleted;
    unsigned int      use_count;
    sel_fd_cleared_cb done;
} fd_state_t;

/* The control structure for each file descriptor. */
typedef struct fd_control_s
{
    /* This structure is allocated when an FD is set and it holds
       whether the FD has been deleted and information to handle the
       deletion. */
    fd_state_t       *state;
    void             *data;		/* Operation-specific data */
    sel_fd_handler_t handle_read;
    sel_fd_handler_t handle_write;
    sel_fd_handler_t handle_except;
} fd_control_t;

typedef struct heap_val_s
{
    /* Set this to the function to call when the timeout occurs. */
    sel_timeout_handler_t handler;

    /* Set this to whatever you like.  You can use this to store your
       own data. */
    void *user_data;

    /* Set this to the time when the timer will go off. */
    struct timeval timeout;

    /* Who owns me? */
    struct selector_s *sel;

    /* Am I currently running? */
    int in_heap;

    /* Am I currently stopped? */
    int stopped;

    /* Have I been freed? */
    int freed;

    /* Am I currently in a handler? */
    int in_handler;

    sel_timeout_handler_t done_handler;
    void *done_cb_data;
} heap_val_t;

typedef struct theap_s theap_t;
#define heap_s theap_s
#define heap_node_s sel_timer_s
#define HEAP_EXPORT_NAME(s) theap_ ## s
#define HEAP_NAMES_LOCAL static
#define HEAP_OUTPUT_PRINTF "(%ld.%7.7ld)"
#define HEAP_OUTPUT_DATA pos->timeout.tv_sec, pos->timeout.tv_usec

static int
cmp_timeval(const struct timeval *tv1, const struct timeval *tv2)
{
    if (tv1->tv_sec < tv2->tv_sec)
	return -1;

    if (tv1->tv_sec > tv2->tv_sec)
	return 1;

    if (tv1->tv_usec < tv2->tv_usec)
	return -1;

    if (tv1->tv_usec > tv2->tv_usec)
	return 1;

    return 0;
}

static int
heap_cmp_key(heap_val_t *v1, heap_val_t *v2)
{
    return cmp_timeval(&v1->timeout, &v2->timeout);
}

#include "heap.h"

/* Used to build a list of threads that may need to be woken if a
   timer on the top of the heap changes, or an FD is added/removed.
   See wake_sel_thread() for more info. */
typedef struct sel_wait_list_s
{
    /* The thread to wake up. */
    long            thread_id;

    /* How to wake it. */
    sel_send_sig_cb send_sig;
    void            *send_sig_cb_data;

    /* This is the memory used to hold the timeout for select
       operation. */
    volatile struct timeval *timeout;

    struct sel_wait_list_s *next, *prev;
} sel_wait_list_t;

struct sel_runner_s
{
    struct selector_s *sel;
    sel_runner_func_t func;
    void *cb_data;
    int in_use;
    sel_runner_t *next;
};

struct selector_s
{
    /* This is an array of all the file descriptors possible.  This is
       moderately wasteful of space, but easy to do.  Hey, memory is
       cheap. */
    volatile fd_control_t fds[FD_SETSIZE];

  /* These are the offical fd_sets used to track what file descriptors
       need to be monitored. */
    volatile fd_set read_set;
    volatile fd_set write_set;
    volatile fd_set except_set;

    volatile int maxfd; /* The largest file descriptor registered with
			   this code. */

    void *fd_lock;

    /* The timer heap. */
    theap_t timer_heap;

    /* This is a list of items waiting to be woken up because they are
       sitting in a select.  See wake_sel_thread() for more info. */
    sel_wait_list_t wait_list;

    void *timer_lock;

    sel_runner_t *runner_head;
    sel_runner_t *runner_tail;

    int wake_sig;

#ifdef HAVE_EPOLL_PWAIT
    int epollfd;
#endif
    sel_lock_t *(*sel_lock_alloc)(void *cb_data);
    void (*sel_lock_free)(sel_lock_t *);
    void (*sel_lock)(sel_lock_t *);
    void (*sel_unlock)(sel_lock_t *);
};

static void
sel_timer_lock(struct selector_s *sel)
{
    if (sel->sel_lock)
	sel->sel_lock(sel->timer_lock);
}

static void
sel_timer_unlock(struct selector_s *sel)
{
    if (sel->sel_lock)
	sel->sel_unlock(sel->timer_lock);
}

static void
sel_fd_lock(struct selector_s *sel)
{
    if (sel->sel_lock)
	sel->sel_lock(sel->fd_lock);
}

static void
sel_fd_unlock(struct selector_s *sel)
{
    if (sel->sel_lock)
	sel->sel_unlock(sel->fd_lock);
}

/* This function will wake the SEL thread.  It must be called with the
   timer lock held, because it messes with timeout.

   The operation is is subtle, but it does work.  The timeout in the
   selector is the data passed in (must be the actual data) as the
   timeout to select.  When we want to wake the select, we set the
   timeout to zero first.  That way, if the select has calculated the
   timeout but has not yet called select, then this will set it to
   zero (causing it to wait zero time).  If select has already been
   called, then the signal send should wake it up.  We only need to do
   this after we have calculated the timeout, but before we have
   called select, thus only things in the wait list matter. */
static void
wake_sel_thread(struct selector_s *sel)
{
    sel_wait_list_t *item;

    item = sel->wait_list.next;
    while (item != &sel->wait_list) {
	item->timeout->tv_sec = 0;
	item->timeout->tv_usec = 0;
	if (item->send_sig)
	    item->send_sig(item->thread_id, item->send_sig_cb_data);
	item = item->next;
    }
}

static void
wake_fd_sel_thread(struct selector_s *sel)
{
    wake_sel_thread(sel);
    sel_fd_unlock(sel);
}

static void
wake_timer_sel_thread(struct selector_s *sel, volatile sel_timer_t *old_top)
{
    if (old_top != theap_get_top(&sel->timer_heap))
	/* If the top value changed, restart the waiting thread. */
	wake_sel_thread(sel);
}

/* Wait list management.  These *must* be called with the timer list
   locked, and the values in the item *must not* change while in the
   list. */
static void
add_sel_wait_list(struct selector_s *sel, sel_wait_list_t *item,
		  sel_send_sig_cb send_sig,
		  void            *cb_data,
		  long thread_id, volatile struct timeval *timeout)
{
    item->thread_id = thread_id;
    item->timeout = timeout;
    item->send_sig = send_sig;
    item->send_sig_cb_data = cb_data;
    item->next = sel->wait_list.next;
    item->prev = &sel->wait_list;
    sel->wait_list.next->prev = item;
    sel->wait_list.next = item;
}
static void
remove_sel_wait_list(struct selector_s *sel, sel_wait_list_t *item)
{
    item->next->prev = item->prev;
    item->prev->next = item->next;
}

/* Initialize a single file descriptor. */
static void
init_fd(fd_control_t *fd)
{
    fd->state = NULL;
    fd->data = NULL;
    fd->handle_read = NULL;
    fd->handle_write = NULL;
    fd->handle_except = NULL;
}

#ifdef HAVE_EPOLL_PWAIT
static int
sel_update_epoll(struct selector_s *sel, int fd, int op)
{
    struct epoll_event event;

    if (sel->epollfd < 0)
	return 1;

    memset(&event, 0, sizeof(event));
    event.events = EPOLLONESHOT;
    event.data.fd = fd;
    if (FD_ISSET(fd, &sel->read_set))
	event.events |= EPOLLIN | EPOLLHUP;
    if (FD_ISSET(fd, &sel->write_set))
	event.events |= EPOLLOUT;
    if (FD_ISSET(fd, &sel->write_set))
	event.events |= EPOLLERR | EPOLLPRI;

    epoll_ctl(sel->epollfd, op, fd, &event);
    return 0;
}
#else
static int
sel_update_epoll(struct selector_s *sel, int fd, int op)
{
    return 1;
}
#endif

/* Set the handlers for a file descriptor. */
int
sel_set_fd_handlers(struct selector_s *sel,
		    int               fd,
		    void              *data,
		    sel_fd_handler_t  read_handler,
		    sel_fd_handler_t  write_handler,
		    sel_fd_handler_t  except_handler,
		    sel_fd_cleared_cb done)
{
    fd_control_t *fdc;
    fd_state_t   *state, *oldstate = NULL;
    void         *olddata = NULL;
    int          added = 1;

    state = malloc(sizeof(*state));
    if (!state)
	return ENOMEM;
    state->deleted = 0;
    state->use_count = 0;
    state->done = done;

    sel_fd_lock(sel);
    fdc = (fd_control_t *) &(sel->fds[fd]);
    if (fdc->state) {
	oldstate = fdc->state;
	olddata = fdc->data;
	added = 0;
    }
    fdc->state = state;
    fdc->data = data;
    fdc->handle_read = read_handler;
    fdc->handle_write = write_handler;
    fdc->handle_except = except_handler;

    if (added) {
	/* Move maxfd up if necessary. */
	if (fd > sel->maxfd) {
	    sel->maxfd = fd;
	}

	if (sel_update_epoll(sel, fd, EPOLL_CTL_ADD)) {
	    wake_fd_sel_thread(sel);
	    goto out;
	}
    }
    sel_fd_unlock(sel);

 out:
    if (oldstate) {
	oldstate->deleted = 1;
	if (oldstate->use_count == 0) {
	    if (oldstate->done)
		oldstate->done(fd, olddata);
	    free(oldstate);
	}
    }
    return 0;
}

/* Clear the handlers for a file descriptor and remove it from
   select's monitoring. */
void
sel_clear_fd_handlers(struct selector_s *sel,
		      int        fd)
{
    fd_control_t *fdc;
    fd_state_t   *oldstate = NULL;
    void         *olddata = NULL;

    sel_fd_lock(sel);
    fdc = (fd_control_t *) &(sel->fds[fd]);

    if (fdc->state) {
	oldstate = fdc->state;
	olddata = fdc->data;
	fdc->state = NULL;

	sel_update_epoll(sel, fd, EPOLL_CTL_DEL);
    }

    init_fd(fdc);
    FD_CLR(fd, &sel->read_set);
    FD_CLR(fd, &sel->write_set);
    FD_CLR(fd, &sel->except_set);

    /* Move maxfd down if necessary. */
    if (fd == sel->maxfd) {
	while ((sel->maxfd >= 0) && (! sel->fds[sel->maxfd].state)) {
	    sel->maxfd--;
	}
    }

    sel_fd_unlock(sel);

    if (oldstate) {
	oldstate->deleted = 1;
	if (oldstate->use_count == 0) {
	    if (oldstate->done)
		oldstate->done(fd, olddata);
	    free(oldstate);
	}
    }
}

/* Set whether the file descriptor will be monitored for data ready to
   read on the file descriptor. */
void
sel_set_fd_read_handler(struct selector_s *sel, int fd, int state)
{
    fd_control_t *fdc = (fd_control_t *) &(sel->fds[fd]);

    sel_fd_lock(sel);
    if (!fdc->state)
	goto out;

    if (state == SEL_FD_HANDLER_ENABLED) {
	if (FD_ISSET(fd, &sel->read_set))
	    goto out;
	FD_SET(fd, &sel->read_set);
    } else if (state == SEL_FD_HANDLER_DISABLED) {
	if (!FD_ISSET(fd, &sel->read_set))
	    goto out;
	FD_CLR(fd, &sel->read_set);
    }
    if (sel_update_epoll(sel, fd, EPOLL_CTL_MOD)) {
	wake_fd_sel_thread(sel);
	return;
    }

 out:
    sel_fd_unlock(sel);
}

/* Set whether the file descriptor will be monitored for when the file
   descriptor can be written to. */
void
sel_set_fd_write_handler(struct selector_s *sel, int fd, int state)
{
    fd_control_t *fdc = (fd_control_t *) &(sel->fds[fd]);

    sel_fd_lock(sel);
    if (!fdc->state)
	goto out;

    if (state == SEL_FD_HANDLER_ENABLED) {
	if (FD_ISSET(fd, &sel->write_set))
	    goto out;
	FD_SET(fd, &sel->write_set);
    } else if (state == SEL_FD_HANDLER_DISABLED) {
	if (!FD_ISSET(fd, &sel->write_set))
	    goto out;
	FD_CLR(fd, &sel->write_set);
    }
    if (sel_update_epoll(sel, fd, EPOLL_CTL_MOD)) {
	wake_fd_sel_thread(sel);
	return;
    }

 out:
    sel_fd_unlock(sel);
}

/* Set whether the file descriptor will be monitored for exceptions
   on the file descriptor. */
void
sel_set_fd_except_handler(struct selector_s *sel, int fd, int state)
{
    fd_control_t *fdc = (fd_control_t *) &(sel->fds[fd]);

    sel_fd_lock(sel);
    if (!fdc->state)
	goto out;

    if (state == SEL_FD_HANDLER_ENABLED) {
	if (FD_ISSET(fd, &sel->except_set))
	    goto out;
	FD_SET(fd, &sel->except_set);
    } else if (state == SEL_FD_HANDLER_DISABLED) {
	if (!FD_ISSET(fd, &sel->except_set))
	    goto out;
	FD_CLR(fd, &sel->except_set);
    }
    if (sel_update_epoll(sel, fd, EPOLL_CTL_MOD)) {
	wake_fd_sel_thread(sel);
	return;
    }

 out:
    sel_fd_unlock(sel);
}

static void
diff_timeval(struct timeval *dest,
	     struct timeval *left,
	     struct timeval *right)
{
    if (   (left->tv_sec < right->tv_sec)
	|| (   (left->tv_sec == right->tv_sec)
	    && (left->tv_usec < right->tv_usec)))
    {
	/* If left < right, just force to zero, don't allow negative
           numbers. */
	dest->tv_sec = 0;
	dest->tv_usec = 0;
	return;
    }

    dest->tv_sec = left->tv_sec - right->tv_sec;
    dest->tv_usec = left->tv_usec - right->tv_usec;
    while (dest->tv_usec < 0) {
	dest->tv_usec += 1000000;
	dest->tv_sec--;
    }
}

int
sel_alloc_timer(struct selector_s     *sel,
		sel_timeout_handler_t handler,
		void                  *user_data,
		sel_timer_t           **new_timer)
{
    sel_timer_t *timer;

    timer = malloc(sizeof(*timer));
    if (!timer)
	return ENOMEM;
    memset(timer, 0, sizeof(*timer));

    timer->val.handler = handler;
    timer->val.user_data = user_data;
    timer->val.sel = sel;
    timer->val.stopped = 1;
    *new_timer = timer;

    return 0;
}

int
sel_free_timer(sel_timer_t *timer)
{
    struct selector_s *sel = timer->val.sel;
    int in_handler;

    sel_timer_lock(sel);
    if (timer->val.in_heap) {
	sel_stop_timer(timer);
    }
    timer->val.freed = 1;
    in_handler = timer->val.in_handler;
    sel_timer_unlock(sel);

    if (!in_handler)
	free(timer);

    return 0;
}

int
sel_start_timer(sel_timer_t    *timer,
		struct timeval *timeout)
{
    struct selector_s *sel = timer->val.sel;
    volatile sel_timer_t *top;

    sel_timer_lock(sel);
    if (timer->val.in_heap) {
	sel_timer_unlock(sel);
	return EBUSY;
    }

    top = theap_get_top(&sel->timer_heap);

    timer->val.timeout = *timeout;

    if (!timer->val.in_handler) {
	/* Wait until the handler returns to start the timer. */
	theap_add(&sel->timer_heap, timer);
	timer->val.in_heap = 1;
    }
    timer->val.stopped = 0;

    wake_timer_sel_thread(sel, top);

    sel_timer_unlock(sel);

    return 0;
}

int
sel_stop_timer(sel_timer_t *timer)
{
    struct selector_s *sel = timer->val.sel;

    sel_timer_lock(sel);
    if (timer->val.stopped) {
	sel_timer_unlock(sel);
	return ETIMEDOUT;
    }

    if (timer->val.in_heap) {
	volatile sel_timer_t *top = theap_get_top(&sel->timer_heap);

	theap_remove(&sel->timer_heap, timer);
	timer->val.in_heap = 0;
	wake_timer_sel_thread(sel, top);
    }
    timer->val.stopped = 1;

    sel_timer_unlock(sel);

    return 0;
}

int
sel_stop_timer_with_done(sel_timer_t *timer,
			 sel_timeout_handler_t done_handler,
			 void *cb_data)
{
    struct selector_s *sel = timer->val.sel;
    volatile sel_timer_t *top;

    sel_timer_lock(sel);
    if (timer->val.stopped) {
	sel_timer_unlock(sel);
	goto out;
    }

    if (timer->val.in_handler) {
	timer->val.done_handler = done_handler;
	timer->val.done_cb_data = cb_data;
	sel_timer_unlock(sel);
	return 0;
    }

    if (timer->val.in_heap) {
	top = theap_get_top(&sel->timer_heap);

	theap_remove(&sel->timer_heap, timer);
	timer->val.in_heap = 0;

	wake_timer_sel_thread(sel, top);
    }
    timer->val.stopped = 1;
    sel_timer_unlock(sel);

 out:
    done_handler(sel, timer, cb_data);
    return 0;
}

void
sel_get_monotonic_time(struct timeval *tv)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    tv->tv_sec = ts.tv_sec;
    tv->tv_usec = (ts.tv_nsec + 500) / 1000;
}

/*
 * Process timers on selector.  The timeout is always set, to a very
 * long value if no timers are waiting.  Note that this *must* be
 * called with sel->timer_lock held.  Note that if this processes
 * any timers, the timeout will be set to { 0,0 }.
 */
static void
process_timers(struct selector_s       *sel,
	       volatile struct timeval *timeout)
{
    struct timeval now;
    sel_timer_t    *timer;
    int            called = 0;

    timer = theap_get_top(&sel->timer_heap);
    sel_get_monotonic_time(&now);
    while (timer && cmp_timeval(&now, &timer->val.timeout) >= 0) {
	called = 1;
	theap_remove(&(sel->timer_heap), timer);
	timer->val.in_heap = 0;
	timer->val.stopped = 1;
	timer->val.in_handler = 1;
	sel_timer_unlock(sel);
	timer->val.handler(sel, timer, timer->val.user_data);
	sel_timer_lock(sel);
	timer->val.in_handler = 0;
	if (timer->val.done_handler) {
	    sel_timeout_handler_t done_handler = timer->val.done_handler;
	    void *done_cb_data = timer->val.done_cb_data;
	    timer->val.done_handler = NULL;
	    sel_timer_unlock(sel);
	    done_handler(sel, timer, done_cb_data);
	    sel_timer_lock(sel);
	}
	if (timer->val.freed)
	    free(timer);
	else if (!timer->val.stopped) {
	    /* We were restarted while in the handler. */
	    theap_add(&sel->timer_heap, timer);
	    timer->val.in_heap = 1;
	}

	timer = theap_get_top(&sel->timer_heap);
    }

    if (called) {
	/* If called, set the timeout to zero. */
	timeout->tv_sec = 0;
	timeout->tv_usec = 0;
    } else if (timer) {
	sel_get_monotonic_time(&now);
	diff_timeval((struct timeval *) timeout,
		     (struct timeval *) &timer->val.timeout,
		     &now);
    } else {
	/* No timers, just set a long time. */
	timeout->tv_sec = 100000;
	timeout->tv_usec = 0;
    }
}

int
sel_alloc_runner(struct selector_s *sel, sel_runner_t **new_runner)
{
    sel_runner_t *runner;

    runner = malloc(sizeof(*runner));
    if (!runner)
	return ENOMEM;
    memset(runner, 0, sizeof(*runner));
    runner->sel = sel;
    *new_runner = runner;
    return 0;
}

int
sel_free_runner(sel_runner_t *runner)
{
    struct selector_s *sel = runner->sel;

    sel_timer_lock(sel);
    if (runner->in_use) {
	sel_timer_unlock(sel);
	return EBUSY;
    }
    sel_timer_unlock(sel);
    free(runner);
    return 0;
}

int
sel_run(sel_runner_t *runner, sel_runner_func_t func, void *cb_data)
{
    struct selector_s *sel = runner->sel;

    sel_timer_lock(sel);
    if (runner->in_use) {
	sel_timer_unlock(sel);
	return EBUSY;
    }

    runner->func = func;
    runner->cb_data = cb_data;
    runner->next = NULL;
    runner->in_use = 1;

    if (sel->runner_tail) {
	sel->runner_tail->next = runner;
	sel->runner_tail = runner;
    } else {
	sel->runner_head = runner;
	sel->runner_tail = runner;
    }
    sel_timer_unlock(sel);
    return 0;
}

static void
process_runners(struct selector_s *sel)
{
    while (sel->runner_head) {
	sel_runner_t *runner = sel->runner_head;
	sel_runner_func_t func;
	void *cb_data;

	sel->runner_head = sel->runner_head->next;
	if (!sel->runner_head)
	    sel->runner_tail = NULL;
	runner->in_use = 0;
	func = runner->func;
	cb_data = runner->cb_data;
	sel_timer_unlock(sel);
	func(runner, cb_data);
	sel_timer_lock(sel);
    }
}

static void
handle_selector_call(struct selector_s *sel, int i, volatile fd_set *fdset,
		     sel_fd_handler_t handler)
{
    void             *data;
    fd_state_t       *state;

    if (handler == NULL) {
	/* Somehow we don't have a handler for this.
	   Just shut it down. */
	FD_CLR(i, fdset);
	return;
    }

    if (!FD_ISSET(i, fdset))
	/* The value was cleared, ignore it. */
	return;

    data = sel->fds[i].data;
    state = sel->fds[i].state;
    state->use_count++;
    sel_fd_unlock(sel);
    handler(i, data);
    sel_fd_lock(sel);
    state->use_count--;
    if (state->deleted && state->use_count == 0) {
	if (state->done) {
	    sel_fd_unlock(sel);
	    state->done(i, data);
	    sel_fd_lock(sel);
	}
	free(state);
    }
}

/*
 * return == 0  when timeout
 * 	  >  0  when successful
 * 	  <  0  when error
 */
static int
process_fds(struct selector_s	    *sel,
	    volatile struct timeval *timeout)
{
    fd_set      tmp_read_set;
    fd_set      tmp_write_set;
    fd_set      tmp_except_set;
    int i;
    int err;
    int num_fds;

    sel_fd_lock(sel);
    memcpy(&tmp_read_set, (void *) &sel->read_set, sizeof(tmp_read_set));
    memcpy(&tmp_write_set, (void *) &sel->write_set, sizeof(tmp_write_set));
    memcpy(&tmp_except_set, (void *) &sel->except_set, sizeof(tmp_except_set));
    num_fds = sel->maxfd + 1;
    sel_fd_unlock(sel);

    err = select(num_fds,
		 &tmp_read_set,
		 &tmp_write_set,
		 &tmp_except_set,
		 (struct timeval *) timeout);
    if (err <= 0)
	goto out;

    /* We got some I/O. */
    sel_fd_lock(sel);
    for (i = 0; i <= sel->maxfd; i++) {
	if (FD_ISSET(i, &tmp_read_set))
	    handle_selector_call(sel, i, &sel->read_set,
				 sel->fds[i].handle_read);
	if (FD_ISSET(i, &tmp_write_set))
	    handle_selector_call(sel, i, &sel->write_set,
				 sel->fds[i].handle_write);
	if (FD_ISSET(i, &tmp_except_set))
	    handle_selector_call(sel, i, &sel->except_set,
				 sel->fds[i].handle_except);
    }
    sel_fd_unlock(sel);
out:
    return err;
}

#ifdef HAVE_EPOLL_PWAIT
static int
process_fds_epoll(struct selector_s *sel, struct timeval *tvtimeout)
{
    int rv, fd;
    struct epoll_event event;
    int timeout;
    sigset_t sigmask;

    if (tvtimeout->tv_sec > 600)
	 /* Don't wait over 10 minutes, to work around an old epoll bug
	    and avoid issues with timeout overflowing on 64-bit systems,
	    which is much larger that 10 minutes, but who cares. */
	timeout = 600 * 1000;
    else
	timeout = ((tvtimeout->tv_sec * 1000) +
		   (tvtimeout->tv_usec + 999) / 1000);

#ifdef USE_PTHREADS
    pthread_sigmask(SIG_SETMASK, NULL, &sigmask);
#else
    sigprocmask(SIG_SETMASK, NULL, &sigmask);
#endif
    sigdelset(&sigmask, sel->wake_sig);
    rv = epoll_pwait(sel->epollfd, &event, 1, timeout, &sigmask);

    if (rv <= 0)
	return rv;

    sel_fd_lock(sel);
    fd = event.data.fd;
    if (event.events & (EPOLLIN | EPOLLHUP))
	handle_selector_call(sel, fd, &sel->read_set,
			     sel->fds[fd].handle_read);
    if (event.events & EPOLLOUT)
	handle_selector_call(sel, fd, &sel->write_set,
			     sel->fds[fd].handle_write);
    if (event.events & (EPOLLERR | EPOLLPRI))
	handle_selector_call(sel, fd, &sel->except_set,
			     sel->fds[fd].handle_except);

    /* Rearm the event.  Remember it could have been deleted in the handler. */
    if (sel->fds[fd].state)
	sel_update_epoll(sel, fd, EPOLL_CTL_MOD);
    sel_fd_unlock(sel);

    return 0;
}
#endif

int
sel_select(struct selector_s *sel,
	   sel_send_sig_cb send_sig,
	   long            thread_id,
	   void            *cb_data,
	   struct timeval  *timeout)
{
    int             err;
    struct timeval  loc_timeout;
    sel_wait_list_t wait_entry;

    sel_timer_lock(sel);
    process_runners(sel);
    process_timers(sel, (struct timeval *)(&loc_timeout));
    if (timeout) {
	if (cmp_timeval((struct timeval *)(&loc_timeout), timeout) >= 0)
	    memcpy(&loc_timeout, timeout, sizeof(loc_timeout));
    }
    add_sel_wait_list(sel, &wait_entry, send_sig, cb_data, thread_id,
		      &loc_timeout);
    sel_timer_unlock(sel);

#ifdef HAVE_EPOLL_PWAIT
    if (sel->epollfd >= 0)
	err = process_fds_epoll(sel, &loc_timeout);
    else
#endif
	err = process_fds(sel, &loc_timeout);

    sel_timer_lock(sel);
    remove_sel_wait_list(sel, &wait_entry);
    sel_timer_unlock(sel);

    return err;
}

/* The main loop for the program.  This will select on the various
   sets, then scan for any available I/O to process.  It also monitors
   the time and call the timeout handlers periodically. */
int
sel_select_loop(struct selector_s *sel,
		sel_send_sig_cb send_sig,
		long            thread_id,
		void            *cb_data)
{
    for (;;) {
	int err = sel_select(sel, send_sig, thread_id, cb_data, NULL);

	if ((err < 0) && (errno != EINTR)) {
	    err = errno;
	    /* An error occurred. */
	    /* An error is bad, we need to abort. */
	    syslog(LOG_ERR, "select_loop() - select: %m");
	    return err;
	}
    }
}

/* Initialize the select code. */
int
sel_alloc_selector_thread(struct selector_s **new_selector, int wake_sig,
			  sel_lock_t *(*sel_lock_alloc)(void *cb_data),
			  void (*sel_lock_free)(sel_lock_t *),
			  void (*sel_lock)(sel_lock_t *),
			  void (*sel_unlock)(sel_lock_t *),
			  void *cb_data)
{
    struct selector_s *sel;
    unsigned int i;

    sel = malloc(sizeof(*sel));
    if (!sel)
	return ENOMEM;
    memset(sel, 0, sizeof(*sel));

    sel->sel_lock_alloc = sel_lock_alloc;
    sel->sel_lock_free = sel_lock_free;
    sel->sel_lock = sel_lock;
    sel->sel_unlock = sel_unlock;

    /* The list is initially empty. */
    sel->wait_list.next = &sel->wait_list;
    sel->wait_list.prev = &sel->wait_list;

    sel->wake_sig = wake_sig;

    FD_ZERO((fd_set *) &sel->read_set);
    FD_ZERO((fd_set *) &sel->write_set);
    FD_ZERO((fd_set *) &sel->except_set);

    for (i = 0; i < FD_SETSIZE; i++) {
	init_fd((fd_control_t *) &(sel->fds[i]));
    }

    theap_init(&sel->timer_heap);

    if (sel->sel_lock_alloc) {
	sel->timer_lock = sel->sel_lock_alloc(cb_data);
	if (!sel->timer_lock) {
	    free(sel);
	    return ENOMEM;
	}
	sel->fd_lock = sel->sel_lock_alloc(cb_data);
	if (!sel->fd_lock) {
	    sel->sel_lock_free(sel->fd_lock);
	    free(sel);
	    return ENOMEM;
	}
    }

#ifdef HAVE_EPOLL_PWAIT
    sel->epollfd = epoll_create(32768);
    if (sel->epollfd == -1) {
	syslog(LOG_ERR, "Unable to set up epoll, falling back to select: %m");
    } else {
	int rv;
	sigset_t sigset;

	sigemptyset(&sigset);
	sigaddset(&sigset, wake_sig);
	rv = sigprocmask(SIG_BLOCK, &sigset, NULL);
	if (rv == -1) {
	    rv = errno;
	    close(sel->epollfd);
	    if (sel->sel_lock_alloc) {
		sel->sel_lock_free(sel->fd_lock);
		sel->sel_lock_free(sel->timer_lock);
	    }
	    free(sel);
	    return rv;
	}
    }
#endif

    *new_selector = sel;

    return 0;
}

int
sel_alloc_selector_nothread(struct selector_s **new_selector)
{
    return sel_alloc_selector_thread(new_selector, 0, NULL, NULL, NULL, NULL,
				     NULL);
}

int
sel_free_selector(struct selector_s *sel)
{
    sel_timer_t *elem;

    elem = theap_get_top(&(sel->timer_heap));
    while (elem) {
	theap_remove(&(sel->timer_heap), elem);
	free(elem);
	elem = theap_get_top(&(sel->timer_heap));
    }
#ifdef HAVE_EPOLL_PWAIT
    if (sel->epollfd >= 0)
	close(sel->epollfd);
#endif
    if (sel->fd_lock)
	sel->sel_lock_free(sel->fd_lock);
    if (sel->timer_lock)
	sel->sel_lock_free(sel->timer_lock);
    free(sel);

    return 0;
}
