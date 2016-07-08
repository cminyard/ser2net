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
    selector_t *sel;

    /* Am I currently running? */
    int in_heap;
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

    /* The timer heap. */
    theap_t timer_heap;

    /* This is a list of items waiting to be woken up because they are
       sitting in a select.  See wake_sel_thread() for more info. */
    sel_wait_list_t wait_list;
};

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
wake_sel_thread(selector_t *sel)
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

/* Wait list management.  These *must* be called with the timer list
   locked, and the values in the item *must not* change while in the
   list. */
static void
add_sel_wait_list(selector_t *sel, sel_wait_list_t *item,
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
remove_sel_wait_list(selector_t *sel, sel_wait_list_t *item)
{
    item->next->prev = item->prev;
    item->prev->next = item->next;
}

static void
wake_sel_thread_lock(selector_t *sel)
{
    wake_sel_thread(sel);
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

/* Set the handlers for a file descriptor. */
int
sel_set_fd_handlers(selector_t        *sel,
		    int               fd,
		    void              *data,
		    sel_fd_handler_t  read_handler,
		    sel_fd_handler_t  write_handler,
		    sel_fd_handler_t  except_handler,
		    sel_fd_cleared_cb done)
{
    fd_control_t *fdc;
    fd_state_t   *state;

    state = malloc(sizeof(*state));
    if (!state)
	return ENOMEM;
    state->deleted = 0;
    state->use_count = 0;
    state->done = done;

    fdc = (fd_control_t *) &(sel->fds[fd]);
    if (fdc->state) {
	fdc->state->deleted = 1;
	if (fdc->state->use_count == 0) {
	    if (fdc->state->done)
		fdc->state->done(fd, fdc->data);
	    free(fdc->state);
	}
    }
    fdc->state = state;
    fdc->data = data;
    fdc->handle_read = read_handler;
    fdc->handle_write = write_handler;
    fdc->handle_except = except_handler;

    /* Move maxfd up if necessary. */
    if (fd > sel->maxfd) {
	sel->maxfd = fd;
    }

    wake_sel_thread_lock(sel);
    return 0;
}

/* Clear the handlers for a file descriptor and remove it from
   select's monitoring. */
void
sel_clear_fd_handlers(selector_t *sel,
		      int        fd)
{
    fd_control_t *fdc;
    fdc = (fd_control_t *) &(sel->fds[fd]);

    if (fdc->state) {
	fdc->state->deleted = 1;
	if (fdc->state->use_count == 0) {
	    if (fdc->state->done)
		fdc->state->done(fd, fdc->data);
	    free(fdc->state);
	}
	fdc->state = NULL;
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

    wake_sel_thread_lock(sel);
}

/* Set whether the file descriptor will be monitored for data ready to
   read on the file descriptor. */
void
sel_set_fd_read_handler(selector_t *sel, int fd, int state)
{
    if (state == SEL_FD_HANDLER_ENABLED) {
	FD_SET(fd, &sel->read_set);
    } else if (state == SEL_FD_HANDLER_DISABLED) {
	FD_CLR(fd, &sel->read_set);
    }
    wake_sel_thread_lock(sel);
}

/* Set whether the file descriptor will be monitored for when the file
   descriptor can be written to. */
void
sel_set_fd_write_handler(selector_t *sel, int fd, int state)
{
    if (state == SEL_FD_HANDLER_ENABLED) {
	FD_SET(fd, &sel->write_set);
    } else if (state == SEL_FD_HANDLER_DISABLED) {
	FD_CLR(fd, &sel->write_set);
    }
    wake_sel_thread_lock(sel);
}

/* Set whether the file descriptor will be monitored for exceptions
   on the file descriptor. */
void
sel_set_fd_except_handler(selector_t *sel, int fd, int state)
{
    if (state == SEL_FD_HANDLER_ENABLED) {
	FD_SET(fd, &sel->except_set);
    } else if (state == SEL_FD_HANDLER_DISABLED) {
	FD_CLR(fd, &sel->except_set);
    }
    wake_sel_thread_lock(sel);
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
sel_alloc_timer(selector_t            *sel,
		sel_timeout_handler_t handler,
		void                  *user_data,
		sel_timer_t           **new_timer)
{
    sel_timer_t *timer;

    timer = malloc(sizeof(*timer));
    if (!timer)
	return ENOMEM;

    timer->val.handler = handler;
    timer->val.user_data = user_data;
    timer->val.in_heap = 0;
    timer->val.sel = sel;
    *new_timer = timer;

    return 0;
}

int
sel_free_timer(sel_timer_t *timer)
{
    if (timer->val.in_heap) {
	sel_stop_timer(timer);
    }
    free(timer);

    return 0;
}

int
sel_start_timer(sel_timer_t    *timer,
		struct timeval *timeout)
{
    volatile sel_timer_t *top;

    if (timer->val.in_heap) {
	return EBUSY;
    }

    top = theap_get_top(&timer->val.sel->timer_heap);

    timer->val.timeout = *timeout;
    theap_add(&timer->val.sel->timer_heap, timer);
    timer->val.in_heap = 1;

    if (top != theap_get_top(&timer->val.sel->timer_heap))
	/* If the top value changed, restart the waiting thread. */
	wake_sel_thread(timer->val.sel);

    return 0;
}

int
sel_stop_timer(sel_timer_t *timer)
{
    volatile sel_timer_t *top;

    if (!timer->val.in_heap) {
	return ETIMEDOUT;
    }

    top = theap_get_top(&timer->val.sel->timer_heap);

    theap_remove(&timer->val.sel->timer_heap, timer);
    timer->val.in_heap = 0;

    if (top != theap_get_top(&timer->val.sel->timer_heap))
	/* If the top value changed, restart the waiting thread. */
	wake_sel_thread(timer->val.sel);

    return 0;
}

static void
get_monotonic_time(struct timeval *tv)
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
process_timers(selector_t	       *sel,
	       volatile struct timeval *timeout)
{
    struct timeval now;
    sel_timer_t    *timer;
    int            called = 0;

    timer = theap_get_top(&sel->timer_heap);
    get_monotonic_time(&now);
    while (timer && cmp_timeval(&now, &timer->val.timeout) >= 0) {
	called = 1;
	theap_remove(&(sel->timer_heap), timer);
	timer->val.in_heap = 0;

	timer->val.handler(sel, timer, timer->val.user_data);

	timer = theap_get_top(&sel->timer_heap);
    }

    if (called) {
	/* If called, set the timeout to zero. */
	timeout->tv_sec = 0;
	timeout->tv_usec = 0;
    } else if (timer) {
	get_monotonic_time(&now);
	diff_timeval((struct timeval *) timeout,
		     (struct timeval *) &timer->val.timeout,
		     &now);
    } else {
	/* No timers, just set a long time. */
	timeout->tv_sec = 100000;
	timeout->tv_usec = 0;
    }
}

/*
 * return == 0  when timeout
 * 	  >  0  when successful
 * 	  <  0  when error
 */
static int
process_fds(selector_t	            *sel,
	    sel_send_sig_cb         send_sig,
	    long                    thread_id,
	    void                    *cb_data,
	    volatile struct timeval *timeout)
{
    fd_set      tmp_read_set;
    fd_set      tmp_write_set;
    fd_set      tmp_except_set;
    int i;
    int err;
    int num_fds;

    memcpy(&tmp_read_set, (void *) &sel->read_set, sizeof(tmp_read_set));
    memcpy(&tmp_write_set, (void *) &sel->write_set, sizeof(tmp_write_set));
    memcpy(&tmp_except_set, (void *) &sel->except_set, sizeof(tmp_except_set));
    num_fds = sel->maxfd+1;

    err = select(num_fds,
		 &tmp_read_set,
		 &tmp_write_set,
		 &tmp_except_set,
		 (struct timeval *) timeout);
    if (err <= 0)
	goto out;

    /* We got some I/O. */
    for (i=0; i<=sel->maxfd; i++) {
	if (FD_ISSET(i, &tmp_read_set)) {
	    sel_fd_handler_t handle_read;
	    void             *data;
	    fd_state_t       *state;

	    if (sel->fds[i].handle_read == NULL) {
		/* Somehow we don't have a handler for this.
		   Just shut it down. */
		sel_set_fd_read_handler(sel, i, SEL_FD_HANDLER_DISABLED);
	    } else {
		handle_read = sel->fds[i].handle_read;
		data = sel->fds[i].data;
		state = sel->fds[i].state;
		state->use_count++;
		handle_read(i, data);
		state->use_count--;
		if (state->deleted && state->use_count == 0) {
		    if (state->done)
			state->done(i, data);
		    free(state);
		}
	    }
	}
	if (FD_ISSET(i, &tmp_write_set)) {
	    sel_fd_handler_t handle_write;
	    void             *data;
	    fd_state_t       *state;

	    if (sel->fds[i].handle_write == NULL) {
		/* Somehow we don't have a handler for this.
                   Just shut it down. */
		sel_set_fd_write_handler(sel, i, SEL_FD_HANDLER_DISABLED);
	    } else {
		handle_write = sel->fds[i].handle_write;
		data = sel->fds[i].data;
		state = sel->fds[i].state;
		state->use_count++;
		handle_write(i, data);
		state->use_count--;
		if (state->deleted && state->use_count == 0) {
		    if (state->done)
			state->done(i, data);
		    free(state);
		}
	    }
	}
	if (FD_ISSET(i, &tmp_except_set)) {
	    sel_fd_handler_t handle_except;
	    void             *data;
	    fd_state_t       *state;

	    if (sel->fds[i].handle_except == NULL) {
		/* Somehow we don't have a handler for this.
                   Just shut it down. */
		sel_set_fd_except_handler(sel, i, SEL_FD_HANDLER_DISABLED);
	    } else {
	        handle_except = sel->fds[i].handle_except;
		data = sel->fds[i].data;
		state = sel->fds[i].state;
		state->use_count++;
	        handle_except(i, data);
		state->use_count--;
		if (state->deleted && state->use_count == 0) {
		    if (state->done)
			state->done(i, data);
		    free(state);
		}
	    }
	}
    }
out:
    return err;
}

static t_signal_handler user_sighup_handler = NULL;
static t_signal_handler user_sigint_handler = NULL;
static int got_sighup = 0; /* Did I get a HUP signal? */
static int got_sigint = 0; /* Did I get an INT signal? */

int
sel_select(selector_t      *sel,
	   sel_send_sig_cb send_sig,
	   long            thread_id,
	   void            *cb_data,
	   struct timeval  *timeout)
{
    int             err;
    struct timeval  loc_timeout;
    sel_wait_list_t wait_entry;

    process_timers(sel, (struct timeval *)(&loc_timeout));
    if (timeout) {
	if (cmp_timeval((struct timeval *)(&loc_timeout), timeout) >= 0)
	    memcpy(&loc_timeout, timeout, sizeof(loc_timeout));
    }
    add_sel_wait_list(sel, &wait_entry, send_sig, cb_data, thread_id,
		      &loc_timeout);

    err = process_fds(sel, send_sig, thread_id, cb_data, &loc_timeout);

    remove_sel_wait_list(sel, &wait_entry);

    if (got_sighup) {
	got_sighup = 0;
	if (user_sighup_handler != NULL) {
	    int old_errno = errno;
	    user_sighup_handler();
	    errno = old_errno;
	}
    }
    if (got_sigint) {
	got_sigint = 0;
	if (user_sigint_handler != NULL) {
	    int old_errno = errno;
	    user_sigint_handler();
	    errno = old_errno;
	}
    }

    return err;
}

/* The main loop for the program.  This will select on the various
   sets, then scan for any available I/O to process.  It also monitors
   the time and call the timeout handlers periodically. */
int
sel_select_loop(selector_t      *sel,
		sel_send_sig_cb send_sig,
		long            thread_id,
		void            *cb_data)
{
    int             err;

    for (;;) {
	err = sel_select(sel, send_sig, thread_id, cb_data, NULL);
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
sel_alloc_selector(selector_t **new_selector)
{
    selector_t *sel;
    unsigned int i;

    sel = malloc(sizeof(*sel));
    if (!sel)
	return ENOMEM;
    memset(sel, 0, sizeof(*sel));

    /* The list is initially empty. */
    sel->wait_list.next = &sel->wait_list;
    sel->wait_list.prev = &sel->wait_list;

    FD_ZERO((fd_set *) &sel->read_set);
    FD_ZERO((fd_set *) &sel->write_set);
    FD_ZERO((fd_set *) &sel->except_set);

    for (i=0; i<FD_SETSIZE; i++) {
	init_fd((fd_control_t *) &(sel->fds[i]));
    }

    theap_init(&sel->timer_heap);

    *new_selector = sel;

    return 0;
}

int
sel_free_selector(selector_t *sel)
{
    sel_timer_t *elem;

    elem = theap_get_top(&(sel->timer_heap));
    while (elem) {
	theap_remove(&(sel->timer_heap), elem);
	free(elem);
	elem = theap_get_top(&(sel->timer_heap));
    }
    free(sel);

    return 0;
}

void
set_signal_handler(int sig, t_signal_handler handler)
{
    if (sig == SIGHUP)
	user_sighup_handler = handler;
    else if (sig == SIGINT)
	user_sigint_handler = handler;
}


static void sighup_handler(int sig)
{
    got_sighup = 1;
}

static void sigint_handler(int sig)
{
    got_sigint = 1;
}

void
setup_signals(void)
{
    struct sigaction act;
    int              err;

    act.sa_handler = sighup_handler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_RESTART;
    err = sigaction(SIGHUP, &act, NULL);
    if (err) {
	perror("sigaction");
    }

    act.sa_handler = sigint_handler;
    /* Only handle SIGINT once. */
    act.sa_flags |= SA_RESETHAND;
    err = sigaction(SIGINT, &act, NULL);
    if (err) {
	perror("sigaction");
    }
}
