/*
 *  ser2net - A program for allowing telnet connection to serial ports
 *  Copyright (C) 2001  Corey Minyard <minyard@acm.org>
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

/* This file holds code to abstract the "select" call and make it
   easier to use.  The main thread lives here, the rest of the code
   uses a callback interface.  Basically, other parts of the program
   can register file descriptors with this code, when interesting
   things happen on those file descriptors this code will call
   routines registered with it. */

#include "selector.h"

#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>
#include <signal.h>

/* The control structure for each file descriptor. */
typedef struct fd_control
{
    int          in_use;
    void         *data;		/* Operation-specific data */
    t_fd_handler handle_read;
    t_fd_handler handle_write;
    t_fd_handler handle_except;
} t_fd_control;

struct sel_timer_s
{
    /* Set this to the function to call when the timeout occurs. */
    timeout_handler_t handler;

    /* Set this to whatever you like.  You can use this to store your
       own data. */
    void *user_data;

    /* Set this to the time when the timer will go off. */
    struct timeval timeout;

    /* Who owns me? */
    selector_t *sel;

    /* Am I currently running? */
    int in_heap;

    /* Links for the heap. */
    sel_timer_t *left, *right, *up;
};

struct selector_s
{
    /* This is an array of all the file descriptors possible.  This is
       moderately wasteful of space, but easy to do.  Hey, memory is
       cheap. */
    t_fd_control fds[FD_SETSIZE];
    
    /* These are the offical fd_sets used to track what file descriptors
       need to be monitored. */
    fd_set read_set;
    fd_set write_set;
    fd_set except_set;

    int maxfd; /* The largest file descriptor registered with this
		  code. */

    /* The timer heap. */
    sel_timer_t *timer_top, *timer_last;
};

static t_sighup_handler user_sighup_handler = NULL;
static int got_sighup = 0; /* Did I get a HUP signal? */

/* Initialize a single file descriptor. */
static void
init_fd(t_fd_control *fd)
{
    fd->in_use = 0;
    fd->data = NULL;
    fd->handle_read = NULL;
    fd->handle_write = NULL;
    fd->handle_except = NULL;
}

/* Set the handlers for a file descriptor. */
void
set_fd_handlers(selector_t   *sel,
		int          fd,
		void         *data,
		t_fd_handler read_handler,
		t_fd_handler write_handler,
		t_fd_handler except_handler)
{
    sel->fds[fd].in_use = 1;
    sel->fds[fd].data = data;
    sel->fds[fd].handle_read = read_handler;
    sel->fds[fd].handle_write = write_handler;
    sel->fds[fd].handle_except = except_handler;

    /* Move maxfd up if necessary. */
    if (fd > sel->maxfd) {
	sel->maxfd = fd;
    }
}

/* Clear the handlers for a file descriptor and remove it from
   select's monitoring. */
void
clear_fd_handlers(selector_t   *sel,
		  int          fd)
{
    init_fd(&(sel->fds[fd]));
    FD_CLR(fd, &sel->read_set);
    FD_CLR(fd, &sel->write_set);
    FD_CLR(fd, &sel->except_set);

    /* Move maxfd down if necessary. */
    if (fd == sel->maxfd) {
	while ((sel->maxfd >= 0) && (! sel->fds[sel->maxfd].in_use)) {
	    sel->maxfd--;
	}
    }
}

/* Set whether the file descriptor will be monitored for data ready to
   read on the file descriptor. */
void
set_fd_read_handler(selector_t *sel, int fd, int state)
{
    if (state == FD_HANDLER_ENABLED) {
	FD_SET(fd, &sel->read_set);
    } else if (state == FD_HANDLER_DISABLED) {
	FD_CLR(fd, &sel->read_set);
    }
    /* FIXME - what to do on errors? */
}

/* Set whether the file descriptor will be monitored for when the file
   descriptor can be written to. */
void
set_fd_write_handler(selector_t *sel, int fd, int state)
{
    if (state == FD_HANDLER_ENABLED) {
	FD_SET(fd, &sel->write_set);
    } else if (state == FD_HANDLER_DISABLED) {
	FD_CLR(fd, &sel->write_set);
    }
    /* FIXME - what to do on errors? */
}

/* Set whether the file descriptor will be monitored for exceptions
   on the file descriptor. */
void
set_fd_except_handler(selector_t *sel, int fd, int state)
{
    if (state == FD_HANDLER_ENABLED) {
	FD_SET(fd, &sel->except_set);
    } else if (state == FD_HANDLER_DISABLED) {
	FD_CLR(fd, &sel->except_set);
    }
    /* FIXME - what to do on errors? */
}

static int
cmp_timeval(struct timeval *tv1, struct timeval *tv2)
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

void
find_next_pos(sel_timer_t *curr, sel_timer_t ***next, sel_timer_t **parent)
{
    unsigned int upcount = 0;

    if (curr->up && (curr->up->left == curr)) {
	/* We are a left node, the next node is just my right partner. */
	*next = &(curr->up->right);
	*parent = curr->up;
	return;
    }

    /* While we are a right node, go up. */
    while (curr->up && (curr->up->right == curr)) {
	upcount++;
	curr = curr->up;
    }

    if (curr->up) {
	/* Now we are a left node, trace up then back down. */
	curr = curr->up->right;
    }
    while (upcount) {
	curr = curr->left;
	upcount--;
    }
    *next = &(curr->left);
    *parent = curr;
}

static void
find_prev_elem(sel_timer_t *curr, sel_timer_t **prev)
{
    unsigned int upcount = 0;

    if (curr->up && (curr->up->right == curr)) {
	/* We are a right node, the previous node is just my left partner. */
	*prev = curr->up->left;
	return;
    }

    /* While we are a left node, go up. */
    while (curr->up && (curr->up->left == curr)) {
	upcount++;
	curr = curr->up;
    }

    if (curr->up) {
	/* Now we are a right node, trace up then back down. */
	curr = curr->up->left;
    } else {
	/* We are going to the previous "row". */
	upcount--;
    }
    while (upcount) {
	curr = curr->right;
	upcount--;
    }
    *prev = curr;
}

static void
send_up(sel_timer_t *elem, sel_timer_t **top, sel_timer_t **last)
{
    sel_timer_t *tmp1, *tmp2, *parent;

    parent = elem->up;
    while (parent && (cmp_timeval(&elem->timeout, &parent->timeout) < 0)) {
	tmp1 = elem->left;
	tmp2 = elem->right;
	if (parent->left == elem) {
	    elem->left = parent;
	    elem->right = parent->right;
	    if (elem->right)
		elem->right->up = elem;
	} else {
	    elem->right = parent;
	    elem->left = parent->left;
	    if (elem->left)
		elem->left->up = elem;
	}
	elem->up = parent->up;

	if (parent->up) {
	    if (parent->up->left == parent) {
		parent->up->left = elem;
	    } else {
		parent->up->right = elem;
	    }
	} else {
	    *top = elem;
	}

	parent->up = elem;
	parent->left = tmp1;
	parent->right = tmp2;

	if (*last == elem)
	    *last = parent;

	parent = elem->up;
    }
}

static void
send_down(sel_timer_t *elem, sel_timer_t **top, sel_timer_t **last)
{
    sel_timer_t *tmp1, *tmp2, *left, *right;

    left = elem->left;
    while (left) {
	if (cmp_timeval(&elem->timeout, &left->timeout) > 0) {
	    tmp1 = left->left;
	    tmp2 = left->right;
	    if (elem->up) {
		if (elem->up->left == elem) {
		    elem->up->left = left;
		} else {
		    elem->up->right = left;
		}
	    } else {
		*top = left;
	    }
	    left->up = elem->up;
	    elem->up = left;

	    left->left = elem;
	    left->right = elem->right;
	    elem->left = tmp1;
	    elem->right = tmp2;
	    if (left->right)
		left->right->up = left;

	    if (*last == left)
		*last = elem;
	} else {
	    right = elem->right;
	    if (cmp_timeval(&elem->timeout, &right->timeout) > 0) {
		tmp1 = right->left;
		tmp2 = right->right;
		if (elem->up) {
		    if (elem->up->left == elem) {
			elem->up->left = right;
		    } else {
			elem->up->right = right;
		    }
		} else {
		    *top = right;
		}
		right->up = elem->up;
		elem->up = right;

		right->left = elem->left;
		right->right = elem;
		elem->left = tmp1;
		elem->right = tmp2;
		if (right->left)
		    right->left->up = left;

		if (*last == right)
		    *last = elem;
	    } else {
		goto done;
	    }
	}
	left = elem->left;
    }
done:
}

static void
add_to_heap(sel_timer_t **top, sel_timer_t **last, sel_timer_t *elem)
{
    sel_timer_t **next;
    sel_timer_t *parent;

    elem->left = NULL;
    elem->right = NULL;
    elem->up = NULL;

    if (*top == NULL) {
	*top = elem;
	*last = elem;
	return;
    }

    find_next_pos(*last, &next, &parent);
    *next = elem;
    elem->up = parent;
    *last = elem;
    if (cmp_timeval(&elem->timeout, &parent->timeout) < 0) {
	send_up(elem, top, last);
    }
}

static void
remove_from_heap(sel_timer_t **top, sel_timer_t **last, sel_timer_t *elem)
{
    sel_timer_t *to_insert;

    /* First remove the last element from the tree, if it's not what's
       being removed, we will use it for insertion into the removal
       place. */
    to_insert = *last;
    if (! to_insert->up) {
	/* This is the only element in the heap. */
	*top = NULL;
	*last = NULL;
	return;
    } else {
	/* Set the new last position, and remove the item we will
           insert. */
	find_prev_elem(to_insert, last);
	if (to_insert->up->left == to_insert) {
	    to_insert->up->left = NULL;
	} else {
	    to_insert->up->right = NULL;
	}
    }

    if (elem == to_insert) {
	/* We got lucky and removed the last element.  We are done. */
	return;
    }

    /* Now stick the formerly last element into the removed element's
       position. */
    if (elem->up) {
	if (elem->up->left == elem) {
	    elem->up->left = to_insert;
	} else {
	    elem->up->right = to_insert;
	}
    } else {
	/* The head of the tree is being replaced. */
	*top = to_insert;
    }
    to_insert->up = elem->up;
    if (elem->left)
	elem->left->up = to_insert;
    if (elem->right)
	elem->right->up = to_insert;
    to_insert->left = elem->left;
    to_insert->right = elem->right;

    if (*last == elem)
	*last = to_insert;

    elem = to_insert;

    /* Now propigate it to the right place in the tree. */
    if (elem->up && cmp_timeval(&elem->timeout, &elem->up->timeout) < 0) {
	send_up(elem, top, last);
    } else {
	send_down(elem, top, last);
    }
}

int
alloc_timer(selector_t        *sel,
	    timeout_handler_t handler,
	    void              *user_data,
	    sel_timer_t       **new_timer)
{
    sel_timer_t *timer;

    timer = malloc(sizeof(*timer));
    if (!timer)
	return ENOMEM;

    timer->handler = handler;
    timer->user_data = user_data;
    timer->in_heap = 0;
    timer->sel = sel;
    *new_timer = timer;

    return 0;
}

int free_timer(sel_timer_t *timer)
{
    if (timer->in_heap) {
	stop_timer(timer);
    }
    free(timer);
}

int
start_timer(sel_timer_t    *timer,
	    struct timeval *timeout)
{
    if (timer->in_heap)
	return EBUSY;

    timer->timeout = *timeout;
    add_to_heap(&(timer->sel->timer_top), &(timer->sel->timer_last), timer);
    timer->in_heap = 1;
    return 0;
}

int
stop_timer(sel_timer_t *timer)
{
    if (!timer->in_heap)
	return ETIMEDOUT;

    remove_from_heap(&(timer->sel->timer_top),
		     &(timer->sel->timer_last),
		     timer);
    timer->in_heap = 0;
    return 0;
}

/* The main loop for the program.  This will select on the various
   sets, then scan for any available I/O to process.  It also monitors
   the time and call the timeout handlers periodically. */
void
select_loop(selector_t *sel)
{
    fd_set      tmp_read_set;
    fd_set      tmp_write_set;
    fd_set      tmp_except_set;
    int         i;
    int         err;
    sel_timer_t *timer;
    struct timeval timeout, *to_time;

    for (;;) {
	if (sel->timer_top) {
	    struct timeval now;

	    /* Check for timers to time out. */
	    gettimeofday(&now, NULL);
	    timer = sel->timer_top;
	    while (cmp_timeval(&now, &timer->timeout) >= 0) {
		remove_from_heap(&(sel->timer_top),
				 &(sel->timer_last),
				 timer);

		timer->in_heap = 0;
		timer->handler(sel, timer, timer->user_data);

		timer = sel->timer_top;
		gettimeofday(&now, NULL);
		if (!timer)
		    goto no_timers;
	    }

	    /* Calculate how long to wait now. */
	    diff_timeval(&timeout, &sel->timer_top->timeout, &now);
	    to_time = &timeout;
	} else {
	no_timers:
	    to_time = NULL;
	}
	memcpy(&tmp_read_set, &sel->read_set, sizeof(tmp_read_set));
	memcpy(&tmp_write_set, &sel->write_set, sizeof(tmp_write_set));
	memcpy(&tmp_except_set, &sel->except_set, sizeof(tmp_except_set));
	err = select(sel->maxfd+1,
		     &tmp_read_set,
		     &tmp_write_set,
		     &tmp_except_set,
		     to_time);
	if (err == 0) {
	    /* A timeout occurred. */
	} else if (err < 0) {
	    /* An error occurred. */
	    if (errno == EINTR) {
		/* EINTR is ok, just restart the operation. */
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
	    } else {
		/* An error is bad, we need to abort. */
		syslog(LOG_ERR, "select_loop() - select: %m");
		exit(1);
	    }
	} else {
	    /* We got some I/O. */
	    for (i=0; i<=sel->maxfd; i++) {
		if (FD_ISSET(i, &tmp_read_set)) {
		    if (sel->fds[i].handle_read == NULL) {
			/* Somehow we don't have a handler for this.
                           Just shut it down. */
			set_fd_read_handler(sel, i, FD_HANDLER_DISABLED);
		    } else {
			sel->fds[i].handle_read(i, sel->fds[i].data);
		    }
		}
		if (FD_ISSET(i, &tmp_write_set)) {
		    if (sel->fds[i].handle_write == NULL) {
			/* Somehow we don't have a handler for this.
                           Just shut it down. */
			set_fd_write_handler(sel, i, FD_HANDLER_DISABLED);
		    } else {
			sel->fds[i].handle_write(i, sel->fds[i].data);
		    }
		}
		if (FD_ISSET(i, &tmp_except_set)) {
		    if (sel->fds[i].handle_except == NULL) {
			/* Somehow we don't have a handler for this.
                           Just shut it down. */
			set_fd_except_handler(sel, i, FD_HANDLER_DISABLED);
		    } else {
			sel->fds[i].handle_except(i, sel->fds[i].data);
		    }
		}
	    }
	}

	if (got_sighup) {
	    got_sighup = 0;
	    if (user_sighup_handler != NULL) {
		user_sighup_handler();
	    }
	}
    }
}

/* Initialize the select code. */
int
alloc_selector(selector_t **new_selector)
{
    selector_t *sel;
    int        i;

    sel = malloc(sizeof(*sel));
    if (!sel)
	return ENOMEM;

    FD_ZERO(&sel->read_set);
    FD_ZERO(&sel->write_set);
    FD_ZERO(&sel->except_set);

    for (i=0; i<FD_SETSIZE; i++) {
	init_fd(&(sel->fds[i]));
    }

    sel->timer_top = NULL;
    sel->timer_last = NULL;

    *new_selector = sel;

    return 0;
}

static void
free_heap_element(sel_timer_t *elem)
{
    if (!elem)
	return;

    free_heap_element(elem->left);
    free_heap_element(elem->right);
    free(elem);
}

int
free_selector(selector_t *sel)
{
    int         rv;
    sel_timer_t *heap;

    heap = sel->timer_top;

    free(sel);
    free_heap_element(heap);

    return 0;
}

void
set_sighup_handler(t_sighup_handler handler)
{
    user_sighup_handler = handler;
}


void sighup_handler(int sig)
{
    got_sighup = 1;
}

void
setup_sighup(void)
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
}
