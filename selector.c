/*
 * selector.c
 *
 * Code for abstracting select for files and timers.
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2002 MontaVista Software Inc.
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
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>

/* The control structure for each file descriptor. */
typedef struct fd_control_s
{
    int              in_use;
    void             *data;		/* Operation-specific data */
    sel_fd_handler_t handle_read;
    sel_fd_handler_t handle_write;
    sel_fd_handler_t handle_except;
} fd_control_t;

struct sel_timer_s
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

    /* Links for the heap. */
    sel_timer_t *left, *right, *up;
};

struct selector_s
{
    /* This is an array of all the file descriptors possible.  This is
       moderately wasteful of space, but easy to do.  Hey, memory is
       cheap. */
    fd_control_t fds[FD_SETSIZE];
    
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

static t_signal_handler user_sighup_handler = NULL;
static t_signal_handler user_sigint_handler = NULL;
static int got_sighup = 0; /* Did I get a HUP signal? */
static int got_sigint = 0; /* Did I get an INT signal? */

/* Initialize a single file descriptor. */
static void
init_fd(fd_control_t *fd)
{
    fd->in_use = 0;
    fd->data = NULL;
    fd->handle_read = NULL;
    fd->handle_write = NULL;
    fd->handle_except = NULL;
}

/* Set the handlers for a file descriptor. */
void
sel_set_fd_handlers(selector_t       *sel,
		    int              fd,
		    void             *data,
		    sel_fd_handler_t read_handler,
		    sel_fd_handler_t write_handler,
		    sel_fd_handler_t except_handler)
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
sel_clear_fd_handlers(selector_t   *sel,
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
sel_set_fd_read_handler(selector_t *sel, int fd, int state)
{
    if (state == SEL_FD_HANDLER_ENABLED) {
	FD_SET(fd, &sel->read_set);
    } else if (state == SEL_FD_HANDLER_DISABLED) {
	FD_CLR(fd, &sel->read_set);
    }
    /* FIXME - what to do on errors? */
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
    /* FIXME - what to do on errors? */
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

#undef MASSIVE_DEBUG
#ifdef MASSIVE_DEBUG
FILE **debug_out = &stderr;
static void
print_tree_item(sel_timer_t *pos, int indent)
{
    int i;
    for (i=0; i<indent; i++)
	fprintf(*debug_out, " ");
    fprintf(*debug_out, "  %p: %p %p %p (%ld.%7.7ld)\n", pos, pos->left, pos->right,
	   pos->up, pos->timeout.tv_sec, pos->timeout.tv_usec);
    if (pos->left)
	print_tree_item(pos->left, indent+1);
    if (pos->right)
	print_tree_item(pos->right, indent+1);
}

static void
print_tree(sel_timer_t *top, sel_timer_t *last)
{
    fprintf(*debug_out, "top=%p\n", top);
    if (top)
	print_tree_item(top, 0);
    fprintf(*debug_out, "last=%p\n", last);
    fflush(*debug_out);
}

static void
check_tree_item(sel_timer_t *curr,
		int         *depth,
		int         max_depth,
		sel_timer_t **real_last,
		int         *found_last)
{
    if (! curr->left) {
	if (curr->right) {
	    fprintf(*debug_out, "Tree corrupt B\n");
	    *((int *) NULL) = 0;
	} else if (*depth > max_depth) {
	    fprintf(*debug_out, "Tree corrupt C\n");
	    *((int *) NULL) = 0;
	} else if (*depth < (max_depth - 1)) {
	    fprintf(*debug_out, "Tree corrupt D\n");
	    *((int *) NULL) = 0;
	} else if ((*found_last) && (*depth == max_depth)) {
	    fprintf(*debug_out, "Tree corrupt E\n");
	    *((int *) NULL) = 0;
	} else if (*depth == max_depth) {
	    *real_last = curr;
	} else {
	    *found_last = 1;
	}
    } else {
	if (curr->left->up != curr) {
	    fprintf(*debug_out, "Tree corrupt I\n");
	    *((int *) NULL) = 0;
	}
	if (cmp_timeval(&(curr->left->timeout), &(curr->timeout)) < 0) {
	    fprintf(*debug_out, "Tree corrupt K\n");
	    *((int *) NULL) = 0;
	}
	(*depth)++;
	check_tree_item(curr->left, depth, max_depth, real_last, found_last);
	(*depth)--;

	if (! curr->right) {
	    if (*depth != (max_depth - 1)) {
		fprintf(*debug_out, "Tree corrupt F\n");
		*((int *) NULL) = 0;
	    }
	    if (*found_last) {
		fprintf(*debug_out, "Tree corrupt G\n");
		*((int *) NULL) = 0;
	    }
	    *found_last = 1;
	} else {
	    if (curr->right->up != curr) {
		fprintf(*debug_out, "Tree corrupt H\n");
		*((int *) NULL) = 0;
	    }
	    if (cmp_timeval(&(curr->right->timeout), &(curr->timeout)) < 0) {
		fprintf(*debug_out, "Tree corrupt L\n");
		*((int *) NULL) = 0;
	    }
	    (*depth)++;
	    check_tree_item(curr->right, depth, max_depth, real_last, found_last);
	    (*depth)--;
	}
    }
}

static void
check_tree(sel_timer_t *top, sel_timer_t *last)
{
    unsigned int depth = 0, max_depth = 0;
    int          found_last = 0;
    sel_timer_t  *real_last;

    if (!top) {
	if (last) {
	    fprintf(*debug_out, "Tree corrupt A\n");
	    *((int *) NULL) = 0;
	}
	return;
    }

    real_last = top;
    while (real_last->left) {
	real_last = real_last->left;
	max_depth++;
    }

    real_last = NULL;
    check_tree_item(top, &depth, max_depth, &real_last, &found_last);

    if (real_last != last) {
	fprintf(*debug_out, "Tree corrupt J\n");
	*((int *) NULL) = 0;
    }
    fflush(*debug_out);
}
#endif

static void
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
	upcount--;
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
	if (parent->left)
	    parent->left->up = parent;
	parent->right = tmp2;
	if (parent->right)
	    parent->right->up = parent;

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
	right = elem->right;
	/* Choose the smaller of the two below me to swap with. */
	if ((right) && (cmp_timeval(&left->timeout, &right->timeout) > 0)) {

	    if (cmp_timeval(&elem->timeout, &right->timeout) > 0) {
		/* Swap with the right element. */
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
		    right->left->up = right;
		if (elem->left)
		    elem->left->up = elem;
		if (elem->right)
		    elem->right->up = elem;

		if (*last == right)
		    *last = elem;
	    } else
		goto done;
	} else {
	    /* The left element is smaller, or the right doesn't exist. */
	    if (cmp_timeval(&elem->timeout, &left->timeout) > 0) {
		/* Swap with the left element. */
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
		if (elem->left)
		    elem->left->up = elem;
		if (elem->right)
		    elem->right->up = elem;

		if (*last == left)
		    *last = elem;
	    } else
		goto done;
	}
	left = elem->left;
    }
done:
    return;
}

static void
add_to_heap(sel_timer_t **top, sel_timer_t **last, sel_timer_t *elem)
{
    sel_timer_t **next;
    sel_timer_t *parent;

#ifdef MASSIVE_DEBUG
    fprintf(*debug_out, "add_to_heap entry\n");
    print_tree(*top, *last);
    check_tree(*top, *last);
#endif

    elem->left = NULL;
    elem->right = NULL;
    elem->up = NULL;

    if (*top == NULL) {
	*top = elem;
	*last = elem;
	goto out;
    }

    find_next_pos(*last, &next, &parent);
    *next = elem;
    elem->up = parent;
    *last = elem;
    if (cmp_timeval(&elem->timeout, &parent->timeout) < 0) {
	send_up(elem, top, last);
    }

 out:
#ifdef MASSIVE_DEBUG
    fprintf(*debug_out, "add_to_heap exit\n");
    print_tree(*top, *last);
    check_tree(*top, *last);
#endif
    return;
}

static void
remove_from_heap(sel_timer_t **top, sel_timer_t **last, sel_timer_t *elem)
{
    sel_timer_t *to_insert;

#ifdef MASSIVE_DEBUG
    fprintf(*debug_out, "remove_from_head entry\n");
    print_tree(*top, *last);
    check_tree(*top, *last);
#endif

    /* First remove the last element from the tree, if it's not what's
       being removed, we will use it for insertion into the removal
       place. */
    to_insert = *last;
    if (! to_insert->up) {
	/* This is the only element in the heap. */
	*top = NULL;
	*last = NULL;
	goto out;
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
	goto out;
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

 out:
#ifdef MASSIVE_DEBUG
    fprintf(*debug_out, "remove_from_head exit\n");
    print_tree(*top, *last);
    check_tree(*top, *last);
#endif
    return;
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

    timer->handler = handler;
    timer->user_data = user_data;
    timer->in_heap = 0;
    timer->sel = sel;
    *new_timer = timer;

    return 0;
}

int
sel_free_timer(sel_timer_t *timer)
{
    if (timer->in_heap) {
	sel_stop_timer(timer);
    }
    free(timer);

    return 0;
}

int
sel_start_timer(sel_timer_t    *timer,
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
sel_stop_timer(sel_timer_t *timer)
{
    if (!timer->in_heap)
	return ETIMEDOUT;

    remove_from_heap(&(timer->sel->timer_top),
		     &(timer->sel->timer_last),
		     timer);
    timer->in_heap = 0;
    return 0;
}

void
sel_select_once(selector_t *sel)
{
    fd_set      tmp_read_set;
    fd_set      tmp_write_set;
    fd_set      tmp_except_set;
    int         i;
    int         err;
    sel_timer_t *timer;
    struct timeval timeout, *to_time;

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
		    sel_set_fd_read_handler(sel, i, SEL_FD_HANDLER_DISABLED);
		} else {
		    sel->fds[i].handle_read(i, sel->fds[i].data);
		}
	    }
	    if (FD_ISSET(i, &tmp_write_set)) {
		if (sel->fds[i].handle_write == NULL) {
		    /* Somehow we don't have a handler for this.
		       Just shut it down. */
		    sel_set_fd_write_handler(sel, i, SEL_FD_HANDLER_DISABLED);
		} else {
		    sel->fds[i].handle_write(i, sel->fds[i].data);
		}
	    }
	    if (FD_ISSET(i, &tmp_except_set)) {
		if (sel->fds[i].handle_except == NULL) {
		    /* Somehow we don't have a handler for this.
		       Just shut it down. */
		    sel_set_fd_except_handler(sel, i, SEL_FD_HANDLER_DISABLED);
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
    if (got_sigint) {
	got_sigint = 0;
	if (user_sigint_handler != NULL) {
	    user_sigint_handler();
	}
    }
}

/* The main loop for the program.  This will select on the various
   sets, then scan for any available I/O to process.  It also monitors
   the time and call the timeout handlers periodically. */
void
sel_select_loop(selector_t *sel)
{
    for (;;)
	sel_select_once(sel);
}

/* Initialize the select code. */
int
sel_alloc_selector(selector_t **new_selector)
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

    sel->maxfd = 0;
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
sel_free_selector(selector_t *sel)
{
    sel_timer_t *heap;

    heap = sel->timer_top;

    free(sel);
    free_heap_element(heap);

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
