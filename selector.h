/*
 * selector.h
 *
 * MontaVista IPMI interface code for timers and file waiting.
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

#ifndef SELECTOR
#define SELECTOR
#include <sys/time.h> /* For timeval */

#ifdef __cplusplus
extern "C" {
#endif

/* The main data structure used by the selector. */
struct selector_s;

/* You have to create a selector before you can use it. */

/* Create a selector for use with threads.  You have to pass in the
   lock functions and a signal used to wake waiting threads. */
typedef struct sel_lock_s sel_lock_t;
int sel_alloc_selector_thread(struct selector_s **new_selector, int wake_sig,
			      sel_lock_t *(*sel_lock_alloc)(void *cb_data),
			      void (*sel_lock_free)(sel_lock_t *),
			      void (*sel_lock)(sel_lock_t *),
			      void (*sel_unlock)(sel_lock_t *),
			      void *cb_data);

  /* Create a selector for use in a single-threaded environment.  No
     need for locks or wakeups.  This just call the above call with
     NULL for all the values. */
int sel_alloc_selector_nothread(struct selector_s **new_selector);

/* Used to destroy a selector. */
int sel_free_selector(struct selector_s *new_selector);


/* A function to call when select sees something on a file
   descriptor. */
typedef void (*sel_fd_handler_t)(int fd, void *data);

/* Set the handlers for a file descriptor.  The "data" parameter is
   not used, it is just passed to the exception handlers.  The done
   handler (if non-NULL) will be called when the data is removed or
   replaced. */
typedef void (*sel_fd_cleared_cb)(int fd, void *data);
int sel_set_fd_handlers(struct selector_s *sel,
			int               fd,
			void              *data,
			sel_fd_handler_t  read_handler,
			sel_fd_handler_t  write_handler,
			sel_fd_handler_t  except_handler,
			sel_fd_cleared_cb done);

/* Remove the handlers for a file descriptor.  This will also disable
   the handling of all I/O for the fd.  Note that when this returns,
   some other thread may be in a handler.  To avoid races with
   clearing the data (SMP only), you should provide a done handler in
   the set routine; it will be called when the registered handler is
   sure to not be called again. */
void sel_clear_fd_handlers(struct selector_s *sel,
			   int        fd);

/* Turn on and off handling for I/O from a file descriptor. */
#define SEL_FD_HANDLER_ENABLED	0
#define SEL_FD_HANDLER_DISABLED	1
void sel_set_fd_read_handler(struct selector_s *sel, int fd, int state);
void sel_set_fd_write_handler(struct selector_s *sel, int fd, int state);
void sel_set_fd_except_handler(struct selector_s *sel, int fd, int state);

struct sel_timer_s;
typedef struct sel_timer_s sel_timer_t;

typedef void (*sel_timeout_handler_t)(struct selector_s *sel,
				      sel_timer_t *timer,
				      void        *data);

int sel_alloc_timer(struct selector_s     *sel,
		    sel_timeout_handler_t handler,
		    void                  *user_data,
		    sel_timer_t           **new_timer);

int sel_free_timer(sel_timer_t *timer);

int sel_start_timer(sel_timer_t    *timer,
		    struct timeval *timeout);

int sel_stop_timer(sel_timer_t *timer);
int sel_stop_timer_with_done(sel_timer_t *timer,
			     sel_timeout_handler_t done_handler,
			     void *cb_data);

/* Use this for times provided to sel_start_time() */
void sel_get_monotonic_time(struct timeval *tv);

typedef struct sel_runner_s sel_runner_t;
typedef void (*sel_runner_func_t)(sel_runner_t *runner, void *cb_data);
int sel_alloc_runner(struct selector_s *sel, sel_runner_t **new_runner);
int sel_free_runner(sel_runner_t *runner);
int sel_run(sel_runner_t *runner, sel_runner_func_t func, void *cb_data);

/* For multi-threaded programs, you will need to wake the selector
   thread if you add a timer to the top of the heap or change the fd
   mask.  This code should send a signal to the thread that calls
   sel-select_loop.  The user will have to allocate the signal, set
   the handlers, etc.  The thread_id and cb_data are just the values
   passed into sel_select_loop(). */
typedef void (*sel_send_sig_cb)(long thread_id, void *cb_data);

/*
 * This is the select interface for program. All handlers on timers and
 * fds will get chances to be called.
 * return >0 if sel_select did something (ran a timer or fd)
 *         0 if timeout
 *        <0 if error (errno will be set)
 * The timeout is a relative timeout (just like normal select() on
 * *nix).
 */
int sel_select(struct selector_s *sel,
	       sel_send_sig_cb send_sig,
	       long            thread_id,
	       void            *cb_data,
	       struct timeval  *timeout);

/* This is the main loop for the program.  If NULL is passed in to
   send_sig, then the signal sender is not used.  If this encounters
   an unrecoverable problem with select(), it will return the errno.
   Otherwise it will loop forever. */
int sel_select_loop(struct selector_s *sel,
		    sel_send_sig_cb send_sig,
		    long            thread_id,
		    void            *cb_data);

typedef void (*ipmi_sel_add_read_fds_cb)(struct selector_s *sel,
					 int            *num_fds,
					 fd_set         *fdset,
					 struct timeval *timeout,
					 int            *timeout_invalid,
					 void           *cb_data);
typedef void (*ipmi_sel_check_read_fds_cb)(struct selector_s *sel,
					   fd_set     *fds,
					   void       *cb_data);
typedef void (*ipmi_sel_check_timeout_cb)(struct selector_s *sel,
					  void       *cb_data);
void ipmi_sel_set_read_fds_handler(struct selector_s          *sel,
				   ipmi_sel_add_read_fds_cb   add,
				   ipmi_sel_check_read_fds_cb handle,
				   ipmi_sel_check_timeout_cb  timeout,
				   void                       *cb_data);

#ifdef __cplusplus
}
#endif

#endif /* SELECTOR */
