/*
 *  gensio - A library for abstracting stream I/O
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

/*
 * This include file defines a network I/O abstraction to allow code
 * to use TCP, UDP, stdio, telnet, ssl, etc. without having to know
 * the underlying details.
 */

#ifndef GENSIO_H
#define GENSIO_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

/*
 * Function pointers to provide OS functions.
 */

struct gensio_lock;
struct gensio_timer;
struct gensio_runner;

struct gensio_once {
    bool called;
};

/*
 * A bitmask of log levels to tell what to log.  Defaults to fatal and err
 * only.
 */
extern unsigned int gensio_log_mask;

enum gensio_log_levels {
    GENSIO_LOG_FATAL,
    GENSIO_LOG_ERR,
    GENSIO_LOG_WARNING,
    GENSIO_LOG_INFO,
    GENSIO_LOG_DEBUG
};

struct gensio_os_funcs {
    /* For use by the code doing the os function translation. */
    void *user_data;

    /* For use by other code. */
    void *other_data;

    /****** Memory Allocation ******/
    /* Return allocated and zeroed data.  Return NULL on error. */
    void *(*zalloc)(struct gensio_os_funcs *f, unsigned int size);

    /* Free data allocated by zalloc. */
    void (*free)(struct gensio_os_funcs *f, void *data);

    /****** Mutexes ******/
    /* Allocate a lock.  Return NULL on error. */
    struct gensio_lock *(*alloc_lock)(struct gensio_os_funcs *f);

    /* Free a lock allocated with alloc_lock. */
    void (*free_lock)(struct gensio_lock *lock);

    /* Lock the lock. */
    void (*lock)(struct gensio_lock *lock);

    /* Unlock the lock. */
    void (*unlock)(struct gensio_lock *lock);

    /****** File Descriptor Handling ******/
    /*
     * Setup handlers to be called on the fd for various reasons:
     *
     * read_handler - called when data is ready to read.
     * write_handler - called when there is room to write data.
     * except_handler - called on exception cases (tcp urgent data).
     * cleared_handler - called when clear_fd_handlers completes.
     *
     * Note that all handlers are disabled when this returns, you must
     * enable them for the callbacks to be called.
     */
    int (*set_fd_handlers)(struct gensio_os_funcs *f,
			   int fd,
			   void *cb_data,
			   void (*read_handler)(int fd, void *cb_data),
			   void (*write_handler)(int fd, void *cb_data),
			   void (*except_handler)(int fd, void *cb_data),
			   void (*cleared_handler)(int fd, void *cb_data));

    /*
     * Clear the handlers for an fd.  Note that the operation is not
     * complete when the function returns.  The code may be running in
     * callbacks during this call, and it won't wait.  Instead,
     * cleared_handler is called when the operation completes, you
     * need to wait for that.
     */
    void (*clear_fd_handlers)(struct gensio_os_funcs *f, int fd);

    /*
     * Like the above, but does not call the cleared_handler function
     * when done.  This can only be called if you never enabled the
     * handlers, it is only for shutdown when an error occurs at startup.
     */
    void (*clear_fd_handlers_norpt)(struct gensio_os_funcs *f, int fd);

    /*
     * Enable/disable the various handlers.  Note that if you disable
     * a handler, it may still be running in a callback, this does not
     * wait.
     */
    void (*set_read_handler)(struct gensio_os_funcs *f, int fd, bool enable);
    void (*set_write_handler)(struct gensio_os_funcs *f, int fd, bool enable);
    void (*set_except_handler)(struct gensio_os_funcs *f, int fd, bool enable);

    /****** Timers ******/
    /*
     * Allocate a timer that calls the given handler when it goes
     * off.  Return NULL on error.
     */
    struct gensio_timer *(*alloc_timer)(struct gensio_os_funcs *f,
					void (*handler)(struct gensio_timer *t,
							void *cb_data),
					void *cb_data);

    /*
     * Free a timer allocated with alloc_timer.  The timer should not
     * be running.
     */
    void (*free_timer)(struct gensio_timer *timer);

    /*
     * Start the timer running.  Returns EBUSY if the timer is already
     * running.  This is a relative timeout.
     */
    int (*start_timer)(struct gensio_timer *timer, struct timeval *timeout);

    /*
     * Start the timer running.  Returns EBUSY if the timer is already
     * running.  This is an absolute timeout based on the monotonic
     * time returned by get_monotonic_time.
     */
    int (*start_timer_abs)(struct gensio_timer *timer, struct timeval *timeout);

    /*
     * Stop the timer.  Returns ETIMEDOUT if the timer is not running.
     * Note that the timer may still be running in a timeout handler
     * when this returns.
     */
    int (*stop_timer)(struct gensio_timer *timer);

    /*
     * Like the above, but the done_handler is called when the timer is
     * completely stopped and no handler is running.  If ETIMEDOUT is
     * returned, the done_handler is not called.
     */
    int (*stop_timer_with_done)(struct gensio_timer *timer,
				void (*done_handler)(struct gensio_timer *t,
						     void *cb_data),
				void *cb_data);

    /****** Runners ******/
    /*
     * Allocate a runner.  Return NULL on error.  A runner runs things
     * at a base context.  This is useful for handling situations
     * where you need to run something outside of a lock or context,
     * you schedule the runner.
     */
    struct gensio_runner *(*alloc_runner)(struct gensio_os_funcs *f,
				void (*handler)(struct gensio_runner *r,
						void *cb_data),
				void *cb_data);

    /* Free a runner allocated with alloc_runner. */
    void (*free_runner)(struct gensio_runner *runner);

    /*
     * Run a runner.  Return EBUSY if the runner is already scheduled
     * to run.
     */
    int (*run)(struct gensio_runner *runner);

    /****** Waiters ******/
    /*
     * Allocate a waiter, returns NULL on error.  A waiter is used to
     * wait for some action to occur.  When the action occurs, that code
     * should call wake to wake the waiter.  Normal operation of the
     * file descriptors, tiemrs, runners, etc. happens while waiting.
     * You should be careful of the context of calling a waiter, like
     * what locks you are holding or what callbacks you are in.
     *
     * Note that waiters and wakes are count based, if you call wake()
     * before wait() that's ok.  If you call wake() 3 times, there
     * are 3 wakes pending.
     */
    struct gensio_waiter *(*alloc_waiter)(struct gensio_os_funcs *f);

    /* Free a waiter allocated by alloc_waiter. */
    void (*free_waiter)(struct gensio_waiter *waiter);

    /*
     * Wait for count wakeups for up to the amount of time (relative)
     * given in timeout.  If timeout is NULL wait forever.  This
     * returns ETIMEDOUT on a timeout.  It can return other errors.
     * The timeout is updated to the remaining time.
     * Note that if you get a timeout, none of the wakeups will be
     * "used" by this call.
     */
    int (*wait)(struct gensio_waiter *waiter, unsigned int count,
		struct timeval *timeout);

    /*
     * Like wait, but return if a signal is received by the thread.
     * This is useful if you want to handle SIGINT or something like
     * that.
     */
    int (*wait_intr)(struct gensio_waiter *waiter, unsigned int count,
		     struct timeval *timeout);

    /* Wake the given waiter. */
    void (*wake)(struct gensio_waiter *waiter);

    /****** Misc ******/
    /*
     * Run the timers, fd handling, runners, etc.  This does one
     * operation and returns.  If timeout is non-NULL, if nothing
     * happens before the relative time given it will return.
     * The timeout is updated to the remaining time.
     */
    int (*service)(struct gensio_os_funcs *f, struct timeval *timeout);

    /* Free this structure. */
    void (*free_funcs)(struct gensio_os_funcs *f);

    /* Call this function once. */
    void (*call_once)(struct gensio_os_funcs *f, struct gensio_once *once,
		      void (*func)(void *cb_data), void *cb_data);

    void (*get_monotonic_time)(struct gensio_os_funcs *f, struct timeval *time);

    void (*vlog)(struct gensio_os_funcs *f, enum gensio_log_levels level,
		 const char *log, va_list args);
};

void gensio_vlog(struct gensio_os_funcs *o, enum gensio_log_levels level,
		 const char *str, va_list args);
void gensio_log(struct gensio_os_funcs *o, enum gensio_log_levels level,
		const char *str, ...);


struct gensio;

/*
 * Called when data is read from the I/O device.
 *
 * If err is zero, buf points to a data buffer and buflen is the
 * number of bytes available.
 *
 * If err is set, buf and buflen are undefined.  readerr is a standard
 * *nix errno.
 *
 * You must return the number of bytes consumed.  Note that you must
 * disable read if you don't consume all the bytes or in other
 * situations where you don't want the read handler called.
 */
#define GENSIO_EVENT_READ		1

/*
 * Called when data can be written to the I/O device.  Only io is
 * set, all other parameters are unused and the return value is
 * ignored.
 */
#define GENSIO_EVENT_WRITE_READY	2

/*
 * Called when an urgent signal is received from the I/O device.  Only
 * io is set, all other parameters are unused and the return value is
 * ignored.
 */
#define GENSIO_EVENT_URGENT		3

/*
 * A new channel has been created by the remote end of the connection.
 * The new channel gensio is in auxdata.  buf may contain a string
 * with information about the new channel.  If this returns an error,
 * the channel creation is refused and the channel is closed.
 */
#define GENSIO_EVENT_NEW_CHANNEL	4

/*
 * Serial callbacks start here and run to 2000.
 */
#define SERGENIO_EVENT_BASE	1000

/*
 * If a user creates their own gensio with their own events, they should
 * use this range.
 */
#define GENSIO_EVENT_USER_MIN		100000
#define GENSIO_EVENT_USER_MAX		199999

/*
 * Called for any event from the I/O.  Parameters are:
 *
 *   event - What event is being reported?  One of GENSIO_EVENT_xxx.
 *
 *   err - If zero, there is no error.  If non-zero, this is reporting
 *         an error.  Generally only on read events.
 *
 *   buf - For events reporting data transferred (generally read), this
 *         is the data.  Undefined for events not transferring data.
 *
 *   buflen - The length of data being transferred.  This passes in the
 *            lenth, the user should update it with the number of bytes
 *            actually processed.  NULL for events not transferring data.
 *
 *   auxdata - Depending on the event, other data may be transferred.
 *             this holds a pointer to it.
 *
 * This function should return 0 if it handled the event, or ENOTSUP if
 * it didn't.
 */
typedef int (*gensio_event)(struct gensio *io, int event, int err,
			    unsigned char *buf, unsigned int *buflen,
			    void *auxdata);

/*
 * Callbacks for functions that don't give an error (close);
 */
typedef void (*gensio_done)(struct gensio *io, void *open_data);

/*
 * Callbacks for functions that give an error (open);
 */
typedef void (*gensio_done_err)(struct gensio *io, int err, void *open_data);

/*
 * Set the callback data for the net.  This must be done in the
 * new_connection callback for the accepter before any other operation
 * is done on the gensio.  The only exception is that gensio_close() may
 * be called with callbacks not set.  This function may be called
 * again if the gensio is not enabled.
 */
void gensio_set_callback(struct gensio *io, gensio_event cb, void *user_data);

/*
 * Return the user data supplied in gensio_set_callbacks().
 */
void *gensio_get_user_data(struct gensio *io);

/*
 * Set the user data.  May be called if the gensio is not enabled.
 */
void gensio_set_user_data(struct gensio *io, void *user_data);

/*
 * Write data to the gensio.  This should only be called from the
 * write callback for most general usage.  Writes buflen bytes
 * from buf.
 *
 * Returns errno on error, or 0 on success.  This will NEVER return
 * EAGAIN, EWOULDBLOCK, or EINTR.  Those are handled internally.
 *
 * On a non-error return, count is set to the number of bytes
 * consumed by the write call, which may be less than buflen.  If
 * it is less than buflen, then not all the data was written.
 * Note that count may be set to zero.  This can happen on an
 * EAGAIN type situation.  count may be NULL if you don't care.
 */
int gensio_write(struct gensio *io, unsigned int *count,
		 const void *buf, unsigned int buflen);

/*
 * Convert the remote address for this network connection to a
 * string.  The string starts at buf + *pos and goes to buf +
 * buflen.  If pos is NULL, then zero is used.  The string is
 * NIL terminated.
 *
 * Returns an errno on an error, and a string error will be put
 * into the buffer.
 *
 * In all cases, if pos is non-NULL it will be updated to be the
 * NIL char after the last byte of the string, where you would
 * want to put any new data into the string.
 */
int gensio_raddr_to_str(struct gensio *io, unsigned int *pos,
			char *buf, unsigned int buflen);

/*
 * Return the remote address for the connection.  addrlen must be
 * set to the size of addr and will be updated to the actual size.
 */
int gensio_get_raddr(struct gensio *io, void *addr, unsigned int *addrlen);

/*
 * Returns an id for the remote end.  For stdio clients this is the
 * pid.  For termios this is the fd.  It returns an error
 * for all others.
 */
int gensio_remote_id(struct gensio *io, int *id);

/*
 * Open the gensio.  gensios recevied from an accepter are open upon
 * receipt, but client gensios are started closed and need to be opened
 * before use.  If no error is returned, the gensio will be open when
 * the open_done callback is called.
 */
int gensio_open(struct gensio *io, gensio_done_err open_done, void *open_data);

/*
 * Like gensio_open(), but waits for the open to complete.
 */
int gensio_open_s(struct gensio *io);

/*
 * Open a channel on the given gensio.  The gensio must one that
 * supports channels (like SCTP, SSH, or stdio).  The args parm is
 * specific to the gensio type, and contains information that
 * describes how to set up the new channel.  The channel open creates
 * a new gensio object with its own callbacks and user data.
 *
 * For stdio, this only opens a channel for stderr input, args can be
 * "readbuf=<num>" and sets the size of the input buffer.  This is how
 * you get stderr output from a stdio channel, and it only works for
 * client-created stdio, not acceptor-created stdio.
 */
int gensio_open_channel(struct gensio *io, const char *args,
			gensio_event cb, void *user_data,
			gensio_done_err open_done, void *open_data,
			struct gensio **new_io);

/*
 * Like gensio_open_channel, but waits for the open to complete and
 * returns the gensio for the channel.
 */
int gensio_open_channel_s(struct gensio *io, const char *args,
			  gensio_event cb, void *user_data,
			  struct gensio **new_io);

/*
 * Return the type string for the gensio (if depth is 0) or one of its
 * children (depth > 0).  Return NULL if the depth is greater than the
 * number of children.
 */
const char *gensio_get_type(struct gensio *io, unsigned int depth);

/*
 * Close the gensio.  Note that the close operation is not complete
 * until close_done() is called.  This shuts down internal file
 * descriptors and such, but does not free the gensio.
 */
int gensio_close(struct gensio *io, gensio_done close_done, void *close_data);

/*
 * Like gensio_close, but blocks until the operation is complete.
 *
 * BE VERY CAREFUL WITH THIS FUNCTION.  Do not call it from a callback
 * because it waits until all operations on the gensio are done, and
 * they won't be done until the callback returns.  You will deadlock
 * if you do this.
 */
int gensio_close_s(struct gensio *io);

/*
 * Frees data assoicated with the gensio.  If it is open, the gensio is
 * closed.  Note that you should not call gensio_free() after gensio_close()
 * before the done callback is called.  The results are undefined.
 */
void gensio_free(struct gensio *io);

/*
 * Enable or disable data to be read from the network connection.
 */
void gensio_set_read_callback_enable(struct gensio *io, bool enabled);

/*
 * Enable the write_callback when data can be written on the
 * network connection.
 */
void gensio_set_write_callback_enable(struct gensio *io, bool enabled);

/*
 * Is the gensio a client or server?
 */
bool gensio_is_client(struct gensio *io);

/*
 * Is the genio reliable (won't loose data).
 */
bool gensio_is_reliable(struct gensio *io);

/*
 * Is the genio packet-oriented.  In a packet-oriented genio, if one
 * side writes a chunk of data, when the other side does a read it
 * will get the same chunk of data as a single unit assuming it's
 * buffer sizes are set properly.
 */
bool gensio_is_packet(struct gensio *io);

struct gensio_accepter;

/*
 * Got a new connection on the event.  data points to the new gensio.
 */
#define GENSIO_ACC_EVENT_NEW_CONNECTION	1

/*
 * The gensio accepter had an issue that wouldn't otherwise be reported
 * as an error return.  data points to a gensio_loginfo.
 */
#define GENSIO_ACC_EVENT_LOG		2
struct gensio_loginfo {
    enum gensio_log_levels level;
    char *str;
    va_list args;
};

/*
 * Report an event from the accepter to the user.
 *
 *  event - The event that occurred, of the type GENSIO_ACC_EVENT_xxx.
 *
 *  data - Specific data for the event, see the event description.
 *
 */
typedef int (*gensio_accepter_event)(struct gensio_accepter *accepter,
				     int event,
				     void *data);

/*
 * Callbacks for functions that don't give an error (close);
 */
typedef void (*gensio_acc_done)(struct gensio_accepter *acc, void *open_data);

/*
 * Return the type string for the gensio accepter (if depth is 0) or
 * one of its children (depth > 0).  Return NULL if the depth is
 * greater than the number of children.
 */
const char *gensio_acc_get_type(struct gensio_accepter *acc,
				unsigned int depth);
    
/*
 * Return the user data supplied to the allocator.
 */
void *gensio_acc_get_user_data(struct gensio_accepter *accepter);

/*
 * Set the user data.  May be called if the accepter is not enabled.
 */
void gensio_acc_set_user_data(struct gensio_accepter *accepter,
			      void *user_data);

/*
 * Set the callbacks and user data.  May be called if the accepter is
 * not enabled.
 */
void gensio_acc_set_callback(struct gensio_accepter *accepter,
			     gensio_accepter_event cb, void *user_data);

/*
 * An accepter is allocated without opening any sockets.  This
 * actually starts up the accepter, allocating the sockets and
 * such.  It is started with accepts enabled.
 *
 * Returns a standard errno on an error, zero otherwise.
 */
int gensio_acc_startup(struct gensio_accepter *accepter);

/*
 * Closes all sockets and disables everything.  shutdown_complete()
 * will be called if successful after the shutdown is complete, if it
 * is not NULL.
 *
 * Returns a EAGAIN if the accepter is already shut down, zero
 * otherwise.
 */
int gensio_acc_shutdown(struct gensio_accepter *accepter,
			gensio_acc_done shutdown_done, void *shutdown_data);

/*
 * Enable the accept callback when connections come in.
 */
void gensio_acc_set_accept_callback_enable(struct gensio_accepter *accepter,
					   bool enabled);

/*
 * Free the network accepter.  If the network accepter is started
 * up, this shuts it down first and shutdown_complete() is NOT called.
 */
void gensio_acc_free(struct gensio_accepter *accepter);

/*
 * Create a new connection from the given gensio accepter.  For TCP and
 * UDP, the addr is an addrinfo returned by getaddrinfo.  Note that
 * with this call, if connect_done is called with an error, the gensio
 * is *not* automatically freed.  You must do that.
 */
int gensio_acc_connect(struct gensio_accepter *accepter, void *addr,
		       gensio_done_err connect_done, void *cb_data,
		       struct gensio **new_io);
/*
 * Returns if the accepter requests exit on close.  A hack for stdio.
 */
bool gensio_acc_exit_on_close(struct gensio_accepter *accepter);

/*
 * Is the genio reliable (won't loose data).
 */
bool gensio_acc_is_reliable(struct gensio_accepter *accepter);

/*
 * Is the genio packet-oriented.  In a packet-oriented genio, if one
 * side writes a chunk of data, when the other side does a read it
 * will get the same chunk of data as a single unit assuming it's
 * buffer sizes are set properly.
 */
bool gensio_acc_is_packet(struct gensio_accepter *accepter);

/*
 * Convert a string representation of an I/O location into an accepter.
 */
int str_to_gensio_accepter(const char *str, struct gensio_os_funcs *o,
			   gensio_accepter_event cb, void *user_data,
			   struct gensio_accepter **accepter);

/*
 * Handler registered so that str_to_gensio_accepter can process an
 * accepter.  This is so users can create their own gensio accepter
 * types.
 */
typedef int (*str_to_gensio_acc_handler)(const char *str, char *args[],
					 struct gensio_os_funcs *o,
					 gensio_accepter_event cb,
					 void *user_data,
					 struct gensio_accepter **new_gensio);
/*
 * Add a gensio accepter to the set of registered gensio accepters.
 */
int register_gensio_accepter(struct gensio_os_funcs *o,
			     const char *name,
			     str_to_gensio_acc_handler handler);

/*
 * Allocators for the various gensio accepter types, compatible with
 * register_gensio_accepter().
 */
int str_to_tcp_gensio_accepter(const char *str, char *args[],
			       struct gensio_os_funcs *o,
			       gensio_accepter_event cb,
			       void *user_data,
			       struct gensio_accepter **new_acc);
int str_to_udp_gensio_accepter(const char *str, char *args[],
			       struct gensio_os_funcs *o,
			       gensio_accepter_event cb,
			       void *user_data,
			       struct gensio_accepter **new_acc);
int str_to_stdio_gensio_accepter(const char *str, char *args[],
				 struct gensio_os_funcs *o,
				 gensio_accepter_event cb,
				 void *user_data,
				 struct gensio_accepter **new_acc);
int str_to_ssl_gensio_accepter(const char *str, char *args[],
			       struct gensio_os_funcs *o,
			       gensio_accepter_event cb,
			       void *user_data,
			       struct gensio_accepter **new_acc);
int str_to_telnet_gensio_accepter(const char *str, char *args[],
				  struct gensio_os_funcs *o,
				  gensio_accepter_event cb,
				  void *user_data,
				  struct gensio_accepter **acc_gensio);

/*
 * Convert a string representation of an I/O location into a client
 * gensio.
 */
int str_to_gensio(const char *str,
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio **gensio);

/*
 * Allocators for the various gensio types, compatible with
 * register_gensio().
 */
int str_to_tcp_gensio(const char *str, char *args[],
		      struct gensio_os_funcs *o,
		      gensio_event cb, void *user_data,
		      struct gensio **new_gensio);
int str_to_udp_gensio(const char *str, char *args[],
		      struct gensio_os_funcs *o,
		      gensio_event cb, void *user_data,
		      struct gensio **new_gensio);
int str_to_stdio_gensio(const char *str, char *args[],
			struct gensio_os_funcs *o,
			gensio_event cb, void *user_data,
			struct gensio **new_gensio);
int str_to_ssl_gensio(const char *str, char *args[],
		      struct gensio_os_funcs *o,
		      gensio_event cb, void *user_data,
		      struct gensio **new_gensio);
int str_to_telnet_gensio(const char *str, char *args[],
			 struct gensio_os_funcs *o,
			 gensio_event cb, void *user_data,
			 struct gensio **new_gensio);
int str_to_termios_gensio(const char *str, char *args[],
			  struct gensio_os_funcs *o,
			  gensio_event cb, void *user_data,
			  struct gensio **new_gensio);
int str_to_ipmisol_gensio(const char *str, char *args[],
			  struct gensio_os_funcs *o,
			  gensio_event cb, void *user_data,
			  struct gensio **new_gensio);


/*
 * Allocators for accepters for different I/O types.
 */
int tcp_gensio_accepter_alloc(struct addrinfo *ai, char *args[],
			      struct gensio_os_funcs *o,
			      gensio_accepter_event cb,
			      void *user_data,
			      struct gensio_accepter **accepter);

int udp_gensio_accepter_alloc(struct addrinfo *ai, char *args[],
			      struct gensio_os_funcs *o,
			      gensio_accepter_event cb,
			      void *user_data,
			      struct gensio_accepter **accepter);

int stdio_gensio_accepter_alloc(char *args[],
				struct gensio_os_funcs *o,
				gensio_accepter_event cb,
				void *user_data,
				struct gensio_accepter **accepter);

int ssl_gensio_accepter_alloc(struct gensio_accepter *child, char *args[],
			      struct gensio_os_funcs *o,
			      gensio_accepter_event cb,
			      void *user_data,
			      struct gensio_accepter **accepter);

int telnet_gensio_accepter_alloc(struct gensio_accepter *child, char *args[],
				 struct gensio_os_funcs *o,
				 gensio_accepter_event cb,
				 void *user_data,
				 struct gensio_accepter **accepter);

/* Client allocators. */

/*
 * Create a TCP gensio for the given ai.
 */
int tcp_gensio_alloc(struct addrinfo *ai, char *args[],
		     struct gensio_os_funcs *o,
		     gensio_event cb, void *user_data,
		     struct gensio **new_gensio);

/*
 * Create a UDP gensio for the given ai.  It uses the first entry in
 * ai.
 */
int udp_gensio_alloc(struct addrinfo *ai, char *args[],
		     struct gensio_os_funcs *o,
		     gensio_event cb, void *user_data,
		     struct gensio **new_gensio);

/* Run a program (in argv[0]) and attach to it's stdio. */
int stdio_gensio_alloc(char *const argv[], char *args[],
		       struct gensio_os_funcs *o,
		       gensio_event cb, void *user_data,
		       struct gensio **new_gensio);

/*
 * Make an SSL connection over another gensio.
 */
int ssl_gensio_alloc(struct gensio *child, char *args[],
		     struct gensio_os_funcs *o,
		     gensio_event cb, void *user_data,
		     struct gensio **io);

int termios_gensio_alloc(const char *devname, char *args[],
			 struct gensio_os_funcs *o,
			 gensio_event cb, void *user_data,
			 struct gensio **io);

int telnet_gensio_alloc(struct gensio *child, char *args[],
			struct gensio_os_funcs *o,
			gensio_event cb, void *user_data,
			struct gensio **io);

int ipmisol_gensio_alloc(const char *devname, char *args[],
			 struct gensio_os_funcs *o,
			 gensio_event cb, void *user_data,
			 struct gensio **io);

/*
 * Compare two sockaddr structure and return TRUE if they are equal
 * and FALSE if not.  Only works for AF_INET4 and AF_INET6.
 * If compare_ports is false, then the port comparison is ignored.
 */
bool sockaddr_equal(const struct sockaddr *a1, socklen_t l1,
		    const struct sockaddr *a2, socklen_t l2,
		    bool compare_ports);

/*
 * Scan for a network port in the form:
 *
 *   [ipv4|ipv6,][tcp|udp,][<hostname>,]<port>
 *
 * If neither ipv4 nor ipv6 is specified, addresses for both are
 * returned.  If neither tcp nor udp is specified, tcp is assumed.
 * The hostname can be a resolvable hostname, an IPv4 octet, or an
 * IPv6 address.  If it is not supplied, inaddr_any is used.  In the
 * absence of a hostname specification, a wildcard address is used.
 * The mandatory second part is the port number or a service name.
 *
 * If the port is all zero, then is_port_set is set to true, false
 * otherwise.  If the address is UDP, is_dgram is set to true, false
 * otherwise.
 */
int scan_network_port(const char *str, struct addrinfo **ai, bool *is_dgram,
		      bool *is_port_set);

/*
 * This allows a global to disable uucp locking for everything.
 */
extern bool gensio_uucp_locking_enabled;

/*
 * Defaults provide a way to set overall or class-based defaults for
 * gensio values (or you can use it yourself to create your own defaults).
 *
 * For default values, each class will use gensio_get_default with
 * their class (termios, telnet, ssl, etc.).  If a value has been set
 * for its class, it will use that value.  If a value has been set with
 * class set to NULL (the "global" defaults") then the value will be
 * used from there.  Otherwise the code will use it's own internal value.
 *
 * The classonly parameter to getdefault means to not look in the global
 * defaults.
 *
 * If you use this for your own default, it is recommended that you use
 * your own "class" name and set "classonly" to true.
 *
 * int and bool are pretty self-explanatory.  Except that if you pass in
 * a non-NULL strval, the code will attempt to get the value from the
 * strval and will return NULL if the value is not valid.  If the value
 * is <minval or >maxval, ERANGE is returned.
 *
 * When setting a str, the value is copied.  The return value of the str
 * is the saved value, you should *not* free it.
 *
 * If it's a enum, setting the value you will pass in a string and a
 * table of possible values in "enum" (terminated with a NULL name).
 * The code will look up the string you pass in in the enums table,
 * and set the value to the integer value.  If the string is not in
 * the enums table, it will return EINVAL.  When you get the value, it
 * will return the value in intval.
 *
 * When getting the value, the type must match what is set in the set
 * call.  If the name is not found, ENOENT is returned.  If the type
 * does not match, then EINVAL is returned.  Note that if you save
 * a value as an enum, you can fetch it as an int.
 *
 * Setting the same default again will replace the old value.
 */
enum gensio_default_type {
    GENSIO_DEFAULT_INT,
    GENSIO_DEFAULT_BOOL,
    GENSIO_DEFAULT_ENUM,
    GENSIO_DEFAULT_STR
};

struct gensio_enum_val {
    char *name;
    int val;
};

int gensio_add_default(struct gensio_os_funcs *o,
		       const char *name,
		       enum gensio_default_type type,
		       const char *strval, int intval,
		       int minval, int maxval,
		       const struct gensio_enum_val *enums);

void gensio_reset_defaults(struct gensio_os_funcs *o);

int gensio_set_default(struct gensio_os_funcs *o,
		       const char *class, const char *name,
		       const char *strval, int intval);

int gensio_get_default(struct gensio_os_funcs *o,
		       const char *class, const char *name, bool classonly,
		       enum gensio_default_type type,
		       const char **strval, int *intval);

/*
 * This allows a global to disable uucp locking for everything.
 */
extern bool gensio_uucp_locking_enabled;

#ifdef __cplusplus
}
#endif

#endif /* GENSIO_H */
