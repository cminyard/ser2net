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

/*
 * This include file defines a network I/O abstraction to allow code
 * to use TCP, UDP, stdio, telnet, ssl, etc. without having to know
 * the underlying details.
 */

#ifndef SER2NET_GENIO_H
#define SER2NET_GENIO_H

#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

/*
 * Function pointers to provide OS functions.
 */

struct genio_lock;
struct genio_timer;
struct genio_runner;

struct genio_once {
    bool called;
};

struct genio_os_funcs {
    /* For use by the code doing the os function translation. */
    void *user_data;

    /* For use by other code. */
    void *other_data;

    /****** Memory Allocation ******/
    /* Return allocated and zeroed data.  Return NULL on error. */
    void *(*zalloc)(struct genio_os_funcs *f, unsigned int size);

    /* Free data allocated by zalloc. */
    void (*free)(struct genio_os_funcs *f, void *data);

    /****** Mutexes ******/
    /* Allocate a lock.  Return NULL on error. */
    struct genio_lock *(*alloc_lock)(struct genio_os_funcs *f);

    /* Free a lock allocated with alloc_lock. */
    void (*free_lock)(struct genio_lock *lock);

    /* Lock the lock. */
    void (*lock)(struct genio_lock *lock);

    /* Unlock the lock. */
    void (*unlock)(struct genio_lock *lock);

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
    int (*set_fd_handlers)(struct genio_os_funcs *f,
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
    void (*clear_fd_handlers)(struct genio_os_funcs *f, int fd);

    /*
     * Like the above, but does not call the cleared_handler function
     * when done.
     */
    void (*clear_fd_handlers_norpt)(struct genio_os_funcs *f, int fd);

    /*
     * Enable/disable the various handlers.  Note that if you disable
     * a handler, it may still be running in a callback, this does not
     * wait.
     */
    void (*set_read_handler)(struct genio_os_funcs *f, int fd, bool enable);
    void (*set_write_handler)(struct genio_os_funcs *f, int fd, bool enable);
    void (*set_except_handler)(struct genio_os_funcs *f, int fd, bool enable);

    /****** Timers ******/
    /*
     * Allocate a timer that calls the given handler when it goes
     * off.  Return NULL on error.
     */
    struct genio_timer *(*alloc_timer)(struct genio_os_funcs *f,
				       void (*handler)(struct genio_timer *t,
						       void *cb_data),
				       void *cb_data);

    /*
     * Free a timer allocated with alloc_timer.  The timer should not
     * be running.
     */
    void (*free_timer)(struct genio_timer *timer);

    /*
     * Start the timer running.  Returns EBUSY if the timer is already
     * running.
     */
    int (*start_timer)(struct genio_timer *timer, struct timeval *timeout);

    /*
     * Stop the timer.  Returns ETIMEDOUT if the timer is not running.
     * Note that the timer may still be running in a timeout handler
     * when this returns.
     */
    int (*stop_timer)(struct genio_timer *timer);

    /*
     * Like the above, but the done_handler is called when the timer is
     * completely stopped and no handler is running.  If ETIMEDOUT is
     * returned, the done_handler is not called.
     */
    int (*stop_timer_with_done)(struct genio_timer *timer,
				void (*done_handler)(struct genio_timer *t,
						     void *cb_data),
				void *cb_data);

    /****** Runners ******/
    /*
     * Allocate a runner.  Return NULL on error.  A runner runs things
     * at a base context.  This is useful for handling situations
     * where you need to run something outside of a lock or context,
     * you schedule the runner.
     */
    struct genio_runner *(*alloc_runner)(struct genio_os_funcs *f,
					 void (*handler)(struct genio_runner *r,
							 void *cb_data),
					 void *cb_data);

    /* Free a runner allocated with alloc_runner. */
    void (*free_runner)(struct genio_runner *runner);

    /*
     * Run a runner.  Return EBUSY if the runner is already scheduled
     * to run.
     */
    int (*run)(struct genio_runner *runner);

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
    struct genio_waiter *(*alloc_waiter)(struct genio_os_funcs *f);

    /* Free a waiter allocated by alloc_waiter. */
    void (*free_waiter)(struct genio_waiter *waiter);

    /*
     * Wait for a wakeup for up to the amount of time (relative) given
     * in timeout.  If timeout is NULL wait forever.  This return
     * ETIMEDOUT on a timeout.  It can return other errors.
     * The timeout is updated to the remaining time.
     */
    int (*wait)(struct genio_waiter *waiter, struct timeval *timeout);

    /*
     * Like wait, but return if a signal is received by the thread.
     * This is useful if you want to handle SIGINT or something like
     * that.
     */
    int (*wait_intr)(struct genio_waiter *waiter, struct timeval *timeout);

    /* Wake the given waiter. */
    void (*wake)(struct genio_waiter *waiter);

    /****** Misc ******/
    /*
     * Run the timers, fd handling, runners, etc.  This does one
     * operation and returns.  If timeout is non-NULL, if nothing
     * happens before the relative time given it will return.
     * The timeout is updated to the remaining time.
     */
    int (*service)(struct genio_os_funcs *f, struct timeval *timeout);

    /* Free this structure. */
    void (*free_funcs)(struct genio_os_funcs *f);

    /* Call this function once. */
    void (*call_once)(struct genio_os_funcs *f, struct genio_once *once,
		      void (*func)(void *cb_data), void *cb_data);

    void (*get_monotonic_time)(struct genio_os_funcs *f, struct timeval *time);
};

struct genio;

struct genio_callbacks {
    /*
     * Called when data is read from the I/O device.
     *
     * If readerr is zero, buf points to a data buffer and buflen is
     * the number of bytes available.
     *
     * If readerr is set, buf and buflen are undefined.  readerr is
     * a standard *nix errno.
     *
     * Note that you must disable read if you don't consume all
     * the bytes or in other situations where you don't want the
     * read handler called.
     *
     * Flags are per-type options, they generally don't matter except
     * for some specific situations.
     */
    unsigned int (*read_callback)(struct genio *io, int readerr,
				  unsigned char *buf, unsigned int buflen,
				  unsigned int flags);

    /* Flags for read callbacks. */

/* For stdin client genio, data is from stderr instead of stdout. */
#define GENIO_ERR_OUTPUT	1

    /*
     * Called when the user may write to the genio.
     */
    void (*write_callback)(struct genio *io);

    /*
     * Called when urgent data is available.  This should only be done
     * on TCP sockets.  Optional.
     */
    void (*urgent_callback)(struct genio *io);
};

/*
 * Set the callback data for the net.  This must be done in the
 * new_connection callback for the acceptor before any other operation
 * is done on the genio.  The only exception is that genio_close() may
 * be called with callbacks not set.  This function may be called
 * again if the genio is not enabled.
 */
void genio_set_callbacks(struct genio *io,
			 const struct genio_callbacks *cbs, void *user_data);

/*
 * Return the user data supplied in genio_set_callbacks().
 */
void *genio_get_user_data(struct genio *io);

/*
 * Set the user data.  May be called if the genio is not enabled.
 */
void genio_set_user_data(struct genio *io, void *user_data);

/*
 * Write data to the genio.  This should only be called from the
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
int genio_write(struct genio *io, unsigned int *count,
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
int genio_raddr_to_str(struct genio *io, int *pos,
		       char *buf, unsigned int buflen);

/*
 * Return the remote address for the connection.  addrlen must be
 * set to the size of addr and will be updated to the actual size.
 */
int genio_get_raddr(struct genio *io,
		    struct sockaddr *addr, socklen_t *addrlen);

/*
 * Returns an id for the remote end.  For stdio clients this is the
 * pid.  For sergenio_termios this is the fd.  It returns an error
 * for all others.
 */
int genio_remote_id(struct genio *io, int *id);

/*
 * Open the genio.  genios recevied from an acceptor are open upon
 * receipt, but client genios are started closed and need to be opened
 * before use.  If no error is returned, the genio will be open when
 * the open_done callback is called.
 */
int genio_open(struct genio *io,
	       void (*open_done)(struct genio *io, int err, void *open_data),
	       void *open_data);

/*
 * Like genio_open(), but waits for the open to complete.
 */
int genio_open_s(struct genio *io, struct genio_os_funcs *o);

/*
 * Close the genio.  Note that the close operation is not complete
 * until close_done() is called.  This shuts down internal file
 * descriptors and such, but does not free the genio.
 */
int genio_close(struct genio *io,
		void (*close_done)(struct genio *io, void *close_data),
		void *close_data);

/*
 * Frees data assoicated with the genio.  If it is open, the genio is
 * closed.  Note that you should not call genio_free() after genio_close()
 * before the done callback is called.  The results are undefined.
 */
void genio_free(struct genio *io);

/*
 * Enable or disable data to be read from the network connection.
 */
void genio_set_read_callback_enable(struct genio *io, bool enabled);

/*
 * Enable the write_callback when data can be written on the
 * network connection.
 */
void genio_set_write_callback_enable(struct genio *io, bool enabled);

/*
 * Is the genio a client or server?
 */
bool genio_is_client(struct genio *io);

struct genio_acceptor;

struct genio_acceptor_callbacks {
    /*
     * A new connection for the acceptor is in io.
     */
    void (*new_connection)(struct genio_acceptor *acceptor, struct genio *io);
};

/*
 * Return the user data supplied to the allocator.
 */
void *genio_acc_get_user_data(struct genio_acceptor *acceptor);

/*
 * Set the user data.  May be called if the acceptor is not enabled.
 */
void genio_acc_set_user_data(struct genio_acceptor *acceptor,
			     void *user_data);

/*
 * Set the callbacks and user data.  May be called if the acceptor is
 * not enabled.
 */
void genio_acc_set_callbacks(struct genio_acceptor *acceptor,
			     struct genio_acceptor_callbacks *cbs,
			     void *user_data);

/*
 * An acceptor is allocated without opening any sockets.  This
 * actually starts up the acceptor, allocating the sockets and
 * such.  It is started with accepts enabled.
 *
 * Returns a standard errno on an error, zero otherwise.
 */
int genio_acc_startup(struct genio_acceptor *acceptor);

/*
 * Closes all sockets and disables everything.  shutdown_complete()
 * will be called if successful after the shutdown is complete, if it
 * is not NULL.
 *
 * Returns a EAGAIN if the acceptor is already shut down, zero
 * otherwise.
 */
int genio_acc_shutdown(struct genio_acceptor *acceptor,
		       void (*shutdown_done)(struct genio_acceptor *acceptor,
					     void *shutdown_data),
		       void *shutdown_data);

/*
 * Enable the accept callback when connections come in.
 */
void genio_acc_set_accept_callback_enable(struct genio_acceptor *acceptor,
					  bool enabled);

/*
 * Free the network acceptor.  If the network acceptor is started
 * up, this shuts it down first and shutdown_complete() is NOT called.
 */
void genio_acc_free(struct genio_acceptor *acceptor);

/*
 * Create a new connection from the given genio acceptor.  For TCP and
 * UDP, the addr is an addrinfo returned by getaddrinfo.  Note that
 * with this call, if connect_done is called with an error, the genio
 * is *not* automatically freed.  You must do that.
 */
int genio_acc_connect(struct genio_acceptor *acceptor, void *addr,
		      void (*connect_done)(struct genio *io, int err,
					   void *cb_data),
		      void *cb_data, struct genio **new_io);
/*
 * Returns if the acceptor requests exit on close.  A hack for stdio.
 */
bool genio_acc_exit_on_close(struct genio_acceptor *acceptor);

/*
 * Convert a string representation of a network address into a network
 * acceptor.  max_read_size is the internal read buffer size for the
 * connections.
 */
int str_to_genio_acceptor(const char *str, struct genio_os_funcs *o,
			  unsigned int max_read_size,
			  const struct genio_acceptor_callbacks *cbs,
			  void *user_data,
			  struct genio_acceptor **acceptor);

/*
 * Convert a string representation of a network address into a
 * client genio.
 */
int str_to_genio(const char *str,
		 struct genio_os_funcs *o,
		 unsigned int max_read_size,
		 const struct genio_callbacks *cbs,
		 void *user_data,
		 struct genio **genio);

/*
 * Allocators for different I/O types.
 */
int tcp_genio_acceptor_alloc(const char *name,
			     struct genio_os_funcs *o,
			     struct addrinfo *ai,
			     unsigned int max_read_size,
			     const struct genio_acceptor_callbacks *cbs,
			     void *user_data,
			     struct genio_acceptor **acceptor);
int udp_genio_acceptor_alloc(const char *name,
			     struct genio_os_funcs *o,
			     struct addrinfo *ai,
			     unsigned int max_read_size,
			     const struct genio_acceptor_callbacks *cbs,
			     void *user_data,
			     struct genio_acceptor **acceptor);
int stdio_genio_acceptor_alloc(struct genio_os_funcs *o,
			       unsigned int max_read_size,
			       const struct genio_acceptor_callbacks *cbs,
			       void *user_data,
			       struct genio_acceptor **acceptor);
int ssl_genio_acceptor_alloc(const char *name,
			     char *args[],
			     struct genio_os_funcs *o,
			     struct genio_acceptor *child,
			     unsigned int max_read_size,
			     const struct genio_acceptor_callbacks *cbs,
			     void *user_data,
			     struct genio_acceptor **acceptor);

/* Client allocators. */

/*
 * Create a TCP genio for the given ai.
 */
int tcp_genio_alloc(struct addrinfo *ai,
		    struct genio_os_funcs *o,
		    unsigned int max_read_size,
		    const struct genio_callbacks *cbs,
		    void *user_data,
		    struct genio **new_genio);

/*
 * Create a UDP genio for the given ai.  It uses the first entry in
 * ai.
 */
int udp_genio_alloc(struct addrinfo *ai,
		    struct genio_os_funcs *o,
		    unsigned int max_read_size,
		    const struct genio_callbacks *cbs,
		    void *user_data,
		    struct genio **new_genio);

/* Run a program (in argv[0]) and attach to it's stdio. */
int stdio_genio_alloc(char *const argv[],
		      struct genio_os_funcs *o,
		      unsigned int max_read_size,
		      const struct genio_callbacks *cbs,
		      void *user_data,
		      struct genio **new_genio);

/*
 * Make an SSL connection over another genio.
 */
int ssl_genio_alloc(struct genio *child,
		    char *args[],
		    struct genio_os_funcs *o,
		    unsigned int max_read_size,
		    const struct genio_callbacks *cbs, void *user_data,
		    struct genio **io);


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
 * Helper function for dealing with buffers writing to genio.
 */
int genio_buffer_do_write(void *cb_data,
			  void  *buf, size_t buflen, size_t *written);

#endif /* SER2NET_GENIO_H */
