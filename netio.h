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
 * to use TCP, UDP, stdio, etc. without having to know the underlying
 * details.
 */

#ifndef SER2NET_NETIO_H
#define SER2NET_NETIO_H

#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

/*
 * This structure represents a network connection, return from the
 * acceptor callback in netio_acceptor.
 */
struct netio {
    /*
     * This is available to the user of this function, the netio code
     * does not touch it.
     */
    void *user_data;

    /*
     * The following functions must be set up by the netio user in the
     * accept callback.  After returning from the accept callback, these
     * may be called at any time until close_done() is called.
     */

    /*
     * Called when data is read from the I/O device.
     *
     * If readerr is zero, buf points to a data buffer and buflen is
     * the number of bytes available.
     *
     * If readerr is set, buf and buflen are undefined.  readerr is
     * a standard *nix errno.
     *
     * The user must return the number of bytes consumed.  If the full
     * number of bytes is not consumed, read will automatically be
     * disabled.  Read is also disabled if an error is reported.
     */
    unsigned int (*read_callback)(struct netio *net, int readerr,
				  unsigned char *buf, unsigned int buflen);

    /*
     * Called when the user may write to the netio.
     */
    void (*write_callback)(struct netio *net);

    /*
     * Called when urgent data is available.  This should only be done
     * on TCP sockets.
     */
    void (*urgent_callback)(struct netio *net);

    /*
     * Called when a close operation completes.  May be NULL.
     */
    void (*close_done)(struct netio *net);


    /*
     * The following functions are set by the netio code for use by
     * the user.  DO NOT MODIFY THESE!
     */

    int (*write)(struct netio *net, int *count,
		 const void *buf, unsigned int buflen);

    int (*raddr_to_str)(struct netio *net, int *pos,
			char *buf, unsigned int buflen);

    void (*close)(struct netio *net);

    void (*set_read_callback_enable)(struct netio *net, bool enabled);

    void (*set_write_callback_enable)(struct netio *net, bool enabled);

    /*
     * Internal to the netio code.  The user should *NOT* touch this.
     */
    void *internal_data;
};

/*
 * Write data to the netio.  This should only be called from the
 * write callback for most general usage.  Writes buflen bytes
 * from buf.
 *
 * Returns errno on error, or 0 on success.  This will NEVER return
 * EAGAIN, EWOULDBLOCK, or EINTR.  Those are handled internally.
 *
 * On a non-error return, count is set to the number of bytes
 * consumed by the write call, with may be less than buflen.  If
 * it is less than buflen, then not all the data was written.
 * Note that count may be set to zero.  This can happen on an
 * EAGAIN type situation.
 */
int netio_write(struct netio *net, int *count,
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
int netio_raddr_to_str(struct netio *net, int *pos,
		       char *buf, unsigned int buflen);

/*
 * Close the netio.  Note that the close operation is not complete
 * until close_done() is called.
 */
void netio_close(struct netio *net);

/*
 * Enable or disable data to be read from the network connection.
 */
void netio_set_read_callback_enable(struct netio *net, bool enabled);

/*
 * Enable the write_callback when data can be written on the
 * network connection.
 */
void netio_set_write_callback_enable(struct netio *net, bool enabled);


/*
 * This function handles accepts on network I/O code and calls back the
 * user for the new connection.
 */
struct netio_acceptor {
    /*
     * This is available to the user of this function, the netio code
     * does not touch it.
     */
    void *user_data;

    /*
     * The following functions must be set up by the netio user before
     * calling startup().
     */

    /*
     * A new net connection for the acceptor is in net.
     */
    void (*new_connection)(struct netio_acceptor *acceptor, struct netio *net);

    /*
     * The shutdown operation is complete.  May be NULL.
     */
    void (*shutdown_done)(struct netio_acceptor *acceptor);

    /*
     * FIXME - this is set by the stdio netio so that ser2net knows to
     * close when the connection is complete.  This should be done some
     * other way.
     */
    bool exit_on_close;

    /*
     * The following functions are set by the netio code for use by
     * the user.  DO NOT MODIFY THESE!
     */

    int (*add_remaddr)(struct netio_acceptor *acceptor, const char *str);

    int (*startup)(struct netio_acceptor *acceptor);

    int (*shutdown)(struct netio_acceptor *acceptor);

    void (*set_accept_callback_enable)(struct netio_acceptor *acceptor,
				       bool enabled);

    void (*free)(struct netio_acceptor *acceptor);

    /*
     * Internal to the netio code.  The user should *NOT* touch this.
     */
    void *internal_data;
};

/*
 * Add an allowed remote address to the acceptor.  If no remote
 * addresses are added, connections are accepted from anywhere.
 * Otherwise, only connections that match the given remote address
 * are allowed.  If no port is given in the string, then any port
 * from the remote address is allowed.  Otherwise only the given
 * port is allowed.
 *
 * Returns a standard errno on an error, zero otherwise.
 */
int netio_acc_add_remaddr(struct netio_acceptor *acceptor, const char *str);

/*
 * An acceptor is allocated without opening any sockets.  This
 * actually starts up the acceptor, allocating the sockets and
 * such.  It is started with accepts enabled.
 *
 * Returns a standard errno on an error, zero otherwise.
 */
int netio_acc_startup(struct netio_acceptor *acceptor);

/*
 * Closes all sockets and disables everything.  shutdown_complete()
 * will be called if successful after the shutdown is complete.
 *
 * Returns a EAGAIN if the acceptor is already shut down, zero
 * otherwise.
 */
int netio_acc_shutdown(struct netio_acceptor *acceptor);

/*
 * Enable the accept callback when connections come in.
 */
void netio_acc_set_accept_callback_enable(struct netio_acceptor *acceptor,
					  bool enabled);

/*
 * Free the network acceptor.  If the network acceptor is started
 * up, this shuts it down first and shutdown_complete() is NOT called.
 */
void netio_acc_free(struct netio_acceptor *acceptor);

/*
 * Convert a string representation of a network address into a network
 * acceptor.  max_read_size is the internal read buffer size for the
 * connections.
 */
int str_to_netio_acceptor(const char *str, unsigned int max_read_size,
			  struct netio_acceptor **acceptor);

/*
 * Allocators for different I/O types.
 */
int tcp_netio_acceptor_alloc(const char *name,
			     struct addrinfo *ai,
			     unsigned int max_read_size,
			     struct netio_acceptor **acceptor);
int udp_netio_acceptor_alloc(const char *name,
			     struct addrinfo *ai,
			     unsigned int max_read_size,
			     struct netio_acceptor **acceptor);
int stdio_netio_acceptor_alloc(unsigned int max_read_size,
			       struct netio_acceptor **acceptor);

#endif /* SER2NET_NETIO_H */

