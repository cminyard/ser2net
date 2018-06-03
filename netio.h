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

#ifndef SER2NET_NETIO_H
#define SER2NET_NETIO_H

#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

struct netio {
    /*
     * Set by the user for actions from the network port.
     */
    void *user_data;
    /* If readerr is set, buf and buflen are undefined.  Return the
       number of bytes consumed.  If the full number of bytes is not
       consumed, read will automatically be disabled.  Read is also
       disabled if an error is reported. */
    unsigned int (*read_callback)(struct netio *net, int readerr,
				  unsigned char *buf, unsigned int buflen);
    void (*write_callback)(struct netio *net);
    void (*urgent_callback)(struct netio *net);
    void (*close_done)(struct netio *net);

    /*
     * Set by the network port for calling by the user.
     */
    void *internal_data;

    /* Return errno, or 0 on success. */
    int (*write)(struct netio *net, int *count,
		 const void *buf, unsigned int buflen);

    /*
     * Convert the remote address to a string.  Returns an errno on an
     * error, but will also add a string error to the buffer.  pos is
     * the current position in the buffer to write the string, it it
     * updated to the new end of the string.  If pos is NULL, start at zero.
     */
    int (*raddr_to_str)(struct netio *net, int *pos,
			char *buf, unsigned int buflen);

    void (*close)(struct netio *net);
    void (*set_read_callback_enable)(struct netio *net, bool enabled);
    void (*set_write_callback_enable)(struct netio *net, bool enabled);
};

struct netio_acceptor {
    void *user_data;
    void (*new_connection)(struct netio_acceptor *acceptor, struct netio *net);

    bool exit_on_close;

    void *internal_data;
    int (*add_remaddr)(struct netio_acceptor *acceptor, const char *str);
    /* Acceptor is allocated without opening any sockets.  This does that
       operation. */
    int (*startup)(struct netio_acceptor *acceptor);
    /* Blocks until shutdown is complete and all callbacks have returned. */
    int (*shutdown)(struct netio_acceptor *acceptor);
    void (*set_accept_callback_enable)(struct netio_acceptor *acceptor,
				       bool enabled);
    void (*free)(struct netio_acceptor *acceptor);
};

int str_to_netio_acceptor(const char *str, unsigned int max_read_size,
			  struct netio_acceptor **acceptor);

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

