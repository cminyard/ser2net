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

#ifndef SER2NET_NETIO_INTERNAL_H
#define SER2NET_NETIO_INTERNAL_H

#include <stddef.h>
#include "netio.h"
#include "utils/utils.h"

enum netio_type {
    NETIO_TYPE_TCP,
    NETIO_TYPE_UDP,
    NETIO_TYPE_STDIO
};

struct netio_functions {
    int (*write)(struct netio *net, int *count,
		 const void *buf, unsigned int buflen);

    int (*raddr_to_str)(struct netio *net, int *pos,
			char *buf, unsigned int buflen);

    socklen_t (*get_raddr)(struct netio *net,
			   struct sockaddr *addr, socklen_t addrlen);

    void (*close)(struct netio *net);

    void (*set_read_callback_enable)(struct netio *net, bool enabled);

    void (*set_write_callback_enable)(struct netio *net, bool enabled);
};

/*
 * This structure represents a network connection, return from the
 * acceptor callback in netio_acceptor.
 */
struct netio {
    void *user_data;
    const struct netio_callbacks *cbs;

    const struct netio_functions *funcs;

    enum netio_type type;
};

struct netio_acceptor_functions {
    int (*startup)(struct netio_acceptor *acceptor);

    int (*shutdown)(struct netio_acceptor *acceptor);

    void (*set_accept_callback_enable)(struct netio_acceptor *acceptor,
				       bool enabled);

    void (*free)(struct netio_acceptor *acceptor);
};

/*
 * This function handles accepts on network I/O code and calls back the
 * user for the new connection.
 */
struct netio_acceptor {
    void *user_data;
    const struct netio_acceptor_callbacks *cbs;

    const struct netio_acceptor_functions *funcs;

    enum netio_type type;
};

#define container_of(ptr, type, member) \
    ((type *)(((char *) ptr) - offsetof(type, member)))

int netio_append_remaddr(struct port_remaddr **list, const char *str,
			 bool do_dgram);
bool netio_check_remaddr(struct port_remaddr *list,
			 struct sockaddr *addr, socklen_t len);

#endif /* SER2NET_NETIO_INTERNAL_H */
