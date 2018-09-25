/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
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

#ifndef GENSIO_LL_FD_H
#define GENSIO_LL_FD_H

#include <gensio/gensio_base.h>

enum gensio_ll_close_state {
    GENSIO_LL_CLOSE_STATE_START,
    GENSIO_LL_CLOSE_STATE_DONE
};

struct gensio_fd_ll_ops {
    int (*sub_open)(void *handler_data,
		    int (**check_open)(void *handler_data, int fd),
		    int (**retry_open)(void *handler_data, int *fd),
		    int *fd);

    int (*raddr_to_str)(void *handler_data, unsigned int *pos,
			char *buf, unsigned int buflen);

    int (*get_raddr)(void *handler_data, void *addr, unsigned int *addrlen);

    int (*remote_id)(void *handler_data, int *id);

    /*
     * When GENSIO_LL_CLOSE_STATE_START, timeout will be NULL and the
     * return value is ignored.  Return 0.  When
     * GENSIO_LL_CLOSE_STATE_DONE, return EAGAIN to get called again
     * after next_timeout milliseconds, zero to continue the close.
     */
    int (*check_close)(void *handler_data, enum gensio_ll_close_state state,
		       struct timeval *next_timeout);

    void (*free)(void *handler_data);
};

struct gensio_ll *fd_gensio_ll_alloc(struct gensio_os_funcs *o,
				     int fd,
				     const struct gensio_fd_ll_ops *ops,
				     void *handler_data,
				     unsigned int max_read_size);


#endif /* GENSIO_LL_FD_H */
