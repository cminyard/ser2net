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

#ifndef GENSIO_FILTER_TELNET_H
#define GENSIO_FILTER_TELNET_H

#include <gensio/gensio_base.h>

struct gensio_telnet_filter_callbacks {
    void (*got_sync)(void *handler_data);
    void (*got_cmd)(void *handler_data, unsigned char cmd);
    int (*com_port_will_do)(void *handler_data, unsigned char cmd);
    void (*com_port_cmd)(void *handler_data, const unsigned char *option,
			 unsigned int len);
    void (*timeout)(void *handler_data);
    void (*free)(void *handler_data);
};

struct gensio_telnet_filter_rops {
    void (*send_option)(struct gensio_filter *filter,
			const unsigned char *buf, unsigned int len);
    void (*send_cmd)(struct gensio_filter *filter,
		     const unsigned char *buf, unsigned int len);
    void (*start_timer)(struct gensio_filter *filter, struct timeval *timeout);
};

int gensio_telnet_filter_alloc(struct gensio_os_funcs *o, char *args[],
			       const struct gensio_telnet_filter_callbacks *cbs,
			       void *handler_data,
			       const struct gensio_telnet_filter_rops **rops,
			       struct gensio_filter **rfilter);

int gensio_telnet_server_filter_alloc(
		     struct gensio_os_funcs *o,
		     bool allow_rfc2217,
		     unsigned int max_read_size,
		     unsigned int max_write_size,
		     const struct gensio_telnet_filter_callbacks *cbs,
		     void *handler_data,
		     const struct gensio_telnet_filter_rops **rops,
		     struct gensio_filter **rfilter);

#endif /* GENSIO_FILTER_TELNET_H */
