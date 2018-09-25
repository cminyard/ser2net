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

#ifndef GENSIO_FILTER_SSL_H
#define GENSIO_FILTER_SSL_H

#include <gensio/gensio_base.h>

int gensio_ssl_filter_alloc(struct gensio_os_funcs *o, char *args[],
			    struct gensio_filter **rfilter);

int gensio_ssl_server_filter_alloc(struct gensio_os_funcs *o,
				   char *keyfile,
				   char *certfile,
				   char *CAfilepath,
				   unsigned int max_read_size,
				   unsigned int max_write_size,
				   struct gensio_filter **rfilter);

#endif /* GENSIO_FILTER_SSL_H */
