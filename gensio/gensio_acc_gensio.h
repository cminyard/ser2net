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

#ifndef GENSIO_ACC_GENSIO_H
#define GENSIO_ACC_GENSIO_H

#include <gensio/gensio_base.h>

struct gensio_gensio_acc_cbs {
    int (*connect_start)(void *acc_data, struct gensio *child,
			 struct gensio **new_net);
    int (*new_child)(void *acc_data, void **finish_data,
		     struct gensio_filter **filter);
    int (*finish_child)(void *acc_data, void *finish_data, struct gensio *io);
    void (*free)(void *acc_data);
};

int gensio_gensio_acceptor_alloc(struct gensio_acceptor *child,
				 struct gensio_os_funcs *o,
				 const char *typename,
				 gensio_acceptor_event cb, void *user_data,
				 const struct gensio_gensio_acc_cbs *acc_cbs,
				 void *acc_data,
				 struct gensio_acceptor **acceptor);

#endif /* GENSIO_ACC_GENSIO_H */
