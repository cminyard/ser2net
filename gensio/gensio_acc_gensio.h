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

/*
 * Create the new parent gensio over the child, for the "connect" function
 * of the genio.  This creates a client gensio.
 *
 * child => data1
 * *new_io => data2
 */
#define GENSIO_GENSIO_ACC_CONNECT_START		1

/*
 * A new child gensio was created, create a filter for it's parent
 * gensio.  Whatever you return in finish_data will be passed in to
 * finish parent when that is called.
 *
 * *finish_data => data1
 * *new_filter => data2
 */
#define GENSIO_GENSIO_ACC_NEW_CHILD		2

/*
 * The parent gensio has been created for the child, finish things up.
 *
 * finish_data => data1
 * new_parent => data2
 */
#define GENSIO_GENSIO_ACC_FINISH_PARENT		3

/*
 * Free the data.
 */
#define GENSIO_GENSIO_ACC_FREE			4

typedef int (*gensio_gensio_acc_cb)(void *acc_data, int op,
				    void *data1, void *data2);

int gensio_gensio_accepter_alloc(struct gensio_accepter *child,
				 struct gensio_os_funcs *o,
				 const char *typename,
				 gensio_accepter_event cb, void *user_data,
				 gensio_gensio_acc_cb acc_cb,
				 void *acc_data,
				 struct gensio_accepter **accepter);

#endif /* GENSIO_ACC_GENSIO_H */
