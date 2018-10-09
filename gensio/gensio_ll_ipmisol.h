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

#ifndef GENSIO_LL_IPMISOL_H
#define GENSIO_LL_IPMISOL_H

#include <gensio/gensio_base.h>

#define GENSIO_SOL_LL_FREE	GENSIO_EVENT_USER_MIN
/*
 * op is client values from sergenio.h serial callbacks, plus
 * GENSIO_SOL_LL_FREE to tell the user that it can free its data.
 */
typedef void (*gensio_ll_ipmisol_cb)(void *handler_data, int op, void *data);

/* op is values from sergensio_class.h. */
typedef int (*gensio_ll_ipmisol_ops)(struct gensio_ll *ll, int op,
				     int val, char *buf,
				     void *done, void *cb_data);

int ipmisol_gensio_ll_alloc(struct gensio_os_funcs *o,
			    const char *devname,
			    gensio_ll_ipmisol_cb ser_cbs,
			    void *ser_cbs_data,
			    unsigned int max_read_size,
			    unsigned int max_write_size,
			    gensio_ll_ipmisol_ops *rops,
			    struct gensio_ll **rll);

#endif /* GENSIO_LL_IPMISOL_H */
