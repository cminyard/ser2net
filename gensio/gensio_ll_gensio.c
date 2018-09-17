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

#include <errno.h>
#include <gensio/gensio_internal.h>
#include <gensio/gensio_base.h>

#include <assert.h>
#include <unistd.h>

struct gensio_ll_child {
    struct gensio_ll ll;
    struct gensio_os_funcs *o;
    struct gensio *child;
    const struct gensio_ll_callbacks *cbs;
    void *cb_data;

    gensio_ll_open_done open_done;
    void *open_data;

    gensio_ll_close_done close_done;
    void *close_data;
};

#define ll_to_child(v) container_of(v, struct gensio_ll_child, ll)

static void
child_set_callbacks(struct gensio_ll *ll,
		    const struct gensio_ll_callbacks *cbs,
		    void *cb_data)
{
    struct gensio_ll_child *cdata = ll_to_child(ll);

    cdata->cbs = cbs;
    cdata->cb_data = cb_data;
}

static int
child_write(struct gensio_ll *ll, unsigned int *rcount,
	    const unsigned char *buf, unsigned int buflen)
{
    struct gensio_ll_child *cdata = ll_to_child(ll);

    return gensio_write(cdata->child, rcount, buf, buflen);
}

static int
child_raddr_to_str(struct gensio_ll *ll, int *pos,
		   char *buf, unsigned int buflen)
{
    struct gensio_ll_child *cdata = ll_to_child(ll);

    return gensio_raddr_to_str(cdata->child, pos, buf, buflen);
}

static int
child_get_raddr(struct gensio_ll *ll,
		struct sockaddr *addr, socklen_t *addrlen)
{
    struct gensio_ll_child *cdata = ll_to_child(ll);

    return gensio_get_raddr(cdata->child, addr, addrlen);
}

static int
child_remote_id(struct gensio_ll *ll, int *id)
{
    struct gensio_ll_child *cdata = ll_to_child(ll);

    return gensio_remote_id(cdata->child, id);
}

static void
child_open_handler(struct gensio *io, int err, void *open_data)
{
    struct gensio_ll_child *cdata = open_data;

    cdata->open_done(cdata->cb_data, err, cdata->open_data);
}

static int
child_open(struct gensio_ll *ll, gensio_ll_open_done done, void *open_data)
{
    struct gensio_ll_child *cdata = ll_to_child(ll);
    int rv;

    cdata->open_done = done;
    cdata->open_data = open_data;
    rv = gensio_open(cdata->child, child_open_handler, cdata);
    if (rv == 0)
	rv = EINPROGRESS; /* gensios always call the open handler. */
    return rv;
}

static void
child_close_handler(struct gensio *io, void *close_data)
{
    struct gensio_ll_child *cdata = close_data;

    cdata->close_done(cdata->cb_data, cdata->close_data);
}

static int
child_close(struct gensio_ll *ll, gensio_ll_close_done done, void *close_data)
{
    struct gensio_ll_child *cdata = ll_to_child(ll);
    int rv;

    cdata->close_done = done;
    cdata->close_data = close_data;
    rv = gensio_close(cdata->child, child_close_handler, cdata);
    if (rv == 0)
	rv = EINPROGRESS; /* Close is always deferred. */
    return rv;
}

static void child_set_read_callback_enable(struct gensio_ll *ll, bool enabled)
{
    struct gensio_ll_child *cdata = ll_to_child(ll);

    gensio_set_read_callback_enable(cdata->child, enabled);
}

static void child_set_write_callback_enable(struct gensio_ll *ll, bool enabled)
{
    struct gensio_ll_child *cdata = ll_to_child(ll);

    gensio_set_write_callback_enable(cdata->child, enabled);
}

static void child_free(struct gensio_ll *ll)
{
    struct gensio_ll_child *cdata = ll_to_child(ll);

    gensio_free(cdata->child);
    cdata->o->free(cdata->o, cdata);
}

const static struct gensio_ll_ops child_ll_ops = {
    .set_callbacks = child_set_callbacks,
    .write = child_write,
    .raddr_to_str = child_raddr_to_str,
    .get_raddr = child_get_raddr,
    .remote_id = child_remote_id,
    .open = child_open,
    .close = child_close,
    .set_read_callback_enable = child_set_read_callback_enable,
    .set_write_callback_enable = child_set_write_callback_enable,
    .free = child_free
};

static unsigned int
child_read_callback(struct gensio *io, int readerr,
		    unsigned char *buf, unsigned int buflen,
		    unsigned int flags)
{
    struct gensio_ll_child *cdata = gensio_get_user_data(io);

    return cdata->cbs->read_callback(cdata->cb_data, readerr, buf, buflen);
}

static void
child_write_callback(struct gensio *io)
{
    struct gensio_ll_child *cdata = gensio_get_user_data(io);

    return cdata->cbs->write_callback(cdata->cb_data);
}

static void
child_urgent_callback(struct gensio *io)
{
    struct gensio_ll_child *cdata = gensio_get_user_data(io);

    return cdata->cbs->urgent_callback(cdata->cb_data);
}

static const struct gensio_callbacks gensio_ll_gensio_cbs = {
    .read_callback = child_read_callback,
    .write_callback = child_write_callback,
    .urgent_callback = child_urgent_callback
};

struct gensio_ll *
gensio_gensio_ll_alloc(struct gensio_os_funcs *o,
		       struct gensio *child)
{
    struct gensio_ll_child *cdata;

    cdata = o->zalloc(o, sizeof(*cdata));
    if (!cdata)
	return NULL;

    cdata->o = o;
    cdata->child = child;
    cdata->ll.ops = &child_ll_ops;

    gensio_set_callbacks(child, &gensio_ll_gensio_cbs, cdata);

    return &cdata->ll;
}
