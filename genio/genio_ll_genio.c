/*
 *  genio - A library for abstracting stream I/O
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
#include "genio_internal.h"
#include "genio_base.h"

#include <assert.h>
#include <unistd.h>

struct genio_ll_child {
    struct genio_ll ll;
    struct genio_os_funcs *o;
    struct genio *child;
    const struct genio_ll_callbacks *cbs;
    void *cb_data;

    genio_ll_open_done open_done;
    void *open_data;

    genio_ll_close_done close_done;
    void *close_data;
};

#define ll_to_child(v) container_of(v, struct genio_ll_child, ll)

static void
child_set_callbacks(struct genio_ll *ll,
		    const struct genio_ll_callbacks *cbs,
		    void *cb_data)
{
    struct genio_ll_child *cdata = ll_to_child(ll);

    cdata->cbs = cbs;
    cdata->cb_data = cb_data;
}

static int
child_write(struct genio_ll *ll, unsigned int *rcount,
	    const unsigned char *buf, unsigned int buflen)
{
    struct genio_ll_child *cdata = ll_to_child(ll);

    return genio_write(cdata->child, rcount, buf, buflen);
}

static int
child_raddr_to_str(struct genio_ll *ll, int *pos,
		   char *buf, unsigned int buflen)
{
    struct genio_ll_child *cdata = ll_to_child(ll);

    return genio_raddr_to_str(cdata->child, pos, buf, buflen);
}

static int
child_get_raddr(struct genio_ll *ll,
		struct sockaddr *addr, socklen_t *addrlen)
{
    struct genio_ll_child *cdata = ll_to_child(ll);

    return genio_get_raddr(cdata->child, addr, addrlen);
}

static int
child_remote_id(struct genio_ll *ll, int *id)
{
    struct genio_ll_child *cdata = ll_to_child(ll);

    return genio_remote_id(cdata->child, id);
}

static void
child_open_handler(struct genio *io, int err, void *open_data)
{
    struct genio_ll_child *cdata = open_data;

    cdata->open_done(cdata->cb_data, err, cdata->open_data);
}

static int
child_open(struct genio_ll *ll, genio_ll_open_done done, void *open_data)
{
    struct genio_ll_child *cdata = ll_to_child(ll);
    int rv;

    cdata->open_done = done;
    cdata->open_data = open_data;
    rv = genio_open(cdata->child, child_open_handler, cdata);
    if (rv == 0)
	rv = EINPROGRESS; /* genios always call the open handler. */
    return rv;
}

static void
child_close_handler(struct genio *io, void *close_data)
{
    struct genio_ll_child *cdata = close_data;

    cdata->close_done(cdata->cb_data, cdata->close_data);
}

static int
child_close(struct genio_ll *ll, genio_ll_close_done done, void *close_data)
{
    struct genio_ll_child *cdata = ll_to_child(ll);
    int rv;

    cdata->close_done = done;
    cdata->close_data = close_data;
    rv = genio_close(cdata->child, child_close_handler, cdata);
    if (rv == 0)
	rv = EINPROGRESS; /* Close is always deferred. */
    return rv;
}

static void child_set_read_callback_enable(struct genio_ll *ll, bool enabled)
{
    struct genio_ll_child *cdata = ll_to_child(ll);

    genio_set_read_callback_enable(cdata->child, enabled);
}

static void child_set_write_callback_enable(struct genio_ll *ll, bool enabled)
{
    struct genio_ll_child *cdata = ll_to_child(ll);

    genio_set_write_callback_enable(cdata->child, enabled);
}

static void child_free(struct genio_ll *ll)
{
    struct genio_ll_child *cdata = ll_to_child(ll);

    genio_free(cdata->child);
    cdata->o->free(cdata->o, cdata);
}

const static struct genio_ll_ops child_ll_ops = {
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
child_read_callback(struct genio *io, int readerr,
		    unsigned char *buf, unsigned int buflen,
		    unsigned int flags)
{
    struct genio_ll_child *cdata = genio_get_user_data(io);

    return cdata->cbs->read_callback(cdata->cb_data, readerr, buf, buflen);
}

static void
child_write_callback(struct genio *io)
{
    struct genio_ll_child *cdata = genio_get_user_data(io);

    return cdata->cbs->write_callback(cdata->cb_data);
}

static void
child_urgent_callback(struct genio *io)
{
    struct genio_ll_child *cdata = genio_get_user_data(io);

    return cdata->cbs->urgent_callback(cdata->cb_data);
}

static const struct genio_callbacks genio_ll_genio_cbs = {
    .read_callback = child_read_callback,
    .write_callback = child_write_callback,
    .urgent_callback = child_urgent_callback
};

struct genio_ll *
genio_genio_ll_alloc(struct genio_os_funcs *o,
		     struct genio *child)
{
    struct genio_ll_child *cdata;

    cdata = o->zalloc(o, sizeof(*cdata));
    if (!cdata)
	return NULL;

    cdata->o = o;
    cdata->child = child;
    cdata->ll.ops = &child_ll_ops;

    genio_set_callbacks(child, &genio_ll_genio_cbs, cdata);

    return &cdata->ll;
}
