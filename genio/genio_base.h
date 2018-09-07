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

#ifndef GENIO_BASE_H
#define GENIO_BASE_H

#include <genio/genio.h>

struct genio_filter {
    const struct genio_filter_ops *ops;
};

typedef int (*genio_ul_filter_data_handler)(void *cb_data,
					    unsigned int *rcount,
					    const unsigned char *buf,
					    unsigned int buflen);

typedef int (*genio_ll_filter_data_handler)(void *cb_data,
					    unsigned int *rcount,
					    unsigned char *buf,
					    unsigned int buflen);

struct genio_filter_ops {
    /* Is there data ready to be read from the top of the filter? */
    bool (*ul_read_pending)(struct genio_filter *filter);

    /* Is there data ready to be written out of the bottom of the filter? */
    bool (*ll_write_pending)(struct genio_filter *filter);

    /* Is the filter expecting that data should come in the bottom? */
    bool (*ll_read_needed)(struct genio_filter *filter);

    /*
     * Provides a way to verify keys and such after the open is complete.
     * Returning an error will abort the connection before the open is
     * returned.
     */
    int (*check_open_done)(struct genio_filter *filter);

    /*
     * Attempt to start a connection on the filter.  Returns 0 on
     * immediate success.  Returns EINPROGRESS if the connect attempt
     * should be retried.
     */
    int (*try_connect)(struct genio_filter *filter);

    /*
     * Attempt to disconnect the filter.  Returns 0 on immediate
     * success.  Returns EINPROGRESS if the connect attempt should be
     * retried.
     */
    int (*try_disconnect)(struct genio_filter *filter);

    /*
     * Write data into the top of the filter.  If no data is provided
     * (buf is NULL) then this will just attempt to write any pending
     * data out of the bottom of the filter into the handler.
     */
    int (*ul_write)(struct genio_filter *filter,
		    genio_ul_filter_data_handler handler, void *cb_data,
		    unsigned int *rcount,
		    const unsigned char *buf, unsigned int buflen);

    /*
     * Write data into the bottom of the filter.  If no data is
     * provided (buf is NULL) then this will just attempt to write any
     * pending data out of the top of the filter into the handler.
     */
    int (*ll_write)(struct genio_filter *filter,
		   genio_ll_filter_data_handler handler, void *cb_data,
		   unsigned int *rcount,
		   unsigned char *buf, unsigned int buflen);

    /* Handle urgent data. */
    void (*ll_urgent)(struct genio_filter *filter);

    int (*setup)(struct genio_filter *filter);
    void (*cleanup)(struct genio_filter *filter);
    void (*free)(struct genio_filter *filter);
};

struct genio_ll {
    const struct genio_ll_ops *ops;
};

typedef void (*genio_ll_open_done)(void *cb_data, int err, void *open_data);
typedef void (*genio_ll_close_done)(void *cb_data, void *close_data);

struct genio_ll_callbacks {
    unsigned int (*read_callback)(void *cb_data, int readerr,
				   unsigned char *buf,
				   unsigned int buflen);
    void (*write_callback)(void *cb_data);
    void (*urgent_callback)(void *cb_data);
};

struct genio_ll_ops {
    void (*set_callbacks)(struct genio_ll *ll,
			  const struct genio_ll_callbacks *cbs,
			  void *cb_data);

    int (*write)(struct genio_ll *ll, unsigned int *rcount,
		 const unsigned char *buf, unsigned int buflen);

    int (*raddr_to_str)(struct genio_ll *ll, int *pos,
			char *buf, unsigned int buflen);

    int (*get_raddr)(struct genio_ll *ll,
		     struct sockaddr *addr, socklen_t addrlen);

    /*
     * Returns 0 if the open was immediate, EINPROGRESS if it was deferred,
     * and an errno otherwise.
     */
    int (*open)(struct genio_ll *ll, genio_ll_open_done done, void *open_data);

    /*
     * Returns 0 if the open was immediate, EINPROGRESS if it was deferred.
     * No other returns are allowed.
     */
    int (*close)(struct genio_ll *ll, genio_ll_close_done done,
		 void *close_data);

    void (*set_read_callback_enable)(struct genio_ll *ll, bool enabled);

    void (*set_write_callback_enable)(struct genio_ll *ll, bool enabled);

    void (*free)(struct genio_ll *ll);
};

struct genio_fd_ll_ops {
    int (*sub_open)(void *handler_data,
		    int (**check_open)(void *handler_data, int fd),
		    int (**retry_open)(void *handler_data, int *fd),
		    int *fd);

    int (*raddr_to_str)(void *handler_data, int *pos,
			char *buf, unsigned int buflen);

    int (*get_raddr)(void *handler_data,
			struct sockaddr *addr, socklen_t addrlen);

    void (*free)(void *handler_data);
};

struct genio_ll *fd_genio_ll_alloc(struct genio_os_funcs *o,
				   const struct genio_fd_ll_ops *ops,
				   int fd,
				   void *handler_data,
				   unsigned int max_read_size);

struct genio_ll *genio_genio_ll_alloc(struct genio_os_funcs *o,
				      struct genio *child,
				      const struct genio_ll_callbacks *cbs,
				      void *cb_data);

struct genio *base_genio_alloc(struct genio_os_funcs *o,
			       struct genio_ll *ll,
			       struct genio_filter *filter,
			       enum genio_type type,
			       const struct genio_callbacks *cbs,
			       void *user_data);

struct genio *base_genio_server_alloc(struct genio_os_funcs *o,
				      struct genio_ll *ll,
				      struct genio_filter *filter,
				      enum genio_type type,
				      void (*open_done)(struct genio *net,
							int err,
							void *open_data),
				      void *open_data);

#endif /* GENIO_BASE_H */
