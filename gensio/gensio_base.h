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

#ifndef GENSIO_BASE_H
#define GENSIO_BASE_H

#include <gensio/gensio.h>

struct gensio_filter {
    const struct gensio_filter_ops *ops;
};

typedef int (*gensio_ul_filter_data_handler)(void *cb_data,
					     unsigned int *rcount,
					     const unsigned char *buf,
					     unsigned int buflen);

typedef int (*gensio_ll_filter_data_handler)(void *cb_data,
					     unsigned int *rcount,
					     unsigned char *buf,
					     unsigned int buflen);

struct gensio_filter_callbacks {
    /*
     * The filter has some asynchronously generated data that it needs
     * to send, tell the gensio base to recalculate its enables.
     */
    void (*output_ready)(void *cb_data);

    void (*start_timer)(void *cb_data, struct timeval *timeout);
};

struct gensio_filter_ops {
    void (*set_callbacks)(struct gensio_filter *filter,
			  const struct gensio_filter_callbacks *cbs,
			  void *cb_data);

    /* Is there data ready to be read from the top of the filter? */
    bool (*ul_read_pending)(struct gensio_filter *filter);

    /* Is there data ready to be written out of the bottom of the filter? */
    bool (*ll_write_pending)(struct gensio_filter *filter);

    /* Is the filter expecting that data should come in the bottom? */
    bool (*ll_read_needed)(struct gensio_filter *filter);

    /*
     * Provides a way to verify keys and such after the open is complete.
     * Returning an error will abort the connection before the open is
     * returned.
     */
    int (*check_open_done)(struct gensio_filter *filter);

    /*
     * Attempt to start a connection on the filter.  Returns 0 on
     * immediate success.  Returns EINPROGRESS if the connect attempt
     * should be retried when any I/O occurs.  Returns EAGAIN if the
     * connect attempt should be retried after any I/O or when the
     * timeout occurs.
     */
    int (*try_connect)(struct gensio_filter *filter, struct timeval *timeout);

    /*
     * Attempt to disconnect the filter.  Returns 0 on immediate
     * success.  Returns EINPROGRESS if the connect attempt should be
     * retried.  Returns EAGAIN if the connect attempt should be
     * retried after any I/O or when the timeout occurs.
     */
    int (*try_disconnect)(struct gensio_filter *filter, struct timeval *timeout);

    /*
     * Write data into the top of the filter.  If no data is provided
     * (buf is NULL) then this will just attempt to write any pending
     * data out of the bottom of the filter into the handler.
     */
    int (*ul_write)(struct gensio_filter *filter,
		    gensio_ul_filter_data_handler handler, void *cb_data,
		    unsigned int *rcount,
		    const unsigned char *buf, unsigned int buflen);

    /*
     * Write data into the bottom of the filter.  If no data is
     * provided (buf is NULL) then this will just attempt to write any
     * pending data out of the top of the filter into the handler.
     */
    int (*ll_write)(struct gensio_filter *filter,
		    gensio_ll_filter_data_handler handler, void *cb_data,
		    unsigned int *rcount,
		    unsigned char *buf, unsigned int buflen);

    /* Handle urgent data. */
    void (*ll_urgent)(struct gensio_filter *filter);

    void (*timeout)(struct gensio_filter *filter);

    int (*setup)(struct gensio_filter *filter);
    void (*cleanup)(struct gensio_filter *filter);
    void (*free)(struct gensio_filter *filter);
};

/* FIXME - make args const */
int gensio_ssl_filter_alloc(struct gensio_os_funcs *o, char *args[],
			    struct gensio_filter **rfilter);

int gensio_ssl_server_filter_alloc(struct gensio_os_funcs *o,
				   char *keyfile,
				   char *certfile,
				   char *CAfilepath,
				   unsigned int max_read_size,
				   unsigned int max_write_size,
				   struct gensio_filter **rfilter);

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

struct gensio_ll {
    const struct gensio_ll_ops *ops;
};

typedef void (*gensio_ll_open_done)(void *cb_data, int err, void *open_data);
typedef void (*gensio_ll_close_done)(void *cb_data, void *close_data);

struct gensio_ll_callbacks {
    unsigned int (*read_callback)(void *cb_data, int readerr,
				  unsigned char *buf,
				  unsigned int buflen);
    void (*write_callback)(void *cb_data);
    void (*urgent_callback)(void *cb_data);
};

struct gensio_ll_ops {
    void (*set_callbacks)(struct gensio_ll *ll,
			  const struct gensio_ll_callbacks *cbs,
			  void *cb_data);

    int (*write)(struct gensio_ll *ll, unsigned int *rcount,
		 const unsigned char *buf, unsigned int buflen);

    int (*raddr_to_str)(struct gensio_ll *ll, int *pos,
			char *buf, unsigned int buflen);

    int (*get_raddr)(struct gensio_ll *ll,
		     struct sockaddr *addr, socklen_t *addrlen);

    int (*remote_id)(struct gensio_ll *ll, int *id);

    /*
     * Returns 0 if the open was immediate, EINPROGRESS if it was deferred,
     * and an errno otherwise.
     */
    int (*open)(struct gensio_ll *ll, gensio_ll_open_done done, void *open_data);

    /*
     * Returns 0 if the open was immediate, EINPROGRESS if it was deferred.
     * No other returns are allowed.
     */
    int (*close)(struct gensio_ll *ll, gensio_ll_close_done done,
		 void *close_data);

    void (*set_read_callback_enable)(struct gensio_ll *ll, bool enabled);

    void (*set_write_callback_enable)(struct gensio_ll *ll, bool enabled);

    void (*free)(struct gensio_ll *ll);
};

enum gensio_ll_close_state {
    GENSIO_LL_CLOSE_STATE_START,
    GENSIO_LL_CLOSE_STATE_DONE
};

struct gensio_fd_ll_ops {
    int (*sub_open)(void *handler_data,
		    int (**check_open)(void *handler_data, int fd),
		    int (**retry_open)(void *handler_data, int *fd),
		    int *fd);

    int (*raddr_to_str)(void *handler_data, int *pos,
			char *buf, unsigned int buflen);

    int (*get_raddr)(void *handler_data,
		     struct sockaddr *addr, socklen_t *addrlen);

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

struct gensio_ll *gensio_gensio_ll_alloc(struct gensio_os_funcs *o,
					 struct gensio *child);

struct gensio *base_gensio_alloc(struct gensio_os_funcs *o,
				 struct gensio_ll *ll,
				 struct gensio_filter *filter,
				 enum gensio_type type,
				 const struct gensio_callbacks *cbs,
				 void *user_data);

struct gensio *base_gensio_server_alloc(struct gensio_os_funcs *o,
					struct gensio_ll *ll,
					struct gensio_filter *filter,
					enum gensio_type type,
					void (*open_done)(struct gensio *net,
							  int err,
							  void *open_data),
					void *open_data);

struct gensio_gensio_acc_cbs {
    int (*connect_start)(void *acc_data, struct gensio *child,
			 struct gensio **new_net);
    int (*new_child)(void *acc_data, void **finish_data,
		     struct gensio_filter **filter);
    void (*finish_child)(void *acc_data, void *finish_data, struct gensio *io);
    void (*free)(void *acc_data);
};

int gensio_gensio_acceptor_alloc(const char *name,
				 struct gensio_os_funcs *o,
				 struct gensio_acceptor *child,
				 enum gensio_type type,
				 const struct gensio_acceptor_callbacks *cbs,
				 void *user_data,
				 const struct gensio_gensio_acc_cbs *acc_cbs,
				 void *acc_data,
				 struct gensio_acceptor **acceptor);

#endif /* GENSIO_BASE_H */
