/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2001  Corey Minyard <minyard@acm.org>
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

#ifndef GENSIO_INTERNAL_H
#define GENSIO_INTERNAL_H

#include <stddef.h>
#include <gensio/gensio.h>

/*
 * This is the default for most gensio layers.  Some have specific buffer
 * sizes, especially packet protocols like UDP and SSL.
 */
#define GENSIO_DEFAULT_BUF_SIZE		1024

struct gensio_functions {
    int (*write)(struct gensio *io, unsigned int *count,
		 const void *buf, unsigned int buflen);

    int (*raddr_to_str)(struct gensio *io, int *pos,
			char *buf, unsigned int buflen);

    int (*get_raddr)(struct gensio *io,
		     struct sockaddr *addr, socklen_t *addrlen);

    int (*remote_id)(struct gensio *io, int *id);

    int (*open)(struct gensio *io,
		void (*open_done)(struct gensio *io, int err, void *open_data),
		void *open_data);

    int (*close)(struct gensio *io,
		 void (*close_done)(struct gensio *io, void *close_data),
		 void *close_data);

    void (*free)(struct gensio *io);

    void (*ref)(struct gensio *io);

    void (*set_read_callback_enable)(struct gensio *io, bool enabled);

    void (*set_write_callback_enable)(struct gensio *io, bool enabled);
};

/*
 * Increment the gensio's refcount.  There are situations where one
 * piece of code passes a gensio into another piece of code, and
 * that other piece of code that might free it on an error, but
 * the upper layer gets the error and wants to free it, too.  This
 * keeps it around for that situation.
 */
void gensio_ref(struct gensio *io);

struct gensio *gensio_data_alloc(struct gensio_os_funcs *o,
				 gensio_event cb, void *user_data,
				 const struct gensio_functions *funcs,
				 const char *typename, void *gensio_data);
void gensio_data_free(struct gensio *io);
void *gensio_get_gensio_data(struct gensio *io);

void gensio_set_is_client(struct gensio *io, bool is_client);
void gensio_set_is_packet(struct gensio *io, bool is_packet);
void gensio_set_is_reliable(struct gensio *io, bool is_reliable);
gensio_event gensio_get_cb(struct gensio *io);
void gensio_set_cb(struct gensio *io, gensio_event cb, void *user_data);
int gensio_cb(struct gensio *io, int event, int err,
	      unsigned char *buf, unsigned int *buflen,
	      unsigned long channel, void *auxdata);

/*
 * Add and get the classdata for a gensio.
 */
int gensio_addclass(struct gensio *io, const char *name, void *classdata);
void *gensio_getclass(struct gensio *io, const char *name);

struct gensio_acceptor_functions {
    int (*startup)(struct gensio_acceptor *acceptor);

    int (*shutdown)(struct gensio_acceptor *acceptor,
		    void (*shutdown_done)(struct gensio_acceptor *acceptor,
					  void *shutdown_data),
		    void *shutdown_data);

    void (*set_accept_callback_enable)(struct gensio_acceptor *acceptor,
				       bool enabled);

    void (*free)(struct gensio_acceptor *acceptor);

    int (*connect)(struct gensio_acceptor *acceptor, void *addr,
		   void (*connect_done)(struct gensio *io, int err,
					void *cb_data),
		   void *cb_data, struct gensio **new_io);
};

struct gensio_acceptor *gensio_acc_data_alloc(struct gensio_os_funcs *o,
		      gensio_acceptor_event cb, void *user_data,
		      const struct gensio_acceptor_functions *funcs,
		      const char *typename, void *gensio_acc_data);
void gensio_acc_data_free(struct gensio_acceptor *acc);
void *gensio_acc_get_gensio_data(struct gensio_acceptor *acc);
int gensio_acc_cb(struct gensio_acceptor *acc, int event, void *data);
int gensio_acc_addclass(struct gensio_acceptor *acc,
			const char *name, void *classdata);
void *gensio_acc_getclass(struct gensio_acceptor *acc, const char *name);
const char *gensio_acc_get_type(struct gensio_acceptor *acc);

void gensio_acc_set_is_packet(struct gensio_acceptor *io, bool is_packet);
void gensio_acc_set_is_reliable(struct gensio_acceptor *io, bool is_reliable);

void gensio_acc_vlog(struct gensio_acceptor *acc, enum gensio_log_levels level,
		     char *str, va_list args);
void gensio_acc_log(struct gensio_acceptor *acc, enum gensio_log_levels level,
		    char *str, ...);

#define container_of(ptr, type, member)			\
    ((type *)(((char *) ptr) - offsetof(type, member)))

struct opensocks
{
    int fd;
    int family;
};

/*
 * Open a set of sockets given the addrinfo list, one per address.
 * Return the actual number of sockets opened in nr_fds.  Set the
 * I/O handler to readhndlr, with the given data.
 *
 * Note that if the function is unable to open an address, it just
 * goes on.  It returns NULL if it is unable to open any addresses.
 * Also, open IPV6 addresses first.  This way, addresses in shared
 * namespaces (like IPV4 and IPV6 on INADDR6_ANY) will work properly
 */
struct opensocks *gensio_open_socket(struct gensio_os_funcs *o,
				     struct addrinfo *ai,
				     void (*readhndlr)(int, void *),
				     void (*writehndlr)(int, void *),
				     void *data,
				     unsigned int *nr_fds,
				     void (*fd_handler_cleared)(int, void *));

/* Returns a NULL if the fd is ok, a non-NULL error string if not */
const char *gensio_check_tcpd_ok(int new_fd);

/*
 * There are no provided routines to duplicate addrinfo structures,
 * so we really need to do it ourselves.
 */
struct addrinfo *gensio_dup_addrinfo(struct gensio_os_funcs *o,
				     struct addrinfo *ai);
void gensio_free_addrinfo(struct gensio_os_funcs *o, struct addrinfo *ai);

char *gensio_strdup(struct gensio_os_funcs *o, const char *str);

int gensio_check_keyvalue(const char *str, const char *key, const char **value);
int gensio_check_keyuint(const char *str, const char *key, unsigned int *value);

int gensio_scan_args(const char **rstr, int *argc, char ***args);

#endif /* GENSIO_INTERNAL_H */
