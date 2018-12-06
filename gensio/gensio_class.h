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

#ifndef GENSIO_CLASS_H
#define GENSIO_CLASS_H

#include <stddef.h>
#include <gensio/gensio.h>

/*
 * This is the default for most gensio layers.  Some have specific buffer
 * sizes, especially packet protocols like UDP and SSL.
 */
#define GENSIO_DEFAULT_BUF_SIZE		1024

/*
 * Functions for gensio_func...
 */

/*
 * count => count
 * buf => buf
 * buflen => buflen
 */
#define GENSIO_FUNC_WRITE		1

/*
 * pos => count
 * buf => auxdata
 * buflen => buflen
 */
#define GENSIO_FUNC_RADDR_TO_STR	2

/*
 * addr => auxdata
 * addrlen => count
 */
#define GENSIO_FUNC_GET_RADDR		3

/*
 * id => auxdata
 */
#define GENSIO_FUNC_REMOTE_ID		4

/*
 * open_done => buf
 * open_data => auxdata
 */
#define GENSIO_FUNC_OPEN		5

/*
 * close_done => buf
 * close_data => auxdata
 */
#define GENSIO_FUNC_CLOSE		6

/* No translations needed, return value not used */
#define GENSIO_FUNC_FREE		7

/* No translations needed, return value not used */
#define GENSIO_FUNC_REF			8

/* enabled => buflen, return value not used. */
#define GENSIO_FUNC_SET_READ_CALLBACK	9

/* enabled => buflen, return value not used. */
#define GENSIO_FUNC_SET_WRITE_CALLBACK	10

/*
 * Following struct in auxdata
 */
struct gensio_func_open_channel_data {
    char **args;
    gensio_event cb;
    void *user_data;
    gensio_done_err open_done;
    void *open_data;
    struct gensio *new_io;
};
#define GENSIO_FUNC_OPEN_CHANNEL	11

typedef int (*gensio_func)(struct gensio *io, int func, unsigned int *count,
			   const void *buf, unsigned int buflen,
			   void *auxdata);

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
				 gensio_func func, struct gensio *child,
				 const char *typename, void *gensio_data);
void gensio_data_free(struct gensio *io);
void *gensio_get_gensio_data(struct gensio *io);

void gensio_set_is_client(struct gensio *io, bool is_client);
void gensio_set_is_packet(struct gensio *io, bool is_packet);
void gensio_set_is_reliable(struct gensio *io, bool is_reliable);
gensio_event gensio_get_cb(struct gensio *io);
void gensio_set_cb(struct gensio *io, gensio_event cb, void *user_data);
int gensio_cb(struct gensio *io, int event, int err,
	      unsigned char *buf, unsigned int *buflen, void *auxdata);

/*
 * Add and get the classdata for a gensio.
 */
int gensio_addclass(struct gensio *io, const char *name, void *classdata);
void *gensio_getclass(struct gensio *io, const char *name);

/*
 * Functions for gensio_acc_func...
 */

/*
 * No translation needed
 */
#define GENSIO_ACC_FUNC_STARTUP			1

/*
 * shutdown_done => done
 * shutdown_data => data
 */
#define GENSIO_ACC_FUNC_SHUTDOWN		2

/*
 * enabled => val
 */
#define GENSIO_ACC_FUNC_SET_ACCEPT_CALLBACK	3

/*
 * No translation needed
 */
#define GENSIO_ACC_FUNC_FREE			4

/*
 * addr => addr
 * connect_done => done
 * cb_data => data
 * new_io => ret
 */
#define GENSIO_ACC_FUNC_CONNECT			5

typedef int (*gensio_acc_func)(struct gensio_accepter *acc, int func, int val,
			       void *addr, void *done, void *data,
			       void *ret);

struct gensio_accepter *gensio_acc_data_alloc(struct gensio_os_funcs *o,
		      gensio_accepter_event cb, void *user_data,
		      gensio_acc_func func, struct gensio_accepter *child,
		      const char *typename, void *gensio_acc_data);
void gensio_acc_data_free(struct gensio_accepter *acc);
void *gensio_acc_get_gensio_data(struct gensio_accepter *acc);
int gensio_acc_cb(struct gensio_accepter *acc, int event, void *data);
int gensio_acc_addclass(struct gensio_accepter *acc,
			const char *name, void *classdata);
void *gensio_acc_getclass(struct gensio_accepter *acc, const char *name);

void gensio_acc_set_is_packet(struct gensio_accepter *io, bool is_packet);
void gensio_acc_set_is_reliable(struct gensio_accepter *io, bool is_reliable);

void gensio_acc_vlog(struct gensio_accepter *acc, enum gensio_log_levels level,
		     char *str, va_list args);
void gensio_acc_log(struct gensio_accepter *acc, enum gensio_log_levels level,
		    char *str, ...);

/*
 * Handler registered so that str_to_gensio can process a gensio.
 * This is so users can create their own gensio types.
 */
typedef int (*str_to_gensio_handler)(const char *str, char *args[],
				     struct gensio_os_funcs *o,
				     gensio_event cb, void *user_data,
				     struct gensio **new_gensio);

/*
 * Add a gensio to the set of registered gensios.
 */
int register_gensio(struct gensio_os_funcs *o,
		    const char *name, str_to_gensio_handler handler);

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
 * Take a string in the form [ipv4|ipv6,][hostname,]port and convert
 * it to an addrinfo structure.  If this returns success, the user
 * must free rai with freeaddrinfo().  If is_dgram is true, allocate
 * a datagram socket, otherwise a stream socket.
 */
int gensio_scan_netaddr(const char *str, bool is_dgram, struct addrinfo **rai);

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

#endif /* GENSIO_CLASS_H */
