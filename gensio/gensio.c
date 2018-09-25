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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>

#include <utils/utils.h>

#include <gensio/gensio.h>
#include <gensio/gensio_class.h>

struct gensio_classobj {
    const char *name;
    void *classdata;
    struct gensio_classobj *next;
};

int
gen_addclass(struct gensio_os_funcs *o,
	     struct gensio_classobj **classes,
	     const char *name, void *classdata)
{
    struct gensio_classobj *c;

    c = o->zalloc(o, sizeof(*c));
    if (!c)
	return ENOMEM;
    c->name = name;
    c->classdata = classdata;
    c->next = *classes;
    *classes = c;
    return 0;
}

void *
gen_getclass(struct gensio_classobj *classes, const char *name)
{
    struct gensio_classobj *c;

    for (c = classes; c; c = c->next) {
	if (strcmp(c->name, name) == 0)
	    return c->classdata;
    }
    return NULL;
}

struct gensio {
    struct gensio_os_funcs *o;
    void *user_data;
    gensio_event cb;

    struct gensio_classobj *classes;

    gensio_func func;
    void *gensio_data;

    const char *typename;

    bool is_client;
    bool is_packet;
    bool is_reliable;
};

struct gensio *
gensio_data_alloc(struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  gensio_func func,
		  const char *typename, void *gensio_data)
{
    struct gensio *io = o->zalloc(o, sizeof(*io));

    if (!io)
	return NULL;

    io->o = o;
    io->cb = cb;
    io->user_data = user_data;
    io->func = func;
    io->typename = typename;
    io->gensio_data = gensio_data;

    return io;
}

void
gensio_data_free(struct gensio *io)
{
    while (io->classes) {
	struct gensio_classobj *c = io->classes;

	io->classes = c->next;
	io->o->free(io->o, c);
    }
    io->o->free(io->o, io);
}

void *
gensio_get_gensio_data(struct gensio *io)
{
    return io->gensio_data;
}

gensio_event
gensio_get_cb(struct gensio *io)
{
    return io->cb;
}

void gensio_set_cb(struct gensio *io, gensio_event cb, void *user_data)
{
    io->cb = NULL;
    io->user_data = NULL;
}

int
gensio_cb(struct gensio *io, int event, int err,
	  unsigned char *buf, unsigned int *buflen,
	  unsigned long channel, void *auxdata)
{
    return io->cb(io, event, err, buf, buflen, channel, auxdata);
}

int
gensio_addclass(struct gensio *io, const char *name, void *classdata)
{
    return gen_addclass(io->o, &io->classes, name, classdata);
}

void *
gensio_getclass(struct gensio *io, const char *name)
{
    return gen_getclass(io->classes, name);
}

struct gensio_accepter {
    struct gensio_os_funcs *o;

    void *user_data;
    gensio_accepter_event cb;

    struct gensio_classobj *classes;

    const struct gensio_accepter_functions *funcs;
    gensio_acc_func func;
    void *gensio_acc_data;

    const char *typename;

    bool is_packet;
    bool is_reliable;
};

struct gensio_accepter *
gensio_acc_data_alloc(struct gensio_os_funcs *o,
		      gensio_accepter_event cb, void *user_data,
		      gensio_acc_func func,
		      const char *typename, void *gensio_acc_data)
{
    struct gensio_accepter *acc = o->zalloc(o, sizeof(*acc));

    if (!acc)
	return NULL;

    acc->o = o;
    acc->cb = cb;
    acc->user_data = user_data;
    acc->func = func;
    acc->typename = typename;
    acc->gensio_acc_data = gensio_acc_data;

    return acc;
}

void
gensio_acc_data_free(struct gensio_accepter *acc)
{
    while (acc->classes) {
	struct gensio_classobj *c = acc->classes;

	acc->classes = c->next;
	acc->o->free(acc->o, c);
    }
    acc->o->free(acc->o, acc);
}

void *
gensio_acc_get_gensio_data(struct gensio_accepter *acc)
{
    return acc->gensio_acc_data;
}

int
gensio_acc_cb(struct gensio_accepter *acc, int event, void *data)
{
    return acc->cb(acc, event, data);
}

int
gensio_acc_addclass(struct gensio_accepter *acc,
		    const char *name, void *classdata)
{
    return gen_addclass(acc->o, &acc->classes, name, classdata);
}

void *
gensio_acc_getclass(struct gensio_accepter *acc, const char *name)
{
    return gen_getclass(acc->classes, name);
}

const char *
gensio_acc_get_type(struct gensio_accepter *acc)
{
    return acc->typename;
}

void
check_ipv6_only(int family, struct sockaddr *addr, int fd)
{
    int null = 0;

    if (family != AF_INET6)
	return;

    if (!IN6_IS_ADDR_UNSPECIFIED(&(((struct sockaddr_in6 *) addr)->sin6_addr)))
	return;

    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &null, sizeof(null));
}

/* FIXME - The error handling in this function isn't good, fix it. */
struct opensocks *
gensio_open_socket(struct gensio_os_funcs *o,
		   struct addrinfo *ai, void (*readhndlr)(int, void *),
		   void (*writehndlr)(int, void *), void *data,
		   unsigned int *nr_fds,
		   void (*fd_handler_cleared)(int, void *))
{
    struct addrinfo *rp;
    int optval = 1;
    int family = AF_INET6; /* Try IPV6 first, then IPV4. */
    struct opensocks *fds;
    unsigned int curr_fd = 0;
    unsigned int max_fds = 0;
    int rv;

    for (rp = ai; rp != NULL; rp = rp->ai_next)
	max_fds++;

    if (max_fds == 0)
	return NULL;

    fds = o->zalloc(o, sizeof(*fds) * max_fds);
    if (!fds)
	return NULL;

  restart:
    for (rp = ai; rp != NULL; rp = rp->ai_next) {
	if (family != rp->ai_family)
	    continue;

	fds[curr_fd].fd = socket(rp->ai_family, rp->ai_socktype,
				 rp->ai_protocol);
	if (fds[curr_fd].fd == -1)
	    continue;

	fds[curr_fd].family = rp->ai_family;

	if (fcntl(fds[curr_fd].fd, F_SETFL, O_NONBLOCK) == -1)
	    goto next;

	if (setsockopt(fds[curr_fd].fd, SOL_SOCKET, SO_REUSEADDR,
		       (void *)&optval, sizeof(optval)) == -1)
	    goto next;

	check_ipv6_only(rp->ai_family, rp->ai_addr, fds[curr_fd].fd);

	if (bind(fds[curr_fd].fd, rp->ai_addr, rp->ai_addrlen) != 0)
	    goto next;

	if (rp->ai_socktype == SOCK_STREAM && listen(fds[curr_fd].fd, 1) != 0)
	    goto next;

	rv = o->set_fd_handlers(o, fds[curr_fd].fd, data,
				readhndlr, writehndlr, NULL,
				fd_handler_cleared);
	if (rv)
	    goto next;
	curr_fd++;
	continue;

      next:
	close(fds[curr_fd].fd);
    }
    if (family == AF_INET6) {
	family = AF_INET;
	goto restart;
    }

    if (curr_fd == 0) {
	o->free(o, fds);
	fds = NULL;
    }
    *nr_fds = curr_fd;
    return fds;
}

int
gensio_scan_args(const char **rstr, int *argc, char ***args)
{
    const char *str = *rstr;
    int err = 0;

    if (*str == '(') {
	err = str_to_argv_lengths_endchar(str + 1, argc, args, NULL,
					  " \f\n\r\t\v,", ")", &str);
	if (!err && (!str || *str != ','))
	    err = EINVAL; /* No terminating ')' or ',' after */
	else
	    str++;
    } else {
	str += 1;
	err = str_to_argv_lengths("", argc, args, NULL, ")");
    }

    if (!err)
	*rstr = str;

    return err;
}

/*
 * Scan for a network port in the form:
 *
 *   [ipv4|ipv6,][tcp|udp,][<hostname>,]<port>
 *
 * If neither ipv4 nor ipv6 is specified, addresses for both are
 * returned.  If neither tcp nor udp is specified, tcp is assumed.
 * The hostname can be a resolvable hostname, an IPv4 octet, or an
 * IPv6 address.  If it is not supplied, inaddr_any is used.  In the
 * absence of a hostname specification, a wildcard address is used.
 * The mandatory second part is the port number or a service name.
 *
 * If the port is all zero, then is_port_set is set to true, false
 * otherwise.  If the address is UDP, is_dgram is set to true, false
 * otherwise.
 */
static int
scan_network_port_args(const char *str, struct addrinfo **rai, bool *is_dgram,
		       bool *is_port_set, int *argc, char ***args)
{
    char *strtok_data, *strtok_buffer;
    char *ip;
    char *port;
    struct addrinfo hints, *ai;
    int family = AF_UNSPEC;
    int socktype = SOCK_STREAM;
    int err = 0;

    if (strncmp(str, "ipv4,", 5) == 0) {
	family = AF_INET;
	str += 5;
    } else if (strncmp(str, "ipv6,", 5) == 0) {
	family = AF_INET6;
	str += 5;
    }

    if (strncmp(str, "tcp,", 4) == 0 ||
		(args && strncmp(str, "tcp(", 4) == 0)) {
	if (args) {
	    str += 3;
	    err = gensio_scan_args(&str, argc, args);
	} else {
	    str += 4;
	}
	if (err)
	    return err;
    } else if (strncmp(str, "udp,", 4) == 0 ||
	       (args && strncmp(str, "udp(", 4) == 0)) {
	/* Only allow UDP if asked for. */
	if (!is_dgram)
	    return EINVAL;
	if (args) {
	    str += 3;
	    err = gensio_scan_args(&str, argc, args);
	} else {
	    str += 4;
	}
	if (err)
	    return err;
	socktype = SOCK_DGRAM;
    } else if (args) {
	err = str_to_argv_lengths("", argc, args, NULL, ")");
	if (err)
	    return err;
    }

    strtok_buffer = strdup(str);
    if (!strtok_buffer)
	return ENOMEM;

    ip = strtok_r(strtok_buffer, ",", &strtok_data);
    port = strtok_r(NULL, "", &strtok_data);
    if (port == NULL) {
	port = ip;
	ip = NULL;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = family;
    hints.ai_socktype = socktype;
    if (getaddrinfo(ip, port, &hints, &ai)) {
	free(strtok_buffer);
	return EINVAL;
    }

    if (is_dgram)
	*is_dgram = socktype == SOCK_DGRAM;

    if (is_port_set)
	*is_port_set = !strisallzero(port);

    free(strtok_buffer);
    if (*rai)
	freeaddrinfo(*rai);
    *rai = ai;
    return 0;
}

int
scan_network_port(const char *str, struct addrinfo **ai, bool *is_dgram,
		  bool *is_port_set)
{
    return scan_network_port_args(str, ai, is_dgram, is_port_set, NULL, NULL);
}

int
gensio_scan_netaddr(const char *str, bool is_dgram, struct addrinfo **rai)
{
    char *strtok_data, *strtok_buffer;
    char *ip;
    char *port;
    struct addrinfo hints, *ai;
    int family = AF_UNSPEC;
    int socktype = SOCK_STREAM;

    if (is_dgram)
	socktype = SOCK_DGRAM;

    if (strncmp(str, "ipv4,", 5) == 0) {
	family = AF_INET;
	str += 5;
    } else if (strncmp(str, "ipv6,", 5) == 0) {
	family = AF_INET6;
	str += 5;
    }

    strtok_buffer = strdup(str);
    if (!strtok_buffer)
	return ENOMEM;

    ip = strtok_r(strtok_buffer, ",", &strtok_data);
    port = strtok_r(NULL, "", &strtok_data);
    if (port == NULL) {
	port = ip;
	ip = NULL;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = family;
    hints.ai_socktype = socktype;
    if (getaddrinfo(ip, port, &hints, &ai)) {
	free(strtok_buffer);
	return EINVAL;
    }

    free(strtok_buffer);
    *rai = ai;
    return 0;
}

bool
sockaddr_equal(const struct sockaddr *a1, socklen_t l1,
	       const struct sockaddr *a2, socklen_t l2,
	       bool compare_ports)
{
    if (l1 != l2)
	return false;
    if (a1->sa_family != a2->sa_family)
	return false;
    switch (a1->sa_family) {
    case AF_INET:
	{
	    struct sockaddr_in *s1 = (struct sockaddr_in *) a1;
	    struct sockaddr_in *s2 = (struct sockaddr_in *) a2;
	    if (compare_ports && s1->sin_port != s2->sin_port)
		return false;
	    if (s1->sin_addr.s_addr != s2->sin_addr.s_addr)
		return false;
	}
	break;

    case AF_INET6:
	{
	    struct sockaddr_in6 *s1 = (struct sockaddr_in6 *) a1;
	    struct sockaddr_in6 *s2 = (struct sockaddr_in6 *) a2;
	    if (compare_ports && s1->sin6_port != s2->sin6_port)
		return false;
	    if (memcmp(s1->sin6_addr.s6_addr, s2->sin6_addr.s6_addr,
		       sizeof(s1->sin6_addr.s6_addr)) != 0)
		return false;
	}
	break;

    default:
	/* Unknown family. */
	return false;
    }

    return true;
}

int
gensio_buffer_do_write(void *cb_data, void  *buf, size_t buflen,
		       size_t *written)
{
    struct gensio *io = cb_data;
    int err = 0;
    unsigned int count;

    err = gensio_write(io, &count, 0, buf, buflen);
    if (!err)
	*written = count;

    return err;
}

void
gensio_set_callback(struct gensio *io, gensio_event cb, void *user_data)
{
    io->cb = cb;
    io->user_data = user_data;
}

void *
gensio_get_user_data(struct gensio *io)
{
    return io->user_data;
}

void
gensio_set_user_data(struct gensio *io, void *user_data)
{
    io->user_data = user_data;
}

int
gensio_write(struct gensio *io, unsigned int *count, unsigned long channel,
	     const void *buf, unsigned int buflen)
{
    return io->func(io, GENSIO_FUNC_WRITE, count, channel, buf, buflen, NULL);
}

int
gensio_raddr_to_str(struct gensio *io, unsigned int *pos,
		    char *buf, unsigned int buflen)
{
    return io->func(io, GENSIO_FUNC_RADDR_TO_STR, pos, 0, NULL, buflen, buf);
}

int
gensio_get_raddr(struct gensio *io, void *addr, unsigned int *addrlen)
{
    return io->func(io, GENSIO_FUNC_GET_RADDR, addrlen, 0, NULL, 0, addr);
}

int
gensio_remote_id(struct gensio *io, int *id)
{
    return io->func(io, GENSIO_FUNC_REMOTE_ID, NULL, 0, NULL, 0, id);
}

int
gensio_open(struct gensio *io, gensio_done_err open_done, void *open_data)
{
    return io->func(io, GENSIO_FUNC_OPEN, NULL, 0, open_done, 0, open_data);
}

struct gensio_open_s_data {
    struct gensio_os_funcs *o;
    int err;
    struct gensio_waiter *waiter;
};

static void
gensio_open_s_done(struct gensio *io, int err, void *cb_data)
{
    struct gensio_open_s_data *data = cb_data;

    data->err = err;
    data->o->wake(data->waiter);
}

int
gensio_open_s(struct gensio *io, struct gensio_os_funcs *o)
{
    struct gensio_open_s_data data;
    int err;

    data.o = o;
    data.err = 0;
    data.waiter = o->alloc_waiter(o);
    if (!data.waiter)
	return ENOMEM;
    err = gensio_open(io, gensio_open_s_done, &data);
    if (!err) {
	o->wait(data.waiter, NULL);
	err = data.err;
    }
    o->free_waiter(data.waiter);
    return err;
}

int
gensio_close(struct gensio *io, gensio_done close_done, void *close_data)
{
    return io->func(io, GENSIO_FUNC_CLOSE, NULL, 0, close_done, 0, close_data);
}

void
gensio_free(struct gensio *io)
{
    io->func(io, GENSIO_FUNC_FREE, NULL, 0, NULL, 0, NULL);
}

void
gensio_set_read_callback_enable(struct gensio *io, bool enabled)
{
    io->func(io, GENSIO_FUNC_SET_READ_CALLBACK, NULL, 0, NULL, enabled, NULL);
}

void
gensio_set_write_callback_enable(struct gensio *io, bool enabled)
{
    io->func(io, GENSIO_FUNC_SET_WRITE_CALLBACK, NULL, 0, NULL, enabled, NULL);
}

void
gensio_ref(struct gensio *io)
{
    io->func(io, GENSIO_FUNC_REF, NULL, 0, NULL, 0, NULL);
}

bool
gensio_is_client(struct gensio *io)
{
    return io->is_client;
}

bool
gensio_is_reliable(struct gensio *io)
{
    return io->is_reliable;
}

bool
gensio_is_packet(struct gensio *io)
{
    return io->is_packet;
}

void
gensio_set_is_client(struct gensio *io, bool is_client)
{
    io->is_client = is_client;
}

void
gensio_set_is_reliable(struct gensio *io, bool is_reliable)
{
    io->is_reliable = is_reliable;
}

void
gensio_set_is_packet(struct gensio *io, bool is_packet)
{
    io->is_packet = is_packet;
}

void *
gensio_acc_get_user_data(struct gensio_accepter *accepter)
{
    return accepter->user_data;
}

void
gensio_acc_set_user_data(struct gensio_accepter *accepter,
			 void *user_data)
{
    accepter->user_data = user_data;
}

void
gensio_acc_set_callback(struct gensio_accepter *accepter,
			gensio_accepter_event cb,
			void *user_data)
{
    accepter->cb = cb;
    accepter->user_data = user_data;
}

int
gensio_acc_startup(struct gensio_accepter *accepter)
{
    return accepter->func(accepter, GENSIO_ACC_FUNC_STARTUP, 0,
			  NULL, NULL, NULL, NULL);
}

int
gensio_acc_shutdown(struct gensio_accepter *accepter,
		    gensio_acc_done shutdown_done, void *shutdown_data)
{
    return accepter->func(accepter, GENSIO_ACC_FUNC_SHUTDOWN, 0,
			  0, shutdown_done, shutdown_data, NULL);
}

void
gensio_acc_set_accept_callback_enable(struct gensio_accepter *accepter,
				      bool enabled)
{
    accepter->func(accepter, GENSIO_ACC_FUNC_SET_ACCEPT_CALLBACK, enabled,
		   NULL, NULL, NULL, NULL);
}

void
gensio_acc_free(struct gensio_accepter *accepter)
{
    accepter->func(accepter, GENSIO_ACC_FUNC_FREE, 0, NULL, NULL, NULL, NULL);
}

int
gensio_acc_connect(struct gensio_accepter *accepter, void *addr,
		   gensio_done_err connect_done, void *cb_data,
		   struct gensio **new_io)
{
    return accepter->func(accepter, GENSIO_ACC_FUNC_FREE, 0,
			  addr, connect_done, cb_data, new_io);
}

/* FIXME - this is a cheap hack and needs to be fixed. */
bool
gensio_acc_exit_on_close(struct gensio_accepter *accepter)
{
    return strcmp(accepter->typename, "stdio") == 0;
}

bool
gensio_acc_is_reliable(struct gensio_accepter *accepter)
{
    return accepter->is_reliable;
}

bool
gensio_acc_is_packet(struct gensio_accepter *accepter)
{
    return accepter->is_packet;
}

void
gensio_acc_set_is_reliable(struct gensio_accepter *accepter, bool is_reliable)
{
     accepter->is_reliable = is_reliable;
}

void
gensio_acc_set_is_packet(struct gensio_accepter *accepter, bool is_packet)
{
    accepter->is_packet = is_packet;
}

struct registered_gensio_accepter {
    const char *name;
    str_to_gensio_acc_handler handler;
    struct registered_gensio_accepter *next;
};

struct registered_gensio_accepter *reg_gensio_accs;
struct gensio_lock *reg_gensio_acc_lock;


struct gensio_once gensio_acc_str_initialized;

static void
add_default_gensio_accepters(void *cb_data)
{
    struct gensio_os_funcs *o = cb_data;

    reg_gensio_acc_lock = o->alloc_lock(o);
    register_gensio_accepter(o, "tcp", str_to_tcp_gensio_accepter);
    register_gensio_accepter(o, "udp", str_to_udp_gensio_accepter);
    register_gensio_accepter(o, "stdio", str_to_stdio_gensio_accepter);
    register_gensio_accepter(o, "ssl", str_to_ssl_gensio_accepter);
    register_gensio_accepter(o, "telnet", str_to_telnet_gensio_accepter);
}

int
register_gensio_accepter(struct gensio_os_funcs *o,
			 const char *name, str_to_gensio_acc_handler handler)
{
    struct registered_gensio_accepter *n;

    o->call_once(o, &gensio_acc_str_initialized,
		 add_default_gensio_accepters, o);

    n = o->zalloc(o, sizeof(*n));
    if (!n)
	return ENOMEM;

    n->name = name;
    n->handler = handler;
    o->lock(reg_gensio_acc_lock);
    n->next = reg_gensio_accs;
    reg_gensio_accs = n;
    o->unlock(reg_gensio_acc_lock);
    return 0;
}

int str_to_gensio_accepter(const char *str,
			   struct gensio_os_funcs *o,
			   gensio_accepter_event cb, void *user_data,
			   struct gensio_accepter **accepter)
{
    int err;
    struct addrinfo *ai = NULL;
    bool is_dgram, is_port_set;
    char *dummy_args[1] = { NULL };
    int argc;
    char **args = NULL;
    struct registered_gensio_accepter *r;
    unsigned int len;

    o->call_once(o, &gensio_acc_str_initialized,
		 add_default_gensio_accepters, o);

    while (isspace(*str))
	str++;
    for (r = reg_gensio_accs; r; r = r->next) {
	len = strlen(r->name);
	if (strncmp(r->name, str, len) != 0 ||
			(str[len] != ',' && str[len] != '('))
	    continue;

	str += len;
	err = gensio_scan_args(&str, &argc, &args);
	if (!err)
	    err = r->handler(str, args, o, cb, user_data, accepter);
	if (args)
	    str_to_argv_free(argc, args);
	return err;
    }

    if (strisallzero(str)) {
	err = stdio_gensio_accepter_alloc(dummy_args, o, cb, user_data,
					  accepter);
    } else {
	err = scan_network_port_args(str, &ai, &is_dgram, &is_port_set,
				     &argc, &args);
	if (!err) {
	    if (!is_port_set) {
		err = EINVAL;
	    } else if (is_dgram) {
		err = udp_gensio_accepter_alloc(ai, args, o, cb,
						user_data, accepter);
	    } else {
		err = tcp_gensio_accepter_alloc(ai, args, o, cb,
						user_data, accepter);
	    }

	    freeaddrinfo(ai);
	}
    }

    if (args && args != dummy_args)
	str_to_argv_free(argc, args);

    return err;
}

struct registered_gensio {
    const char *name;
    str_to_gensio_handler handler;
    struct registered_gensio *next;
};

struct registered_gensio *reg_gensios;
struct gensio_lock *reg_gensio_lock;


struct gensio_once gensio_str_initialized;

static void
add_default_gensios(void *cb_data)
{
    struct gensio_os_funcs *o = cb_data;

    reg_gensio_lock = o->alloc_lock(o);
    register_gensio(o, "tcp", str_to_tcp_gensio);
    register_gensio(o, "udp", str_to_udp_gensio);
    register_gensio(o, "stdio", str_to_stdio_gensio);
#ifdef HAVE_OPENSSL
    register_gensio(o, "ssl", str_to_ssl_gensio);
#endif
    register_gensio(o, "telnet", str_to_telnet_gensio);
    register_gensio(o, "termios", str_to_termios_gensio);
}

int
register_gensio(struct gensio_os_funcs *o,
		const char *name, str_to_gensio_handler handler)
{
    struct registered_gensio *n;

    o->call_once(o, &gensio_str_initialized, add_default_gensios, o);

    n = o->zalloc(o, sizeof(*n));
    if (!n)
	return ENOMEM;

    n->name = name;
    n->handler = handler;
    o->lock(reg_gensio_lock);
    n->next = reg_gensios;
    reg_gensios = n;
    o->unlock(reg_gensio_lock);
    return 0;
}

int
str_to_gensio(const char *str,
	      struct gensio_os_funcs *o,
	      gensio_event cb, void *user_data,
	      struct gensio **gensio)
{
    int err = 0;
    struct addrinfo *ai = NULL;
    bool is_dgram, is_port_set;
    int argc;
    char **args = NULL;
    struct registered_gensio *r;
    unsigned int len;

    o->call_once(o, &gensio_str_initialized, add_default_gensios, o);

    while (isspace(*str))
	str++;
    for (r = reg_gensios; r; r = r->next) {
	len = strlen(r->name);
	if (strncmp(r->name, str, len) != 0 ||
			(str[len] != ',' && str[len] != '('))
	    continue;

	str += len;
	err = gensio_scan_args(&str, &argc, &args);
	if (!err)
	    err = r->handler(str, args, o, cb, user_data, gensio);
	if (args)
	    str_to_argv_free(argc, args);
	return err;
    }

    err = scan_network_port_args(str, &ai, &is_dgram, &is_port_set,
				 &argc, &args);
    if (!err) {
	if (!is_port_set) {
	    err = EINVAL;
	} else if (is_dgram) {
	    err = udp_gensio_alloc(ai, args, o, cb, user_data, gensio);
	} else {
	    err = tcp_gensio_alloc(ai, args, o, cb, user_data, gensio);
	}

	freeaddrinfo(ai);
    }

    if (args)
	str_to_argv_free(argc, args);

    return err;
}

const char *
gensio_check_tcpd_ok(int new_fd)
{
#ifdef HAVE_TCPD_H
    struct request_info req;

    request_init(&req, RQ_DAEMON, progname, RQ_FILE, new_fd, NULL);
    fromhost(&req);

    if (!hosts_access(&req))
	return "Access denied\r\n";
#endif

    return NULL;
}

struct addrinfo *
gensio_dup_addrinfo(struct gensio_os_funcs *o, struct addrinfo *iai)
{
    struct addrinfo *ai = NULL, *aic, *aip = NULL;

    while (iai) {
	aic = o->zalloc(o, sizeof(*aic));
	if (!aic)
	    goto out_nomem;
	memcpy(aic, iai, sizeof(*aic));
	aic->ai_next = NULL;
	aic->ai_addr = o->zalloc(o, iai->ai_addrlen);
	if (!aic->ai_addr) {
	    o->free(o, aic);
	    goto out_nomem;
	}
	memcpy(aic->ai_addr, iai->ai_addr, iai->ai_addrlen);
	if (iai->ai_canonname) {
	    aic->ai_canonname = gensio_strdup(o, iai->ai_canonname);
	    if (!aic->ai_canonname) {
		o->free(o, aic->ai_addr);
		o->free(o, aic);
		goto out_nomem;
	    }
	}
	if (aip) {
	    aip->ai_next = aic;
	    aip = aic;
	} else {
	    ai = aic;
	    aip = aic;
	}
	iai = iai->ai_next;
    }

    return ai;

 out_nomem:
    gensio_free_addrinfo(o, ai);
    return NULL;
}

void
gensio_free_addrinfo(struct gensio_os_funcs *o, struct addrinfo *ai)
{
    while (ai) {
	struct addrinfo *aic = ai;

	ai = ai->ai_next;
	o->free(o, aic->ai_addr);
	if (aic->ai_canonname)
	    o->free(o, aic->ai_canonname);
	o->free(o, aic);
    }
}

char *
gensio_strdup(struct gensio_os_funcs *o, const char *str)
{
    char *s;

    if (!str)
	return NULL;

    s = o->zalloc(o, strlen(str) + 1);
    if (!s)
	return NULL;
    strcpy(s, str);
    return s;
}

int
gensio_check_keyvalue(const char *str, const char *key, const char **value)
{
    unsigned int keylen = strlen(key);

    if (strncmp(str, key, keylen) != 0)
	return 0;
    if (str[keylen] != '=')
	return 0;
    *value = str + keylen + 1;
    return 1;
}

int
gensio_check_keyuint(const char *str, const char *key, unsigned int *rvalue)
{
    const char *sval;
    char *end;
    int rv = gensio_check_keyvalue(str, key, &sval);
    unsigned int value;

    if (!rv)
	return 0;

    if (!*sval)
	return -1;

    value = strtoul(sval, &end, 0);
    if (*end != '\0')
	return -1;

    *rvalue = value;
    return 1;
}

void
gensio_acc_vlog(struct gensio_accepter *acc, enum gensio_log_levels level,
		char *str, va_list args)
{
    struct gensio_loginfo info;

    info.level = level;
    info.str = str;
    va_copy(info.args, args);
    acc->cb(acc, GENSIO_ACC_EVENT_LOG, &info);
}

void
gensio_acc_log(struct gensio_accepter *acc, enum gensio_log_levels level,
	       char *str, ...)
{
    va_list args;

    va_start(args, str);
    gensio_acc_vlog(acc, level, str, args);
    va_end(args);
}
