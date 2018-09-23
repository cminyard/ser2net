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
#include <gensio/gensio_internal.h>
#include <gensio/sergensio.h>

/* FIXME - The error handling in this function isn't good, fix it. */
struct opensocks *
open_socket(struct gensio_os_funcs *o,
	    struct addrinfo *ai, void (*readhndlr)(int, void *),
	    void (*writehndlr)(int, void *), void *data,
	    unsigned int *nr_fds, void (*fd_handler_cleared)(int, void *))
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

    err = gensio_write(io, &count, buf, buflen);
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
gensio_write(struct gensio *io, unsigned int *count,
	     const void *buf, unsigned int buflen)
{
    return io->funcs->write(io, count, buf, buflen);
}

int
gensio_raddr_to_str(struct gensio *io, int *pos,
		    char *buf, unsigned int buflen)
{
    return io->funcs->raddr_to_str(io, pos, buf, buflen);
}

int
gensio_get_raddr(struct gensio *io,
		 struct sockaddr *addr, socklen_t *addrlen)
{
    if (!io->funcs->get_raddr)
	return ENOTSUP;
    return io->funcs->get_raddr(io, addr, addrlen);
}

int
gensio_remote_id(struct gensio *io, int *id)
{
    if (!io->funcs->remote_id)
	return ENOTSUP;
    return io->funcs->remote_id(io, id);
}

int
gensio_open(struct gensio *io, void (*open_done)(struct gensio *io,
						 int err,
						 void *open_data),
	   void *open_data)
{
    return io->funcs->open(io, open_done, open_data);
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
gensio_close(struct gensio *io, void (*close_done)(struct gensio *io,
						   void *close_data),
	    void *close_data)
{
    return io->funcs->close(io, close_done, close_data);
}

void
gensio_free(struct gensio *io)
{
    return io->funcs->free(io);
}

void
gensio_set_read_callback_enable(struct gensio *io, bool enabled)
{
    io->funcs->set_read_callback_enable(io, enabled);
}

void
gensio_set_write_callback_enable(struct gensio *io, bool enabled)
{
    io->funcs->set_write_callback_enable(io, enabled);
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

void *
gensio_acc_get_user_data(struct gensio_acceptor *acceptor)
{
    return acceptor->user_data;
}

void
gensio_acc_set_user_data(struct gensio_acceptor *acceptor,
			 void *user_data)
{
    acceptor->user_data = user_data;
}

void
gensio_acc_set_callback(struct gensio_acceptor *acceptor,
			gensio_acceptor_event cb,
			void *user_data)
{
    acceptor->cb = cb;
    acceptor->user_data = user_data;
}

int
gensio_acc_startup(struct gensio_acceptor *acceptor)
{
    return acceptor->funcs->startup(acceptor);
}

int
gensio_acc_shutdown(struct gensio_acceptor *acceptor,
		    void (*shutdown_done)(struct gensio_acceptor *acceptor,
					  void *shutdown_data),
		    void *shutdown_data)
{
    return acceptor->funcs->shutdown(acceptor, shutdown_done, shutdown_data);
}

void
gensio_acc_set_accept_callback_enable(struct gensio_acceptor *acceptor,
				      bool enabled)
{
    acceptor->funcs->set_accept_callback_enable(acceptor, enabled);
}

void
gensio_acc_free(struct gensio_acceptor *acceptor)
{
    acceptor->funcs->free(acceptor);
}

int
gensio_acc_connect(struct gensio_acceptor *acceptor, void *addr,
		   void (*connect_done)(struct gensio *io, int err,
					void *cb_data),
		   void *cb_data, struct gensio **new_io)
{
    if (!acceptor->funcs->connect)
	return ENOTSUP;
    return acceptor->funcs->connect(acceptor, addr, connect_done, cb_data,
				    new_io);
}

bool
gensio_acc_exit_on_close(struct gensio_acceptor *acceptor)
{
    return acceptor->type == GENSIO_TYPE_STDIO;
}

bool
gensio_acc_is_reliable(struct gensio_acceptor *acceptor)
{
    return acceptor->is_reliable;
}

bool
gensio_acc_is_packet(struct gensio_acceptor *acceptor)
{
    return acceptor->is_packet;
}

static int
gensio_process_acc_filter(const char *str, enum gensio_type type,
			  struct gensio_os_funcs *o,
			  gensio_acceptor_event cb, void *user_data,
			  struct gensio_acceptor **acceptor)
{
    int err = 0;
    struct gensio_acceptor *acc = NULL, *acc2 = NULL;
    int argc;
    char **args = NULL;
    const char *name = str;

    err = gensio_scan_args(&str, &argc, &args);
    if (!err)
	err = str_to_gensio_acceptor(str, o, NULL, NULL, &acc2);
    if (!err) {
	if (type == GENSIO_TYPE_SSL) {
	    err = ssl_gensio_acceptor_alloc(name, args, o, acc2,
					   cb, user_data, &acc);
	} else if (type == GENSIO_TYPE_SER_TELNET) {
	    err = sergensio_telnet_acceptor_alloc(name, args, o, acc2,
						  cb, user_data, &acc);
	} else {
	    err = EINVAL;
	}
    }

    if (args)
	str_to_argv_free(argc, args);

    if (err) {
	if (acc)
	    gensio_acc_free(acc);
	else if (acc2)
	    gensio_acc_free(acc2);
    } else {
	*acceptor = acc;
    }

    return err;
}

int str_to_gensio_acceptor(const char *str,
			   struct gensio_os_funcs *o,
			   gensio_acceptor_event cb, void *user_data,
			   struct gensio_acceptor **acceptor)
{
    int err;
    struct addrinfo *ai = NULL;
    bool is_dgram, is_port_set;
    char *dummy_args[1] = { NULL };
    int argc;
    char **args = NULL;

    while (isspace(*str))
	str++;
    if (strisallzero(str)) {
	err = stdio_gensio_acceptor_alloc(dummy_args, o, cb, user_data,
					  acceptor);
    } else if (strncmp(str, "stdio,", 6) == 0 ||
	       strncmp(str, "stdio(", 6) == 0) {
	str += 5;
	err = gensio_scan_args(&str, &argc, &args);
	if (!err)
	    err = stdio_gensio_acceptor_alloc(args, o, cb, user_data,
					      acceptor);
    } else if (strncmp(str, "ssl,", 4) == 0 ||
	       strncmp(str, "ssl(", 4) == 0) {
	err = gensio_process_acc_filter(str + 3, GENSIO_TYPE_SSL, o,
					cb, user_data, acceptor);
    } else if (strncmp(str, "telnet,", 7) == 0 ||
	       strncmp(str, "telnet(", 7) == 0) {
	err = gensio_process_acc_filter(str + 6, GENSIO_TYPE_SER_TELNET, o,
					cb, user_data, acceptor);
    } else {
	err = scan_network_port_args(str, &ai, &is_dgram, &is_port_set,
				     &argc, &args);
	if (!err) {
	    if (!is_port_set) {
		err = EINVAL;
	    } else if (is_dgram) {
		err = udp_gensio_acceptor_alloc(str, args, o, ai, cb,
						user_data, acceptor);
	    } else {
		err = tcp_gensio_acceptor_alloc(str, args, o, ai, cb,
						user_data, acceptor);
	    }

	    freeaddrinfo(ai);
	}
    }

    if (args && args != dummy_args)
	str_to_argv_free(argc, args);

    return err;
}

static int
gensio_process_filter(const char *str,
		      enum gensio_type type,
		      struct gensio_os_funcs *o,
		      gensio_event cb, void *user_data,
		      struct gensio **gensio)
{
    int err = 0;
    struct gensio *io = NULL, *io2 = NULL;
    struct sergensio *sio = NULL;
    int argc;
    char **args;

    err = gensio_scan_args(&str, &argc, &args);
    if (!err)
	err = str_to_gensio(str, o, NULL, NULL, &io2);
    if (!err) {
	if (type == GENSIO_TYPE_SER_TELNET) {
	    err = sergensio_telnet_alloc(io2, args, o, NULL, cb, user_data,
					 &sio);
	    if (!err)
		io = sergensio_to_gensio(sio);
	} else if (type == GENSIO_TYPE_SSL) {
	    err = ssl_gensio_alloc(io2, args, o, cb, user_data, &io);
	} else {
	    err = EINVAL;
	}
    }

    if (args)
	str_to_argv_free(argc, args);

    if (err) {
	if (io)
	    gensio_free(io);
	else if (io2)
	    gensio_free(io2);
    } else {
	*gensio = io;
    }

    return err;
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

    while (isspace(*str))
	str++;
    if (strncmp(str, "stdio,", 6) == 0
		|| strncmp(str, "stdio(", 6) == 0) {
	int sargc;
	char **sargv;

	str += 5;
	err = gensio_scan_args(&str, &argc, &args);
	if (!err)
	    err = str_to_argv(str, &sargc, &sargv, NULL);
	if (!err)
	    err = stdio_gensio_alloc(sargv, args, o, cb, user_data, gensio);
	str_to_argv_free(sargc, sargv);
    } else if (strncmp(str, "telnet,", 7) == 0 ||
	       strncmp(str, "telnet(", 7) == 0) {
	err = gensio_process_filter(str + 6, GENSIO_TYPE_SER_TELNET, o,
				    cb, user_data, gensio);
    } else if (strncmp(str, "ssl,", 4) == 0 ||
	       strncmp(str, "ssl(", 4) == 0) {
	err = gensio_process_filter(str + 3, GENSIO_TYPE_SSL, o,
				    cb, user_data, gensio);
    } else if (strncmp(str, "termios,", 8) == 0 ||
	       strncmp(str, "termios(", 8) == 0) {
	struct sergensio *sio;

	str += 7;
	err = gensio_scan_args(&str, &argc, &args);
	if (!err)
	    err = sergensio_termios_alloc(str, args, o, NULL,
					  cb, user_data, &sio);
	if (!err)
	    *gensio = sergensio_to_gensio(sio);
    } else {
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
    }

    if (args)
	str_to_argv_free(argc, args);

    return err;
}

bool
gensio_match_type(struct gensio *io, enum gensio_type *types)
{
    while (*types) {
	if (io->type == *types)
	    return true;
	types++;
    }
    return false;
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
