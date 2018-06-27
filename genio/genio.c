/*
 *  ser2net - A program for allowing telnet connection to serial ports
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
#include "utils/utils.h"
#include "genio.h"
#include "genio_internal.h"

/* FIXME - The error handling in this function isn't good, fix it. */
struct opensocks *
open_socket(struct selector_s *sel,
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

    fds = malloc(sizeof(*fds) * max_fds);
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

	rv = sel_set_fd_handlers(sel, fds[curr_fd].fd, data,
				 readhndlr, writehndlr, NULL,
				 fd_handler_cleared);
	if (rv)
	    goto next;
	sel_set_fd_read_handler(sel, fds[curr_fd].fd,
				SEL_FD_HANDLER_ENABLED);
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
	free(fds);
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
scan_network_port(const char *str, struct addrinfo **rai, bool *is_dgram,
		  bool *is_port_set)
{
    char *strtok_data, *strtok_buffer;
    char *ip;
    char *port;
    struct addrinfo hints, *ai;
    int family = AF_UNSPEC;
    int socktype = SOCK_STREAM;

    if (strncmp(str, "ipv4,", 5) == 0) {
	family = AF_INET;
	str += 5;
    } else if (strncmp(str, "ipv6,", 5) == 0) {
	family = AF_INET6;
	str += 5;
    }

    if (strncmp(str, "tcp,", 4) == 0) {
	str += 4;
    } else if (strncmp(str, "udp,", 4) == 0) {
	/* Only allow UDP if asked for. */
	if (!is_dgram)
	    return EINVAL;
	socktype = SOCK_DGRAM;
	str += 4;
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
genio_buffer_do_write(void *cb_data, void  *buf, size_t buflen, size_t *written)
{
    struct genio *net = cb_data;
    int err = 0;
    unsigned int count;

    err = genio_write(net, &count, buf, buflen);
    if (!err)
	*written = count;

    return err;
}

void
genio_set_callbacks(struct genio *net,
		    const struct genio_callbacks *cbs, void *user_data)
{
    net->cbs = cbs;
    net->user_data = user_data;
}

void *
genio_get_user_data(struct genio *net)
{
    return net->user_data;
}

void
genio_set_user_data(struct genio *net, void *user_data)
{
    net->user_data = user_data;
}

int
genio_write(struct genio *net, unsigned int *count,
	    const void *buf, unsigned int buflen)
{
    return net->funcs->write(net, count, buf, buflen);
}

int
genio_raddr_to_str(struct genio *net, int *pos,
		       char *buf, unsigned int buflen)
{
    return net->funcs->raddr_to_str(net, pos, buf, buflen);
}

socklen_t
genio_get_raddr(struct genio *net,
		struct sockaddr *addr, socklen_t addrlen)
{
    if (net->funcs->get_raddr)
	return net->funcs->get_raddr(net, addr, addrlen);
    else
	return ENOTSUP;
}

int
genio_open(struct genio *net)
{
    return net->funcs->open(net);
}

int
genio_close(struct genio *net, void (*close_done)(struct genio *net))
{
    return net->funcs->close(net, close_done);
}

void
genio_free(struct genio *net)
{
    return net->funcs->free(net);
}

void
genio_set_read_callback_enable(struct genio *net, bool enabled)
{
    net->funcs->set_read_callback_enable(net, enabled);
}

void
genio_set_write_callback_enable(struct genio *net, bool enabled)
{
    net->funcs->set_write_callback_enable(net, enabled);
}

void *
genio_acceptor_get_user_data(struct genio_acceptor *acceptor)
{
    return acceptor->user_data;
}

void
genio_acceptor_set_user_data(struct genio_acceptor *acceptor,
			     void *user_data)
{
    acceptor->user_data = user_data;
}

int
genio_acc_startup(struct genio_acceptor *acceptor)
{
    return acceptor->funcs->startup(acceptor);
}

int
genio_acc_shutdown(struct genio_acceptor *acceptor,
		   void (*shutdown_done)(struct genio_acceptor *acceptor))
{
    return acceptor->funcs->shutdown(acceptor, shutdown_done);
}

void
genio_acc_set_accept_callback_enable(struct genio_acceptor *acceptor,
				     bool enabled)
{
    acceptor->funcs->set_accept_callback_enable(acceptor, enabled);
}

void
genio_acc_free(struct genio_acceptor *acceptor)
{
    acceptor->funcs->free(acceptor);
}

bool
genio_acc_exit_on_close(struct genio_acceptor *acceptor)
{
    return acceptor->type == GENIO_TYPE_STDIO;
}

int str_to_genio_acceptor(const char *str,
			  struct selector_s *sel,
			  unsigned int max_read_size,
			  const struct genio_acceptor_callbacks *cbs,
			  void *user_data,
			  struct genio_acceptor **acceptor)
{
    int err;
    struct addrinfo *ai = NULL;
    bool is_dgram, is_port_set;

    if (strisallzero(str)) {
	err = stdio_genio_acceptor_alloc(sel, max_read_size, cbs, user_data,
					 acceptor);
    } else {
	err = scan_network_port(str, &ai, &is_dgram, &is_port_set);
	if (!err) {
	    if (!is_port_set) {
		err = EINVAL;
	    } else if (is_dgram) {
		err = udp_genio_acceptor_alloc(str, sel, ai, max_read_size, cbs,
					       user_data, acceptor);
	    } else {
		err = tcp_genio_acceptor_alloc(str, sel, ai, max_read_size, cbs,
					       user_data, acceptor);
	    }

	    if (err) {
		freeaddrinfo(ai);
	    }
	}
    }

    return err;
}

int
str_to_genio(const char *str,
	     struct selector_s *sel,
	     unsigned int max_read_size,
	     const struct genio_callbacks *cbs,
	     void *user_data,
	     struct genio **genio)
{
    int err;
    struct addrinfo *ai = NULL;
    bool is_dgram, is_port_set;

    if (strncmp(str, "stdio,", 6) == 0) {
	int argc;
	char **argv;

	err = str_to_argv(str + 6, &argc, &argv, NULL);
	if (err)
	    return err;
	err = stdio_genio_alloc(argv, sel, max_read_size, cbs, user_data,
				genio);
    } else {
	err = scan_network_port(str, &ai, &is_dgram, &is_port_set);
	if (!err) {
	    if (!is_port_set) {
		err = EINVAL;
	    } else if (is_dgram) {
		err = udp_genio_alloc(ai, sel, max_read_size, cbs,
				      user_data, genio);
	    } else {
		err = tcp_genio_alloc(ai, sel, max_read_size, cbs,
				      user_data, genio);
	    }

	    if (err) {
		freeaddrinfo(ai);
	    }
	}
    }

    return err;
}
