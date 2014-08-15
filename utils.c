/*
 *  ser2net - A program for allowing telnet connection to serial ports
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

/* This file holds basic utilities used by the ser2net program. */

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "ser2net.h"
#include "utils.h"
#include "selector.h"

/* Scan for a positive integer, and return it.  Return -1 if the
   integer was invalid. */
int
scan_int(char *str)
{
    int rv = 0;

    if (*str == '\0') {
	return -1;
    }

    for (;;) {
	switch (*str) {
	case '0': case '1': case '2': case '3': case '4':
	case '5': case '6': case '7': case '8': case '9':
	    rv = (rv * 10) + ((*str) - '0');
	    break;

	case '\0':
	    return rv;

	default:
	    return -1;
	}

	str++;
    }

    return rv;
}

/* Scan for a TCP port in the form "[hostname,]x", where the optional
   first part is a resolvable hostname, an IPv4 octet, or an IPv6 address.
   In the absence of a host specification, a wildcard address is used.
   The mandatory second part is the port number or a service name. */
int
scan_tcp_port(char *str, struct addrinfo **rai)
{
    char *strtok_data, *strtok_buffer;
    char *ip;
    char *port;
    struct addrinfo hints, *ai;

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
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(ip, port, &hints, &ai)) {
	free(strtok_buffer);
	return EINVAL;
    }

    free(strtok_buffer);
    if (*rai)
	freeaddrinfo(*rai);
    *rai = ai;
    return 0;
}

void
check_ipv6_only(int family, struct sockaddr *addr, int fd)
{
    if ((family == AF_INET6)
	&& IN6_IS_ADDR_UNSPECIFIED(&(((struct sockaddr_in6 *) addr)->sin6_addr)))
    {
	int null = 0;

	setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &null, sizeof(null));
    }
}

int *
open_socket(struct addrinfo *ai, void (*readhndlr)(int, void *), void *data,
	    unsigned int *nr_fds)
{
    struct addrinfo *rp;
    int optval = 1;
    int family = AF_INET6; /* Try IPV6 first, then IPV4. */
    int *fds;
    unsigned int curr_fd = 0;
    unsigned int max_fds = 0;

    for (rp = ai; rp != NULL; rp = rp->ai_next)
	max_fds++;

    fds = malloc(sizeof(int) * max_fds);
    if (!fds)
	return NULL;

  restart:
    for (rp = ai; rp != NULL; rp = rp->ai_next) {
	if (family != rp->ai_family)
	    continue;

	fds[curr_fd] = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
	if (fds[curr_fd] == -1)
	    continue;

	if (fcntl(fds[curr_fd], F_SETFL, O_NONBLOCK) == -1)
	    goto next;

	if (setsockopt(fds[curr_fd], SOL_SOCKET, SO_REUSEADDR,
		       (void *)&optval, sizeof(optval)) == -1)
	    goto next;

	check_ipv6_only(rp->ai_family, rp->ai_addr, fds[curr_fd]);

	if (bind(fds[curr_fd], rp->ai_addr, rp->ai_addrlen) != 0)
	    goto next;

	if (listen(fds[curr_fd], 1) != 0)
	    goto next;

	sel_set_fd_handlers(ser2net_sel, fds[curr_fd], data,
			    readhndlr, NULL, NULL);
	sel_set_fd_read_handler(ser2net_sel, fds[curr_fd],
				SEL_FD_HANDLER_ENABLED);
	curr_fd++;
	continue;

      next:
	close(fds[curr_fd]);
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

int
write_full(int fd, char *data, size_t count)
{
    ssize_t written;

 restart:
    while ((written = write(fd, data, count)) > 0) {
	data += written;
	count -= written;
    }
    if (written < 0) {
	if (errno == EAGAIN)
	    goto restart;
	return -1;
    }
    return 0;
}

void
write_ignore_fail(int fd, const char *data, size_t count)
{
    ssize_t written;

    while ((written = write(fd, data, count)) > 0) {
	data += written;
	count -= written;
    }
}
