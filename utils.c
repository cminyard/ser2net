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

#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>

#include "utils.h"

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
scan_tcp_port(char *str, int domain,
	      struct sockaddr_storage *addr, socklen_t *addr_len)
{
    char *strtok_data;
    char *ip;
    char *port;
    struct addrinfo hints, *ai;

    memset(addr, 0, sizeof(*addr));

    ip = strtok_r(str, ",", &strtok_data);
    port = strtok_r(NULL, "", &strtok_data);
    if (port == NULL) {
	port = ip;
	ip = NULL;
    }
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = domain;
    if (getaddrinfo(ip, port, &hints, &ai))
	return -1;

    memcpy(addr, ai->ai_addr, ai->ai_addrlen);
    *addr_len = ai->ai_addrlen;
    freeaddrinfo(ai);
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

int
port_from_in_addr(int family, struct sockaddr *addr)
{
    switch (family) {
    case AF_INET6:
	return ((struct sockaddr_in6 *) addr)->sin6_port;

    case AF_INET:
    default:
	return ((struct sockaddr_in *) addr)->sin_port;
    }
}

int
write_full(int fd, char *data, size_t count)
{
    size_t written;

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
write_ignore_fail(int fd, char *data, size_t count)
{
    ssize_t written;

    while ((written = write(fd, data, count)) > 0) {
	data += written;
	count -= written;
    }
}
