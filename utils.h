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

#ifndef UTILS
#define UTILS

#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

/* Scan for a positive integer, and return it.  Return -1 if the
   integer was invalid.  Spaces are not handled. */
int scan_int(char *str);

/* Scan for a TCP port in the form "[hostname,]x", where the optional
 * first part is a resolvable hostname, an IPv4 octet, or an IPv6 address.
 * In the absence of a host specification, a wildcard address is used.
 * The mandatory second part is the port number or a service name. */
int scan_tcp_port(char *str, struct addrinfo **ai);

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
int *open_socket(struct addrinfo *ai, void (*readhndlr)(int, void *),
		 void *data, unsigned int *nr_fds);

/*
 * Search for a banner/open/close string by name.  Note that the
 * returned value needs to be free-ed when done.
 */
enum str_type { BANNER, OPENSTR, CLOSESTR, SIGNATURE };
char *find_str(const char *name, enum str_type *type);

/*
 * Search for a tracefile by name.  Note that the
 * returned value needs to be free-ed when done.
 */
char *find_tracefile(const char *name);

/* Search for RS485 configuration by name. */
struct serial_rs485 *find_rs485conf(const char *name);

void check_ipv6_only(int family, struct sockaddr *addr, int fd);

/* Make sure the full contents get written, return an error if it occurs. */
int write_full(int fd, char *data, size_t count);

/* Write the data completely out, return without comment on error. */
void write_ignore_fail(int fd, const char *data, size_t count);

#endif /* UTILS */
