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

/* Scan for a positive integer, and return it.  Return -1 if the
   integer was invalid.  Spaces are not handled. */
int scan_int(char *str);

/* Scan for a TCP port in the form "[hostname,]x", where the optional
 * first part is a resolvable hostname, an IPv4 octet, or an IPv6 address.
 * In the absence of a host specification, a wildcard address is used.
 * The mandatory second part is the port number or a service name. */
int scan_tcp_port(char *str, int domain, struct sockaddr_storage *addr,
                  socklen_t *addr_len);

/* Search for a banner/open/close string by name. */
enum str_type { BANNER, OPENSTR, CLOSESTR, SIGNATURE };
char *find_str(char *name, enum str_type *type);

/* Search for a tracefile by name. */
char *find_tracefile(char *name);

void check_ipv6_only(int family, struct sockaddr *addr, int fd);

int port_from_in_addr(int family, struct sockaddr *addr);

/* Make sure the full contents get written, return an error if it occurs. */
int write_full(int fd, char *data, size_t count);

/* Write the data completely out, return without comment on error. */
void write_ignore_fail(int fd, char *data, size_t count);

#endif /* UTILS */
