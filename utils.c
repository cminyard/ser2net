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
#include <netinet/in.h>
#include <arpa/inet.h>

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

/* Scan for a TCP port in the form "[x.x.x.x,]x" where the first part is
   the IP address (options, defaults to INADDR_ANY) and the second part
   is the port number (required). */
int
scan_tcp_port(char *str, struct sockaddr_in *addr)
{
    char *strtok_data;
    char *ip;
    char *port;
    int  port_num;

    ip = strtok_r(str, ",", &strtok_data);
    port = strtok_r(NULL, "", &strtok_data);
    if (port == NULL) {
	port = ip;
	ip = NULL;
	addr->sin_addr.s_addr = INADDR_ANY;
	port_num = scan_int(port);
	if (port_num == -1) {
	    return -1;
	}
	addr->sin_port = htons(port_num);
    } else {
	/* Both an IP and port were specified. */
	addr->sin_addr.s_addr = inet_addr(ip);
	if (addr->sin_addr.s_addr == INADDR_NONE) {
	    struct hostent *hp;

	    hp = gethostbyname(ip);
	    if (hp == NULL) {
		return -1;
	    }
	    if (hp->h_addrtype != AF_INET) {
		return -1;
	    }
	    memcpy(&addr->sin_addr, hp->h_addr_list[0], hp->h_length);
	}

	port_num = scan_int(port);
	if (port_num == -1) {
	    return -1;
	}
	addr->sin_port = htons(port_num);
    }
    addr->sin_family = AF_INET;

    return 0;
}
