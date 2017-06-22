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
#include <stdbool.h>

/*
 * Compare two sockaddr structure and return TRUE if they are equal
 * and FALSE if not.  Only works for AF_INET4 and AF_INET6.
 * If a2->sin_port is zero, then the port comparison is ignored.
 */
bool sockaddr_equal(struct sockaddr *a1, socklen_t l1,
		    struct sockaddr *a2, socklen_t l2,
		    bool compare_ports);

/* Returns true if the string is a numeric zero, false if not. */
int strisallzero(char *str);

/* Scan for a positive integer, and return it.  Return -1 if the
   integer was invalid.  Spaces are not handled. */
int scan_int(char *str);

/* Scan for a network port in the form "[hostname,]x", where the optional
 * first part is a resolvable hostname, an IPv4 octet, or an IPv6 address.
 * In the absence of a host specification, a wildcard address is used.
 * The mandatory second part is the port number or a service name. */
int scan_network_port(const char *str, struct addrinfo **ai, bool *is_dgram,
		      bool *is_port_set);

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
struct opensocks *
open_socket(struct addrinfo *ai, void (*readhndlr)(int, void *),
	    void (*writehndlr)(int, void *), void *data,
	    unsigned int *nr_fds,
	    void (*fd_handler_cleared)(int, void *));

/*
 * Search for a banner/open/close string by name.  Note that the
 * returned value needs to be free-ed when done.
 */
enum str_type { BANNER, OPENSTR, CLOSESTR, SIGNATURE, CLOSEON, DEVNAME };
char *find_str(const char *name, enum str_type *type, unsigned int *len);

/*
 * Clean up longstrings.
 */
void free_longstrs(void);
void free_tracefiles(void);
void free_rs485confs(void);

/*
 * Search for a tracefile by name.  Note that the
 * returned value needs to be free-ed when done.
 */
char *find_tracefile(const char *name);

/* Search for RS485 configuration by name. */
struct serial_rs485 *find_rs485conf(const char *name);

void check_ipv6_only(int family, struct sockaddr *addr, int fd);

/* Do a sendto if an address is provided, a write if not. */
int net_write(int fd, const void *buf, size_t len, int flags,
	      const struct sockaddr *addr, socklen_t addrlen);

/* Make sure the full contents get written, return an error if it occurs. */
int write_full(int fd, char *data, size_t count);

/* Write the data completely out, return without comment on error. */
void write_ignore_fail(int fd, const char *data, size_t count);

/* Convert a string holding a baud rate into the numeric baud rate.
   Returns -1 on an invalid value. */
int speedstr_to_speed(const char *speed);

enum parity_vals { PARITY_NONE, PARITY_EVEN, PARITY_ODD,
		   PARITY_MARK, PARITY_SPACE };
enum parity_vals lookup_parity(const char *str);

/* Return the default int value for the given name. */
int find_default_int(const char *name);

/* Return the default string value for the given name.  Return NULL if
   out of memory.  The returned value must be freed. */
char *find_default_str(const char *name);

/* Separate out a string into an argv array, returning the argc/argv
   values given.  Returns -ENOMEM when out of memory or -EINVAL if
   there is something wrong with the string.  seps is a list of
   separators, parameters will be separated by that vlaue.  If seps is
   NULL it will default to the equivalent of isspace().  The argv
   array must be freed with str_to_argv_free(). */
int str_to_argv(const char *s, int *argc, char ***argv, char *seps);

/* Free the return of str_to_argv */
void str_to_argv_free(int argc, char **argv);

/* Tools to wait for events. */
typedef struct waiter_s waiter_t;
waiter_t *alloc_waiter(void);
void free_waiter(waiter_t *waiter);
void wait_for_waiter(waiter_t *waiter);
void wake_waiter(waiter_t *waiter);

struct absout {
    int (*out)(struct absout *e, const char *str, ...);
    void *data;
};

#endif /* UTILS */
