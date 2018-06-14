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
#include "selector.h"

/* Returns true if the string is a numeric zero, false if not. */
int strisallzero(const char *str);

int cmpstrval(const char *s, const char *prefix, unsigned int *end);

/* Scan for a positive integer, and return it.  Return -1 if the
   integer was invalid.  Spaces are not handled. */
int scan_int(char *str);

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
waiter_t *alloc_waiter(struct selector_s *sel, int wake_sig);
void free_waiter(waiter_t *waiter);
void wait_for_waiter(waiter_t *waiter, unsigned int count);
void wake_waiter(waiter_t *waiter);

struct absout {
    int (*out)(struct absout *e, const char *str, ...);
    void *data;
};

#endif /* UTILS */
