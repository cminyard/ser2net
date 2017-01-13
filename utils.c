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
#include <ctype.h>

#include "ser2net.h"
#include "utils.h"
#include "selector.h"
#include "locking.h"

int
strisallzero(char *str)
{
    if (*str == '\0')
	return 0;

    while (*str == '0')
	str++;
    return *str == '\0';
}

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

/* Scan for a network port in the form "[hostname,]x", where the optional
   first part is a resolvable hostname, an IPv4 octet, or an IPv6 address.
   In the absence of a host specification, a wildcard address is used.
   The mandatory second part is the port number or a service name. */
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
sockaddr_equal(struct sockaddr *a1, socklen_t l1,
	       struct sockaddr *a2, socklen_t l2,
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

struct opensocks *
open_socket(struct addrinfo *ai, void (*readhndlr)(int, void *),
	    void (*writehndlr)(int, void *), void *data,
	    unsigned int *nr_fds, void (*fd_handler_cleared)(int, void *))
{
    struct addrinfo *rp;
    int optval = 1;
    int family = AF_INET6; /* Try IPV6 first, then IPV4. */
    struct opensocks *fds;
    unsigned int curr_fd = 0;
    unsigned int max_fds = 0;

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

	sel_set_fd_handlers(ser2net_sel, fds[curr_fd].fd, data,
			    readhndlr, writehndlr, NULL, fd_handler_cleared);
	sel_set_fd_read_handler(ser2net_sel, fds[curr_fd].fd,
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

int
net_write(int fd, const void *buf, size_t len, int flags,
	  const struct sockaddr *addr, socklen_t addrlen)
{
    if (addr)
	return sendto(fd, buf, len, flags, addr, addrlen);
    else
	return write(fd, buf, len);
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

void str_to_argv_free(int argc, char **argv)
{
    int i;

    if (!argv)
	return;
    for (i = 0; i < argc; i++) {
	if (argv[i])
	    free(argv[i]);
    }
    free(argv);
}

enum state {
    in_space,
    in_parm,
    in_squote,
    in_dquote,
    in_bs, in_bs_hex, in_bs_hex2, in_bs_oct2, in_bs_oct3
};

static int add_to_parm(char **parm, size_t *parmlen, size_t *parmpos, char c)
{
    if (*parmpos >= *parmlen) {
	char *new_parm = realloc(*parm, *parmlen + 10);
	if (!new_parm)
	    return ENOMEM;
	*parmlen += 10;
	*parm = new_parm;
    }

    (*parm)[*parmpos] = c;
    (*parmpos)++;
    return 0;
}

static int add_parm(int *argc, int *argc_max, char ***argv,
		    char *parm, size_t len)
{
    char *s;

    if (*argc >= *argc_max) {
	char **new_argv = realloc(*argv, *argc_max + (10 * sizeof(char *)));
	if (!new_argv)
	    return ENOMEM;
	*argv = new_argv;
	*argc_max += 10;
    }

    s = malloc(len + 1);
    if (!s)
	return ENOMEM;
    memcpy(s, parm, len);
    s[len] = '\0';
    (*argv)[*argc] = s;
    (*argc)++;
    return 0;
}

int fromxdigit(char c)
{
    if (c >= '0' && c <= '9')
	return c - '0';
    else if (c >= 'a' && c <= 'f')
	return c - 'a' + 10;
    else
	return c - 'A' + 10;
}

int str_to_argv(const char *s, int *r_argc, char ***r_argv, char *seps)
{
    int argc = 0;
    int argc_max = 0;
    char **argv = NULL;
    enum state state, prev_state = in_parm, prev_bs_state = in_parm;
    char *parm = NULL;
    size_t parmlen = 0;
    size_t parmpos = 0;
    int rv = 0;
    int c = 0;

    if (!seps)
	seps = " \f\n\r\t\v";

    state = in_space;
    for (; *s; s++) {
	switch (state) {
	case in_space:
	    if (strchr(seps, *s))
		break;
	    parmpos = 0;
	    if (*s == '\'') {
		prev_state = state;
		state = in_squote;
	    } else if (*s == '"') {
		prev_state = state;
		state = in_dquote;
	    } else if (*s == '\\') {
		prev_bs_state = state;
		state = in_bs;
	    } else {
		rv = add_to_parm(&parm, &parmlen, &parmpos, *s);
		if (rv)
		    goto err;
		state = in_parm;
	    }
	    break;

	case in_parm:
	    if (strchr(seps, *s)) {
		rv = add_parm(&argc, &argc_max, &argv, parm, parmpos);
		if (rv)
		    goto err;
		state = in_space;
	    } else if (*s == '\'') {
		prev_state = state;
		state = in_squote;
	    } else if (*s == '"') {
		prev_state = state;
		state = in_dquote;
	    } else if (*s == '\\') {
		prev_bs_state = state;
		state = in_bs;
	    } else {
		rv = add_to_parm(&parm, &parmlen, &parmpos, *s);
		if (rv)
		    goto err;
	    }
	    break;

	case in_squote:
	    if (*s == '\'') {
		state = prev_state;
	    } else if (*s == '\\') {
		prev_bs_state = state;
		state = in_bs;
	    } else {
		rv = add_to_parm(&parm, &parmlen, &parmpos, *s);
		if (rv)
		    goto err;
	    }
	    break;

	case in_dquote:
	    if (*s == '"') {
		state = prev_state;
	    } else if (*s == '\\') {
		prev_bs_state = state;
		state = in_bs;
	    } else {
		rv = add_to_parm(&parm, &parmlen, &parmpos, *s);
		if (rv)
		    goto err;
	    }
	    break;

	case in_bs:
	    switch (*s) {
	    case '\\': c = '\\'; break;
	    case 'a': c = '\a'; break;
	    case 'b': c = '\b'; break;
	    case 'e': c = '\e'; break;
	    case 'f': c = '\f'; break;
	    case 'n': c = '\n'; break;
	    case 'r': c = '\r'; break;
	    case 't': c = '\t'; break;
	    case 'v': c = '\v'; break;
	    case 'x':
		c = 0;
		state = in_bs_hex;
		break;
	    case '0': case '1': case '2': case '3': case '4':
	    case '5': case '6': case '7': case '8': case '9':
		c = *s - '0';
		if (*(s + 1) >= '0' && *(s + 1) <= '7')
		    state = in_bs_oct2;
		else
		    goto add_parm_c;
		break;
	    }
	    if (state == in_bs)
		goto add_parm_c;
	    break;

	case in_bs_hex:
	    if (!isxdigit(*s)) {
		rv = -EINVAL;
		goto err;
	    }
	    c = fromxdigit(*s);
	    if (isxdigit(*(s + 1)))
		state = in_bs_hex2;
	    else
		goto add_parm_c;
	    break;

	case in_bs_hex2:
	    c = (c * 16) + fromxdigit(*s);
	    goto add_parm_c;

	case in_bs_oct2:
	    c = (c * 8) + (*s - '0');
	    if (*(s + 1) >= '0' && *(s + 1) <= '7')
		state = in_bs_oct3;
	    else
		goto add_parm_c;
	    break;

	case in_bs_oct3:
	    c = (c * 8) + (*s - '0');
	    goto add_parm_c;
	}
	continue;

    add_parm_c:
	rv = add_to_parm(&parm, &parmlen, &parmpos, c);
	if (rv)
	    goto err;
	state = prev_bs_state;
    }

    switch (state) {
    case in_space:
	break;

    case in_parm:
	rv = add_parm(&argc, &argc_max, &argv, parm, parmpos);
	break;

    default:
	rv = -EINVAL;
    }

 err:
    free(parm);
    if (rv) {
	str_to_argv_free(argc, argv);
    } else {
	*r_argc = argc;
	*r_argv = argv;
    }
    return rv;
}

#include <assert.h>

#ifdef USE_PTHREADS
struct waiter_s {
    int set;
    pthread_mutex_t lock;
    pthread_cond_t cond;
};

waiter_t *alloc_waiter(void)
{
    waiter_t *waiter;

    waiter = malloc(sizeof(waiter_t));
    if (waiter) {
	memset(waiter, 0, sizeof(*waiter));
	pthread_mutex_init(&waiter->lock, NULL);
	pthread_cond_init(&waiter->cond, NULL);
    }
    return waiter;
}

void free_waiter(waiter_t *waiter)
{
    assert(waiter);
    assert(waiter->set == 0);
    pthread_mutex_destroy(&waiter->lock);
    pthread_cond_destroy(&waiter->cond);
    free(waiter);
}

void wait_for_waiter(waiter_t *waiter)
{
    pthread_mutex_lock(&waiter->lock);
    if (!waiter->set)
	pthread_cond_wait(&waiter->cond, &waiter->lock);
    waiter->set = 0;
    pthread_mutex_unlock(&waiter->lock);
}

void wake_waiter(waiter_t *waiter)
{
    pthread_mutex_lock(&waiter->lock);
    pthread_cond_signal(&waiter->cond);
    waiter->set = 1;
    pthread_mutex_unlock(&waiter->lock);
}
#else
struct waiter_s {
    int set;
};

waiter_t *alloc_waiter(void)
{
    waiter_t *waiter;

    waiter = malloc(sizeof(waiter_t));
    if (waiter)
	memset(waiter, 0, sizeof(*waiter));
    return waiter;
}

void free_waiter(waiter_t *waiter)
{
    assert(waiter);
    assert(waiter->set == 0);
    free(waiter);
}

void wait_for_waiter(waiter_t *waiter)
{
    assert(waiter->set == 1);
    waiter->set = 0;
}

void wake_waiter(waiter_t *waiter)
{
    waiter->set = 1;
}
#endif
