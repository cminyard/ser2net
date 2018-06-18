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
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>

#include "utils.h"

int
cmpstrval(const char *s, const char *prefix, unsigned int *end)
{
    int len = strlen(prefix);

    if (strncmp(s, prefix, len))
	return 0;
    *end = len;
    return 1;
}

int
strisallzero(const char *str)
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
scan_int(const char *str)
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
    if (!argv)
	return;
    if (argv[argc + 1])
	free(argv[argc + 1]);
    free(argv);
}

static bool is_sep_space(char c, char *seps)
{
    return c && strchr(seps, c);
}

static char *skip_spaces(char *s, char *seps)
{
    while (is_sep_space(*s, seps))
	s++;
    return s;
}

static bool isodigit(char c)
{
    return isdigit(c) && c != '8' && c != '9';
}

static int gettok(char **s, char **tok, char *seps)
{
    char *t = skip_spaces(*s, seps);
    char *p = t;
    char *o = t;
    char inquote = '\0';
    unsigned int escape = 0;
    unsigned int base = 8;
    char cval = 0;

    if (!*t) {
	*s = t;
	*tok = NULL;
	return 0;
    }

    for (; *p; p++) {
	if (escape) {
	    if (escape == 1) {
		cval = 0;
		if (isodigit(*p)) {
		    base = 8;
		    cval = *p - '0';
		    escape++;
		} else if (*p == 'x') {
		    base = 16;
		    escape++;
		} else {
		    switch (*p) {
		    case 'a': *o++ = '\a'; break;
		    case 'b': *o++ = '\b'; break;
		    case 'f': *o++ = '\f'; break;
		    case 'n': *o++ = '\n'; break;
		    case 'r': *o++ = '\r'; break;
		    case 't': *o++ = '\t'; break;
		    case 'v': *o++ = '\v'; break;
		    default:  *o++ = *p;
		    }
		    escape = 0;
		}
	    } else if (escape >= 2) {
		if ((base == 16 && isxdigit(*p)) || isodigit(*p)) {
		    if (isodigit(*p))
			cval = cval * base + *p - '0';
		    else if (isupper(*p))
			cval = cval * base + *p - 'A';
		    else
			cval = cval * base + *p - 'a';
		    if (escape >= 3) {
			*o++ = cval;
			escape = 0;
		    } else {
			escape++;
		    }
		} else {
		    *o++ = cval;
		    escape = 0;
		    goto process_char;
		}
	    }
	    continue;
	}
    process_char:
	if (*p == inquote) {
	    inquote = '\0';
	} else if (!inquote && (*p == '\'' || *p == '"')) {
	    inquote = *p;
	} else if (*p == '\\') {
	    escape = 1;
	} else if (!inquote && is_sep_space(*p, seps)) {
	    p++;
	    break;
	} else {
	    *o++ = *p;
	}
    }

    if ((base == 8 && escape > 1) || (base == 16 && escape > 2)) {
	*o++ = cval;
	escape = 0;
    }

    *s = p;
    if (inquote || escape)
	return -1;

    *o = '\0';
    *tok = t;
    return 0;
}

int str_to_argv(const char *ins, int *r_argc, char ***r_argv, char *seps)
{
    char *orig_s = strdup(ins);
    char *s = orig_s;
    char **argv = NULL;
    char *tok;
    unsigned int argc = 0;
    unsigned int args = 0;
    int err;

    if (!s)
	return ENOMEM;

    if (!seps)
	seps = " \f\n\r\t\v";

    args = 10;
    argv = malloc(sizeof(*argv) * args);
    if (!argv) {
	free(orig_s);
	return ENOMEM;
    }

    err = gettok(&s, &tok, seps);
    while (tok && !err) {
	/*
	 * Leave one spot at the end for the NULL and one for the
	 * pointer to the allocated string.
	 */
	if (argc >= args - 2) {
	    char **nargv = realloc(argv, sizeof(*argv) * (args + 10));

	    if (!nargv) {
		err = ENOMEM;
		goto out;
	    }
	    argv = nargv;
	    args += 10;
	}
	argv[argc++] = tok;

	err = gettok(&s, &tok, seps);
    }

    argv[argc] = NULL; /* NULL terminate the array. */
    argv[argc + 1] = orig_s; /* Keep this around for freeing. */

 out:
    if (err) {
	free(orig_s);
	free(argv);
    } else {
	*r_argc = argc;
	*r_argv = argv;
    }
    return err;
}
