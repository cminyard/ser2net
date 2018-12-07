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
#include <termios.h>

#include "utils.h"

int
cmpstrval(const char *s, const char *prefix, const char **val)
{
    int len = strlen(prefix);

    if (strncmp(s, prefix, len))
	return 0;
    *val = s + len;

    return 1;
}

void
str_to_argv_free(int argc, char **argv)
{
    if (!argv)
	return;
    if (argv[argc + 1])
	free(argv[argc + 1]);
    if (argv[argc + 2])
	free(argv[argc + 2]);
    free(argv);
}

static bool
is_sep_space(char c, char *seps)
{
    return c && strchr(seps, c);
}

static char *
skip_spaces(char *s, char *seps)
{
    while (is_sep_space(*s, seps))
	s++;
    return s;
}

static bool
isodigit(char c)
{
    return isdigit(c) && c != '8' && c != '9';
}

static int
gettok(char **s, char **tok, char *seps, unsigned int *len, char *endchars)
{
    char *t = skip_spaces(*s, seps);
    char *p = t;
    char *o = t;
    char inquote = '\0';
    unsigned int escape = 0;
    unsigned int base = 8;
    char cval = 0;

    if (!*t || strchr(endchars, *t)) {
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
	} else if (!inquote) {
	    if (is_sep_space(*p, seps)) {
		p++;
		break;
	    } else if (strchr(endchars, *p)) {
		/* Don't skip endchars. */
		break;
	    } else {
		*o++ = *p;
	    }
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
	return EINVAL;

    *o = '\0';
    if (len)
	*len = o - t;
    *tok = t;
    return 0;
}

int
str_to_argv_lengths_endchar(const char *ins, int *r_argc, char ***r_argv,
			    unsigned int **r_lengths, char *seps,
			    char *endchars, const char **nextptr)
{
    char *orig_s = strdup(ins);
    unsigned int *lengths = NULL;
    char *s = orig_s;
    char **argv = NULL;
    char *tok;
    unsigned int argc = 0;
    unsigned int args = 0;
    unsigned int len;
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
    if (r_lengths) {
	lengths = malloc(sizeof(*lengths) * args);
	if (!lengths) {
	    free(argv);
	    free(orig_s);
	    return ENOMEM;
	}
    }

    err = gettok(&s, &tok, seps, &len, endchars);
    while (tok && !err) {
	/*
	 * Leave one spot at the end for the NULL and one for the
	 * pointer to the allocated string and one for the lengths
	 * array.
	 */
	if (argc >= args - 3) {
	    char **nargv;

	    args += 10;
	    nargv = realloc(argv, sizeof(*argv) * args);
	    if (!nargv) {
		err = ENOMEM;
		goto out;
	    }
	    if (r_lengths) {
		unsigned int *nlengths = realloc(lengths,
						 sizeof(*lengths) * args);

		if (!nlengths) {
		    err = ENOMEM;
		    goto out;
		}
		lengths = nlengths;
	    }
	    argv = nargv;
	}
	if (lengths)
	    lengths[argc] = len;
	argv[argc++] = tok;

	err = gettok(&s, &tok, seps, &len, endchars);
    }

    argv[argc] = NULL; /* NULL terminate the array. */
    argv[argc + 1] = orig_s; /* Keep this around for freeing. */
    argv[argc + 2] = (void *) lengths; /* Keep this around for freeing. */

 out:
    if (err) {
	free(orig_s);
	free(argv);
	if (lengths)
	    free(lengths);
    } else {
	if (r_argc)
	    *r_argc = argc;
	*r_argv = argv;
	if (r_lengths)
	    *r_lengths = lengths;
	if (nextptr) {
	    if (strchr(endchars, *s))
		*nextptr = ins + (s - orig_s) + 1;
	    else
		*nextptr = NULL;
	}
    }
    return err;
}

int
str_to_argv_lengths(const char *ins, int *r_argc, char ***r_argv,
		    unsigned int **r_lengths, char *seps)
{
    return str_to_argv_lengths_endchar(ins, r_argc, r_argv, r_lengths,
				       seps, "", NULL);
}

int
str_to_argv(const char *ins, int *r_argc, char ***r_argv, char *seps)
{
    return str_to_argv_lengths(ins, r_argc, r_argv, NULL, seps);
}

int
lookup_enum(struct enum_val *enums, const char *str, int len)
{
    while (enums->str != NULL) {
	if (len == -1 && strcmp(enums->str, str) == 0)
	    return enums->val;
	if (strlen(enums->str) == len && strncmp(enums->str, str, len) == 0)
	    return enums->val;
	enums++;
    }
    return -1;
}

int
cmp_timeval(struct timeval *tv1, struct timeval *tv2)
{
    if (tv1->tv_sec > tv2->tv_sec)
	return 1;
    else if (tv1->tv_sec < tv2->tv_sec)
	return -1;
    else if (tv1->tv_usec > tv2->tv_usec)
	return 1;
    else if (tv1->tv_usec < tv2->tv_usec)
	return -1;
    else
	return 0;
}

void
add_to_timeval(struct timeval *tv1, struct timeval *tv2)
{
    tv1->tv_sec += tv2->tv_sec;
    tv1->tv_usec += tv2->tv_usec;
    while (tv1->tv_usec > 1000000) {
	tv1->tv_usec -= 1000000;
	tv1->tv_sec += 1;
    }
    while (tv1->tv_usec < 0) {
	tv1->tv_usec += 1000000;
	tv1->tv_sec -= 1;
    }
}
