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

static struct baud_rates_s {
    int real_rate;
    int val;
    const char *str;
} baud_rates[] =
{
    { 50, B50, "50" },
    { 75, B75, "75" },
    { 110, B110, "110" },
    { 134, B134, "134" },
    { 150, B150, "150" },
    { 200, B200, "200" },
    { 300, B300, "300" },
    { 600, B600, "600" },
    { 1200, B1200, "1200" },
    { 1800, B1800, "1800" },
    { 2400, B2400, "2400" },
    { 4800, B4800, "4800" },
    { 9600, B9600, "9600" },
    /* We don't support 14400 baud */
    { 19200, B19200, "19200" },
    /* We don't support 28800 baud */
    { 38400, B38400, "38400" },
    { 57600, B57600, "57600" },
    { 115200, B115200, "115200" },
#ifdef B230400
    { 230400, B230400, "230400" },
#endif
#ifdef B460800
    { 460800, B460800, "460800" },
#endif
#ifdef B500000
    { 500000, B500000, "500000" },
#endif
#ifdef B576000
    { 576000, B576000, "576000" },
#endif
#ifdef B921600
    { 921600, B921600, "921600" },
#endif
#ifdef B1000000
    { 1000000, B1000000, "1000000" },
#endif
#ifdef B1152000
    { 1152000, B1152000, "1152000" },
#endif
#ifdef B1500000
    { 1500000, B1500000, "1500000" },
#endif
#ifdef B2000000
    { 2000000, B2000000, "2000000" },
#endif
#ifdef B2500000
    { 2500000, B2500000, "2500000" },
#endif
#ifdef B3000000
    { 3000000, B3000000, "3000000" },
#endif
#ifdef B3500000
    { 3500000, B3500000, "3500000" },
#endif
#ifdef B4000000
    { 4000000, B4000000, "4000000" },
#endif
};
#define BAUD_RATES_LEN ((sizeof(baud_rates) / sizeof(struct baud_rates_s)))

int
get_baud_rate(int rate, int *val)
{
    unsigned int i;
    for (i = 0; i < BAUD_RATES_LEN; i++) {
	if (rate == baud_rates[i].real_rate) {
	    if (val)
		*val = baud_rates[i].val;
	    return 1;
	}
    }

    return 0;
}

const char *
get_baud_rate_str(int baud_rate)
{
    unsigned int i;
    for (i = 0; i < BAUD_RATES_LEN; i++) {
	if (baud_rate == baud_rates[i].val)
	    return baud_rates[i].str;
    }

    return "unknown speed";
}

void
get_rate_from_baud_rate(int baud_rate, int *val)
{
    unsigned int i;

    for (i = 0; i < BAUD_RATES_LEN; i++) {
	if (baud_rate == baud_rates[i].val) {
	    *val = baud_rates[i].real_rate;
	    return;
	}
    }

    *val = 0;
}

static struct cisco_baud_rates_s {
    int real_rate;
    int cisco_ios_val;
} cisco_baud_rates[] = {
    { 300, 3 },
    { 600 , 4},
    { 1200, 5 },
    { 2400, 6 },
    { 4800, 7 },
    { 9600, 8 },
    { 19200, 10 },
    { 38400, 12 },
    { 57600, 13 },
    { 115200, 14 },
    { 230400, 15 },
};
#define CISCO_BAUD_RATES_LEN \
    ((sizeof(cisco_baud_rates) / sizeof(struct cisco_baud_rates_s)))

int cisco_baud_to_baud(int cisco_val)
{
    unsigned int i;

    for (i = 0; i < CISCO_BAUD_RATES_LEN; i++) {
	if (cisco_val == cisco_baud_rates[i].cisco_ios_val)
	    return cisco_baud_rates[i].real_rate;
    }

    return 0;
}

int baud_to_cisco_baud(int val)
{
    unsigned int i;

    for (i = 0; i < CISCO_BAUD_RATES_LEN; i++) {
	if (val == cisco_baud_rates[i].real_rate)
	    return cisco_baud_rates[i].cisco_ios_val;
    }

    return 0;
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

struct enum_val speed_enums[] = {
    { "300",	300 },
    { "600",	600 },
    { "1200",	1200 },
    { "2400",	2400 },
    { "4800",	4800 },
    { "9600",	9600 },
    { "19200",	19200 },
    { "38400",	38400 },
    { "57600",	57600 },
    { "115200",	115200 },
    { "230400",	230400 },
    { "460800",	460800 },
    { "500000",	500000 },
    { "576000",	576000 },
    { "921600",	921600 },
    { "1000000",1000000 },
    { "1152000",1152000 },
    { "1500000",1500000 },
    { "2000000",2000000 },
    { "2500000",2500000 },
    { "3000000",3000000 },
    { "3500000",3500000 },
    { "4000000",4000000 },
    { NULL },
};

static int
speedstr_to_speed(const char *speed, const char **rest)
{
    const char *end = speed;
    unsigned int len;
    int rv;

    while (*end && isdigit(*end))
	end++;
    len = end - speed;
    if (len < 3)
	return -1;

    rv = lookup_enum(speed_enums, speed, len);
    if (rv != -1)
	*rest = end;
    return rv;
}

void
set_termios_parity(struct termios *termctl, enum parity_vals val)
{
    switch (val) {
    case PARITY_NONE:
	termctl->c_cflag &= ~(PARENB);
	break;
    case PARITY_EVEN:
    case PARITY_SPACE:
	termctl->c_cflag |= PARENB;
	termctl->c_cflag &= ~(PARODD);
#ifdef CMSPAR
	if (val == PARITY_SPACE)
	    termctl->c_cflag |= CMSPAR;
#endif
	break;
    case PARITY_ODD:
    case PARITY_MARK:
	termctl->c_cflag |= PARENB | PARODD;
#ifdef CMSPAR
	if (val == PARITY_MARK)
	    termctl->c_cflag |= CMSPAR;
#endif
	break;
    }
}

void
set_termios_xonoff(struct termios *termctl, int enabled)
{
    if (enabled) {
	termctl->c_iflag |= (IXON | IXOFF | IXANY);
	termctl->c_cc[VSTART] = 17;
	termctl->c_cc[VSTOP] = 19;
    } else {
	termctl->c_iflag &= ~(IXON | IXOFF | IXANY);
    }
}

void
set_termios_rtscts(struct termios *termctl, int enabled)
{
    if (enabled)
	termctl->c_cflag |= CRTSCTS;
    else
	termctl->c_cflag &= ~CRTSCTS;
}

void
set_termios_datasize(struct termios *termctl, int size)
{
    termctl->c_cflag &= ~CSIZE;
    switch (size) {
    case 5: termctl->c_cflag |= CS5; break;
    case 6: termctl->c_cflag |= CS6; break;
    case 7: termctl->c_cflag |= CS7; break;
    case 8: termctl->c_cflag |= CS8; break;
    }
}

int
set_termios_from_speed(struct termios *termctl, int speed, const char *others)
{
    int speed_val;

    if (!get_baud_rate(speed, &speed_val))
	return -1;

    cfsetospeed(termctl, speed_val);
    cfsetispeed(termctl, speed_val);

    if (*others) {
	enum parity_vals val;

	switch (*others) {
	case 'N': val = PARITY_NONE; break;
	case 'E': val = PARITY_EVEN; break;
	case 'O': val = PARITY_ODD; break;
	case 'M': val = PARITY_MARK; break;
	case 'S': val = PARITY_SPACE; break;
	default:
	    return -1;
	}
	set_termios_parity(termctl, val);
	others++;
    }

    if (*others) {
	int val;

	switch (*others) {
	case '5': val = 5; break;
	case '6': val = 6; break;
	case '7': val = 7; break;
	case '8': val = 8; break;
	default:
	    return -1;
	}
	set_termios_datasize(termctl, val);
	others++;
    }

    if (*others) {
	switch (*others) {
	case '1':
	    termctl->c_cflag &= ~(CSTOPB);
	    break;

	case '2':
	    termctl->c_cflag |= CSTOPB;
	    break;

	default:
	    return -1;
	}
	others++;
    }

    if (*others)
	return -1;

    return 0;
}

struct enum_val parity_enums[] = {
    { "NONE", PARITY_NONE },
    { "EVEN", PARITY_EVEN },
    { "ODD", PARITY_ODD },
    { "none", PARITY_NONE },
    { "even", PARITY_EVEN },
    { "odd", PARITY_ODD },
    { "MARK", PARITY_MARK },
    { "SPACE", PARITY_SPACE },
    { "mark", PARITY_MARK },
    { "space", PARITY_SPACE },
    { NULL }
};

static enum parity_vals
lookup_parity(const char *str)
{
    return lookup_enum(parity_enums, str, -1);
}

int
process_termios_parm(struct termios *termio, char *parm)
{
    int rv = 0, val;
    const char *rest = "";

    if ((val = speedstr_to_speed(parm, &rest)) != -1) {
	if (set_termios_from_speed(termio, val, rest) == -1)
	    rv = EINVAL;
    } else if (strcmp(parm, "1STOPBIT") == 0) {
	termio->c_cflag &= ~(CSTOPB);
    } else if (strcmp(parm, "2STOPBITS") == 0) {
	termio->c_cflag |= CSTOPB;
    } else if (strcmp(parm, "5DATABITS") == 0) {
	set_termios_datasize(termio, 5);
    } else if (strcmp(parm, "6DATABITS") == 0) {
	set_termios_datasize(termio, 6);
    } else if (strcmp(parm, "7DATABITS") == 0) {
	set_termios_datasize(termio, 7);
    } else if (strcmp(parm, "8DATABITS") == 0) {
	set_termios_datasize(termio, 8);
    } else if ((val = lookup_parity(parm)) != -1) {
	set_termios_parity(termio, val);
    } else if (strcmp(parm, "XONXOFF") == 0) {
	set_termios_xonoff(termio, 1);
    } else if (strcmp(parm, "-XONXOFF") == 0) {
	set_termios_xonoff(termio, 0);
    } else if (strcmp(parm, "RTSCTS") == 0) {
	set_termios_rtscts(termio, 1);
    } else if (strcmp(parm, "-RTSCTS") == 0) {
	set_termios_rtscts(termio, 0);
    } else if (strcmp(parm, "LOCAL") == 0) {
	termio->c_cflag |= CLOCAL;
    } else if (strcmp(parm, "-LOCAL") == 0) {
	termio->c_cflag &= ~CLOCAL;
    } else if (strcmp(parm, "HANGUP_WHEN_DONE") == 0) {
	termio->c_cflag |= HUPCL;
    } else if (strcmp(parm, "-HANGUP_WHEN_DONE") == 0) {
	termio->c_cflag &= ~HUPCL;
    } else {
	rv = ENOTSUP;
    }

    return rv;
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

void
sub_from_timeval(struct timeval *tv1, struct timeval *tv2)
{
    tv1->tv_sec -= tv2->tv_sec;
    tv1->tv_usec -= tv2->tv_usec;
    while (tv1->tv_usec > 1000000) {
	tv1->tv_usec -= 1000000;
	tv1->tv_sec += 1;
    }
    while (tv1->tv_usec < 0) {
	tv1->tv_usec += 1000000;
	tv1->tv_sec -= 1;
    }
}
