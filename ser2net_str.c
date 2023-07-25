/*
 *  ser2net - A program for allowing telnet connection to serial ports
 *  Copyright (C) 2001-2020  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: GPL-2.0-only
 *
 *  In addition, as a special exception, the copyright holders of
 *  ser2net give you permission to combine ser2net with free software
 *  programs or libraries that are released under the GNU LGPL and
 *  with code included in the standard release of OpenSSL under the
 *  OpenSSL license (or modified versions of such code, with unchanged
 *  license). You may copy and distribute such a system following the
 *  terms of the GNU GPL for ser2net and the licenses of the other code
 *  concerned, provided that you include the source code of that
 *  other code when and as the GNU GPL requires distribution of source
 *  code.
 *
 *  Note that people who make modified versions of ser2net are not
 *  obligated to grant this special exception for their modified
 *  versions; it is their choice whether to do so. The GNU General
 *  Public License gives permission to release a modified version
 *  without this exception; this exception also makes it possible to
 *  release a modified version which carries forward this exception.
 */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <gensio/gensio.h>
#include "port.h"

gensiods
net_raddr_str(struct gensio *io, char *buf, gensiods buflen)
{
    int err;

    buf[0] = '0';
    buf[1] = '\n';
#if (defined(gensio_version_major) && (gensio_version_major > 2 ||	\
	       (gensio_version_major == 2 && gensio_version_minor > 0)))
    err = gensio_control(io, GENSIO_CONTROL_DEPTH_FIRST, true,
			 GENSIO_CONTROL_RADDR, buf, &buflen);
#else
    err = gensio_raddr_to_str(io, &buflen, buf, buflen);
#endif
    if (err) {
	buf[0] = '\0';
	buflen = 0;
    }

    return buflen;
}

static int
from_hex_digit(char c)
{
    if ((c >= '0') && (c <= '9'))
	return c - '0';
    if ((c >= 'A') && (c <= 'F'))
	return c - 'A' + 10;
    if ((c >= 'a') && (c <= 'f'))
	return c - 'a' + 10;
    return 0;
}

static char *smonths[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
			   "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
static char *sdays[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };

static void
process_str(port_info_t *port, net_info_t *netcon, brkout_time *tb,
	    const char *s,
	    void (*op)(void *data, char val), void *data, int isfilename)
{
    char val;
    char *t, *s2;

    while (*s) {
	if (*s == '\\') {
	    s++;
	    if (!*s)
		return;
	    switch (*s) {
	    /* Standard "C" characters. */
	    case 'a': op(data, 7); break;
	    case 'b': op(data, 8); break;
	    case 'f': op(data, 12); break;
	    case 'n': op(data, 10); break;
	    case 'r': op(data, 13); break;
	    case 't': op(data, 9); break;
	    case 'v': op(data, 11); break;
	    case '\\': op(data, '\\'); break;
	    case '?': op(data, '?'); break;
	    case '\'': op(data, '\''); break;
	    case '"': op(data, '"'); break;

	    case 'd': /* Actual device name */
	    case 'o': /* Device name on config line */
		/* ser2net device name. */
		if (*s == 'o' && port->orig_devname)
		    s2 = port->orig_devname;
		else if (*s == 'o')
		    s2 = port->name;
		else
		    s2 = port->devname;

		if (isfilename) {
		    /* Can't have '/' in a filename. */
		    t = strrchr(s2, '/');
		    if (t)
			t++;
		    else
			t = s2;
		} else
		    t = s2;
		for (; *t; t++)
		    op(data, *t);
		break;

	    /* Port's name. */
	    case 'N':
		for (t = port->name; *t; t++)
		    op(data, *t);
		break;

	    case 'p':
		/* ser2net network port. */
		for (t = port->accstr; *t; t++)
		    op(data, *t);
		break;

	    case 'B':
		/* ser2net serial parms. */
		{
		    char str[1024];

		    if (net_raddr_str(port->io, str, sizeof(str)) == 0)
			break;
		    t = strchr(str, ',');
		    if (!t)
			break;
		    for (; *t && *t != ' '; t++)
			op(data, *t);
		}
		break;

	    case '0': case '1': case '2': case '3': case '4': case '5':
	    case '6': case '7':
		/* Octal digit */
		val = (*s) - '0';
		s++;
		if (!*s) {
		    op(data, val);
		    return;
		}
		if (!isdigit(*s)) {
		    continue;
		}
		val = (val * 8) + (*s) - '0';
		s++;
		if (!*s) {
		    op(data, val);
		    return;
		}
		if (!isdigit(*s)) {
		    continue;
		}
		val = (val * 8) + (*s) - '0';
		op(data, val);
		break;

	    case 'x':
		/* Hex digit */
		s++;
		if (!*s)
		    return;
		if (!isxdigit(*s))
		    continue;
		val = from_hex_digit(*s);
		s++;
		if (!*s) {
		    op(data, val);
		    return;
		}
		if (!isxdigit(*s))
		    continue;
		val = (val * 16) + from_hex_digit(*s);
		op(data, val);
		break;

	    /* \Y -> year */
	    case 'Y':
	    {
		char d[12], *dp;
		snprintf(d, sizeof(d), "%d", bt_year(tb));
		for (dp = d; *dp; dp++)
		    op(data, *dp);
		break;
	    }

	    /* \y -> day of the year (days since Jan 1) */
	    case 'y':
	    {
		char d[10], *dp;
		snprintf(d, sizeof(d), "%d", bt_yearday(tb));
		for (dp = d; *dp; dp++)
		    op(data, *dp);
		break;
	    }

	    /* \M -> month (Jan, Feb, Mar, etc.) */
	    case 'M': {
		int month = bt_month(tb);

		if (month >= 12)
		    op(data, '?');
		else {
		    char *dp = smonths[month];
		    for (; *dp; dp++)
			op(data, *dp);
		}
		break;
	    }

	    /* \m -> month (as a number) */
	    case 'm':
	    {
		char d[12], *dp;
		/* bt_month runs from 0-11, thus the "+ 1" */
		snprintf(d, sizeof(d), "%d", bt_month(tb) + 1);
		for (dp = d; *dp; dp++)
		    op(data, *dp);
		break;
	    }

	    /* \A -> day of the week (Mon, Tue, etc.) */
	    case 'A': {
		int weekday = bt_weekday(tb);

		if (weekday >= 7)
		    op(data, '?');
		else {
		    char *dp = sdays[weekday];
		    for (; *dp; dp++)
			op(data, *dp);
		}
		break;
	    }

	    /* \D -> day of the month */
	    case 'D':
	    {
		char d[12], *dp;
		snprintf(d, sizeof(d), "%d", bt_monthday(tb));
		for (dp = d; *dp; dp++)
		    op(data, *dp);
		break;
	    }

	    /* \H -> hour (24-hour time) */
	    case 'H':
	    {
		char d[10], *dp;
		snprintf(d, sizeof(d), "%2.2d", bt_hour(tb));
		for (dp = d; *dp; dp++)
		    op(data, *dp);
		break;
	    }

	    /* \h -> hour (12-hour time) */
	    case 'h':
	    {
		char d[10], *dp;
		int hour;

		hour = bt_hour(tb);
		if (hour <= 0 || hour >= 24)
		    hour = 12;
		else if (hour > 12)
		    hour -= 12;
		snprintf(d, sizeof(d), "%2.2d", hour);
		for (dp = d; *dp; dp++)
		    op(data, *dp);
		break;
	    }

	    /* \i -> minute */
	    case 'i':
	    {
		char d[10], *dp;

		snprintf(d, sizeof(d), "%2.2d", bt_minute(tb));
		for (dp = d; *dp; dp++)
		    op(data, *dp);
		break;
	    }

	    /* \S -> second */
	    case 'S':
	    {
		char d[10], *dp;

		snprintf(d, sizeof(d), "%2.2d", bt_second(tb));
		for (dp = d; *dp; dp++)
		    op(data, *dp);
		break;
	    }

	    /* \q -> am/pm */
	    case 'q':
		if (bt_hour(tb) < 12) {
		    op(data, 'a');
		} else {
		    op(data, 'p');
		}
		op(data, 'm');
		break;

	    /* \P -> AM/PM */
	    case 'P':
		if (bt_hour(tb) < 12) {
		    op(data, 'A');
		} else {
		    op(data, 'P');
		}
		op(data, 'M');
		break;

	    /* \T -> time (HH:MM:SS) */
	    case 'T':
	    {
		char d[10], *dp;
		snprintf(d, sizeof(d), "%2.2d:%2.2d:%2.2d",
			 bt_hour(tb), bt_minute(tb), bt_second(tb));
		for (dp = d; *dp; dp++)
		    op(data, *dp);
		break;
	    }

	    /* \e -> epoc (seconds since Jan 1, 1970) */
	    case 'e':
	    {
		char d[30], *dp;
		snprintf(d, sizeof(d), "%ld", bt_epoc(tb));
		for (dp = d; *dp; dp++)
		    op(data, *dp);
		break;
	    }

	    /* \U -> microseconds in the current second */
	    case 'U':
	    {
		char d[10], *dp;
		snprintf(d, sizeof(d), "%6.6ld", (long) bt_usec(tb));
		for (dp = d; *dp; dp++)
		    op(data, *dp);
		break;
	    }

	    /* \I -> remote IP address (in dot format) */
	    case 'I':
	    {
		char ip[100], *ipp;

		if (!netcon)
		    netcon = first_live_net_con(port);
		if (!netcon)
		    break;
		if (net_raddr_str(netcon->net, ip, sizeof(ip)) == 0)
		    break;
		for (ipp = ip; *ipp; ipp++)
		    op(data, *ipp);
		break;
	    }

	    default:
		op(data, *s);
	    }
	} else
	    op(data, *s);
	s++;
    }
}

static void
count_op(void *data, char c)
{
    gensiods *idata = data;

    (*idata)++;
}

struct bufop_data {
    gensiods pos;
    char *str;
};

static void
buffer_op(void *data, char c)
{
    struct bufop_data *bufop = data;
    bufop->str[bufop->pos] = c;
    (bufop->pos)++;
}

char *
process_str_to_str(port_info_t *port, net_info_t *netcon,
		   const char *str, timev *ts,
		   gensiods *lenrv, int isfilename, struct absout *eout)
{
    gensiods len = 0;
    brkout_time now;
    struct bufop_data bufop;

    breakout_time(ts, &now);
    process_str(port, netcon, &now, str, count_op, &len, isfilename);
    if (!lenrv)
	/* If we don't return a length, append a nil char. */
	len++;
    bufop.pos = 0;
    if (len == 0)
	bufop.str = malloc(1);
    else
	bufop.str = malloc(len + 1);
    if (!bufop.str) {
	eout->out(eout, "Out of memory processing string: %s", port->name);
	return NULL;
    }
    process_str(port, netcon, &now, str, buffer_op, &bufop, isfilename);
    bufop.str[len] = '\0';

    if (lenrv)
	*lenrv = len;
    else
	bufop.str[bufop.pos] = '\0';

    return bufop.str;
}

struct gbuf *
process_str_to_buf(port_info_t *port, net_info_t *netcon, const char *str,
		   struct absout *eout)
{
    char *bstr;
    struct gbuf *buf;
    gensiods len;
    timev ts;

    if (!str || *str == '\0')
	return NULL;
    get_curr_time(&ts);

    buf = malloc(sizeof(*buf));
    if (!buf) {
	eout->out(eout, "Out of memory processing string: %s", port->name);
	return NULL;
    }
    bstr = process_str_to_str(port, netcon, str, &ts, &len, 0, eout);
    if (!bstr) {
	free(buf);
	eout->out(eout, "Error processing string: %s", port->name);
	return NULL;
    }
    buf->buf = (unsigned char *) bstr;
    buf->maxsize = len;
    buf->pos = 0;
    buf->cursize = len;

    return buf;
}
