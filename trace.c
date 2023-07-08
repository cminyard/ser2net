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
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "ser2net.h"
#include "port.h"

static int
timestamp(trace_info_t *t, char *buf, int size)
{
    timev result;

    if (!t->timestamp)
        return 0;
    get_curr_time(&result);
    return time_to_str(buf, size, &result);
}

static int
trace_write_end(char *out, int size, const unsigned char *start, int col)
{
    int pos = 0, w;

    strncat(out, " |", size - pos);
    pos += 2;
    for(w = 0; w < col; w++) {
        pos += snprintf(out + pos, size - pos, "%c",
			isprint(start[w]) ? start[w] : '.');
    }
    strncat(out + pos, "|\n", size - pos);
    pos += 2;
    return pos;
}

static int
trace_write(port_info_t *port, trace_info_t *t, const unsigned char *buf,
	    gensiods buf_len, const char *prefix, unsigned int *out_len)
{
    int rv = 0, w, col = 0, pos;
    ftype *file = t->f;
    gensiods q;
    static char out[1024];
    const unsigned char *start;

    if (buf_len == 0)
        return 0;

    if (!t->hexdump)
	return f_write(file, buf, buf_len, out_len);

    pos = timestamp(t, out, sizeof(out));
    pos += snprintf(out + pos, sizeof(out) - pos, "%s ", prefix);

    start = buf;
    for (q = 0; q < buf_len; q++) {
        pos += snprintf(out + pos, sizeof(out) - pos, "%02x ", buf[q]);
        col++;
        if (col >= 8) {
            trace_write_end(out + pos, sizeof(out) - pos, start, col);
            rv = f_write(file, out, strlen(out), NULL);
            if (rv)
                return rv;
            pos = timestamp(t, out, sizeof(out));
            pos += snprintf(out + pos, sizeof(out) - pos, "%s ", prefix);
            col = 0;
            start = buf + q + 1;
        }
    }
    if (col > 0) {
        for (w = 8; w > col; w--) {
            strncat(out + pos, "   ", sizeof(out) - pos);
            pos += 3;
        }
        trace_write_end(out + pos, sizeof(out) - pos, start, col);
        rv = f_write(file, out, strlen(out), NULL);
        if (rv)
            return rv;
    }
    if (out_len)
	*out_len = buf_len;
    return 0;
}

void
do_trace(port_info_t *port, trace_info_t *t, const unsigned char *buf,
	 gensiods buf_len, const char *prefix)
{
    int rv;
    unsigned int outlen;

    while (buf_len > 0) {
	rv = trace_write(port, t, buf, buf_len, prefix, &outlen);
	if (rv == -1) {
	    seout.out(&seout,
		      "Unable to write to trace file on port %s: %s",
		      port->name, gensio_err_to_str(rv));

	    f_close(t->f);
	    t->f = NULL;
	    return;
	}

	/* Handle a partial write */
	buf_len -= outlen;
	buf += outlen;
    }
}

static void
hf_out(port_info_t *port, char *buf, int len)
{
    if (port->tr && port->tr->timestamp)
        f_write(port->tr->f, buf, len, NULL);

    /* don't output to write file if it's the same as read file */
    if (port->tw && port->tw != port->tr && port->tw->timestamp)
        f_write(port->tw->f, buf, len, NULL);

    /* don't output to both file if it's the same as read or write file */
    if (port->tb && port->tb != port->tr && port->tb != port->tw
		&& port->tb->timestamp)
        f_write(port->tb->f, buf, len, NULL);
}

void
header_trace(port_info_t *port, net_info_t *netcon)
{
    char buf[1024];
    trace_info_t tr = { 1, 1, NULL, NULL };
    gensiods len = 0;

    len += timestamp(&tr, buf, sizeof(buf));
    if (sizeof(buf) > len)
	len += snprintf(buf + len, sizeof(buf) - len, "OPEN (");
    if (sizeof(buf) > len)
	len += net_raddr_str(netcon->net, buf + len, sizeof(buf) - len);
    if (sizeof(buf) > len)
	len += snprintf(buf + len, sizeof(buf) - len, ")\n");

    hf_out(port, buf, len);
}

void
footer_trace(port_info_t *port, char *type, const char *reason)
{
    char buf[1024];
    trace_info_t tr = { 1, 1, NULL, NULL };
    int len = 0;

    len += timestamp(&tr, buf, sizeof(buf));
    if (sizeof(buf) > len)
	len += snprintf(buf + len, sizeof(buf) - len,
			"CLOSE %s (%s)\n", type, reason);

    hf_out(port, buf, len);
}

static void
open_trace_file(port_info_t *port,
                trace_info_t *t,
                timev *ts,
                trace_info_t **out, struct absout *eout)
{
    int rv;
    char *trfile;

    trfile = process_str_to_str(port, NULL, t->filename, ts, NULL, 1, eout);
    if (!trfile) {
	eout->out(eout, "Unable to translate trace file %s", t->filename);
	return;
    }

    rv = f_open(trfile, DO_WRITE | DO_CREATE | DO_APPEND, 0600, &t->f);
    if (rv)
	eout->out(eout, "Unable to open trace file %s: %s",
		  trfile, gensio_err_to_str(rv));
    else
	*out = t;

    free(trfile);
}

void
setup_trace(port_info_t *port, struct absout *eout)
{
    timev ts;

    /* Only get the time once so all trace files have consistent times. */
    get_curr_time(&ts);

    port->tw = NULL;
    if (port->trace_write.filename)
	open_trace_file(port, &port->trace_write, &ts, &port->tw, eout);

    port->tr = NULL;
    if (port->trace_read.filename) {
	trace_info_t *np = &port->trace_read;
	if (port->tw && (strcmp(np->filename, port->tw->filename) == 0))
	    port->tr = port->tw;
	else
	    open_trace_file(port, np, &ts, &port->tr, eout);
    }

    port->tb = NULL;
    if (port->trace_both.filename) {
	trace_info_t *np = &port->trace_both;
	if (port->tw && (strcmp(np->filename, port->tw->filename) == 0))
	    port->tb = port->tw;
	else if (port->tr && (strcmp(np->filename, port->tr->filename) == 0))
	    port->tb = port->tr;
	else
	    open_trace_file(port, np, &ts, &port->tb, eout);
    }

    return;
}

void
shutdown_trace(port_info_t *port)
{
    if (port->trace_write.f) {
	f_close(port->trace_write.f);
	port->trace_write.f = NULL;
    }
    if (port->trace_read.f) {
	f_close(port->trace_read.f);
	port->trace_read.f = NULL;
    }
    if (port->trace_both.f) {
	f_close(port->trace_both.f);
	port->trace_both.f = NULL;
    }

    port->tw = port->tr = port->tb = NULL;
}
