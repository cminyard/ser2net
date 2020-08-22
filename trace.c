/*
 *  ser2net - A program for allowing telnet connection to serial ports
 *  Copyright (C) 2001-2020  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include "ser2net.h"
#include "port.h"

static int
timestamp(trace_info_t *t, char *buf, int size)
{
    time_t result;
    if (!t->timestamp)
        return 0;
    result = time(NULL);
    return strftime(buf, size, "%Y/%m/%d %H:%M:%S ", localtime(&result));
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
	    gensiods buf_len, const char *prefix)
{
    int rv = 0, w, col = 0, pos, file = t->fd;
    gensiods q;
    static char out[1024];
    const unsigned char *start;

    if (buf_len == 0)
        return 0;

    if (!t->hexdump)
        return write(file, buf, buf_len);

    pos = timestamp(t, out, sizeof(out));
    pos += snprintf(out + pos, sizeof(out) - pos, "%s ", prefix);

    start = buf;
    for (q = 0; q < buf_len; q++) {
        pos += snprintf(out + pos, sizeof(out) - pos, "%02x ", buf[q]);
        col++;
        if (col >= 8) {
            trace_write_end(out + pos, sizeof(out) - pos, start, col);
            rv = write(file, out, strlen(out));
            if (rv < 0)
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
        rv = write(file, out, strlen(out));
        if (rv < 0)
            return rv;
    }
    return buf_len;
}

void
do_trace(port_info_t *port, trace_info_t *t, const unsigned char *buf,
	 gensiods buf_len, const char *prefix)
{
    int rv;

    while (buf_len > 0) {
    retry_write:
	rv = trace_write(port, t, buf, buf_len, prefix);
	if (rv == -1) {
	    char errbuf[128];
	    int err = errno;

	    if (err == EINTR)
		goto retry_write;

	    /* Fatal error writing to the file, log it and close the file. */

	    if (strerror_r(err, errbuf, sizeof(errbuf)) == -1)
		syslog(LOG_ERR, "Unable write to trace file on port %s: %d",
		       port->name, err);
	    else
		syslog(LOG_ERR, "Unable to write to trace file on port %s: %s",
		       port->name, errbuf);

	    close(t->fd);
	    t->fd = -1;
	    return;
	}

	/* Handle a partial write */
	buf_len -= rv;
	buf += rv;
    }
}

static void
hf_out(port_info_t *port, char *buf, int len)
{
    if (port->tr && port->tr->timestamp)
        write_ignore_fail(port->tr->fd, buf, len);

    /* don't output to write file if it's the same as read file */
    if (port->tw && port->tw != port->tr && port->tw->timestamp)
        write_ignore_fail(port->tw->fd, buf, len);

    /* don't output to both file if it's the same as read or write file */
    if (port->tb && port->tb != port->tr && port->tb != port->tw
		&& port->tb->timestamp)
        write_ignore_fail(port->tb->fd, buf, len);
}

void
header_trace(port_info_t *port, net_info_t *netcon)
{
    char buf[1024];
    trace_info_t tr = { 1, 1, NULL, -1 };
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
    trace_info_t tr = { 1, 1, NULL, -1 };
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
                struct timeval *tv,
                trace_info_t **out)
{
    int rv;
    char *trfile;

    trfile = process_str_to_str(port, NULL, t->filename, tv, NULL, 1);
    if (!trfile) {
	syslog(LOG_ERR, "Unable to translate trace file %s", t->filename);
	t->fd = -1;
	return;
    }

    rv = open(trfile, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (rv == -1) {
	char errbuf[128];
	int err = errno;

	if (strerror_r(err, errbuf, sizeof(errbuf)) == -1)
	    syslog(LOG_ERR, "Unable to open trace file %s: %d",
		   trfile, err);
	else
	    syslog(LOG_ERR, "Unable to open trace file %s: %s",
		   trfile, errbuf);
    }

    free(trfile);
    t->fd = rv;
    *out = t;
}

void
setup_trace(port_info_t *port)
{
    struct timeval tv;

    /* Only get the time once so all trace files have consistent times. */
    gettimeofday(&tv, NULL);

    port->tw = NULL;
    if (port->trace_write.filename)
	open_trace_file(port, &port->trace_write, &tv, &port->tw);

    port->tr = NULL;
    if (port->trace_read.filename) {
	trace_info_t *np = &port->trace_read;
	if (port->tw && (strcmp(np->filename, port->tw->filename) == 0))
	    port->tr = port->tw;
	else
	    open_trace_file(port, np, &tv, &port->tr);
    }

    port->tb = NULL;
    if (port->trace_both.filename) {
	trace_info_t *np = &port->trace_both;
	if (port->tw && (strcmp(np->filename, port->tw->filename) == 0))
	    port->tb = port->tw;
	else if (port->tr && (strcmp(np->filename, port->tr->filename) == 0))
	    port->tb = port->tr;
	else
	    open_trace_file(port, np, &tv, &port->tb);
    }

    return;
}

void
shutdown_trace(port_info_t *port)
{
    if (port->trace_write.fd != -1) {
	close(port->trace_write.fd);
	port->trace_write.fd = -1;
    }
    if (port->trace_read.fd != -1) {
	close(port->trace_read.fd);
	port->trace_read.fd = -1;
    }
    if (port->trace_both.fd != -1) {
	close(port->trace_both.fd);
	port->trace_both.fd = -1;
    }

    port->tw = port->tr = port->tb = NULL;
}
