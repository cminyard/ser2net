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

/* This file holds the code that reads the configuration file and
   calls the code in dataxfer to actually create all the ports in the
   configuration file. */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>
#include <stdarg.h>

#include "dataxfer.h"
#include "readconfig.h"
#include "utils.h"
#include "telnet.h"

#define MAX_LINE_SIZE 256	/* Maximum line length in the config file. */

extern char *config_port;

static int config_num = 0;

static int lineno = 0;

struct longstr_s
{
    char *name;
    char *str;
    enum str_type type;
    struct longstr_s *next;
};

static struct longstr_s *working_longstr;
static int working_longstr_continued = 0;
static int working_longstr_len = 0;

/* All the strings in the system. */
struct longstr_s *longstrs = NULL;

static void
finish_longstr(void)
{
    if (!working_longstr)
	/* Couldn't allocate memory someplace. */
	goto out;

    /* On the final alloc an extra byte will be added for the nil char */
    working_longstr->str[working_longstr_len] = '\0';
    
    working_longstr->next = longstrs;
    longstrs = working_longstr;
    working_longstr = NULL;

 out:
    working_longstr_len = 0;
}

/* Parse the incoming string, it may be on multiple lines. */
static void
handle_longstr(char *name, char *line, enum str_type type)
{
    int line_len;

    /* If the user gave an empty string, we get a NULL. */
    if (!line)
	line = "";

    line_len = strlen(line);

    working_longstr_continued = (line_len > 0) && (line[line_len-1] == '\\');

    working_longstr = malloc(sizeof(*working_longstr));
    if (!working_longstr) {
	syslog(LOG_ERR, "Out of memory handling string on %d", lineno);
	return;
    }
    working_longstr->type = type;

    working_longstr->name = strdup(name);
    if (!working_longstr->name) {
	free(working_longstr);
	working_longstr = NULL;
	syslog(LOG_ERR, "Out of memory handling longstr on %d", lineno);
	return;
    }

    if (working_longstr_continued)
	line_len--;

    /* Add 1 if it's not continued and thus needs the '\0' */
    working_longstr->str = malloc(line_len + !working_longstr_continued);
    if (!working_longstr->str) {
	free(working_longstr->name);
	free(working_longstr);
	working_longstr = NULL;
	syslog(LOG_ERR, "Out of memory handling longstr on %d", lineno);
	return;
    }

    memcpy(working_longstr->str, line, line_len);
    working_longstr_len = line_len;

    if (!working_longstr_continued)
	finish_longstr();
}

static void
handle_continued_longstr(char *line)
{
    int line_len = strlen(line);
    char *newstr;

    working_longstr_continued = (line_len > 0) && (line[line_len-1] == '\\');

    if (!working_longstr)
	/* Ran out of memory during processing */
	goto out;

    if (working_longstr_continued)
	line_len--;

    /* Add 1 if it's not continued and thus needs the '\0' */
    newstr = realloc(working_longstr->str, (working_longstr_len + line_len
					    + !working_longstr_continued));
    if (!newstr) {
	free(working_longstr->str);
	free(working_longstr->name);
	free(working_longstr);
	working_longstr = NULL;
	syslog(LOG_ERR, "Out of memory handling longstr on %d", lineno);
	goto out;
    }
    working_longstr->str = newstr;
    memcpy(working_longstr->str + working_longstr_len, line, line_len);
    working_longstr_len += line_len;

out:
    if (!working_longstr_continued)
	finish_longstr();
}

char *
find_str(const char *name, enum str_type *type)
{
    struct longstr_s *longstr = longstrs;

    while (longstr) {
	if (strcmp(name, longstr->name) == 0) {
	    *type = longstr->type;
	    return strdup(longstr->str);
	}
	longstr = longstr->next;
    }
    return NULL;
}

static void
free_longstrs(void)
{
    struct longstr_s *longstr;

    if (working_longstr) {
	if (working_longstr->name)
	    free(working_longstr->name);
	if (working_longstr->str)
	    free(working_longstr->str);
	free(working_longstr);
	working_longstr = NULL;
    }
    working_longstr_len = 0;
    working_longstr_continued = 0;

    while (longstrs) {
	longstr = longstrs;
	longstrs = longstrs->next;
	free(longstr->name);
	free(longstr->str);
	free(longstr);
    }
}

struct tracefile_s
{
    char *name;
    char *str;
    struct tracefile_s *next;
};

#ifdef USE_RS485_FEATURE
struct rs485conf_s
{
    char *name;
    struct serial_rs485 conf;
    struct rs485conf_s *next;
};
#endif

/* All the tracefiles in the system. */
struct tracefile_s *tracefiles = NULL;

static void
handle_tracefile(char *name, char *fname)
{
    struct tracefile_s *new_tracefile;

    new_tracefile = malloc(sizeof(*new_tracefile));
    if (!new_tracefile) {
	syslog(LOG_ERR, "Out of memory handling tracefile on %d", lineno);
	return;
    }

    new_tracefile->name = strdup(name);
    if (!new_tracefile->name) {
	syslog(LOG_ERR, "Out of memory handling tracefile on %d", lineno);
	free(new_tracefile);
	return;
    }

    new_tracefile->str = strdup(fname);
    if (!new_tracefile->str) {
	syslog(LOG_ERR, "Out of memory handling tracefile on %d", lineno);
	free(new_tracefile->name);
	free(new_tracefile);
	return;
    }

    new_tracefile->next = tracefiles;
    tracefiles = new_tracefile;
}

char *
find_tracefile(const char *name)
{
    struct tracefile_s *tracefile = tracefiles;

    while (tracefile) {
	if (strcmp(name, tracefile->name) == 0)
	    return strdup(tracefile->str);
	tracefile = tracefile->next;
    }
    syslog(LOG_ERR, "Tracefile %s not found, it will be ignored", name);
    return NULL;
}

static void
free_tracefiles(void)
{
    struct tracefile_s *tracefile;

    while (tracefiles) {
	tracefile = tracefiles;
	tracefiles = tracefiles->next;
	free(tracefile->name);
	free(tracefile->str);
	free(tracefile);
    }
}

#ifdef USE_RS485_FEATURE
/* All the RS485 configs in the system. */
struct rs485conf_s *rs485confs = NULL;

static void
handle_rs485conf(char *name, char *str)
{
    struct rs485conf_s *new_rs485conf;
    uint8_t rts_on_send, rx_during_tx;

    new_rs485conf = malloc(sizeof(*new_rs485conf));
    if (!new_rs485conf) {
	syslog(LOG_ERR, "Out of memory handling rs485 config on %d", lineno);
	return;
    }

    new_rs485conf->name = strdup(name);
    if (!new_rs485conf->name) {
	syslog(LOG_ERR, "Out of memory handling rs485 config on %d", lineno);
	free(new_rs485conf);
	return;
    }

    if (sscanf(str, "%u:%u:%1hhu:%1hhu",
               &new_rs485conf->conf.delay_rts_before_send,
               &new_rs485conf->conf.delay_rts_after_send,
               &rts_on_send,
               &rx_during_tx) != 4) {
	syslog(LOG_ERR, "Couldn't parse RS485 config on %d", lineno);
	return;
    }

    /* check, if flags have values 0 or 1 */
    if (rts_on_send > 1) {
	syslog(LOG_ERR, "RTS_ON_SEND parameter can be 0 or 1 on %d", lineno);
	return;
    }

    if (rx_during_tx > 1) {
	syslog(LOG_ERR, "RX_DURING_TX parameter can be 0 or 1 on %d", lineno);
	return;
    }

    new_rs485conf->conf.flags = SER_RS485_ENABLED;

    if (rts_on_send) {
        new_rs485conf->conf.flags |= SER_RS485_RTS_ON_SEND;
    } else {
        new_rs485conf->conf.flags |= SER_RS485_RTS_AFTER_SEND;
    }

    if (rx_during_tx) {
        new_rs485conf->conf.flags |= SER_RS485_RX_DURING_TX;
    }

    new_rs485conf->next = rs485confs;
    rs485confs = new_rs485conf;
}

struct serial_rs485 *
find_rs485conf(const char *name)
{
    struct rs485conf_s *new_rs485conf = rs485confs;

    while (new_rs485conf) {
        if (strcmp(name, new_rs485conf->name) == 0)
            return &new_rs485conf->conf;
        new_rs485conf = new_rs485conf->next;
    }
    syslog(LOG_ERR, "RS485 configuration %s not found, it will be ignored", name);
    return NULL;
}

static void
free_rs485confs(void)
{
    struct rs485conf_s *rs485conf;

    while (rs485confs) {
        rs485conf = rs485confs;
        rs485confs = rs485confs->next;
        free(rs485conf->name);
        free(rs485conf);
    }
}
#endif

static int
startswith(char *str, const char *test, char **strtok_data)
{
    int len = strlen(test);

    if ((strncmp(str, test, len) == 0) && (str[len] == ':')) {
	strtok_r(str, ":", strtok_data);
	return 1;
    }
    return 0;
}

static int
syslog_eprint(struct absout *e, const char *str, ...)
{
    va_list ap;
    char buf[1024];

    va_start(ap, str);
    vsnprintf(buf, sizeof(buf), str, ap);
    va_end(ap);
    syslog(LOG_ERR, "%s on line %d", buf, *((int *) e->data));
    return 0;
}

static struct absout syslog_eout = {
    .out = syslog_eprint,
    .data = &lineno
};

void
handle_config_line(char *inbuf)
{
    char *portnum, *state, *timeout, *devname, *devcfg, *comma;
    char *strtok_data = NULL;

    lineno++;

    if (working_longstr_continued) {
	char *str = strtok_r(inbuf, "\n", &strtok_data);
	if (!str)
	    str = "";
	handle_continued_longstr(str);
	return;
    }

    if (inbuf[0] == '#') {
	/* Ignore comments. */
	return;
    }

    if (startswith(inbuf, "CONTROLPORT", &strtok_data)) {
	if (config_port)
	    /*
	     * The control port has already been configured either on the
	     * command line or on a previous statement.  Only take the first.
	     */
	    return;
	config_port = strdup(strtok_r(NULL, "\n", &strtok_data));
	if (!config_port) {
	    syslog(LOG_ERR, "Could not allocate memory for CONTROLPORT");
	    return;
	}
	return;
    }

    if (startswith(inbuf, "BANNER", &strtok_data)) {
	char *name = strtok_r(NULL, ":", &strtok_data);
	char *str = strtok_r(NULL, "\n", &strtok_data);
	if (name == NULL) {
	    syslog(LOG_ERR, "No banner name given on line %d", lineno);
	    return;
	}
	handle_longstr(name, str, BANNER);
	return;
    }

    if (startswith(inbuf, "SIGNATURE", &strtok_data)) {
	char *name = strtok_r(NULL, ":", &strtok_data);
	char *str = strtok_r(NULL, "\n", &strtok_data);
	if (name == NULL) {
	    syslog(LOG_ERR, "No signature given on line %d", lineno);
	    return;
	}
	handle_longstr(name, str, SIGNATURE);
	return;
    }

#ifdef USE_RS485_FEATURE
    if (startswith(inbuf, "RS485CONF", &strtok_data)) {
        char *name = strtok_r(NULL, ":", &strtok_data);
        char *str = strtok_r(NULL, "\n", &strtok_data);
        if (name == NULL) {
            syslog(LOG_ERR, "No signature given on line %d", lineno);
            return;
        }
        if ((str == NULL) || (strlen(str) == 0)) {
            syslog(LOG_ERR, "No RS485 configuration given on line %d", lineno);
            return;
        }
        handle_rs485conf(name, str);
        return;
    }
#endif

    if (startswith(inbuf, "OPENSTR", &strtok_data)) {
	char *name = strtok_r(NULL, ":", &strtok_data);
	char *str = strtok_r(NULL, "\n", &strtok_data);
	if (name == NULL) {
	    syslog(LOG_ERR, "No open string name given on line %d", lineno);
	    return;
	}
	handle_longstr(name, str, OPENSTR);
	return;
    }

    if (startswith(inbuf, "CLOSESTR", &strtok_data)) {
	char *name = strtok_r(NULL, ":", &strtok_data);
	char *str = strtok_r(NULL, "\n", &strtok_data);
	if (name == NULL) {
	    syslog(LOG_ERR, "No close string name given on line %d", lineno);
	    return;
	}
	handle_longstr(name, str, CLOSESTR);
	return;
    }

    if (startswith(inbuf, "TRACEFILE", &strtok_data)) {
	char *name = strtok_r(NULL, ":", &strtok_data);
	char *str = strtok_r(NULL, "\n", &strtok_data);
	if (name == NULL) {
	    syslog(LOG_ERR, "No tracefile name given on line %d", lineno);
	    return;
	}
	if ((str == NULL) || (strlen(str) == 0)) {
	    syslog(LOG_ERR, "No tracefile given on line %d", lineno);
	    return;
	}
	handle_tracefile(name, str);
	return;
    }

    comma = strchr(inbuf, ',');
    if (comma) {
	if (!strtok_r(comma, ":", &strtok_data)) {
	    syslog(LOG_ERR, "Invalid port on line %d", lineno);
	    return;
	}
	portnum = inbuf;
    } else {
	portnum = strtok_r(inbuf, ":", &strtok_data);
	if (portnum == NULL) {
	    /* An empty line is ok. */
	    return;
	}
    }

    state = strtok_r(NULL, ":", &strtok_data);
    if (state == NULL) {
	syslog(LOG_ERR, "No state given on line %d", lineno);
	return;
    }

    timeout = strtok_r(NULL, ":", &strtok_data);
    if (timeout == NULL) {
	syslog(LOG_ERR, "No timeout given on line %d", lineno);
	return;
    }

    devname = strtok_r(NULL, ":", &strtok_data);
    if (devname == NULL) {
	syslog(LOG_ERR, "No device name given on line %d", lineno);
	return;
    }

    devcfg = strtok_r(NULL, ":", &strtok_data);
    if (devcfg == NULL) {
	/* An empty device config is ok. */
	devcfg = "";
    }

    portconfig(&syslog_eout, portnum, state, timeout, devname, devcfg,
	       config_num);
}

/* Read the specified configuration file and call the routine to
   create the ports. */
int
readconfig(char *filename)
{
    FILE *instream;
    char inbuf[MAX_LINE_SIZE];
    int  rv = 0;

    lineno = 0;

    instream = fopen(filename, "r");
    if (instream == NULL) {
	syslog(LOG_ERR, "Unable to open config file '%s': %m", filename);
	return -1;
    }

    free_longstrs();
    free_tracefiles();
#ifdef USE_RS485_FEATURE
    free_rs485confs();
#endif

    config_num++;

    while (fgets(inbuf, MAX_LINE_SIZE, instream) != NULL) {
	int len = strlen(inbuf);
	if (inbuf[len-1] != '\n') {
	    lineno++;
	    syslog(LOG_ERR, "line %d is too long in config file", lineno);
	    continue;
	}
	/* Remove the '\n' */
	inbuf[len-1] = '\0';
	handle_config_line(inbuf);
    }

    /* Delete anything that wasn't in the new config file. */
    clear_old_port_config(config_num);

    fclose(instream);
    return rv;
}

