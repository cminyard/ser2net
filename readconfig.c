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
#include <ctype.h>
#include <stdio.h>
#include <syslog.h>
#include <stdarg.h>
#include <values.h>

#include "dataxfer.h"
#include "readconfig.h"
#include "utils.h"
#include "telnet.h"

#ifdef HAVE_OPENIPMI
#include <OpenIPMI/ipmi_conn.h>
#include <OpenIPMI/ipmi_sol.h>
#endif

#define MAX_LINE_SIZE 256	/* Maximum line length in the config file. */

extern char *config_port;

static int config_num = 0;

static int lineno = 0;

struct longstr_s
{
    char *name;
    char *str;
    unsigned int length;
    enum str_type type;
    struct longstr_s *next;
};

static struct longstr_s *working_longstr;
static int working_longstr_continued = 0;
static int working_longstr_len = 0;

/* All the strings in the system. */
struct longstr_s *longstrs = NULL;

static int isoctdigit(char c)
{
    return ((c >= '0') && (c <= '7'));
}

/* Assumes the value is pre-checked */
static int hexchar_to_val(char c)
{
    if ((c >= '0') && (c <= '9'))
	return c - '0';
    if (isupper(c))
	return c - 'A' + 10;
    return c - 'a' + 10;
}

/*
 * Convert \004 and other ESC sequences in place, inspired from
 * http://stackoverflow.com/questions/17015970/how-does-c-compiler-convert-escape-sequence-to-actual-bytes
 */
static void
translateescapes(char *string, unsigned int *outlen,
		 char **err, char **errpos)
{
    char *ip = string, *op = string;
    unsigned int cleft = strlen(string);
    unsigned int iplen;

    *err = NULL;
    while (*ip) {
	cleft--;
	if (*ip != '\\') {
	    *op++ = *ip++;
	    continue;
	}

	if (cleft == 0)
	    goto out_str_in_bslash;

	iplen = 2;
	switch (ip[1]) {
	case '\\': *op = '\\'; break;
	case 'r': *op = '\r'; break;
	case 'n': *op = '\n'; break;
	case 't': *op = '\t'; break;
	case 'v': *op = '\v'; break;
	case 'a': *op = '\a'; break;
	case '0': case '1': case '2': case '3':
	case '4': case '5': case '6': case '7':
	    if (cleft < 3)
		goto out_str_in_bslash;
	    if (!isoctdigit(ip[2]) || !isoctdigit(ip[3])) {
		*err = "Invalid octal sequence";
		*errpos = ip - 1;
	    }
	    iplen = 4;
	    *op = (ip[1] -'0') * 64 + (ip[2] - '0') * 8 + (ip[3] - '0');
	    break;
	case 'x':
	    if (cleft < 3)
		goto out_str_in_bslash;
	    if (!isxdigit(ip[2]) || !isxdigit(ip[3])) {
		*err = "Invalid octal sequence";
		*errpos = ip - 1;
	    }
	    iplen = 4;
	    *op = 16 * hexchar_to_val(ip[2]) + hexchar_to_val(ip[3]);
	    break;
	default:
	    *err = "Unknown escape sequence";
	    *errpos = ip - 1;
	    return;
	}

	ip += iplen;
	cleft -= iplen;
	op++;
    }

    *outlen = op - string;
    *op = '\0';
    return;

 out_str_in_bslash:
    *err = "end of string right after a \\";
    *errpos = "";
}

static void
free_working_longstr(void)
{
    if (working_longstr->name)
	free(working_longstr->name);
    if (working_longstr->str)
	free(working_longstr->str);
    free(working_longstr);
    working_longstr = NULL;
}

static void
finish_longstr(void)
{
    if (!working_longstr)
	/* Couldn't allocate memory someplace. */
	goto out;

    /* On the final alloc an extra byte will be added for the nil char */
    working_longstr->str[working_longstr_len] = '\0';
    
    if (working_longstr->type == CLOSEON) {
	char *err = NULL, *errpos = NULL;

	translateescapes(working_longstr->str, &working_longstr->length,
			 &err, &errpos);
	if (err) {
	    syslog(LOG_ERR, "%s (starting at %s) on line %d", err, errpos,
		   lineno);
	    free_working_longstr();
	    goto out;
	}
    } else {
	working_longstr->length = working_longstr_len;
    }

    working_longstr->next = longstrs;
    longstrs = working_longstr;
    working_longstr = NULL;

 out:
    working_longstr_len = 0;
}

/* Parse the incoming string, it may be on multiple lines. */
static void
handle_longstr(const char *name, const char *line, enum str_type type)
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
    memset(working_longstr, 0, sizeof(*working_longstr));
    working_longstr->type = type;

    working_longstr->name = strdup(name);
    if (!working_longstr->name) {
	free_working_longstr();
	syslog(LOG_ERR, "Out of memory handling longstr on %d", lineno);
	return;
    }

    if (working_longstr_continued)
	line_len--;

    /* Add 1 if it's not continued and thus needs the '\0' */
    working_longstr->str = malloc(line_len + !working_longstr_continued);
    if (!working_longstr->str) {
	free_working_longstr();
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
find_str(const char *name, enum str_type *type, unsigned int *len)
{
    struct longstr_s *longstr = longstrs;

    while (longstr) {
	if (strcmp(name, longstr->name) == 0) {
	    char *rv;

	    /* Note that longstrs can contain \0, so be careful in handling */
	    if (type)
		*type = longstr->type;
	    if (len)
		*len = longstr->length;
	    rv = malloc(longstr->length + 1);
	    if (!rv)
		return NULL;
	    memcpy(rv, longstr->str, longstr->length + 1);
	    return rv;
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

struct enum_val
{
    char *str;
    int val;
};

static int
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

static struct enum_val speed_enums[] = {
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

int
speedstr_to_speed(const char *speed)
{
    return lookup_enum(speed_enums, speed, -1);
}

struct enum_val parity_enums[] = {
    { "NONE", PARITY_NONE },
    { "EVEN", PARITY_EVEN },
    { "ODD", PARITY_ODD },
    { "none", PARITY_NONE },
    { "even", PARITY_EVEN },
    { "odd", PARITY_ODD },
    { NULL }
};

#ifdef HAVE_OPENIPMI
struct enum_val shared_serial_alert_enums[] = {
    { "fail",		ipmi_sol_serial_alerts_fail },
    { "deferred", 	ipmi_sol_serial_alerts_deferred },
    { "succeed", 	ipmi_sol_serial_alerts_succeed },
    { NULL }
};
#endif

enum parity_vals
lookup_parity(const char *str)
{
    return lookup_enum(parity_enums, str, -1);
}

enum default_type { DEFAULT_INT, DEFAULT_BOOL, DEFAULT_ENUM };

struct default_data
{
    const char *name;
    enum default_type type;
    int min;
    int max;
    struct enum_val *enums;
    union {
	int intval;
    } val;
    union {
	int intval;
    } def;
};

struct default_data defaults[] = {
    /* serial device only */
    { "stopbits",	DEFAULT_INT,	.min = 1, .max = 2, .def.intval = 1 },
    { "databits",	DEFAULT_INT,	.min = 5, .max = 8, .def.intval = 8 },
    { "parity",		DEFAULT_ENUM,	.enums = parity_enums,
					.def.intval = PARITY_NONE },
    { "xonxoff",	DEFAULT_BOOL,	.def.intval = 0 },
    { "rtscts",		DEFAULT_BOOL,	.def.intval = 0 },
    { "local",		DEFAULT_BOOL,	.def.intval = 0 },
    { "hangup_when_done", DEFAULT_BOOL,	.def.intval = 0 },
    /* Serial port and SOL */
    { "speed",		DEFAULT_ENUM,	.enums = speed_enums,
					.def.intval = 9600 },
    { "nobreak",	DEFAULT_BOOL,	.def.intval = 0 },
    /* All port types */
    { "remctl",		DEFAULT_BOOL,	.def.intval = 0 },
    { "telnet_brk_on_sync",DEFAULT_BOOL,.def.intval = 0 },
    { "kickolduser",	DEFAULT_BOOL,	.def.intval = 0 },
    { "chardelay",	DEFAULT_BOOL,	.def.intval = 1 },
    { "chardelay-scale",DEFAULT_INT,	.min=1, .max=1000, .def.intval = 20 },
    { "chardelay-min",	DEFAULT_INT,	.min=1, .max=100000,
					.def.intval = 1000 },
#ifdef HAVE_OPENIPMI
    /* SOL only */
    { "authenticated",	DEFAULT_BOOL,	.def.intval = 1 },
    { "encrypted",	DEFAULT_BOOL,	.def.intval = 1 },
    { "ack-timeout",	DEFAULT_INT,	.min=1, .max=INT_MAX,
					.def.intval = 1000000 },
    { "ack-retries",	DEFAULT_INT,	.min=1, .max=INT_MAX,
					.def.intval = 10 },
    { "shared-serial-alert", DEFAULT_ENUM, .enums = shared_serial_alert_enums,
				   .def.intval = ipmi_sol_serial_alerts_fail },
    { "deassert_CTS_DCD_DSR_on_connect", DEFAULT_BOOL, .def.intval = 0 },
#endif
    { NULL }
};


static void
setup_defaults(void)
{
    int i;

    for (i = 0; defaults[i].name; i++) {
	defaults[i].val.intval = defaults[i].def.intval;
    }
}

int
find_default_int(const char *name)
{
    int i;

    for (i = 0; defaults[i].name; i++) {
	if (strcmp(defaults[i].name, name) == 0)
	    return defaults[i].val.intval;
    }
    abort();
}

static void
handle_new_default(const char *name, const char *str)
{
    int i, val, len;
    char *end;
    const char *s;

    while (isspace(*str))
	str++;
    s = str;
    while (!isspace(*s) && *s != '\0')
	s++;
    if (s == str) {
	syslog(LOG_ERR, "No default value on %d", lineno);
	return;
    }
    len = s - str;

    for (i = 0; defaults[i].name; i++) {
	if (strcmp(defaults[i].name, name) != 0)
	    continue;

	switch (defaults[i].type) {
	case DEFAULT_INT:
	    val = strtoul(str, &end, 10);
	    if (end != s) {
		syslog(LOG_ERR, "Invalid integer value on %d", lineno);
		return;
	    }
	    if (val < defaults[i].min || val > defaults[i].max) {
		syslog(LOG_ERR, "Integer value out of range on %d, "
		       "min is %d, max is %d",
		       lineno, defaults[i].min, defaults[i].max);
		return;
	    }
	    defaults[i].val.intval = val;
	    break;

	case DEFAULT_BOOL:
	    val = strtoul(str, &end, 10);
	    if (end == s)
		defaults[i].val.intval = !!val;
	    else if (len == 4 && ((strncmp(str, "true", 4) == 0) ||
				  (strncmp(str, "TRUE", 4) == 0)))
		defaults[i].val.intval = 1;
	    else if (len == 5 && ((strncmp(str, "false", 5) == 0) ||
				  (strncmp(str, "FALSE", 5) == 0)))
		defaults[i].val.intval = 0;
	    else
		syslog(LOG_ERR, "Invalid integer value on %d", lineno);
	    break;

	case DEFAULT_ENUM:
	    val = lookup_enum(defaults[i].enums, str, len);
	    if (val == -1) {
		syslog(LOG_ERR, "Invalid enumeration value on %d", lineno);
		return;
	    }
	    defaults[i].val.intval = val;
	    break;
	}
	return;
    }
}

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

    if (startswith(inbuf, "CLOSEON", &strtok_data)) {
	char *name = strtok_r(NULL, ":", &strtok_data);
	char *str = strtok_r(NULL, "\n", &strtok_data);
	if (name == NULL) {
	    syslog(LOG_ERR, "No close on string name given on line %d", lineno);
	    return;
	}
	handle_longstr(name, str, CLOSEON);
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

    if (startswith(inbuf, "DEVICE", &strtok_data)) {
	char *name = strtok_r(NULL, ":", &strtok_data);
	char *str = strtok_r(NULL, "\n", &strtok_data);
	if (name == NULL) {
	    syslog(LOG_ERR, "No device name given on line %d", lineno);
	    return;
	}
	handle_longstr(name, str, DEVNAME);
	return;
    }

    if (startswith(inbuf, "DEFAULT", &strtok_data)) {
	char *name = strtok_r(NULL, ":", &strtok_data);
	char *str = strtok_r(NULL, "\n", &strtok_data);
	if (name == NULL) {
	    syslog(LOG_ERR, "No default name given on line %d", lineno);
	    return;
	}
	handle_new_default(name, str);
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

    setup_defaults();
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

