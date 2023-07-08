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

/* This file holds the code that reads the configuration file and
   calls the code in dataxfer to actually create all the ports in the
   configuration file. */

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdarg.h>
#include <limits.h>
#include <gensio/gensio.h>
#include <gensio/argvutils.h>

#include "ser2net.h"
#include "dataxfer.h"
#include "readconfig.h"
#include "led.h"
#include "defaults.h"

static int lineno = 0;

struct longstr_s
{
    char *name;
    char *str;
    unsigned int length;
    enum str_type type;
    struct longstr_s *next;
};

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

/* Parse the incoming string, it may be on multiple lines. */
static void
handle_longstr(const char *name, const char *line, enum str_type type,
	       struct absout *eout)
{
    struct longstr_s *longstr;

    /* If the user gave an empty string, we get a NULL. */
    if (!line)
	line = "";

    longstr = malloc(sizeof(*longstr));
    if (!longstr) {
	eout->out(eout, "Out of memory handling string on %d", lineno);
	return;
    }
    memset(longstr, 0, sizeof(*longstr));
    longstr->type = type;

    longstr->name = strdup(name);
    if (!longstr->name) {
	eout->out(eout, "Out of memory handling longstr on %d", lineno);
	goto out_err;
    }

    longstr->str = strdup(line);
    if (!longstr->str) {
	eout->out(eout, "Out of memory handling longstr on %d", lineno);
	goto out_err;
    }

    longstr->length = strlen(line);

    if (longstr->type == CLOSEON) {
	char *err = NULL, *errpos = NULL;

	translateescapes(longstr->str, &longstr->length,
			 &err, &errpos);
	if (err) {
	    eout->out(eout, "%s (starting at %s) on line %d", err, errpos,
		   lineno);
	    goto out_err;
	}
    }

    longstr->next = longstrs;
    longstrs = longstr;
    return;

 out_err:
    if (longstr->name)
	free(longstr->name);
    if (longstr->str)
	free(longstr->str);
    free(longstr);
    return;
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

void
free_longstrs(void)
{

    while (longstrs) {
	struct longstr_s *longstr = longstrs;

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

/* All the tracefiles in the system. */
struct tracefile_s *tracefiles = NULL;

static void
handle_tracefile(char *name, char *fname, struct absout *eout)
{
    struct tracefile_s *new_tracefile;

    new_tracefile = malloc(sizeof(*new_tracefile));
    if (!new_tracefile) {
	eout->out(eout, "Out of memory handling tracefile on %d", lineno);
	return;
    }

    new_tracefile->name = strdup(name);
    if (!new_tracefile->name) {
	eout->out(eout, "Out of memory handling tracefile on %d", lineno);
	free(new_tracefile);
	return;
    }

    new_tracefile->str = strdup(fname);
    if (!new_tracefile->str) {
	eout->out(eout, "Out of memory handling tracefile on %d", lineno);
	free(new_tracefile->name);
	free(new_tracefile);
	return;
    }

    new_tracefile->next = tracefiles;
    tracefiles = new_tracefile;
}

char *
find_tracefile(const char *name, struct absout *eout)
{
    struct tracefile_s *tracefile = tracefiles;

    while (tracefile) {
	if (strcmp(name, tracefile->name) == 0)
	    return strdup(tracefile->str);
	tracefile = tracefile->next;
    }
    eout->out(eout, "Tracefile %s not found, it will be ignored", name);
    return NULL;
}

void
free_tracefiles(void)
{
    while (tracefiles) {
	struct tracefile_s *tracefile = tracefiles;

	tracefiles = tracefiles->next;
	free(tracefile->name);
	free(tracefile->str);
	free(tracefile);
    }
}

struct rs485conf
{
    char *name;
    char *str;
    struct rs485conf *next;
};

/* All the RS485 configs in the system. */
struct rs485conf *rs485confs = NULL;

static void
handle_rs485conf(char *name, char *str, struct absout *eout)
{
    struct rs485conf *new_rs485conf;

    new_rs485conf = malloc(sizeof(*new_rs485conf));
    if (!new_rs485conf) {
	eout->out(eout, "Out of memory handling rs485 config on %d", lineno);
	return;
    }
    memset(new_rs485conf, 0, sizeof(*new_rs485conf));

    new_rs485conf->name = strdup(name);
    if (!new_rs485conf->name) {
	eout->out(eout, "Out of memory handling rs485 config on %d", lineno);
	goto out_err;
    }

    new_rs485conf->str = strdup(str);
    if (!new_rs485conf->str) {
	eout->out(eout, "Out of memory handling rs485 config on %d", lineno);
	goto out_err;
    }

    new_rs485conf->next = rs485confs;
    rs485confs = new_rs485conf;
    return;

 out_err:
    if (new_rs485conf->str)
	free(new_rs485conf->str);
    if (new_rs485conf->name)
	free(new_rs485conf->name);
    free(new_rs485conf);
}

char *
find_rs485conf(const char *name, struct absout *eout)
{
    struct rs485conf *rs485 = rs485confs;

    while (rs485) {
        if (strcmp(name, rs485->name) == 0)
            return strdup(rs485->str);
        rs485 = rs485->next;
    }
    eout->out(eout, "RS485 configuration %s not found, it will be ignored",
	   name);
    return NULL;
}

void
free_rs485confs(void)
{
    while (rs485confs) {
	struct rs485conf *rs485 = rs485confs;

        rs485 = rs485->next;
        free(rs485->str);
        free(rs485->name);
        free(rs485);
    }
}

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

/*
 * This rather complicated variable is used to scan the string for
 * ":off", ":on", ":telnet", ":raw:", or ":rawlp:".  It's a basic state
 * machine where if a character in the first string "c" matches the
 * current character, you go to the state machine index in the
 * corresponding location giving by the character in string "next".
 * So ":raw:" would see the ":" in state zero and go to state 1.  Then
 * the "r" in state 1 would go to state 7.  Then "a" in state 7 would
 * go to state 8, "w" to state name.  The ":" has a zero, that means a
 * match was found.
 *
 * This is nasty, but it allows there to be ":" characters in the
 * portnum so that IPV6 addresses can be specified.
 */
static struct {
    char *c;
    char *next;
} scanstate[] = {
    { ":",   "\x01" },		/* 0x00 */
    { "tro", "\x02\x07\x0b" },	/* 0x01 */
    { "e",   "\x03" },		/* 0x02 */
    { "l",   "\x04" },		/* 0x03 */
    { "n",   "\x05" },		/* 0x04 */
    { "e",   "\x06" },		/* 0x05 */
    { "t",   "\x0d" },		/* 0x06 */
    { "a",   "\x08" },		/* 0x07 */
    { "w",   "\x09" },		/* 0x09 */
    { ":l",  "\x00\x0a" },	/* 0x09 */
    { "p",   "\x0d" },		/* 0x0a */
    { "fn",  "\x0c\x0d" },	/* 0x0b */
    { "f",   "\x0d" },		/* 0x0c */
    { ":",   "\x00" }		/* 0x0d */
};

static char *
scan_for_state(char *str)
{
    int s = 0;
    char *b = str;

    for (; *str; str++) {
	int i;

	for (i = 0; scanstate[s].c[i]; i++) {
	    if (scanstate[s].c[i] == *str)
		break;
	}

	if (scanstate[s].c[i]) {
	    s = scanstate[s].next[i];
	    if (s == 0)
		return b;
	} else {
	    s = 0;
	    b = str + 1;
	}
    }

    return NULL;
}

void
handle_config_line(char *inbuf, int len, struct absout *eout)
{
    char *portnum, *state, *timeoutstr, *devname, *devcfg;
    unsigned int timeout;
    char *strtok_data = NULL;
    const char **devcfg_argv;
    int err;

    if (len == 0)
	/* Ignore empty lines */
	goto out;

    if (inbuf[0] == '#')
	/* Ignore comments. */
	goto out;

    if (startswith(inbuf, "BANNER", &strtok_data)) {
	char *name = strtok_r(NULL, ":", &strtok_data);
	char *str = strtok_r(NULL, "\n", &strtok_data);
	if (name == NULL) {
	    eout->out(eout, "No banner name given on line %d", lineno);
	    goto out;
	}
	handle_longstr(name, str, BANNER, eout);
	goto out;
    }

    if (startswith(inbuf, "SIGNATURE", &strtok_data)) {
	char *name = strtok_r(NULL, ":", &strtok_data);
	char *str = strtok_r(NULL, "\n", &strtok_data);
	if (name == NULL) {
	    eout->out(eout, "No signature given on line %d", lineno);
	    goto out;
	}
	handle_longstr(name, str, SIGNATURE, eout);
	goto out;
    }

    if (startswith(inbuf, "OPENSTR", &strtok_data)) {
	char *name = strtok_r(NULL, ":", &strtok_data);
	char *str = strtok_r(NULL, "\n", &strtok_data);
	if (name == NULL) {
	    eout->out(eout, "No open string name given on line %d", lineno);
	    goto out;
	}
	handle_longstr(name, str, OPENSTR, eout);
	goto out;
    }

    if (startswith(inbuf, "CLOSESTR", &strtok_data)) {
	char *name = strtok_r(NULL, ":", &strtok_data);
	char *str = strtok_r(NULL, "\n", &strtok_data);
	if (name == NULL) {
	    eout->out(eout, "No close string name given on line %d", lineno);
	    goto out;
	}
	handle_longstr(name, str, CLOSESTR, eout);
	goto out;
    }

    if (startswith(inbuf, "CLOSEON", &strtok_data)) {
	char *name = strtok_r(NULL, ":", &strtok_data);
	char *str = strtok_r(NULL, "\n", &strtok_data);
	if (name == NULL) {
	    eout->out(eout, "No close on string name given on line %d", lineno);
	    goto out;
	}
	handle_longstr(name, str, CLOSEON, eout);
	goto out;
    }

    if (startswith(inbuf, "DEVICE", &strtok_data)) {
	char *name = strtok_r(NULL, ":", &strtok_data);
	char *str = strtok_r(NULL, "\n", &strtok_data);
	if (name == NULL) {
	    eout->out(eout, "No device name given on line %d", lineno);
	    goto out;
	}
	handle_longstr(name, str, DEVNAME, eout);
	goto out;
    }

    if (startswith(inbuf, "TRACEFILE", &strtok_data)) {
	char *name = strtok_r(NULL, ":", &strtok_data);
	char *str = strtok_r(NULL, "\n", &strtok_data);
	if (name == NULL) {
	    eout->out(eout, "No tracefile name given on line %d", lineno);
	    goto out;
	}
	if ((str == NULL) || (strlen(str) == 0)) {
	    eout->out(eout, "No tracefile given on line %d", lineno);
	    goto out;
	}
	handle_tracefile(name, str, eout);
	goto out;
    }

    if (startswith(inbuf, "CONTROLPORT", &strtok_data)) {
	char *config_port = strtok_r(NULL, "\n", &strtok_data);

	controller_init(config_port, NULL, NULL, eout);
	goto out;
    }

    if (startswith(inbuf, "RS485CONF", &strtok_data)) {
        char *name = strtok_r(NULL, ":", &strtok_data);
        char *str = strtok_r(NULL, "\n", &strtok_data);
        if (name == NULL) {
            eout->out(eout, "No signature given on line %d", lineno);
            goto out;
        }
        if ((str == NULL) || (strlen(str) == 0)) {
            eout->out(eout, "No RS485 configuration given on line %d", lineno);
            goto out;
        }
        handle_rs485conf(name, str, eout);
        goto out;
    }

    if (startswith(inbuf, "DEFAULT", &strtok_data)) {
	char *name = strtok_r(NULL, ":", &strtok_data);
	char *str = strtok_r(NULL, ":\n", &strtok_data);
	char *class = strtok_r(NULL, "\n", &strtok_data);

	if (name == NULL) {
	    eout->out(eout, "No default name given on line %d", lineno);
	    goto out;
	}
	if (str && strlen(str) == 0) {
	    str = NULL;
	}
	if (class) {
	    /* Watch out for trailing spaces. */
	    unsigned int len = strlen(class);

	    while(len > 0 && isspace(class[len]))
		len--;
	    class[len] = '\0';
	}

	err = gensio_set_default(so, class, name, str, 0);
	if (err)
	    eout->out(eout, "error setting default value on line %d for %s: %s",
		   lineno, name, strerror(err));
	goto out;
    }

    if (startswith(inbuf, "DELDEFAULT", &strtok_data)) {
	char *name = strtok_r(NULL, ":", &strtok_data);
	char *class = strtok_r(NULL, "\n", &strtok_data);

	if (!name) {
	    eout->out(eout, "No default name given on line %d", lineno);
	    goto out;
	}
	if (!class || strcmp(class, "ser2net") == 0 ||
			strcmp(class, "default") == 0) {
	    eout->out(eout, "Can only delete class default on line %d", lineno);
	    goto out;
	}

	err = gensio_del_default(so, class, name, false);
	if (err)
	    eout->out(eout, "error deleting default value on line %d for %s: %s",
		   lineno, name, strerror(err));
	goto out;
    }

    if (startswith(inbuf, "ROTATOR", &strtok_data)) {
	char *name = strtok_r(NULL, ":", &strtok_data);
	char *str = strtok_r(NULL, "\n", &strtok_data);
	int portc;
	const char **portv;

	if (name == NULL) {
	    eout->out(eout, "No rotator name given on line %d", lineno);
	    goto out;
	}

	err = gensio_str_to_argv(so, str, &portc, &portv, NULL);
	if (err) {
	    eout->out(eout, "Unable to allocate rotator argv on line %d",
		   lineno);
	    goto out;
	}
	err = add_rotator(eout, name, name, portc, portv, NULL, lineno);
	if (err)
	    gensio_argv_free(so, portv);
	goto out;
    }

    if (startswith(inbuf, "LED", &strtok_data)) {
	char *name = strtok_r(NULL, ":", &strtok_data);
	char *driver = strtok_r(NULL, ":", &strtok_data);
	char *cfg;
	const char **argv;

	if (name == NULL || strlen(name) == 0) {
	    eout->out(eout, "No LED name given on line %d", lineno);
	    goto out;
	}
	if ((driver == NULL) || (strlen(driver) == 0)) {
	    eout->out(eout, "No LED driver given on line %d", lineno);
	    goto out;
	}
	cfg = strtok_r(NULL, "\n", &strtok_data);
	err = gensio_str_to_argv(so, cfg, NULL, &argv, NULL);
	if (err) {
	    eout->out(eout, "Error parsing LED config: %s\n",
		   gensio_err_to_str(err));
	    goto out;
	}
	add_led(name, driver, argv, lineno, eout);
	gensio_argv_free(so, argv);
	goto out;
    }

    /* Scan for the state. */
    state = scan_for_state(inbuf);
    if (!state) {
	eout->out(eout, "No state given on line %d", lineno);
	goto out;
    }

    /* Everything before the state is the port number. */
    portnum = inbuf;
    *state = '\0';
    state++;

    /* Terminate the state. */
    inbuf = strchr(state, ':'); /* ":" must be there if scan_for_state works */
    *inbuf = '\0';
    inbuf++;

    timeoutstr = strtok_r(inbuf, ":", &strtok_data);
    if (timeoutstr == NULL) {
	eout->out(eout, "No timeout given on line %d", lineno);
	goto out;
    } else {
	char *end;

	timeout = strtoul(timeoutstr, &end, 0);
	if (end == timeoutstr || *end != '\0') {
	    eout->out(eout, "Invalid timeout '%s' on line %d\n",
		   timeoutstr, lineno);
	    goto out;
	}
    }

    devname = strtok_r(NULL, ":", &strtok_data);
    if (devname == NULL) {
	eout->out(eout, "No device name given on line %d", lineno);
	goto out;
    }

    devcfg = strtok_r(NULL, "", &strtok_data);
    if (devcfg == NULL)
	/* An empty device config is ok. */
	devcfg = "";

    err = gensio_str_to_argv(so, devcfg, NULL, &devcfg_argv, NULL);
    if (err) {
	eout->out(eout, "Invalid device config on line %d: %s",
	       lineno, gensio_err_to_str(err));
	goto out;
    }

    portconfig(eout, portnum, portnum, state, timeout, devname,
	       devcfg_argv);

    gensio_argv_free(so, devcfg_argv);
 out:
    return;
}

int
readconfig_init(void)
{
    int err = setup_defaults();

    if (err)
	return err;
    free_longstrs();
    free_tracefiles();
    free_rs485confs();
    free_leds();

    free_rotators();
    return 0;
}

/* Read the specified configuration file and call the routine to
   create the ports. */
int
readconfig(ftype *f, struct absout *eout)
{
    int rv = 0;
    unsigned int linesize = 0;
    char *inbuf = NULL;
    unsigned int len = 0;

    lineno = 0;

    do {
	rv = f_gets(f, &inbuf, &len, &linesize);
	if (rv == GE_REMCLOSE) {
	    rv = 0;
	    break;
	}
	if (rv) {
	    eout->out(eout, "Unable to read input line: %s",
		      gensio_err_to_str(rv));
	    goto out_err;
	}
	lineno++;

	/* Handle continued line. */
	if (len > 0 && inbuf[len - 1] == '\\') {
	    len--;
	    continue;
	}

	handle_config_line(inbuf, len, eout);
	len = 0;
    } while(1);

 out_err:
    free(inbuf);
    return rv;
}

