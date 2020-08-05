/*
 *  ser2net - A program for allowing telnet connection to serial ports
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
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

#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdbool.h>
#include <yaml.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <gensio/gensio.h>
#include <gensio/argvutils.h>
#include "ser2net.h"
#include "dataxfer.h"
#include "readconfig.h"
#include "led.h"

//#define DEBUG 1

/*
 * States for the state machine reading the configuration file.
 */
enum ystate {
    PARSE_ERR,
    BEGIN_DOC,

    /*
     * The main level consists of mappings.
     */
    MAIN_LEVEL,

    IN_DEFINE,

    /*
     * We have read the type of the main mapping (connection, led, etc)
     * now waiting for a mapping start.
     */
    IN_MAIN_NAME,

    /*
     * We are in the mapping of a "normal" main mapping, it will contain
     * things like name, accepter, etc. in key-value pairs.
     */
    IN_MAIN_MAP,

    /*
     * Got the key-value name, waiting for the value.
     */
    IN_MAIN_MAP_KEYVAL,

    /*
     * Got an "options" key, these consists of another mapping holding
     * the options.
     */
    IN_OPTIONS,
    IN_OPTIONS_MAP,
    IN_OPTIONS_NAME,

    /*
     * Special handling for an integer timeout.
     */
    IN_CONNSPEC_TIMEOUT,

    /*
     * Special handling for an enable bool.
     */
    IN_CONNSPEC_ENABLE,

    /*
     * Rotators have a sequence of connections.
     */
    IN_ROTATOR_CONNECTIONS,
    IN_ROTATOR_CONNECTIONS_SEQ,

    /*
     * Shouldn't see anything after this.
     */
    END_DOC
};

struct alias {
    char *name;
    char *value;
    unsigned int namelen;
    struct alias *next;
};

struct yfile {
    char *name;
    char *value;
    unsigned int namelen;
    struct yfile *next;
};

struct scalar_next_state;

struct option_info {
    char *name;
    enum ystate option_next_state;
};

struct keyval_info {
    char *name;
    unsigned int keyval_offset;
    int keyval_type;
};

struct map_info {
    char *name;
    struct scalar_next_state *states;
    enum ystate next_state;
    int map_type;
    bool needs_anchor;
};

enum which_info {
    WHICH_INFO_NONE = 0,
    WHICH_INFO_OPTION,
    WHICH_INFO_KEYVAL,
    WHICH_INFO_MAP
};

struct scalar_next_state {
    char *name;
    enum ystate next_state;
    enum which_info infotype;
    union {
	struct option_info *option_info;
	struct keyval_info *keyval_info;
	struct map_info *map_info;
    };
};

struct yconf {
    enum ystate state;

    struct map_info *map_info;

    struct keyval_info *keyval_info;
    /* main keyvalue types. */
    char *name;
    char *accepter;
    char *driver;
    char *connector;
    char *value;
    char *class;

    unsigned int timeout;
    bool enable;

    char **connections;
    unsigned int curr_connection;
    unsigned int connections_len;

    struct option_info *option_info;
    char **options;
    char *optionname;
    unsigned int curr_option;
    unsigned int options_len;

    struct alias *aliases;

    struct yfile *files;

    yaml_parser_t parser;
    yaml_event_t e;
    struct absout *eout;
};

static void
dofree(char **val)
{
    if (*val) {
	free(*val);
	*val = NULL;
    }
}
static void
yconf_cleanup_main(struct yconf *y)
{
    dofree(&y->name);
    dofree(&y->accepter);
    dofree(&y->driver);
    y->timeout = 0;
    y->enable = true;
    dofree(&y->connector);
    dofree(&y->value);
    dofree(&y->class);
    dofree(&y->optionname);
    if (y->options) {
	unsigned int i;

	for (i = 0; i < y->curr_option && y->options[i]; i++) {
	    free(y->options[i]);
	    y->options[i] = NULL;
	}
    }
    y->curr_option = 0;
    if (y->connections) {
	unsigned int i;

	for (i = 0; i < y->curr_connection && y->connections[i]; i++) {
	    free(y->connections[i]);
	    y->connections[i] = NULL;
	}
    }
    y->curr_connection = 0;
}

static int
syslog_eprint(struct absout *e, const char *str, ...)
{
    va_list ap;
    char buf[1024];
    struct yconf *y = e->data;

    va_start(ap, str);
    vsnprintf(buf, sizeof(buf), str, ap);
    va_end(ap);
    syslog(LOG_ERR, "%s on line %lu column %lu", buf,
	   (unsigned long) y->e.start_mark.line,
	   (unsigned long) y->e.start_mark.column);
    return 0;
}

static struct alias *
lookup_alias_len(struct yconf *y, const char *name, unsigned int len)
{
    struct alias *a;

    a = y->aliases;
    while (a && (a->namelen != len || strncmp(a->name, name, len) != 0))
	a = a->next;
    return a;
}

static struct alias *
lookup_alias(struct yconf *y, const char *name)
{
    return lookup_alias_len(y, name, strlen(name));
}

static int
add_alias(struct yconf *y, const char *iname, const char *ivalue)
{
    struct alias *a;
    char *name, *value;

    name = strdup(iname);
    if (!name) {
	y->eout->out(y->eout, "Out of memory allocating alias name");
	return -1;
    }
    value = strdup(ivalue);
    if (!value) {
	free(name);
	y->eout->out(y->eout, "Out of memory allocating alias value");
	return -1;
    }

    a = lookup_alias(y, name);
    if (a) {
	free(a->name);
	free(a->value);
    } else {
	a = malloc(sizeof(*a));
	if (!a) {
	    free(name);
	    free(value);
	    y->eout->out(y->eout, "Out of memory allocating alias");
	    return -1;
	}
	a->next = y->aliases;
	y->aliases = a;
    }
    a->name = name;
    a->value = value;
    a->namelen = strlen(name);
    return 0;
}

static struct yfile *
lookup_filename_len(struct yconf *y, const char *filename, unsigned int len)
{
    struct yfile *f = y->files;
    int infd, rv;
    char *name, *value = NULL;
    struct stat stat;

    while (f && f->namelen == len && strncmp(f->name, filename, len) != 0)
	f = f->next;
    if (f)
	return f;

    name = strndup(filename, len);
    if (!name) {
	y->eout->out(y->eout, "Out of memory allocating alias name");
	return NULL;
    }

    infd = open(name, O_RDONLY);
    if (infd == -1) {
	y->eout->out(y->eout, "Error opening %s: %s", name, strerror(errno));
	goto out_err;
    }

    rv = fstat(infd, &stat);
    if (rv == -1) {
	y->eout->out(y->eout, "Error stat-ing %s: %s", name, strerror(errno));
	goto out_err;
    }

    value = malloc(stat.st_size + 1);
    if (!value) {
	y->eout->out(y->eout, "Error allocating memory for file %s", name);
	goto out_err;
    }

    rv = read(infd, value, stat.st_size);
    if (rv == -1) {
	y->eout->out(y->eout, "Error reading %s: %s", name, strerror(errno));
	goto out_err;
    }
    value[stat.st_size] = '\0';

    f = malloc(sizeof(*f));
    if (!f) {
	y->eout->out(y->eout, "Error allocating memory for file struct %s",
		     name);
	goto out_err;
    }
    close(infd);

    f->name = name;
    f->namelen = strlen(name);
    f->value = value;
    f->next = y->files;
    y->files = f;

    return f;

 out_err:
    if (value)
	free(value);
    free(name);
    if (infd != -1)
	close(infd);
    return NULL;
}

static int
add_option(struct yconf *y, const char *name, const char *option,
	   const char *place)
{
    if (y->curr_option >= y->options_len) {
	unsigned int new_len = y->options_len + 10;
	char **new_options = malloc(sizeof(char *) * new_len);

	if (!new_options) {
	    y->eout->out(y->eout,
			 "Out of memory allocating option array for %s", place);
	    return -1;
	}
	memcpy(new_options, y->options, sizeof(char *) * y->options_len);
	free(y->options);
	y->options = new_options;
	y->options_len = new_len;
	    
    }

    if (name) {
	char *s;
	if (option && strlen(option) > 0) {
	    s = malloc(strlen(name) + strlen(option) + 2);
	    if (s)
		sprintf(s, "%s=%s", name, option);
	} else {
	    s = strdup(name);
	}
	if (!s) {
	    y->eout->out(y->eout, "Out of memory allocating option %s for %s",
			 option, place);
	    return -1;
	}
	y->options[y->curr_option] = s;
    } else {
	y->options[y->curr_option] = NULL;
    }
    y->curr_option++;
    return 0;
}

static int
add_connection(struct yconf *y, const char *connection, const char *place)
{
    if (y->curr_connection >= y->connections_len) {
	unsigned int new_len = y->connections_len + 10;
	char **new_connections = malloc(sizeof(char *) * new_len);

	if (!new_connections) {
	    y->eout->out(y->eout,
			 "Out of memory allocating connection array for %s",
			 place);
	    return -1;
	}
	memcpy(new_connections, y->connections,
	       sizeof(char *) * y->connections_len);
	free(y->connections);
	y->connections = new_connections;
	y->connections_len = new_len;
	    
    }

    if (connection) {
	y->connections[y->curr_connection] = strdup(connection);
	if (!y->connections[y->curr_connection]) {
	    y->eout->out(y->eout,
			 "Out of memory allocating connection %s for %s",
			 connection, place);
	    return -1;
	}
    } else {
	y->connections[y->curr_connection] = NULL;
    }
    y->curr_connection++;
    return 0;
}

enum main_keytypes {
    MAIN_KEYTYPE_name,
    MAIN_KEYTYPE_accepter,
    MAIN_KEYTYPE_driver,
    MAIN_KEYTYPE_connector,
    MAIN_KEYTYPE_value,
    MAIN_KEYTYPE_class
};

#define DECL_KEYVAL(type)						\
    static struct keyval_info keyval_##type = { #type,			\
						offsetof(struct yconf, type), \
						MAIN_KEYTYPE_##type }

DECL_KEYVAL(name);
DECL_KEYVAL(accepter);
DECL_KEYVAL(driver);
DECL_KEYVAL(connector);
DECL_KEYVAL(value);
DECL_KEYVAL(class);

#define KEYVAL_OFFSET(y)			\
    ((char **) (((char *) (y)) + (y)->keyval_info->keyval_offset))

static struct scalar_next_state sc_default[] = {
    { "name", IN_MAIN_MAP_KEYVAL, WHICH_INFO_KEYVAL,
      .keyval_info = &keyval_name },
    { "value", IN_MAIN_MAP_KEYVAL, WHICH_INFO_KEYVAL,
      .keyval_info = &keyval_value },
    { "class", IN_MAIN_MAP_KEYVAL, WHICH_INFO_KEYVAL,
      .keyval_info = &keyval_class },
    {}
};

static struct scalar_next_state sc_deldefault[] = {
    { "name", IN_MAIN_MAP_KEYVAL, WHICH_INFO_KEYVAL,
      .keyval_info = &keyval_name },
    { "class", IN_MAIN_MAP_KEYVAL, WHICH_INFO_KEYVAL,
      .keyval_info = &keyval_class },
    {}
};

static struct option_info connspec_option_info = {
    "connection",
    IN_MAIN_MAP,
};

static struct scalar_next_state sc_connection[] = {
    { "accepter", IN_MAIN_MAP_KEYVAL, WHICH_INFO_KEYVAL,
      .keyval_info = &keyval_accepter },
    { "timeout", IN_CONNSPEC_TIMEOUT },
    { "enable", IN_CONNSPEC_ENABLE },
    { "connector", IN_MAIN_MAP_KEYVAL, WHICH_INFO_KEYVAL,
      .keyval_info = &keyval_connector },
    { "options", IN_OPTIONS, WHICH_INFO_OPTION,
      .option_info = &connspec_option_info },
    {}
};

static struct option_info rotator_option_info = {
    "rotator",
    IN_MAIN_MAP,
};

static struct scalar_next_state sc_rotator[] = {
    { "accepter", IN_MAIN_MAP_KEYVAL, WHICH_INFO_KEYVAL,
      .keyval_info = &keyval_accepter },
    { "connections", IN_ROTATOR_CONNECTIONS },
    { "options", IN_OPTIONS, WHICH_INFO_OPTION,
      .option_info = &rotator_option_info },
    {}
};

static struct option_info led_option_info = {
    "led",
    IN_MAIN_MAP,
};

static struct scalar_next_state sc_led[] = {
    { "driver", IN_MAIN_MAP_KEYVAL, WHICH_INFO_KEYVAL,
      .keyval_info = &keyval_driver },
    { "options", IN_OPTIONS, WHICH_INFO_OPTION,
      .option_info = &led_option_info },
    {}
};

static struct scalar_next_state sc_admin[] = {
    { "accepter", IN_MAIN_MAP_KEYVAL, WHICH_INFO_KEYVAL,
      .keyval_info = &keyval_accepter },
    { "options", IN_OPTIONS, WHICH_INFO_OPTION,
      .option_info = &led_option_info },
    {}
};

enum main_map_types {
    MAIN_MAP_DEFAULT,
    MAIN_MAP_DELDEFAULT,
    MAIN_MAP_CONNECTION,
    MAIN_MAP_ROTATOR,
    MAIN_MAP_LED,
    MAIN_MAP_ADMIN
};

static struct map_info sc_default_map = {
    "default", sc_default, MAIN_LEVEL, MAIN_MAP_DEFAULT, false
};

static struct map_info sc_deldefault_map = {
    "deldefault", sc_deldefault, MAIN_LEVEL, MAIN_MAP_DELDEFAULT, false
};

static struct map_info sc_connection_map = {
    "connection", sc_connection, MAIN_LEVEL, MAIN_MAP_CONNECTION, true
};

static struct map_info sc_rotator_map = {
    "rotator", sc_rotator, MAIN_LEVEL, MAIN_MAP_ROTATOR, true
};

static struct map_info sc_led_map = {
    "led", sc_led, MAIN_LEVEL, MAIN_MAP_LED, true
};

static struct map_info sc_admin_map = {
    "admin", sc_admin, MAIN_LEVEL, MAIN_MAP_ADMIN, false
};

static struct scalar_next_state sc_main[] = {
    { "define", IN_DEFINE },
    { "default", IN_MAIN_NAME, WHICH_INFO_MAP, .map_info = &sc_default_map },
    { "delete_default", IN_MAIN_NAME, WHICH_INFO_MAP,
      .map_info = &sc_deldefault_map },
    { "connection", IN_MAIN_NAME, WHICH_INFO_MAP,
      .map_info = &sc_connection_map },
    { "rotator", IN_MAIN_NAME, WHICH_INFO_MAP, .map_info = &sc_rotator_map },
    { "led", IN_MAIN_NAME, WHICH_INFO_MAP, .map_info = &sc_led_map },
    { "admin", IN_MAIN_NAME, WHICH_INFO_MAP, .map_info = &sc_admin_map },
    {}
};

static int
setstr(char **oval, const char *ival, const char *mapname, const char *keyname,
       struct absout *eout)
{
    if (!ival || strlen(ival) == 0) {
	eout->out(eout, "Empty %s %s not permitted", mapname, keyname);
	return -1;
    }	
    if (*oval) {
	eout->out(eout, "%s %s already set in connection", mapname, keyname);
	return -1;
    }
    *oval = strdup(ival);
    if (!*oval) {
	eout->out(eout, "Unable to allocate %s %s", mapname, keyname);
	return -1;
    }
    return 0;
}

static void
scalar_next_state(struct yconf *y,
		  struct scalar_next_state *s, const char *scalar)
{
    while (s->name) {
	if (strcasecmp(s->name, scalar) == 0) {
	    switch (s->infotype) {
	    case WHICH_INFO_NONE: break;
	    case WHICH_INFO_OPTION: y->option_info = s->option_info; break;
	    case WHICH_INFO_KEYVAL: y->keyval_info = s->keyval_info; break;
	    case WHICH_INFO_MAP: y->map_info = s->map_info; break;
	    }
	    y->state = s->next_state;
	    return;
	}
	s++;
    }
    y->state = PARSE_ERR;
}

/*
 * Convert *(xxx) into the alias text and *{filename} into the
 * file's contents.
 */
static char *
process_scalar(struct yconf *y, const char *iscalar)
{
    struct absout *eout = y->eout;
    const char *s, *start = NULL;
    char *rv = NULL, *out = NULL;
    unsigned int len = 0, alen;
    int state = 0;

 restart:
    for (s = iscalar; *s; s++) {
	if (state == 0) {
	    if (*s == '*')
		state = 1;
	    else {
		if (out)
		    *out++ = *s;
		len++;
	    }
	} else if (state == 1) {
	    /* Last character was a '*' */
	    if (*s == '(') {
		start = s + 1;
		state = 2;
	    } else if (*s == '{') {
		start = s + 1;
		state = 3;
	    } else if (*s == '*') {
		if (out)
		    *out++ = *s;
		len++; /* Stay in state 1 */
	    } else {
		if (out) {
		    *out++ = '*';
		    *out++ = *s;
		}
		len += 2;
		state = 0;
	    }
	} else if (state == 2) {
	    /* We are in a '*(' */
	    if (start == s && *s == '*') {
		/* '*(*' outputs a '*(' */
		if (out) {
		    *out++ = '*';
		    *out++ = '(';
		}
		len += 2;
		state = 0;
	    } else if (!*s) {
		eout->out(eout, "Missing ')' for alias at '%s'", start - 2);
		goto out_err;
	    } else if (*s == ')') {
		struct alias *a = lookup_alias_len(y, start, s - start);
		if (!a) {
		    eout->out(eout, "unknown alias at '%s'", start - 2);
		    goto out_err;
		}
		alen = strlen(a->value);
		if (out) {
		    memcpy(out, a->value, alen);
		    out += alen;
		}
		len += alen;
		state = 0;
	    }
	} else if (state == 3) {
	    /* We are in a '*{' */
	    if (start == s && *s == '*') {
		/* '*{*' outputs a '*{' */
		if (out) {
		    *out++ = '*';
		    *out++ = '{';
		}
		len += 2;
		state = 0;
	    } else if (!*s) {
		eout->out(eout, "Missing '}' for filename at '%s'", start - 2);
		goto out_err;
	    } else if (*s == '}') {
		struct yfile *f = lookup_filename_len(y, start, s - start);
		if (!f)
		    goto out_err;
		alen = strlen(f->value);
		if (out) {
		    memcpy(out, f->value, alen);
		    out += alen;
		}
		len += alen;
		state = 0;
	    }
	}
    }
    if (!out) {
	out = malloc(len + 1);
	if (!out) {
	    eout->out(eout, "Out of memory processing string '%s'", iscalar);
	    return NULL;
	}
	rv = out;
	goto restart;
    }
    *out = '\0';

    return rv;

 out_err:
    if (rv)
	free(rv);
    return NULL;
}

static int
yhandle_scalar(struct yconf *y, const char *anchor, const char *iscalar)
{
    struct absout *eout = y->eout;
    bool anchor_allowed = false;
    char *end;
    char *scalar;

    scalar = process_scalar(y, iscalar);
    if (!scalar)
	return -1;

    switch (y->state) {
    case MAIN_LEVEL:
	scalar_next_state(y, sc_main, scalar);
	if (y->state == PARSE_ERR) {
	    eout->out(eout, "Invalid token at the main level: %s\n", scalar);
	    goto out_err;
	}
	break;

    case IN_DEFINE:
	anchor_allowed = true;
	if (!anchor)
	    eout->out(eout, "No anchor for define, define ignored\n");
	else {
	    if (add_alias(y, anchor, scalar))
		goto out_err;
	}
	y->state = MAIN_LEVEL;
	break;

    case IN_MAIN_MAP:
	scalar_next_state(y, y->map_info->states, scalar);
	if (y->state == PARSE_ERR) {
	    eout->out(eout, "Invalid token in the %s: %s",
		      y->map_info->name, scalar);
	    goto out_err;
	}
	break;
	    
    case IN_MAIN_MAP_KEYVAL:
	if (setstr(KEYVAL_OFFSET(y), scalar, y->map_info->name,
		   y->keyval_info->name, eout))
	    goto out_err;
	y->state = IN_MAIN_MAP;
	break;

    case IN_CONNSPEC_TIMEOUT:
	y->timeout = strtoul(scalar, &end, 0);
	if (end == scalar || *end != '\0') {
	    eout->out(eout, "Invalid number in connection timeout");
	    goto out_err;
	}
	y->state = IN_MAIN_MAP;
	break;

    case IN_CONNSPEC_ENABLE:
	if (strcasecmp(scalar, "on") == 0) {
	    y->enable = true;
	} else if (strcasecmp(scalar, "off") == 0) {
	    y->enable = false;
	} else {
	    eout->out(eout, "enable must be 'on' or 'off'");
	    goto out_err;
	}
	y->state = IN_MAIN_MAP;
	break;

    case IN_OPTIONS_MAP:
	if (setstr(&y->optionname, scalar, y->option_info->name, "option name",
		   eout))
	    goto out_err;
	y->state = IN_OPTIONS_NAME;
	break;

    case IN_OPTIONS_NAME:
	if (add_option(y, y->optionname, scalar, y->option_info->name))
	    goto out_err;
	dofree(&y->optionname);
	y->state = IN_OPTIONS_MAP;
	break;

    case IN_ROTATOR_CONNECTIONS_SEQ:
	if (add_connection(y, scalar, "rotator"))
	    goto out_err;
	break;

    default:
	eout->out(eout, "Unexpected scalar value");
	goto out_err;
    }

    if (anchor && !anchor_allowed)
	eout->out(eout, "Anchor on non-scalar ignored\n");

    free(scalar);
    return 0;

 out_err:
    free(scalar);
    return -1;
}

static int
yhandle_seq_start(struct yconf *y)
{
    switch (y->state) {
    case IN_ROTATOR_CONNECTIONS:
	y->state = IN_ROTATOR_CONNECTIONS_SEQ;
	break;

    default:
	y->eout->out(y->eout, "Unexpected sequence start: %d", y->state);
	return -1;
    }

    return 0;
}

static int
yhandle_seq_end(struct yconf *y)
{
    switch (y->state) {
    case IN_ROTATOR_CONNECTIONS_SEQ:
	y->state = IN_MAIN_MAP;
	break;

    default:
	y->eout->out(y->eout, "Unexpected sequence end: %d", y->state);
	return -1;
    }

    return 0;
}

static int
yhandle_mapping_start(struct yconf *y)
{
    struct absout *eout = y->eout;

    switch (y->state) {
    case BEGIN_DOC:
	y->state = MAIN_LEVEL;
	break;

    case IN_MAIN_NAME:
	if (y->map_info->needs_anchor) {
	    char *anchor = (char *) y->e.data.mapping_start.anchor;

	    if (!anchor) {
		eout->out(eout, "Main mapping requires an anchor for the name");
		return -1;
	    }
	    y->name = strdup(anchor);
	    if (!y->name) {
		eout->out(eout, "Out of memory allocating name");
		return -1;
	    }
	    if (add_alias(y, anchor, anchor))
		return -1;
	}
	y->state = IN_MAIN_MAP;
	break;

    case IN_OPTIONS:
	y->state = IN_OPTIONS_MAP;
	break;

    default:
	eout->out(eout, "Unexpected mapping start: %d", y->state);
	return -1;
    }

    return 0;
}

static int
yhandle_mapping_end(struct yconf *y)
{
    struct absout *eout = y->eout;
    int err, argc;
    const char **argv;

    switch (y->state) {
    case MAIN_LEVEL:
	y->state = END_DOC;
	break;

    case IN_MAIN_MAP:
	switch (y->map_info->map_type) {
	case MAIN_MAP_DEFAULT:
	    if (!y->name) {
		eout->out(eout, "No name given in default");
		return -1;
	    }
	    err = gensio_set_default(so, y->class, y->name, y->value, 0);
	    if (err) {
		eout->out(eout, "Unable to set default name %s:%s:%s: %s",
			  y->class ? y->class : "",
			  y->name, y->value, gensio_err_to_str(err));
		return -1;
	    }
	    y->state = MAIN_LEVEL;
	    yconf_cleanup_main(y);
	    break;

	case MAIN_MAP_DELDEFAULT:
	    if (!y->name) {
		eout->out(eout, "No name given in delete_default");
		return -1;
	    }
	    if (!y->class) {
		eout->out(eout, "No class given in delete_default");
		return -1;
	    }
	    err = gensio_del_default(so, y->class, y->name, false);
	    if (err) {
		eout->out(eout, "Unable to set default name %s:%s:%s: %s",
			  y->class ? y->class : "",
			  y->name, y->value, gensio_err_to_str(err));
		return -1;
	    }
	    y->state = MAIN_LEVEL;
	    yconf_cleanup_main(y);
	    break;

	case MAIN_MAP_CONNECTION:
	    if (!y->name) {
		eout->out(eout, "No name given in connection");
		return -1;
	    }
	    if (!y->accepter) {
		eout->out(eout, "No accepter given in connection");
		return -1;
	    }
	    if (!y->connector) {
		eout->out(eout, "No connector given in connection");
		return -1;
	    }
	    /* NULL terminate the options. */
	    if (add_option(y, NULL, NULL, "connection"))
		return -1;
	    portconfig(eout, y->name, y->accepter,
		       y->enable ? "raw" : "off", y->timeout,
		       y->connector, (const char **) y->options);
	    y->state = MAIN_LEVEL;
	    yconf_cleanup_main(y);
	    break;
	
	case MAIN_MAP_ROTATOR:
	    if (!y->name) {
		eout->out(eout, "No name given in rotator");
		return -1;
	    }
	    if (!y->accepter) {
		eout->out(eout, "No accepter given in rotator");
		return -1;
	    }
	    if (y->curr_connection == 0) {
		eout->out(eout, "No connections given in rotator");
		return -1;
	    }
	    /* NULL terminate the connections. */
	    if (add_connection(y, NULL, "rotator"))
		return -1;
	    err = gensio_argv_copy(so, (const char **) y->connections,
				   &argc, &argv);
	    if (err) {
		eout->out(eout, "Unable to allocate rotator connections");
		return -1;
	    }
	    /* NULL terminate the options. */
	    if (add_option(y, NULL, NULL, "rotator"))
		return -1;
	    err = add_rotator(y->name, y->accepter, argc, argv,
			      (const char **) y->options, y->e.start_mark.line);
	    if (err)
		gensio_argv_free(so, argv);
	    y->state = MAIN_LEVEL;
	    yconf_cleanup_main(y);
	    break;

	case MAIN_MAP_LED:
	    if (!y->name) {
		eout->out(eout, "No name given in led");
		return -1;
	    }
	    if (!y->driver) {
		eout->out(eout, "No driver given in led");
		return -1;
	    }
	    /* NULL terminate the options. */
	    if (add_option(y, NULL, NULL, "led"))
		return -1;
	    err = add_led(y->name, y->driver,
			  (const char **) y->options, y->e.start_mark.line);
	    y->state = MAIN_LEVEL;
	    yconf_cleanup_main(y);
	    break;

	case MAIN_MAP_ADMIN:
	    if (!y->accepter) {
		eout->out(eout, "No accepter given in admin");
		return -1;
	    }
	    /* NULL terminate the options. */
	    if (add_option(y, NULL, NULL, "admin"))
		return -1;
	    controller_init(y->accepter, (const char **) y->options, eout);
	    y->state = MAIN_LEVEL;
	    yconf_cleanup_main(y);
	    break;
	}
	break;

    case IN_OPTIONS_MAP:
	y->state = y->option_info->option_next_state;
	break;

    default:
	eout->out(eout, "Unexpected mapping end: %d", y->state);
	return -1;
    }

    return 0;
}

struct yaml_read_handler_data {
    FILE *f;
    char **config_lines;
    unsigned int num_config_lines;
    unsigned int curr;
    unsigned int pos;
    char in_quote;
    bool in_escape;
};

/*
 * Copy characters from input to buffer, up to either buffer_size or
 * input_size.  Upon return buffer_size and input_size are updated to
 * the actual number of each processed.
 *
 * "#" characters outside of quotes are converted to newlines.
 *
 * Returns 0 on an error or 1 on success.
 */
static int
process_buffer(struct yaml_read_handler_data *d,
	       unsigned char *buffer, size_t *buffer_size,
	       char *input, unsigned int *input_size)
{
    unsigned int in_len = 0;
    size_t out_len = 0;

    while (in_len < *input_size && out_len < *buffer_size) {
	char c = *input++;

	switch(c) {
	case '\'':
	case '"':
	    if (d->in_quote == '"' && d->in_escape)
		/* \" in "" doens't end the quotes. */
		goto normal_char;
	    if (d->in_quote == c)
		d->in_quote = 0;
	    else if (!d->in_quote)
		d->in_quote = c;
	    goto normal_char;

	case '#':
	    if (!d->in_quote)
		c = '\n';
	    goto normal_char;

	case '\\':
	    d->in_escape = !d->in_escape;
	    goto normal_char_skip_escape;

	default:
	normal_char:
	    d->in_escape = false;
	normal_char_skip_escape:
	    *buffer++ = c;
	    in_len++;
	    out_len++;
	    break;
	}
    }

    *input_size = in_len;
    *buffer_size = out_len;

    return 1;
}

static int
yaml_read_handler(void *data, unsigned char *buffer, size_t size,
		  size_t *size_read)
{
    struct yaml_read_handler_data *d = data;

    *size_read = 0;

    if (d->f) {
	*size_read = fread(buffer, 1, size, d->f);
	if (*size_read < size) {
	    if (ferror(d->f)) {
		syslog(LOG_ERR, "Error reading input file: %m");
		return 0;
	    }
	    /* End of file */
	    d->f = NULL;
	    size -= *size_read;
	    buffer += *size_read;
	} else {
	    return 1;
	}
    }

    while (d->curr < d->num_config_lines && size > 1) {
	unsigned int len = strlen(d->config_lines[d->curr]);

	size--; /* leave space for the terminating newline. */
	if (d->pos < len) {
	    unsigned int input_processed = len - d->pos;
	    size_t output_processed = size;

	    if (!process_buffer(d, buffer, &output_processed,
				d->config_lines[d->curr] + d->pos,
				&input_processed)) {
		syslog(LOG_ERR, "Invalid yaml config string");
		return 0;
	    }
	    size -= output_processed;
	    buffer += output_processed;
	    *size_read += output_processed;
	    d->pos += input_processed;
	    if (d->pos >= len) {
		d->pos = 0;
		d->curr++;
		*buffer++ = '\n'; /* Put a newline after each -Y */
		(*size_read)++;
	    }
	}
    }

    /*
     * We could check d->in_quote and d->in_escape, but normal yaml
     * processing should catch those errors.
     */

    return 1;
}

int
yaml_readconfig(FILE *f, char **config_lines, unsigned int num_config_lines)
{
    bool done = false;
    struct yconf y;
    struct absout yeout = { .out = syslog_eprint, .data = &y };
    struct absout *eout = &yeout;
    int err = 0;
    struct yaml_read_handler_data d;

    memset(&y, 0, sizeof(y));
    y.enable = true;
    y.options = malloc(sizeof(char *) * 10);
    if (!y.options) {
	syslog(LOG_ERR, "Out of memory allocating options array");
	return ENOMEM;
    }
    y.options_len = 10;
    y.connections = malloc(sizeof(char *) * 10);
    if (!y.connections) {
	free(y.options);
	syslog(LOG_ERR, "Out of memory allocating connection array");
	return ENOMEM;
    }
    y.connections_len = 10;
    y.state = BEGIN_DOC;
    y.eout = eout;

    yaml_parser_initialize(&y.parser);

    memset(&d, 0, sizeof(d));
    d.f = f;
    d.config_lines = config_lines;
    d.num_config_lines = num_config_lines;
    yaml_parser_set_input(&y.parser, yaml_read_handler, &d);

    while (!done && !err) {
	if (!yaml_parser_parse(&y.parser, &y.e)) {
	    syslog(LOG_ERR, "yaml parsing error at line %lu column %lu: %s",
		   (unsigned long) y.parser.problem_mark.line,
		   (unsigned long) y.parser.problem_mark.column,
		   y.parser.problem);
	    err = EINVAL;
	    break;
	}

	switch (y.e.type) {
	case YAML_NO_EVENT:
	case YAML_STREAM_START_EVENT:
	case YAML_DOCUMENT_START_EVENT:
	case YAML_DOCUMENT_END_EVENT:
	    break;

	case YAML_STREAM_END_EVENT:
	    if (y.state != END_DOC) {
		syslog(LOG_ERR, "yaml file ended in invalid state: %d",
		       y.state);
		err = EINVAL;
	    }
	    done = true;
	    break;

	case YAML_ALIAS_EVENT: {
	    struct alias *a;
#if DEBUG
	    printf("YAML_ALIAS_EVENT\n");
	    printf(" anc: '%s'\n", y.e.data.alias.anchor);
#endif
	    a = lookup_alias(&y, (char *) y.e.data.alias.anchor);
	    if (!a) {
		eout->out(eout, "Unable to find alias '%s'",
			  y.e.data.alias.anchor);
		err = EINVAL;
	    } else {
		if (yhandle_scalar(&y, NULL, a->value))
		    err = EINVAL;
	    }
	    break;
	}

	case YAML_SCALAR_EVENT:
#if DEBUG
	    printf("YAML_SCALAR_EVENT\n");
	    printf(" anc: '%s'\n", y.e.data.scalar.anchor);
	    printf(" tag: '%s'\n", y.e.data.scalar.tag);
	    printf(" val: '%s'\n", y.e.data.scalar.value);
#endif
	    if (yhandle_scalar(&y, (char *) y.e.data.scalar.anchor,
			       (char *) y.e.data.scalar.value))
		err = EINVAL;
	    break;

	case YAML_SEQUENCE_START_EVENT:
#if DEBUG
	    printf("YAML_SEQUENCE_START_EVENT\n");
	    printf(" anc: '%s'\n", y.e.data.sequence_start.anchor);
	    printf(" tag: '%s'\n", y.e.data.sequence_start.tag);
#endif
	    if (yhandle_seq_start(&y))
		err = EINVAL;
	    break;

	case YAML_SEQUENCE_END_EVENT:
#if DEBUG
	    printf("YAML_SEQUENCE_END_EVENT\n");
#endif
	    if (yhandle_seq_end(&y))
		err = EINVAL;
	    break;

	case YAML_MAPPING_START_EVENT:
#if DEBUG
	    printf("YAML_MAPPING_START_EVENT\n");
	    printf(" anc: '%s'\n", y.e.data.mapping_start.anchor);
	    printf(" tag: '%s'\n", y.e.data.mapping_start.tag);
#endif
	    if (yhandle_mapping_start(&y))
		err = EINVAL;
	    break;

	case YAML_MAPPING_END_EVENT:
#if DEBUG
	    printf("YAML_MAPPING_END_EVENT\n");
#endif
	    if (yhandle_mapping_end(&y))
		err = EINVAL;
	    break;
	}

	yaml_event_delete(&y.e);
    }

    yaml_parser_delete(&y.parser);

    yconf_cleanup_main(&y);
    free(y.options);
    free(y.connections);
    while (y.aliases) {
	struct alias *a = y.aliases;
	y.aliases = a->next;
	free(a->name);
	free(a->value);
	free(a);
    }

    while (y.files) {
	struct yfile *f = y.files;
	y.files = f->next;
	free(f->name);
	free(f->value);
	free(f);
    }

    return err;
}
