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
#include <stdarg.h>
#include <stdbool.h>
#include <yaml.h>
#include <syslog.h>
#include <gensio/gensio.h>
#include <gensio/argvutils.h>
#include "ser2net.h"
#include "dataxfer.h"
#include "readconfig.h"

//#define DEBUG 1

enum ystate {
    PARSE_ERR,
    BEGIN_DOC,
    MAIN_LEVEL,
    IN_DEFINE,
    IN_DEFAULT,
    IN_DEFAULT_MAP,
    IN_DEFAULT_NAME,
    IN_DEFAULT_VALUE,
    IN_DEFAULT_CLASS,
    IN_DELDEFAULT,
    IN_DELDEFAULT_MAP,
    IN_DELDEFAULT_NAME,
    IN_DELDEFAULT_CLASS,
    IN_CONNSPEC,
    IN_CONNSPEC_MAP,
    IN_CONNSPEC_NAME,
    IN_CONNSPEC_ACCEPTER,
    IN_CONNSPEC_TIMEOUT,
    IN_CONNSPEC_CONNECTOR,
    IN_CONNSPEC_OPTIONS,
    IN_CONNSPEC_OPTIONS_MAP,
    IN_CONNSPEC_OPTIONS_NAME,
    IN_ROTATOR,
    IN_ROTATOR_MAP,
    IN_ROTATOR_NAME,
    IN_ROTATOR_ACCEPTER,
    IN_ROTATOR_CONNECTIONS,
    IN_ROTATOR_CONNECTIONS_SEQ,
    IN_ROTATOR_OPTIONS,
    IN_ROTATOR_OPTIONS_MAP,
    IN_ROTATOR_OPTIONS_NAME,
    END_DOC
};

struct alias {
    char *name;
    char *value;
    struct alias *next;
};

struct yconf {
    enum ystate state;
    char *name;
    char *accepter;
    unsigned int timeout;
    char *connector;
    char *value;
    char *class;
    char *optionname;
    char **connections;
    unsigned int curr_connection;
    unsigned int connections_len;
    char **options;
    unsigned int curr_option;
    unsigned int options_len;
    yaml_parser_t parser;
    yaml_event_t e;
    struct alias *aliases;
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
    y->timeout = 0;
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
	   y->e.start_mark.line, y->e.start_mark.column);
    return 0;
}

static struct alias *
lookup_alias(struct yconf *y, const char *name)
{
    struct alias *a;

    a = y->aliases;
    while (a && strcmp(a->name, name) != 0)
	a = a->next;
    return a;
}

static int
add_alias(struct yconf *y, const char *iname, const char *ivalue,
	  struct absout *eout)
{
    struct alias *a;
    char *name, *value;

    name = strdup(iname);
    if (!name) {
	eout->out(eout, "Out of memory allocating alias name");
	return -1;
    }
    value = strdup(ivalue);
    if (!value) {
	free(name);
	eout->out(eout, "Out of memory allocating alias value");
	return -1;
    }

    a = lookup_alias(y, name);
    if (a) {
	free(a->name);
	free(a->value);
    } else {
	a = malloc(sizeof(*a));
	if (!a) {
	    eout->out(eout, "Out of memory allocating alias");
	    return -1;
	}
	a->next = y->aliases;
	y->aliases = a;
    }
    a->name = name;
    a->value = value;
    return 0;
}

static int
add_option(struct yconf *y, const char *name, const char *option,
	   const char *place, struct absout *eout)
{
    if (y->curr_option >= y->options_len) {
	unsigned int new_len = y->options_len + 10;
	char **new_options = malloc(sizeof(char *) * new_len);

	if (!new_options) {
	    eout->out(eout, "Out of memory allocating option array for %s",
		      place);
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
	    eout->out(eout, "Out of memory allocating option %s for %s",
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
add_connection(struct yconf *y, const char *connection, const char *place,
	       struct absout *eout)
{
    if (y->curr_connection >= y->connections_len) {
	unsigned int new_len = y->connections_len + 10;
	char **new_connections = malloc(sizeof(char *) * new_len);

	if (!new_connections) {
	    eout->out(eout, "Out of memory allocating connection array for %s",
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
	    eout->out(eout, "Out of memory allocating connection %s for %s",
		      connection, place);
	    return -1;
	}
    } else {
	y->connections[y->curr_connection] = NULL;
    }
    y->curr_connection++;
    return 0;
}

struct scalar_next_state {
    char *name;
    enum ystate next_state;
};

static struct scalar_next_state sc_main[] = {
    { "define", IN_DEFINE },
    { "default", IN_DEFAULT },
    { "delete_default", IN_DELDEFAULT },
    { "connection", IN_CONNSPEC },
    { "rotator", IN_ROTATOR },
    {}
};

static struct scalar_next_state sc_default[] = {
    { "name", IN_DEFAULT_NAME },
    { "value", IN_DEFAULT_VALUE },
    { "class", IN_DEFAULT_CLASS },
    {}
};

static struct scalar_next_state sc_deldefault[] = {
    { "name", IN_DELDEFAULT_NAME },
    { "class", IN_DELDEFAULT_CLASS },
    {}
};

static struct scalar_next_state sc_connspec[] = {
    { "name", IN_CONNSPEC_NAME },
    { "accepter", IN_CONNSPEC_ACCEPTER },
    { "timeout", IN_CONNSPEC_TIMEOUT },
    { "connector", IN_CONNSPEC_CONNECTOR },
    { "options", IN_CONNSPEC_OPTIONS },
    {}
};

static struct scalar_next_state sc_rotator[] = {
    { "name", IN_ROTATOR_NAME },
    { "accepter", IN_ROTATOR_ACCEPTER },
    { "connections", IN_ROTATOR_CONNECTIONS },
    { "options", IN_ROTATOR_OPTIONS },
    {}
};

static int
setstr(char **oval, const char *ival, const char *desc, struct absout *eout)
{
    if (!ival || strlen(ival) == 0) {
	eout->out(eout, "Empty %s not permitted", desc);
	return -1;
    }	
    if (*oval) {
	eout->out(eout, "%s already set in connection", desc);
	return -1;
    }
    *oval = strdup(ival);
    if (!*oval) {
	eout->out(eout, "Unable to allocate %s", desc);
	return -1;
    }
    return 0;
}

static enum ystate
scalar_next_state(struct scalar_next_state *s, const char *scalar)
{
    while (s->name) {
	if (strcmp(s->name, scalar) == 0)
	    return s->next_state;
	s++;
    }
    return PARSE_ERR;
}

static int
yhandle_scalar(struct yconf *y, const char *anchor, const char *scalar,
	       struct absout *eout)
{
    bool anchor_allowed = false;
    char *end;

    switch (y->state) {
    case MAIN_LEVEL:
	y->state = scalar_next_state(sc_main, scalar);
	if (y->state == PARSE_ERR) {
	    eout->out(eout, "Invalid token at the main level: %s\n", scalar);
	    return -1;
	}
	break;

    case IN_DEFINE:
	anchor_allowed = true;
	if (!anchor)
	    eout->out(eout, "No anchor for define, define ignored\n");
	else {
	    if (add_alias(y, anchor, scalar, eout))
		return -1;
	}
	y->state = MAIN_LEVEL;
	break;

    case IN_DEFAULT_MAP:
	y->state = scalar_next_state(sc_default, scalar);
	if (y->state == PARSE_ERR) {
	    eout->out(eout, "Invalid token in the default: %s\n", scalar);
	    return -1;
	}
	break;
	    
    case IN_DEFAULT_NAME:
	if (setstr(&y->name, scalar, "default name", eout))
	    return -1;
	y->state = IN_DEFAULT_MAP;
	break;

    case IN_DEFAULT_VALUE:
	if (setstr(&y->value, scalar, "default value", eout))
	    return -1;
	y->state = IN_DEFAULT_MAP;
	break;

    case IN_DEFAULT_CLASS:
	if (setstr(&y->class, scalar, "default class", eout))
	    return -1;
	y->state = IN_DEFAULT_MAP;
	break;

    case IN_DELDEFAULT_MAP:
	y->state = scalar_next_state(sc_deldefault, scalar);
	if (y->state == PARSE_ERR) {
	    eout->out(eout, "Invalid token in delete_default: %s\n", scalar);
	    return -1;
	}
	break;
	    
    case IN_DELDEFAULT_NAME:
	if (setstr(&y->name, scalar, "delete_default name", eout))
	    return -1;
	y->state = IN_DELDEFAULT_MAP;
	break;

    case IN_DELDEFAULT_CLASS:
	if (setstr(&y->class, scalar, "delete_default class", eout))
	    return -1;
	y->state = IN_DEFAULT_MAP;
	break;

    case IN_CONNSPEC_MAP:
	y->state = scalar_next_state(sc_connspec, scalar);
	if (y->state == PARSE_ERR) {
	    eout->out(eout, "Invalid token in the connection map: %s\n",
		      scalar);
	    return -1;
	}
	break;

    case IN_CONNSPEC_NAME:
	if (setstr(&y->name, scalar, "connection name", eout))
	    return -1;
	y->state = IN_CONNSPEC_MAP;
	break;

    case IN_CONNSPEC_ACCEPTER:
	if (setstr(&y->accepter, scalar, "connection accepter", eout))
	    return -1;
	y->state = IN_CONNSPEC_MAP;
	break;

    case IN_CONNSPEC_TIMEOUT:
	y->timeout = strtoul(scalar, &end, 0);
	if (end == scalar || *end != '\0') {
	    eout->out(eout, "Invalid number in connection timeout");
	    return -1;
	}
	y->state = IN_CONNSPEC_MAP;
	break;

    case IN_CONNSPEC_CONNECTOR:
	if (setstr(&y->connector, scalar, "connection connector", eout))
	    return -1;
	y->state = IN_CONNSPEC_MAP;
	break;

    case IN_CONNSPEC_OPTIONS_MAP:
	if (setstr(&y->optionname, scalar, "connection option name", eout))
	    return -1;
	y->state = IN_CONNSPEC_OPTIONS_NAME;
	break;

    case IN_CONNSPEC_OPTIONS_NAME:
	if (add_option(y, y->optionname, scalar, "connection", eout))
	    return -1;
	dofree(&y->optionname);
	y->state = IN_CONNSPEC_OPTIONS_MAP;
	break;

    case IN_ROTATOR_MAP:
	y->state = scalar_next_state(sc_rotator, scalar);
	if (y->state == PARSE_ERR) {
	    eout->out(eout, "Invalid token in the rotator map: %s\n",
		      scalar);
	    return -1;
	}
	break;

    case IN_ROTATOR_NAME:
	if (setstr(&y->name, scalar, "rotator name", eout))
	    return -1;
	y->state = IN_ROTATOR_MAP;
	break;

    case IN_ROTATOR_ACCEPTER:
	if (setstr(&y->accepter, scalar, "rotator accepter", eout))
	    return -1;
	y->state = IN_ROTATOR_MAP;
	break;

    case IN_ROTATOR_CONNECTIONS_SEQ:
	if (add_connection(y, scalar, "rotator", eout))
	    return -1;
	break;

    case IN_ROTATOR_OPTIONS_MAP:
	if (setstr(&y->optionname, scalar, "rotator option name", eout))
	    return -1;
	y->state = IN_ROTATOR_OPTIONS_NAME;
	break;

    case IN_ROTATOR_OPTIONS_NAME:
	if (add_option(y, y->optionname, scalar, "rotator", eout))
	    return -1;
	dofree(&y->optionname);
	y->state = IN_ROTATOR_OPTIONS_MAP;
	break;

    case PARSE_ERR:
    case BEGIN_DOC:
    case IN_DEFAULT:
    case IN_DELDEFAULT:
    case IN_CONNSPEC:
    case IN_CONNSPEC_OPTIONS:
    case IN_ROTATOR:
    case IN_ROTATOR_CONNECTIONS:
    case IN_ROTATOR_OPTIONS:
    case END_DOC:
	eout->out(eout, "Unexpected scalar value");
	return -1;
    }

    if (anchor && !anchor_allowed)
	eout->out(eout, "Anchor on non-scalar ignored\n");
    return 0;
}

static int
yhandle_seq_start(struct yconf *y, struct absout *eout)
{
    switch (y->state) {
    case IN_ROTATOR_CONNECTIONS:
	y->state = IN_ROTATOR_CONNECTIONS_SEQ;
	break;

    case IN_CONNSPEC_OPTIONS:
    case IN_ROTATOR_OPTIONS:
    case PARSE_ERR:
    case BEGIN_DOC:
    case MAIN_LEVEL:
    case IN_DEFINE:
    case IN_DEFAULT:
    case IN_DEFAULT_MAP:
    case IN_DEFAULT_NAME:
    case IN_DEFAULT_VALUE:
    case IN_DEFAULT_CLASS:
    case IN_DELDEFAULT:
    case IN_DELDEFAULT_MAP:
    case IN_DELDEFAULT_NAME:
    case IN_DELDEFAULT_CLASS:
    case IN_CONNSPEC:
    case IN_CONNSPEC_MAP:
    case IN_CONNSPEC_NAME:
    case IN_CONNSPEC_ACCEPTER:
    case IN_CONNSPEC_TIMEOUT:
    case IN_CONNSPEC_CONNECTOR:
    case IN_CONNSPEC_OPTIONS_MAP:
    case IN_CONNSPEC_OPTIONS_NAME:
    case IN_ROTATOR:
    case IN_ROTATOR_MAP:
    case IN_ROTATOR_NAME:
    case IN_ROTATOR_ACCEPTER:
    case IN_ROTATOR_CONNECTIONS_SEQ:
    case IN_ROTATOR_OPTIONS_MAP:
    case IN_ROTATOR_OPTIONS_NAME:
    case END_DOC:
	eout->out(eout, "Unexpected sequence start: %d", y->state);
	return -1;
    }

    return 0;
}

static int
yhandle_seq_end(struct yconf *y, struct absout *eout)
{
    switch (y->state) {
    case IN_ROTATOR_CONNECTIONS_SEQ:
	y->state = IN_ROTATOR_MAP;
	break;

    case PARSE_ERR:
    case BEGIN_DOC:
    case MAIN_LEVEL:
    case IN_DEFINE:
    case IN_DEFAULT:
    case IN_DEFAULT_MAP:
    case IN_DEFAULT_NAME:
    case IN_DEFAULT_VALUE:
    case IN_DEFAULT_CLASS:
    case IN_DELDEFAULT:
    case IN_DELDEFAULT_MAP:
    case IN_DELDEFAULT_NAME:
    case IN_DELDEFAULT_CLASS:
    case IN_CONNSPEC:
    case IN_CONNSPEC_MAP:
    case IN_CONNSPEC_NAME:
    case IN_CONNSPEC_ACCEPTER:
    case IN_CONNSPEC_TIMEOUT:
    case IN_CONNSPEC_CONNECTOR:
    case IN_CONNSPEC_OPTIONS:
    case IN_CONNSPEC_OPTIONS_MAP:
    case IN_CONNSPEC_OPTIONS_NAME:
    case IN_ROTATOR:
    case IN_ROTATOR_MAP:
    case IN_ROTATOR_NAME:
    case IN_ROTATOR_ACCEPTER:
    case IN_ROTATOR_CONNECTIONS:
    case IN_ROTATOR_OPTIONS:
    case IN_ROTATOR_OPTIONS_MAP:
    case IN_ROTATOR_OPTIONS_NAME:
    case END_DOC:
	eout->out(eout, "Unexpected sequence end: %d", y->state);
	return -1;
    }

    return 0;
}

static int
yhandle_mapping_start(struct yconf *y, struct absout *eout)
{
    switch (y->state) {
    case BEGIN_DOC:
	y->state = MAIN_LEVEL;
	break;

    case IN_DEFAULT:
	y->state = IN_DEFAULT_MAP;
	break;

    case IN_DELDEFAULT:
	y->state = IN_DELDEFAULT_MAP;
	break;

    case IN_CONNSPEC:
	y->state = IN_CONNSPEC_MAP;
	break;

    case IN_ROTATOR:
	y->state = IN_ROTATOR_MAP;
	break;

    case IN_CONNSPEC_OPTIONS:
	y->state = IN_CONNSPEC_OPTIONS_MAP;
	break;

    case IN_ROTATOR_OPTIONS:
	y->state = IN_ROTATOR_OPTIONS_MAP;
	break;

    case PARSE_ERR:
    case MAIN_LEVEL:
    case IN_DEFINE:
    case IN_DEFAULT_MAP:
    case IN_DEFAULT_NAME:
    case IN_DEFAULT_VALUE:
    case IN_DEFAULT_CLASS:
    case IN_DELDEFAULT_MAP:
    case IN_DELDEFAULT_NAME:
    case IN_DELDEFAULT_CLASS:
    case IN_CONNSPEC_MAP:
    case IN_CONNSPEC_NAME:
    case IN_CONNSPEC_ACCEPTER:
    case IN_CONNSPEC_TIMEOUT:
    case IN_CONNSPEC_CONNECTOR:
    case IN_CONNSPEC_OPTIONS_MAP:
    case IN_CONNSPEC_OPTIONS_NAME:
    case IN_ROTATOR_MAP:
    case IN_ROTATOR_NAME:
    case IN_ROTATOR_ACCEPTER:
    case IN_ROTATOR_CONNECTIONS:
    case IN_ROTATOR_CONNECTIONS_SEQ:
    case IN_ROTATOR_OPTIONS_MAP:
    case IN_ROTATOR_OPTIONS_NAME:
    case END_DOC:
	eout->out(eout, "Unexpected mapping start: %d", y->state);
	return -1;
    }

    return 0;
}

static int
yhandle_mapping_end(struct yconf *y, struct absout *eout)
{
    int err, argc;
    const char **argv;

    switch (y->state) {
    case MAIN_LEVEL:
	y->state = END_DOC;
	break;

    case IN_DEFAULT_MAP:
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

    case IN_DELDEFAULT_MAP:
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

    case IN_CONNSPEC_MAP:
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
	if (add_option(y, NULL, NULL, "connection", eout))
	    return -1;
	portconfig(eout, y->name, y->accepter, "raw", y->timeout, y->connector,
		   (const char **) y->options, config_num);
	y->state = MAIN_LEVEL;
	yconf_cleanup_main(y);
	break;
	
    case IN_ROTATOR_MAP:
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
	if (add_connection(y, NULL, "rotator", eout))
	    return -1;
	err = gensio_argv_copy(so, (const char **) y->connections,
			       &argc, &argv);
	if (err) {
	    eout->out(eout, "Unable to allocat rotator connections");
	    return -1;
	}
	/* NULL terminate the options. */
	if (add_option(y, NULL, NULL, "rotator", eout))
	    return -1;
	err = add_rotator(y->name, y->accepter, argc, argv,
			  (const char **) y->options, y->e.start_mark.line);
	if (err)
	    gensio_argv_free(so, argv);
	y->state = MAIN_LEVEL;
	yconf_cleanup_main(y);
	break;

    case IN_CONNSPEC_OPTIONS_MAP:
	y->state = IN_CONNSPEC_MAP;
	break;

    case IN_ROTATOR_OPTIONS_MAP:
	y->state = IN_ROTATOR_MAP;
	break;

    case PARSE_ERR:
    case BEGIN_DOC:
    case IN_DEFINE:
    case IN_DEFAULT:
    case IN_DEFAULT_NAME:
    case IN_DEFAULT_VALUE:
    case IN_DEFAULT_CLASS:
    case IN_DELDEFAULT:
    case IN_DELDEFAULT_NAME:
    case IN_DELDEFAULT_CLASS:
    case IN_CONNSPEC:
    case IN_CONNSPEC_NAME:
    case IN_CONNSPEC_ACCEPTER:
    case IN_CONNSPEC_TIMEOUT:
    case IN_CONNSPEC_CONNECTOR:
    case IN_CONNSPEC_OPTIONS:
    case IN_CONNSPEC_OPTIONS_NAME:
    case IN_ROTATOR:
    case IN_ROTATOR_NAME:
    case IN_ROTATOR_ACCEPTER:
    case IN_ROTATOR_CONNECTIONS:
    case IN_ROTATOR_CONNECTIONS_SEQ:
    case IN_ROTATOR_OPTIONS:
    case IN_ROTATOR_OPTIONS_NAME:
    case END_DOC:
	eout->out(eout, "Unexpected mapping end: %d", y->state);
	return -1;
    }

    return 0;
}

int
yaml_readconfig(FILE *f)
{
    bool done = false;
    struct yconf y;
    struct absout yeout = { .out = syslog_eprint, .data = &y };
    int err = 0;

    memset(&y, 0, sizeof(y));
    y.options = malloc(sizeof(char *) * 10);
    if (!y.options) {
	syslog(LOG_ERR, "Out of memory allocating options array");
	return -1;
    }
    y.options_len = 10;
    y.connections = malloc(sizeof(char *) * 10);
    if (!y.connections) {
	free(y.options);
	syslog(LOG_ERR, "Out of memory allocating connection array");
	return -1;
    }
    y.connections_len = 10;
    y.state = BEGIN_DOC;

    yaml_parser_initialize(&y.parser);
    yaml_parser_set_input_file(&y.parser, f);

    while (!done && !err) {
	if (!yaml_parser_parse(&y.parser, &y.e)) {
	    syslog(LOG_ERR, "yaml parsing error at line %lu column %lu: %s",
		   y.parser.problem_mark.line, y.parser.problem_mark.column,
		   y.parser.problem);
	    err = -1;
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
		err = -1;
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
		yeout.out(&yeout, "Unable to find alias '%s'",
			  y.e.data.alias.anchor);
		err = -1;
	    } else {
		err = yhandle_scalar(&y, NULL, a->value, &yeout);
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
	    err = yhandle_scalar(&y, (char *) y.e.data.scalar.anchor,
				 (char *) y.e.data.scalar.value, &yeout);
	    break;

	case YAML_SEQUENCE_START_EVENT:
#if DEBUG
	    printf("YAML_SEQUENCE_START_EVENT\n");
	    printf(" anc: '%s'\n", y.e.data.sequence_start.anchor);
	    printf(" tag: '%s'\n", y.e.data.sequence_start.tag);
#endif
	    err = yhandle_seq_start(&y, &yeout);
	    break;

	case YAML_SEQUENCE_END_EVENT:
#if DEBUG
	    printf("YAML_SEQUENCE_END_EVENT\n");
#endif
	    err = yhandle_seq_end(&y, &yeout);
	    break;

	case YAML_MAPPING_START_EVENT:
#if DEBUG
	    printf("YAML_MAPPING_START_EVENT\n");
	    printf(" anc: '%s'\n", y.e.data.mapping_start.anchor);
	    printf(" tag: '%s'\n", y.e.data.mapping_start.tag);
#endif
	    err = yhandle_mapping_start(&y, &yeout);
	    break;

	case YAML_MAPPING_END_EVENT:
#if DEBUG
	    printf("YAML_MAPPING_END_EVENT\n");
#endif
	    err = yhandle_mapping_end(&y, &yeout);
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

    /* Delete anything that wasn't in the new config file. */
    clear_old_port_config(config_num);

    return err;
}
