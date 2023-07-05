/*
 *  ser2net - A program for allowing telnet connection to serial ports
 *  Copyright (C) 2001=2020  Corey Minyard <minyard@acm.org>
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
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <yaml.h>

#include <gensio/selector.h>
#include <gensio/gensio.h>
#include <gensio/gensio_mdns.h>
#include <gensio/argvutils.h>

#include "ser2net.h"
#include "controller.h"
#include "dataxfer.h"
#include "defaults.h"

/* This file holds the code that runs the control port. */

static struct gensio_lock *cntlr_lock;
static struct gensio_accepter *controller_accepter;
static char *controller_authdir;
static char *controller_pamauth;
static struct gensio_waiter *accept_waiter;

static int max_controller_ports = 4;	/* How many control connections
					   do we allow at a time. */
static int num_controller_ports = 0;	/* How many control connections
					   are currently active. */

#define INBUF_SIZE 2048	/* The size of the maximum input command or YAML doc. */

char *prompt = "-> ";

/* This data structure is kept for each control connection. */
typedef struct controller_info {
    struct gensio_lock *lock;
    int in_shutdown;

    struct gensio *net;

    unsigned char inbuf[INBUF_SIZE + 1];/* Buffer to receive command on. */
    int  inbuf_count;			/* The number of bytes currently
					   in the inbuf. */
    bool echo_off;

    struct gensio_lock *outlock;
    bool yaml;				/* Am I in YAML output mode? */
    char *outbuf;			/* The output buffer, NULL if
					   no output. */
    int  outbufsize;			/* Total size of the memory
					   allocated in outbuf. */
    int  outbuf_pos;			/* The current position in the
					   output buffer. */
    int  outbuf_count;			/* The number of bytes
					   (starting at outbuf_pos)
					   left to transmit. */
    unsigned int indent;

    bool yamlin;			/* Am I in YAML input mode? */
    yaml_parser_t parser;
    size_t parse_pos;
    size_t read_pos;
    unsigned int match_len;
    yaml_document_t doc;

    void *monitor_port_id;		/* When port monitoring, this is
					   the id given when the monitoring
					   is started.  It is used to stop
					   monitoring. */

    struct controller_info *next;	/* Used to keep these items in
					   a linked list. */

    void (*shutdown_complete)(void *);
    void *shutdown_complete_cb_data;
} controller_info_t;

static struct gensio_waiter *controller_shutdown_waiter;

/* List of current control connections. */
controller_info_t *controllers = NULL;

static void
controller_close_done(struct gensio *net, void *cb_data)
{
    controller_info_t *cntlr = gensio_get_user_data(net);

    controller_info_t *prev;
    controller_info_t *curr;
    void (*shutdown_complete)(void *);
    void *shutdown_complete_cb_data;

    gensio_free(net);

    so->free_lock(cntlr->lock);
    so->free_lock(cntlr->outlock);

    if (cntlr->outbuf != NULL) {
	free(cntlr->outbuf);
    }
    cntlr->outbuf = NULL;

    /* Remove it from the linked list. */
    prev = NULL;
    so->lock(cntlr_lock);
    curr = controllers;
    while (curr != NULL) {
	if (cntlr == curr) {
	    if (prev == NULL) {
		controllers = controllers->next;
	    } else {
		prev->next = curr->next;
	    }
	    num_controller_ports--;
	    break;
	}

	prev = curr;
	curr = curr->next;
    }
    so->unlock(cntlr_lock);

    shutdown_complete = cntlr->shutdown_complete;
    shutdown_complete_cb_data = cntlr->shutdown_complete_cb_data;

    free(cntlr);

    if (shutdown_complete)
	shutdown_complete(shutdown_complete_cb_data);
}

/* Shut down a control connection and remove it from the list of
   controllers. */
static void
shutdown_controller(controller_info_t *cntlr)
{
    if (cntlr->in_shutdown) {
	so->unlock(cntlr->lock);
	return;
    }

    if (cntlr->monitor_port_id != NULL) {
	data_monitor_stop(cntlr, cntlr->monitor_port_id);
	cntlr->monitor_port_id = NULL;
    }

    cntlr->in_shutdown = 1;
    so->unlock(cntlr->lock);

    gensio_close(cntlr->net, controller_close_done, NULL);
}

void
controller_indent(struct controller_info *cntlr, int amount)
{
    cntlr->indent += amount;
}

/* Send some output to the control connection.  This allocates and
   free a buffer in blocks of 1024 and increases the size of the
   buffer as necessary. */
static void
controller_raw_output(struct controller_info *cntlr,
		      const char *data, int count)
{
    if (cntlr->outbuf != NULL) {
	/* Already outputting data, just add more onto it. */
	int  new_size = cntlr->outbuf_count + count;

	if (new_size <= cntlr->outbufsize) {
	    /* It will fit into the current buffer, just move things
	       around and append it. */
	    if (cntlr->outbuf_pos > 0) {
		int i;

		for (i = 0; i < cntlr->outbuf_count; i++) {
		    cntlr->outbuf[i] = cntlr->outbuf[cntlr->outbuf_pos + i];
		}
	    }
	    memcpy(&(cntlr->outbuf[cntlr->outbuf_count]), data, count);
	} else {
	    /* We need to allocate a larger buffer. */
	    char *newbuf;

	    /* Allocate the next even multiple of 1024 bytes. */
	    new_size = ((new_size / 1024) * 1024) + 1024;
	    newbuf = malloc(new_size);

	    if (newbuf == NULL) {
		/* Out of memory, just ignore the request */
		return;
	    }

	    cntlr->outbufsize = new_size;

	    /* Copy all the data into a new buffer. */
	    memcpy(newbuf,
		   &(cntlr->outbuf[cntlr->outbuf_pos]),
		   cntlr->outbuf_count);
	    memcpy(newbuf + cntlr->outbuf_count, data, count);
	    free(cntlr->outbuf);
	    cntlr->outbuf = newbuf;
	}
	cntlr->outbuf_pos = 0;
	cntlr->outbuf_count += count;
    } else {
	/* We are starting a new buffer, just get it. */
	char *newbuf;
	int  new_size = ((count / 1024) * 1024) + 1024;

	newbuf = malloc(new_size);
	if (newbuf == NULL) {
	    /* Out of memory, just ignore the request */
	    return;
	}

	cntlr->outbufsize = new_size;

	memcpy(newbuf, data, count);
	cntlr->outbuf = newbuf;
	cntlr->outbuf_pos = 0;
	cntlr->outbuf_count = count;
	gensio_set_read_callback_enable(cntlr->net, false);
	gensio_set_write_callback_enable(cntlr->net, true);
    }
}

static void
controller_output(struct controller_info *cntlr,
		  const char *field, const char *tag,
		  const char *data, int count)
{
    so->lock(cntlr->outlock);
    if (field) {
	unsigned int i;

	for (i = 0; i < cntlr->indent; i++)
	    controller_raw_output(cntlr, "  ", 2);
	controller_raw_output(cntlr, field, strlen(field));
	controller_raw_output(cntlr, ": ", 2);
	if (cntlr->yaml && tag)
	    controller_raw_output(cntlr, tag, strlen(tag));
    }
    controller_raw_output(cntlr, data, count);
    if (field)
	controller_raw_output(cntlr, "\r\n", 2);
    so->unlock(cntlr->outlock);
}

static unsigned int
expand_quotes(char *out, const char *in, unsigned int outsize)
{
    unsigned int outpos = 1;

    *out++ = '\'';
    while (*in) {
	if (*in == '\'') {
	    if (outpos + 2 >= outsize)
		break;
	    *out++ = '\\';
	    outpos++;
	}
	if (outpos + 1 >= outsize)
	    break;
	*out++ = *in++;
	outpos++;
    }
    *out++ = '\'';
    return outpos + 1;
}

int
controller_voutputf(struct controller_info *cntlr,
		    const char *field, const char *str, va_list ap)
{
    char buffer[1024], buffer2[2048 + 2];
    int rv;

    rv = vsnprintf(buffer, sizeof(buffer) / 2, str, ap);
    if (strcmp(str, "%d") == 0 || strcmp(str, "%lu") == 0) {
	controller_output(cntlr, field, "!!int ", buffer, rv);
    } else if (cntlr->yaml && field) {
	unsigned int len = expand_quotes(buffer2, buffer, sizeof(buffer2));
	controller_output(cntlr, field, "!!str ", buffer2, len);
    } else {
	controller_output(cntlr, field, "!!str ", buffer, rv);
    }
    return rv;
}

int
controller_outputf(struct controller_info *cntlr,
		   const char *field, const char *str, ...)
{
    va_list ap;
    int rv;

    va_start(ap, str);
    rv = controller_voutputf(cntlr, field, str, ap);
    va_end(ap);
    return rv;
}

void controller_outs(struct controller_info *cntlr,
		     const char *field, const char *s)
{
    if (!s) {
	controller_output(cntlr, field, NULL, "", 0);
    } else if (cntlr->yaml && field) {
	char buffer[2048 + 2];
	unsigned int len = expand_quotes(buffer, s, sizeof(buffer));

	controller_output(cntlr, field, "!!str ", buffer, len);
    } else {
	controller_output(cntlr, field, "!!str ", s, strlen(s));
    }
}


/* Write some data directly to the controllers output port. */
void
controller_write(struct controller_info *cntlr, const char *data,
		 gensiods count)
{
    gensio_write(cntlr->net, NULL, data, count, NULL);
}

static char *help_str =
"exit - leave the program.\r\n"
"help - display this help.\r\n"
"version - display the version of this program.\r\n"
"yaml - Go into yaml output mode.  In this mode there is no echo or\r\n"
"       line processing is done.  Some commands are disabled.  Output\r\n"
"       is yaml, beginning with --- and ending with ... for each\r\n"
"       response to a command.\r\n"
"monitor <type> <tcp port> - display all the input for a given port on\r\n"
"       the calling control port.  Only one direction may be monitored\r\n"
"       at a time.  The type field may be 'tcp' or 'term' and specifies\r\n"
"       whether to monitor data from the net port or from the serial port\r\n"
"       Note that data monitoring is best effort, if the controller port\r\n"
"       cannot keep up the data will be silently dropped.  A controller\r\n"
"       may only monitor one thing and a port may only be monitored by\r\n"
"       one controller.\r\n"
"monitor stop - stop the current monitor.\r\n"
"disconnect <tcp port> - disconnect the tcp connection on the port.\r\n"
"showport [<tcp port>] - Show information about a port. If no port is\r\n"
"       given, all ports are displayed.\r\n"
"showshortport [<tcp port>] - Show information about a port in a one-line\r\n"
"       format. If no port is given, all ports are displayed.\r\n"
"setporttimeout <tcp port> <timeout> - Set the amount of time in seconds\r\n"
"       before the port connection will be shut down if no activity\r\n"
"       has been seen on the port.\r\n"
"setportcontrol <tcp port> <controls>\r\n"
"       Dynamically modify the characteristics of the port.  These are\r\n"
"       immediate and won't live between connections.  Valid controls are\r\n"
"       DTRHI, DTRLO, RTSHI, and RTSLO.\r\n"
"setportenable <tcp port> <enable state> - Sets the port operation state.\r\n"
"       Valid states are:\r\n"
"         off - The port is shut down\r\n"
"         on - The port is up and all I/O is transferred\r\n"
"reload - Reload the configuration file.\r\n";

static int
cntlr_eout(struct absout *e, const char *str, ...)
{
    controller_info_t *cntlr = e->data;
    va_list ap;
    char buf[1024];

    va_start(ap, str);
    vsnprintf(buf, sizeof(buf), str, ap);
    va_end(ap);
    syslog(LOG_ERR, "%s", buf);
    return controller_outputf(cntlr, "error", "%s", buf);
}

void
cntlr_report_conchange(const char *type, const char *con, const char *remaddr)
{
    controller_info_t *cntlr;

    /* No controller port set up. */
    if (!cntlr_lock)
	return;

    so->lock(cntlr_lock);
    for (cntlr = controllers; cntlr; cntlr = cntlr->next) {
	if (!cntlr->yaml)
	    continue;

	so->lock(cntlr->lock);
	start_maint_op();
	controller_outs(cntlr, NULL, "\r\n%YAML 1.1\r\n---\r\n");
	controller_outs(cntlr, type, NULL);
	controller_indent(cntlr, 1);
	controller_outputf(cntlr, "name", con);
	controller_outputf(cntlr, "remaddr", remaddr);
	controller_indent(cntlr, -1);
	controller_outputf(cntlr, NULL, "...\r\n");
	end_maint_op();
	so->unlock(cntlr->lock);
    }
    so->unlock(cntlr_lock);
}

static int
process_command(controller_info_t *cntlr, const char *cmd, const char *id,
		int nparms, char * const parms[])
{
    bool yaml = cntlr->yaml;

    if (yaml) {
	controller_outs(cntlr, NULL, "\r\n%YAML 1.1\r\n---\r\n");
	controller_outs(cntlr, "response", NULL);
	controller_indent(cntlr, 1);
	controller_outputf(cntlr, "name", cmd);
	if (id)
	    controller_outputf(cntlr, "id", id);
    }
    if (strcmp(cmd, "exit") == 0) {
	shutdown_controller(cntlr);
	return 1; /* We don't want a prompt any more. */
    } else if (strcmp(cmd, "quit") == 0) {
	shutdown_controller(cntlr);
	return 1; /* We don't want a prompt any more. */
    } else if (!cntlr->yaml && strcmp(cmd, "help") == 0) {
	controller_outs(cntlr, NULL, help_str);
    } else if (strcmp(cmd, "version") == 0) {
	controller_outputf(cntlr, "version", "%s", VERSION);
    } else if (!cntlr->yaml && strcmp(cmd, "yaml") == 0) {
	cntlr->yaml = true;
    } else if (strcmp(cmd, "showport") == 0) {
	start_maint_op();
	showports(cntlr, parms[0], cntlr->yaml);
	end_maint_op();
    } else if (!cntlr->yaml && strcmp(cmd, "showshortport") == 0) {
	start_maint_op();
	showshortports(cntlr, parms[0]);
	end_maint_op();
    } else if (!cntlr->yaml && strcmp(cmd, "monitor") == 0) {
	if (parms[0] == NULL) {
	    controller_outs(cntlr, "error", "No monitor type given\r\n");
	    goto out;
	}
	if (strcmp(parms[0], "stop") == 0) {
	    if (cntlr->monitor_port_id != NULL) {
		start_maint_op();
		data_monitor_stop(cntlr, cntlr->monitor_port_id);
		end_maint_op();
		cntlr->monitor_port_id = NULL;
	    }
	} else {
	    if (cntlr->monitor_port_id != NULL) {
		controller_outs(cntlr, "error", "Already monitoring a port");
		goto out;
	    }
	    if (parms[1] == NULL) {
		controller_outs(cntlr, "error", "No monitor port given");
		goto out;
	    }
	    start_maint_op();
	    cntlr->monitor_port_id = data_monitor_start(cntlr,
							parms[0], parms[1]);
	    end_maint_op();
	}
    } else if (strcmp(cmd, "disconnect") == 0) {
	if (parms[0] == NULL) {
	    controller_outs(cntlr, "error", "No port given");
	    goto out;
	}
	start_maint_op();
	disconnect_port(cntlr, parms[0]);
	end_maint_op();
    } else if (strcmp(cmd, "setporttimeout") == 0) {
	if (parms[0] == NULL) {
	    controller_outs(cntlr, "error", "No port given");
	    goto out;
	}
	if (parms[1] == NULL) {
	    controller_outs(cntlr, "error", "No timeout given");
	    goto out;
	}
	start_maint_op();
	setporttimeout(cntlr, parms[0], parms[1]);
	end_maint_op();
    } else if (strcmp(cmd, "setportenable") == 0) {
	if (parms[0] == NULL) {
	    controller_outs(cntlr, "error", "No port given");
	    goto out;
	}
	if (parms[1] == NULL) {
	    controller_outs(cntlr, "error", "No enable given");
	    goto out;
	}
	start_maint_op();
	setportenable(cntlr, parms[0], parms[1]);
	end_maint_op();
    } else if (strcmp(cmd, "setportcontrol") == 0) {
	if (parms[0] == NULL) {
	    controller_outs(cntlr, "error", "No port given");
	    goto out;
	}
	if (parms[1] == NULL) {
	    controller_outs(cntlr, "error", "No device controls");
	    goto out;
	}
	start_maint_op();
	setportcontrol(cntlr, parms[0], parms + 1);
	end_maint_op();
    } else if (strcmp(cmd, "reload") == 0) {
	int rv;
	struct absout eout = { cntlr_eout, cntlr };

	start_maint_op();
	rv = reread_config_file("admin request", &eout);
	end_maint_op();

	if (!rv) {
	    controller_outs(cntlr, "error", "reload done");
	} else {
	    controller_outputf(cntlr, "error", "reload error - %s",
			       strerror(rv));
	}
    } else {
	controller_outputf(cntlr, "error", "Unknown command - %s", cmd);
    }

 out:
    if (yaml) {
	controller_indent(cntlr, -1);
	controller_outputf(cntlr, NULL, "...\r\n");
    }

    return 0;
}

/* Process a line of input.  This scans for commands, reads any
   parameters, then calls the actual code to handle the command. */
static int
process_input_line(controller_info_t *cntlr)
{
    char *strtok_data;
    char *tok;
    char *parms[5];
    int nparms;
    int rv = 0;

    tok = strtok_r((char *) cntlr->inbuf, " \t", &strtok_data);
    if (tok == NULL)
	/* Empty line, just ignore it. */
	goto out_noend;

    for (nparms = 0; nparms < 4; nparms++) {
	parms[nparms] = strtok_r(NULL, " \t", &strtok_data);
	if (!parms[nparms])
	    break;
    }
    parms[nparms] = NULL;
    rv = process_command(cntlr, tok, NULL, nparms, parms);

 out_noend:
    if (!cntlr->yaml && !rv)
	controller_outs(cntlr, NULL, prompt);
    return rv;
}

/* Removes one or more characters starting at pos and going backwards.
   So, for instance, if inbuf holds "abcde", pos points to d, and
   count is 2, the new inbuf will be "abe".  This is used for
   backspacing. */
static int
remove_chars(controller_info_t *cntlr, int pos, int count) {
    int j;

    for (j = pos-count + 1; j < (cntlr->inbuf_count - count); j++)
	cntlr->inbuf[j] = cntlr->inbuf[j + count];
    cntlr->inbuf_count -= count;
    pos -= count;

    return pos;
}

//#define YAML_DEBUG
#ifdef YAML_DEBUG
static void
print_node(yaml_document_t *doc, yaml_node_t *n, unsigned int indent)
{
    unsigned int i;
    yaml_node_pair_t *p;
    yaml_node_item_t *t;
    yaml_node_t *key, *value;

    switch(n->type) {
    case YAML_SCALAR_NODE:
	printf("!!str ");
	printf("%s", n->data.scalar.value);
	break;
    case YAML_SEQUENCE_NODE:
	printf("!!seq ");
	for (t = n->data.sequence.items.start; t < n->data.sequence.items.top;
		t++) {
	    printf("\n");
	    for (i = 0; i < indent; i++)
		printf("  ");
	    value = yaml_document_get_node(doc, *t);
	    print_node(doc, value, indent + 1);
	}
	break;
    case YAML_MAPPING_NODE:
	printf("!!map ");
	for (p = n->data.mapping.pairs.start; p < n->data.mapping.pairs.top;
		p++) {
	    printf("\n");
	    for (i = 0; i < indent; i++)
		printf("  ");
	    key = yaml_document_get_node(doc, p->key);
	    value = yaml_document_get_node(doc, p->value);
	    print_node(doc, key, indent + 1);
	    printf(": ");
	    print_node(doc, value, indent + 1);
	}
	break;
    default:
	printf("?");
    }
}
#endif

static int
handle_yaml_doc(struct controller_info *cntlr)
{
    yaml_document_t *doc = &cntlr->doc;
    yaml_node_t *n, *n2, *n3, *k, *v;
    yaml_node_pair_t *p;
    yaml_node_item_t *t;
    char *name = NULL, *parms[5], *id = NULL;
    int nparms = 0;
    int rv;

    memset(parms, 0, sizeof(parms));

#ifdef YAML_DEBUG
    printf("Got yaml doc\n");
#endif
    n = yaml_document_get_root_node(doc);
    if (!n || n->type == YAML_NO_NODE ||
		(n->type == YAML_SCALAR_NODE && !n->data.scalar.value[0])) {
#ifdef YAML_DEBUG
	printf("Empty document\n");
#endif
	return 1;
    }

#ifdef YAML_DEBUG
    printf("Root node: ");
    print_node(doc, n, 1);
    printf("\n");
#endif

    if (n->type != YAML_MAPPING_NODE)
	goto out_err;

    k = yaml_document_get_node(doc, n->data.mapping.pairs.start->key);
    if (k->type != YAML_SCALAR_NODE)
	goto out_err;
    if (strcmp((char *) k->data.scalar.value, "command") != 0)
	goto out_err;
    
    n2 = yaml_document_get_node(doc, n->data.mapping.pairs.start->value);
    if (n2->type != YAML_MAPPING_NODE)
	goto out_err;

    for (p = n2->data.mapping.pairs.start; p < n2->data.mapping.pairs.top;
		p++) {
	k = yaml_document_get_node(doc, p->key);
	if (k->type != YAML_SCALAR_NODE)
	    goto out_err;
	if (strcmp((char *) k->data.scalar.value, "name") == 0) {
	    v = yaml_document_get_node(doc, p->value);
	    if (v->type != YAML_SCALAR_NODE)
		goto out_err;
	    name = (char *) v->data.scalar.value;
	} else if (strcmp((char *) k->data.scalar.value, "parms") == 0) {
	    n3 = yaml_document_get_node(doc, p->value);
	    if (n3->type != YAML_SEQUENCE_NODE)
		goto out_err;
	    for (t = n3->data.sequence.items.start;
		 t < n3->data.sequence.items.top;
		 t++) {
		v = yaml_document_get_node(doc, *t);
		if (nparms < 4) {
		    if (v->type != YAML_SCALAR_NODE)
			goto out_err;
		    parms[nparms] = (char *) v->data.scalar.value;
		    nparms++;
		}
	    }
	} else if (strcmp((char *) k->data.scalar.value, "id") == 0) {
	    v = yaml_document_get_node(doc, p->value);
	    if (v->type != YAML_SCALAR_NODE)
		goto out_err;
	    id = (char *) v->data.scalar.value;
	} else {
	    goto out_err;
	}
    }

    if (!name)
	goto out_err;

    rv = !process_command(cntlr, name, id, nparms, parms);
    
    yaml_document_delete(doc);
    return rv;

 out_err:
    controller_outs(cntlr, NULL, "\r\n%YAML 1.1\r\n---\r\n");
    controller_outs(cntlr, "response", NULL);
    controller_indent(cntlr, 1);
    if (name)
	controller_outputf(cntlr, "name", name);
    if (id)
	controller_outputf(cntlr, "id", id);
    controller_outputf(cntlr, "error", "Invalid yaml command");
    controller_indent(cntlr, -1);
    yaml_document_delete(doc);
    return 1;
}

static int
yaml_cntlr_read(void *data, unsigned char *buffer, size_t size,
		size_t *size_read)
{
    struct controller_info *cntlr = data;
    size_t left = cntlr->parse_pos - cntlr->read_pos;

    if (left == 0)
	/* This shouldn't happen, we supplied a whole document. */
	return 0;

    if (size > left)
	size = left;
    memcpy(buffer, cntlr->inbuf + cntlr->read_pos, size);
    cntlr->read_pos += size;
    *size_read = size;
    return 1;
}

static int
parse_yaml(struct controller_info *cntlr)
{
    if (!yaml_parser_load(&cntlr->parser, &cntlr->doc))
	return 0;
    return handle_yaml_doc(cntlr);
}

static int
process_yaml(struct controller_info *cntlr)
{
    int rv = 1;

    while (cntlr->parse_pos < cntlr->inbuf_count) {
	char c = cntlr->inbuf[cntlr->parse_pos];

	cntlr->parse_pos++;

	/* Looking for \n...\n to mark a document end. */
	if (cntlr->match_len == 4) {
	    if (c == '\n' || c == '\r') {
		if (!parse_yaml(cntlr)) {
		    shutdown_controller(cntlr);
		    rv = 0;
		} else {
		    /* Copy the rest of the buffer to the beginning. */
		    cntlr->inbuf_count -= cntlr->parse_pos;
		    memmove(cntlr->inbuf, cntlr->inbuf + cntlr->parse_pos,
			    cntlr->inbuf_count);
		    cntlr->parse_pos = 0;
		    cntlr->match_len = 0;
		    cntlr->read_pos = 0;
		}
		break;
	    }
	    cntlr->match_len = 0;
	}
	if (c == '\n' || c == '\r') {
	    cntlr->match_len = 1;
	} else if (cntlr->match_len > 0 && c == '.') {
	    cntlr->match_len++;
	} else {
	    cntlr->match_len = 0;
	}
    }

    return rv;
}

static int
init_yaml(struct controller_info *cntlr)
{
    cntlr->yaml = true;
    cntlr->yamlin = true;

    yaml_parser_initialize(&cntlr->parser);
    yaml_parser_set_input(&cntlr->parser, yaml_cntlr_read, cntlr);
    return 1;
}

/* Data is ready to read on the TCP port. */
static void
controller_read(struct gensio *net, int err,
		unsigned char *buf, gensiods *ibuflen)
{
    controller_info_t *cntlr = gensio_get_user_data(net);
    int read_start, i;
    gensiods buflen = 0;

    so->lock(cntlr->lock);
    if (cntlr->in_shutdown)
	/* Can get here on a race condition, just return. */
	goto out_unlock;

    if (err) {
	/* Got an error on the read, shut down the port. */
	if (err != GE_REMCLOSE)
	    syslog(LOG_ERR, "read error for controller port: %s",
		   gensio_err_to_str(err));
	shutdown_controller(cntlr); /* Releases the lock */
	goto out_return;
    }

    buflen = *ibuflen;

    if (cntlr->inbuf_count == INBUF_SIZE) {
	controller_outs(cntlr, NULL, "Input line too long\r\n");
	cntlr->inbuf_count = 0;
	goto out_unlock;
    }

    read_start = cntlr->inbuf_count;
    if (buflen > INBUF_SIZE - read_start)
	buflen = INBUF_SIZE - read_start;
    memcpy(cntlr->inbuf + read_start, buf, buflen);
    cntlr->inbuf_count += buflen;

    if (cntlr->yamlin) {
    handle_yaml:
	if (!process_yaml(cntlr))
	    goto out;
	goto out_unlock;
    }

    for (i = read_start; i < cntlr->inbuf_count; i++) {
	if (cntlr->inbuf[i] == 0x0) {
	    /* Ignore nulls. */
	    i = remove_chars(cntlr, i, 1);
	} else if (!cntlr->yaml &&
		   (cntlr->inbuf[i] == '\b' || cntlr->inbuf[i] == 0x7f)) {
	    /* Got a backspace. */

	    if (i == 0) {
		/* We ignore backspaces at the beginning of the line. */
		i = remove_chars(cntlr, i, 1);
	    } else {
		i = remove_chars(cntlr, i, 2);
		if (!cntlr->echo_off)
		    controller_outs(cntlr, NULL, "\b \b");
	    }
	} else if (i == 0 && cntlr->inbuf[i] == '%') {
	    /* Turn off echo for this command. */
	    cntlr->echo_off = true;
	} else if (cntlr->inbuf[i] == '\r' || cntlr->inbuf[i] == '\n') {
	    /* We got a newline, process the command. */
	    int j;

	    if (strncmp((char *) cntlr->inbuf, "%YAML", 5) == 0) {
		if (!init_yaml(cntlr))
		    goto out;
		goto handle_yaml;
	    }

	    cntlr->inbuf[i] = '\0';

	    if (!cntlr->yaml)
		controller_outs(cntlr, NULL, "\r\n");

	    if (process_input_line(cntlr))
		goto out; /* Controller was shut down. */

	    cntlr->echo_off = false;

	    /* Now copy any leftover data to the beginning of the buffer. */
	    /* Don't use memcpy or strcpy because the memory might
               overlap */
	    i++;
	    cntlr->inbuf_count -= i;
	    for (j = 0; j < cntlr->inbuf_count; i++, j++) {
		cntlr->inbuf[j] = cntlr->inbuf[i];
	    }
	    i = -1;
	} else if (!cntlr->echo_off && !cntlr->yaml) {
	    /* It's a normal character, just echo it. */
	    controller_output(cntlr, NULL, NULL,
			      (char *) &(cntlr->inbuf[i]), 1);
	}
    }
 out_unlock:
    so->unlock(cntlr->lock);
 out:
    *ibuflen = buflen;
 out_return:
    return;
}

/* The TCP port has room to write some data.  This is only activated
   if a write fails to complete, it is deactivated as soon as writing
   is available again. */
static void
controller_write_ready(struct gensio *net)
{
    controller_info_t *cntlr = gensio_get_user_data(net);
    int err;
    gensiods write_count;

    so->lock(cntlr->outlock);
    if (cntlr->in_shutdown)
	goto out;

    err = gensio_write(net, &write_count,
		       &(cntlr->outbuf[cntlr->outbuf_pos]),
		       cntlr->outbuf_count, NULL);
    if (err == EAGAIN) {
	/* This again was due to O_NONBso->lock, just ignore it. */
    } else if (err == EPIPE) {
	goto out_fail;
    } else if (err) {
	/* Some other bad error. */
	syslog(LOG_ERR, "The tcp write for controller had error: %s",
	       gensio_err_to_str(err));
	goto out_fail;
    }

    cntlr->outbuf_count -= write_count;
    if (cntlr->outbuf_count != 0) {
	/* We didn't write all the data, continue writing. */
	cntlr->outbuf_pos += write_count;
    } else {
	/* We are done writing, turn the reader back on. */
	free(cntlr->outbuf);
	cntlr->outbuf = NULL;
	gensio_set_read_callback_enable(net, true);
	gensio_set_write_callback_enable(net, false);
    }
 out:
    so->unlock(cntlr->outlock);
    return;

 out_fail:
    /* Let the read handle the error. */
    gensio_set_read_callback_enable(net, true);
    gensio_set_write_callback_enable(net, false);
    so->unlock(cntlr->outlock);
}

static int
controller_io_event(struct gensio *net, void *user_data, int event, int err,
		    unsigned char *buf, gensiods *buflen,
		    const char *const *auxdata)
{
    switch (event) {
    case GENSIO_EVENT_READ:
	controller_read(net, err, buf, buflen);
	return 0;

    case GENSIO_EVENT_WRITE_READY:
	controller_write_ready(net);
	return 0;

#ifdef GENSIO_EVENT_PARMLOG
    case GENSIO_EVENT_PARMLOG: {
	struct gensio_parmlog_data *d = (struct gensio_parmlog_data *) buf;
	vsyslog(LOG_ERR, d->log, d->args);
	return 0;
    }
#endif
    }

    return ENOTSUP;
}

static int
controller_acc_new_child(struct gensio *net)
{
    controller_info_t *cntlr;
    char *err = NULL;

    so->lock(cntlr_lock);
    if (num_controller_ports >= max_controller_ports) {
	err = "Too many controller ports\r\n";
	goto errout;
    } else {
	cntlr = malloc(sizeof(*cntlr));
	if (cntlr == NULL) {
	    err = "Could not allocate controller port\r\n";
	    goto errout;
	}
	memset(cntlr, 0, sizeof(*cntlr));
    }

    cntlr->lock = so->alloc_lock(so);
    if (!cntlr->lock) {
	free(cntlr);
	err = "Out of memory allocating lock";
	goto errout;
    }

    cntlr->outlock = so->alloc_lock(so);
    if (!cntlr->outlock) {
	so->free_lock(cntlr->lock);
	free(cntlr);
	err = "Out of memory allocating lock";
	goto errout;
    }

    cntlr->net = net;

    gensio_set_callback(net, controller_io_event, cntlr);

    cntlr->inbuf_count = 0;
    cntlr->outbuf = NULL;
    cntlr->monitor_port_id = NULL;
    cntlr->parse_pos = 1; /* Assume we start with a \n. */

    controller_outs(cntlr, NULL, prompt);

    cntlr->next = controllers;
    controllers = cntlr;
    num_controller_ports++;

    so->unlock(cntlr_lock);
    return 0;

errout:
    so->unlock(cntlr_lock);
    /* We have a problem so refuse this one. */
    gensio_write(net, NULL, err, strlen(err), NULL);
    gensio_free(net);
    return 0;
}

/* A connection request has come in for the control port. */
static int
controller_acc_child_event(struct gensio_accepter *accepter, void *user_data,
			   int event, void *data)
{
    switch (event) {
    case GENSIO_ACC_EVENT_NEW_CONNECTION:
	return controller_acc_new_child(data);

#ifdef GENSIO_ACC_EVENT_PARMLOG
    case GENSIO_ACC_EVENT_PARMLOG: {
	struct gensio_parmlog_data *d = (struct gensio_parmlog_data *) data;
	vsyslog(LOG_ERR, d->log, d->args);
	return 0;
    }
#endif

    default:
	return handle_acc_auth_event(
	    controller_authdir, controller_pamauth,
	    NULL, event, data
	);
    }
}

static void
controller_shutdown_done(struct gensio_accepter *net, void *cb_data)
{
    so->wake(accept_waiter);
}

#ifdef DO_MDNS
static bool admin_mdns;
static unsigned int admin_mdns_port;
static int admin_mdns_interface = -1;
static int admin_mdns_nettype = GENSIO_NETTYPE_UNSPEC;
static char *admin_name;
static char *admin_mdns_name;
static char *admin_mdns_type;
static char *admin_mdns_domain;
static char *admin_mdns_host;
static const char **admin_mdns_txt;
static gensiods admin_mdns_txt_argc;
static gensiods admin_mdns_txt_args;
static struct gensio_mdns_service *admin_mdns_service;

static void
admin_cleanup_mdns_data(void)
{
    admin_mdns = false;
    admin_mdns_port = 0;
    admin_mdns_interface = -1;
    admin_mdns_nettype = GENSIO_NETTYPE_UNSPEC;
    if (admin_name) {
	free(admin_name);
	admin_name = NULL;
    }
    if (admin_mdns_name) {
	free(admin_mdns_name);
	admin_mdns_name = NULL;
    }
    if (admin_mdns_type) {
	free(admin_mdns_type);
	admin_mdns_type = NULL;
    }
    if (admin_mdns_domain) {
	free(admin_mdns_domain);
	admin_mdns_domain = NULL;
    }
    if (admin_mdns_host) {
	free(admin_mdns_host);
	admin_mdns_host = NULL;
    }

    if (admin_mdns_txt) {
	gensio_argv_free(so, admin_mdns_txt);
	admin_mdns_txt = NULL;
    }
    admin_mdns_txt_argc = 0;
    admin_mdns_txt_args = 0;
}

static char *
admin_derive_mdns_type(void)
{
    /* Get a mdns type based on the gensio. */
    unsigned int i;
    const char *type, *ntype = "_iostream._tcp";

    type = gensio_acc_get_type(controller_accepter, 0);
    for (i = 1; type; i++) {
	if (strcmp(type, "tcp") == 0)
	    break;
	if (strcmp(type, "udp") == 0) {
	    ntype = "_iostream._udp";
	    break;
	}
	type = gensio_acc_get_type(controller_accepter, i);
    }
    return strdup(ntype);
}

static void
admin_mdns_addprovider(struct absout *eout)
{
    gensiods i;
    static char *provstr = "provider=";
    char *tmps = NULL;

    for (i = 0; i < admin_mdns_txt_argc; i++) {
	if (strncmp(admin_mdns_txt[i], provstr, strlen(provstr)) == 0)
	    /* User already specified it, don't override. */
	    return;
    }

    tmps = gensio_alloc_sprintf(so, "%s%s", provstr, "ser2net");
    if (!tmps)
	goto out_nomem;

    if (gensio_argv_append(so, &admin_mdns_txt, tmps,
			   &admin_mdns_txt_args, &admin_mdns_txt_argc,
			   false))
	goto out_nomem;
    return;

 out_nomem:
    eout->out(eout, "Error allocating admin mdns provider: out of memory");
    if (tmps)
	so->free(so, tmps);
}

static void
admin_mdns_addstack(struct absout *eout)
{
    gensiods i;
    static char *stackstr = "gensiostack=";
    const char *type;
    char *stack = NULL, *tmps = NULL;

    for (i = 0; i < admin_mdns_txt_argc; i++) {
	if (strncmp(admin_mdns_txt[i], stackstr, strlen(stackstr)) == 0)
	    /* User already specified it, don't override. */
	    return;
    }

    for (i = 0; ; i++) {
	type = gensio_acc_get_type(controller_accepter, i);
	if (!type)
	    break;

	if (strcmp(type, "telnet") == 0) {
	    tmps = gensio_alloc_sprintf(so, "%s%s%s",
					stack ? stack : "", stack ? "," : "",
					type);
	} else {
	    tmps = gensio_alloc_sprintf(so, "%s%s%s",
					stack ? stack : "", stack ? "," : "",
					type);
	}
	if (!tmps)
	    goto out_nomem;
	if (stack)
	    so->free(so, stack);
	stack = tmps;
    }

    if (!stack)
	return;

    tmps = gensio_alloc_sprintf(so, "%s%s", stackstr, stack);
    if (!tmps)
	goto out_nomem;
    stack = tmps;

    if (gensio_argv_append(so, &admin_mdns_txt, stack,
			   &admin_mdns_txt_args, &admin_mdns_txt_argc,
			   false))
	goto out_nomem;
    return;

 out_nomem:
    eout->out(eout, "Error allocating admin mdns stack: out of memory");
    if (stack)
	so->free(so, stack);
}

static void
admin_mdns_setup(struct absout *eout)
{
    int err;
    char portnum_str[20];
    gensiods portnum_len = sizeof(portnum_str);

    if (!admin_mdns)
	return;

    if (!admin_mdns_name && !admin_name) {
	eout->out(eout, "admin mdns enabled, but no name given");
	return;
    }

    if (!mdns) {
	eout->out(eout, "mdns requested for admin port, but mdns failed"
		  " to start or is disabled in gensio.");
	return;
    }

    if (!admin_mdns_port) {
	strcpy(portnum_str, "0");
	err = gensio_acc_control(controller_accepter,
				 GENSIO_CONTROL_DEPTH_FIRST,
				 true, GENSIO_ACC_CONTROL_LPORT, portnum_str,
				 &portnum_len);
	if (err) {
	    eout->out(eout, "Can't get admin mdns port: %s",
		      gensio_err_to_str(err));
	    goto out_cleanup;
	}
	admin_mdns_port = strtoul(portnum_str, NULL, 0);
    }

    if (!admin_mdns_type) {
	admin_mdns_type = admin_derive_mdns_type();
	if (!admin_mdns_type) {
	    eout->out(eout, "Can't alloc admin mdns type: out of memory");
	    goto out_cleanup;
	}
    }

    if (!admin_mdns_name) {
	admin_mdns_name = strdup(admin_name);
	if (!admin_mdns_name) {
	    eout->out(eout, "Can't alloc admin mdns name: out of memory");
	    goto out_cleanup;
	}
    }

    admin_mdns_addprovider(eout);
    admin_mdns_addstack(eout);

    /*
     * Always stick on the NULL, that doesn't update argc so it's safe,
     * a new txt will just write over the NULL we added.
     */
    err = gensio_argv_append(so, &admin_mdns_txt, NULL,
			     &admin_mdns_txt_args, &admin_mdns_txt_argc, true);
    if (err) {
	eout->out(eout, "Error terminating admin mdns-txt: %s",
		  gensio_err_to_str(err));
	goto out_cleanup;
    }

    err = gensio_mdns_add_service(mdns, admin_mdns_interface,
				  admin_mdns_nettype,
				  admin_mdns_name, admin_mdns_type,
				  admin_mdns_domain, admin_mdns_host,
				  admin_mdns_port, admin_mdns_txt,
				  &admin_mdns_service);
    if (err) {
	eout->out(eout, "Can't add admin mdns service: %s",
		  gensio_err_to_str(err));
	goto out_cleanup;
    }
    return;

 out_cleanup:
    admin_cleanup_mdns_data();
    return;
}

static void
admin_mdns_shutdown(void)
{
    if (admin_mdns_service)
	gensio_mdns_remove_service(admin_mdns_service);
    admin_mdns_service = NULL;
    admin_cleanup_mdns_data();
}

#else

static void
admin_mdns_setup(struct absout *eout)
{
}

static void
admin_mdns_shutdown(void)
{
}
#endif /* DO_MDNS */

static int
controller_handle_options(const char * const *options, struct absout *eout)
{
    unsigned int i;
    const char *val;
    char *fval;

    admin_mdns_interface = find_default_int("mdns-interface");

    if (find_default_str("authdir-admin", &controller_authdir)) {
	eout->out(eout, "Can't get default value for authdir-admin:"
		  " out of memeory");
	return -1;
    }

    if (find_default_str("pamauth-admin", &controller_pamauth)) {
	eout->out(eout, "Can't get default value for pamauth-admin:"
		  " out of memeory");
	return -1;
    }

    for (i = 0; options && options[i]; i++) {
	if (gensio_check_keyvalue(options[i], "authdir-admin", &val) > 0) {
	    char *s = strdup(val);

	    if (!s) {
		eout->out(eout, "Can't get value for authdir-admin:"
			  " out of memeory");
		return -1;
	    }
	    if (controller_authdir)
		free(controller_authdir);
	    controller_authdir = s;
	    continue;
	}
	if (gensio_check_keyvalue(options[i], "pamauth-admin", &val) > 0) {
	    char *s = strdup(val);

	    if (!s) {
		eout->out(eout, "Can't get value for pamauth-admin:"
			  " out of memeory");
		return -1;
	    }
	    if (controller_pamauth)
		free(controller_pamauth);
	    controller_pamauth = s;
	    continue;
	}
#ifdef DO_MDNS
	if (gensio_check_keybool(options[i], "mdns", &admin_mdns) > 0)
	    continue;
	if (gensio_check_keyuint(options[i], "mdns-port", &admin_mdns_port) > 0)
	    continue;
	if (gensio_check_keyint(options[i], "mdns-interface",
				&admin_mdns_interface) > 0)
	    continue;
	if (gensio_check_keyenum(options[i], "mdns-nettype",
				 mdns_nettypes,
				 &admin_mdns_nettype) > 0)
	    continue;
	if (gensio_check_keyvalue(options[i], "mdns-name", &val) > 0) {
	    fval = strdup(val);
	    if (!fval) {
		eout->out(eout, "Out of memory allocating admin mdns-name");
		return -1;
	    }
	    if (admin_mdns_name)
		free(admin_mdns_name);
	    admin_mdns_name = fval;
	}
	if (gensio_check_keyvalue(options[i], "mdns-type", &val) > 0) {
	    fval = strdup(val);
	    if (!fval) {
		eout->out(eout, "Out of memory allocating admin mdns-type");
		return -1;
	    }
	    if (admin_mdns_type)
		free(admin_mdns_type);
	    admin_mdns_type = fval;
	}
	if (gensio_check_keyvalue(options[i], "mdns-domain", &val) > 0) {
	    fval = strdup(val);
	    if (!fval) {
		eout->out(eout, "Out of memory allocating admin mdns-domain");
		return -1;
	    }
	    if (admin_mdns_domain)
		free(admin_mdns_domain);
	    admin_mdns_domain = fval;
	}
	if (gensio_check_keyvalue(options[i], "mdns-host", &val) > 0) {
	    fval = strdup(val);
	    if (!fval) {
		eout->out(eout, "Out of memory allocating admin mdns-host");
		return -1;
	    }
	    if (admin_mdns_host)
		free(admin_mdns_host);
	    admin_mdns_host = fval;
	}
	if (gensio_check_keyvalue(options[i], "mdns-txt", &val) > 0) {
	    int err = gensio_argv_append(so, &admin_mdns_txt, val,
					 &admin_mdns_txt_args,
					 &admin_mdns_txt_argc,
					 true);

	    if (err) {
		eout->out(eout, "Out of memory allocating admin mdns-txt: %s",
			  gensio_err_to_str(err));
		return -1;
	    }
	}
#endif
	eout->out(eout, "Invalid option to admin port: %s", options[i]);
	return -1;
    }

    return 0;
}

/* Set up the controller port to accept connections. */
void
controller_init(char *controller_port, const char *name,
		const char * const *options, struct absout *eout)
{
    int rv;
#ifdef GENSIO_ACC_CONTROL_TCPDNAME
    char progname[1];
    gensiods len;
#endif

    if (controller_accepter) {
	eout->out(eout, "Admin port already configured");
	return;
    }

    if (name) {
	admin_name = strdup(name);
	if (!admin_name) {
	    eout->out(eout, "Unable to allocate admin name");
	    return;
	}
    }

    if (controller_handle_options(options, eout))
	return;

    if (!cntlr_lock) {
	cntlr_lock = so->alloc_lock(so);
	if (!cntlr_lock)
	    goto out_nomem;
    }

    if (!controller_shutdown_waiter) {
	controller_shutdown_waiter = so->alloc_waiter(so);
	if (!controller_shutdown_waiter)
	    goto out_nomem;
    }

    if (!accept_waiter) {
	accept_waiter = so->alloc_waiter(so);
	if (!accept_waiter) {
	    eout->out(eout, "Unable to allocate controller accept waiter");
	    goto out;
	}
    }

    rv = str_to_gensio_accepter(controller_port, so,
				controller_acc_child_event, NULL,
				&controller_accepter);
    if (rv) {
	eout->out(eout, "Unable to allocate controller accepter: %s",
		  gensio_err_to_str(rv));
	goto out;
    }

#ifdef GENSIO_ACC_CONTROL_TCPDNAME
    len = 0;
    rv = gensio_acc_control(controller_accepter, GENSIO_CONTROL_DEPTH_FIRST,
			    true, GENSIO_ACC_CONTROL_TCPDNAME, progname, &len);
    if (rv == GE_NOTSUP) {
	/* No TCP in the stack, doesn't matter. */
	rv = 0;
    } else {
	if (rv == GE_NODATA) { /* The user didn't set it. */
	    rv = gensio_acc_control(controller_accepter,
				    GENSIO_CONTROL_DEPTH_FIRST,
				    false, GENSIO_ACC_CONTROL_TCPDNAME,
				    "ser2net-control", NULL);
	}
    }
    if (rv)
	eout->out(eout, "Error setting controller tcpdname: %s",
		  gensio_err_to_str(rv));

#endif
    rv = gensio_acc_startup(controller_accepter);
    if (rv)
	eout->out(eout, "Unable to start controller accepter: %s",
		  gensio_err_to_str(rv));

    admin_mdns_setup(eout);

 out:
    return;

 out_nomem:
    eout->out(eout, "Unable to allocate memory for controller");
    return;
}

void
controller_shutdown(void)
{
    if (controller_accepter) {
	admin_mdns_shutdown();
	gensio_acc_shutdown(controller_accepter, controller_shutdown_done,
			    NULL);
	so->wait(accept_waiter, 1, NULL);
	gensio_acc_free(controller_accepter);
	controller_accepter = NULL;
	if (controller_authdir)
	    free(controller_authdir);
	controller_authdir = NULL;
    }
}

static void
shutdown_controller_done(void *cb_data)
{
    struct gensio_waiter *waiter = cb_data;

    so->wake(waiter);
}

void
free_controllers(void)
{
    controller_shutdown();
    while (controllers) {
	controllers->shutdown_complete = shutdown_controller_done;
	controllers->shutdown_complete_cb_data = controller_shutdown_waiter;
	so->lock(controllers->lock);
	shutdown_controller(controllers); /* Releases the lock. */
	so->wait(controller_shutdown_waiter, 1, NULL);
    }
    if (controller_shutdown_waiter)
	so->free_waiter(controller_shutdown_waiter);
    if (accept_waiter)
	so->free_waiter(accept_waiter);
}
