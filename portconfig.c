/*
 *  ser2net - A program for allowing telnet connection to serial ports
 *  Copyright (C) 2020  Corey Minyard <minyard@acm.org>
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
#include <assert.h>
#include <gensio/gensio.h>
#include <gensio/argvutils.h>
#include "ser2net.h"
#include "port.h"
#include "absout.h"
#include "readconfig.h"
#include "defaults.h"
#include "led.h"

#ifdef gensio_version_major
/* When the version info was added, the type was changed. */
typedef struct gensio_addr gaddrinfo;
#define gensio_free_addrinfo(o, a) gensio_addr_free(a)
#else
typedef struct addrinfo gaddrinfo;
#endif

/*
 * This infrastructure allows a list of addresses to be kept.  This is
 * for checking remote addresses
 */
struct port_remaddr
{
    char *str;
    gaddrinfo *ai;
    bool is_port_set;
    struct port_remaddr *next;
};

/* Add a remaddr to the given list, return 0 on success or errno on fail. */
static int
remaddr_append(struct port_remaddr **list, struct port_remaddr **cblist,
	       const char *str, bool is_connect_back)
{
    struct port_remaddr *r = NULL, *r2, *rcb = NULL;
    gaddrinfo *ai = NULL;
    bool is_port_set = false;
    int err = 0;

    if (!is_connect_back) {
	if (*str == '!') {
	    str++;
	    is_connect_back = true;
	}

#ifdef gensio_version_major
	err = gensio_scan_network_port(so, str, false, &ai, NULL,
				       &is_port_set, NULL, NULL);
#else
	int socktype, protocol;
	err = gensio_scan_network_port(so, str, false, &ai,
				       &socktype, &protocol,
				       &is_port_set, NULL, NULL);
#endif
	if (err)
	    return err;
	/* FIXME - We currently ignore the protocol. */

	r = malloc(sizeof(*r));
	if (!r) {
	    err = GE_NOMEM;
	    goto out;
	}
	memset(r, 0, sizeof(*r));

	r->str = strdup(str);
	if (!r->str) {
	    free(r);
	    r = NULL;
	    err = GE_NOMEM;
	    goto out;
	}
	r->ai = ai;
	ai = NULL;
	r->is_port_set = is_port_set;
	r->next = NULL;

	r2 = *list;
	if (!r2) {
	    *list = r;
	} else {
	    while (r2->next)
		r2 = r2->next;
	    r2->next = r;
	}
    }

    if (is_connect_back) {
	rcb = malloc(sizeof(*rcb));
	if (!rcb) {
	    err = GE_NOMEM;
	    goto out;
	}
	memset(rcb, 0, sizeof(*rcb));

	rcb->str = strdup(str);
	if (!rcb->str) {
	    err = GE_NOMEM;
	    goto out;
	}
	rcb->next = NULL;

	r2 = *cblist;
	if (!r2) {
	    *cblist = rcb;
	} else {
	    while (r2->next)
		r2 = r2->next;
	    r2->next = rcb;
	}
    }
 out:
    if (err) {
	if (r) {
	    if (r->str)
		free(r->str);
	    if (r->ai)
		gensio_free_addrinfo(so, r->ai);
	    free(r);
	}
	if (rcb)
	    /* rcb->str cannot be set, the last failure is its allocation. */
	    free(rcb);
	if (ai)
	    gensio_free_addrinfo(so, ai);
    }
    return err;
}

static bool
ai_check(gaddrinfo *ai, const struct sockaddr *addr, socklen_t len,
	 bool is_port_set)
{
#ifdef gensio_version_major
    return gensio_addr_addr_present(ai, addr, len, is_port_set);
#else
    while (ai) {
	if (gensio_sockaddr_equal(addr, len, ai->ai_addr, ai->ai_addrlen,
				  is_port_set))
	    return true;
	ai = ai->ai_next;
    }

    return false;
#endif
}

/* Check that the given address matches something in the list. */
bool
remaddr_check(const struct port_remaddr *list,
	      const struct sockaddr *addr, socklen_t len)
{
    const struct port_remaddr *r = list;

    if (!r)
	return true;

    for (; r; r = r->next) {
	if (ai_check(r->ai, addr, len, r->is_port_set))
	    return true;
    }

    return false;
}

void
remaddr_list_free(struct port_remaddr *list)
{
    struct port_remaddr *r;

    while (list) {
	r = list;
	list = r->next;
	if (r->ai)
	    gensio_free_addrinfo(so, r->ai);
	free(r->str);
	free(r);
    }
}

static int
port_add_remaddr(struct absout *eout, port_info_t *port, const char *istr)
{
    char *str;
    char *strtok_data;
    char *remstr;
    int err = 0;

    str = strdup(istr);
    if (!str) {
	eout->out(eout, "Out of memory handling remote address '%s'", istr);
	return GE_NOMEM;
    }

    remstr = strtok_r(str, ";", &strtok_data);
    /* Note that we ignore an empty remaddr. */
    while (remstr && *remstr) {
	err = remaddr_append(&port->remaddrs, &port->connbacks, remstr, false);
	if (err) {
	    eout->out(eout, "Error adding remote address '%s': %s\n", remstr,
		      gensio_err_to_str(err));
	    break;
	}
	remstr = strtok_r(NULL, ";", &strtok_data);
    }
    free(str);
    return err;
}

static int
port_add_connback(struct absout *eout, port_info_t *port, const char *istr)
{
    char *str;
    char *strtok_data;
    char *remstr;
    int err = 0;

    str = strdup(istr);
    if (!str) {
	eout->out(eout, "Out of memory handling connect back address '%s'",
		  istr);
	return GE_NOMEM;
    }

    remstr = strtok_r(str, ";", &strtok_data);
    /* Note that we ignore an empty remaddr. */
    while (remstr && *remstr) {
	err = remaddr_append(NULL, &port->connbacks, remstr, true);
	if (err) {
	    eout->out(eout, "Error adding connect back address '%s': %s\n",
		      remstr, gensio_err_to_str(err));
	    break;
	}
	remstr = strtok_r(NULL, ";", &strtok_data);
    }
    free(str);
    return err;
}

/* Must be called with port->lock held. */
static void
finish_free_port(port_info_t *port)
{
    assert(port->free_count > 0);
    port->free_count--;
    if (port->free_count != 0) {
	so->unlock(port->lock);
	return;
    }
    so->unlock(port->lock);
    so->free_lock(port->lock);
    remaddr_list_free(port->remaddrs);
    remaddr_list_free(port->connbacks);
    if (port->accepter)
	gensio_acc_free(port->accepter);
    if (port->dev_to_net.buf)
	free(port->dev_to_net.buf);
    if (port->net_to_dev.buf)
	free(port->net_to_dev.buf);
    if (port->timer)
	so->free_timer(port->timer);
    if (port->send_timer)
	so->free_timer(port->send_timer);
    if (port->runshutdown)
	so->free_runner(port->runshutdown);
    if (port->io)
	gensio_free(port->io);
    if (port->trace_read.filename)
	free(port->trace_read.filename);
    if (port->trace_write.filename)
	free(port->trace_write.filename);
    if (port->trace_both.filename)
	free(port->trace_both.filename);
    if (port->devname)
	free(port->devname);
    if (port->name)
	free(port->name);
    if (port->accstr)
	free(port->accstr);
    if (port->new_config)
	free_port(port->new_config);
    if (port->bannerstr)
	free(port->bannerstr);
    if (port->signaturestr)
	free(port->signaturestr);
    if (port->authdir)
	free(port->authdir);
    free_user_list(port->allowed_users);
    if (port->default_allowed_users)
	free(port->default_allowed_users);
    if (port->openstr)
	free(port->openstr);
    if (port->closestr)
	free(port->closestr);
    if (port->closeon)
	free(port->closeon);
    if (port->netcons)
	free(port->netcons);
    if (port->orig_devname)
	free(port->orig_devname);
    if (port->sendon)
	free(port->sendon);
    if (port->led_rx)
	free_led(port->led_rx);
    if (port->led_tx)
	free_led(port->led_tx);
    if (port->led_conn)
	free_led(port->led_conn);
#ifdef DO_MDNS
    mdns_shutdown(&port->mdns_info);
#endif /* DO_MDNS */
    free(port);
}

static void
gen_timer_shutdown_done(struct gensio_timer *timer, void *cb_data)
{
    port_info_t *port = cb_data;

    so->lock(port->lock);
    finish_free_port(port); /* Releases lock */
}

void
free_port(port_info_t *port)
{
    net_info_t *netcon;
    int err;

    if (port->netcons) {
	for_each_connection(port, netcon) {
	    char *err = "Port was deleted\n\r";
	    if (netcon->new_net) {
		gensio_write(netcon->new_net, NULL, err, strlen(err), NULL);
		gensio_free(netcon->new_net);
	    }
	}
    }

    so->lock(port->lock);
    port->free_count = 1;

    /* Make sure all the timers are stopped. */
    if (port->send_timer) {
	err = so->stop_timer_with_done(port->send_timer,
				       gen_timer_shutdown_done, port);
	if (err != GE_TIMEDOUT)
	    port->free_count++;
    }

    if (port->timer) {
	err = so->stop_timer_with_done(port->timer,
				       gen_timer_shutdown_done, port);
	if (err != GE_TIMEDOUT)
	    port->free_count++;
    }
    finish_free_port(port); /* Releases lock */
}

static int
strdupcat(char **str, const char *cat)
{
    char *s = malloc(strlen(*str) + strlen(cat) + 2);

    if (!s)
	return GE_NOMEM;
    strcpy(s, *str);
    strcat(s, ",");
    strcat(s, cat);
    free(*str);
    *str = s;
    return 0;
}

static int
check_keyvalue_default(const char *str, const char *name, const char **value,
		       const char *def)
{
    if (strcmp(str, name) == 0)
	*value = def;
    else
	return gensio_check_keyvalue(str, name, value);
    return 1;
}

static int
update_str_val(const char *str, char **outstr, const char *name,
	       struct absout *eout)
{
    char *fval = strdup(str);

    if (!fval) {
	eout->out(eout, "Out of memory allocating %s", name);
	return -1;
    }
    if (*outstr)
	free(*outstr);
    *outstr = fval;
    return 0;
}

static int
myconfig(port_info_t *port, struct absout *eout, const char *pos)
{
    char *fval;
    const char *val;
    int rv;

    if (gensio_check_keybool(pos, "kickolduser",
			     &port->kickolduser_mode) > 0) {
    } else if (gensio_check_keybool(pos, "timeout-on-os-queue",
				    &port->timeout_on_os_queue) > 0) {
    } else if (gensio_check_keybool(pos, "trace-hexdump",
				    &port->trace_read.hexdump) > 0) {
	port->trace_write.hexdump = port->trace_read.hexdump;
	port->trace_both.hexdump = port->trace_read.hexdump;
    } else if (gensio_check_keybool(pos, "trace-timestamp",
				    &port->trace_read.timestamp) > 0) {
	port->trace_write.timestamp = port->trace_read.timestamp;
	port->trace_both.timestamp = port->trace_read.timestamp;
    } else if (gensio_check_keybool(pos, "trace-read-hexdump",
				    &port->trace_read.hexdump) > 0) {
    } else if (gensio_check_keybool(pos, "trace-read-timestamp",
				    &port->trace_read.timestamp) > 0) {
    } else if (gensio_check_keybool(pos, "trace-write-hexdump",
				    &port->trace_write.hexdump) > 0) {
    } else if (gensio_check_keybool(pos, "trace-write-timestamp",
				    &port->trace_write.timestamp) > 0) {
    } else if (gensio_check_keybool(pos, "trace-both-hexdump",
				    &port->trace_both.hexdump) > 0) {
    } else if (gensio_check_keybool(pos, "trace-both-timestamp",
				    &port->trace_both.timestamp) > 0) {
    } else if (gensio_check_keyvalue(pos, "trace-read", &val) > 0) {
	/* trace read, data from the port to the socket */
	if (update_str_val(val, &port->trace_read.filename, "trace-read", eout))
	    return -1;
    } else if (gensio_check_keyvalue(pos, "trace-write", &val) > 0) {
	/* trace write, data from the socket to the port */
	if (update_str_val(val, &port->trace_write.filename, "trace-write",
			   eout))
	    return -1;
    } else if (gensio_check_keyvalue(pos, "trace-both", &val) > 0) {
	/* trace both directions. */
	if (update_str_val(val, &port->trace_both.filename, "trace-both", eout))
	    return -1;
    } else if (gensio_check_keyvalue(pos, "led-rx", &val) > 0) {
	/* LED for UART RX traffic */
	port->led_rx = find_led(val);
	if (!port->led_rx) {
	    eout->out(eout, "Could not find led-rx LED: %s", val);
	    return -1;
	}
    } else if (gensio_check_keyvalue(pos, "led-tx", &val) > 0) {
	/* LED for UART TX traffic */
	port->led_tx = find_led(val);
	if (!port->led_tx) {
	    eout->out(eout, "Could not find led-tx LED: %s", val);
	    return -1;
	}
    } else if (gensio_check_keyvalue(pos, "led-conn", &val) > 0) {
	/* LED for UART Connection */
	port->led_conn = find_led(val);
	if (!port->led_conn) {
	    eout->out(eout, "Could not find led-conn LED: %s", val);
	    return -1;
	}
    } else if (gensio_check_keybool(pos, "telnet-brk-on-sync",
				    &port->telnet_brk_on_sync) > 0) {
    } else if (gensio_check_keybool(pos, "chardelay",
				    &port->enable_chardelay) > 0) {
    } else if (gensio_check_keybool(pos, "no-con-to-acc",
				    &port->no_dev_to_net) > 0) {
    } else if (gensio_check_keybool(pos, "no-acc-to-con",
				    &port->no_net_to_dev) > 0) {
    } else if (gensio_check_keyuint(pos, "chardelay-scale",
				   &port->chardelay_scale) > 0) {
    } else if (gensio_check_keyuint(pos, "chardelay-min",
				   &port->chardelay_min) > 0) {
    } else if (gensio_check_keyuint(pos, "chardelay-max",
				   &port->chardelay_max) > 0) {
    } else if (gensio_check_keyds(pos, "dev-to-net-bufsize",
				  &port->dev_to_net.maxsize) > 0) {
	if (port->dev_to_net.maxsize < 2)
	    port->dev_to_net.maxsize = 2;
    } else if (gensio_check_keyds(pos, "net-to-dev-bufsize",
				  &port->net_to_dev.maxsize) > 0) {
	if (port->net_to_dev.maxsize < 2)
	    port->net_to_dev.maxsize = 2;
    } else if (gensio_check_keyuint(pos, "max-connections",
				   &port->max_connections) > 0) {
	if (port->max_connections < 1)
	    port->max_connections = 1;
    } else if (gensio_check_keyuint(pos, "accepter-retry-time",
				   &port->accepter_retry_time) > 0) {
	if (port->accepter_retry_time < 1)
	    port->accepter_retry_time = 1;
    } else if (gensio_check_keyuint(pos, "connector-retry-time",
				   &port->connector_retry_time) > 0) {
	if (port->connector_retry_time < 1)
	    port->connector_retry_time = 1;
    } else if (gensio_check_keyvalue(pos, "authdir", &val) > 0) {
	fval = strdup(val);
	if (!fval) {
	    eout->out(eout, "Out of memory allocating authdir");
	    return -1;
	}
	if (port->authdir)
	    free(port->authdir);
	port->authdir = fval;
    } else if (gensio_check_keyvalue(pos, "pamauth", &val) > 0) {
	fval = strdup(val);
	if (!fval) {
	    eout->out(eout, "Out of memory allocating pamauth");
	    return -1;
	}
	if (port->pamauth)
	    free(port->pamauth);
	port->pamauth = fval;
    } else if (gensio_check_keyvalue(pos, "allowed-users", &val) > 0) {
	rv = add_allowed_users(&port->allowed_users, val, eout);
	if (rv)
	    return -1;
    } else if (gensio_check_keyvalue(pos, "remaddr", &val) > 0) {
	rv = port_add_remaddr(eout, port, val);
	if (rv)
	    return -1;
    } else if (gensio_check_keyvalue(pos, "connback", &val) > 0) {
	rv = port_add_connback(eout, port, val);
	if (rv)
	    return -1;
    } else if (gensio_check_keyuint(pos, "connback-timeout",
				    &port->connback_timeout) > 0) {
	port->connback_timeout_set = true;
    } else if (check_keyvalue_default(pos, "banner", &val, "") > 0) {
	fval = strdup(val);
	if (!fval) {
	    eout->out(eout, "Out of memory allocating banner");
	    return -1;
	}
	if (port->bannerstr)
	    free(port->bannerstr);
	port->bannerstr = fval;
    } else if (check_keyvalue_default(pos, "openstr", &val, "") > 0) {
	fval = strdup(val);
	if (!fval) {
	    eout->out(eout, "Out of memory allocating openstr");
	    return -1;
	}
	if (port->openstr)
	    free(port->openstr);
	port->openstr = fval;
    } else if (check_keyvalue_default(pos, "closestr", &val, "") > 0) {
	fval = strdup(val);
	if (!fval) {
	    eout->out(eout, "Out of memory allocating closestr");
	    return -1;
	}
	if (port->closestr)
	    free(port->closestr);
	port->closestr = fval;
    } else if (gensio_check_keyvalue(pos, "closeon", &val) > 0) {
	struct timeval tv = { 0, 0 };
	gensiods len;

	fval = process_str_to_str(port, NULL, val, &tv, &len, false, eout);
	if (!fval) {
	    eout->out(eout, "Out of memory allocating closeon");
	    return -1;
	}
	if (port->closeon)
	    free(port->closeon);
	port->closeon = fval;
	port->closeon_len = len;
    } else if (check_keyvalue_default(pos, "signature", &val, "") > 0) {
	fval = strdup(val);
	if (!fval) {
	    eout->out(eout, "Out of memory banner");
	    return -1;
	}
	if (port->signaturestr)
	    free(port->signaturestr);
	port->signaturestr = fval;
    } else if (gensio_check_keyvalue(pos, "sendon", &val) > 0) {
	struct timeval tv =  { 0, 0 };
	gensiods len;

	fval= process_str_to_str(port, NULL, val, &tv, &len, false, eout);
	if (!fval) {
	    eout->out(eout, "Out of memory allocating sendon");
	    return -1;
	}
	if (port->sendon)
	    free(port->sendon);
	port->sendon = fval;
	port->sendon_len = len;
#ifdef DO_MDNS
    } else if (mdns_checkoption(pos, &port->mdns_info, port->name, eout) > 0) {
#endif /* DO_MDNS */
    } else {
	eout->out(eout, "Unknown config item: %s", pos);
	return -1;
    }

    return 0;
}

static void
process_connect_back(struct absout *eout, port_info_t *port,
		     struct port_remaddr *r)
{
    net_info_t *netcon;

    for_each_connection(port, netcon) {
        if (netcon->remote_fixed)
            continue;

	netcon->remote_fixed = true;
	netcon->remote_str = r->str;
	netcon->connect_back = true;
	return;
    }

    if (eout)
	eout->out(eout, "Too many connect back remote addresses specified"
		  " for the max-connections given");
}

static int
init_port_data(port_info_t *port, struct absout *eout)
{
    port->enabled = false;

    port->net_to_dev_state = PORT_CLOSED;
    port->dev_to_net_state = PORT_CLOSED;
    port->trace_read.f = NULL;
    port->trace_write.f = NULL;
    port->trace_both.f = NULL;

    port->telnet_brk_on_sync = find_default_bool("telnet-brk-on-sync");
    port->kickolduser_mode = find_default_bool("kickolduser");
    port->timeout_on_os_queue = find_default_bool("timeout-on-os-queue");
    port->enable_chardelay = find_default_int("chardelay");
    port->chardelay_scale = find_default_int("chardelay-scale");
    port->chardelay_min = find_default_int("chardelay-min");
    port->chardelay_max = find_default_int("chardelay-max");
    port->dev_to_net.maxsize = find_default_int("dev-to-net-bufsize");
    port->net_to_dev.maxsize = find_default_int("net-to-dev-bufsize");
    port->max_connections = find_default_int("max-connections");
    port->connector_retry_time = find_default_int("connector-retry-time");
    port->accepter_retry_time = find_default_int("accepter-retry-time");
    if (find_default_str("authdir", &port->authdir))
	return GE_NOMEM;
    if (find_default_str("pamauth", &port->pamauth))
	return GE_NOMEM;
    if (find_default_str("allowed-users", &port->default_allowed_users))
	return GE_NOMEM;
    if (find_default_str("signature", &port->signaturestr))
	return GE_NOMEM;
    if (find_default_str("banner", &port->bannerstr))
	return GE_NOMEM;
    if (find_default_str("openstr", &port->openstr))
	return GE_NOMEM;
    if (find_default_str("closestr", &port->closestr))
	return GE_NOMEM;
    if (find_default_str("closeon", &port->closeon))
	return GE_NOMEM;
    if (find_default_str("sendon", &port->sendon))
	return GE_NOMEM;

    port->led_tx = NULL;
    port->led_rx = NULL;
    port->led_conn = NULL;

#ifdef DO_MDNS
    mdns_info_getdefaults(&port->mdns_info, port->name, eout);
    /* The bool is not defaulted in getdefaults. */
    port->mdns_info.mdns = find_default_bool("mdns");
#endif /* DO_MDNS */

    return 0;
}

/* Create a port based on a set of parameters passed in. */
int
portconfig(struct absout *eout,
	   const char *name,
	   const char *accstr,
	   const char *state,
	   unsigned int timeout,
	   const char *devname,
	   const char * const *devcfg)
{
    port_info_t *new_port, *curr;
    net_info_t *netcon;
    int err;
    bool write_only = false;
    unsigned int i;
    struct port_remaddr *r;

    so->lock(ports_lock);
    curr = new_ports;
    while (curr) {
	if (strcmp(curr->name, name) == 0) {
	    /* We don't allow duplicate names. */
	    so->unlock(ports_lock);
	    eout->out(eout, "Duplicate connection name: %s", name);
	    return -1;
	}
	curr = curr->next;
    }
    so->unlock(ports_lock);

    new_port = malloc(sizeof(port_info_t));
    if (new_port == NULL) {
	eout->out(eout, "Could not allocate a port data structure");
	return -1;
    }
    memset(new_port, 0, sizeof(*new_port));

    new_port->lock = so->alloc_lock(so);
    if (!new_port->lock) {
	eout->out(eout, "Could not allocate lock");
	goto errout;
    }

    new_port->devname = strdup(devname);
    if (!new_port->devname) {
	eout->out(eout, "unable to allocate device name");
	goto errout;
    }

    err = init_port_data(new_port, eout);
    if (err)
	goto errout;

    if (!new_port->name) {
	new_port->name = strdup(name);
	if (!new_port->name) {
	    eout->out(eout, "unable to allocate port name");
	    goto errout;
	}
    }

    if (!new_port->accstr) {
	new_port->accstr = strdup(accstr);
	if (!new_port->accstr) {
	    eout->out(eout, "unable to allocate port accepter string");
	    goto errout;
	}
    }

    if (strcmp(state, "on") == 0) {
	new_port->enabled = true;
    } else if (strcmp(state, "raw") == 0) {
	new_port->enabled = true;
    } else if (strcmp(state, "rawlp") == 0) {
	/* FIXME - remove this someday. */
	new_port->enabled = true;
	write_only = true;
    } else if (strcmp(state, "telnet") == 0) {
	/* FIXME - remove this someday. */
	new_port->enabled = true;
	new_port->do_telnet = true;
    } else if (strcmp(state, "off") == 0) {
	new_port->enabled = false;
    } else {
	eout->out(eout, "state was invalid");
	goto errout;
    }

    new_port->timeout = timeout;

    for (i = 0; devcfg[i]; i++) {
	err = myconfig(new_port, eout, devcfg[i]);
	if (err)
	    goto errout;
    }

    if (write_only) {
	err = strdupcat(&new_port->devname, "WRONLY");
	if (err) {
	    eout->out(eout, "Out of memory appending to devname");
	    goto errout;
	}
    }

    if (new_port->rs485) {
	err = strdupcat(&new_port->devname, "rs485=");
	if (!err)
	    err = strdupcat(&new_port->devname, new_port->rs485);
	if (err) {
	    eout->out(eout, "Out of memory appending to devname");
	    goto errout;
	}
    }

    if (!new_port->allowed_users && new_port->default_allowed_users) {
	err = add_allowed_users(&new_port->allowed_users,
				new_port->default_allowed_users,
				eout);
	if (err)
	    goto errout;
    }
    if (new_port->default_allowed_users) {
	free(new_port->default_allowed_users);
	new_port->default_allowed_users = NULL;
    }

    if (dataxfer_setup_port(new_port, eout))
	goto errout;

    if (gbuf_init(&new_port->dev_to_net, new_port->dev_to_net.maxsize))
    {
	eout->out(eout, "Could not allocate dev to net buffer");
	goto errout;
    }

    if (gbuf_init(&new_port->net_to_dev, new_port->net_to_dev.maxsize))
    {
	eout->out(eout, "Could not allocate net to dev buffer");
	goto errout;
    }

    /*
     * Don't handle the remaddr/connect back defaults until here, we
     * don't want to mess with it if the user has set it, because the
     * user may set it to an empty string.
     */
    if (!new_port->remaddrs) {
	char *remaddr;
	if (find_default_str("remaddr", &remaddr)) {
	    eout->out(eout, "Out of memory processing default remote address");
	} else if (remaddr) {
	    err = port_add_remaddr(eout, new_port, remaddr);
	    free(remaddr);
	    if (err)
		goto errout;
	}
    }
    if (!new_port->connbacks) {
	char *remaddr;
	if (find_default_str("connback", &remaddr)) {
	    eout->out(eout, "Out of memory processing default connect back "
		      "address");
	} else if (remaddr) {
	    err = port_add_connback(eout, new_port, remaddr);
	    free(remaddr);
	    if (err)
		goto errout;
	}
    }

    new_port->netcons = malloc(sizeof(net_info_t) * new_port->max_connections);
    if (new_port->netcons == NULL) {
	eout->out(eout, "Could not allocate a port data structure");
	goto errout;
    }
    memset(new_port->netcons, 0,
	   sizeof(net_info_t) * new_port->max_connections);
    for_each_connection(new_port, netcon)
	netcon->port = new_port;

    for (r = new_port->connbacks; r; r = r->next)
	process_connect_back(eout, new_port, r);

    /* Link it on the end of new_ports for now. */
    if (new_ports_end)
	new_ports_end->next = new_port;
    else
	new_ports = new_port;
    new_ports_end = new_port;

    return 0;

errout:
    free_port(new_port);
    return -1;
}
