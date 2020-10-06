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
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <gensio/gensio.h>
#include <gensio/argvutils.h>
#include "ser2net.h"
#include "port.h"
#include "defaults.h"

typedef struct rotator
{
    /* Rotators use the ports_lock for mutex. */
    int curr_port;
    const char **portv;
    int portc;

    char *name;
    char *accstr;

    struct gensio_accepter *accepter;

    char *authdir;
    struct gensio_list *allowed_users;
    char *default_allowed_users;

    unsigned int accepter_retry_time;

    /* If the rotator fails startup, start time timer to retry it. */
    struct gensio_timer *restart_timer;

    struct rotator *next;
} rotator_t;

static rotator_t *rotators = NULL;

/* Returns with the port locked, if non-NULL. */
static port_info_t *
find_rotator_port(const char *portname, struct gensio *net,
		  unsigned int *netconnum)
{
    port_info_t *port = ports;

    while (port) {
	if (strcmp(port->name, portname) == 0) {
	    unsigned int i;
	    struct sockaddr_storage addr;
	    gensiods socklen;
	    int err;

	    so->lock(port->lock);
	    if (!port->enabled)
		goto next;
	    if (port->dev_to_net_state == PORT_CLOSING)
		goto next;
	    err = net_raddr(net, &addr, &socklen);
	    if (err)
		goto next;
	    if (!remaddr_check(port->remaddrs,
			       (struct sockaddr *) &addr, socklen))
		goto next;
	    if (port->net_to_dev_state == PORT_UNCONNECTED &&
		is_device_already_inuse(port))
		goto next;

	    for (i = 0; i < port->max_connections; i++) {
		if (!port->netcons[i].net) {
		    *netconnum = i;
		    return port;
		}
	    }
	next:
	    so->unlock(port->lock);
	}
	port = port->next;
    }

    return NULL;
}

/* A connection request has come in on a port. */
static int
rot_new_con(rotator_t *rot, struct gensio *net)
{
    int i;
    const char *err;

    so->lock(ports_lock);
    i = rot->curr_port;
    do {
	unsigned int netconnum = 0;
	port_info_t *port = find_rotator_port(rot->portv[i], net, &netconnum);

	if (++i >= rot->portc)
	    i = 0;
	if (port) {
	    rot->curr_port = i;
	    so->unlock(ports_lock);
	    handle_new_net(port, net, &port->netcons[netconnum]);
	    so->unlock(port->lock);
	    return 0;
	}
    } while (i != rot->curr_port);
    so->unlock(ports_lock);

    err = "No free port found\r\n";
    gensio_write(net, NULL, err, strlen(err), NULL);
    gensio_free(net);
    return 0;
}

static int
handle_rot_child_event(struct gensio_accepter *accepter, void *user_data,
		       int event, void *data)
{
    rotator_t *rot = user_data;

    if (event == GENSIO_ACC_EVENT_LOG) {
	do_gensio_log(rot->accstr, data);
	return 0;
    }

    switch (event) {
    case GENSIO_ACC_EVENT_NEW_CONNECTION:
	return rot_new_con(rot, data);

    default:
	return handle_acc_auth_event(rot->authdir, rot->allowed_users,
				     event, data);
    }
}

static struct gensio_waiter *rotator_shutdown_wait;

static void
handle_rot_shutdown_done(struct gensio_accepter *accepter, void *cb_data)
{
    so->wake(rotator_shutdown_wait);
}

static void
rot_timer_shutdown_done(struct gensio_timer *timer, void *cb_data)
{
    so->wake(rotator_shutdown_wait);
}

static void
free_rotator(rotator_t *rot)
{
    int err;
    unsigned int free_count = 0;

    if (rot->accepter) {
	err = gensio_acc_shutdown(rot->accepter, handle_rot_shutdown_done, rot);
	if (!err)
	    free_count++;
    }

    if (rot->restart_timer) {
	err = so->stop_timer_with_done(rot->restart_timer,
				       rot_timer_shutdown_done, rot);
	if (err != GE_TIMEDOUT)
	    free_count++;
    }

    if (free_count)
	so->wait(rotator_shutdown_wait, free_count, NULL);

    if (rot->accepter)
	gensio_acc_free(rot->accepter);
    if (rot->authdir)
	free(rot->authdir);
    free_user_list(rot->allowed_users);
    if (rot->default_allowed_users)
	free(rot->default_allowed_users);
    if (rot->name)
	free(rot->name);
    if (rot->accstr)
	free(rot->accstr);
    if (rot->portv)
	gensio_argv_free(so, rot->portv);
    if (rot->restart_timer)
	so->free_timer(rot->restart_timer);
    free(rot);
}

void
free_rotators(void)
{
    rotator_t *rot, *next;

    rot = rotators;
    while (rot) {
	next = rot->next;
	free_rotator(rot);
	rot = next;
    }
    rotators = NULL;
}

static void
rot_timeout(struct gensio_timer *timer, void *cb_data)
{
    rotator_t *rot = cb_data;
    int rv;

    rv = gensio_acc_startup(rot->accepter);
    if (rv) {
	gensio_time timeout = { rot->accepter_retry_time, 0 };

	syslog(LOG_ERR, "Failed to start rotator: %s", gensio_err_to_str(rv));
	so->start_timer(rot->restart_timer, &timeout);
    }
}

void
shutdown_rotators(void)
{
    if (rotator_shutdown_wait)
	so->free_waiter(rotator_shutdown_wait);
}

int
init_rotators(void)
{
    rotator_shutdown_wait = so->alloc_waiter(so);
    if (!rotator_shutdown_wait)
	return ENOMEM;
    return 0;
}

int
add_rotator(struct absout *eout, const char *name, const char *accstr,
	    int portc, const char **ports, const char **options, int lineno)
{
    rotator_t *rot;
    int rv;

    rot = malloc(sizeof(*rot));
    if (!rot)
	return ENOMEM;
    memset(rot, 0, sizeof(*rot));

    rot->name = strdup(name);
    if (!rot->name)
	goto out_nomem;

    rot->accstr = strdup(accstr);
    if (!rot->accstr)
	goto out_nomem;

    if (find_default_str("authdir", &rot->authdir))
	goto out_nomem;

    if (find_default_str("allowed-users", &rot->default_allowed_users))
	goto out_nomem;

    rot->accepter_retry_time = find_default_int("accepter-retry-time");

    if (options) {
	unsigned int i;
	const char *str;

	for (i = 0; options[i]; i++) {
	    if (gensio_check_keyvalue(options[i], "authdir", &str) > 0) {
		if (rot->authdir)
		    free(rot->authdir);
		rot->authdir = strdup(str);
		if (!rot->authdir) {
		    eout->out(eout, "Out of memory allocating rotator"
			      " authdir on line %d\n", lineno);
		    goto out_nomem;
		}
		continue;
	    } else if (gensio_check_keyvalue(options[i],
					     "allowed-users", &str) > 0) {
		rv = add_allowed_users(&rot->allowed_users, str, eout);
		if (rv)
		    goto out_err;
		continue;
	    } else if (gensio_check_keyuint(options[i], "accepter-retry-time",
					    &rot->accepter_retry_time) > 0) {
		if (rot->accepter_retry_time < 1)
		    rot->accepter_retry_time = 1;
		continue;
	    }
	    free_rotator(rot);
	    eout->out(eout, "Invalid option %s for rotator on line %d\n",
		      options[i], lineno);
	    return EINVAL;
	}
    }

    rot->restart_timer = so->alloc_timer(so, rot_timeout, rot);
    if (!rot->restart_timer) {
	eout->out(eout, "Unable to allocate timer on line %d", lineno);
	goto out_nomem;
    }

    rot->portc = portc;
    rot->portv = ports;

    rv = str_to_gensio_accepter(rot->accstr, so,
				handle_rot_child_event, rot, &rot->accepter);
    if (rv) {
	eout->out(eout, "accepter was invalid on line %d", lineno);
	goto out_err;
    }

    if (!rot->allowed_users && rot->default_allowed_users) {
	rv = add_allowed_users(&rot->allowed_users, rot->default_allowed_users,
			       eout);
	if (rv)
	    goto out_err;
    }
    if (rot->default_allowed_users) {
	free(rot->default_allowed_users);
	rot->default_allowed_users = NULL;
    }


    rot->next = rotators;
    rotators = rot;

    rv = gensio_acc_startup(rot->accepter);
    if (rv) {
	gensio_time timeout = { rot->accepter_retry_time, 0 };

	eout->out(eout, "Failed to start rotator on line %d: %s", lineno,
		  gensio_err_to_str(rv));
	so->start_timer(rot->restart_timer, &timeout);
	/* Don't error out, retry. */
    }

    return 0;

 out_nomem:
    rv = ENOMEM;
 out_err:
    /* If we fail, the user should free these. */
    rot->portc = 0;
    rot->portv = NULL;

    free_rotator(rot);
    return rv;
}
