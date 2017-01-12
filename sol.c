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

/* This code handles IPMI SOL. */

#include <errno.h>
#include "devio.h"

#ifdef HAVE_OPENIPMI

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <syslog.h>

#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_smi.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_auth.h>
#include <OpenIPMI/ipmi_lan.h>

#include <OpenIPMI/ipmi_posix.h>
#include <OpenIPMI/internal/ipmi_int.h>
#include <OpenIPMI/ipmi_sol.h>
#include <OpenIPMI/ipmi_debug.h>

#include "ser2net.h"
#include "selector.h"
#include "utils.h"
#include "dataxfer.h"

static os_handler_t *os_hnd;

struct solcfg_data {
    /* Information about the terminal device. */
    char           *devname;		/* The full path to the device */
    int            devfd;		/* The file descriptor for the
                                           device, only valid if the
                                           TCP port is open. */

    ipmi_sol_conn_t *sol;
    ipmi_con_t *ipmi;
    int last_any_port_up;
    int closed;

    int speed;

    unsigned char read_data[1024];
    unsigned int read_start;
    unsigned int read_end;

    int write_ready_enabled;
    int read_ready_enabled;
    int except_ready_enabled;
    int exception_pending;

    int ready;

    unsigned int nacks_sent;

    /* Holds whether break is on or not. */
    int break_set;

    /* Disable break-commands */
    int disablebreak;

    struct devio *io;

    ipmi_args_t *args;

    /* SOL parms */
    int authenticated;
    int encrypted;
    int ack_timeout;
    int ack_retries;
    int deassert_CTS_DCD_DSR_on_connect;
    int shared_serial_alert_behavior;
};

static struct baud_rates_s {
    int real_rate;
    int val;
    int cisco_ios_val;
} baud_rates[] =
{
    { 9600, IPMI_SOL_BIT_RATE_9600, 8 },
    { 19200, IPMI_SOL_BIT_RATE_19200, 10 },
    { 38400, IPMI_SOL_BIT_RATE_38400, 12 },
    { 57600, IPMI_SOL_BIT_RATE_57600, 13 },
    { 115200, IPMI_SOL_BIT_RATE_115200, 14 },
};
#define BAUD_RATES_LEN ((sizeof(baud_rates) / sizeof(struct baud_rates_s)))

static int
get_baud_rate(int rate, int cisco, int *val)
{
    unsigned int i;
    for (i = 0; i < BAUD_RATES_LEN; i++) {
	if (cisco) {
	    if (rate == baud_rates[i].cisco_ios_val) {
		*val = baud_rates[i].val;
		return 1;
	    }
	} else {
	    if (rate == baud_rates[i].real_rate) {
		*val = baud_rates[i].val;
		return 1;
	    }
	}
    }

    return 0;
}

static int
get_rate_from_sol_baud_rate(int baud_rate, int cisco)
{
    unsigned int i;
    int val = 0;

    for (i = 0; i < BAUD_RATES_LEN; i++) {
	if (baud_rate == baud_rates[i].val) {
	    if (cisco) {
		if (baud_rates[i].cisco_ios_val < 0)
		    /* We are at a baud rate unsupported by the
		       enumeration, just return zero. */
		    val = 0;
		else
		    val = baud_rates[i].cisco_ios_val;
	    } else {
		val = baud_rates[i].real_rate;
	    }
	    break;
	}
    }

    return val;
}


static char *
baud_string(int speed)
{
    char *str;
    switch (speed) {
    case IPMI_SOL_BIT_RATE_9600: str = "9600"; break;
    case IPMI_SOL_BIT_RATE_19200: str = "19200"; break;
    case IPMI_SOL_BIT_RATE_38400: str = "38400"; break;
    case IPMI_SOL_BIT_RATE_57600: str = "57600"; break;
    case IPMI_SOL_BIT_RATE_115200: str = "115200"; break;
    default: str = "unknown speed";
    }
    return str;
}

static void
solcfg_serparm_to_str(struct devio *io, char *str, int strlen)
{
    struct solcfg_data *d = io->my_data;

    snprintf(str, strlen, "%s", baud_string(d->speed));
}

/* Send the serial port device configuration to the control port. */
static void
solcfg_show_solcfg(struct devio *io, struct absout *out)
{
    struct solcfg_data *d = io->my_data;

    out->out(out, "%s", baud_string(d->speed));
}

static int
solcfg_set_devcontrol(struct devio *io, const char *instr)
{
    return -1; /* FIXME */
}

static void
solcfg_show_devcontrol(struct devio *io, struct absout *out)
{
}

static void check_write_handler(struct solcfg_data *d)
{
    while (d->ready && d->write_ready_enabled)
	d->io->write_handler(d->io);
}

static void check_read_handler(struct solcfg_data *d)
{
    while (d->ready && d->read_ready_enabled && (d->read_start != d->read_end))
	d->io->read_handler(d->io);
}

static void check_except_handler(struct solcfg_data *d, int set)
{
    if (set)
	d->exception_pending = 1;
    if (d->except_ready_enabled && d->exception_pending) {
	d->exception_pending = 0;
	d->io->except_handler(d->io);
    }
}

static int solcfg_read(struct devio *io, void *buf, size_t size)
{
    struct solcfg_data *d = io->my_data;
    unsigned int left;
    int rv = 0;

    if (size == 0)
	return 0;

    if (d->read_end == d->read_start) {
	errno = EAGAIN;
	return -1;
    }

    if (d->read_end < d->read_start)
	/* Amount of data to the end of the buffer.  If the data wraps
	   we handle that in a check below. */
	left = sizeof(d->read_data) - d->read_start;
    else
	/* Total amount in buffer */
	left = d->read_end - d->read_start;

 read_rest:
    if (left > size)
	left = size;
    memcpy(buf, d->read_data + d->read_start, left);
    rv += left;
    size -= left;
    d->read_start += left;

    if (d->read_start >= sizeof(d->read_data)) {
	/* We wrapped, get the data at the beginning of the buffer now. */
	d->read_start = 0;
	left = d->read_end;
	goto read_rest;
    }

    if (d->nacks_sent > 0) {
	/* Calculate the data used. */
	if (d->read_end < d->read_start)
	    left = sizeof(d->read_data) - d->read_start + d->read_end;
	else
	    left = d->read_end - d->read_start;
	/* Convert to free space */
	left = sizeof(d->read_data) - left;

	/* Only release the NACK if we have sufficient free space left */
	if (left > 128) { /* FIXME - magic number */
	    while (d->nacks_sent > 0) {
		if (ipmi_sol_release_nack(d->sol) != 0)
		    goto out;
		d->nacks_sent--;
	    }
	}
    }

 out:
    return rv;
}

struct sol_tc {
    unsigned int size;
    struct solcfg_data *d;
};

static void
transmit_complete(ipmi_sol_conn_t *conn,
		  int             error,
		  void            *cb_data)
{
    struct sol_tc *tc = cb_data;
    struct solcfg_data *d = tc->d;

    if (error) {
	check_except_handler(d, 1);
	goto out;
    }

    check_write_handler(d);

 out:
    free(tc);
}

static int solcfg_write(struct devio *io, void *buf, size_t size)
{
    struct solcfg_data *d = io->my_data;
    int rv;
    struct sol_tc *tc;

    if (!d->ready) {
	errno = EAGAIN;
	return -1;
    }

    if (size == 0)
	return 0;

    tc = malloc(sizeof(*tc));
    if (!tc) {
	errno = ENOMEM;
	return -1;
    }

    tc->size = size;
    tc->d = d;
    rv = ipmi_sol_write(d->sol, buf, size, transmit_complete, tc);
    if (rv) {
	free(tc);
	if (rv == ENOMEM) {
	    errno = EAGAIN;
	    return 0;
	}
	errno = EINVAL; /* Just a guess */
	return -1;
    }
    return size;
}

static void solcfg_read_handler_enable(struct devio *io, int enabled)
{
    struct solcfg_data *d = io->my_data;

    d->read_ready_enabled = enabled;
    check_read_handler(d);
}

static void solcfg_write_handler_enable(struct devio *io, int enabled)
{
    struct solcfg_data *d = io->my_data;

    d->write_ready_enabled = enabled;
    check_write_handler(d);
}

static void solcfg_except_handler_enable(struct devio *io, int enabled)
{
    struct solcfg_data *d = io->my_data;

    d->except_ready_enabled = enabled;
    check_except_handler(d, 0);
}

static void sol_send_break_cb(ipmi_sol_conn_t *conn, int error, void *cb_data)
{
    struct solcfg_data *d = cb_data;

    if (error)
	check_except_handler(d, 1);
}

static int solcfg_send_break(struct devio *io)
{
    struct solcfg_data *d = io->my_data;

    ipmi_sol_send_break(d->sol, sol_send_break_cb, d);
    return 0;
}

static int solcfg_get_modem_state(struct devio *io, unsigned char *modemstate)
{
    return -1;
}

static int solcfg_baud_rate(struct devio *io, int *val, int cisco, int *bps)
{
    struct solcfg_data *d = io->my_data;
    int sol_rate = 0;

    if (*val != 0) {
	int err = get_baud_rate(*val, cisco, &sol_rate);
	if (!err)
	    ipmi_sol_set_bit_rate(d->sol, sol_rate);
    }

    sol_rate = ipmi_sol_get_bit_rate(d->sol);
    *val = get_rate_from_sol_baud_rate(sol_rate, cisco);
    *bps = get_rate_from_sol_baud_rate(sol_rate, 0);
    return 0;
}

static int solcfg_data_size(struct devio *io, unsigned char *val, int *bpc)
{
    *val = 8;
    *bpc = 10;
    return 0;
}

static int solcfg_parity(struct devio *io, unsigned char *val, int *bpc)
{
    *val = 1; /* NONE */
    *bpc = 10;
    return 0;
}

static int solcfg_stop_size(struct devio *io, unsigned char *val, int *bpc)
{
    *val = 1; /* 1 stop bit. */
    *bpc = 10;
    return 0;
}

static int solcfg_flow_control(struct devio *io, unsigned char val)
{
    return -1;
}

static int solcfg_control(struct devio *io, unsigned char *val)
{
    return -1;
}

static int solcfg_flush(struct devio *io, int *val)
{
    return 0;
}

static int sol_data_received(ipmi_sol_conn_t *conn,
			     const void *idata, size_t count, void *user_data)
{
    struct solcfg_data *d = user_data;
    const char *data = idata;
    int space;

    if (d->read_end >= d->read_start)
	/* Amount of data to the end of the buffer plus the buffer beginning. */
	space = sizeof(d->read_data) - d->read_start + d->read_end;
    else  /* Wrapped */
	space = d->read_start - d->read_end;
    space -= 1; /* Can't use the last byte in the buffer, or we can't
		   tell full from empty. */

    if (count > space)
	goto send_nack;

    if (d->read_end >= d->read_start &&
		count >= (sizeof(d->read_data) - d->read_end)) {
	/* New data will cause a wrap, handle copying to the end of
	   the buffer first. */
	space = sizeof(d->read_data) - d->read_end;
	memcpy(d->read_data + d->read_end, data, space);
	data += space;
	count -= space;
	d->read_end = 0;
    }

    memcpy(d->read_data + d->read_end, data, count);
    d->read_end += count;

    check_read_handler(d);

    return 0;

 send_nack:
    d->nacks_sent++;
    return 1;
}

static void sol_break_detected(ipmi_sol_conn_t *conn, void *user_data)
{
}

static void bmc_transmit_overrun(ipmi_sol_conn_t *conn, void *user_data)
{
}

static void finish_close_connection(struct solcfg_data *d)
{
    if (ser2net_debug_level > 0)
	printf("Finish close: %d %p\n", d->closed, d->ipmi);
    if (d->sol)
	ipmi_sol_free(d->sol);
    d->sol = NULL;
    if (d->ipmi)
	d->ipmi->close_connection(d->ipmi);
    d->ipmi = NULL;
    d->closed = 1;
    d->ready = 0;
}

static void sol_connection_state(ipmi_sol_conn_t *conn, ipmi_sol_state state,
				 int error, void *cb_data)
{
    struct solcfg_data *d = cb_data;

    if (ser2net_debug_level > 0)
	printf("sol_con_change: %d %d\n", state, error);
    if (error) {
	finish_close_connection(d);
	if (d->io)
	    check_except_handler(d, 1);
	else
	    free(d);
	return;
    }

    switch (state) {
    case ipmi_sol_state_closed:
	finish_close_connection(d);
	if (!d->io)
	    free(d);
	break;

    case ipmi_sol_state_connecting:
	break;

    case ipmi_sol_state_connected:
	d->ready = 1;
	check_read_handler(d);
	check_write_handler(d);
	break;

    case ipmi_sol_state_connected_ctu:
	break;

    case ipmi_sol_state_closing:
	d->ready = 0;
	break;
    }
}

static void conn_changed(ipmi_con_t   *ipmi,
			 int          err,
			 unsigned int port_num,
			 int          any_port_up,
			 void         *cb_data)
{
    struct solcfg_data *d = cb_data;

    if (ser2net_debug_level > 0)
	printf("con_change: %d %d\n", any_port_up, err);
    if (any_port_up == d->last_any_port_up)
	return;

    d->last_any_port_up = any_port_up;

    if (!d->sol) {
	finish_close_connection(d);
	if (!d->io)
	    free(d);
	return;
    }

    if (err) {
	check_except_handler(d, 1);
	return;
    }

    if (!d->ready && any_port_up) {
	ipmi_sol_open(d->sol);
    }
}

static int solcfg_setup(struct devio *io, const char *name, const char **errstr,
			int *bps, int *bpc)
{
    int rv;
    struct solcfg_data *d = io->my_data;

    if (!d->closed) {
	*errstr = "Connection still in use";
	return -1;
    }

    rv = ipmi_args_setup_con(d->args, os_hnd, NULL, &d->ipmi);
    if (rv) {
	*errstr = "Error setting up SOL connection";
	goto out;
    }

    rv = ipmi_sol_create(d->ipmi, &d->sol);
    if (rv) {
	d->ipmi->close_connection(d->ipmi);
	d->ipmi = NULL;
	*errstr = "Error creating SOL connection";
	goto out;
    }

    rv = ipmi_sol_register_data_received_callback(d->sol, sol_data_received, d);
    if (rv) {
	*errstr = "Error registering data callback";
	goto out;
    }

    rv = ipmi_sol_register_break_detected_callback(d->sol,
						   sol_break_detected, d);
    if (rv) {
	*errstr = "Error registering break detected callback";
	goto out;
    }

    rv = ipmi_sol_register_bmc_transmit_overrun_callback(d->sol,
							 bmc_transmit_overrun,
							 d);
    if (rv) {
	*errstr = "Error registering transmit overrun callback";
	goto out;
    }

    rv = ipmi_sol_register_connection_state_callback(d->sol,
						     sol_connection_state, d);
    if (rv) {
	*errstr = "Error registering connection state callback";
	goto out;
    }

    ipmi_sol_set_ACK_retries(d->sol, d->ack_retries);
    ipmi_sol_set_ACK_timeout(d->sol, d->ack_timeout);
    ipmi_sol_set_use_authentication(d->sol, d->authenticated);
    ipmi_sol_set_use_encryption(d->sol, d->encrypted);
    ipmi_sol_set_shared_serial_alert_behavior(d->sol,
					      d->shared_serial_alert_behavior);
    ipmi_sol_set_deassert_CTS_DCD_DSR_on_connect(d->sol,
					 d->deassert_CTS_DCD_DSR_on_connect);

    ipmi_sol_set_bit_rate(d->sol, d->speed);

    *bps = get_rate_from_sol_baud_rate(d->speed, 0);
    *bpc = 10;

    d->ready = 0;
    d->last_any_port_up = -1;
    rv = d->ipmi->add_con_change_handler(d->ipmi, conn_changed, d);
    if (rv) {
	*errstr = "Error adding connection change handler";
	goto out;
    }
    d->ipmi->start_con(d->ipmi);

    d->closed = 0;

out:
    if (rv) {
	rv = -1;
	if (d->sol) {
	    ipmi_sol_close(d->sol);
	    ipmi_sol_free(d->sol);
	    d->sol = NULL;
	}
	if (d->ipmi) {
	    d->ipmi->close_connection(d->ipmi);
	    d->ipmi = NULL;
	}
    }
    return rv;
}

static void solcfg_shutdown(struct devio *io,
			    void (*shutdown_done)(struct devio *))
{
    struct solcfg_data *d = io->my_data;

    if (d->sol) {
	ipmi_sol_close(d->sol);
	d->ready = 0;
    }
    shutdown_done(io);
}

static void solcfg_free(struct devio *io)
{
    struct solcfg_data *d = io->my_data;

    if (d->args)
	ipmi_free_args(d->args);
    io->f = NULL;
    io->my_data = NULL;
    d->io = NULL;
    if (!d->ipmi)
	free(d);
}

/* Configure a serial port control structure based upon input strings
   in instr.  These strings are described in the man page for this
   program. */
static int
solconfig(struct solcfg_data *d, struct absout *eout, const char *instr,
	  int (*otherconfig)(void *data, struct absout *eout, const char *item),
	  void *data)
{
    char *str = NULL;
    char *pos, *endpos;
    char *strtok_data;
    int  rv = 0;
    int argc, curr_arg = 0;
    char **argv;
    ipmi_args_t *args = NULL;
    int speed;

    if (strncmp(d->io->devname + 4, "lan ", 4) != 0) {
	eout->out(eout, "SOL config must start with 'lan ', it was %s",
		  d->io->devname + 4);
	return -1;
    }

    speed = find_default_int("speed");
    switch (speed) {
    case 9600: d->speed = IPMI_SOL_BIT_RATE_9600; break;
    case 19200: d->speed = IPMI_SOL_BIT_RATE_19200; break;
    case 38400: d->speed = IPMI_SOL_BIT_RATE_38400; break;
    case 57600: d->speed = IPMI_SOL_BIT_RATE_57600; break;
    case 115200: d->speed = IPMI_SOL_BIT_RATE_115200; break;
    default:
	eout->out(eout, "Invalid default speed for SOL %s: %d",
		  d->io->devname + 4, speed);
	return -1;
    }

    /* Enable authentication and encryption by default. */
    d->authenticated = find_default_int("authenticated");
    d->encrypted = find_default_int("encrypted");
    d->disablebreak = find_default_int("nobreak");
    d->ack_timeout = find_default_int("ack-timeout");
    d->ack_retries = find_default_int("ack-retries");
    d->shared_serial_alert_behavior = find_default_int("shared-serial-alert");
    d->deassert_CTS_DCD_DSR_on_connect =
	find_default_int("deassert_CTS_DCD_DSR_on_connect");

    rv = str_to_argv(d->io->devname + 4, &argc, &argv, NULL);
    if (rv == -ENOMEM) {
	eout->out(eout, "Out of memory parsing SOL string");
	return -1;
    } else if (rv) {
	eout->out(eout, "Invalid SOL string: %s", d->io->devname + 4);
	return -1;
    } else if (argc == 0) {
	eout->out(eout, "No SOL string given");
	return -1;
    }

    rv = ipmi_parse_args2(&curr_arg, argc, argv, &args);
    if (rv) {
	eout->out(eout, "Invalid SOL arguments");
	str_to_argv_free(argc, argv);
	goto out;
    }

    if (curr_arg != argc) {
	eout->out(eout, "Extra SOL arguments starting with '%s'",
		  argv[curr_arg]);
	str_to_argv_free(argc, argv);
	rv = -1;
	goto out;
    }
    str_to_argv_free(argc, argv);

    str = strdup(instr);
    if (str == NULL) {
	rv = -1;
	goto out;
    }

    pos = strtok_r(str, " \t", &strtok_data);
    while (pos != NULL) {
	if (strcmp(pos, "9600") == 0) {
	    d->speed = IPMI_SOL_BIT_RATE_9600;
	} else if (strcmp(pos, "19200") == 0) {
	    d->speed = IPMI_SOL_BIT_RATE_19200;
	} else if (strcmp(pos, "38400") == 0) {
	    d->speed = IPMI_SOL_BIT_RATE_38400;
	} else if (strcmp(pos, "57600") == 0) {
	    d->speed = IPMI_SOL_BIT_RATE_57600;
	} else if (strcmp(pos, "115200") == 0) {
	    d->speed = IPMI_SOL_BIT_RATE_115200;
	} else if (strcmp(pos, "-NOBREAK") == 0) {
	    d->disablebreak = 0;
	} else if (strcmp(pos, "NOBREAK") == 0) {
	    d->disablebreak = 1;
	} else if (strcmp(pos, "-authenticated") == 0) {
	    d->authenticated = 0;
	} else if (strcmp(pos, "authenticated") == 0) {
	    d->authenticated = 1;
	} else if (strcmp(pos, "-encrypted") == 0) {
	    d->encrypted = 0;
	} else if (strcmp(pos, "encrypted") == 0) {
	    d->encrypted = 1;
	} else if (strcmp(pos, "-deassert_CTS_DCD_DSR_on_connect") == 0) {
	    d->deassert_CTS_DCD_DSR_on_connect = 0;
	} else if (strcmp(pos, "deassert_CTS_DCD_DSR_on_connect") == 0) {
	    d->deassert_CTS_DCD_DSR_on_connect = 1;
	} else if (strcmp(pos, "shared_serial_alert_fail") == 0) {
	    d->shared_serial_alert_behavior = ipmi_sol_serial_alerts_fail;
	} else if (strcmp(pos, "shared_serial_alert_deferred") == 0) {
	    d->shared_serial_alert_behavior = ipmi_sol_serial_alerts_deferred;
	} else if (strcmp(pos, "shared_serial_alert_succeed") == 0) {
	    d->shared_serial_alert_behavior = ipmi_sol_serial_alerts_succeed;
	} else if (strncmp(pos, "ack-timeout=", 12) == 0) {
	    d->ack_timeout = strtoul(pos + 12, &endpos, 10);
	    if (endpos == pos + 12 || *endpos != '\0') {
		eout->out(eout, "Invalid number for ack-timeout: %s\n",
			  pos + 12);
		goto out;
	    }
	} else if (strncmp(pos, "ack-retries=", 12) == 0) {
	    d->ack_retries = strtoul(pos + 12, &endpos, 10);
	    if (endpos == pos + 12 || *endpos != '\0') {
		eout->out(eout, "Invalid number for ack-retries: %s\n",
			  pos + 12);
		goto out;
	    }
	} else {
	    if (otherconfig(data, eout, pos) == -1)
		goto out;
	}

	pos = strtok_r(NULL, " \t", &strtok_data);
    }

 out:
    if (rv && args)
	ipmi_free_args(args);
    if (!rv) {
	if (d->args)
	    ipmi_free_args(d->args);
	d->args = args;
    }
    if (str)
	free(str);
    return rv;
}

static int
solcfg_reconfig(struct devio *io, struct absout *eout, const char *instr,
		int (*otherconfig)(void *data, struct absout *eout,
				   const char *item),
		void *data)
{
    struct solcfg_data *d = io->my_data;

    return solconfig(d, eout, instr, otherconfig, data);
}

static struct devio_f solcfg_io_f = {
    .setup = solcfg_setup,
    .shutdown = solcfg_shutdown,
    .reconfig = solcfg_reconfig,
    .read = solcfg_read,
    .write = solcfg_write,
    .read_handler_enable = solcfg_read_handler_enable,
    .write_handler_enable = solcfg_write_handler_enable,
    .except_handler_enable = solcfg_except_handler_enable,
    .send_break = solcfg_send_break,
    .get_modem_state = solcfg_get_modem_state,
    .set_devcontrol = solcfg_set_devcontrol,
    .show_devcontrol = solcfg_show_devcontrol,
    .show_devcfg = solcfg_show_solcfg,
    .baud_rate = solcfg_baud_rate,
    .data_size = solcfg_data_size,
    .parity = solcfg_parity,
    .stop_size = solcfg_stop_size,
    .control = solcfg_control,
    .flow_control = solcfg_flow_control,
    .flush = solcfg_flush,
    .free = solcfg_free,
    .serparm_to_str = solcfg_serparm_to_str
};

static void
sol_ipmi_log(os_handler_t *hnd, enum ipmi_log_type_e log_type,
	     const char *format, va_list ap)
{
    int slevel = -1;

    switch (log_type) {
    case IPMI_LOG_INFO:
	if (ser2net_debug_level > 0)
	    slevel = LOG_INFO;
	break;

    case IPMI_LOG_WARNING:
	slevel = LOG_WARNING;
	break;

    case IPMI_LOG_SEVERE:
	slevel = LOG_ERR;
	break;

    case IPMI_LOG_FATAL:
	slevel = LOG_CRIT;
	break;

    case IPMI_LOG_ERR_INFO:
	slevel = LOG_NOTICE;
	break;

    case IPMI_LOG_DEBUG:
    case IPMI_LOG_DEBUG_START:
    case IPMI_LOG_DEBUG_CONT:
    case IPMI_LOG_DEBUG_END:
	if (!ser2net_debug)
	    return;
	slevel = LOG_DEBUG;
    }

    if (slevel < 0)
	return;

    switch (log_type) {
    case IPMI_LOG_DEBUG_START:
    case IPMI_LOG_DEBUG_CONT:
	vfprintf(stderr, format, ap);
	break;
    case IPMI_LOG_DEBUG:
    case IPMI_LOG_DEBUG_END:
	vfprintf(stderr, format, ap);
	fprintf(stderr, "\n");
	break;
    default:
	vsyslog(slevel, format, ap);
    }
}

int
sol_init(void)
{
#ifdef USE_PTHREADS
    os_hnd = ipmi_posix_thread_get_os_handler2(ser2net_wake_sig);
#else
    os_hnd = ipmi_posix_get_os_handler();
#endif
    if (!os_hnd)
	return -ENOMEM;
    os_hnd->vlog = sol_ipmi_log;
#ifdef USE_PTHREADS
    ipmi_posix_thread_os_handler_set_sel(os_hnd, ser2net_sel);
#else
    ipmi_posix_os_handler_set_sel(os_hnd, ser2net_sel);
#endif
    ipmi_init(os_hnd);
    return 0;
}

void
sol_shutdown(void)
{
    ipmi_shutdown();
    os_hnd->free_os_handler(os_hnd);
}

int
solcfg_init(struct devio *io, struct absout *eout, const char *instr,
	    int (*otherconfig)(void *data, struct absout *eout,
			       const char *item),
	    void *data)
{
    struct solcfg_data *d;

    d = malloc(sizeof(*d));
    if (!d)
	return -1;
    memset(d, 0, sizeof(*d));

    io->my_data = d;
    io->f = &solcfg_io_f;
    d->io = io;
    d->closed = 1;

    if (solconfig(d, eout, instr, otherconfig, data) == -1) {
	io->my_data = NULL;
	io->f = NULL;
	free(d);
	return -1;
    }

    return 0;
}

#else

int
sol_init(void)
{
    return 0;
}

int
solcfg_init(struct devio *io, struct absout *eout, const char *instr,
	    int (*otherconfig)(void *data, struct absout *eout,
			       const char *item),
	    void *data)
{
    return -ENOSYS;
}

void
sol_shutdown(void)
{
}

#endif
