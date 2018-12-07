/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
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

#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/ioctl.h>
#if HAVE_DECL_TIOCSRS485
#include <linux/serial.h>
#endif

#include <gensio/sergensio_class.h>
#include <gensio/gensio_ll_fd.h>

#include "uucplock.h"
#include "utils.h"

static struct baud_rates_s {
    int real_rate;
    int val;
    const char *str;
} baud_rates[] =
{
    { 50, B50, "50" },
    { 75, B75, "75" },
    { 110, B110, "110" },
    { 134, B134, "134" },
    { 150, B150, "150" },
    { 200, B200, "200" },
    { 300, B300, "300" },
    { 600, B600, "600" },
    { 1200, B1200, "1200" },
    { 1800, B1800, "1800" },
    { 2400, B2400, "2400" },
    { 4800, B4800, "4800" },
    { 9600, B9600, "9600" },
    /* We don't support 14400 baud */
    { 19200, B19200, "19200" },
    /* We don't support 28800 baud */
    { 38400, B38400, "38400" },
    { 57600, B57600, "57600" },
    { 115200, B115200, "115200" },
#ifdef B230400
    { 230400, B230400, "230400" },
#endif
#ifdef B460800
    { 460800, B460800, "460800" },
#endif
#ifdef B500000
    { 500000, B500000, "500000" },
#endif
#ifdef B576000
    { 576000, B576000, "576000" },
#endif
#ifdef B921600
    { 921600, B921600, "921600" },
#endif
#ifdef B1000000
    { 1000000, B1000000, "1000000" },
#endif
#ifdef B1152000
    { 1152000, B1152000, "1152000" },
#endif
#ifdef B1500000
    { 1500000, B1500000, "1500000" },
#endif
#ifdef B2000000
    { 2000000, B2000000, "2000000" },
#endif
#ifdef B2500000
    { 2500000, B2500000, "2500000" },
#endif
#ifdef B3000000
    { 3000000, B3000000, "3000000" },
#endif
#ifdef B3500000
    { 3500000, B3500000, "3500000" },
#endif
#ifdef B4000000
    { 4000000, B4000000, "4000000" },
#endif
};
#define BAUD_RATES_LEN ((sizeof(baud_rates) / sizeof(struct baud_rates_s)))

static int
get_baud_rate(int rate, int *val)
{
    unsigned int i;
    for (i = 0; i < BAUD_RATES_LEN; i++) {
	if (rate == baud_rates[i].real_rate) {
	    if (val)
		*val = baud_rates[i].val;
	    return 1;
	}
    }

    return 0;
}

static const char *
get_baud_rate_str(int baud_rate)
{
    unsigned int i;
    for (i = 0; i < BAUD_RATES_LEN; i++) {
	if (baud_rate == baud_rates[i].val)
	    return baud_rates[i].str;
    }

    return "unknown speed";
}
static void
get_rate_from_baud_rate(int baud_rate, int *val)
{
    unsigned int i;

    for (i = 0; i < BAUD_RATES_LEN; i++) {
	if (baud_rate == baud_rates[i].val) {
	    *val = baud_rates[i].real_rate;
	    return;
	}
    }

    *val = 0;
}

static int
speedstr_to_speed(const char *speed, const char **rest)
{
    const char *end = speed;
    unsigned int len;
    int rv;

    while (*end && isdigit(*end))
	end++;
    len = end - speed;
    if (len < 1)
	return -1;

    rv = strtoul(speed, NULL, 10);
    *rest = end;

    return rv;
}

static void
set_termios_parity(struct termios *termctl, int val)
{
    switch (val) {
    default:
    case 'N': case 'n':
	termctl->c_cflag &= ~(PARENB);
	break;
    case 'E': case 'e':
    case 'S': case 's':
	termctl->c_cflag |= PARENB;
	termctl->c_cflag &= ~(PARODD);
#ifdef CMSPAR
	if (val == 'S' || val == 's')
	    termctl->c_cflag |= CMSPAR;
#endif
	break;
    case 'O': case 'o':
    case 'M': case 'm':
	termctl->c_cflag |= PARENB | PARODD;
#ifdef CMSPAR
	if (val == 'M' || val == 'm')
	    termctl->c_cflag |= CMSPAR;
#endif
	break;
    }
}


struct penum_val { char *str; int val; };
static struct penum_val parity_enums[] = {
    { "NONE", 'N' },
    { "EVEN", 'E' },
    { "ODD", 'O' },
    { "none", 'N' },
    { "even", 'E' },
    { "odd", 'O' },
    { "MARK", 'M' },
    { "SPACE", 'S' },
    { "mark", 'M' },
    { "space", 'S' },
    { NULL }
};

static int
lookup_parity_str(const char *str)
{
    unsigned int i;

    for (i = 0; parity_enums[i].str; i++) {
	if (strcmp(parity_enums[i].str, str) == 0)
	    return parity_enums[i].val;
    }
    return -1;
}

static void
set_termios_xonxoff(struct termios *termctl, int enabled)
{
    if (enabled) {
	termctl->c_iflag |= (IXON | IXOFF | IXANY);
	termctl->c_cc[VSTART] = 17;
	termctl->c_cc[VSTOP] = 19;
    } else {
	termctl->c_iflag &= ~(IXON | IXOFF | IXANY);
    }
}

static void
set_termios_rtscts(struct termios *termctl, int enabled)
{
    if (enabled)
	termctl->c_cflag |= CRTSCTS;
    else
	termctl->c_cflag &= ~CRTSCTS;
}

static void
set_termios_datasize(struct termios *termctl, int size)
{
    termctl->c_cflag &= ~CSIZE;
    switch (size) {
    case 5: termctl->c_cflag |= CS5; break;
    case 6: termctl->c_cflag |= CS6; break;
    case 7: termctl->c_cflag |= CS7; break;
    default: case 8: termctl->c_cflag |= CS8; break;
    }
}

static int
set_termios_from_speed(struct termios *termctl, int speed, const char *others)
{
    int speed_val;

    if (!get_baud_rate(speed, &speed_val))
	return -1;

    cfsetospeed(termctl, speed_val);
    cfsetispeed(termctl, speed_val);

    if (*others) {
	switch (*others) {
	case 'N':
	case 'E':
	case 'O':
	case 'M':
	case 'S':
	    break;
	default:
	    return -1;
	}
	set_termios_parity(termctl, *others);
	others++;
    }

    if (*others) {
	int val;

	switch (*others) {
	case '5': val = 5; break;
	case '6': val = 6; break;
	case '7': val = 7; break;
	case '8': val = 8; break;
	default:
	    return -1;
	}
	set_termios_datasize(termctl, val);
	others++;
    }

    if (*others) {
	switch (*others) {
	case '1':
	    termctl->c_cflag &= ~(CSTOPB);
	    break;

	case '2':
	    termctl->c_cflag |= CSTOPB;
	    break;

	default:
	    return -1;
	}
	others++;
    }

    if (*others)
	return -1;

    return 0;
}

enum termio_op {
    TERMIO_OP_TERMIO,
    TERMIO_OP_MCTL,
    TERMIO_OP_BRK
};

struct termio_op_q {
    enum termio_op op;
    int (*getset)(struct termios *termio, int *mctl, int *val);
    void (*done)(struct sergensio *sio, int err, int val, void *cb_data);
    void *cb_data;
    struct termio_op_q *next;
};

struct sterm_data {
    struct sergensio *sio;
    struct gensio_os_funcs *o;

    struct gensio_lock *lock;

    struct gensio_timer *timer;
    bool timer_stopped;

    bool open;
    unsigned int close_timeouts_left;

    char *devname;
    char *parms;

    int fd;

    bool write_only;		/* No termios, no read. */

    struct termios default_termios;

    bool deferred_op_pending;
    struct gensio_runner *deferred_op_runner;
    struct termio_op_q *termio_q;
    bool break_set;
    bool disablebreak;
    unsigned int last_modemstate;
    unsigned int modemstate_mask;
    bool handling_modemstate;
    bool sent_first_modemstate;

#if HAVE_DECL_TIOCSRS485
    struct serial_rs485 rs485;
#endif
};

static void termios_process(struct sterm_data *sdata);

static void
sterm_lock(struct sterm_data *sdata)
{
    sdata->o->lock(sdata->lock);
}

static void
sterm_unlock(struct sterm_data *sdata)
{
    sdata->o->unlock(sdata->lock);
}

static void
sterm_deferred_op(struct gensio_runner *runner, void *cbdata)
{
    struct sterm_data *sdata = cbdata;

    sterm_lock(sdata);
 restart:
    termios_process(sdata);

    if (sdata->termio_q)
	/* Something was added, process it. */
	goto restart;

    sdata->deferred_op_pending = false;
    sterm_unlock(sdata);
}

static void
sterm_start_deferred_op(struct sterm_data *sdata)
{
    if (!sdata->deferred_op_pending) {
	sdata->deferred_op_pending = true;
	sdata->o->run(sdata->deferred_op_runner);
    }
}

static void
termios_process(struct sterm_data *sdata)
{
    while (sdata->termio_q) {
	struct termio_op_q *qe = sdata->termio_q;
	int val = 0, err = 0;

	sdata->termio_q = qe->next;

	if (qe->op == TERMIO_OP_TERMIO) {
	    struct termios termio;

	    if (tcgetattr(sdata->fd, &termio) == -1)
		err = errno;
	    else
		err = qe->getset(&termio, NULL, &val);
	} else if (qe->op == TERMIO_OP_MCTL) {
	    int mctl = 0;

	    if (ioctl(sdata->fd, TIOCMGET, &mctl) == -1)
		err = errno;
	    else
		err = qe->getset(NULL, &mctl, &val);
	} else if (qe->op == TERMIO_OP_BRK) {
	    if (sdata->break_set)
		val = SERGENSIO_BREAK_ON;
	    else
		val = SERGENSIO_BREAK_OFF;
	}

	sterm_unlock(sdata);
	qe->done(sdata->sio, err, val, qe->cb_data);
	sdata->o->free(sdata->o, qe);
	sterm_lock(sdata);
    }
}

static int
termios_set_get(struct sterm_data *sdata, int val, enum termio_op op,
		int (*getset)(struct termios *termio, int *mctl, int *val),
		void (*done)(struct sergensio *sio, int err,
			     int val, void *cb_data),
		void *cb_data)
{
    struct termios termio;
    struct termio_op_q *qe = NULL;
    int err = 0;

    if (sdata->write_only)
	return ENOTSUP;

    if (done) {
	qe = sdata->o->zalloc(sdata->o, sizeof(*qe));
	if (!qe)
	    return ENOMEM;
	qe->getset = getset;
	qe->done = done;
	qe->cb_data = cb_data;
	qe->op = op;
	qe->next = NULL;
    }

    sterm_lock(sdata);
    if (!sdata->open) {
	err = EBUSY;
	goto out_unlock;
    }

    if (val) {
	if (op == TERMIO_OP_TERMIO) {
	    if (tcgetattr(sdata->fd, &termio) == -1) {
		err = errno;
		goto out_unlock;
	    }

	    err = getset(&termio, NULL, &val);
	    if (err)
		goto out_unlock;
	    tcsetattr(sdata->fd, TCSANOW, &termio);
	} else if (op == TERMIO_OP_MCTL) {
	    int mctl = 0;

	    if (ioctl(sdata->fd, TIOCMGET, &mctl) == -1) {
		err = errno;
	    } else {
		err = qe->getset(NULL, &mctl, &val);
		if (!err) {
		    if (ioctl(sdata->fd, TIOCMSET, &mctl) == -1)
			err = errno;
		}
	    }
	    if (err)
		goto out_unlock;
	} else if (op == TERMIO_OP_BRK) {
	    int iocval;
	    bool bval;

	    if (val == SERGENSIO_BREAK_ON) {
		iocval = TIOCSBRK;
		bval = true;
	    } else if (val == SERGENSIO_BREAK_OFF) {
		iocval = TIOCCBRK;
		bval = false;
	    } else {
		err = EINVAL;
		goto out_unlock;
	    }
	    if (ioctl(sdata->fd, iocval) == -1) {
		err = errno;
		goto out_unlock;
	    }
	    sdata->break_set = bval;
	} else {
	    err = EINVAL;
	    goto out_unlock;
	}
    }

    if (qe) {
	if (!sdata->termio_q) {
	    sdata->termio_q = qe;
	    sterm_start_deferred_op(sdata);
	} else {
	    struct termio_op_q *curr = sdata->termio_q;

	    while (curr->next)
		curr = curr->next;
	    curr->next = qe;
	}
    }
 out_unlock:
    if (err && qe)
	sdata->o->free(sdata->o, qe);
    sterm_unlock(sdata);
    return err;
}

static int
termios_get_set_baud(struct termios *termio, int *mctl, int *ival)
{
    int val = *ival;

    if (val) {
	if (!get_baud_rate(val, &val))
	    return EINVAL;

	cfsetispeed(termio, val);
	cfsetospeed(termio, val);
    } else {
	get_rate_from_baud_rate(cfgetispeed(termio), ival);
    }

    return 0;
}

static int
sterm_baud(struct sergensio *sio, int baud,
	   void (*done)(struct sergensio *sio, int err,
			int baud, void *cb_data),
	   void *cb_data)
{
    return termios_set_get(sergensio_get_gensio_data(sio), baud,
			   TERMIO_OP_TERMIO,
			   termios_get_set_baud, done, cb_data);
}

static int
termios_get_set_datasize(struct termios *termio, int *mctl, int *ival)
{
    if (*ival) {
	int val;

	switch (*ival) {
	case 5: val = CS5; break;
	case 6: val = CS6; break;
	case 7: val = CS7; break;
	case 8: val = CS8; break;
	default:
	    return EINVAL;
	}
	termio->c_cflag &= ~CSIZE;
	termio->c_cflag |= val;
    } else {
	switch (termio->c_cflag & CSIZE) {
	case CS5: *ival = 5; break;
	case CS6: *ival = 6; break;
	case CS7: *ival = 7; break;
	case CS8: *ival = 8; break;
	default:
	    return EINVAL;
	}
    }
    return 0;
}

static int
sterm_datasize(struct sergensio *sio, int datasize,
	       void (*done)(struct sergensio *sio, int err, int datasize,
			    void *cb_data),
	       void *cb_data)
{
    return termios_set_get(sergensio_get_gensio_data(sio), datasize,
			   TERMIO_OP_TERMIO,
			   termios_get_set_datasize, done, cb_data);
}

static int
termios_get_set_parity(struct termios *termio, int *mctl, int *ival)
{
    if (*ival) {
	int val;

	switch(*ival) {
	case SERGENSIO_PARITY_NONE: val = 0; break;
	case SERGENSIO_PARITY_ODD: val = PARENB | PARODD; break;
	case SERGENSIO_PARITY_EVEN: val = PARENB; break;
#ifdef CMSPAR
	case SERGENSIO_PARITY_MARK: val = PARENB | PARODD | CMSPAR; break;
	case SERGENSIO_PARITY_SPACE: val = PARENB | CMSPAR; break;
#endif
	default:
	    return EINVAL;
	}
	termio->c_cflag &= ~(PARENB | PARODD);
#ifdef CMSPAR
	termio->c_cflag &= ~CMSPAR;
#endif
	termio->c_cflag |= val;
    } else {
	if (!(termio->c_cflag & PARENB)) {
	    *ival = SERGENSIO_PARITY_NONE;
	} else if (termio->c_cflag & PARODD) {
#ifdef CMSPAR
	    if (termio->c_cflag & CMSPAR)
		*ival = SERGENSIO_PARITY_MARK;
	    else
#endif
		*ival = SERGENSIO_PARITY_ODD;
	} else {
#ifdef CMSPAR
	    if (termio->c_cflag & CMSPAR)
		*ival = SERGENSIO_PARITY_SPACE;
	    else
#endif
		*ival = SERGENSIO_PARITY_EVEN;
	}
    }

    return 0;
}

static int
sterm_parity(struct sergensio *sio, int parity,
	     void (*done)(struct sergensio *sio, int err, int parity,
			  void *cb_data),
	     void *cb_data)
{
    return termios_set_get(sergensio_get_gensio_data(sio), parity,
			   TERMIO_OP_TERMIO,
			   termios_get_set_parity, done, cb_data);
}

static int
termios_get_set_stopbits(struct termios *termio, int *mctl, int *ival)
{
    if (*ival) {
	if (*ival == 1)
	    termio->c_cflag &= ~CSTOPB;
	else if (*ival == 2)
	    termio->c_cflag |= CSTOPB;
	else
	    return EINVAL;
    } else {
	if (termio->c_cflag & CSTOPB)
	    *ival = 2;
	else
	    *ival = 1;
    }

    return 0;
}

static int
sterm_stopbits(struct sergensio *sio, int stopbits,
	       void (*done)(struct sergensio *sio, int err, int stopbits,
			    void *cb_data),
	       void *cb_data)
{
    return termios_set_get(sergensio_get_gensio_data(sio), stopbits,
			   TERMIO_OP_TERMIO,
			   termios_get_set_stopbits, done, cb_data);
}

static int
termios_get_set_flowcontrol(struct termios *termio, int *mctl, int *ival)
{
    if (*ival) {
	int val;

	switch (*ival) {
	case SERGENSIO_FLOWCONTROL_NONE: val = 0; break;
	case SERGENSIO_FLOWCONTROL_XON_XOFF: val = IXON | IXOFF; break;
	case SERGENSIO_FLOWCONTROL_RTS_CTS: val = CRTSCTS; break;
	default:
	    return EINVAL;
	}
	termio->c_cflag &= ~(IXON | IXOFF | CRTSCTS);
	termio->c_cflag |= val;
    } else {
	if (termio->c_cflag & CRTSCTS)
	    *ival = SERGENSIO_FLOWCONTROL_RTS_CTS;
	else if (termio->c_cflag & (IXON | IXOFF))
	    *ival = SERGENSIO_FLOWCONTROL_XON_XOFF;
	else
	    *ival = SERGENSIO_FLOWCONTROL_NONE;
    }

    return 0;
}

static int
termios_get_set_iflowcontrol(struct termios *termio, int *mctl, int *ival)
{
    if (*ival) {
	int val;

	/* We can only independently set XON/XOFF. */
	switch (*ival) {
	case SERGENSIO_FLOWCONTROL_NONE: val = 0; break;
	case SERGENSIO_FLOWCONTROL_XON_XOFF: val = IXOFF; break;
	default:
	    return EINVAL;
	}
	termio->c_cflag &= ~IXOFF;
	termio->c_cflag |= val;
    } else {
	if (termio->c_cflag & IXOFF)
	    *ival = SERGENSIO_FLOWCONTROL_XON_XOFF;
	else
	    *ival = SERGENSIO_FLOWCONTROL_NONE;
    }

    return 0;
}

static int
sterm_flowcontrol(struct sergensio *sio, int flowcontrol,
		  void (*done)(struct sergensio *sio, int err,
			       int flowcontrol, void *cb_data),
		  void *cb_data)
{
    return termios_set_get(sergensio_get_gensio_data(sio), flowcontrol,
			   TERMIO_OP_TERMIO,
			   termios_get_set_flowcontrol, done, cb_data);
}

static int
sterm_iflowcontrol(struct sergensio *sio, int iflowcontrol,
		   void (*done)(struct sergensio *sio, int err,
				int iflowcontrol, void *cb_data),
		   void *cb_data)
{
    return termios_set_get(sergensio_get_gensio_data(sio), iflowcontrol,
			   TERMIO_OP_TERMIO,
			   termios_get_set_iflowcontrol, done, cb_data);
}

static int
sterm_sbreak(struct sergensio *sio, int breakv,
	     void (*done)(struct sergensio *sio, int err, int breakv,
			  void *cb_data),
	     void *cb_data)
{
    return termios_set_get(sergensio_get_gensio_data(sio), breakv,
			   TERMIO_OP_BRK,
			   NULL, done, cb_data);
}

static int
termios_get_set_dtr(struct termios *termio, int *mctl, int *ival)
{
    if (*ival) {
	if (*ival == SERGENSIO_DTR_ON)
	    *mctl |= TIOCM_DTR;
	else if (*ival == SERGENSIO_DTR_OFF)
	    *mctl &= ~TIOCM_DTR;
	else
	    return EINVAL;
    } else {
	if (*mctl & TIOCM_DTR)
	    *ival = SERGENSIO_DTR_ON;
	else
	    *ival = SERGENSIO_DTR_OFF;
    }

    return 0;
}

static int
sterm_dtr(struct sergensio *sio, int dtr,
	  void (*done)(struct sergensio *sio, int err, int dtr,
		       void *cb_data),
	  void *cb_data)
{
    return termios_set_get(sergensio_get_gensio_data(sio), dtr, TERMIO_OP_MCTL,
			   termios_get_set_dtr, done, cb_data);
}

static int
termios_get_set_rts(struct termios *termio, int *mctl, int *ival)
{
    if (*ival) {
	if (*ival == SERGENSIO_RTS_ON)
	    *mctl |= TIOCM_RTS;
	else if (*ival == SERGENSIO_RTS_OFF)
	    *mctl &= ~TIOCM_RTS;
	else
	    return EINVAL;
    } else {
	if (*mctl & TIOCM_RTS)
	    *ival = SERGENSIO_RTS_ON;
	else
	    *ival = SERGENSIO_RTS_OFF;
    }

    return 0;
}

static int
sterm_rts(struct sergensio *sio, int rts,
	  void (*done)(struct sergensio *sio, int err, int rts,
		       void *cb_data),
	  void *cb_data)
{
    return termios_set_get(sergensio_get_gensio_data(sio), rts, TERMIO_OP_MCTL,
			   termios_get_set_rts, done, cb_data);
}

static void
termios_timeout(struct gensio_timer *t, void *cb_data)
{
    struct sterm_data *sdata = cb_data;
    int val;
    unsigned int modemstate = 0;
    bool force_send;

    sterm_lock(sdata);
    if (sdata->handling_modemstate) {
	sterm_unlock(sdata);
	return;
    }
    sdata->handling_modemstate = true;
    sterm_unlock(sdata);

    if (ioctl(sdata->fd, TIOCMGET, &val) != 0)
	return;

    if (val & TIOCM_CD)
	modemstate |= 0x80;
    if (val & TIOCM_RI)
	modemstate |= 0x40;
    if (val & TIOCM_DSR)
	modemstate |= 0x20;
    if (val & TIOCM_CTS)
	modemstate |= 0x10;

    sterm_lock(sdata);
    /* Bits for things that changed. */
    modemstate |= (modemstate ^ sdata->last_modemstate) >> 4;
    sdata->last_modemstate = modemstate & sdata->modemstate_mask;
    modemstate &= sdata->last_modemstate;
    force_send = !sdata->sent_first_modemstate;
    sdata->sent_first_modemstate = true;
    sterm_unlock(sdata);

    /*
     * The bottom 4 buts of modemstate is the "changed" bits, only
     * report this if someing changed that was in the mask.
     */
    if ((force_send || modemstate & 0xf)) {
	struct gensio *io = sergensio_to_gensio(sdata->sio);
	unsigned int vlen = sizeof(modemstate);

	gensio_cb(io, GENSIO_EVENT_SER_MODEMSTATE, 0,
		  (unsigned char *) &modemstate, &vlen, NULL);
    }

    if (sdata->modemstate_mask) {
	struct timeval timeout = {1, 0};

	sdata->o->start_timer(sdata->timer, &timeout);
    }

    sterm_lock(sdata);
    sdata->handling_modemstate = false;
    sterm_unlock(sdata);
}

static int
sterm_modemstate(struct sergensio *sio, unsigned int val)
{
    struct sterm_data *sdata = sergensio_get_gensio_data(sio);

    sterm_lock(sdata);
    sdata->modemstate_mask = val;
    sterm_unlock(sdata);
    if (sdata->modemstate_mask) {
	struct timeval timeout = {0, 1};

	sdata->o->start_timer(sdata->timer, &timeout);
    } else {
	sdata->o->stop_timer(sdata->timer);
    }
    return 0;
}

static int
sterm_flowcontrol_state(struct sergensio *sio, bool val)
{
    struct sterm_data *sdata = sergensio_get_gensio_data(sio);
    int err;
    int tval;

    if (val)
	tval = TCOOFF;
    else
	tval = TCOON;

    err = tcflow(sdata->fd, tval);
    if (err)
	return errno;
    return 0;
}

static int
sterm_flush(struct sergensio *sio, unsigned int val)
{
    struct sterm_data *sdata = sergensio_get_gensio_data(sio);
    int err;
    int tval;

    switch(val) {
    case SERGIO_FLUSH_RCV_BUFFER:	tval = TCIFLUSH; break;
    case SERGIO_FLUSH_XMIT_BUFFER:	tval = TCOFLUSH; break;
    case SERGIO_FLUSH_RCV_XMIT_BUFFERS:	tval = TCIOFLUSH; break;
    default: return EINVAL;
    }

    err = tcflush(sdata->fd, tval);
    if (err)
	return errno;
    return 0;
}

static int
sterm_send_break(struct sergensio *sio)
{
    struct sterm_data *sdata = sergensio_get_gensio_data(sio);

    tcsendbreak(sdata->fd, 0);
    return 0;
}

static int
sergensio_sterm_func(struct sergensio *sio, int op, int val, char *buf,
		     void *done, void *cb_data)
{
    struct sterm_data *sdata = sergensio_get_gensio_data(sio);

    if (sdata->write_only)
	return ENOTSUP;

    switch (op) {
    case SERGENSIO_FUNC_BAUD:
	return sterm_baud(sio, val, done, cb_data);

    case SERGENSIO_FUNC_DATASIZE:
	return sterm_datasize(sio, val, done, cb_data);

    case SERGENSIO_FUNC_PARITY:
	return sterm_parity(sio, val, done, cb_data);

    case SERGENSIO_FUNC_STOPBITS:
	return sterm_stopbits(sio, val, done, cb_data);

    case SERGENSIO_FUNC_FLOWCONTROL:
	return sterm_flowcontrol(sio, val, done, cb_data);

    case SERGENSIO_FUNC_IFLOWCONTROL:
	return sterm_iflowcontrol(sio, val, done, cb_data);

    case SERGENSIO_FUNC_SBREAK:
	return sterm_sbreak(sio, val, done, cb_data);

    case SERGENSIO_FUNC_DTR:
	return sterm_dtr(sio, val, done, cb_data);

    case SERGENSIO_FUNC_RTS:
	return sterm_rts(sio, val, done, cb_data);

    case SERGENSIO_FUNC_MODEMSTATE:
	return sterm_modemstate(sio, val);

    case SERGENSIO_FUNC_FLOWCONTROL_STATE:
	return sterm_flowcontrol_state(sio, val);

    case SERGENSIO_FUNC_FLUSH:
	return sterm_flush(sio, val);

    case SERGENSIO_FUNC_SEND_BREAK:
	return sterm_send_break(sio);

    case SERGENSIO_FUNC_SIGNATURE:
    case SERGENSIO_FUNC_LINESTATE:
    default:
	return ENOTSUP;
    }
}

static void
sterm_timer_stopped(struct gensio_timer *timer, void *cb_data)
{
    struct sterm_data *sdata = cb_data;

    sdata->timer_stopped = true;
}

static int
sterm_check_close_drain(void *handler_data, enum gensio_ll_close_state state,
			struct timeval *next_timeout)
{
    struct sterm_data *sdata = handler_data;
    int rv, count = 0, err = 0;

    sterm_lock(sdata);
    if (state == GENSIO_LL_CLOSE_STATE_START) {
	sdata->open = false;
	/* FIXME - this should be calculated. */
	sdata->close_timeouts_left = 200;
	rv = sdata->o->stop_timer_with_done(sdata->timer,
					    sterm_timer_stopped, sdata);
	if (rv)
	    sdata->timer_stopped = true;
    }

    if (state != GENSIO_LL_CLOSE_STATE_DONE)
	goto out_unlock;

    sdata->open = false;
    if (sdata->termio_q)
	goto out_eagain;

    if (!sdata->timer_stopped)
	goto out_eagain;

    rv = ioctl(sdata->fd, TIOCOUTQ, &count);
    if (rv || count == 0)
	goto out_rm_uucp;

    sdata->close_timeouts_left--;
    if (sdata->close_timeouts_left == 0)
	goto out_rm_uucp;

 out_eagain:
    err = EAGAIN;
    next_timeout->tv_sec = 0;
    next_timeout->tv_usec = 10000;
 out_rm_uucp:
    if (!err)
	uucp_rm_lock(sdata->devname);
 out_unlock:
    sterm_unlock(sdata);
    return err;
}

#ifdef __CYGWIN__
static void cfmakeraw(struct termios *termios_p) {
    termios_p->c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON);
    termios_p->c_oflag &= ~OPOST;
    termios_p->c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN);
    termios_p->c_cflag &= ~(CSIZE|PARENB);
    termios_p->c_cflag |= CS8;
}
#endif

static int
sterm_sub_open(void *handler_data,
	       int (**check_open)(void *handler_data, int fd),
	       int (**retry_open)(void *handler_data, int *fd),
	       int *fd)
{
    struct sterm_data *sdata = handler_data;
    int err;
    int options;

    err = uucp_mk_lock(sdata->devname);
    if (err > 0) {
	err = EBUSY;
	goto out;
    }
    if (err < 0) {
	err = errno;
	goto out;
    }

    sdata->timer_stopped = false;

    options = O_NONBLOCK | O_NOCTTY;
    if (sdata->write_only)
	options |= O_WRONLY;
    else
	options |= O_RDWR;
    sdata->fd = open(sdata->devname, options);
    if (sdata->fd == -1) {
	err = errno;
	goto out_uucp;
    }

    if (!sdata->write_only &&
		tcsetattr(sdata->fd, TCSANOW, &sdata->default_termios) == -1) {
	err = errno;
	goto out_uucp;
    }

    if (!sdata->write_only && !sdata->disablebreak)
	ioctl(sdata->fd, TIOCCBRK);

#if HAVE_DECL_TIOCSRS485
    if (sdata->rs485.flags & SER_RS485_ENABLED) {
	if (ioctl(sdata->fd, TIOCSRS485, &sdata->rs485) < 0) {
	    err = errno;
	    goto out_uucp;
	}
    }
#endif

    sterm_lock(sdata);
    sdata->open = true;
    sdata->sent_first_modemstate = false;
    sterm_unlock(sdata);

    if (!sdata->write_only)
	sterm_modemstate(sdata->sio, 255);

    *fd = sdata->fd;

    return 0;

 out_uucp:
    uucp_rm_lock(sdata->devname);
 out:
    if (sdata->fd != -1) {
	close(sdata->fd);
	sdata->fd = -1;
    }
    return err;
}

static int
sterm_raddr_to_str(void *handler_data, unsigned int *epos,
		   char *buf, unsigned int buflen)
{
    struct sterm_data *sdata = handler_data;
    int pos = 0;

    if (epos)
	pos = *epos;

    pos += snprintf(buf + pos, buflen - pos, "%s", sdata->devname);

    if (!sdata->write_only) {
	struct termios itermio, *termio;
	speed_t speed;
	int stopbits;
	int databits;
	int parity_enabled;
	int parity;
	int xon;
	int xoff;
	int xany;
	int flow_rtscts;
	int clocal;
	int hangup_when_done;
	char str[4];

	if (sdata->fd == -1) {
	    termio = &sdata->default_termios;
	} else {
	    if (tcgetattr(sdata->fd, &itermio) == -1)
		goto out;
	    termio = &itermio;
	}

	speed = cfgetospeed(termio);
	stopbits = termio->c_cflag & CSTOPB;
	databits = termio->c_cflag & CSIZE;
	parity_enabled = termio->c_cflag & PARENB;
	parity = termio->c_cflag & PARODD;
	xon = termio->c_iflag & IXON;
	xoff = termio->c_iflag & IXOFF;
	xany = termio->c_iflag & IXANY;
	flow_rtscts = termio->c_cflag & CRTSCTS;
	clocal = termio->c_cflag & CLOCAL;
	hangup_when_done = termio->c_cflag & HUPCL;

	if (parity_enabled && parity)
	    str[0] = 'O';
	else if (parity_enabled)
	    str[0] = 'E';
	else
	    str[0] = 'N';

	switch (databits) {
	case CS5: str[1] = '5'; break;
	case CS6: str[1] = '6'; break;
	case CS7: str[1] = '7'; break;
	case CS8: str[1] = '8'; break;
	default: str[1] = '?';
	}

	if (stopbits)
	    str[2] = '2';
	else
	    str[2] = '1';

	str[3] = '\0';

	pos += snprintf(buf + pos, buflen - pos,
			",%s%s", get_baud_rate_str(speed), str);

	if (xon && xoff && xany)
	    pos += snprintf(buf + pos, buflen - pos, ",%s", "XONXOFF");

	if (flow_rtscts)
	    pos += snprintf(buf + pos, buflen - pos, ",%s", "RTSCTS");

	if (clocal)
	    pos += snprintf(buf + pos, buflen - pos, ",%s", "CLOCAL");

	if (hangup_when_done)
	    pos += snprintf(buf + pos, buflen - pos, ",%s", "HANGUP_WHEN_DONE");

    }
    if (!sdata->write_only && sdata->fd != -1) {
	int status = 0;

	ioctl(sdata->fd, TIOCMGET, &status);

	if (status & TIOCM_RTS)
	    pos += snprintf(buf + pos, buflen - pos, " %s", "RTSHI");
	else
	    pos += snprintf(buf + pos, buflen - pos, " %s", "RTSLO");

	if (status & TIOCM_DTR)
	    pos += snprintf(buf + pos, buflen - pos, " %s", "DTRHI");
	else
	    pos += snprintf(buf + pos, buflen - pos, " %s", "DTRLO");
    } else {
	pos += snprintf(buf + pos, buflen - pos, " %s", "offline");
    }

 out:
    if (epos)
	*epos = pos;

    return 0;
}

static int
sterm_remote_id(void *handler_data, int *id)
{
    struct sterm_data *sdata = handler_data;

    *id = sdata->fd;
    return 0;
}

static void
sterm_free(void *handler_data)
{
    struct sterm_data *sdata = handler_data;

    if (sdata->lock)
	sdata->o->free_lock(sdata->lock);
    if (sdata->timer)
	sdata->o->free_timer(sdata->timer);
    if (sdata->devname)
	sdata->o->free(sdata->o, sdata->devname);
    if (sdata->deferred_op_runner)
	sdata->o->free_runner(sdata->deferred_op_runner);
    sdata->o->free(sdata->o, sdata);
}

static const struct gensio_fd_ll_ops sterm_fd_ll_ops = {
    .sub_open = sterm_sub_open,
    .raddr_to_str = sterm_raddr_to_str,
    .remote_id = sterm_remote_id,
    .check_close = sterm_check_close_drain,
    .free = sterm_free
};


static int
process_termios_parm(struct termios *termio, char *parm)
{
    int rv = 0, val;
    const char *rest = "";

    if ((val = speedstr_to_speed(parm, &rest)) != -1) {
	if (set_termios_from_speed(termio, val, rest) == -1)
	    rv = EINVAL;
    } else if (strcmp(parm, "1STOPBIT") == 0) {
	termio->c_cflag &= ~(CSTOPB);
    } else if (strcmp(parm, "2STOPBITS") == 0) {
	termio->c_cflag |= CSTOPB;
    } else if (strcmp(parm, "5DATABITS") == 0) {
	set_termios_datasize(termio, 5);
    } else if (strcmp(parm, "6DATABITS") == 0) {
	set_termios_datasize(termio, 6);
    } else if (strcmp(parm, "7DATABITS") == 0) {
	set_termios_datasize(termio, 7);
    } else if (strcmp(parm, "8DATABITS") == 0) {
	set_termios_datasize(termio, 8);
    } else if ((val = lookup_parity_str(parm)) != -1) {
	set_termios_parity(termio, val);
    } else if (strcmp(parm, "XONXOFF") == 0) {
	set_termios_xonxoff(termio, 1);
    } else if (strcmp(parm, "-XONXOFF") == 0) {
	set_termios_xonxoff(termio, 0);
    } else if (strcmp(parm, "RTSCTS") == 0) {
	set_termios_rtscts(termio, 1);
    } else if (strcmp(parm, "-RTSCTS") == 0) {
	set_termios_rtscts(termio, 0);
    } else if (strcmp(parm, "LOCAL") == 0) {
	termio->c_cflag |= CLOCAL;
    } else if (strcmp(parm, "-LOCAL") == 0) {
	termio->c_cflag &= ~CLOCAL;
    } else if (strcmp(parm, "HANGUP_WHEN_DONE") == 0) {
	termio->c_cflag |= HUPCL;
    } else if (strcmp(parm, "-HANGUP_WHEN_DONE") == 0) {
	termio->c_cflag &= ~HUPCL;
    } else {
	rv = ENOTSUP;
    }

    return rv;
}

static int
process_rs485(struct sterm_data *sdata, char *str)
{
#if HAVE_DECL_TIOCSRS485
    int argc, i;
    char **argv, *end;
    int err = str_to_argv(str, &argc, &argv, ":");

    if (err)
	return err;
    if (argc < 2)
	return EINVAL;

    sdata->rs485.delay_rts_before_send = strtoul(argv[0], &end, 10);
    if (end == argv[0] || *end != '\0')
	goto out_inval;

    sdata->rs485.delay_rts_after_send = strtoul(argv[1], &end, 10);
    if (end == argv[1] || *end != '\0')
	goto out_inval;

    for (i = 2; i < argc; i++) {
	if (strcmp(argv[i], "rts_on_send") == 0) {
	    sdata->rs485.flags |= SER_RS485_RTS_ON_SEND;
	} else if (strcmp(argv[i], "rts_after_send") == 0) {
	    sdata->rs485.flags |= SER_RS485_RTS_AFTER_SEND;
	} else if (strcmp(argv[i], "rx_during_tx") == 0) {
	    sdata->rs485.flags |= SER_RS485_RX_DURING_TX;
#ifdef SER_RS485_TERMINATE_BUS
	} else if (strcmp(argv[i], "terminate_bus") == 0) {
	    sdata->rs485.flags |= SER_RS485_TERMINATE_BUS;
#endif
	} else {
	    goto out_inval;
	}
    }

    sdata->rs485.flags |= SER_RS485_ENABLED;

 out:
    str_to_argv_free(argc, argv);
    return err;

 out_inval:
    err = EINVAL;
    goto out;
#else
    return ENOTSUP;
#endif
}

static int
sergensio_process_parms(struct sterm_data *sdata)
{
    int argc, i;
    char **argv;
    int err = str_to_argv(sdata->parms, &argc, &argv, " \f\t\n\r\v,");

    if (err)
	return err;

    for (i = 0; i < argc; i++) {
	if (strcmp(argv[i], "WRONLY") == 0) {
	    sdata->write_only = true;
	    continue;
	} else if (strcmp(argv[i], "NOBREAK") == 0) {
	    sdata->disablebreak = true;
	    continue;
	} else if (strcmp(argv[i], "-NOBREAK") == 0) {
	    sdata->disablebreak = false;
	    continue;
	} else if (strncmp(argv[i], "rs485=", 6) == 0) {
	    err = process_rs485(sdata, argv[i] + 6);
	    if (err)
		break;
	    continue;
	}
	err = process_termios_parm(&sdata->default_termios, argv[i]);
	if (err)
	    break;
    }

    str_to_argv_free(argc, argv);
    return err;
}

static void
sergensio_setup_defaults(struct gensio_os_funcs *o, struct sterm_data *sdata)
{
    int val;
    struct termios *termctl = &sdata->default_termios;

    cfmakeraw(termctl);

    val = 9600;
    gensio_get_default(o, "termios", "speed", false,
		       GENSIO_DEFAULT_INT, NULL, &val);
    if (!get_baud_rate(val, &val))
	val = B9600;
    cfsetospeed(termctl, val);
    cfsetispeed(termctl, val);

    val = 'N';
    gensio_get_default(o, "termios", "parity", false,
		       GENSIO_DEFAULT_INT, NULL, &val);
    set_termios_parity(termctl, val);

    val = 8;
    gensio_get_default(o, "termios", "databits", false,
		       GENSIO_DEFAULT_INT, NULL, &val);
    set_termios_datasize(termctl, val);

    val = 1;
    gensio_get_default(o, "termios", "stopbits", false,
		       GENSIO_DEFAULT_INT, NULL, &val);
    if (val == 2)
	termctl->c_cflag |= CSTOPB;
    else
	termctl->c_cflag &= ~(CSTOPB);

    sdata->default_termios.c_cflag |= CREAD;
    sdata->default_termios.c_cc[VSTART] = 17;
    sdata->default_termios.c_cc[VSTOP] = 19;
    sdata->default_termios.c_iflag |= IGNBRK;

    val = 0;
    gensio_get_default(o, "termios", "xonxoff", false,
		       GENSIO_DEFAULT_BOOL, NULL, &val);
    set_termios_xonxoff(termctl, val);

    val = 0;
    gensio_get_default(o, "termios", "rtscts", false,
		       GENSIO_DEFAULT_BOOL, NULL, &val);
    set_termios_rtscts(termctl, val);

    val = 0;
    gensio_get_default(o, "termios", "local", false,
		       GENSIO_DEFAULT_BOOL, NULL, &val);
    if (val)
	termctl->c_cflag |= CLOCAL;

    val = 0;
    gensio_get_default(o, "termios", "hangup_when_done", false,
		       GENSIO_DEFAULT_BOOL, NULL, &val);
    if (val)
	termctl->c_cflag |= HUPCL;
}

int
termios_gensio_alloc(const char *devname, char *args[],
		     struct gensio_os_funcs *o,
		     gensio_event cb, void *user_data,
		     struct gensio **rio)
{
    struct sterm_data *sdata = o->zalloc(o, sizeof(*sdata));
    struct gensio_ll *ll;
    struct gensio *io;
    int err;
    char *comma;
    unsigned int max_read_size = GENSIO_DEFAULT_BUF_SIZE;
    int i;

    if (!sdata)
	return ENOMEM;

    for (i = 0; args[i]; i++) {
	if (gensio_check_keyuint(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	return EINVAL;
    }

    sdata->o = o;

    sdata->timer = o->alloc_timer(o, termios_timeout, sdata);
    if (!sdata->timer)
	goto out_nomem;

    sdata->fd = -1;

    sergensio_setup_defaults(o, sdata);

    sdata->devname = gensio_strdup(o, devname);
    if (!sdata->devname)
	goto out_nomem;

    comma = strchr(sdata->devname, ',');
    if (comma) {
	*comma++ = '\0';
	sdata->parms = comma;
	err = sergensio_process_parms(sdata);
	if (err)
	    goto out_err;
    }

    sdata->deferred_op_runner = o->alloc_runner(o, sterm_deferred_op, sdata);
    if (!sdata->deferred_op_runner)
	goto out_nomem;

    sdata->lock = o->alloc_lock(o);
    if (!sdata->lock)
	goto out_nomem;

    ll = fd_gensio_ll_alloc(o, -1, &sterm_fd_ll_ops, sdata, max_read_size);
    if (!ll)
	goto out_nomem;

    /*
     * After this point, freeing the ll or io will free sdata through
     * the free callbacks.
     */

    io = base_gensio_alloc(o, ll, NULL, "termios", cb, user_data);
    if (!io) {
	gensio_ll_free(ll);
	return ENOMEM;
    }

    sdata->sio = sergensio_data_alloc(o, io, sergensio_sterm_func, sdata);
    if (!sdata->sio) {
	gensio_free(io);
	return ENOMEM;
    }

    err = gensio_addclass(io, "sergensio", sdata->sio);
    if (err) {
	gensio_free(io);
	return err;
    }

    *rio = io;
    return 0;

 out_nomem:
    err = ENOMEM;
 out_err:
    sterm_free(sdata);
    return err;
}

int
str_to_termios_gensio(const char *str, char *args[],
		      struct gensio_os_funcs *o,
		      gensio_event cb, void *user_data,
		      struct gensio **new_gensio)
{
    return termios_gensio_alloc(str, args, o, cb, user_data, new_gensio);
}
