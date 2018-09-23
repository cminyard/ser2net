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
#include <sys/ioctl.h>

#include <utils/utils.h>
#include <utils/uucplock.h>

#include <gensio/sergensio_internal.h>
#include <gensio/gensio_base.h>

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
    struct sergensio sio;
    struct gensio_os_funcs *o;

    struct gensio_lock *lock;

    struct gensio_timer *timer;
    bool timer_stopped;

    bool open;
    unsigned int close_timeouts_left;

    char *devname;
    char *parms;

    int fd;

    struct termios default_termios;

    bool deferred_op_pending;
    struct gensio_runner *deferred_op_runner;
    struct termio_op_q *termio_q;
    bool break_set;
    unsigned int last_modemstate;
    unsigned int modemstate_mask;
    bool handling_modemstate;
    bool sent_first_modemstate;
};

static void termios_process(struct sterm_data *sdata);

#define mysergensio_to_sterm(v) container_of(v, struct sterm_data, sio)

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
	qe->done(&sdata->sio, err, val, qe->cb_data);
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
    return termios_set_get(mysergensio_to_sterm(sio), baud, TERMIO_OP_TERMIO,
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
    return termios_set_get(mysergensio_to_sterm(sio), datasize,
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
    return termios_set_get(mysergensio_to_sterm(sio), parity, TERMIO_OP_TERMIO,
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
    return termios_set_get(mysergensio_to_sterm(sio), stopbits,
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
    return termios_set_get(mysergensio_to_sterm(sio), flowcontrol,
			   TERMIO_OP_TERMIO,
			   termios_get_set_flowcontrol, done, cb_data);
}

static int
sterm_iflowcontrol(struct sergensio *sio, int iflowcontrol,
		   void (*done)(struct sergensio *sio, int err,
				int iflowcontrol, void *cb_data),
		   void *cb_data)
{
    return termios_set_get(mysergensio_to_sterm(sio), iflowcontrol,
			   TERMIO_OP_TERMIO,
			   termios_get_set_iflowcontrol, done, cb_data);
}

static int
sterm_sbreak(struct sergensio *sio, int breakv,
	     void (*done)(struct sergensio *sio, int err, int breakv,
			  void *cb_data),
	     void *cb_data)
{
    return termios_set_get(mysergensio_to_sterm(sio), breakv, TERMIO_OP_BRK,
			   NULL, done, cb_data);
}

static int
termios_get_set_dtr(struct termios *termio, int *mctl, int *ival)
{
    if (*ival) {
	if (*ival == SERGENSIO_DTR_ON)
	    *mctl |= TIOCM_DTR;
	else if (*ival == SERGENSIO_DTR_OFF)
	    *mctl &= TIOCM_DTR;
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
    return termios_set_get(mysergensio_to_sterm(sio), dtr, TERMIO_OP_MCTL,
			   termios_get_set_dtr, done, cb_data);
}

static int
termios_get_set_rts(struct termios *termio, int *mctl, int *ival)
{
    if (*ival) {
	if (*ival == SERGENSIO_RTS_ON)
	    *mctl |= TIOCM_RTS;
	else if (*ival == SERGENSIO_RTS_OFF)
	    *mctl &= TIOCM_RTS;
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
    return termios_set_get(mysergensio_to_sterm(sio), rts, TERMIO_OP_MCTL,
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
	struct gensio *io = sergensio_to_gensio(&sdata->sio);
	unsigned int vlen = sizeof(modemstate);

	io->cb(io, GENSIO_EVENT_SER_MODEMSTATE, 0,
	       (unsigned char *) &modemstate, &vlen, 0, NULL);
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
    struct sterm_data *sdata = mysergensio_to_sterm(sio);

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
    struct sterm_data *sdata = mysergensio_to_sterm(sio);
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
    struct sterm_data *sdata = mysergensio_to_sterm(sio);
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

static const struct sergensio_functions sterm_funcs = {
    .baud = sterm_baud,
    .datasize = sterm_datasize,
    .parity = sterm_parity,
    .stopbits = sterm_stopbits,
    .flowcontrol = sterm_flowcontrol,
    .iflowcontrol = sterm_iflowcontrol,
    .sbreak = sterm_sbreak,
    .dtr = sterm_dtr,
    .rts = sterm_rts,
    .modemstate = sterm_modemstate,
    .flowcontrol_state = sterm_flowcontrol_state,
    .flush = sterm_flush
};

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

    sdata->fd = open(sdata->devname, O_NONBLOCK | O_NOCTTY | O_RDWR);
    if (sdata->fd == -1) {
	err = errno;
	goto out_uucp;
    }

    if (tcsetattr(sdata->fd, TCSANOW, &sdata->default_termios) == -1) {
	err = errno;
	goto out_uucp;
    }

    ioctl(sdata->fd, TIOCCBRK);

    sterm_lock(sdata);
    sdata->open = true;
    sdata->sent_first_modemstate = false;
    sterm_unlock(sdata);

    sterm_modemstate(&sdata->sio, 255);

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
sterm_raddr_to_str(void *handler_data, int *epos,
		   char *buf, unsigned int buflen)
{
    struct sterm_data *sdata = handler_data;

    int pos = 0;

    if (epos)
	pos = *epos;

    pos += snprintf(buf + pos, buflen - pos, "termios,%s", sdata->devname);

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
    if (sdata->sio.io)
	sdata->o->free(sdata->o, sdata->sio.io);
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
sergensio_process_parms(struct sterm_data *sdata)
{
    int argc, i;
    char **argv;
    int err = str_to_argv(sdata->parms, &argc, &argv, " \f\t\n\r\v,");

    if (err)
	return err;

    for (i = 0; i < argc; i++) {
	err = process_termios_parm(&sdata->default_termios, argv[i]);
	if (err)
	    break;
    }

    str_to_argv_free(argc, argv);
    return err;
}

int
termios_gensio_alloc(const char *devname, char *args[],
		     struct gensio_os_funcs *o,
		     gensio_event cb, void *user_data,
		     struct gensio **io)
{
    struct sterm_data *sdata = o->zalloc(o, sizeof(*sdata));
    struct gensio_ll *ll;
    int err;
    char *comma;
    unsigned int max_read_size = GENSIO_DEFAULT_BUF_SIZE;
    int i;

    for (i = 0; args[i]; i++) {
	if (gensio_check_keyuint(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	return EINVAL;
    }

    if (!sdata)
	return ENOMEM;

    sdata->o = o;

    sdata->timer = o->alloc_timer(o, termios_timeout, sdata);
    if (!sdata->timer)
	goto out_nomem;

    sdata->fd = -1;

    cfmakeraw(&sdata->default_termios);
    cfsetispeed(&sdata->default_termios, B9600);
    cfsetospeed(&sdata->default_termios, B9600);
    sdata->default_termios.c_cflag |= CREAD | CS8;
    sdata->default_termios.c_cc[VSTART] = 17;
    sdata->default_termios.c_cc[VSTOP] = 19;
    sdata->default_termios.c_iflag |= IGNBRK;

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

    sdata->sio.io = base_gensio_alloc(o, ll, NULL, GENSIO_TYPE_SER_TERMIOS,
				      false, false, cb, user_data);
    if (!sdata->sio.io) {
	ll->ops->free(ll);
	goto out_nomem;
    }

    sdata->sio.io->parent_object = &sdata->sio;
    sdata->sio.funcs = &sterm_funcs;

    *io = sdata->sio.io;
    return 0;

 out_nomem:
    err = ENOMEM;
 out_err:
    sterm_free(sdata);
    return err;
}
