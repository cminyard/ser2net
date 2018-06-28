/*
 *  ser2net - A program for allowing telnet connection to serial ports
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

#include "utils/utils.h"
#include "utils/locking.h"
#include "utils/uucplock.h"

#include "sergenio_internal.h"

enum termio_op {
    TERMIO_OP_TERMIO,
    TERMIO_OP_MCTL,
    TERMIO_OP_BRK
};

struct termio_op_q {
    enum termio_op op;
    int (*getset)(struct termios *termio, int *mctl, int *val);
    void (*done)(struct sergenio *snet, int err, int val, void *cb_data);
    void *cb_data;
    struct termio_op_q *next;
};

struct sterm_data {
    struct sergenio snet;

    struct selector_s *sel;

    char *devname;
    char *parms;

    DEFINE_LOCK(, lock);

    int fd;

    struct termios default_termios;

    void (*close_done)(struct genio *io);
    bool closed;
    bool in_close;
    bool in_free;

    bool read_enabled;
    bool in_read;
    bool deferred_read;
    unsigned int read_buffer_size;
    unsigned char *read_data;
    unsigned int data_pending_len;
    unsigned int data_pos;

    /*
     * Used to run read callbacks from the selector to avoid running
     * it directly from user calls.
     */
    bool deferred_op_pending;
    sel_runner_t *deferred_op_runner;

    struct termio_op_q *termio_q;
    bool break_set;
};

static void termios_process(struct sterm_data *sdata);

#define mygenio_to_sterm(v) container_of(v, struct sterm_data, snet.net)
#define mysergenio_to_sterm(v) container_of(v, struct sterm_data, snet)

static void
sterm_finish_free(struct sterm_data *sdata)
{
    if (sdata->deferred_op_runner)
	sel_free_runner(sdata->deferred_op_runner);
    if (sdata->read_data)
	free(sdata->read_data);
    if (sdata->devname)
	free(sdata->devname);
    free(sdata);
}

static void
sterm_finish_close(struct sterm_data *sdata)
{
    struct termios termio;

    /* Disable flow control to avoid a long shutdown. */
    if (tcgetattr(sdata->fd, &termio) != -1) {
	termio.c_iflag &= ~(IXON | IXOFF);
	termio.c_cflag &= ~CRTSCTS;
	tcsetattr(sdata->fd, TCSANOW, &termio);
    }
    tcflush(sdata->fd, TCOFLUSH);
    close(sdata->fd);
    sdata->fd = -1;
    uucp_rm_lock(sdata->devname);
    if (sdata->close_done)
	sdata->close_done(&sdata->snet.net);
    if (sdata->in_free)
	sterm_finish_free(sdata);
}

/* Must be called with sdata->lock held */
static void
sterm_finish_read(struct sterm_data *sdata, int err, unsigned int count)
{
    if (err < 0) {
	sdata->read_enabled = false;
    } else if (count < sdata->data_pending_len) {
	/* If the user doesn't consume all the data, disable
	   automatically. */
	sdata->data_pending_len -= count;
	sdata->data_pos += count;
	sdata->read_enabled = false;
    } else {
	sdata->data_pending_len = 0;
    }

    sdata->in_read = false;

    if (sdata->read_enabled)
	sel_set_fd_read_handler(sdata->sel, sdata->fd,
				SEL_FD_HANDLER_ENABLED);
}

static void
sterm_deferred_op(sel_runner_t *runner, void *cbdata)
{
    struct sterm_data *sdata = cbdata;
    struct genio *net = &sdata->snet.net;
    unsigned int count;
    bool in_read;

    LOCK(sdata->lock);
 restart:
    if (sdata->deferred_read) {
	in_read = sdata->in_read;
	sdata->deferred_read = false;
    }

    if (in_read) {
	UNLOCK(sdata->lock);
	count = net->cbs->read_callback(net, 0,
					sdata->read_data + sdata->data_pos,
					sdata->data_pending_len, 0);
	LOCK(sdata->lock);
	sterm_finish_read(sdata, 0, count);
    }

    termios_process(sdata);

    if (sdata->deferred_read || sdata->termio_q)
	/* Something was added, process it. */
	goto restart;

    sdata->deferred_op_pending = false;

    if (sdata->in_close) {
	UNLOCK(sdata->lock);
	sterm_finish_close(sdata);
	return;
    }
    UNLOCK(sdata->lock);
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
	    val = sdata->break_set;
	}

	UNLOCK(sdata->lock);
	qe->done(&sdata->snet, err, val, qe->cb_data);
	free(qe);
	LOCK(sdata->lock);
    }
}

static int
termios_set_get(struct sterm_data *sdata, int val, enum termio_op op,
		int (*getset)(struct termios *termio, int *mctl, int *val),
		void (*done)(struct sergenio *snet, int err,
			     int val, void *cb_data),
		void *cb_data)
{
    struct termios termio;
    struct termio_op_q *qe = NULL;
    int err = 0;

    if (done) {
	qe = malloc(sizeof(*qe));
	if (!qe)
	    return ENOMEM;
	qe->getset = getset;
	qe->done = done;
	qe->cb_data = cb_data;
	qe->op = op;
	qe->next = NULL;
    }

    LOCK(sdata->lock);
    if (val) {
	if (op == TERMIO_OP_TERMIO) {
	    if (tcgetattr(sdata->fd, &termio) == -1) {
		if (qe)
		    free(qe);
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

	    if (val == SERGENIO_BREAK_ON) {
		iocval = TIOCSBRK;
		bval = true;
	    } else if (val == SERGENIO_BREAK_OFF) {
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
	    if (!sdata->deferred_op_pending) {
		sdata->deferred_op_pending = true;
		sel_run(sdata->deferred_op_runner, sterm_deferred_op, sdata);
	    }
	} else {
	    struct termio_op_q *curr = sdata->termio_q;

	    while (curr->next)
		curr = curr->next;
	    curr->next = qe;
	}
    }
 out_unlock:
    if (err && qe)
	free(qe);
    UNLOCK(sdata->lock);
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
sterm_baud(struct sergenio *snet, int baud,
	   void (*done)(struct sergenio *snet, int err,
			int baud, void *cb_data),
	   void *cb_data)
{
    return termios_set_get(mysergenio_to_sterm(snet), baud, TERMIO_OP_TERMIO,
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
sterm_datasize(struct sergenio *snet, int datasize,
	       void (*done)(struct sergenio *snet, int err, int datasize,
			    void *cb_data),
	       void *cb_data)
{
    return termios_set_get(mysergenio_to_sterm(snet), datasize,
			   TERMIO_OP_TERMIO,
			   termios_get_set_datasize, done, cb_data);
}

static int
termios_get_set_parity(struct termios *termio, int *mctl, int *ival)
{
    if (*ival) {
	int val;

	switch(*ival) {
	case SERGENIO_PARITY_NONE: val = 0; break;
	case SERGENIO_PARITY_ODD: val = PARENB | PARODD; break;
	case SERGENIO_PARITY_EVEN: val = PARENB; break;
#ifdef CMSPAR
	case SERGENIO_PARITY_MARK: val = PARENB | PARODD | CMSPAR; break;
	case SERGENIO_PARITY_SPACE: val = PARENB | CMSPAR; break;
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
	    *ival = SERGENIO_PARITY_NONE;
	} else if (termio->c_cflag & PARODD) {
#ifdef CMSPAR
	    if (termio->c_cflag & CMSPAR)
		*ival = SERGENIO_PARITY_MARK;
	    else
#endif
		*ival = SERGENIO_PARITY_ODD;
	} else {
#ifdef CMSPAR
	    if (termio->c_cflag & CMSPAR)
		*ival = SERGENIO_PARITY_SPACE;
	    else
#endif
		*ival = SERGENIO_PARITY_EVEN;
	}
    }

    return 0;
}

static int
sterm_parity(struct sergenio *snet, int parity,
	     void (*done)(struct sergenio *snet, int err, int parity,
			  void *cb_data),
	     void *cb_data)
{
    return termios_set_get(mysergenio_to_sterm(snet), parity, TERMIO_OP_TERMIO,
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
sterm_stopbits(struct sergenio *snet, int stopbits,
	       void (*done)(struct sergenio *snet, int err, int stopbits,
			    void *cb_data),
	       void *cb_data)
{
    return termios_set_get(mysergenio_to_sterm(snet), stopbits,
			   TERMIO_OP_TERMIO,
			   termios_get_set_stopbits, done, cb_data);
}

static int
termios_get_set_flowcontrol(struct termios *termio, int *mctl, int *ival)
{
    if (*ival) {
	int val;

	switch (*ival) {
	case SERGENIO_FLOWCONTROL_NONE: val = 0; break;
	case SERGENIO_FLOWCONTROL_XON_XOFF: val = IXON | IXOFF; break;
	case SERGENIO_FLOWCONTROL_RTS_CTS: val = CRTSCTS; break;
	default:
	    return EINVAL;
	}
	termio->c_cflag &= ~(IXON | IXOFF | CRTSCTS);
	termio->c_cflag |= val;
    } else {
	if (termio->c_cflag & CRTSCTS)
	    *ival = SERGENIO_FLOWCONTROL_RTS_CTS;
	else if (termio->c_cflag & (IXON | IXOFF))
	    *ival = SERGENIO_FLOWCONTROL_XON_XOFF;
	else
	    *ival = SERGENIO_FLOWCONTROL_NONE;
    }

    return 0;
}

static int
sterm_flowcontrol(struct sergenio *snet, int flowcontrol,
		  void (*done)(struct sergenio *snet, int err,
			       int flowcontrol, void *cb_data),
		  void *cb_data)
{
    return termios_set_get(mysergenio_to_sterm(snet), flowcontrol,
			   TERMIO_OP_TERMIO,
			   termios_get_set_flowcontrol, done, cb_data);
}

static int
sterm_breakv(struct sergenio *snet, int breakv,
	     void (*done)(struct sergenio *snet, int err, int breakv,
			  void *cb_data),
	     void *cb_data)
{
    return termios_set_get(mysergenio_to_sterm(snet), breakv, TERMIO_OP_BRK,
			   NULL, done, cb_data);
}

static int
termios_get_set_dtr(struct termios *termio, int *mctl, int *ival)
{
    if (*ival) {
	if (*ival == SERGENIO_DTR_ON)
	    *mctl |= TIOCM_DTR;
	else if (*ival == SERGENIO_DTR_OFF)
	    *mctl &= TIOCM_DTR;
	else
	    return EINVAL;
    } else {
	if (*mctl & TIOCM_DTR)
	    *ival = SERGENIO_DTR_ON;
	else 
	    *ival = SERGENIO_DTR_OFF;
    }

    return 0;
}

static int
sterm_dtr(struct sergenio *snet, int dtr,
	  void (*done)(struct sergenio *snet, int err, int dtr,
		       void *cb_data),
	  void *cb_data)
{
    return termios_set_get(mysergenio_to_sterm(snet), dtr, TERMIO_OP_MCTL,
			   termios_get_set_dtr, done, cb_data);
}

static int
termios_get_set_rts(struct termios *termio, int *mctl, int *ival)
{
    if (*ival) {
	if (*ival == SERGENIO_RTS_ON)
	    *mctl |= TIOCM_RTS;
	else if (*ival == SERGENIO_RTS_OFF)
	    *mctl &= TIOCM_RTS;
	else
	    return EINVAL;
    } else {
	if (*mctl & TIOCM_RTS)
	    *ival = SERGENIO_RTS_ON;
	else 
	    *ival = SERGENIO_RTS_OFF;
    }

    return 0;
}

static int
sterm_rts(struct sergenio *snet, int rts,
	  void (*done)(struct sergenio *snet, int err, int rts,
		       void *cb_data),
	  void *cb_data)
{
    return termios_set_get(mysergenio_to_sterm(snet), rts, TERMIO_OP_MCTL,
			   termios_get_set_rts, done, cb_data);
}

static const struct sergenio_functions sterm_funcs = {
    .baud = sterm_baud,
    .datasize = sterm_datasize,
    .parity = sterm_parity,
    .stopbits = sterm_stopbits,
    .flowcontrol = sterm_flowcontrol,
    .breakv = sterm_breakv,
    .dtr = sterm_dtr,
    .rts = sterm_rts,
};

static int
sterm_write(struct genio *net, unsigned int *rcount,
	    const void *buf, unsigned int buflen)
{
    struct sterm_data *sdata = mygenio_to_sterm(net);
    int rv, err = 0;

 retry:
    rv = write(sdata->fd, buf, buflen);
    if (rv < 0) {
	if (errno == EINTR)
	    goto retry;
	if (errno == EWOULDBLOCK || errno == EAGAIN)
	    rv = 0; /* Handle like a it wrote zero bytes. */
	else
	    err = errno;
    } else if (rv == 0) {
	err = EPIPE;
    }

    if (!err && rcount)
	*rcount = rv;

    return err;
}

static int
sterm_raddr_to_str(struct genio *net, int *epos,
		  char *buf, unsigned int buflen)
{
    struct sterm_data *sdata = mygenio_to_sterm(net);

    int pos = 0;

    if (epos)
	pos = *epos;

    pos += snprintf(buf + pos, buflen - pos, "termios,%s", sdata->devname);

    if (epos)
	*epos = pos;

    return 0;
}

static void
devfd_fd_cleared(int fd, void *cb_data)
{
    struct sterm_data *sdata = cb_data;

    LOCK(sdata->lock);
    if (!sdata->termio_q) {
	UNLOCK(sdata->lock);
	sterm_finish_close(sdata);
    } else {
	UNLOCK(sdata->lock);
    }
}

static void
handle_read(int fd, void *cb_data)
{
    struct sterm_data *sdata = cb_data;
    struct genio *net = &sdata->snet.net;
    int rv;
    unsigned int count = 0;

    LOCK(sdata->lock);
    if (!sdata->read_enabled)
	goto out_unlock;
    sdata->read_enabled = false;
    sel_set_fd_read_handler(sdata->sel, sdata->fd, SEL_FD_HANDLER_DISABLED);
    sdata->in_read = true;
    sdata->data_pos = 0;
    UNLOCK(sdata->lock);

 retry:
    rv = read(fd, sdata->read_data, sdata->read_buffer_size);
    if (rv < 0) {
	if (errno == EINTR)
	    goto retry;
	if (errno == EAGAIN || errno == EWOULDBLOCK)
	    rv = 0; /* Pretend like nothing happened. */
	else
	    net->cbs->read_callback(net, errno, 0, 0, 0);
    } else if (rv == 0) {
	net->cbs->read_callback(net, EPIPE, 0, 0, 0);
	rv = -1;
    } else {
	sdata->data_pending_len = rv;
	count = net->cbs->read_callback(net, 0, sdata->read_data, rv, 0);
    }

    LOCK(sdata->lock);
    sterm_finish_read(sdata, rv, count);
 out_unlock:
    UNLOCK(sdata->lock);
}

static void
handle_write(int fd, void *cb_data)
{
    struct sterm_data *sdata = cb_data;
    struct genio *net = &sdata->snet.net;

    net->cbs->write_callback(net);
}

static int
sterm_open(struct genio *net)
{
    struct sterm_data *sdata = mygenio_to_sterm(net);
    int err;

    LOCK(sdata->lock);
    if (!sdata->closed || sdata->in_close) {
	err = EBUSY;
	goto out;
    }

    err = uucp_mk_lock(sdata->devname);
    if (err > 0) {
	err = EBUSY;
	goto out;
    }
    if (err < 0) {
	err = errno;
	goto out;
    }

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

    err = sel_set_fd_handlers(sdata->sel, sdata->fd, sdata,
			      handle_read, handle_write, NULL,
			      devfd_fd_cleared);
    if (err)
	goto out_uucp;
    UNLOCK(sdata->lock);

    return 0;

 out_uucp:
    uucp_rm_lock(sdata->devname);
 out:
    if (sdata->fd != -1) {
	close(sdata->fd);
	sdata->fd = -1;
    }
    UNLOCK(sdata->lock);

    return err;
}

static void
__sterm_close(struct sterm_data *sdata,
	      void (*close_done)(struct genio *net))
{
    sdata->closed = true;
    sdata->in_close = true;
    sdata->close_done = close_done;
    sel_clear_fd_handlers(sdata->sel, sdata->fd);
}

static int
sterm_close(struct genio *net, void (*close_done)(struct genio *net))
{
    struct sterm_data *sdata = mygenio_to_sterm(net);
    int err = 0;

    LOCK(sdata->lock);
    if (sdata->closed || sdata->in_close)
	err = EBUSY;
    else
	__sterm_close(sdata, close_done);
    UNLOCK(sdata->lock);

    return err;
}

static void
sterm_free(struct genio *net)
{
    struct sterm_data *sdata = mygenio_to_sterm(net);

    LOCK(sdata->lock);
    sdata->in_free = true;
    if (sdata->in_close) {
	sdata->close_done = NULL;
	UNLOCK(sdata->lock);
    } else if (sdata->closed) {
	UNLOCK(sdata->lock);
	sterm_finish_free(sdata);
    } else {
	__sterm_close(sdata, NULL);
	UNLOCK(sdata->lock);
    }
}

static void
sterm_set_read_callback_enable(struct genio *net, bool enabled)
{
    struct sterm_data *sdata = mygenio_to_sterm(net);

    LOCK(sdata->lock);
    sdata->read_enabled = enabled;
    if (sdata->in_read || (sdata->data_pending_len && !enabled)) {
	/* Nothing to do, let the read handling wake things up. */
    } else if (sdata->data_pending_len) {
	sdata->deferred_read = true;
	sdata->in_read = true;
	if (!sdata->deferred_op_pending) {
	    /* Call the read from the selector to avoid lock nesting issues. */
	    sdata->deferred_op_pending = true;
	    sel_run(sdata->deferred_op_runner, sterm_deferred_op, sdata);
	}
    } else {
	int op;

	if (enabled)
	    op = SEL_FD_HANDLER_ENABLED;
	else
	    op = SEL_FD_HANDLER_DISABLED;

	sel_set_fd_read_handler(sdata->sel, sdata->fd, op);
    }
    UNLOCK(sdata->lock);
}

static void
sterm_set_write_callback_enable(struct genio *net, bool enabled)
{  
    struct sterm_data *sdata = mygenio_to_sterm(net);
    int op;

    if (enabled)
	op = SEL_FD_HANDLER_ENABLED;
    else
	op = SEL_FD_HANDLER_DISABLED;

    sel_set_fd_write_handler(sdata->sel, sdata->fd, op);  
}

static const struct genio_functions sterm_net_funcs = {
    .write = sterm_write,
    .raddr_to_str = sterm_raddr_to_str,
    .open = sterm_open,
    .close = sterm_close,
    .free = sterm_free,
    .set_read_callback_enable = sterm_set_read_callback_enable,
    .set_write_callback_enable = sterm_set_write_callback_enable
};

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
sergenio_process_parms(struct sterm_data *sdata)
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
sergenio_termios_alloc(const char *devname, struct selector_s *sel,
		       unsigned int read_buffer_size,
		       const struct sergenio_callbacks *scbs,
		       const struct genio_callbacks *cbs, void *user_data,
		       struct sergenio **snet)
{
    struct sterm_data *sdata = malloc(sizeof(*sdata));
    int err;
    char *comma;

    if (!sdata)
	return ENOMEM;

    memset(sdata, 0, sizeof(*sdata));
    sdata->fd = -1;

    cfmakeraw(&sdata->default_termios);
    cfsetispeed(&sdata->default_termios, B9600);
    cfsetospeed(&sdata->default_termios, B9600);
    sdata->default_termios.c_cc[VSTART] = 17;
    sdata->default_termios.c_cc[VSTOP] = 19;

    sdata->devname = strdup(devname);
    if (!sdata->devname) {
	err = ENOMEM;
	goto out;
    }
    comma = strchr(sdata->devname, ',');
    if (comma) {
	*comma++ = '\0';
	sdata->parms = comma;
	err = sergenio_process_parms(sdata);
	if (err)
	    goto out;
    }

    sdata->read_buffer_size = read_buffer_size;
    sdata->read_data = malloc(read_buffer_size);
    if (!sdata->read_data) {
	err = ENOMEM;
	goto out;
    }

    err = sel_alloc_runner(sdata->sel, &sdata->deferred_op_runner);
    if (err)
	goto out;

    sdata->sel = sel;
    sdata->snet.scbs = scbs;
    sdata->snet.net.user_data = user_data;
    sdata->snet.funcs = &sterm_funcs;
    sdata->snet.net.cbs = cbs;
    sdata->snet.net.funcs = &sterm_net_funcs;
    sdata->snet.net.type = GENIO_TYPE_SER_TERMIOS;
    sdata->snet.net.is_client = true;
    sdata->closed = true;

    *snet = &sdata->snet;
    return 0;

 out:
    sterm_finish_free(sdata);
    return err;
}
