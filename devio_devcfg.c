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

/* This code handles generating the configuration for the serial port. */
#include <unistd.h>
#include <stdint.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <syslog.h>

#include "utils/selector.h"
#include "utils/utils.h"
#include "utils/uucplock.h"
#include "ser2net.h"
#include "dataxfer.h"
#include "readconfig.h"
#include "devio.h"

#include <assert.h>

struct devcfg_data {
    /* Information about the terminal device. */
    char           *devname;		/* The full path to the device */
    int            devfd;		/* The file descriptor for the
                                           device, only valid if the
                                           TCP port is open. */
    struct termios default_termctl;
    struct termios current_termctl;

    void (*shutdown_done)(struct devio *);

    /* Used to make sure the shutdown isn't stuck. */
    struct gensio_timer *shutdown_timer;
    unsigned int shutdown_retries;

    /* Holds whether break is on or not. */
    int break_set;

    /* Disable break-commands */
    int disablebreak;

    unsigned int last_modemstate;

#if HAVE_DECL_TIOCSRS485
    struct serial_rs485 *rs485conf;
#endif
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

/* Initialize a serial port control structure for the first time.
   This should only be called when the port is created.  It sets the
   port to the default 9600N81. */
static void
devinit(struct termios *termctl)
{
    cfmakeraw(termctl);
    cfsetispeed(termctl, B9600);
    cfsetospeed(termctl, B9600);
    termctl->c_cflag |= CREAD | CS8;
    termctl->c_cc[VSTART] = 17;
    termctl->c_cc[VSTOP] = 19;

    set_termios_from_speed(termctl, find_default_int("speed"), "");
    set_termios_datasize(termctl, find_default_int("databits"));
    if (find_default_int("stopbits") == 1)
	termctl->c_cflag &= ~(CSTOPB);
    else
	termctl->c_cflag |= CSTOPB;

    set_termios_parity(termctl, find_default_int("parity"));
    set_termios_xonoff(termctl, find_default_int("xonxoff"));
    set_termios_rtscts(termctl, find_default_int("rtscts"));

    if (find_default_int("local"))
	termctl->c_cflag |= CLOCAL;
    else
	termctl->c_cflag &= ~CLOCAL;

    if (find_default_int("hangup_when_done"))
	termctl->c_cflag &= HUPCL;
    else
	termctl->c_cflag &= ~HUPCL;

    termctl->c_cflag |= CREAD;
    termctl->c_iflag |= IGNBRK;
}

/* Configure a serial port control structure based upon input strings
   in instr.  These strings are described in the man page for this
   program. */
static int
devconfig(struct devcfg_data *d, struct absout *eout, const char *instr,
	  int (*otherconfig)(void *data, struct absout *eout, const char *item),
	  void *data)
{
    struct termios *termctl = &d->default_termctl;
    char *str, *pos;
    const char *val;
    char *strtok_data;
    int rv = 0;

    devinit(termctl);
    d->disablebreak = find_default_int("nobreak");

    str = strdup(instr);
    if (str == NULL) {
	return -1;
    }

    for (pos = strtok_r(str, " \t", &strtok_data); pos != NULL;
	 pos = strtok_r(NULL, " \t", &strtok_data))
    {
	rv = process_termios_parm(termctl, pos);
	if (rv == 0)
	    continue;
	if (rv == EINVAL) {
	    eout->out(eout, "Invalid baud rate: %s", pos);
	    rv = -1;
	    goto out;
	}

	if (strcmp(pos, "NOBREAK") == 0) {
	    d->disablebreak = 1;
	} else if (strcmp(pos, "-NOBREAK") == 0) {
	    d->disablebreak = 0;
#if HAVE_DECL_TIOCSRS485
	} else if (cmpstrval(pos, "rs485=", &val)) {
	    /* get RS485 configuration. */
	    d->rs485conf = find_rs485conf(val);
#endif
	} else {
	    rv = otherconfig(data, eout, pos);
	    if (rv == -1)
		goto out;
	}
    }

 out:
    free(str);
    return rv;
}

static void
devcfg_serparm_to_str(struct devio *io, char *str, int strlen)
{
    struct devcfg_data *d = io->my_data;
    struct termios *termctl = &d->current_termctl;
    speed_t speed = cfgetospeed(termctl);
    int     stopbits = termctl->c_cflag & CSTOPB;
    int     databits = termctl->c_cflag & CSIZE;
    int     parity_enabled = termctl->c_cflag & PARENB;
    int     parity = termctl->c_cflag & PARODD;
    const char *sstr;
    char    pchar, schar, dchar;

    sstr = get_baud_rate_str(speed);

    if (stopbits)
	schar = '2';
    else
	schar = '1';

    switch (databits) {
    case CS7: dchar = '7'; break;
    case CS8: dchar = '8'; break;
    default: dchar = '?';
    }

    if (parity_enabled) {
	if (parity) {
	    pchar = 'O';
	} else {
	    pchar = 'E';
	}
    } else {
	pchar = 'N';
    }

    snprintf(str, strlen, "%s %c%c%c", sstr, pchar, dchar, schar);
}

/* Send the serial port device configuration to the control port. */
static void
devcfg_show_devcfg(struct devio *io, struct absout *out)
{
    struct devcfg_data *d = io->my_data;
    struct termios *termctl = &d->current_termctl;

    speed_t speed = cfgetospeed(termctl);
    int     stopbits = termctl->c_cflag & CSTOPB;
    int     databits = termctl->c_cflag & CSIZE;
    int     parity_enabled = termctl->c_cflag & PARENB;
    int     parity = termctl->c_cflag & PARODD;
    int     xon = termctl->c_iflag & IXON;
    int     xoff = termctl->c_iflag & IXOFF;
    int     xany = termctl->c_iflag & IXANY;
    int     flow_rtscts = termctl->c_cflag & CRTSCTS;
    int     clocal = termctl->c_cflag & CLOCAL;
    int     hangup_when_done = termctl->c_cflag & HUPCL;
    char    *str;

    out->out(out, "%s ", get_baud_rate_str(speed));

    if (xon && xoff && xany) {
      out->out(out, "XONXOFF ");
    }

    if (flow_rtscts) {
      out->out(out, "RTSCTS ");
    }

    if (clocal) {
      out->out(out, "LOCAL ");
    }

    if (hangup_when_done) {
      out->out(out, "HANGUP_WHEN_DONE ");
    }

    if (stopbits) {
	str = "2STOPBITS";
    } else {
	str = "1STOPBIT";
    }
    out->out(out, "%s ", str);

    switch (databits) {
    case CS7: str = "7DATABITS"; break;
    case CS8: str = "8DATABITS"; break;
    default: str = "unknown databits";
    }
    out->out(out, "%s ", str);

    if (parity_enabled) {
	if (parity) {
	    str = "ODD";
	} else {
	    str = "EVEN";
	}
    } else {
	str = "NONE";
    }
    out->out(out, "%s", str);
}

static int
devcfg_set_devcontrol(struct devio *io, const char *instr)
{
    struct devcfg_data *d = io->my_data;
    int fd = d->devfd;
    int rv = 0;
    char *str;
    char *pos;
    int status;
    char *strtok_data;

    str = malloc(strlen(instr) + 1);
    if (str == NULL) {
	return -1;
    }

    strcpy(str, instr);

    pos = strtok_r(str, " \t", &strtok_data);
    while (pos != NULL) {
       if (strcmp(pos, "RTSHI") == 0) {
           ioctl(fd, TIOCMGET, &status);
           status |= TIOCM_RTS;
           ioctl(fd, TIOCMSET, &status);
       } else if (strcmp(pos, "RTSLO") == 0) {
           ioctl(fd, TIOCMGET, &status);
           status &= ~TIOCM_RTS;
           ioctl(fd, TIOCMSET, &status);
       } else if (strcmp(pos, "DTRHI") == 0) {
           ioctl(fd, TIOCMGET, &status);
           status |= TIOCM_DTR;
           ioctl(fd, TIOCMSET, &status);
       } else if (strcmp(pos, "DTRLO") == 0) {
           ioctl(fd, TIOCMGET, &status);
           status &= ~TIOCM_DTR;               /* AKA drop DTR */
           ioctl(fd, TIOCMSET, &status);
	} else {
	    rv = -1;
	    goto out;
	}

	pos = strtok_r(NULL, " \t", &strtok_data);
    }

out:
    free(str);
    return rv;
}

static void
devcfg_show_devcontrol(struct devio *io, struct absout *out)
{
    struct devcfg_data *d = io->my_data;
    char *str;
    int  status;

    ioctl(d->devfd, TIOCMGET, &status);

    if (status & TIOCM_RTS) {
	str = "RTSHI";
    } else {
	str = "RTSLO";
    }
    out->out(out, "%s ", str);

    if (status & TIOCM_DTR) {
	str = "DTRHI";
    } else {
	str = "DTRLO";
    }
    out->out(out, "%s ", str);
}

static void
do_read(int fd, void *data)
{
    struct devio *io = data;
    io->read_handler(io);
}

static void
do_write(int fd, void *data)
{
    struct devio *io = data;
    io->write_handler(io);
}

static void
do_except(int fd, void *data)
{
    struct devio *io = data;
    io->except_handler(io);
}

static int calc_bpc(struct devcfg_data *d)
{
    struct termios *termio = &d->current_termctl;
    int size;

    size = 2; /* Start bit, 1 stop bit. */
    switch (termio->c_cflag & CSIZE) {
    case CS5: size += 5; break;
    case CS6: size += 6; break;
    case CS7: size += 7; break;
    case CS8:
    default:  size += 8; break;
    }

    if (termio->c_cflag & CSTOPB)
	size += 1;

    if (termio->c_cflag & PARENB)
	size += 1;

    return size;
}

static void
devcfg_finish_shutdown(struct devio *io)
{
    struct devcfg_data *d = io->my_data;
    void (*shutdown_done)(struct devio *) = d->shutdown_done;
    struct termios termio;

    /* Disable flow control to avoid a long shutdown. */
    if (tcgetattr(d->devfd, &termio) != -1) {
	termio.c_iflag &= ~(IXON | IXOFF);
	termio.c_cflag &= ~CRTSCTS;
	tcsetattr(d->devfd, TCSANOW, &termio);
    }
    /* To avoid blocking on close if we have written bytes and are in
       flow-control, we flush the output queue. */
    tcflush(d->devfd, TCOFLUSH);
    close(d->devfd);
    d->devfd = -1;
    uucp_rm_lock(io->devname);
    shutdown_done(io);
}

static void
devcfg_check_drained(struct devio *io)
{
    struct devcfg_data *d = io->my_data;
    int rv, count = 0;
    struct timeval timeout;

    rv = ioctl(d->devfd, TIOCOUTQ, &count);
    if (rv || count == 0) {
	devcfg_finish_shutdown(io);
	return;
    }

    d->shutdown_retries--;
    if (d->shutdown_retries == 0) {
	devcfg_finish_shutdown(io);
	return;
    }

    timeout.tv_sec = 0;
    timeout.tv_usec = 10000;
    so->start_timer(d->shutdown_timer, &timeout);
}

void
shutdown_timeout(struct gensio_timer *timer, void *cb_data)
{
    struct devio *io = cb_data;
    
    devcfg_check_drained(io);
}

static void
devfd_fd_cleared(int fd, void *cb_data)
{
    struct devio *io = cb_data;

    devcfg_check_drained(io);
}

static int devcfg_setup(struct devio *io, const char *name, const char **errstr,
			int *bps, int *bpc)
{
    struct devcfg_data *d = io->my_data;
    struct termios *termctl = &d->current_termctl;
    int options;
    int rv;

    *termctl = d->default_termctl;

    rv = uucp_mk_lock(io->devname);
    if (rv > 0 ) {
	*errstr = "Port already in use by another process\r\n";
	return -1;
    } else if (rv < 0) {
	*errstr = "Error creating port lock file\r\n";
	return -1;
    }

    get_rate_from_baud_rate(cfgetispeed(termctl), &rv);
    if (rv == 0)
	rv = 9600;
    *bps = rv;
    *bpc = calc_bpc(d);

    /* Oct 05 2001 druzus: NOCTTY - don't make
       device control tty for our process */
    options = O_NONBLOCK | O_NOCTTY;
    if (io->read_disabled) {
	options |= O_WRONLY;
    } else {
	options |= O_RDWR;
    }
    d->devfd = open(io->devname, options);
    if (d->devfd == -1) {
	syslog(LOG_ERR, "Could not open device %s for port %s: %m",
	       io->devname,
	       name);
	uucp_rm_lock(io->devname);
	return -1;
    }

    if (!io->read_disabled && tcsetattr(d->devfd, TCSANOW, termctl) == -1)
    {
	close(d->devfd);
	d->devfd = -1;
	syslog(LOG_ERR, "Could not set up device %s for port %s: %m",
	       io->devname,
	       name);
	uucp_rm_lock(io->devname);
	return -1;
    }

    /* Turn off BREAK. */
    if (!io->read_disabled && !d->disablebreak
	&& ioctl(d->devfd, TIOCCBRK) == -1) {
	/* Probably not critical, but we should at least log something. */
	syslog(LOG_ERR, "Could not turn off break for device %s port %s: %m",
	       io->devname,
	       name);
    }

#if HAVE_DECL_TIOCSRS485
    if (d->rs485conf) {
        if (d->rs485conf->flags & SER_RS485_ENABLED) {
            if (ioctl(d->devfd , TIOCSRS485, d->rs485conf ) < 0) {
                syslog(LOG_ERR, "Could not set RS485 config for device %s port %s: %m",
                       io->devname,
                       name);
                return -1;
            }
        }
    }
#endif

    rv = so->set_fd_handlers(so, d->devfd, io,
			     io->read_disabled ? NULL : do_read,
			     do_write, do_except, devfd_fd_cleared);
    if (rv) {
	*errstr = strerror(rv);
	return -1;
    }

    return 0;
}

static void devcfg_shutdown(struct devio *io,
			    void (*shutdown_done)(struct devio *))
{
    struct devcfg_data *d = io->my_data;

    if (d->devfd != -1) {
	d->shutdown_done = shutdown_done;
	/*
	 * FIXME - we should calculate the amount of time it should
	 * take to send the pending data based upon baud and count.
	 */
	d->shutdown_retries = 200; /* 2 seconds. */
	so->clear_fd_handlers(so, d->devfd);
    } else {
	shutdown_done(io);
    }
}

static int devcfg_read(struct devio *io, void *buf, size_t size)
{
    struct devcfg_data *d = io->my_data;

    return read(d->devfd, buf, size);
}

static int devcfg_write(struct devio *io, void *buf, size_t size)
{
    struct devcfg_data *d = io->my_data;

    return write(d->devfd, buf, size);
}

static void devcfg_read_handler_enable(struct devio *io, int enabled)
{
    struct devcfg_data *d = io->my_data;

    so->set_read_handler(so, d->devfd, enabled);
}

static void devcfg_write_handler_enable(struct devio *io, int enabled)
{
    struct devcfg_data *d = io->my_data;

    so->set_write_handler(so, d->devfd, enabled);
}

static void devcfg_except_handler_enable(struct devio *io, int enabled)
{
    struct devcfg_data *d = io->my_data;

    so->set_except_handler(so, d->devfd, enabled);
}

static int devcfg_send_break(struct devio *io)
{
    struct devcfg_data *d = io->my_data;

    tcsendbreak(d->devfd, 0);
    return 0;
}

static int devcfg_get_modem_state(struct devio *io, unsigned char *modemstate)
{
    struct devcfg_data *d = io->my_data;
    int val;

    if (ioctl(d->devfd, TIOCMGET, &val) != 0)
	return -1;

    *modemstate = 0;
    if (val & TIOCM_CD)
	*modemstate |= 0x80;
    if (val & TIOCM_RI)
	*modemstate |= 0x40;
    if (val & TIOCM_DSR)
	*modemstate |= 0x20;
    if (val & TIOCM_CTS)
	*modemstate |= 0x10;

    /* Bits for things that changed. */
    *modemstate |= (*modemstate ^ d->last_modemstate) >> 4;

    d->last_modemstate = *modemstate;
    return 0;
}

static int devcfg_baud_rate(struct devio *io, int *val)
{
    struct devcfg_data *d = io->my_data;
    struct termios termio;

    if (tcgetattr(d->devfd, &termio) == -1) {
	*val = 0;
	return -1;
    }

    if ((*val != 0) && (get_baud_rate(*val, val))) {
	/* We have a valid baud rate. */
	cfsetispeed(&termio, *val);
	cfsetospeed(&termio, *val);
	tcsetattr(d->devfd, TCSANOW, &termio);
    }

    tcgetattr(d->devfd, &termio);
    *val = cfgetispeed(&termio);
    get_rate_from_baud_rate(*val, val);

    return 0;
}

static int devcfg_data_size(struct devio *io, int *val, int *bpc)
{
    struct devcfg_data *d = io->my_data;
    struct termios termio;

    if (tcgetattr(d->devfd, &termio) == -1) {
	*val = 0;
	return -1;
    }

    if ((*val >= 5) && (*val <= 8)) {
	termio.c_cflag &= ~CSIZE;
	switch (*val) {
	case 5: termio.c_cflag |= CS5; break;
	case 6: termio.c_cflag |= CS6; break;
	case 7: termio.c_cflag |= CS7; break;
	case 8: termio.c_cflag |= CS8; break;
	}
	tcsetattr(d->devfd, TCSANOW, &termio);
    }

    switch (termio.c_cflag & CSIZE) {
    case CS5: *val = 5; break;
    case CS6: *val = 6; break;
    case CS7: *val = 7; break;
    case CS8: *val = 8; break;
    default:  *val = 0;
    }

    *bpc = calc_bpc(d);

    return 0;
}

static int devcfg_parity(struct devio *io, int *val, int *bpc)
{
    struct devcfg_data *d = io->my_data;
    struct termios termio;

    if (tcgetattr(d->devfd, &termio) == -1) {
	*val = 0;
	return -1;
    }

    /* We don't support MARK or SPACE parity. */
    if ((*val >= 1) && (*val <= 3)) {
	termio.c_cflag &= ~(PARENB | PARODD);
	switch (*val) {
	case 1: break; /* NONE */
	case 2: termio.c_cflag |= PARENB | PARODD; /* ODD */
	    break;
	case 3: termio.c_cflag |= PARENB; /* EVEN */
	    break;
	}
	tcsetattr(d->devfd, TCSANOW, &termio);
    }

    if (termio.c_cflag & PARENB) {
	if (termio.c_cflag & PARODD)
	    *val = 2; /* ODD */
	else
	    *val = 3; /* EVEN */
    } else
	*val = 1; /* NONE */

    *bpc = calc_bpc(d);

    return 0;
}

static int devcfg_stop_size(struct devio *io, int *val, int *bpc)
{
    struct devcfg_data *d = io->my_data;
    struct termios termio;

    if (tcgetattr(d->devfd, &termio) == -1) {
	*val = 0;
	return -1;
    }

    if ((*val >= 1) && (*val <= 2)) {
	termio.c_cflag &= ~CSTOPB;
	switch (*val) {
	case 1: break; /* 1 stop bit */
	case 2: /* 2 stop bits */
	    termio.c_cflag |= CSTOPB;
	    break;
	}
	tcsetattr(d->devfd, TCSANOW, &termio);
    }

    if (termio.c_cflag & CSTOPB)
	*val = 2; /* 2 stop bits. */
    else
	*val = 1; /* 1 stop bit. */

    *bpc = calc_bpc(d);

    return 0;
}

static int devcfg_flowcontrol_state(struct devio *io, int val)
{
    struct devcfg_data *d = io->my_data;

    tcflow(d->devfd, val ? TCIOFF : TCION);
    return 0;
}

static int
devcfg_flowcontrol(struct devio *io, int *val)
{
    struct devcfg_data *d = io->my_data;
    struct termios termio;

    if (tcgetattr(d->devfd, &termio) != -1) {
	if (*val != 0) {
	    termio.c_iflag &= ~(IXON | IXOFF);
	    termio.c_cflag &= ~CRTSCTS;
	    switch (*val) {
	    case 1: break; /* NONE */
	    case 2: termio.c_iflag |= IXON | IXOFF; break;
	    case 3: termio.c_cflag |= CRTSCTS; break;
	    }
	    tcsetattr(d->devfd, TCSANOW, &termio);
	}
	if (termio.c_cflag & CRTSCTS)
	    *val = 3;
	else if (termio.c_iflag & IXON)
	    *val = 2;
	else
	    *val = 1;
    }

    return 0;
}

static int
devcfg_iflowcontrol(struct devio *io, int *val)
{
    struct devcfg_data *d = io->my_data;
    struct termios termio;

    /* Inbound flow-control */
    if (tcgetattr(d->devfd, &termio) != -1) {
	if (*val == 2) {
	    /* We can only set XON/XOFF independently */
	    termio.c_iflag |= IXOFF;
	    tcsetattr(d->devfd, TCSANOW, &termio);
	}
	if (termio.c_cflag & CRTSCTS)
	    *val = 2;
	else if (termio.c_iflag & IXOFF)
	    *val = 1;
	else
	    *val = 0;
    }

    return 0;
}

static int
devcfg_sbreak(struct devio *io, int *val)
{
    struct devcfg_data *d = io->my_data;

    switch (*val) {
    case 2:
	if (ioctl(d->devfd, TIOCCBRK) != -1)
	    d->break_set = 0;
	goto read_break_val;

    case 1:
	if (ioctl(d->devfd, TIOCSBRK) != -1)
	    d->break_set = 1;
	goto read_break_val;

    case 0:
    read_break_val:
	if (d->break_set)
	    *val = 0;
	else
	    *val = 1;
	break;
    }

    return 0;
}

static int
devcfg_dtr(struct devio *io, int *val)
{
    struct devcfg_data *d = io->my_data;
    int ival;

    switch (*val) {
    case 1:
#ifndef __CYGWIN__
	ival = TIOCM_DTR;
	ioctl(d->devfd, TIOCMBIS, &ival);
#else
	ioctl(d->devfd, TIOCMGET, &ival);
	ival |= TIOCM_DTR;
	ioctl(d->devfd, TIOCMSET, &ival);
#endif
	goto read_dtr_val;

    case 2:
#ifndef __CYGWIN__
	ival = TIOCM_DTR;
	ioctl(d->devfd, TIOCMBIC, &ival);
#else
	ioctl(d->devfd, TIOCMGET, &ival);
	ival &= ~TIOCM_DTR;
	ioctl(d->devfd, TIOCMSET, &ival);
#endif
	goto read_dtr_val;

    case 0:
    read_dtr_val:
	if (ioctl(d->devfd, TIOCMGET, &ival) == -1)
	    *val = 0;
	else if (ival & TIOCM_DTR)
	    *val = 1;
	else
	    *val = 2;
	break;
    }

    return 0;
}

static int
devcfg_rts(struct devio *io, int *val)
{
    struct devcfg_data *d = io->my_data;
    int ival;

    switch (*val) {
    case 1:
#ifndef __CYGWIN__
	ival = TIOCM_RTS;
	ioctl(d->devfd, TIOCMBIS, &ival);
#else
	ioctl(d->devfd, TIOCMGET, &ival);
	ival |= TIOCM_RTS;
	ioctl(d->devfd, TIOCMSET, &ival);
#endif
	goto read_rts_val;

    case 2:
#ifndef __CYGWIN__
	ival = TIOCM_RTS;
	ioctl(d->devfd, TIOCMBIC, &ival);
#else
	ioctl(d->devfd, TIOCMGET, &ival);
	ival &= ~TIOCM_RTS;
	ioctl(d->devfd, TIOCMSET, &ival);
#endif
	goto read_rts_val;

    case 0:
    read_rts_val:
	if (ioctl(d->devfd, TIOCMGET, &ival) == -1)
	    *val = 0;
	else if (ival & TIOCM_RTS)
	    *val = 1;
	else
	    *val = 2;
	break;
    }

    return 0;
}

static int devcfg_flush(struct devio *io, int *val)
{
    struct devcfg_data *d = io->my_data;
    int ival;

    switch (*val) {
    case DEVIO_FLUSH_INPUT: ival = TCIFLUSH; goto purge_found;
    case DEVIO_FLUSH_OUTPUT: ival = TCOFLUSH; goto purge_found;
    case DEVIO_FLUSH_INPUT | DEVIO_FLUSH_OUTPUT:
	ival = TCIOFLUSH; goto purge_found;
    }
    *val = 0;
    return -1;
 purge_found:
    tcflush(d->devfd, ival);
    return 0;
}

static void devcfg_free(struct devio *io)
{
    struct devcfg_data *d = io->my_data;

    if (d->devfd != -1)
	close(d->devfd);
    io->my_data = NULL;
    so->free_timer(d->shutdown_timer);
    free(d);
}

static int
devcfg_reconfig(struct devio *io, struct absout *eout, const char *instr,
		int (*otherconfig)(void *data, struct absout *eout,
				   const char *item),
		void *data)
{
    struct devcfg_data *d = io->my_data;

    return devconfig(d, eout, instr, otherconfig, data);
}

static struct devio_f devcfg_io_f = {
    .setup = devcfg_setup,
    .shutdown = devcfg_shutdown,
    .reconfig = devcfg_reconfig,
    .read = devcfg_read,
    .write = devcfg_write,
    .read_handler_enable = devcfg_read_handler_enable,
    .write_handler_enable = devcfg_write_handler_enable,
    .except_handler_enable = devcfg_except_handler_enable,
    .send_break = devcfg_send_break,
    .get_modem_state = devcfg_get_modem_state,
    .set_devcontrol = devcfg_set_devcontrol,
    .show_devcontrol = devcfg_show_devcontrol,
    .show_devcfg = devcfg_show_devcfg,
    .baud_rate = devcfg_baud_rate,
    .data_size = devcfg_data_size,
    .parity = devcfg_parity,
    .stop_size = devcfg_stop_size,
    .flowcontrol = devcfg_flowcontrol,
    .iflowcontrol = devcfg_iflowcontrol,
    .sbreak = devcfg_sbreak,
    .dtr = devcfg_dtr,
    .rts = devcfg_rts,
    .flowcontrol_state = devcfg_flowcontrol_state,
    .flush = devcfg_flush,
    .free = devcfg_free,
    .serparm_to_str = devcfg_serparm_to_str
};

int
devcfg_init(struct devio *io, struct absout *eout, const char *instr,
	    int (*otherconfig)(void *data, struct absout *eout,
			       const char *item),
	    void *data)
{
    struct devcfg_data *d;

    d = malloc(sizeof(*d));
    if (!d)
	return -1;
    memset(d, 0, sizeof(*d));
    d->devfd = -1;

    d->shutdown_timer = so->alloc_timer(so, shutdown_timeout, io);
    if (!d->shutdown_timer) {
	free(d);
	return -1;
    }

    if (devconfig(d, eout, instr, otherconfig, data) == -1) {
	so->free_timer(d->shutdown_timer);
	free(d);
	return -1;
    }

    io->my_data = d;
    io->f = &devcfg_io_f;
    return 0;
}

