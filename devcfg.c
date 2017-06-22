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

#include "ser2net.h"
#include "selector.h"
#include "utils.h"
#include "dataxfer.h"
#include "devio.h"

#include <assert.h>

struct devcfg_data {
    /* Information about the terminal device. */
    char           *devname;		/* The full path to the device */
    int            devfd;		/* The file descriptor for the
                                           device, only valid if the
                                           TCP port is open. */
    struct termios termctl;

    void (*shutdown_done)(struct devio *);

    int default_bps;
    int default_data_size;
    int default_stop_bits;
    int default_parity_on;
    int current_bps;
    int current_data_size;
    int current_stop_bits;
    int current_parity_on;

    /* Holds whether break is on or not. */
    int break_set;

    /* Disable break-commands */
    int disablebreak;

#if HAVE_DECL_TIOCSRS485
    struct serial_rs485 *conf;
#endif
};

static struct baud_rates_s {
    int real_rate;
    int val;
    int cisco_ios_val;
} baud_rates[] =
{
    { 50, B50, -1 },
    { 75, B75, -1 },
    { 110, B110, -1 },
    { 134, B134, -1 },
    { 150, B150, -1 },
    { 200, B200, -1 },
    { 300, B300, 3 },
    { 600, B600 , 4},
    { 1200, B1200, 5 },
    { 1800, B1800, -1 },
    { 2400, B2400, 6 },
    { 4800, B4800, 7 },
    { 9600, B9600, 8 },
    /* We don't support 14400 baud */
    { 19200, B19200, 10 },
    /* We don't support 28800 baud */
    { 38400, B38400, 12 },
    { 57600, B57600, 13 },
    { 115200, B115200, 14 },
    { 230400, B230400, 15 },
    /* We don't support 460800 baud */
};
#define BAUD_RATES_LEN ((sizeof(baud_rates) / sizeof(struct baud_rates_s)))

static int
get_baud_rate(int rate, int *val, int cisco, int *bps)
{
    unsigned int i;
    for (i = 0; i < BAUD_RATES_LEN; i++) {
	if (cisco) {
	    if (rate == baud_rates[i].cisco_ios_val) {
		*val = baud_rates[i].val;
		*bps = baud_rates[i].real_rate;
		return 1;
	    }
	} else {
	    if (rate == baud_rates[i].real_rate) {
		*val = baud_rates[i].val;
		*bps = baud_rates[i].real_rate;
		return 1;
	    }
	}
    }

    return 0;
}

static void
get_rate_from_baud_rate(int baud_rate, int *val, int cisco)
{
    unsigned int i;
    for (i = 0; i < BAUD_RATES_LEN; i++) {
	if (baud_rate == baud_rates[i].val) {
	    if (cisco) {
		if (baud_rates[i].cisco_ios_val < 0)
		    /* We are at a baud rate unsupported by the
		       enumeration, just return zero. */
		    *val = 0;
		else
		    *val = baud_rates[i].cisco_ios_val;
	    } else {
		*val = baud_rates[i].real_rate;
	    }
	    return;
	}
    }
}

#ifdef USE_UUCP_LOCKING
static char *uucp_lck_dir = "/var/lock/";
static char *dev_prefix = "/dev/";

static int
uucp_fname_lock_size(char *devname)
{
    int dev_prefix_len = strlen(dev_prefix);

    if (strncmp(dev_prefix, devname, dev_prefix_len) == 0)
	devname += dev_prefix_len;

    /*
     * Format is "/var/lock/LCK..<devname>".  The 6 is for
     * the "LCK.." and the final nil char.
     */
    return 6 + strlen(uucp_lck_dir) + strlen(devname);
}

static void
uucp_fname_lock(char *buf, char *devname)
{
    int i, dev_prefix_len = strlen(dev_prefix);

    if (strncmp(dev_prefix, devname, dev_prefix_len) == 0)
	devname += dev_prefix_len;

    sprintf(buf, "%sLCK..%s", uucp_lck_dir, devname);
    for (i = strlen(uucp_lck_dir); buf[i]; i++) {
	if (buf[i] == '/')
	    buf[i] = '_';
    }
}

static void
uucp_rm_lock(char *devname)
{
    char *lck_file;

    if (!uucp_locking_enabled) return;

    lck_file = malloc(uucp_fname_lock_size(devname));
    if (lck_file == NULL) {
	return;
    }
    uucp_fname_lock(lck_file, devname);
    unlink(lck_file);
    free(lck_file);
}

/* return 0=OK, -1=error, 1=locked by other proces */
static int
uucp_mk_lock(char *devname)
{
    struct stat stt;
    int pid = -1;

    if (!uucp_locking_enabled)
	return 0;

    if (stat(uucp_lck_dir, &stt) == 0) { /* is lock file directory present? */
	char *lck_file;
	union {
	    uint32_t ival;
	    char     str[64];
	} buf;
	int fd;

	lck_file = malloc(uucp_fname_lock_size(devname));
	if (lck_file == NULL)
	    return -1;

	uucp_fname_lock(lck_file, devname);

	pid = 0;
	if ((fd = open(lck_file, O_RDONLY)) >= 0) {
	    int n;

	    n = read(fd, &buf, sizeof(buf) - 1);
	    close(fd);
	    if (n == 4) 		/* Kermit-style lockfile. */
		pid = buf.ival;
	    else if (n > 0) {		/* Ascii lockfile. */
		buf.str[n] = '\0';
		sscanf(buf.str, "%10d", &pid);
	    }

	    if (pid > 0 && kill((pid_t)pid, 0) < 0 && errno == ESRCH) {
		/* death lockfile - remove it */
		unlink(lck_file);
		pid = 0;
	    } else
		pid = 1;

	}

	if (pid == 0) {
	    int mask;

	    mask = umask(022);
	    fd = open(lck_file, O_WRONLY | O_CREAT | O_EXCL, 0666);
	    umask(mask);
	    if (fd >= 0) {
	        ssize_t rv;

		snprintf(buf.str, sizeof(buf), "%10ld\n",
			 (long)getpid());
		rv = write_full(fd, buf.str, strlen(buf.str));
		close(fd);
		if (rv < 0) {
		    pid = -1;
		    unlink(lck_file);
		}
	    } else {
		pid = -1;
	    }
	}

	free(lck_file);
    }

    return pid;
}
#else
static void uucp_rm_lock(char *devname) { }
static int uucp_mk_lock(char *devname)
{
    return 0;
}
#endif /* USE_UUCP_LOCKING */

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
set_termios_from_speed(struct devcfg_data *d, struct termios *termctl,
		       int speed)
{
    switch (speed) {
    case 300:
	cfsetospeed(termctl, B300);
	cfsetispeed(termctl, B300);
	break;

    case 600:
	cfsetospeed(termctl, B600);
	cfsetispeed(termctl, B600);
	break;

    case 1200:
	cfsetospeed(termctl, B1200);
	cfsetispeed(termctl, B1200);
	break;

    case 2400:
	cfsetospeed(termctl, B2400);
	cfsetispeed(termctl, B2400);
	break;

    case 4800:
	cfsetospeed(termctl, B4800);
	cfsetispeed(termctl, B4800);
	break;

    case 9600:
	cfsetospeed(termctl, B9600);
	cfsetispeed(termctl, B9600);
	break;

    case 19200:
	cfsetospeed(termctl, B19200);
	cfsetispeed(termctl, B19200);
	break;

    case 38400:
	cfsetospeed(termctl, B38400);
	cfsetispeed(termctl, B38400);
	break;

    case 57600:
	cfsetospeed(termctl, B57600);
	cfsetispeed(termctl, B57600);
	break;

    case 115200:
	cfsetospeed(termctl, B115200);
	cfsetispeed(termctl, B115200);
	break;

#ifdef B230400
    case 230400:
	cfsetospeed(termctl, B230400);
	cfsetispeed(termctl, B230400);
	break;
#endif
#ifdef B460800
    case 460800:
	cfsetospeed(termctl, B460800);
	cfsetispeed(termctl, B460800);
	break;
#endif
#ifdef B500000
    case 500000:
	cfsetospeed(termctl, B500000);
	cfsetispeed(termctl, B500000);
	break;
#endif
#ifdef B576000
    case 576000:
	cfsetospeed(termctl, B576000);
	cfsetispeed(termctl, B576000);
	break;
#endif
#ifdef B921600
    case 921600:
	cfsetospeed(termctl, B921600);
	cfsetispeed(termctl, B921600);
	break;
#endif
#ifdef B1000000
    case 1000000:
	cfsetospeed(termctl, B1000000);
	cfsetispeed(termctl, B1000000);
	break;
#endif
#ifdef B1152000
    case 1152000:
	cfsetospeed(termctl, B1152000);
	cfsetispeed(termctl, B1152000);
	break;
#endif
#ifdef B1500000
    case 1500000:
	cfsetospeed(termctl, B1500000);
	cfsetispeed(termctl, B1500000);
	break;
#endif
#ifdef B2000000
    case 2000000:
	cfsetospeed(termctl, B2000000);
	cfsetispeed(termctl, B2000000);
	break;
#endif
#ifdef B2500000
    case 2500000:
	cfsetospeed(termctl, B2500000);
	cfsetispeed(termctl, B2500000);
	break;
#endif
#ifdef B3000000
    case 3000000:
	cfsetospeed(termctl, B3000000);
	cfsetispeed(termctl, B3000000);
	break;
#endif
#ifdef B3500000
    case 3500000:
	cfsetospeed(termctl, B3500000);
	cfsetispeed(termctl, B3500000);
	break;
#endif
#ifdef B4000000
    case 4000000:
	cfsetospeed(termctl, B4000000);
	cfsetispeed(termctl, B4000000);
	break;
#endif
    default:
	return -1;
    }

    d->default_bps = speed;
    return 0;
}

static void
set_termios_parity(struct devcfg_data *d, struct termios *termctl,
		   enum parity_vals val)
{
    switch (val) {
    case PARITY_NONE:
	termctl->c_cflag &= ~(PARENB);
	break;
    case PARITY_EVEN:
    case PARITY_SPACE:
	termctl->c_cflag |= PARENB;
	termctl->c_cflag &= ~(PARODD);
#ifdef CMSPAR
	if (val == PARITY_SPACE)
	    termctl->c_cflag |= CMSPAR;
#endif
	break;
    case PARITY_ODD:
    case PARITY_MARK:
	termctl->c_cflag |= PARENB | PARODD;
#ifdef CMSPAR
	if (val == PARITY_MARK)
	    termctl->c_cflag |= CMSPAR;
#endif
	break;
    }
    d->default_parity_on = val != PARITY_NONE;
}

static void
set_termios_xonoff(struct termios *termctl, int enabled)
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
set_termios_datasize(struct devcfg_data *d, struct termios *termctl, int size)
{
    termctl->c_cflag &= ~CSIZE;
    switch (size) {
    case 5: termctl->c_cflag |= CS5; break;
    case 6: termctl->c_cflag |= CS6; break;
    case 7: termctl->c_cflag |= CS7; break;
    case 8: termctl->c_cflag |= CS8; break;
    }
    d->default_data_size = size;
}

/* Initialize a serial port control structure for the first time.
   This should only be called when the port is created.  It sets the
   port to the default 9600N81. */
static void
devinit(struct devcfg_data *d, struct termios *termctl)
{
    cfmakeraw(termctl);

    set_termios_from_speed(d, termctl, find_default_int("speed"));
    set_termios_datasize(d, termctl, find_default_int("databits"));
    d->default_stop_bits = find_default_int("stopbits");
    if (d->default_stop_bits == 1)
	termctl->c_cflag &= ~(CSTOPB);
    else
	termctl->c_cflag |= CSTOPB;

    set_termios_parity(d, termctl, find_default_int("parity"));
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

    d->disablebreak = find_default_int("nobreak");

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
    struct termios *termctl = &d->termctl;
    char *str;
    char *pos;
    char *strtok_data;
    int  rv = 0, val;

    devinit(d, termctl);

    str = strdup(instr);
    if (str == NULL) {
	return -1;
    }

    pos = strtok_r(str, " \t", &strtok_data);
    while (pos != NULL) {
	if ((val = speedstr_to_speed(pos)) != -1) {
	    rv = set_termios_from_speed(d, termctl, val);
	    if (rv) {
		eout->out(eout, "Invalid baud rate: %d\n", d->default_bps);
		goto out;
	    }
	} else if (strcmp(pos, "1STOPBIT") == 0) {
	    termctl->c_cflag &= ~(CSTOPB);
	    d->default_stop_bits = 1;
	} else if (strcmp(pos, "2STOPBITS") == 0) {
	    termctl->c_cflag |= CSTOPB;
	    d->default_stop_bits = 2;
	} else if (strcmp(pos, "5DATABITS") == 0) {
	    set_termios_datasize(d, termctl, 5);
	} else if (strcmp(pos, "6DATABITS") == 0) {
	    set_termios_datasize(d, termctl, 6);
	} else if (strcmp(pos, "7DATABITS") == 0) {
	    set_termios_datasize(d, termctl, 7);
	} else if (strcmp(pos, "8DATABITS") == 0) {
	    set_termios_datasize(d, termctl, 8);
	} else if ((val = lookup_parity(pos)) != -1) {
	    set_termios_parity(d, termctl, val);
        } else if (strcmp(pos, "XONXOFF") == 0) {
	    set_termios_xonoff(termctl, 1);
        } else if (strcmp(pos, "-XONXOFF") == 0) {
	    set_termios_xonoff(termctl, 0);
        } else if (strcmp(pos, "RTSCTS") == 0) {
	    set_termios_rtscts(termctl, 1);
        } else if (strcmp(pos, "-RTSCTS") == 0) {
	    set_termios_rtscts(termctl, 0);
        } else if (strcmp(pos, "LOCAL") == 0) {
            termctl->c_cflag |= CLOCAL;
        } else if (strcmp(pos, "-LOCAL") == 0) {
            termctl->c_cflag &= ~CLOCAL;
        } else if (strcmp(pos, "HANGUP_WHEN_DONE") == 0) {
            termctl->c_cflag |= HUPCL;
        } else if (strcmp(pos, "-HANGUP_WHEN_DONE") == 0) {
            termctl->c_cflag &= ~HUPCL;
	} else if (strcmp(pos, "NOBREAK") == 0) {
	    d->disablebreak = 1;
	} else if (strcmp(pos, "-NOBREAK") == 0) {
	    d->disablebreak = 0;
	} else {
	    if (otherconfig(data, eout, pos) == -1)
		goto out;
	}

	pos = strtok_r(NULL, " \t", &strtok_data);
    }

#if HAVE_DECL_TIOCSRS485
    d->conf = get_rs485_conf(data);
#endif
 out:
    free(str);
    return rv;
}

static char *
baud_string(int speed)
{
    char *str;
    switch (speed) {
    case B300: str = "300"; break;
    case B600: str = "600"; break;
    case B1200: str = "1200"; break;
    case B2400: str = "2400"; break;
    case B4800: str = "4800"; break;
    case B9600: str = "9600"; break;
    case B19200: str = "19200"; break;
    case B38400: str = "38400"; break;
    case B57600: str = "57600"; break;
    case B115200: str = "115200"; break;
#ifdef B230400
    case B230400: str = "230400"; break;
#endif
#ifdef B460800
    case B460800: str = "460800"; break;
#endif
#ifdef B500000
    case B500000: str = "500000"; break;
#endif
#ifdef B576000
    case B576000: str = "576000"; break;
#endif
#ifdef B921600
    case B921600: str = "921600"; break;
#endif
#ifdef B1000000
    case B1000000: str = "1000000"; break;
#endif
#ifdef B1152000
    case B1152000: str = "1152000"; break;
#endif
#ifdef B1500000
    case B1500000: str = "1500000"; break;
#endif
#ifdef B2000000
    case B2000000: str = "2000000"; break;
#endif
#ifdef B2500000
    case B2500000: str = "2500000"; break;
#endif
#ifdef B3000000
    case B3000000: str = "3000000"; break;
#endif
#ifdef B3500000
    case B3500000: str = "3500000"; break;
#endif
#ifdef B4000000
    case B4000000: str = "4000000"; break;
#endif
    default: str = "unknown speed";
    }
    return str;
}

static void
devcfg_serparm_to_str(struct devio *io, char *str, int strlen)
{
    struct devcfg_data *d = io->my_data;
    struct termios *termctl = &d->termctl;
    speed_t speed = cfgetospeed(termctl);
    int     stopbits = termctl->c_cflag & CSTOPB;
    int     databits = termctl->c_cflag & CSIZE;
    int     parity_enabled = termctl->c_cflag & PARENB;
    int     parity = termctl->c_cflag & PARODD;
    char    *sstr;
    char    pchar, schar, dchar;

    sstr = baud_string(speed);

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
    struct termios *termctl = &d->termctl;

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

    out->out(out, "%s ", baud_string(speed));

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
    return d->current_data_size + d->current_stop_bits +
	d->current_parity_on + 1;
}

static void
devfd_fd_cleared(int fd, void *cb_data)
{
    struct devio *io = cb_data;
    struct devcfg_data *d = io->my_data;
    void (*shutdown_done)(struct devio *) = d->shutdown_done;
    struct termios termio;

    /* Disable flow control to avoid a long shutdown. */
    if (tcgetattr(d->devfd, &termio) != -1) {
	termio.c_iflag &= ~(IXON | IXOFF);
	termio.c_cflag &= ~CRTSCTS;
	tcsetattr(d->devfd, TCSANOW, &termio);
    }
    tcflush(d->devfd, TCOFLUSH);
    close(d->devfd);
    d->devfd = -1;
    uucp_rm_lock(io->devname);
    shutdown_done(io);
}

static int devcfg_setup(struct devio *io, const char *name, const char **errstr,
			int *bps, int *bpc)
{
    struct devcfg_data *d = io->my_data;
    int options;
    int rv;

    rv = uucp_mk_lock(io->devname);
    if (rv > 0 ) {
	*errstr = "Port already in use by another process\r\n";
	return -1;
    } else if (rv < 0) {
	*errstr = "Error creating port lock file\r\n";
	return -1;
    }

    *bps = d->current_bps = d->default_bps;
    d->current_data_size = d->default_data_size;
    d->current_stop_bits = d->default_stop_bits;
    d->current_parity_on = d->default_parity_on;
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

    if (!io->read_disabled && tcsetattr(d->devfd, TCSANOW, &d->termctl) == -1)
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
    if (d->conf) {
        if (d->conf->flags & SER_RS485_ENABLED) {
            if (ioctl(d->devfd , TIOCSRS485, d->conf ) < 0) {
                syslog(LOG_ERR, "Could not set RS485 config for device %s port %s: %m",
                       io->devname,
                       name);
                return -1;
            }
        }
    }
#endif

    sel_set_fd_handlers(ser2net_sel, d->devfd, io,
			io->read_disabled ? NULL : do_read,
			do_write, do_except, devfd_fd_cleared);
    return 0;
}

static void devcfg_shutdown(struct devio *io,
			    void (*shutdown_done)(struct devio *))
{
    struct devcfg_data *d = io->my_data;

    /* To avoid blocking on close if we have written bytes and are in
       flow-control, we flush the output queue. */
    if (d->devfd != -1) {
	d->shutdown_done = shutdown_done;
	sel_clear_fd_handlers(ser2net_sel, d->devfd);
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

    sel_set_fd_read_handler(ser2net_sel, d->devfd,
			    enabled ? SEL_FD_HANDLER_ENABLED :
			    SEL_FD_HANDLER_DISABLED);
}

static void devcfg_write_handler_enable(struct devio *io, int enabled)
{
    struct devcfg_data *d = io->my_data;

    sel_set_fd_write_handler(ser2net_sel, d->devfd,
			     enabled ? SEL_FD_HANDLER_ENABLED :
			     SEL_FD_HANDLER_DISABLED);
}

static void devcfg_except_handler_enable(struct devio *io, int enabled)
{
    struct devcfg_data *d = io->my_data;

    sel_set_fd_except_handler(ser2net_sel, d->devfd,
			      enabled ? SEL_FD_HANDLER_ENABLED :
			      SEL_FD_HANDLER_DISABLED);
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
    return 0;
}

static int devcfg_baud_rate(struct devio *io, int *val, int cisco, int *bps)
{
    struct devcfg_data *d = io->my_data;
    struct termios termio;

    if (tcgetattr(d->devfd, &termio) == -1) {
	*val = 0;
	return -1;
    }

    if ((*val != 0) && (get_baud_rate(*val, val, cisco, bps))) {
	/* We have a valid baud rate. */
	cfsetispeed(&termio, *val);
	cfsetospeed(&termio, *val);
	tcsetattr(d->devfd, TCSANOW, &termio);
    }

    tcgetattr(d->devfd, &termio);
    *val = cfgetispeed(&termio);
    get_rate_from_baud_rate(*val, val, cisco);

    return 0;
}

static int devcfg_data_size(struct devio *io, unsigned char *val, int *bpc)
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
	case 5: termio.c_cflag |= CS5; d->current_data_size = 5; break;
	case 6: termio.c_cflag |= CS6; d->current_data_size = 6; break;
	case 7: termio.c_cflag |= CS7; d->current_data_size = 7; break;
	case 8: termio.c_cflag |= CS8; d->current_data_size = 8; break;
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

static int devcfg_parity(struct devio *io, unsigned char *val, int *bpc)
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
	case 1: d->current_parity_on = 0; break; /* NONE */
	case 2: termio.c_cflag |= PARENB | PARODD; /* ODD */
	    d->current_parity_on = 1;
	    break;
	case 3: termio.c_cflag |= PARENB; /* EVEN */
	    d->current_parity_on = 1;
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

static int devcfg_stop_size(struct devio *io, unsigned char *val, int *bpc)
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
	case 1: d->current_stop_bits = 1; break; /* 1 stop bit */
	case 2: d->current_stop_bits = 2; /* 2 stop bits */
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

static int devcfg_flow_control(struct devio *io, unsigned char val)
{
    struct devcfg_data *d = io->my_data;

    tcflow(d->devfd, val ? TCIOFF : TCION);
    return 0;
}

static int devcfg_control(struct devio *io, unsigned char *val)
{
    struct devcfg_data *d = io->my_data;
    struct termios termio;
    int ival;

    if (tcgetattr(d->devfd, &termio) == -1) {
	*val = 0;
	return -1;
    }

    switch (*val) {
    case 0:
    case 1:
    case 2:
    case 3:
	/* Outbound/both flow control */
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
	break;

    case 13:
    case 14:
    case 15:
    case 16:
    case 17:
    case 18:
    case 19:
	/* Inbound flow-control */
	if (tcgetattr(d->devfd, &termio) != -1) {
	    if (*val == 15) {
		/* We can only set XON/XOFF independently */
		termio.c_iflag |= IXOFF;
		tcsetattr(d->devfd, TCSANOW, &termio);
	    }
	    if (termio.c_cflag & CRTSCTS)
		*val = 16;
	    else if (termio.c_iflag & IXOFF)
		*val = 15;
	    else
		*val = 14;
	}
	break;

	/* Handle BREAK stuff. */
    case 6:
	if (ioctl(d->devfd, TIOCCBRK) != -1)
	    d->break_set = 0;
	goto read_break_val;

    case 5:
	if (ioctl(d->devfd, TIOCSBRK) != -1)
	    d->break_set = 1;
	goto read_break_val;

    case 4:
    read_break_val:
	if (d->break_set)
	    *val = 5;
	else
	    *val = 6;
	break;

    /* DTR handling */
    case 8:
#ifndef __CYGWIN__
	ival = TIOCM_DTR;
	ioctl(d->devfd, TIOCMBIS, &ival);
#else
	ioctl(d->devfd, TIOCMGET, &ival);
	ival |= TIOCM_DTR;
	ioctl(d->devfd, TIOCMSET, &ival);
#endif
	    goto read_dtr_val;

    case 9:
#ifndef __CYGWIN__
	ival = TIOCM_DTR;
	ioctl(d->devfd, TIOCMBIC, &ival);
#else
	ioctl(d->devfd, TIOCMGET, &ival);
	ival &= ~TIOCM_DTR;
	ioctl(d->devfd, TIOCMSET, &ival);
#endif
	goto read_dtr_val;

    case 7:
    read_dtr_val:
	if (ioctl(d->devfd, TIOCMGET, &ival) == -1)
	    *val = 7;
	else if (ival & TIOCM_DTR)
	    *val = 8;
	else
	    *val = 9;
	break;

    /* RTS handling */
    case 11:
#ifndef __CYGWIN__
	ival = TIOCM_RTS;
	ioctl(d->devfd, TIOCMBIS, &ival);
#else
	ioctl(d->devfd, TIOCMGET, &ival);
	ival |= TIOCM_RTS;
	ioctl(d->devfd, TIOCMSET, &ival);
#endif
	goto read_rts_val;

    case 12:
#ifndef __CYGWIN__
	ival = TIOCM_RTS;
	ioctl(d->devfd, TIOCMBIC, &ival);
#else
	ioctl(d->devfd, TIOCMGET, &ival);
	ival &= ~TIOCM_RTS;
	ioctl(d->devfd, TIOCMSET, &ival);
#endif
	goto read_rts_val;

    case 10:
    read_rts_val:
	if (ioctl(d->devfd, TIOCMGET, &ival) == -1)
	    *val = 10;
	else if (ival & TIOCM_RTS)
	    *val = 11;
	else
	    *val = 12;
	break;

    default:
	*val = 0;
	return -1;
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
    .control = devcfg_control,
    .flow_control = devcfg_flow_control,
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

    if (devconfig(d, eout, instr, otherconfig, data) == -1) {
	free(d);
	return -1;
    }

    io->my_data = d;
    io->f = &devcfg_io_f;
    return 0;
}

