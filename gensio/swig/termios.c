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

#include <sys/ioctl.h>
#include <asm/termbits.h>
#include <string.h>
#include <stdbool.h>
#include <malloc.h>
#if HAVE_DECL_TIOCSRS485
#include <linux/serial.h>
#endif
#include <errno.h>

/*
 * Stolen from glibc, but we can't directly include it from there
 * because the "termios" struct there conflicts with the one from the
 * kernel.
 */
#define UNCCS 32
struct user_termios {
    tcflag_t c_iflag;               /* input mode flags */
    tcflag_t c_oflag;               /* output mode flags */
    tcflag_t c_cflag;               /* control mode flags */
    tcflag_t c_lflag;               /* local mode flags */
    cc_t c_line;                    /* line discipline */
    cc_t c_cc[UNCCS];               /* control characters */
    speed_t c_ispeed;               /* input speed */
    speed_t c_ospeed;               /* output speed */
};

#include <linux-serial-echo/serialsim.h>

int remote_termios(struct user_termios *termios, int fd)
{
    struct termios2 ktermios;
    int rv = ioctl(fd, TIOCSERGREMTERMIOS, &ktermios);
    int i;

    if (rv)
	return errno;

    memset(termios, 0, sizeof(*termios));
    termios->c_iflag = ktermios.c_iflag;
    termios->c_oflag = ktermios.c_oflag;
    termios->c_cflag = ktermios.c_cflag;
    termios->c_lflag = ktermios.c_lflag;
    termios->c_line = ktermios.c_line;
    termios->c_ispeed = ktermios.c_ispeed;
    termios->c_ospeed = ktermios.c_ospeed;
    for (i = 0; i < NCCS; i++)
	termios->c_cc[i] = ktermios.c_cc[i];

    return 0;
}

int
set_remote_mctl(unsigned int mctl, int fd)
{
    if (ioctl(fd, TIOCSERSREMMCTRL, mctl))
	return errno;
    return 0;
}

int
set_remote_sererr(unsigned int err, int fd)
{
    if (ioctl(fd, TIOCSERSREMERR, err))
	return errno;
    return 0;
}

int
set_remote_null_modem(bool val, int fd)
{
    if (ioctl(fd, TIOCSERSREMNULLMODEM, (int) val))
	return errno;
    return 0;
}

int
get_remote_mctl(unsigned int *mctl, int fd)
{
    if (ioctl(fd, TIOCSERGREMMCTRL, mctl))
	return errno;
    return 0;
}

int
get_remote_sererr(unsigned int *err, int fd)
{
    if (ioctl(fd, TIOCSERGREMERR, err))
	return errno;
    return 0;
}

int
get_remote_null_modem(int *val, int fd)
{
    if (ioctl(fd, TIOCSERGREMNULLMODEM, val))
	return errno;
    return 0;
}

void
strdupcat(char **str, const char *cat)
{
    char *s;

    if (!*str)
	return;

    s = malloc(strlen(*str) + strlen(cat) + 2);
    if (!s) {
	free(*str);
	*str = NULL;
	return;
    }

    strcpy(s, *str);
    strcat(s, " ");
    strcat(s, cat);
    free(*str);
    *str = s;
}

int
remote_rs485(int fd, char **rstr)
{
#if HAVE_DECL_TIOCSRS485
    struct serial_rs485 rs485;
    char *str = NULL, tmpstr[20];

    if (ioctl(fd, TIOCSERGREMRS485, &rs485))
	return errno;
    snprintf(tmpstr, sizeof(tmpstr), "%d %d",
	     rs485.delay_rts_before_send, rs485.delay_rts_after_send);
    str = strdup(tmpstr);
    if (rs485.flags & SER_RS485_ENABLED)
	strdupcat(&str, "enabled");
    if (rs485.flags & SER_RS485_RTS_ON_SEND)
	strdupcat(&str, "rts_on_send");
    if (rs485.flags & SER_RS485_RTS_AFTER_SEND)
	strdupcat(&str, "rts_after_send");
    if (rs485.flags & SER_RS485_RX_DURING_TX)
	strdupcat(&str, "rx_during_tx");
#ifdef SER_RS485_TERMINATE_BUS
    if (rs485.flags & SER_RS485_TERMINATE_BUS)
	strdupcat(&str, "terminate_bus");
#endif

    if (!str)
	return ENOMEM;

    *rstr = str;
    return 0;
#else
    return ENOTSUP;
#endif
}
