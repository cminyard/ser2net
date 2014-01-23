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

#ifndef SER2NET_IO_H
#define SER2NET_IO_H

#include "dataxfer.h"

struct io_f;

struct io {
    char *devname;
    int read_disabled; /* A printer port */

    void *my_data;
    struct io_f *f;

    void *user_data;
    void (*read_handler)(struct io *io);
    void (*write_handler)(struct io *io);
    void (*except_handler)(struct io *io);
    void (*modem_state_handler)(struct io *io, int modem_state);
};

struct io_f {
    int (*setup)(struct io *io, const char *name, const char **errstr);
    void (*shutdown)(struct io *io);
    int (*reconfig)(struct io *io, struct absout *eout, const char *instr,
	    int (*otherconfig)(void *data, struct absout *eout,
			       const char *item),
	    void *data);
    int (*read)(struct io *io, void *buf, size_t size);
    int (*write)(struct io *io, void *buf, size_t size);
    void (*read_handler_enable)(struct io *io, int enabled);
    void (*write_handler_enable)(struct io *io, int enabled);
    void (*except_handler_enable)(struct io *io, int enabled);
    int (*send_break)(struct io *io);
    int (*get_modem_state)(struct io *io, unsigned char *val);
    int (*set_devcontrol)(struct io *io, const char *controls);
    void (*show_devcontrol)(struct io *io, struct absout *out);
    void (*show_devcfg)(struct io *io, struct absout *out);
    int (*baud_rate)(struct io *io, int *val);
    int (*data_size)(struct io *io, unsigned char *val);
    int (*parity)(struct io *io, unsigned char *val);
    int (*stop_size)(struct io *io, unsigned char *val);
    int (*control)(struct io *io, unsigned char *val);
    int (*flow_control)(struct io *io, unsigned char val);
    int (*flush)(struct io *io, int *val);
    void (*serparm_to_str)(struct io *io, char *str, int strlen);
    void (*free)(struct io *io);
};

#endif /* SER2NET_IO_H */
