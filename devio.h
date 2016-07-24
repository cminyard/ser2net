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

#include <sys/types.h>

struct absout;
struct devio_f;

struct devio {
    char *devname;
    int read_disabled; /* A printer port */

    void *my_data;
    struct devio_f *f;

    void *user_data;
    void (*read_handler)(struct devio *io);
    void (*write_handler)(struct devio *io);
    void (*except_handler)(struct devio *io);
    void (*modem_state_handler)(struct devio *io, int modem_state);
};

struct devio_f {
    int (*setup)(struct devio *io, const char *name, const char **errstr,
		 int *bps, int *bpc);
    void (*shutdown)(struct devio *io, void (*shutdown_done)(struct devio *));
    int (*reconfig)(struct devio *io, struct absout *eout, const char *instr,
	    int (*otherconfig)(void *data, struct absout *eout,
			       const char *item),
	    void *data);
    int (*read)(struct devio *io, void *buf, size_t size);
    int (*write)(struct devio *io, void *buf, size_t size);
    void (*read_handler_enable)(struct devio *io, int enabled);
    void (*write_handler_enable)(struct devio *io, int enabled);
    void (*except_handler_enable)(struct devio *io, int enabled);
    int (*send_break)(struct devio *io);
    int (*get_modem_state)(struct devio *io, unsigned char *val);
    int (*set_devcontrol)(struct devio *io, const char *controls);
    void (*show_devcontrol)(struct devio *io, struct absout *out);
    void (*show_devcfg)(struct devio *io, struct absout *out);
    int (*baud_rate)(struct devio *io, int *val, int cisco, int *bps);
    int (*data_size)(struct devio *io, unsigned char *val, int *bpc);
    int (*parity)(struct devio *io, unsigned char *val, int *bpc);
    int (*stop_size)(struct devio *io, unsigned char *val, int *bpc);
    int (*control)(struct devio *io, unsigned char *val);
    int (*flow_control)(struct devio *io, unsigned char val);

#define DEVIO_FLUSH_INPUT  (1 << 0)
#define DEVIO_FLUSH_OUTPUT (1 << 1)
    int (*flush)(struct devio *io, int *val);
    void (*serparm_to_str)(struct devio *io, char *str, int strlen);
    void (*free)(struct devio *io);
};

#endif /* SER2NET_IO_H */
