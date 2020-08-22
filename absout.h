/*
 *  ser2net - A program for allowing telnet connection to serial ports
 *  Copyright (C) 2001-2020  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef ABSOUT_H
#define ABSOUT_H

struct absout {
    int (*out)(struct absout *e, const char *str, ...);
    void *data;
};
#define abspr(abs, fmt, ...) \
  abs->out(abs, fmt, ##__VA_ARGS__)

#endif /* ABSOUT_H */
