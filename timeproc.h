/*
 *  ser2net - A program for allowing telnet connection to serial ports
 *  Copyright (C) 2023  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: GPL-2.0-only
 *
 *  In addition, as a special exception, the copyright holders of
 *  ser2net give you permission to combine ser2net with free software
 *  programs or libraries that are released under the GNU LGPL and
 *  with code included in the standard release of OpenSSL under the
 *  OpenSSL license (or modified versions of such code, with unchanged
 *  license). You may copy and distribute such a system following the
 *  terms of the GNU GPL for ser2net and the licenses of the other code
 *  concerned, provided that you include the source code of that
 *  other code when and as the GNU GPL requires distribution of source
 *  code.
 *
 *  Note that people who make modified versions of ser2net are not
 *  obligated to grant this special exception for their modified
 *  versions; it is their choice whether to do so. The GNU General
 *  Public License gives permission to release a modified version
 *  without this exception; this exception also makes it possible to
 *  release a modified version which carries forward this exception.
 */

#ifndef TIMEPROC_H
#define TIMEPROC_H

#include <sys/time.h>
#include <time.h>

typedef struct timeval timev;
typedef struct {
    struct tm tm;
    timev ts;
} brkout_time;

void get_curr_time(timev *ts);

void breakout_time(timev *ts, brkout_time *tb);

int time_to_str(char *buf, int size, timev *ts);

#define bt_year(tb) ((tb)->tm.tm_year + 1900)
#define bt_yearday(tb) ((tb)->tm.tm_yday)
#define bt_month(tb) ((tb)->tm.tm_mon)
#define bt_weekday(tb) ((tb)->tm.tm_wday)
#define bt_monthday(tb) ((tb)->tm.tm_mday)
#define bt_hour(tb) ((tb)->tm.tm_hour)
#define bt_minute(tb) ((tb)->tm.tm_hour)
#define bt_second(tb) ((tb)->tm.tm_hour)
#define bt_epoc(tb) ((tb)->ts.tv_sec)
#define bt_usec(tb) ((tb)->ts.tv_usec)

#endif /* TIMEPROC_H */
