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

#include "timeproc.h"

#ifdef WIN32
static struct tm *
localtime_r(long *sec, struct tm *tm)
{
    time_t tsec = *sec;
    localtime_s(tm, &tsec);
    return tm;
}
#endif

void
get_curr_time(timev *ts)
{
    gettimeofday(ts, NULL);
}

void
breakout_time(timev *ts, brkout_time *tb)
{
    localtime_r(&ts->tv_sec, &tb->tm);
    tb->ts = *ts;
}

int
time_to_str(char *buf, int size, timev *ts)
{
    struct tm tm;

    return strftime(buf, size, "%Y/%m/%d %H:%M:%S ",
		    localtime_r(&ts->tv_sec, &tm));
}
