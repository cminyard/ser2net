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

#ifndef UTILS
#define UTILS

#include <stdbool.h>
#include <termios.h>
#include <sys/time.h> /* struct timeval */

#include "argvutils.h"

/*
 * Returns true if the first strlen(prefix) characters of s are the
 * same as prefix.  If true is returned, val is set to the character
 * after the last byte that compares.
 */
int cmpstrval(const char *s, const char *prefix, const char **val);

struct enum_val
{
    char *str;
    int val;
};

/*
 * Given an enum table (terminated by a NULL str entry), find the
 * given string in the table.  If "len" is not -1, use it to only
 * compare the first "len" chars of str.
 */
int lookup_enum(struct enum_val *enums, const char *str, int len);

/* Return -1 if tv1 < tv2, 0 if tv1 == tv2, and 1 if tv1 > tv2 */
int cmp_timeval(struct timeval *tv1, struct timeval *tv2);

/* Add tv2 to tv1 */
void add_to_timeval(struct timeval *tv1, struct timeval *tv2);

#if ENABLE_PRBUF
#include <stdio.h>
static void prbuf(const unsigned char *buf, unsigned int len)
{
    unsigned int i;

    for (i = 0; i < len; i++) {
       if (i % 16 == 0)
           printf("\n");
       printf(" %2.2x", buf[i]);
    }
    printf("\n");
    fflush(stdout);
}
#endif

#endif /* UTILS */
