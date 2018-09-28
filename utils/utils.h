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

/* Returns true if the string is a numeric zero, false if not. */
int strisallzero(const char *str);

/*
 * Returns true if the first strlen(prefix) characters of s are the
 * same as prefix.  If true is returned, val is set to the character
 * after the last byte that compares.
 */
int cmpstrval(const char *s, const char *prefix, const char **val);

/* Scan for a positive integer, and return it.  Return -1 if the
   integer was invalid.  Spaces are not handled. */
int scan_int(const char *str);

/* Write the data completely out, return without comment on error. */
void write_ignore_fail(int fd, const char *data, size_t count);

/* Separate out a string into an argv array, returning the argc/argv
   values given.  Returns -ENOMEM when out of memory or -EINVAL if
   there is something wrong with the string.  seps is a list of
   separators, parameters will be separated by that vlaue.  If seps is
   NULL it will default to the equivalent of isspace().  The argv
   array must be freed with str_to_argv_free(). */
int str_to_argv(const char *s, int *argc, char ***argv, char *seps);

/*
 * Like above, but give the lengths of each argv entry in the lengths
 * array.  The lengths array is automatically freed as part of
 * str_to_argv_free().  Note that the length does not include the
 * ending '\0'.
 */
int str_to_argv_lengths(const char *s, int *argc, char ***argv,
			unsigned int **lengths,
			char *seps);

/*
 * Like the above, but allows a set of characters to be specified that
 * end the sequence, in "endchars".  If the scanner encounters one of
 * those characters outside of an escape or quotes, it will terminate
 * the scan.  If nextptr is not NULL, it sets it to a pointer to after
 * the end character if the end character was encountered, or sets it
 * to NULL if the end character was not encountered.
 */
int str_to_argv_lengths_endchar(const char *ins, int *r_argc, char ***r_argv,
				unsigned int **r_lengths, char *seps,
				char *endchars, const char **nextptr);

/* Free the return of str_to_argv */
void str_to_argv_free(int argc, char **argv);

struct absout {
    int (*out)(struct absout *e, const char *str, ...);
    void *data;
};
#define abspr(abs, fmt, ...) \
  abs->out(abs, fmt, ##__VA_ARGS__)

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

/* Subtract tv2 from tv1 */
void sub_from_timeval(struct timeval *tv1, struct timeval *tv2);

void add_usec_to_timeval(struct timeval *tv, int usec);

int sub_timeval_us(struct timeval *left, struct timeval *right);

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
