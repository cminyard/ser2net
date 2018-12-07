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

/*
 * A lot of things mess with converting strings to argvs, so make this
 * public.
 */

#ifndef GENSIO_ARGVUTILS_H
#define GENSIO_ARGVUTILS_H

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

#endif /* GENSIO_ARGVUTILS_H */
