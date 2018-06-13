/*
 *  ser2net - A program for allowing telnet connection to serial ports
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

/* Serial device test program. */


#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <stdbool.h>
#include <ctype.h>
#include <readline/readline.h>
#include <readline/history.h>
#include "../selector.h"

struct selector_s *sel;
bool done;
bool exit_nl = false;

static char *skip_spaces(char *s)
{
    while (isspace(*s))
	s++;
    return s;
}

static bool isodigit(char c)
{
    return isdigit(c) && c != '8' && c != '9';
}

static int gettok(char **s, char **tok)
{
    char *t = skip_spaces(*s);
    char *p = t;
    char *o = t;
    char inquote = '\0';
    unsigned int escape = 0;
    unsigned int base = 8;
    char cval = 0;

    if (!*t) {
	*s = t;
	*tok = NULL;
	return 0;
    }

    for (; *p; p++) {
	if (escape) {
	    if (escape == 1) {
		cval = 0;
		if (isodigit(*p)) {
		    base = 8;
		    cval = *p - '0';
		    escape++;
		} else if (*p == 'x') {
		    base = 16;
		    escape++;
		} else {
		    switch (*p) {
		    case 'a': *o++ = '\a'; break;
		    case 'b': *o++ = '\b'; break;
		    case 'f': *o++ = '\f'; break;
		    case 'n': *o++ = '\n'; break;
		    case 'r': *o++ = '\r'; break;
		    case 't': *o++ = '\t'; break;
		    case 'v': *o++ = '\v'; break;
		    default:  *o++ = *p;
		    }
		    escape = 0;
		}
	    } else if (escape >= 2) {
		if (base == 16 && isxdigit(*p) || isodigit(*p)) {
		    if (isodigit(*p))
			cval = cval * base + *p - '0';
		    else if (isupper(*p))
			cval = cval * base + *p - 'A';
		    else
			cval = cval * base + *p - 'a';
		    if (escape >= 3) {
			*o++ = cval;
			escape = 0;
		    } else {
			escape++;
		    }
		} else {
		    *o++ = cval;
		    escape = 0;
		    goto process_char;
		}
	    }
	    continue;
	}
    process_char:
	if (*p == inquote) {
	    inquote = '\0';
	} else if (!inquote && (*p == '\'' || *p == '"')) {
	    inquote = *p;
	} else if (*p == '\\') {
	    escape = 1;
	} else if (!inquote && isspace(*p)) {
	    p++;
	    break;
	} else {
	    *o++ = *p;
	}
    }

    if (base == 8 && escape > 1 || base == 16 && escape > 2) {
	*o++ = cval;
	escape = 0;
    }

    *s = p;
    if (inquote || escape)
	return -1;

    *o = '\0';
    *tok = t;
    return 0;
}

static bool tokeq(const char *t, const char *m)
{
    return strcmp(t, m) == 0;
}

static void
cmd_cb_handler(char *cmdline)
{
    char *tok = NULL;
    char *expansion;
    char **argv = NULL;
    unsigned int argc = 0;
    unsigned int args = 0;
    int i;

    if (!cmdline) {
	printf("\n");
	done = true;
	return;
    }

    i = history_expand(cmdline, &expansion);
    if (i < 0 || i == 2) {
	printf("%s\n", expansion);
	return;
    }

    add_history(expansion);

    argv = malloc(sizeof(*argv) * 10);
    if (!argv) {
	printf("Out of memory allocating arguments\n");
	return;
    }
    args = 10;
		  
    i = gettok(&cmdline, &tok);
    while (tok && !i) {
	if (argc >= args - 1) {
	    char **nargv = realloc(argv, sizeof(*argv) * (args + 10));

	    if (!nargv) {
		printf("Out of memory allocating arguments\n");
		goto out;
	    }
	    argv = nargv;
	    args += 10;
	}
	argv[argc++] = tok;

	i = gettok(&cmdline, &tok);
    }

    if (i) {
	printf("Invalid quoting in string\n");
	goto out;
    }

    if (argc == 0)
	return;

    argv[argc] = NULL; /* NULL terminate the array. */

    if (strcmp(argv[0], "exit") == 0) {
	done = true;
	goto out;
    }

    printf("Got command: %s:", argv[0]);
    for (i = 1; i < argc; i++)
	printf(" '%s'", argv[i]);
    printf("\n");

 out:
    free(argv);
}

static void
stdio_read_ready(int fd, void *cbdata)
{
    rl_callback_read_char();
}

static void
cleanup_term(struct selector_s *sel)
{
    rl_callback_handler_remove();
    printf("\b\b  \b\b");
}

static int
setup_term(struct selector_s *sel)
{
    int rv;

    rv = sel_set_fd_handlers(sel, 0, NULL, stdio_read_ready, NULL, NULL, NULL);
    if (rv)
	return rv;

    rl_initialize();
    rl_callback_handler_install("> ", cmd_cb_handler);

    sel_set_fd_read_handler(sel, 0, SEL_FD_HANDLER_ENABLED);

    return 0;
}

static void
cleanup_sig(int sig)
{
    cleanup_term(sel);
    exit(1);
}

static void
setup_sig(void)
{
    signal(SIGINT, cleanup_sig);
    signal(SIGPIPE, cleanup_sig);
    signal(SIGUSR1, cleanup_sig);
    signal(SIGUSR2, cleanup_sig);
#ifdef SIGPWR
    signal(SIGPWR, cleanup_sig);
#endif
}

int
main(int argc, char *argv[])
{
    int curr_arg = 1;
    const char *arg;
    int rv;

    while ((curr_arg < argc) && (argv[curr_arg][0] == '-')) {
	arg = argv[curr_arg];
	curr_arg++;
	if (strcmp(arg, "--") == 0) {
	    break;
	} else if ((strcmp(arg, "-?") == 0) || (strcmp(arg, "--help") == 0)) {
	    printf("Help!\n");
	    exit(0);
	}
    }

    rv = sel_alloc_selector_nothread(&sel);
    if (rv) {
	fprintf(stderr, "Could not alloc selector: %s\n", strerror(rv));
	exit(1);
    }

    setup_sig();

    rv = setup_term(sel);
    if (rv) {
	fprintf(stderr, "Could not set up terminal: %s\n", strerror(rv));
	exit(1);
    }

    while (!done)
	sel_select(sel, NULL, 0, NULL, NULL);

    cleanup_term(sel);

    return 0;
}
