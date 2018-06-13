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
#include <errno.h>
#include <readline/readline.h>
#include <readline/history.h>
#include "utils/selector.h"
#include "utils/utils.h"

struct selector_s *sel;
bool done;
bool exit_nl = false;

static bool tokeq(const char *t, const char *m)
{
    return strcmp(t, m) == 0;
}

static void
cmd_cb_handler(char *cmdline)
{
    char *expansion;
    char **argv = NULL;
    unsigned int argc = 0;
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

    i = str_to_argv(cmdline, &argc, &argv, NULL);
    if (i == ENOMEM) {
	printf("Out of memory processing command line\n");
	goto out;
    }
    if (i) {
	printf("Invalid quoting in string\n");
	goto out;
    }

    printf("Got command: %s:", argv[0]);
    for (i = 1; i < argc; i++)
	printf(" '%s'", argv[i]);
    printf("\n");

    str_to_argv_free(argc, argv);

 out:
    return;
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
