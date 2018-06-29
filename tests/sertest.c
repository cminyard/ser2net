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
#include "utils/waiter.h"
#include "genio/sergenio.h"

struct selector_s *sel;
bool done;

static bool tokeq(const char *t, const char *m)
{
    return strcmp(t, m) == 0;
}

struct genio_list {
    char *name;
    struct genio *io;
    struct genio_list *next;

    struct waiter_s *waiter;
    int read_err;
    int write_err;

    unsigned char *to_write;
    unsigned int to_write_len;

    bool flush_read;
    unsigned char *cmp_read;
    unsigned int cmp_read_len;
};

static struct genio_list *genios;

static struct genio_list *
find_genio(char *name)
{
    struct genio_list *le = genios;

    while (le) {
	if (tokeq(le->name, name))
	    break;
	le = le->next;
    }

    return le;
}

static void
finish_free_genio(struct genio_list *le)
{
    genio_free(le->io);
    free_waiter(le->waiter);
    free(le->name);
    free(le);
}

static void
free_close_done(struct genio *io)
{
    struct genio_list *le = genio_get_user_data(io);

    wake_waiter(le->waiter);
}

static void
free_genios(void)
{
    while (genios) {
	struct genio_list *le = genios;

	genios = le->next;
	if (genio_close(le->io, free_close_done))
	    genio_free(le->io);
	else
	    wait_for_waiter(le->waiter, 1);
	finish_free_genio(le);
    }
}

static int
start_exit(int argc, char **argv, unsigned int *lengths)
{
    done = true;
    return 0;
}

static unsigned int
data_read(struct genio *net, int readerr,
	  unsigned char *buf, unsigned int buflen,
	  unsigned int flags)
{
    struct genio_list *le = genio_get_user_data(net);
    unsigned int to_cmp;
    unsigned int i;

    if (le->flush_read)
	return buflen;

    if (!le->cmp_read) {
	/* FIXME - log this? */
	genio_set_read_callback_enable(le->io, false);
	return 0;
    }

    if (buflen > le->cmp_read_len)
	to_cmp = le->cmp_read_len;
    else
	to_cmp = buflen;

    for (i = 0; i < to_cmp; i++) {
	if (buf[i] != *le->cmp_read) {
	    to_cmp = i; /* Only read up to the last matching value. */
	    le->read_err = EINVAL;
	    goto finish_op;
	}
	le->cmp_read++;
	le->cmp_read_len--;
    }

    if (le->cmp_read_len == 0) {
    finish_op:
	le->cmp_read = NULL;
	genio_set_read_callback_enable(le->io, false);
	wake_waiter(le->waiter);
    }

    return to_cmp;
}

static void
write_ready(struct genio *net)
{
    struct genio_list *le = genio_get_user_data(net);
    unsigned int written;

    if (!le->to_write) {
	/* FIXME - log this? */
	genio_set_write_callback_enable(le->io, false);
	return;
    }

    le->write_err = genio_write(le->io, &written, le->to_write,
				le->to_write_len);
    if (written >= le->to_write_len) {
	genio_set_write_callback_enable(le->io, false);
	le->to_write = NULL;
	le->to_write_len = 0;;
	wake_waiter(le->waiter);
    } else {
	le->to_write += written;
	le->to_write_len -= written;
    }
}

static void
urgent_data_read(struct genio *net)
{
}

struct genio_callbacks gcbs = {
    .read_callback = data_read,
    .write_callback = write_ready,
    .urgent_callback = urgent_data_read,
};

static int
alloc_genio(int argc, char **argv, unsigned int *lengths)
{
    struct genio_list *le;
    int err;

    if (argc < 3) {
	printf("Not enough arguments to function\n");
	return -1;
    }

    le = malloc(sizeof(*le));
    if (!le)
	return ENOMEM;
    memset(le, 0, sizeof(*le));

    le->name = strdup(argv[1]);
    if (!le->name) {
	free(le);
	return ENOMEM;
    }

    le->waiter = alloc_waiter(sel, 0);
    if (!le->waiter) {
	free(le->name);
	free(le);
	return ENOMEM;
    }

    err = str_to_genio(argv[2], sel, 1024, &gcbs, le, &le->io);
    if (err) {
	printf("Error creating genio\n");
	free_waiter(le->waiter);
	free(le->name);
	free(le);
    } else {
	struct genio_list *prev = genios;

	if (!prev) {
	    genios = le;
	} else {
	    while (prev->next)
		prev = prev->next;
	    prev->next = le;
	}
    }

    return err;
}

static int
open_genio(int argc, char **argv, unsigned int *lengths, struct genio_list *le)
{
    int err;

    err = genio_open(le->io);
    if (err)
	printf("Error opening genio\n");

    return err;
}

static void
close_genio_done(struct genio *net)
{
    struct genio_list *le = genio_get_user_data(net);

    wake_waiter(le->waiter);
}

static int
close_genio(int argc, char **argv, unsigned int *lengths, struct genio_list *le)
{
    int err;
    struct timeval timeout = {2, 0};

    err = genio_close(le->io, close_genio_done);
    if (err) {
	printf("Error closing genio\n");
    } else {
	err = wait_for_waiter_timeout(le->waiter, 1, &timeout);
	if (err) {
	    printf("Timeout out waiting for close\n");
	    err = -1;
	}
    }

    return err;
}

static int
free_genio(int argc, char **argv, unsigned int *lengths, struct genio_list *le)
{
    struct genio_list *prev = genios;

    if (prev == le) {
	genios = le->next;
    } else {
	while (prev->next != le)
	    prev = prev->next;
	prev->next = le->next;
    }

    finish_free_genio(le);

    return 0;
}

static int
write_genio(int argc, char **argv, unsigned int *lengths, struct genio_list *le)
{
    le->write_err = 0;
    le->to_write = (unsigned char *) argv[2];
    le->to_write_len = lengths[2];
    genio_set_write_callback_enable(le->io, true);
    wait_for_waiter(le->waiter, 1);
    if (le->write_err)
	printf("Error writing genio\n");

    return le->write_err;
}

static int
read_enable_genio(int argc, char **argv, unsigned int *lengths,
		  struct genio_list *le)
{
    genio_set_read_callback_enable(le->io, true);
    return 0;
}

static int
read_disable_genio(int argc, char **argv, unsigned int *lengths,
		   struct genio_list *le)
{
    genio_set_read_callback_enable(le->io, false);
    return 0;
}

static int
check_read_genio(int argc, char **argv, unsigned int *lengths,
		 struct genio_list *le)
{
    int err;
    struct timeval timeout = { 5, 0 };

    le->read_err = 0;
    le->cmp_read = (unsigned char *) argv[2];
    le->cmp_read_len = lengths[2];
    genio_set_read_callback_enable(le->io, true);
    err = wait_for_waiter_timeout(le->waiter, 1, &timeout);
    if (err) {
	genio_set_read_callback_enable(le->io, false);
	printf("Timeout waiting for read data\n");
	err = -1;
    } else if (le->read_err) {
	printf("Data mismatch reading data\n");
	err = -1;
    }

    return err;
}

static int
flush_read_genio(int argc, char **argv, unsigned int *lengths,
		 struct genio_list *le)
{
    struct timeval timeout = { 1, 0 };

    le->flush_read = true;
    genio_set_read_callback_enable(le->io, true);
    wait_for_waiter_timeout(le->waiter, 1, &timeout);
    le->flush_read = false;

    return 0;
}

static int
xfer_data_genio(int argc, char **argv, unsigned int *lengths,
		struct genio_list *le)
{
    int err = 0;
    unsigned int size, i;
    char *end;
    unsigned char *data;
    struct timeval timeout = { 1, 0 };

    size = strtoul(argv[2], &end, 0);
    if (*end != '\0') {
	printf("Invalid size: %s\n", argv[2]);
	return -1;
    }

    data = malloc(size);
    if (!data)
	return ENOMEM;

    for (i = 0; i < size; i++)
	data[i] = i;

    le->read_err = 0;
    le->write_err = 0;
    le->cmp_read = data;
    le->cmp_read_len = size;
    le->to_write = data;
    le->to_write_len = size;
    genio_set_read_callback_enable(le->io, true);
    genio_set_write_callback_enable(le->io, true);

    while (!le->read_err && !le->write_err && le->cmp_read_len > 0) {
	int err;
	if ((err = sel_select(sel, NULL, 0, NULL, &timeout)) <= 0) {
	    printf("Timeout in operation\n");
	    genio_set_read_callback_enable(le->io, false);
	    genio_set_write_callback_enable(le->io, false);
	    err = -1;
	    break;
	}
    }

    /* Clear these out to avoid abort on exit. */
    if (!le->cmp_read)
	wait_for_waiter(le->waiter, 1);
    if (!le->to_write)
	wait_for_waiter(le->waiter, 1);
    le->cmp_read = NULL;
    le->to_write = NULL;

    if (le->read_err) {
	printf("Data mismatch reading data\n");
	err = -1;
    }
    if (le->write_err) {
	printf("Write error: %s\n", strerror(le->write_err));
	err = -1;
    }

    free(data);

    return err;
}

struct cmd_list {
    const char *name;
    int (*func)(int argc, char **argv, unsigned int *lengths);
    int (*gfunc)(int argc, char **argv, unsigned int *lengths,
		 struct genio_list *le);
};

struct cmd_list cmds[] = {
    { "exit",       .func = start_exit },
    { "connect",    .func = alloc_genio },
    { "open",       .gfunc = open_genio },
    { "close",      .gfunc = close_genio },
    { "free",       .gfunc = free_genio },
    { "write",      .gfunc = write_genio },
    { "read_on",    .gfunc = read_enable_genio },
    { "read_off",   .gfunc = read_disable_genio },
    { "check_read", .gfunc = check_read_genio },
    { "flush_read", .gfunc = flush_read_genio },
    { "xfer",       .gfunc = xfer_data_genio },
    { NULL }
};

static void
cmd_cb_handler(char *cmdline)
{
    char *expansion;
    char **argv = NULL;
    unsigned int *lengths;
    int argc = 0;
    int i, err;

    if (!cmdline) {
	printf("\n");
	done = true;
	return;
    }

    i = history_expand(cmdline, &expansion);
    if (i < 0 || i == 2) {
	printf("%s\n", expansion);
	goto out;
    }

    add_history(expansion);
    rl_free(expansion);

    i = str_to_argv_lengths(cmdline, &argc, &argv, &lengths, NULL);
    if (i == ENOMEM) {
	printf("Out of memory processing command line\n");
	goto out;
    }
    if (i) {
	printf("Invalid quoting in string\n");
	goto out;
    }

    if (argc == 0)
	goto out;

    err = -1;
    for (i = 0; cmds[i].name; i++) {
	if (tokeq(cmds[i].name, argv[0])) {
	    if (cmds[i].gfunc) {
		if (argc < 2) {
		    printf("Not enough arguments to function\n");
		} else {
		    struct genio_list *le = find_genio(argv[1]);
		    if (!le)
			printf("No genio named %s\n", argv[1]);
		    else
			err = cmds[i].gfunc(argc, argv, lengths, le);
		}
	    } else {
		err = cmds[i].func(argc, argv, lengths);
	    }
	    if (err && err != -1)
		printf("Error: %s\n", strerror(i));
	    goto found;
	}
    }

    printf("No command named '%s'\n", argv[0]);

 found:
    str_to_argv_free(argc, argv);

 out:
    rl_free(cmdline);
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
    struct timeval timeout = {0, 0};

    rl_callback_handler_remove();
    printf("\b\b  \b\b");
    sel_clear_fd_handlers(sel, 0);
    while (sel_select(sel, NULL, 0, NULL, &timeout))
	;
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

    free_genios();

    sel_free_selector(sel);

    return 0;
}
