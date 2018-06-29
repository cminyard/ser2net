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
#include <stdarg.h>
#include <readline/readline.h>
#include <readline/history.h>
#include "utils/selector.h"
#include "utils/utils.h"
#include "utils/waiter.h"
#include "genio/sergenio.h"

static bool tokeq(const char *t, const char *m)
{
    return strcmp(t, m) == 0;
}

struct sertest_context;

struct genio_list {
    char *name;
    struct genio *io;
    struct sertest_context *c;
    struct genio_list *next;

    struct waiter_s *waiter;
    int read_err;
    int write_err;

    unsigned char *to_write;
    unsigned int to_write_len;

    bool flush_read;
    unsigned char *cmp_read;
    unsigned int cmp_read_len;
    unsigned int curr_read_byte;
    unsigned char expected;
    unsigned char got;
};

struct sertest_context {
    struct selector_s *sel;
    bool *done;
    struct genio_list *genios;
    struct absout *out;
    int debug;
};

#define dbgout(c, level, fmt, ...)		\
    do { if (c->debug >= level) abspr(c->out, fmt, ##__VA_ARGS__); } while(0)

static struct genio_list *
find_genio(struct sertest_context *c, char *name)
{
    struct genio_list *le = c->genios;

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

void
sertest_cleanup(struct sertest_context *c)
{
    while (c->genios) {
	struct genio_list *le = c->genios;

	c->genios = le->next;
	if (genio_close(le->io, free_close_done)) {
	    /* Already closed, just free it. */
	    genio_free(le->io);
	} else {
	    wait_for_waiter(le->waiter, 1);
	    genio_free(le->io);
	}
	finish_free_genio(le);
    }
    free(c);
}

static int
start_exit(struct sertest_context *c,
	   int argc, char **argv, unsigned int *lengths)
{
    *(c->done) = true;
    return 0;
}

static unsigned int
data_read(struct genio *net, int readerr,
	  unsigned char *buf, unsigned int buflen,
	  unsigned int flags)
{
    struct genio_list *le = genio_get_user_data(net);
    struct sertest_context *c = le->c;
    unsigned int to_cmp;
    unsigned int i;

    if (le->flush_read) {
	dbgout(c, 1, "flush %u bytes\n", buflen);
	return buflen;
    }

    if (!le->cmp_read) {
	dbgout(c, 1, "***No read data on read handler call\n");
	genio_set_read_callback_enable(le->io, false);
	return 0;
    }

    dbgout(c, 2, "Data read with %u bytes, %u to compare\n",
	   buflen, le->cmp_read_len);
    if (buflen > le->cmp_read_len)
	to_cmp = le->cmp_read_len;
    else
	to_cmp = buflen;

    for (i = 0; i < to_cmp; i++) {
	if (buf[i] != *le->cmp_read) {
	    to_cmp = i; /* Only read up to the last matching value. */
	    le->expected = *le->cmp_read;
	    le->got = buf[i];
	    le->read_err = EINVAL;
	    dbgout(c, 1, "Read compare fail at %u bytes, "
		   "expected %2.2x, got %2.2x\n", le->curr_read_byte,
		   le->expected, le->got);
	    goto finish_op;
	}
	le->cmp_read++;
	le->cmp_read_len--;
	le->curr_read_byte++;
    }

    if (le->cmp_read_len == 0) {
	dbgout(c, 1, "Read completed %u bytes\n", le->curr_read_byte);
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
    struct sertest_context *c = le->c;
    unsigned int written = 0;

    if (!le->to_write) {
	dbgout(c, 1, "Write ready with no write data\n");
	genio_set_write_callback_enable(le->io, false);
	return;
    }

    le->write_err = genio_write(le->io, &written, le->to_write,
				le->to_write_len);
    if (le->write_err || written >= le->to_write_len) {
	dbgout(c, 2, "Write finished, err=%d, count=%d\n",
	       le->write_err, written);
	genio_set_write_callback_enable(le->io, false);
	le->to_write = NULL;
	le->to_write_len = 0;
	wake_waiter(le->waiter);
    } else {
	dbgout(c, 2, "Partial write, count=%d\n", written);
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
alloc_genio(struct sertest_context *c,
	    int argc, char **argv, unsigned int *lengths)
{
    struct genio_list *le;
    int err;

    if (argc < 3) {
	abspr(c->out, "Not enough arguments to function\n");
	return -1;
    }

    le = find_genio(c, argv[1]);
    if (le) {
	abspr(c->out, "Name '%s' is already in use\n", argv[1]);
	return -1;
    }

    le = malloc(sizeof(*le));
    if (!le)
	return ENOMEM;
    memset(le, 0, sizeof(*le));
    le->c = c;

    le->name = strdup(argv[1]);
    if (!le->name) {
	free(le);
	return ENOMEM;
    }

    le->waiter = alloc_waiter(c->sel, 0);
    if (!le->waiter) {
	free(le->name);
	free(le);
	return ENOMEM;
    }

    err = str_to_genio(argv[2], c->sel, 1024, &gcbs, le, &le->io);
    if (err) {
	abspr(c->out, "Error creating genio\n");
	free_waiter(le->waiter);
	free(le->name);
	free(le);
    } else {
	struct genio_list *prev = c->genios;

	if (!prev) {
	    c->genios = le;
	} else {
	    while (prev->next)
		prev = prev->next;
	    prev->next = le;
	}
    }

    return err;
}

static int
open_genio(struct sertest_context *c,
	   int argc, char **argv, unsigned int *lengths, struct genio_list *le)
{
    int err;

    err = genio_open(le->io);
    if (err)
	abspr(c->out, "Error opening genio\n");

    return err;
}

static void
close_genio_done(struct genio *net)
{
    struct genio_list *le = genio_get_user_data(net);

    wake_waiter(le->waiter);
}

static int
close_genio(struct sertest_context *c,
	    int argc, char **argv, unsigned int *lengths, struct genio_list *le)
{
    int err;
    struct timeval timeout = {2, 0};

    err = genio_close(le->io, close_genio_done);
    if (err) {
	abspr(c->out, "Error closing genio\n");
    } else {
	err = wait_for_waiter_timeout(le->waiter, 1, &timeout);
	if (err) {
	    abspr(c->out, "Timeout out waiting for close\n");
	    err = -1;
	}
    }

    return err;
}

static int
free_genio(struct sertest_context *c,
	   int argc, char **argv, unsigned int *lengths, struct genio_list *le)
{
    struct genio_list *prev = c->genios;

    if (prev == le) {
	c->genios = le->next;
    } else {
	while (prev->next != le)
	    prev = prev->next;
	prev->next = le->next;
    }

    genio_free(le->io);
    finish_free_genio(le);

    return 0;
}

static int
write_genio(struct sertest_context *c,
	    int argc, char **argv, unsigned int *lengths, struct genio_list *le)
{
    struct timeval timeout = {5, 0};
    int err;

    le->write_err = 0;
    le->to_write = (unsigned char *) argv[2];
    le->to_write_len = lengths[2];
    genio_set_write_callback_enable(le->io, true);
    err = wait_for_waiter_timeout(le->waiter, 1, &timeout);
    if (err) {
	abspr(c->out, "Timed out writing genio\n");
	genio_set_write_callback_enable(le->io, true);
	le->to_write = NULL;
    }
    if (le->write_err)
	abspr(c->out, "Error writing genio\n");

    return le->write_err;
}

static int
read_enable_genio(struct sertest_context *c,
		  int argc, char **argv, unsigned int *lengths,
		  struct genio_list *le)
{
    genio_set_read_callback_enable(le->io, true);
    return 0;
}

static int
read_disable_genio(struct sertest_context *c,
		   int argc, char **argv, unsigned int *lengths,
		   struct genio_list *le)
{
    genio_set_read_callback_enable(le->io, false);
    return 0;
}

static int
check_read_genio(struct sertest_context *c,
		 int argc, char **argv, unsigned int *lengths,
		 struct genio_list *le)
{
    int err;
    struct timeval timeout = { 5, 0 };

    le->read_err = 0;
    le->cmp_read = (unsigned char *) argv[2];
    le->cmp_read_len = lengths[2];
    le->curr_read_byte = 0;
    genio_set_read_callback_enable(le->io, true);
    err = wait_for_waiter_timeout(le->waiter, 1, &timeout);
    if (err) {
	genio_set_read_callback_enable(le->io, false);
	abspr(c->out, "Timeout waiting for read data\n");
	err = -1;
    } else if (le->read_err) {
	abspr(c->out, "Data mismatch reading data at byte %d, "
	       "expected %2.2x but got %2.2x\n",
	       le->curr_read_byte, le->expected, le->got);
	err = -1;
    }

    return err;
}

static int
flush_read_genio(struct sertest_context *c,
		 int argc, char **argv, unsigned int *lengths,
		 struct genio_list *le)
{
    struct timeval timeout = { 1, 0 };

    le->flush_read = true;
    genio_set_read_callback_enable(le->io, true);
    wait_for_waiter_timeout(le->waiter, 1, &timeout);
    genio_set_read_callback_enable(le->io, false);
    le->flush_read = false;

    return 0;
}

static int
xfer_data_genio(struct sertest_context *c,
		int argc, char **argv, unsigned int *lengths,
		struct genio_list *le)
{
    int err = 0;
    unsigned int size, i;
    char *end;
    unsigned char *data;
    struct timeval timeout = { 1, 0 };
    struct genio_list *le2;
    struct timeval test_time, now;
    unsigned int last_read;

    if (argc < 4) {
	abspr(c->out, "Not enough arguments to function\n");
	return -1;
    }

    le2 = find_genio(c, argv[2]);
    if (!le2) {
	abspr(c->out, "No genio named %s\n", argv[2]);
	return -1;
    }

    size = strtoul(argv[3], &end, 0);
    if (*end != '\0') {
	abspr(c->out, "Invalid size: %s\n", argv[2]);
	return -1;
    }

    data = malloc(size);
    if (!data)
	return ENOMEM;

    for (i = 0; i < size; i++)
	data[i] = i;

    sel_get_monotonic_time(&test_time);
    test_time.tv_sec += 5;

    le2->read_err = 0;
    le->write_err = 0;
    le2->cmp_read = data;
    le2->cmp_read_len = size;
    le2->curr_read_byte = 0;
    le->to_write = data;
    le->to_write_len = size;
    genio_set_read_callback_enable(le2->io, true);
    genio_set_write_callback_enable(le->io, true);

    last_read = le2->cmp_read_len;
    while (!le2->read_err && !le->write_err && le2->cmp_read_len > 0) {
	sel_select(c->sel, NULL, 0, NULL, &timeout);
	sel_get_monotonic_time(&now);
	if (cmp_timeval(&now, &test_time) >= 0) {
	    if (last_read == le2->cmp_read_len) {
		/* No progress in 5 seconds. */
		abspr(c->out, "Timeout in operation\n");
		genio_set_read_callback_enable(le2->io, false);
		genio_set_write_callback_enable(le->io, false);
		err = -1;
		break;
	    }
	    last_read = le2->cmp_read_len;
	    test_time = now;
	    test_time.tv_sec += 5;
	}
    }

    /* Clear these out to avoid abort on exit. */
    if (!le2->cmp_read)
	wait_for_waiter(le2->waiter, 1);
    if (!le->to_write)
	wait_for_waiter(le->waiter, 1);
    le2->cmp_read = NULL;
    le->to_write = NULL;

    if (le2->read_err) {
	abspr(c->out, "Data mismatch reading data at byte %d, "
	       "expected %2.2x but got %2.2x\n",
	       le2->curr_read_byte, le2->expected, le2->got);
    }
    if (le->write_err) {
	abspr(c->out, "Write error: %s\n", strerror(le->write_err));
	err = -1;
    }

    free(data);

    return err;
}

struct cmd_list {
    const char *name;
    int (*func)(struct sertest_context *c,
		int argc, char **argv, unsigned int *lengths);
    int (*gfunc)(struct sertest_context *c,
		 int argc, char **argv, unsigned int *lengths,
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

int
sertest_cmd(struct sertest_context *c, char *cmdline)
{
    char **argv = NULL;
    unsigned int *lengths;
    int argc = 0;
    int i, err;

    err = str_to_argv_lengths(cmdline, &argc, &argv, &lengths, NULL);
    if (err == ENOMEM) {
	abspr(c->out, "Out of memory processing command line\n");
	return -1;
    }
    if (err) {
	abspr(c->out, "Invalid quoting in string\n");
	return -1;
    }

    if (argc == 0)
	return 0;

    err = -1;
    for (i = 0; cmds[i].name; i++) {
	if (tokeq(cmds[i].name, argv[0])) {
	    if (cmds[i].gfunc) {
		if (argc < 2) {
		    abspr(c->out, "Not enough arguments to function\n");
		} else {
		    struct genio_list *le = find_genio(c, argv[1]);
		    if (!le)
			abspr(c->out, "No genio named %s\n", argv[1]);
		    else
			err = cmds[i].gfunc(c, argc, argv, lengths, le);
		}
	    } else {
		err = cmds[i].func(c, argc, argv, lengths);
	    }
	    goto found;
	}
    }

    abspr(c->out, "No command named '%s'\n", argv[0]);

 found:
    str_to_argv_free(argc, argv);

    return err;
}

struct sertest_context *
sertest_alloc_context(struct selector_s *sel, bool *done, struct absout *out,
		      int debug)
{
    struct sertest_context *c;

    c = malloc(sizeof(*c));
    if (!c)
	return NULL;
    memset(c, 0, sizeof(*c));
    c->sel = sel;
    c->done = done;
    c->out = out;
    c->debug = debug;

    return c;
}

bool my_done;
struct sertest_context *c;
struct selector_s *my_sel;
int debug;

static void
cmd_cb_handler(char *cmdline)
{
    char *expansion;
    int i, err;

    if (!cmdline) {
	printf("\n");
	my_done = true;
	return;
    }

    i = history_expand(cmdline, &expansion);
    if (i < 0 || i == 2) {
	printf("%s\n", expansion);
	goto out;
    }

    add_history(expansion);
    rl_free(expansion);

    err = sertest_cmd(c, cmdline);
    if (err && err != -1)
	printf("Error: %s\n", strerror(i));

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
    cleanup_term(my_sel);
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

static int
pr_out(struct absout *o, const char *fmt, ...)
{
    int rv;
    va_list ap;

    va_start(ap, fmt);
    rv = vprintf(fmt, ap);
    va_end(ap);

    return rv;
}

static void
process_file(const char *filename)
{
    char *buf = NULL, *p;
    int bufsize = 0;
    int readpos = 0;
    FILE *f;
    struct absout my_out = { .out = pr_out, .data = NULL };
    int err;
    struct timeval zerotime = {0, 0};

    c = sertest_alloc_context(my_sel, &my_done, &my_out, debug);
    if (!c) {
	fprintf(stderr, "Could not allocate sertest context\n");
	exit(1);
    }

    f = fopen(filename, "r");
    if (!f) {
	fprintf(stderr, "Error opening '%s'\n", filename);
	exit(1);
    }

    while (true) {
	if (readpos >= bufsize - 1) {
	    char *nb;

	    bufsize += 100;
	    nb = realloc(buf, bufsize);
	    if (!nb) {
		fprintf(stderr, "Out of memory reading commands\n");
		exit(1);
	    }
	    buf = nb;
	}
	if (!fgets(buf + readpos, bufsize - readpos, f))
	    break;
	readpos = strlen(buf + readpos);
	if (readpos >= bufsize - 1 && buf[readpos - 1] != '\n')
	    /* Didn't get all the line, continue reading. */
	    continue;

	if (readpos == 0)
	    continue;
	if (buf[readpos - 1] == '\n')
	    buf[--readpos] = '\0';
	if (readpos == 0)
	    continue;
	if (buf[readpos - 1] == '\\') {
	    buf[--readpos] = '\0';
	    continue;
	}
	p = buf;
	while (*p && isspace(*p))
	    p++;

	printf("EX: %s\n", p);
	if (*p != '#') {
	    err = sertest_cmd(c, p);
	    if (err) {
		if (err != -1)
		    printf("Error: %s\n", strerror(err));
		exit(1);
	    }
	}
	readpos = 0;
    }

    fclose(f);
    free(buf);

    sertest_cleanup(c);

    while (sel_select(my_sel, NULL, 0, NULL, &zerotime) > 0)
	;
}

static void
interactive_term(void)
{
    struct absout my_out = { .out = pr_out, .data = NULL };
    int rv;

    c = sertest_alloc_context(my_sel, &my_done, &my_out, debug);
    if (!c) {
	fprintf(stderr, "Could not allocate sertest context\n");
	exit(1);
    }

    rv = setup_term(my_sel);
    if (rv) {
	fprintf(stderr, "Could not set up terminal: %s\n", strerror(rv));
	exit(1);
    }

    while (!my_done)
	sel_select(my_sel, NULL, 0, NULL, NULL);

    cleanup_term(my_sel);

    sertest_cleanup(c);
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
	} else if ((strcmp(arg, "-d") == 0) || (strcmp(arg, "--debug") == 0)) {
	    debug++;
	} else if ((strcmp(arg, "-?") == 0) || (strcmp(arg, "--help") == 0)) {
	    printf("Help!\n");
	    exit(0);
	}
    }

    rv = sel_alloc_selector_nothread(&my_sel);
    if (rv) {
	fprintf(stderr, "Could not alloc selector: %s\n", strerror(rv));
	exit(1);
    }

    setup_sig();

    if (curr_arg < argc) {
	for (; curr_arg < argc; curr_arg++)
	    process_file(argv[curr_arg]);
    } else {
	interactive_term();
    }

    sel_free_selector(my_sel);

    return 0;
}
