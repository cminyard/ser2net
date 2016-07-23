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

/* This is the entry point for the ser2net program.  It reads
   parameters, initializes everything, then starts the select loop. */

/* TODO
 *
 * Add some type of security
 */

#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include "ser2net.h"
#include "readconfig.h"
#include "controller.h"
#include "utils.h"
#include "selector.h"
#include "dataxfer.h"

static char *config_file = "/etc/ser2net.conf";
int config_port_from_cmdline = 0;
char *config_port = NULL; /* Can be set from readconfig, too. */
static char *pid_file = NULL;
static int detach = 1;
int ser2net_debug = 0;
int ser2net_debug_level = 0;
#ifdef USE_UUCP_LOCKING
int uucp_locking_enabled = 1;
#endif

selector_t *ser2net_sel;
char *rfc2217_signature = "ser2net";

static char *help_string =
"%s: Valid parameters are:\n"
"  -c <config file> - use a config file besides /etc/ser2net.conf\n"
"  -C <config line> - Handle a single configuration line.  This may be\n"
"     specified multiple times for multiple lines.  This is just like a\n"
"     line in the config file.  This disables the default config file,\n"
"     you must specify a -c after the last -C to have it read a config\n"
"     file, too.\n"
"  -p <controller port> - Start a controller session on the given TCP port\n"
"  -P <file> - set location of pid file\n"
"  -n - Don't detach from the controlling terminal\n"
"  -d - Don't detach and send debug I/O to standard output\n"
"  -l - Increate the debugging level\n"
#ifdef USE_UUCP_LOCKING
"  -u - Disable UUCP locking\n"
#endif
"  -b - unused (was Do CISCO IOS baud-rate negotiation, instead of RFC2217)\n"
"  -v - print the program's version and exit\n"
"  -s - specify a default signature for RFC2217 protocol\n";

static void
reread_config_file(void)
{
    if (config_file) {
	char *prev_config_port = config_port;
	config_port = NULL;
	syslog(LOG_INFO, "Got SIGHUP, re-reading configuration");
	readconfig(config_file);
	if (config_port_from_cmdline) {
	    /* Never override the config port from the command line. */
	    free(config_port);
	    config_port = prev_config_port;
	    goto config_port_unchanged;
	}
	if (config_port && prev_config_port
	    && (strcmp(config_port, prev_config_port) == 0)) {
	    free(prev_config_port);
	    goto config_port_unchanged;
	}

	if (prev_config_port) {
	    controller_shutdown();
	    free(prev_config_port);
	}

	if (config_port) {
	    int rv = controller_init(config_port);
	    if (rv == CONTROLLER_INVALID_TCP_SPEC)
		syslog(LOG_ERR, "Invalid control port specified: %s",
		       config_port);
	    else if (rv == CONTROLLER_OUT_OF_MEMORY)
		syslog(LOG_ERR, "Out of memory opening control port: %s",
		       config_port);
	    else if (rv == CONTROLLER_CANT_OPEN_PORT)
		syslog(LOG_ERR, "Can't open control port: %s",
		       config_port);
	    if (rv) {
		syslog(LOG_ERR, "Control port is disabled");
		free(config_port);
		config_port = NULL;
	    }
	}
    }
 config_port_unchanged:
    return;
}

static void
arg_error(char *name)
{
    fprintf(stderr, help_string, name);
    exit(1);
}

static void
make_pidfile(void)
{
    FILE *fpidfile;
    if (!pid_file)
	return;
    fpidfile = fopen(pid_file, "w");
    if (!fpidfile) {
	syslog(LOG_WARNING,
	       "Error opening pidfile '%s': %m, pidfile not created",
	       pid_file);
	pid_file = NULL;
	return;
    }
    fprintf(fpidfile, "%d\n", getpid());
    fclose(fpidfile);
}

static void
shutdown_cleanly(void)
{
    struct timeval tv;

    free_rotators();
    shutdown_ports();
    do {
	if (check_ports_shutdown())
	    break;
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	sel_select(ser2net_sel, NULL, 0, NULL, &tv);
    } while(1);

    if (pid_file)
	unlink(pid_file);
    exit(1);
}

static int dummyrv; /* Used to ignore return values of read() and write(). */

/* Used to reliably deliver signals to a thread.  This is a pipe that
   we write to from a signal handler to make sure it wakes up. */
static int sig_fd_alert = -1;
static int sig_fd_watch = -1;
static volatile int reread_config = 0; /* Did I get a HUP signal? */
static volatile int term_prog = 0; /* Did I get an INT signal? */

static void sig_wake_selector(void)
{
    char dummy = 0;

    dummyrv = write(sig_fd_alert, &dummy, 1);
}

static void sighup_handler(int sig)
{
    reread_config = 1;
    sig_wake_selector();
}

static void sigint_handler(int sig)
{
    term_prog = 1;
    sig_wake_selector();
}


/* Dummy signal handler, it will just get the data and return. */
static void
sig_fd_read_handler(int fd, void *cb_data)
{
    char dummy[10];

    dummyrv = read(fd, dummy, sizeof(dummy));

    if (term_prog)
	shutdown_cleanly();

    if (reread_config)
	reread_config_file();
}

static void
setup_signals(void)
{
    struct sigaction act;
    int              err;
    int              pipefds[2];

    /* Ignore SIGPIPEs so they don't kill us. */
    signal(SIGPIPE, SIG_IGN);

    err = pipe(pipefds);
    if (err)
	goto out;

    sig_fd_alert = pipefds[1];
    sig_fd_watch = pipefds[0];

    act.sa_handler = sighup_handler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_RESTART;
    err = sigaction(SIGHUP, &act, NULL);
    if (err)
	goto out;

    act.sa_handler = sigint_handler;
    /* Only handle SIGINT once. */
    act.sa_flags |= SA_RESETHAND;
    err = sigaction(SIGINT, &act, NULL);
    if (!err)
	err = sigaction(SIGQUIT, &act, NULL);
    if (!err)
	err = sigaction(SIGTERM, &act, NULL);
    if (err)
	goto out;

    sel_set_fd_handlers(ser2net_sel, sig_fd_watch, NULL, sig_fd_read_handler,
			NULL, NULL, NULL);
    sel_set_fd_read_handler(ser2net_sel, sig_fd_watch, SEL_FD_HANDLER_ENABLED);

 out:
    if (err) {
	fprintf(stderr, "Error setting up signals: %s\n", strerror(err));
	exit(1);
    }
}

int
main(int argc, char *argv[])
{
    int i;
    int err;

    err = sel_setup(NULL, NULL, NULL, NULL);
    if (err) {
	fprintf(stderr,	"Could not setup signal: '%s'\n", strerror(err));
	return -1;
    }

    err = sel_alloc_selector(&ser2net_sel);
    if (err) {
	fprintf(stderr,
		"Could not initialize ser2net selector: '%s'\n",
		strerror(err));
	return -1;
    }

    setup_signals();

    err = sol_init();
    if (err) {
	fprintf(stderr,
		"Could not initialize IPMI SOL: '%s'\n",
		strerror(-err));
	return -1;
    }

    for (i=1; i<argc; i++) {
	if ((argv[i][0] != '-') || (strlen(argv[i]) != 2)) {
	    fprintf(stderr, "Invalid argument: '%s'\n", argv[i]);
	    arg_error(argv[0]);
	}

	switch (argv[i][1]) {
	case 'n':
	    detach = 0;
	    break;

	case 'd':
	    detach = 0;
	    ser2net_debug = 1;
	    break;

	case 'l':
	    ser2net_debug_level++;
	    break;

	case 'b':
	    break;

	case 'C':
	    /* Get a config line. */
	    i++;
	    if (i == argc) {
		fprintf(stderr, "No config line specified with -C\n");
		arg_error(argv[0]);
	    }
	    handle_config_line(argv[i]);
	    config_file = NULL;
	    break;

	case 'c':
	    /* Get a config file. */
	    i++;
	    if (i == argc) {
		fprintf(stderr, "No config file specified with -c\n");
		arg_error(argv[0]);
	    }
	    config_file = argv[i];
	    break;

	case 'p':
	    /* Get the control port. */
	    i++;
	    if (i == argc) {
		fprintf(stderr, "No control port specified with -p\n");
		arg_error(argv[0]);
	    }
	    config_port = strdup(argv[i]);
	    if (!config_port) {
		fprintf(stderr, "Could not allocate memory for -p\n");
		exit(1);
	    }
	    config_port_from_cmdline = 1;
	    break;
	
	case 'P':
	    i++;
	    if (i == argc) {
		fprintf(stderr, "No pid file specified with -P\n");
		arg_error(argv[0]);
	    }
	    pid_file = argv[i];
	    break;

#ifdef USE_UUCP_LOCKING
	case 'u':
	    uucp_locking_enabled = 0;
	    break;
#endif

	case 'v':
	    printf("%s version %s\n", argv[0], VERSION);
	    exit(0);

	case 's':
            i++;
            if (i == argc) {
	        fprintf(stderr, "No signature specified\n");
		exit(1);
            }
            rfc2217_signature = argv[i];
            break;

	default:
	    fprintf(stderr, "Invalid option: '%s'\n", argv[i]);
	    arg_error(argv[0]);
	}
    }

    if (ser2net_debug && !detach)
	openlog("ser2net", LOG_PID | LOG_CONS | LOG_PERROR, LOG_DAEMON);

    if (config_file) {
	if (readconfig(config_file) == -1) {
	    return 1;
	}
    }

    if (config_port != NULL) {
	int rv;
	rv = controller_init(config_port);
	if (rv == CONTROLLER_INVALID_TCP_SPEC) {
	    fprintf(stderr, "Invalid control port specified: %s\n",
		    config_port);
	    arg_error(argv[0]);
	}
	if (rv == CONTROLLER_CANT_OPEN_PORT) {
	    fprintf(stderr, "Unable to open control port, see syslog: %s\n",
		    config_port);
	    exit(1);
	}
    }

    if (detach) {
	int pid;

	/* Detach from the calling terminal. */
	openlog("ser2net", LOG_PID | LOG_CONS, LOG_DAEMON);
	syslog(LOG_NOTICE, "ser2net startup");
	if ((pid = fork()) > 0) {
	    exit(0);
	} else if (pid < 0) {
	    syslog(LOG_ERR, "Error forking first fork: %s", strerror(errno));
	    exit(1);
	} else {
	    /* setsid() is necessary if we really want to demonize */
	    setsid();
	    /* Second fork to really deamonize me. */
	    if ((pid = fork()) > 0) {
		exit(0);
	    } else if (pid < 0) {
		syslog(LOG_ERR, "Error forking second fork: %s",
		       strerror(errno));
		exit(1);
	    }
	}

	/* Close all my standard I/O. */
	if (chdir("/") < 0) {
	    syslog(LOG_ERR, "unable to chdir to '/': %s", strerror(errno));
	    exit(1);
	}
	close(0);
	close(1);
	close(2);
    }

    /* write pid file */
    make_pidfile();

    sel_select_loop(ser2net_sel, NULL, 0, NULL);

    return 0;
}

