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
 * Add getty support and UUCP locking
 * Add some type of security
 */

#include <stdio.h>
#include <signal.h>
#include <syslog.h>
#include <sys/types.h>
#include <unistd.h>

#include "readconfig.h"
#include "controller.h"
#include "utils.h"
#include "selector.h"
#include "dataxfer.h"

static char *config_file = "/etc/ser2net.conf";
static char *config_port = NULL;
static int detach = 1;
static int debug = 0;
#ifdef USE_UUCP_LOCKING
int uucp_locking_enabled = 1;
#endif

static char *help_string =
"%s: Valid parameters are:\n"
"  -c <config file> - use a config file besides /etc/ser2net.conf\n"
"  -p <controller port> - Start a controller session on the given TCP port\n"
"  -n - Don't detach from the controlling terminal\n"
"  -d - Don't detach and send debug I/O to standard output\n"
#ifdef USE_UUCP_LOCKING
"  -u - Disable UUCP locking\n"
#endif
"  -v - print the program's version and exit\n";

void
reread_config(void)
{
    syslog(LOG_INFO, "Got SIGHUP, re-reading configuration");
    readconfig(config_file);
}

void
arg_error(char *name)
{
    fprintf(stderr, help_string, name);
    exit(1);
}

int
main(int argc, char *argv[])
{
    int i;

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
	    debug = 1;
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
	    config_port = argv[i];
	    break;

#ifdef USE_UUCP_LOCKING
	case 'u':
	    uucp_locking_enabled = 0;
	    break;
#endif

	case 'v':
	    printf("%s version %s\n", argv[0], VERSION);
	    exit(0);

	default:
	    fprintf(stderr, "Invalid option: '%s'\n", argv[i]);
	    arg_error(argv[0]);
	}
    }

    selector_init();
    dataxfer_init();
    if (config_port != NULL) {
	if (controller_init(config_port) == -1) {
	    fprintf(stderr, "Invalid control port specified with -p\n");
	    arg_error(argv[0]);
	}
    }

    if (readconfig(config_file) == -1) {
	return 1;
    }

    if (detach) {
	int pid;

	/* Detach from the calling terminal. */
	openlog("ser2net", LOG_PID | LOG_CONS, LOG_DAEMON);
	if ((pid = fork()) > 0) {
	    exit(0);
	} else if (pid < 0) {
	    syslog(LOG_ERR, "Error forking first fork");
	    exit(1);
	} else {
	    /* setsid() is necessary if we really want to demonize */
	    setsid();
	    /* Second fork to really deamonize me. */
	    if ((pid = fork()) > 0) {
		exit(0);
	    } else if (pid < 0) {
		syslog(LOG_ERR, "Error forking second fork");
		exit(1);
	    }
	}

	/* Close all my standard I/O. */
	chdir("/");
	close(0);
	close(1);
	close(2);
    } else if (debug) {
	openlog("ser2net", LOG_PID | LOG_CONS | LOG_PERROR, LOG_DAEMON);
    }

    /* Ignore SIGPIPEs so they don't kill us. */
    signal(SIGPIPE, SIG_IGN);

    set_sighup_handler(reread_config);

    select_loop();

    return 0;
}

