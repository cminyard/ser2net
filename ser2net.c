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

#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include <gensio/selector.h>
#include <gensio/gensio_selector.h>

#include "ser2net.h"
#include "readconfig.h"
#include "controller.h"
#include "dataxfer.h"
#include "led.h"

static char *config_file = SYSCONFDIR "/ser2net/ser2net.yaml";
static bool config_file_set = false;
static char *old_config_file = SYSCONFDIR "/ser2net.conf";
bool admin_port_from_cmdline = false;
char *admin_port = NULL; /* Can be set from readconfig, too. */
static char *pid_file = NULL;
static int detach = 1;
int ser2net_debug = 0;
int ser2net_debug_level = 0;
volatile int in_shutdown = 0;
#ifdef USE_PTHREADS
#include <pthread.h>
int num_threads = 1;
struct thread_info {
    pthread_t id;
};
struct thread_info *threads;
#endif


struct selector_s *ser2net_sel;
struct gensio_os_funcs *so;
char *rfc2217_signature = "ser2net";

static char *help_string =
"%s: Valid parameters are:\n"
"  -c <config file> - use a config file besides /etc/ser2net/ser2net.yaml\n"
"  -C <config line> - Handle a single configuration line.  This may be\n"
"     specified multiple times for multiple lines.  This is just like a\n"
"     line in the config file.  This disables the default config file,\n"
"     you must specify a -c after the last -C to have it read a config\n"
"     file, too.\n"
"  -p <controller port> - Start a controller session on the given TCP port\n"
"  -P <file> - set location of pid file\n"
"  -n - Don't detach from the controlling terminal\n"
"  -d - Don't detach and send debug I/O to standard output\n"
"  -l - Increase the debugging level\n"
"  -u - Disable UUCP locking\n"
#ifdef USE_PTHREADS
"  -t <num threads> - Use the given number of threads, default 1\n"
#endif
"  -b - unused (was Do CISCO IOS baud-rate negotiation, instead of RFC2217)\n"
"  -v - print the program's version and exit\n"
"  -s - specify a default signature for RFC2217 protocol\n";

static bool
str_endswith(const char *str, const char *end)
{
    unsigned int slen = strlen(str);
    unsigned int elen = strlen(end);

    if (elen > slen)
	return false;
    if (strcmp(end, str + slen - elen) == 0)
	return true;
    return false;
}

static FILE *
fopen_config_file(bool *is_yaml)
{
    FILE *instream = fopen(config_file, "r");

    if (!instream) {
	if (config_file_set) {
	    syslog(LOG_ERR, "Unable to open config file '%s': %m",
		   config_file);
	    return NULL;
	}
	instream = fopen(old_config_file, "r");
	if (!instream) {
	    syslog(LOG_ERR, "Unable to open config file '%s' or old one"
		   " '%s': %m", config_file, old_config_file);
	    return NULL;
	}
	*is_yaml = false;
    } else {
	*is_yaml = str_endswith(config_file, ".yaml");
    }
    return instream;
}

static void
reread_config_file(void)
{
    if (config_file) {
	FILE *instream = NULL;
	bool is_yaml;

	syslog(LOG_INFO, "Got SIGHUP, re-reading configuration");
	readconfig_init();

	instream = fopen_config_file(&is_yaml);
	if (!instream)
	    goto out;

	if (!admin_port_from_cmdline)
	    controller_shutdown();
	if (is_yaml)
	    yaml_readconfig(instream);
	else
	    readconfig(instream);
	fclose(instream);

	readconfig_finalize();
    }
 out:
    return;
}

void
write_ignore_fail(int fd, const char *data, size_t count)
{
    ssize_t written;

    while ((written = write(fd, data, count)) > 0) {
	data += written;
	count -= written;
    }
}

void
add_usec_to_timeval(struct timeval *tv, int usec)
{
    tv->tv_usec += usec;
    while (usec >= 1000000) {
	usec -= 1000000;
	tv->tv_sec += 1;
    }
}

int
sub_timeval_us(struct timeval *left, struct timeval *right)
{
    struct timeval dest;

    dest.tv_sec = left->tv_sec - right->tv_sec;
    dest.tv_usec = left->tv_usec - right->tv_usec;
    while (dest.tv_usec < 0) {
	dest.tv_usec += 1000000;
	dest.tv_sec--;
    }

    return (dest.tv_sec * 1000000) + dest.tv_usec;
}

/* Scan for a positive integer, and return it.  Return -1 if the
   integer was invalid. */
int
scan_int(const char *str)
{
    int rv = 0;

    if (*str == '\0') {
	return -1;
    }

    for (;;) {
	switch (*str) {
	case '0': case '1': case '2': case '3': case '4':
	case '5': case '6': case '7': case '8': case '9':
	    rv = (rv * 10) + ((*str) - '0');
	    break;

	case '\0':
	    return rv;

	default:
	    return -1;
	}

	str++;
    }

    return rv;
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

static int dummyrv; /* Used to ignore return values of read() and write(). */

/* Used to reliably deliver signals to a thread.  This is a pipe that
   we write to from a signal handler to make sure it wakes up. */
static int sig_fd_alert = -1;
static int sig_fd_watch = -1;
static volatile int reread_config = 0; /* Did I get a HUP signal? */
static volatile int term_prog = 0; /* Did I get an INT signal? */

static void
sig_wake_selector(void)
{
    char dummy = 0;

    dummyrv = write(sig_fd_alert, &dummy, 1);
}

static void
sighup_handler(int sig)
{
    reread_config = 1;
    sig_wake_selector();
}

static void
sigint_handler(int sig)
{
    term_prog = 1;
    sig_wake_selector();
}

static struct gensio_lock *config_lock;

static struct gensio_lock *maint_lock;

#if USE_PTHREADS
static int in_config_read = 0;

int ser2net_wake_sig = SIGUSR1;
void (*finish_shutdown)(void);

void
start_maint_op(void)
{
    so->lock(maint_lock);
}

void
end_maint_op(void)
{
    so->unlock(maint_lock);
}

static void *
config_reread_thread(void *dummy)
{
    pthread_detach(pthread_self());
    start_maint_op();
    reread_config_file();
    end_maint_op();
    so->lock(config_lock);
    in_config_read = 0;
    so->unlock(config_lock);
    return NULL;
}

static void
thread_reread_config_file(void)
{
    int rv;
    pthread_t thread;

    so->lock(config_lock);
    if (in_config_read) {
	so->unlock(config_lock);
	return;
    }
    in_config_read = 1;
    so->unlock(config_lock);

    rv = pthread_create(&thread, NULL, config_reread_thread, NULL);
    if (rv) {
	syslog(LOG_ERR,
	       "Unable to start thread to reread config file: %s",
	       strerror(rv));
	so->lock(config_lock);
	in_config_read = 0;
	so->unlock(config_lock);
    }
}

static void
wake_thread_sighandler(int sig)
{
    /* Nothing to do, sending the sig just wakes up select(). */
}

static void
wake_thread_send_sig(long thread_id, void *cb_data)
{
    pthread_t        *id = (void *) thread_id;

    pthread_kill(*id, ser2net_wake_sig);
}

static void *
op_loop(void *dummy)
{
    pthread_t self = pthread_self();

    while (!in_shutdown)
	sel_select(ser2net_sel, wake_thread_send_sig, (long) &self, NULL, NULL);

    /* Join the threads only in the first thread.  You cannot join the
       first thread.  Finish the shutdown in the first thread. */
    if (self == threads[0].id) {
	int i;

	for (i = 0; i < num_threads; i++) {
	    if (threads[i].id == self)
		continue;
	    pthread_join(threads[i].id, NULL);
	}
	free(threads);

	finish_shutdown();
    }
    return NULL;
}

static void
start_threads(void)
{
    int i, rv;
    struct sigaction act;

    act.sa_handler = wake_thread_sighandler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    rv = sigaction(ser2net_wake_sig, &act, NULL);
    if (rv) {
	syslog(LOG_ERR, "Unable to set sigaction: %s", strerror(errno));
	exit(1);
    }

    threads = malloc(sizeof(*threads) * num_threads);
    if (!threads) {
	syslog(LOG_ERR, "Unable to allocate thread info");
	exit(1);
    }

    threads[0].id = pthread_self();

    for (i = 1; i < num_threads; i++) {
	rv = pthread_create(&threads[i].id, NULL, op_loop, NULL);
	if (rv) {
	    syslog(LOG_ERR, "Unable to start thread: %s", strerror(rv));
	    exit(1);
	}
    }
}

static void
stop_threads(void (*finish)(void))
{
    int i;
    pthread_t self = pthread_self();

    in_shutdown = 1;
    finish_shutdown = finish;
    start_maint_op();
    /* Make sure we aren't in a reconfig. */
    end_maint_op();

    for (i = 0; i < num_threads; i++) {
	if (threads[i].id == self)
	    continue;
	pthread_kill(threads[i].id, ser2net_wake_sig);
    }
}

struct sel_lock_s
{
    pthread_mutex_t lock;
};

static sel_lock_t *
slock_alloc(void *cb_data)
{
    sel_lock_t *l;

    l = malloc(sizeof(*l));
    if (!l)
	return NULL;
    pthread_mutex_init(&l->lock, NULL);
    return l;
}

static void
slock_free(sel_lock_t *l)
{
    pthread_mutex_destroy(&l->lock);
    free(l);
}

static void
slock_lock(sel_lock_t *l)
{
    pthread_mutex_lock(&l->lock);
}

static void
slock_unlock(sel_lock_t *l)
{
    pthread_mutex_unlock(&l->lock);
}

#else
int ser2net_wake_sig = 0;
void start_maint_op(void) { }
void end_maint_op(void) { }
static void start_threads(void) { }
static void stop_threads(void (*finish)(void)) { finish(); }
#define slock_alloc NULL
#define slock_free NULL
#define slock_lock NULL
#define slock_unlock NULL
static void *
op_loop(void *dummy)
{
    sel_select_loop(ser2net_sel, NULL, 0, NULL);
    return NULL;
}
#endif /* USE_PTHREADS */

static void
finish_shutdown_cleanly(void)
{
    struct timeval tv;

    sel_clear_fd_handlers(ser2net_sel, sig_fd_watch);
    free_rotators();
    free_controllers();
    shutdown_ports();
    do {
	if (check_ports_shutdown())
	    break;
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	sel_select(ser2net_sel, NULL, 0, NULL, &tv);
    } while(1);

    shutdown_dataxfer();

    free_longstrs();
    free_tracefiles();
    free_rs485confs();

    if (pid_file)
	unlink(pid_file);

    if (admin_port)
	free(admin_port);

    so->free_funcs(so);

    exit(1);
}

static void
shutdown_cleanly(void)
{
    stop_threads(finish_shutdown_cleanly);
}

static void
sig_fd_read_handler(int fd, void *cb_data)
{
    char dummy[10];

    dummyrv = read(fd, dummy, sizeof(dummy));

    if (term_prog)
	shutdown_cleanly();

    if (reread_config && !in_shutdown) {
#if USE_PTHREADS
	thread_reread_config_file();
#else
	reread_config_file();
#endif
    }
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

    err = sel_set_fd_handlers(ser2net_sel, sig_fd_watch, NULL,
			      sig_fd_read_handler, NULL, NULL, NULL);
    if (!err)
	sel_set_fd_read_handler(ser2net_sel, sig_fd_watch,
				SEL_FD_HANDLER_ENABLED);

 out:
    if (err) {
	fprintf(stderr, "Error setting up signals: %s\n", strerror(errno));
	exit(1);
    }
}

static void
ser2net_gensio_logger(struct gensio_os_funcs *o, enum gensio_log_levels level,
		      const char *log, va_list args)
{
    int priority = LOG_INFO;

    switch (level) {
    case GENSIO_LOG_FATAL:   priority = LOG_CRIT; break;
    case GENSIO_LOG_ERR:     priority = LOG_ERR; break;
    case GENSIO_LOG_WARNING: priority = LOG_WARNING; break;
    case GENSIO_LOG_INFO:    priority = LOG_INFO; break;
    case GENSIO_LOG_DEBUG:   priority = LOG_DEBUG; break;
    }

    vsyslog(priority, log, args);
}

int
main(int argc, char *argv[])
{
    int i;
    int err;
#ifdef USE_PTHREADS
    char *end;
#endif
    char **config_lines;
    int num_config_lines = 0;
    int print_when_ready = 0;

    config_lines = malloc(sizeof(*config_lines));
    if (!config_lines) {
	fprintf(stderr, "Out of memory\n");
	exit(1);
    }
    *config_lines = NULL;

    if (led_driver_init() < 0) {
	fprintf(stderr, "Error while initializing LED drivers\n");
	exit(1);
    }

    for (i = 1; i < argc; i++) {
	if ((argv[i][0] != '-') || (strlen(argv[i]) != 2)) {
	    fprintf(stderr, "Invalid argument: '%s'\n", argv[i]);
	    arg_error(argv[0]);
	}

	switch (argv[i][1]) {
	case 'r':
	    print_when_ready = 1;
	    break;

	case 'n':
	    detach = 0;
	    break;

	case 'd':
	    detach = 0;
	    ser2net_debug = 1;
	    break;

	case 'l':
	    ser2net_debug_level++;
	    gensio_set_log_mask(gensio_get_log_mask() |
				1 << (ser2net_debug_level + 2));
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
	    num_config_lines++;
	    config_lines = realloc(config_lines, sizeof(*config_lines) *
				   (num_config_lines + 1));
	    if (!config_lines) {
		fprintf(stderr, "Out of memory handling config line\n");
		exit(1);
	    }
	    config_lines[num_config_lines - 1] = argv[i];
	    config_file = NULL;
	    config_file_set = true;
	    break;

	case 'c':
	    /* Get a config file. */
	    i++;
	    if (i == argc) {
		fprintf(stderr, "No config file specified with -c\n");
		arg_error(argv[0]);
	    }
	    config_file = argv[i];
	    config_file_set = true;
	    break;

	case 'p':
	    /* Get the control port. */
	    i++;
	    if (i == argc) {
		fprintf(stderr, "No control port specified with -p\n");
		arg_error(argv[0]);
	    }
	    admin_port = strdup(argv[i]);
	    if (!admin_port) {
		fprintf(stderr, "Could not allocate memory for -p\n");
		exit(1);
	    }
	    admin_port_from_cmdline = true;
	    break;

	case 'P':
	    i++;
	    if (i == argc) {
		fprintf(stderr, "No pid file specified with -P\n");
		arg_error(argv[0]);
	    }
	    pid_file = argv[i];
	    break;

	case 'u':
	    gensio_uucp_locking_enabled = 0;
	    break;

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

#ifdef USE_PTHREADS
	case 't':
            i++;
            if (i == argc) {
	        fprintf(stderr, "No thread count specified\n");
		exit(1);
            }
	    num_threads = strtoul(argv[i], &end, 10);
	    if (end == argv[i] || *end != '\0') {
	        fprintf(stderr, "Invalid thread count specified: %s\n",
			argv[i]);
		exit(1);
	    }
            break;
#endif

	default:
	    fprintf(stderr, "Invalid option: '%s'\n", argv[i]);
	    arg_error(argv[0]);
	}
    }

#ifdef USE_PTHREADS
    if (num_threads > 1)
	err = sel_alloc_selector_thread(&ser2net_sel, ser2net_wake_sig,
					slock_alloc, slock_free,
					slock_lock, slock_unlock, NULL);
    else
#endif
	err = sel_alloc_selector_nothread(&ser2net_sel);

    if (err) {
	fprintf(stderr,
		"Could not initialize ser2net selector: '%s'\n",
		strerror(err));
	exit(1);
    }

    so = gensio_selector_alloc(ser2net_sel, ser2net_wake_sig);
    if (!so) {
	fprintf(stderr, "Could not alloc ser2net gensio selector\n");
	exit(1);
    }
    so->vlog = ser2net_gensio_logger;

    config_lock = so->alloc_lock(so);
    if (!config_lock) {
	fprintf(stderr, "Could not alloc ser2net config lock\n");
	exit(1);
    }

    maint_lock = so->alloc_lock(so);
    if (!maint_lock) {
	fprintf(stderr, "Could not alloc ser2net maint lock\n");
	exit(1);
    }

    setup_signals();

    err = init_dataxfer();
    if (err) {
	fprintf(stderr,
		"Could not initialize dataxfer: '%s'\n",
		strerror(err));
	exit(1);
    }

    if (ser2net_debug && !detach)
	openlog("ser2net", LOG_PID | LOG_CONS | LOG_PERROR, LOG_DAEMON);

    err = readconfig_init();
    if (err) {
	fprintf(stderr,
		"Could not initialize defaults: '%s'\n",
		gensio_err_to_str(err));
	exit(1);
    }

    if (admin_port)
	controller_init(admin_port, NULL, NULL);

    for (i = 0; i < num_config_lines; i++)
	handle_config_line(config_lines[i], strlen(config_lines[i]));
    free(config_lines);
    if (config_file) {
	bool is_yaml;
	FILE *instream = fopen_config_file(&is_yaml);
	int rv;

	if (!instream)
	    exit(1);

	if (is_yaml)
	    rv = yaml_readconfig(instream);
	else
	    rv = readconfig(instream);
	if (rv == -1)
	    exit(1);
	fclose(instream);
    }
    readconfig_finalize();

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

    start_threads();

    if (print_when_ready) {
	printf("Ready\n");
	fflush(stdout);
    }

    op_loop(NULL);

    so->free_lock(maint_lock);
    so->free_lock(config_lock);
    so->free_funcs(so);
    sel_free_selector(ser2net_sel);

    return 0;
}
