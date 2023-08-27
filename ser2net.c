/*
 *  ser2net - A program for allowing telnet connection to serial ports
 *  Copyright (C) 2001-2020  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: GPL-2.0-only
 *
 *  In addition, as a special exception, the copyright holders of
 *  ser2net give you permission to combine ser2net with free software
 *  programs or libraries that are released under the GNU LGPL and
 *  with code included in the standard release of OpenSSL under the
 *  OpenSSL license (or modified versions of such code, with unchanged
 *  license). You may copy and distribute such a system following the
 *  terms of the GNU GPL for ser2net and the licenses of the other code
 *  concerned, provided that you include the source code of that
 *  other code when and as the GNU GPL requires distribution of source
 *  code.
 *
 *  Note that people who make modified versions of ser2net are not
 *  obligated to grant this special exception for their modified
 *  versions; it is their choice whether to do so. The GNU General
 *  Public License gives permission to release a modified version
 *  without this exception; this exception also makes it possible to
 *  release a modified version which carries forward this exception.
 */

/* This is the entry point for the ser2net program.  It reads
   parameters, initializes everything, then starts the select loop. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gensio/gensio_os_funcs_public.h>

#include "ser2net.h"
#include "readconfig.h"
#include "controller.h"
#include "dataxfer.h"
#include "led.h"
#include "fileio.h"

bool admin_port_from_cmdline = false;
char *admin_port = NULL; /* Can be set from readconfig, too. */
static char *pid_file = NULL;
static int detach = 1;
int ser2net_debug = 0;
int ser2net_debug_level = 0;
volatile int in_shutdown = 0;
static unsigned int num_threads = 1;

char *confdir;
char *authdir;
char *admin_authdir;
char *keyfile;
char *certfile;

static char *config_file;
bool config_file_set;

static char *
alloc_vsprintf(const char *fmt, va_list va)
{
    va_list va2;
    int len;
    char c[1], *str;

    va_copy(va2, va);
    len = vsnprintf(c, 0, fmt, va);
    str = malloc(len + 1);
    if (str)
        vsnprintf(str, len + 1, fmt, va2);
    va_end(va2);
    return str;
}

static char *
alloc_sprintf(const char *fmt, ...)
{
    va_list va;
    char *s;

    va_start(va, fmt);
    s = alloc_vsprintf(fmt, va);
    va_end(va);
    return s;
}

#ifdef _WIN32
#include <windows.h>

static int
drop_last_diritem(char *dir)
{
    char *s, *s2;

    s = strrchr(dir, '/');
    s2 = strrchr(dir, '\\');
    if (!s && !s2)
	return 0;
    if (s && s2) {
	if (s < s2)
	    s = s2;
	} else if (s2) {
	s = s2;
    }
    *s = '\0';
    return 1;
}

static char *
get_basedir(void)
{
    char dir[256];
    DWORD rv;

    rv = GetModuleFileNameA(NULL, dir, sizeof(dir));
    if (rv == 0)
	return NULL;
    if (!drop_last_diritem(dir))
	return NULL;
    if (!drop_last_diritem(dir))
	return NULL;
    return strdup(dir);
}

static int
setup_paths_base(void)
{
    char *basedir = get_basedir();

    if (!basedir) {
	fprintf(stderr, "Unable to allocate base dir\n");
	return 1;
    }
    if (!confdir) {
	confdir = alloc_sprintf("%s%setc%sser2net", basedir, DIRSEPS, DIRSEPS);
	if (!confdir) {
	    fprintf(stderr, "Unable to allocate confdir\n");
	    goto out_err;
	}
    }
    if (!authdir) {
	authdir = alloc_sprintf("%s%sshare%sser2net%sauth", basedir, DIRSEPS, DIRSEPS, DIRSEPS);
	if (!confdir) {
	    fprintf(stderr, "Unable to allocate authdir\n");
	    goto out_err;
	}
    }
    free(basedir);
    return 0;

 out_err:
    free(basedir);
    return 1;
}

#else
static int
setup_paths_base(void)
{
    if (!confdir)
	confdir = SYSCONFDIR;
    if (!authdir) {
	authdir = alloc_sprintf("%s%sshare%sser2net",
				DATAROOT, DIRSEPS, DIRSEPS);
	if (!authdir) {
	    fprintf(stderr, "Unable to allocate authdir\n");
	    return 1;
	}
    }
    return 0;
}
#endif

static int
setup_paths(void)
{
    if (setup_paths_base())
	return 1;

    if (!admin_authdir) {
	admin_authdir = alloc_sprintf("%s%sauth", confdir, DIRSEPS);
	if (!admin_authdir) {
	    fprintf(stderr, "Unable to allocate admin authdir\n");
	    goto out_err;
	}
    }
    if (!keyfile) {
	keyfile = alloc_sprintf("%s%sser2net.key", confdir, DIRSEPS);
	if (!keyfile) {
	    fprintf(stderr, "Unable to allocate keyfile\n");
	    goto out_err;
	}
    }
    if (!certfile) {
	certfile = alloc_sprintf("%s%sser2net.crt", confdir, DIRSEPS);
	if (!certfile) {
	    fprintf(stderr, "Unable to allocate certfile\n");
	    goto out_err;
	}
    }
    if (!config_file && !config_file_set) {
	config_file = alloc_sprintf("%s%sser2net.yaml", confdir, DIRSEPS);
	if (!config_file) {
	    fprintf(stderr, "Unable to allocate config file name\n");
	    goto out_err;
	}
    }
    return 0;

 out_err:
    return 1;
}

struct s2n_threadinfo {
    struct gensio_thread *gthread;
    struct gensio_waiter *waiter;
    struct gensio_runner *runner;
} *threads;

struct gensio_os_proc_data *procdata;
struct gensio_os_funcs *so;
char *rfc2217_signature = "ser2net";

static char *help_string =
"%s: Valid parameters are:\n"
"  -c <config file> - use a config file besides %s\n"
"  -C <config line> - Handle a single configuration line.  This may be\n"
"     specified multiple times for multiple lines.  This is just like a\n"
"     line in the config file.  This disables the default config file,\n"
"     you must specify a -c after the last -C to have it read a config\n"
"     file, too.  The config file must not be yaml.\n"
"  -p <controller port> - Start a controller session on the given TCP port\n"
"  -P <file> - set location of pid file\n"
"  -n - Don't detach from the controlling terminal\n"
"  -d - Don't detach and send debug I/O to standard output\n"
"  -l - Increase the debugging level\n"
"  -u - Disable UUCP locking\n"
"  -t <num threads> - Use the given number of threads, default 1\n"
"  -b - unused (was Do CISCO IOS baud-rate negotiation, instead of RFC2217)\n"
"  -v - print the program's version and exit\n"
"  -s - specify a default signature for RFC2217 protocol\n"
"  -Y - Handle a yaml configuration string.  This may be specified multiple\n"
"       times; these strings are strung together as if they were one input\n"
"       string.  This disables the default config file, you must specify -c\n"
"       after the last -Y.  The config file will be processed first, if it\n"
"       is specified, then the -Y strings in order, as if they are one\n"
"       contiguous file.  '#' characters outside of quotes will be converted\n"
"       to newlines to make things easier to handle.  Each -Y will be\n"
"       terminated with a newline automatically.\n";

static char **config_lines;
static unsigned int num_config_lines;

#ifndef WIN32
#include <syslog.h>
#endif

static int
stderr_evout(struct absout *e, const char *str, va_list ap)
{
    char buf[1024];

    vsnprintf(buf, sizeof(buf), str, ap);
#ifndef WIN32
    syslog(LOG_ERR, "%s", buf);
#endif
    fprintf(stderr, "%s\n", buf);
    return 0;
}
static int
stderr_eout(struct absout *e, const char *str, ...)
{
    va_list ap;

    va_start(ap, str);
    stderr_evout(e, str, ap);
    va_end(ap);
    return 0;
}

#ifndef WIN32
#include <errno.h>
#include <unistd.h>

static int
syslog_evout(struct absout *e, const char *str, va_list ap)
{
    char buf[1024];

    vsnprintf(buf, sizeof(buf), str, ap);
    syslog(LOG_ERR, "%s", buf);
    return 0;
}

static int
syslog_eout(struct absout *e, const char *str, ...)
{
    va_list ap;

    va_start(ap, str);
    syslog_evout(e, str, ap);
    va_end(ap);
    return 0;
}

struct absout seout = {
    .out = syslog_eout,
    .vout = syslog_evout
};

static int
gensio_log_level_to_syslog(int gloglevel)
{
    switch (gloglevel) {
    case GENSIO_LOG_FATAL:
	return LOG_EMERG;
    case GENSIO_LOG_ERR:
	return LOG_ERR;
    case GENSIO_LOG_WARNING:
	return LOG_WARNING;
    case GENSIO_LOG_INFO:
    default:
	return LOG_INFO;
    }
    return LOG_ERR;
}

void
do_gensio_log(const char *name, struct gensio_loginfo *i)
{
    char buf[256];

    vsnprintf(buf, sizeof(buf), i->str, i->args);
    syslog(gensio_log_level_to_syslog(i->level), "%s: %s", name, buf);
}

static void
ser2net_gensio_logger(struct gensio_os_funcs *o, enum gensio_log_levels level,
		      const char *log, va_list args)
{
    int priority = gensio_log_level_to_syslog(level);

    vsyslog(priority, log, args);
}

#else

#define SIGUSR1 0

struct absout seout = {
    .out = stderr_eout,
    .vout = stderr_evout
};

void
do_gensio_log(const char *name, struct gensio_loginfo *i)
{
    char buf[256];

    vsnprintf(buf, sizeof(buf), i->str, i->args);
    fprintf(stderr, "%s: %s: %s\n", gensio_log_level_to_str(i->level), name, buf);
}

static void
ser2net_gensio_logger(struct gensio_os_funcs *o, enum gensio_log_levels level,
		      const char *log, va_list args)
{
    char buf[256];

    vsnprintf(buf, sizeof(buf), log, args);
    fprintf(stderr, "%s: %s\n", gensio_log_level_to_str(level), buf);
}

#endif

static struct absout stderr_absout = {
    .out = stderr_eout,
    .vout = stderr_evout
};

static ftype *
fopen_config_file(char **rfilename, struct absout *eout)
{
    int err;
    ftype *instream;

    err = f_open(config_file, DO_READ, 0, &instream);
    if (err) {
	eout->out(eout, "Unable to open config file '%s': %s",
		  config_file, gensio_err_to_str(err));
	return NULL;
    } else {
	*rfilename = config_file;
    }

    return instream;
}

int
reread_config_file(const char *reqtype, struct absout *eout)
{
    int rv = GE_NOTFOUND;

    if (config_file) {
	ftype *instream = NULL;
	char *filename;

	seout.out(&seout, "Got %s, re-reading configuration", reqtype);
	readconfig_init();

	instream = fopen_config_file(&filename, &seout);
	if (!instream)
	    goto out;

	if (!admin_port_from_cmdline)
	    controller_shutdown();
	rv = yaml_readconfig(instream, filename,
			     config_lines, num_config_lines, eout);
	f_close(instream);

	if (!rv)
	    apply_new_ports(&seout);
    }
 out:
    return rv;
}

void
add_usec_to_time(gensio_time *tv, int usec)
{
#ifdef gensio_version_major
    tv->nsecs += usec * 1000;
    while (tv->nsecs >= 1000000000) {
	tv->nsecs -= 1000000000;
	tv->secs += 1;
    }
#else
    tv->tv_usec += usec;
    while (tv->tv_usec >= 1000000) {
	tv->tv_usec -= 1000000;
	tv->tv_sec += 1;
    }
#endif
}

int
sub_time(gensio_time *left, gensio_time *right)
{
    gensio_time dest;

#ifdef gensio_version_major
    dest.secs = left->secs - right->secs;
    dest.nsecs = left->nsecs - right->nsecs;
    while (dest.nsecs < 0) {
	dest.nsecs += 1000000000;
	dest.secs--;
    }

    return (dest.secs * 1000000) + (dest.nsecs + 500) / 1000;
#else
    dest.tv_sec = left->tv_sec - right->tv_sec;
    dest.tv_usec = left->tv_usec - right->tv_usec;
    while (dest.tv_usec < 0) {
	dest.tv_usec += 1000000;
	dest.tv_sec--;
    }

    return (dest.tv_sec * 1000000) + dest.tv_usec;
#endif
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
    if (setup_paths())
	return;
    fprintf(stderr, help_string, name, config_file);
    printf("\n");
    printf("  config file: %s\n", config_file);
    printf("  config dir: %s\n", confdir);
    printf("  user auth dir: %s\n", authdir);
    printf("  admin auth dir: %s\n", admin_authdir);
    printf("  keyfile: %s\n", keyfile);
    printf("  certfile: %s\n", certfile);
}

static int
make_pidfile(void)
{
#ifndef WIN32
    int rv, len;
    ftype *fpidfile;
    char buf[20];

    if (!pid_file)
	return 0;
    rv = f_open(pid_file, DO_WRITE | DO_CREATE, 0644, &fpidfile);
    if (rv) {
	seout.out(&seout,
		  "Error opening pidfile '%s': %m, pidfile not created: %s",
		  pid_file, gensio_err_to_str(rv));
	pid_file = NULL;
	return rv;
    }
    len = snprintf(buf, sizeof(buf), "%d\n", getpid());
    f_write(fpidfile, buf, len, NULL);
    f_close(fpidfile);
#endif
    return 0;
}

static void
cleanup_pidfile(void)
{
#ifndef WIN32
    if (pid_file)
	unlink(pid_file);
#endif
}

void
do_detach(void)
{
#ifndef WIN32
    if (detach) {
	int pid;

	/* Detach from the calling terminal. */
	openlog("ser2net", LOG_PID | LOG_CONS, LOG_DAEMON);
	syslog(LOG_NOTICE, "ser2net startup");
	if ((pid = fork()) > 0) {
	    exit(0);
	} else if (pid < 0) {
	    seout.out(&seout, "Error forking first fork: %s", strerror(errno));
	    exit(1);
	} else {
	    /* setsid() is necessary if we really want to demonize */
	    setsid();
	    /* Second fork to really daemonize me. */
	    if ((pid = fork()) > 0) {
		exit(0);
	    } else if (pid < 0) {
		seout.out(&seout, "Error forking second fork: %s",
			  strerror(errno));
		exit(1);
	    }
	}

	/* Close all my standard I/O. */
	if (chdir("/") < 0) {
	    seout.out(&seout, "unable to chdir to '/': %s", strerror(errno));
	    exit(1);
	}
	close(0);
	close(1);
	close(2);
    } else if (ser2net_debug) {
	openlog("ser2net", LOG_PID | LOG_CONS | LOG_PERROR, LOG_DAEMON);
    } else {
	openlog("ser2net", LOG_PID | LOG_CONS, LOG_DAEMON);
    }
#endif
}

static struct gensio_lock *config_lock;
static struct gensio_lock *maint_lock;

static int in_config_read = 0;

void
start_maint_op(void)
{
    gensio_os_funcs_lock(so, maint_lock);
}

void
end_maint_op(void)
{
    gensio_os_funcs_unlock(so, maint_lock);
}

static void
cleanup_s2n_threadinfo(struct s2n_threadinfo *thread)
{
    if (thread->waiter)
	gensio_os_funcs_free_waiter(so, thread->waiter);
    if (thread->runner)
	gensio_os_funcs_free_runner(so, thread->runner);
}

static void
config_join_runner(struct gensio_runner *r, void *data)
{
    struct s2n_threadinfo *thread = data;

    gensio_os_wait_thread(thread->gthread);
    cleanup_s2n_threadinfo(thread);
    gensio_os_funcs_zfree(so, thread);
}

static void
config_reread_thread(void *data)
{
    struct s2n_threadinfo *thread = data;

    start_maint_op();
    reread_config_file("SIGHUP", &seout);
    end_maint_op();
    gensio_os_funcs_lock(so, config_lock);
    in_config_read = 0;
    gensio_os_funcs_unlock(so, config_lock);
    gensio_os_funcs_run(so, thread->runner);
}

static void
thread_reread_config_file(void *data)
{
    int rv;
    struct s2n_threadinfo *thread = NULL;

    gensio_os_funcs_lock(so, config_lock);
    if (in_config_read || in_shutdown) {
	so->unlock(config_lock);
	return;
    }
    in_config_read = 1;
    gensio_os_funcs_unlock(so, config_lock);

    thread = gensio_os_funcs_zalloc(so, sizeof(*thread));
    if (!thread)
	goto out_nomem;
    thread->waiter = gensio_os_funcs_alloc_waiter(so);
    if (!thread->waiter)
	goto out_nomem;
    thread->runner = gensio_os_funcs_alloc_runner(so, config_join_runner,
						  thread);
    if (!thread->runner)
	goto out_nomem;

    rv = gensio_os_new_thread(so, config_reread_thread,
			      thread, &thread->gthread);
    if (rv) {
	seout.out(&seout,
		  "Unable to start thread to reread config file: %s",
		  gensio_err_to_str(rv));
	goto out_unlock;
    }
    return;

 out_nomem:
    seout.out(&seout, "Reconfig failed: Out of memory");
 out_unlock:
    if (thread)
	cleanup_s2n_threadinfo(thread);
    gensio_os_funcs_lock(so, config_lock);
    in_config_read = 0;
    gensio_os_funcs_unlock(so, config_lock);
}

static void
op_loop(void *data)
{
    struct s2n_threadinfo *thread = data;

    gensio_os_funcs_wait(so, thread->waiter, 1, NULL);
}

static int
start_threads(void)
{
    int i, rv;

    threads = gensio_os_funcs_zalloc(so, sizeof(*threads) * num_threads);
    if (!threads) {
	seout.out(&seout, "Unable to allocate thread info");
	return 1;
    }

    for (i = 0; i < num_threads; i++) {
	threads[i].waiter = gensio_os_funcs_alloc_waiter(so);
	if (!threads[i].waiter)
	    goto out_nomem;
    }

    for (i = 1; i < num_threads; i++) {
	rv = gensio_os_new_thread(so, op_loop, &threads[i],
				  &threads[i].gthread);
	if (rv) {
	    seout.out(&seout, "Unable to start thread: %s",
		      gensio_err_to_str(rv));
	    goto out;
	}
    }
    return 0;

 out_nomem:
    seout.out(&seout, "Unable to alloc data for threads");
 out:
    for (i = 0; i < num_threads; i++) {
	if (threads[i].gthread) {
	    gensio_os_funcs_wake(so, threads[i].waiter);
	    gensio_os_wait_thread(threads[i].gthread);
	}
	cleanup_s2n_threadinfo(&threads[i]);
    }
    gensio_os_funcs_zfree(so, threads);
    threads = NULL;
    return 1;
}

static void
stop_threads(void)
{
    int i;

    for (i = 0; i < num_threads; i++)
	gensio_os_funcs_wake(so, threads[i].waiter);
}

static void
shutdown_cleanly(void *data)
{
    struct gensio_time timeout;

    gensio_os_funcs_lock(so, config_lock);
    in_shutdown = 1;
    /* Make sure we aren't in a reconfig. */
    while (in_config_read) {
	gensio_os_funcs_unlock(so, config_lock);
	timeout.secs = 1;
	timeout.nsecs = 0;
	gensio_os_funcs_service(so, &timeout);
	gensio_os_funcs_lock(so, config_lock);
    }
    gensio_os_funcs_unlock(so, config_lock);

    stop_threads();
}

int
main(int argc, char *argv[])
{
    unsigned int i;
    int err, rv;
    char *end;
    int print_when_ready = 0;
    ftype *instream = NULL;
    char *filename;

    gensio_set_progname("ser2net");

    config_lines = malloc(sizeof(*config_lines));
    if (!config_lines) {
	fprintf(stderr, "Out of memory\n");
	return 1;
    }
    *config_lines = NULL;

    if (led_driver_init() < 0) {
	fprintf(stderr, "Error while initializing LED drivers\n");
	return 1;
    }

    for (i = 1; i < argc; i++) {
	if ((argv[i][0] != '-') || (strlen(argv[i]) != 2)) {
	    fprintf(stderr, "Invalid argument: '%s'\n", argv[i]);
	    arg_error(argv[0]);
	    return 1;
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

	case 'Y':
	    /* Get a config line. */
	    i++;
	    if (i == argc) {
		fprintf(stderr, "No config line specified with -%c\n",
			argv[i][1]);
		arg_error(argv[0]);
		return 1;
	    }
	    num_config_lines++;
	    config_lines = realloc(config_lines, sizeof(*config_lines) *
				   (num_config_lines + 1));
	    if (!config_lines) {
		fprintf(stderr, "Out of memory handling config line\n");
		return 1;
	    }
	    config_lines[num_config_lines - 1] = argv[i];
	    if (!config_file_set) {
		config_file = NULL;
		config_file_set = true;
	    }
	    break;

	case 'c':
	    /* Get a config file. */
	    i++;
	    if (i == argc) {
		fprintf(stderr, "No config file specified with -c\n");
		arg_error(argv[0]);
		return 1;
	    }
	    config_file = argv[i];
	    config_file_set = true;
	    break;

	case 'C':
	    i++;
	    if (i == argc) {
		fprintf(stderr, "No config dir specified with -c\n");
		arg_error(argv[0]);
		return 1;
	    }
	    confdir = argv[i];
	    break;

	case 'a':
	    i++;
	    if (i == argc) {
		fprintf(stderr, "No auth dir specified with -a\n");
		arg_error(argv[0]);
		return 1;
	    }
	    authdir = argv[i];
	    break;

	case 'A':
	    i++;
	    if (i == argc) {
		fprintf(stderr, "No admin auth dir specified with -A\n");
		arg_error(argv[0]);
		return 1;
	    }
	    admin_authdir = argv[i];
	    break;

	case 'p':
	    /* Get the control port. */
	    i++;
	    if (i == argc) {
		fprintf(stderr, "No control port specified with -p\n");
		arg_error(argv[0]);
		return 1;
	    }
	    admin_port = strdup(argv[i]);
	    if (!admin_port) {
		fprintf(stderr, "Could not allocate memory for -p\n");
		return 1;
	    }
	    admin_port_from_cmdline = true;
	    break;

	case 'P':
	    i++;
	    if (i == argc) {
		fprintf(stderr, "No pid file specified with -P\n");
		arg_error(argv[0]);
		return 1;
	    }
	    pid_file = argv[i];
	    break;

	case 'u':
	    gensio_uucp_locking_enabled = 0;
	    break;

	case 'v':
	    printf("%s version %s\n", argv[0], VERSION);
	    return 1;

	case 's':
            i++;
            if (i == argc) {
	        fprintf(stderr, "No signature specified\n");
		return 1;
            }
            rfc2217_signature = argv[i];
            break;

	case 't':
            i++;
            if (i == argc) {
	        fprintf(stderr, "No thread count specified\n");
		return 1;
            }
	    num_threads = strtoul(argv[i], &end, 10);
	    if (end == argv[i] || *end != '\0') {
	        fprintf(stderr, "Invalid thread count specified: %s\n",
			argv[i]);
		return 1;
	    }
	    if (num_threads == 0)
		num_threads = 1;
            break;

	default:
	    fprintf(stderr, "Invalid option: '%s'\n", argv[i]);
	    arg_error(argv[0]);
	    return 1;
	}
    }

    if (setup_paths())
	return 1;

    err = gensio_default_os_hnd(SIGUSR1, &so);
    if (err) {
	fprintf(stderr, "Could not alloc ser2net gensio selector\n");
	return 1;
    }
    so->vlog = ser2net_gensio_logger;

    err = gensio_os_proc_setup(so, &procdata);
    if (err) {
	seout.out(&seout, "Unable to setup proc: %s", gensio_err_to_str(err));
	return 1;
    }

    err = gensio_os_proc_register_reload_handler(procdata,
						 thread_reread_config_file,
						 NULL);
    if (err && err != GE_NOTSUP) {
	seout.out(&seout, "Unable to setup reconfig handler: %s",
		  gensio_err_to_str(err));
	return 1;
    }

    err = gensio_os_proc_register_term_handler(procdata, shutdown_cleanly,
					       NULL);
    if (err) {
	seout.out(&seout, "Unable to setup termination handler: %s",
		  gensio_err_to_str(err));
	return 1;
    }

    config_lock = gensio_os_funcs_alloc_lock(so);
    if (!config_lock) {
	fprintf(stderr, "Could not alloc ser2net config lock\n");
	return 1;
    }

    maint_lock = gensio_os_funcs_alloc_lock(so);
    if (!maint_lock) {
	fprintf(stderr, "Could not alloc ser2net maint lock\n");
	return 1;
    }

    init_mdns();

    err = init_dataxfer();
    if (err) {
	fprintf(stderr,
		"Could not initialize dataxfer: '%s'\n",
		strerror(err));
	return 1;
    }

    err = readconfig_init();
    if (err) {
	fprintf(stderr,
		"Could not initialize defaults: '%s'\n",
		gensio_err_to_str(err));
	return 1;
    }

    if (admin_port)
	controller_init(admin_port, NULL, NULL, &stderr_absout);

    if (config_file) {
	if (strcmp(config_file, "-") == 0) {
	    err = f_stdio_open(stdin, DO_READ, 0, &instream);
	    if (err) {
		fprintf(stderr, "Unable to create stdin file: %s\n",
			gensio_err_to_str(err));
		return 1;
	    }
	    filename = "<stdin>";
	} else {
	    instream = fopen_config_file(&filename, &stderr_absout);
	    if (!instream)
		return 1;
	}
    } else {
	filename = "<cmdline>";
    }

    rv = yaml_readconfig(instream, filename,
			 config_lines, num_config_lines,
			 &stderr_absout);
    if (rv)
	return 1;
    if (instream)
	f_close(instream);

    apply_new_ports(&seout);

    do_detach();

    /* write pid file */
    if (make_pidfile())
	return 1;

    if (start_threads())
	return 1;

    if (print_when_ready) {
	printf("Ready\n");
	fflush(stdout);
    }

    op_loop(&threads[0]);

    for (i = 1; i < num_threads; i++)
	gensio_os_wait_thread(threads[i].gthread);

    free_rotators();
    free_controllers();
    shutdown_ports();
    while (!check_ports_shutdown()) {
	struct gensio_time timeout;

	timeout.secs = 1;
	timeout.nsecs = 0;
	gensio_os_funcs_service(so, &timeout);
    }

    shutdown_dataxfer();

    cleanup_pidfile();

    if (admin_port)
	free(admin_port);

    if (config_lines)
	free(config_lines);

    gensio_os_funcs_free_lock(so, maint_lock);
    gensio_os_funcs_free_lock(so, config_lock);
    gensio_os_funcs_free(so);

    return 0;
}
