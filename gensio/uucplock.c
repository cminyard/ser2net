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

#include "uucplock.h"

bool gensio_uucp_locking_enabled = true;

#ifdef USE_UUCP_LOCKING

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>

static char *uucp_lck_dir = "/var/lock/";
static char *dev_prefix = "/dev/";

static int
uucp_fname_lock_size(char *devname)
{
    int dev_prefix_len = strlen(dev_prefix);

    if (strncmp(dev_prefix, devname, dev_prefix_len) == 0)
	devname += dev_prefix_len;

    /*
     * Format is "/var/lock/LCK..<devname>".  The 6 is for
     * the "LCK.." and the final nil char.
     */
    return 6 + strlen(uucp_lck_dir) + strlen(devname);
}

static void
uucp_fname_lock(char *buf, char *devname)
{
    int i, dev_prefix_len = strlen(dev_prefix);

    if (strncmp(dev_prefix, devname, dev_prefix_len) == 0)
	devname += dev_prefix_len;

    sprintf(buf, "%sLCK..%s", uucp_lck_dir, devname);
    for (i = strlen(uucp_lck_dir); buf[i]; i++) {
	if (buf[i] == '/')
	    buf[i] = '_';
    }
}

void
uucp_rm_lock(char *devname)
{
    char *lck_file;

    if (!gensio_uucp_locking_enabled) return;

    lck_file = malloc(uucp_fname_lock_size(devname));
    if (lck_file == NULL) {
	return;
    }
    uucp_fname_lock(lck_file, devname);
    unlink(lck_file);
    free(lck_file);
}

static int
write_full(int fd, char *data, size_t count)
{
    ssize_t written;

 restart:
    while ((written = write(fd, data, count)) > 0) {
	data += written;
	count -= written;
    }
    if (written < 0) {
	if (errno == EAGAIN)
	    goto restart;
	return -1;
    }
    return 0;
}

int
uucp_mk_lock(char *devname)
{
    struct stat stt;
    int pid = -1;

    if (!gensio_uucp_locking_enabled)
	return 0;

    if (stat(uucp_lck_dir, &stt) == 0) { /* is lock file directory present? */
	char *lck_file;
	union {
	    uint32_t ival;
	    char     str[64];
	} buf;
	int fd;

	lck_file = malloc(uucp_fname_lock_size(devname));
	if (lck_file == NULL)
	    return -1;

	uucp_fname_lock(lck_file, devname);

	pid = 0;
	if ((fd = open(lck_file, O_RDONLY)) >= 0) {
	    int n;

	    n = read(fd, &buf, sizeof(buf) - 1);
	    close(fd);
	    if (n == 4) 		/* Kermit-style lockfile. */
		pid = buf.ival;
	    else if (n > 0) {		/* Ascii lockfile. */
		buf.str[n] = '\0';
		sscanf(buf.str, "%10d", &pid);
	    }

	    if (pid > 0 && kill((pid_t)pid, 0) < 0 && errno == ESRCH) {
		/* death lockfile - remove it */
		unlink(lck_file);
		pid = 0;
	    } else
		pid = 1;

	}

	if (pid == 0) {
	    int mask;

	    mask = umask(022);
	    fd = open(lck_file, O_WRONLY | O_CREAT | O_EXCL, 0666);
	    umask(mask);
	    if (fd >= 0) {
	        ssize_t rv;

		snprintf(buf.str, sizeof(buf), "%10ld\n",
			 (long)getpid());
		rv = write_full(fd, buf.str, strlen(buf.str));
		close(fd);
		if (rv < 0) {
		    pid = -1;
		    unlink(lck_file);
		}
	    } else {
		pid = -1;
	    }
	}

	free(lck_file);
    }

    return pid;
}

#else

void
uucp_rm_lock(char *devname)
{
}

int
uucp_mk_lock(char *devname)
{
    return 0;
}

#endif /* USE_UUCP_LOCKING */
