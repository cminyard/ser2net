/*
 *  ser2net - A program for allowing telnet connection to serial ports
 *  Copyright (C) 2015-2020  Corey Minyard <minyard@acm.org>
 *  Copyright (C) 2015 I2SE GmbH <info@i2se.com>
 *  Copyright (C) 2016 Michael Heimpold <mhei@heimpold.de>
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

#include <gensio/gensio.h>

#ifdef linux

#include <sys/types.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <gensio/argvutils.h>
#include "ser2net.h"
#include "port.h"

#define SYSFS_TTY_BASE "/sys/class/tty/"
#define SYSFS_TTY_BASE_LEN 15

static const char *
get_base_str(const char *devname, unsigned int *len)
{
    const char *e, *s;

    s = strstr(devname, ",serialdev");
    if (s) {
	s++;
	s = strchr(s, ',');
	if (s)
	    s++;
	while (isspace(*s))
	    s++;
    } else {
	s = strstr(devname, "/dev/");
    }
    if (s) {
	e = strchr(s, ',');
	if (e)
	    *len = e - s;
	else
	    *len = strlen(s);
	while (*len > 0 && isspace(s[(*len) - 1]))
	    (*len)--;
    }

    return s;
}

static void
add_attr(struct absout *eout, const char *portname,
	 const char *path, const char *sysfsname,
	 const char ***txt, gensiods *args, gensiods *argc)
{
    char *s, buf[1024];
    ssize_t rv;
    int fd;

    s = gensio_alloc_sprintf(so, "%s/%s", path, sysfsname);
    if (!s) {
	eout->out(eout,
		  "Device %s: Unable to allocate path for %s: out of memory\n",
		  portname, sysfsname);
	return;
    }

    fd = open(s, O_RDONLY);
    so->free(so, s);
    if (fd < 0)
	/* Some of these are options, just ignore open errors. */
	return;
 retry:
    rv = read(fd, buf, sizeof(buf) - 1);
    if (rv < 0) {
	if (errno == EINTR)
	    goto retry;
	eout->out(eout,
		  "Device %s: Unable to read contents of %s: %s\n",
		  portname, sysfsname, strerror(errno));
	goto out;
    }
    while (rv > 0 && isspace(buf[rv - 1]))
	rv--;
    buf[rv] = '\0';

    rv = gensio_argv_sappend(so, txt, args, argc, "%s=%s", sysfsname, buf);
    if (rv < 0)
	eout->out(eout,
		  "Device %s: Unable add txt contents for %s: %s\n",
		  portname, sysfsname, gensio_err_to_str(rv));
 out:
    close(fd);
}

void
add_usb_attrs(struct absout *eout, const char *portname, const char *devstr,
	      char *path, const char ***txt, gensiods *args, gensiods *argc)
{
    int rv;
    char *p, *s;
    unsigned int len;

    rv = gensio_argv_sappend(so, txt, args, argc, "devicetype=serialusb");
    if (rv < 0)
	eout->out(eout,
		  "Device %s: Unable add txt devicetype for %s\n",
		  portname, gensio_err_to_str(rv));

    /* Search backwards three directory levels, the name should match. */
    s = p = strrchr(path, '/');
    if (p && p > path) {
	p--;
	while (p > path && *p != '/')
	    p--;
    }
    if (p && p > path) {
	s = p;
	p--;
	while (p > path && *p != '/')
	    p--;
    }
    len = strlen(devstr);
    if (!p || (s - p - 1 != len) || strncmp(p + 1, devstr, len)) {
	eout->out(eout,
		  "Device %s: usb path is not valid: %s\n",
		  portname, path);
	return;
    }
    *p = '\0';

    add_attr(eout, portname, path, "bInterfaceNumber", txt, args, argc);
    add_attr(eout, portname, path, "interface", txt, args, argc);

    p = strrchr(path, '/');
    if (!p || p == path) {
	eout->out(eout,
		  "Device %s: usb path(2) is not valid: %s\n",
		  portname, path);
	return;
    }
    *p = '\0';
    
    add_attr(eout, portname, path, "idProduct", txt, args, argc);
    add_attr(eout, portname, path, "idVendor", txt, args, argc);
    add_attr(eout, portname, path, "serial", txt, args, argc);
    add_attr(eout, portname, path, "manufacturer", txt, args, argc);
    add_attr(eout, portname, path, "product", txt, args, argc);
}

static int
follow_symlink(char *path)
{
    char path2[PATH_MAX], *s, *t;
    int rv;

    do {
	rv = readlink(path, path2, sizeof(path2) - 1);
	if (rv < 0) {
	    if (errno == EINVAL)
		break;
	    goto out_err;
	}
	path2[rv] = '\0';

	s = path2;
	if (*s == '/') {
	    t = path;
	} else {
	    t = path + strlen(path);
	    while (t > path && *(t - 1) != '/')
		t--;
	    while (strcmp(s, "../") == 0) {
		if (t > path)
		    t--;
		while (t > path && *(t - 1) != '/')
		    t--;
		s += 3;
	    }
	    if (t == path)
		goto out_err;
	    if (strlen(s) + (t - path) > PATH_MAX)
		goto out_err;
	}
	strcpy(t, s);
    } while(true);

    return 0;

 out_err:
    return -EINVAL;
}

void
add_sys_attrs(struct absout *eout, const char *portname,
	      const char *devname,
	      const char ***txt, gensiods *args, gensiods *argc)
{
    const char *d, *s, *t;
    unsigned int len;
    char path[PATH_MAX], path2[PATH_MAX], devstr[128];
    ssize_t rv;

    /* Find the /dev/xxx string in the device name. */
    d = get_base_str(devname, &len);
    if (!d)
	return;
    if (len == 0 || len > sizeof(path) - 1) {
	eout->out(eout, "Device %s: device name too long.\n", portname);
	return;
    }
    memcpy(path, d, len);
    path[len] = 0;

    if (follow_symlink(path)) {
	eout->out(eout, "Device %s: Could not follow symlink: %s\n", path,
		  portname);
	return;
    }

    /* Find the name used in sysfs, usually what is after /dev. */
    t = s = path + strlen(path);
    while (s != path && *s != '/')
	s--;
    len = t - s;
    if (len == 0 || len > sizeof(devstr) - 1) {
	eout->out(eout, "Device %s: base device name size invalid.\n", portname);
	return;
    }
    memcpy(devstr, s + 1, len);
    devstr[len] = '\0';

    /* Find the tty class link at /sys/class/tty/<devname> */
    snprintf(path2, sizeof(path2), "%s%s", SYSFS_TTY_BASE, devstr);

    /* The tty class is a link, find the real location. */
    memcpy(path, SYSFS_TTY_BASE, SYSFS_TTY_BASE_LEN);
    rv = readlink(path2, path + SYSFS_TTY_BASE_LEN,
		  sizeof(path) - SYSFS_TTY_BASE_LEN - 1);
    if (rv < 0) {
	eout->out(eout,
		  "Device %s: Unable to get symlink path at %s: %s\n",
		  portname, path2, strerror(errno));
	return;
    }
    path[rv + SYSFS_TTY_BASE_LEN] = '\0';

    if (strstr(path, "/usb")) {
	add_usb_attrs(eout, portname, devstr, path, txt, args, argc);
    } else {
	rv = gensio_argv_sappend(so, txt, args, argc, "devicetype=serial");
	if (rv < 0)
	    eout->out(eout,
		      "Device %s: Unable add txt devicetype for %s\n",
		      portname, gensio_err_to_str(rv));
    }
}

#else

void
add_sys_attrs(struct absout *eout, const char *portname,
	      const char *devname,
	      const char ***txt, gensiods *args, gensiods *argc)
{
}

#endif
