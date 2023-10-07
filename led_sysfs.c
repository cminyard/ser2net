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

/* This file contains a LED driver for Linux's sysfs based LEDs. */

#ifdef USE_SYSFS_LED_FEATURE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <limits.h>
#include "ser2net.h"
#include "led.h"
#include "led_sysfs.h"

#define SYSFS_LED_BASE "/sys/class/leds"

#define BUFSIZE 4096

struct led_sysfs_s
{
    char *device;
    int state;
    int duration;
    int max_brightness;
};

static int
led_is_trigger_missing(const char *led, struct absout *eout)
{
    char path[PATH_MAX];
    char buffer[BUFSIZE + 1], *trigger;
    int fd, c;

    snprintf(path, sizeof(path), "%s/%s/trigger", SYSFS_LED_BASE, led);

    if ((fd = open(path, O_RDONLY)) == -1) {
	eout->out(eout, "led: Unable to open %s", buffer);
	return -1;
    }

    if ((c = read(fd, buffer, BUFSIZE)) <= 0) {
	eout->out(eout, "led: Unable to read from %s", path);
	close(fd);
	return -1;
    }

    close(fd);

    buffer[c] = '\0';
    trigger = strstr(buffer, "transient");
    if (!trigger)
	eout->out(eout, "led: missing transient trigger in %s,"
		  " maybe you need to 'modprobe ledtrig-transient'", path);
    return trigger == NULL;
}

static int
led_write(const char *led, const char *property, const char *buf, int lineno,
	  struct absout *eout)
{
    char filename[255];
    int fd;
    char linestr[100] = "";

    snprintf(filename, sizeof(filename), "%s/%s/%s",
	     SYSFS_LED_BASE, led, property);

    if ((fd = open(filename, O_WRONLY | O_TRUNC)) == -1) {
	if (lineno)
	    snprintf(linestr, sizeof(linestr), "on line %d ", lineno);
	eout->out(eout, "Unable to open LED %s%s: %s", linestr, led,
		  strerror(errno));
	return -1;
    }

    if (write(fd, buf, strlen(buf)) != strlen(buf)) {
	if (lineno)
	    snprintf(linestr, sizeof(linestr), "on line %d ", lineno);
	eout->out(eout, "Unable to write to LED %s%s: %s", linestr, led,
		  strerror(errno));
	close(fd);
	return -1;
    }

    close(fd);
    return 0;
}

static int
led_read(const char *led, const char *property, char *buf, unsigned int buflen,
	 int *len, int lineno, struct absout *eout)
{
    char filename[255];
    int fd;
    char linestr[100] = "";
    ssize_t rlen;

    snprintf(filename, sizeof(filename), "%s/%s/%s",
	     SYSFS_LED_BASE, led, property);

    if ((fd = open(filename, O_RDONLY)) == -1) {
	if (lineno)
	    snprintf(linestr, sizeof(linestr), "on line %d ", lineno);
	eout->out(eout, "Unable to open LED for read %s%s: %s", linestr, led,
		  strerror(errno));
	return -1;
    }

    rlen = read(fd, buf, buflen);
    if (rlen < 0) {
	if (lineno)
	    snprintf(linestr, sizeof(linestr), "on line %d ", lineno);
	eout->out(eout, "Unable to read from LED %s%s: %s", linestr, led,
		  strerror(errno));
	close(fd);
	return -1;
    }
    *len = rlen;

    close(fd);
    return 0;
}

static int
led_read_num(const char *led, const char *property, int *val,
	 int lineno, struct absout *eout)
{
    char buf[100], *end;
    char linestr[100] = "";
    int len;
    int rv, rval;

    rv = led_read(led, property, buf, sizeof(buf) - 1, &len, lineno, eout);
    if (rv)
	return rv;

    /* Kill trailing spaces and terminate. */
    while(len >= 0 && isspace(buf[--len]))
	;
    buf[++len] = '\0';

    rval = strtol(buf, &end, 0);
    if (!buf[0] || *end != '\0') {
	if (lineno)
	    snprintf(linestr, sizeof(linestr), "on line %d ", lineno);
	eout->out(eout, "Invalid number from LED value %s%s: %s", linestr, led,
		  buf);
	return 1;
    }

    *val = rval;

    return 0;
}

static int
led_sysfs_init(struct led_s *led, const char * const *options, int lineno,
	       struct absout *eout)
{
    struct led_sysfs_s *drv_data = NULL;
    const char *key, *value;
    unsigned int i, len;

    drv_data = calloc(1, sizeof(*drv_data)); if (!drv_data) {
	eout->out(eout,
	       "Out of memory handling LED %s on line %d.",
	       led->name, lineno);
	return -1;
    }

    /* preset to detect default and/or wrong user input */
    drv_data->state = -1;

    for (i = 0; options[i]; i++) {
	value = strchr(options[i], '=');
	if (!value) {
	    eout->out(eout, "Missing '=' in option %s on line %d\n",
		   options[i], lineno);
	    goto out_err;
	} if (value == options[i]) {
	    eout->out(eout, "Missing key in option '%s' on line %d\n",
		   options[i], lineno);
	    goto out_err;
	}
	len = value - options[i];
	value++;
	key = options[i];

	if (strncasecmp(key, "device", len) == 0) {
	    /* if 'device' is given more than once, last wins */
	    if (drv_data->device)
		free(drv_data->device);

	    drv_data->device = strdup(value);
	    if (!drv_data->device) {
		eout->out(eout, "Out of memory handling LED '%s' on line %d.",
		       led->name, lineno);
		goto out_err;
	    }
	}

	if (strncasecmp(key, "duration", len) == 0)
	    drv_data->duration = atoi(value);

	if (strncasecmp(key, "state", len) == 0)
	    drv_data->state = atoi(value);
    }

    if (!drv_data->device) {
	eout->out(eout,
	       "LED '%s': parameter 'device' required, but missing on line %d.",
	       led->name, lineno);
	if (drv_data->device)
	    free(drv_data->device);
	goto out_err;
    }

    if (drv_data->duration < 0) {
	eout->out(eout,
	       "LED '%s': invalid duration, using default on line %d.",
	       led->name, lineno);
	drv_data->duration = 10;
    }
    if (drv_data->duration == 0)
	drv_data->duration = 10;

    if (led_read_num(drv_data->device, "max_brightness",
		     &drv_data->max_brightness, lineno, eout)) {
	eout->out(eout,
	       "LED '%s': Unable to read max_brightness using 1 on line %d.",
	       led->name, lineno);
	drv_data->max_brightness = 1;
    }

    if (drv_data->state == -1)
	drv_data->state = 1;
    if (drv_data->state < 0 || drv_data->state > drv_data->max_brightness) {
	eout->out(eout,
		  "LED '%s': invalid state on line %d: %d."
		  "  min is %d, max is %d."
		  "  Defaulting to 1.",
		  led->name, lineno, drv_data->state, 0,
		  drv_data->max_brightness);
	drv_data->state = 1;
    }

    led->drv_data = (void *)drv_data;

    return 0;

 out_err:
    free(drv_data);
    return -1;
}

static int
led_sysfs_free(struct led_s *led)
{
    struct led_sysfs_s *ctx = (struct led_sysfs_s *)led->drv_data;

    free(ctx->device);
    free(ctx);

    led->drv_data = NULL;
    return 0;
}

static int
led_sysfs_configure(void *led_driver_data, int lineno, struct absout *eout)
{
    struct led_sysfs_s *ctx = (struct led_sysfs_s *)led_driver_data;
    char buffer[255];
    int rv = 0;

    /* check whether we can enable the transient trigger for this led */
    rv = led_is_trigger_missing(ctx->device, eout);
    if (rv != 0)
	return rv;

    /*
     * switch to transient trigger, this will kick creation of additional
     * property file in sysfs
     */
    rv = led_write(ctx->device, "trigger", "transient", lineno, eout);
    if (rv)
	return rv;

    /* pre-configure the trigger for our needs */
    snprintf(buffer, sizeof(buffer), "%d", ctx->duration);
    rv |= led_write(ctx->device, "duration", buffer, lineno, eout);

    snprintf(buffer, sizeof(buffer), "%d", ctx->state);
    rv |= led_write(ctx->device, "state", buffer, lineno, eout);

    return rv;
}

static int
led_sysfs_flash(void *led_driver_data)
{
    struct led_sysfs_s *ctx = (struct led_sysfs_s *)led_driver_data;

    return led_write(ctx->device, "activate", "1", 0, &seout);
}

static int
led_sysfs_deconfigure(void *led_driver_data)
{
    struct led_sysfs_s *ctx = (struct led_sysfs_s *)led_driver_data;
    int rv = 0;


    rv |= led_write(ctx->device, "trigger", "none", 0, &seout);
    rv |= led_write(ctx->device, "brightness", "0", 0, &seout);

    return rv;
}

static struct led_driver_s led_sysfs_driver = {
    .name        = "sysfs",

    .init        = led_sysfs_init,
    .free        = led_sysfs_free,

    .configure   = led_sysfs_configure,
    .flash       = led_sysfs_flash,
    .deconfigure = led_sysfs_deconfigure,
};

int
led_sysfs_register(void)
{
    return led_driver_register(&led_sysfs_driver);
}
#else
int
led_sysfs_register(void)
{
    return 0;
}
#endif
