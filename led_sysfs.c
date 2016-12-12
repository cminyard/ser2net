/*
 *  ser2net - A program for allowing telnet connection to serial ports
 *  Copyright (C) 2001-2016  Corey Minyard <minyard@acm.org>
 *  Copyright (C) 2015 I2SE GmbH <info@i2se.com>
 *  Copyright (C) 2016 Michael Heimpold <mhei@heimpold.de>
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

/* This file contains a LED driver for Linux's sysfs based LEDs. */

#ifdef USE_SYSFS_LED_FEATURE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <syslog.h>
#include "led.h"

#define SYSFS_LED_BASE "/sys/class/leds"

#define BUFSIZE 4096

struct led_sysfs_s
{
    char *device;
    int state;
    int duration;
};

static int
led_is_trigger_missing(const char *led)
{
    char *buffer, *trigger;
    int fd, c;

    buffer = malloc(BUFSIZE);
    if (!buffer)
	return -1;

    snprintf(buffer, BUFSIZE, "%s/%s/trigger", SYSFS_LED_BASE, led);

    if ((fd = open(buffer, O_RDONLY)) == -1) {
	free(buffer);
	return -1;
    }

    if ((c = read(fd, buffer, BUFSIZE)) <= 0) {
	free(buffer);
	close(fd);
	return -1;
    }

    if (close(fd) < 0) {
	free(buffer);
	return -1;
    }

    buffer[c] = '\0';
    trigger = strstr(buffer, "transient");
    free(buffer);
    return trigger == NULL;
}

static int
led_write(const char *led, const char *property, const char *buf)
{
    char filename[255];
    int fd;

    snprintf(filename, sizeof(filename), "%s/%s/%s", SYSFS_LED_BASE, led, property);

    if ((fd = open(filename, O_WRONLY | O_TRUNC)) == -1)
	return -1;

    if (write(fd, buf, strlen(buf)) != strlen(buf)) {
	close(fd);
	return -1;
    }

    return close(fd);
}

static int
led_sysfs_init(struct led_s *led, char *parameters, int lineno)
{
    struct led_sysfs_s *drv_data = NULL;
    char *str1, *str2, *token, *subtoken;
    char *saveptr1, *saveptr2;
    char *key, *value;
    int i;

    drv_data = calloc(1, sizeof(*drv_data));
    if (!drv_data) {
	syslog(LOG_ERR,
	       "Out of memory handling LED %s on line %d.",
	       led->name, lineno);
	return -1;
    }

    /* preset to detect default and/or wrong user input */
    drv_data->state = -1;

    /* parse parameter key=value pairs - seperated by whitespace */
    for (str1 = parameters; ; str1 = NULL) {
	token = strtok_r(str1, " \t", &saveptr1);
	if (!token)
	    break;

	/* parse single key=value pair */
	for (i = 0, str2 = token; ; i++, str2 = NULL) {
	    subtoken = strtok_r(str2, "=", &saveptr2);
	    if (!subtoken)
		break;

	    if (i == 0)
		key = subtoken;

	    if (i == 1) {
		value = subtoken;

		if (strcasecmp(key, "device") == 0) {
		    /* if 'device' is given more than once, last wins */
		    if (drv_data->device)
			free(drv_data->device);

		    drv_data->device = strdup(value);
		    if (!drv_data->device) {
			syslog(LOG_ERR,
			       "Out of memory handling LED '%s' on line %d.",
			       led->name, lineno);
			return -1;
		    }
		}

		if (strcasecmp(key, "duration") == 0)
		    drv_data->duration = atoi(value);

		if (strcasecmp(key, "state") == 0)
		    drv_data->state = atoi(value);
	    }
	}
    }

    if (!drv_data->device) {
	syslog(LOG_ERR,
	       "LED '%s': parameter 'device' required, but missing on line %d.",
	       led->name, lineno);
	free(drv_data);
	return -1;
    }

    if (drv_data->duration < 0) {
	syslog(LOG_ERR,
	       "LED '%s': invalid duration, using default on line %d.",
	       led->name, lineno);
	drv_data->duration = 10;
    }
    if (drv_data->duration == 0)
	drv_data->duration = 10;


    if (drv_data->state == -1)
	drv_data->state = 1;
    if (drv_data->state < 0 || drv_data->state > 1) {
	syslog(LOG_ERR,
	       "LED '%s': invalid state, using default on line %d.",
	       led->name, lineno);
	drv_data->state = 1;
    }

    led->drv_data = (void *)drv_data;

    return 0;
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
led_sysfs_configure(void *led_driver_data)
{
    struct led_sysfs_s *ctx = (struct led_sysfs_s *)led_driver_data;
    char buffer[255];
    int rv = 0;

    /* check whether we can enable the transient trigger for this led */
    rv = led_is_trigger_missing(ctx->device);
    if (rv != 0)
	return rv;

    /*
     * switch to transient trigger, this will kick creation of additional
     * property file in sysfs
     */
    rv = led_write(ctx->device, "trigger", "transient");
    if (rv)
	return rv;

    /* pre-configure the trigger for our needs */
    snprintf(buffer, sizeof(buffer), "%d", ctx->duration);
    rv |= led_write(ctx->device, "duration", buffer);

    snprintf(buffer, sizeof(buffer), "%d", ctx->state);
    rv |= led_write(ctx->device, "state", buffer);

    return rv;
}

static int
led_sysfs_flash(void *led_driver_data)
{
    struct led_sysfs_s *ctx = (struct led_sysfs_s *)led_driver_data;

    return led_write(ctx->device, "activate", "1");
}

static int
led_sysfs_deconfigure(void *led_driver_data)
{
    struct led_sysfs_s *ctx = (struct led_sysfs_s *)led_driver_data;
    int rv = 0;


    rv |= led_write(ctx->device, "trigger", "none");
    rv |= led_write(ctx->device, "brightness", "0");

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
