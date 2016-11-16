/*
 *  ser2net - A program for allowing telnet connection to serial ports
 *  Copyright (C) 2001-2016  Corey Minyard <minyard@acm.org>
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

/* This file holds common LED code required to read the configuration file and
   to dispatch calls from dataxfer to the actual LED driver. */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <syslog.h>

#include "led.h"
#include "led_sysfs.h"

/* list of all registered LED drivers */
static struct led_driver_s *led_drivers = NULL;

/* all LEDs in the system. */
static struct led_s *leds = NULL;

static struct led_driver_s *
led_driver_by_name(const char *name)
{
    struct led_driver_s *drv = led_drivers;

    while (drv) {
	if (strcmp(name, drv->name) == 0)
	    return drv;
	drv = drv->next;
    }

    return NULL;
}

int
led_driver_init(void)
{
    int rv = 0;

    rv |= led_sysfs_register();

    return rv;
}

int
led_driver_register(struct led_driver_s *led_driver)
{
    led_driver->next = led_drivers;
    led_drivers = led_driver;
    return 0;
}

void
handle_led(const char *name, char *cfg, int lineno)
{
    struct led_driver_s *driver;
    struct led_s *new_led;
    char *delim;

    delim = strchr(cfg, ':');
    if (!delim) {
	syslog(LOG_ERR, "Couldn't parse LED definition for '%s' on %d",
	       name, lineno);
	return;
    }
    *delim++ = '\0';

    driver = led_driver_by_name(cfg);
    if (!driver) {
	syslog(LOG_ERR, "Unknown LED driver '%s' for LED '%s' on %d",
	       cfg, name, lineno);
	return;
    }

    new_led = calloc(1, sizeof(*new_led));
    if (!new_led) {
	syslog(LOG_ERR, "Out of memory handling LED '%s' on %d", name, lineno);
	return;
    }

    new_led->name = strdup(name);
    if (!new_led->name) {
	syslog(LOG_ERR, "Out of memory handling LED '%s' on %d", name, lineno);
	free(new_led);
	return;
    }

    new_led->driver = driver;

    if (new_led->driver->init(new_led, delim, lineno) < 0) {
	/* errors should be reported by driver itself */
	free(new_led->name);
	free(new_led);
	return;
    }

    if (new_led->driver->configure) {
	if (new_led->driver->configure(new_led->drv_data) < 0) {
	    /*
	     * errors should be reported by driver itself; however, we
	     * cleanup here
	     */
	    if (new_led->driver->free)
		new_led->driver->free(new_led);

	    free(new_led->name);
	    free(new_led);
	    return;
	}
    }

    new_led->next = leds;
    leds = new_led;
}

struct led_s *
find_led(const char *name)
{
    struct led_s *led = leds;

    while (led) {
	if (strcmp(name, led->name) == 0)
	    return led;
	led = led->next;
    }

    syslog(LOG_ERR, "LED '%s' not found, it will be ignored", name);
    return NULL;
}

void
free_leds(void)
{
    while (leds) {
	struct led_s *led = leds;
	leds = leds->next;

	/* let driver deconfigure the LED */
	if (led->driver->deconfigure)
	    led->driver->deconfigure(led);

	/* let driver free its own data when it registered a cleanup function */
	if (led->driver->free)
	    led->driver->free(led);

	free(led->name);
	free(led);
    }
}

int
led_flash(struct led_s *led)
{
    return led->driver->flash(led->drv_data);
}
