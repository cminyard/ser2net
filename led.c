/*
 *  ser2net - A program for allowing telnet connection to serial ports
 *  Copyright (C) 2016-2020  Corey Minyard <minyard@acm.org>
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

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>

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

struct led_s *
find_led(const char *name)
{
    struct led_s *led = leds;

    while (led) {
	if (strcmp(name, led->name) == 0)
	    return led;
	led = led->next;
    }

    return NULL;
}

int
add_led(const char *name, const char *driverstr, const char * const *options,
	int lineno, struct absout *eout)
{
    struct led_driver_s *driver;
    struct led_s *led;

    led = find_led(name);
    if (led) {
	eout->out(eout, "LED %s already exists on line %d\n", name, lineno);
	return -1;
    }

    driver = led_driver_by_name(driverstr);
    if (!driver) {
	eout->out(eout, "Unknown LED driver '%s' for LED '%s' on %d",
		  driverstr, name, lineno);
	return -1;
    }

    led = calloc(1, sizeof(*led));
    if (!led) {
	eout->out(eout, "Out of memory handling LED '%s' on %d",
		  name, lineno);
	return -1;
    }

    led->name = strdup(name);
    if (!led->name) {
	eout->out(eout, "Out of memory handling LED '%s' on %d",
		  name, lineno);
	free(led);
	return -1;
    }

    led->driver = driver;

    if (led->driver->init(led, options, lineno, eout) < 0) {
	/* errors should be reported by driver itself */
	free(led->name);
	free(led);
	return -1;
    }

    if (led->driver->configure) {
	if (led->driver->configure(led->drv_data, lineno, eout) < 0) {
	    /*
	     * errors should be reported by driver itself; however, we
	     * cleanup here
	     */
	    if (led->driver->free)
		led->driver->free(led);

	    free(led->name);
	    free(led);
	    return -1;
	}
    }

    led->next = leds;
    leds = led;
    return 0;
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
