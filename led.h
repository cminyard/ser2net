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

#ifndef LED_H
#define LED_H

#include "absout.h"

struct led_driver_s;

struct led_s
{
    struct led_s *next;
    char *name;

    unsigned int refcount;
    struct led_driver_s *driver;
    void *drv_data;
};

struct led_driver_s {
    struct led_driver_s *next;
    const char *name;

    /* required: parse the parameters from config file */
    int (*init)(struct led_s *led, const char * const *options, int lineno,
		struct absout *eout);

    /* optional, but required when drv_data is malloced in init */
    int (*free)(struct led_s *led);

    /* optional: called once during initialization, prepares the LED */
    int (*configure)(void *drv_data, int lineno, struct absout *eout);

    /* required: called when data transfer should be signaled */
    int (*flash)(void *drv_data);

    /* required: turn led on or off */
    int (*enable)(void *drv_data, int value);

    /* optional: called during deinitialization, could switch the LED off */
    int (*deconfigure)(void *drv_data);
};

/* Initializes and registers all LED drivers */
int led_driver_init(void);

/* Callback to register a given LED driver in the system */
int led_driver_register(struct led_driver_s *led_driver);

/* Handle an LED config line */
int add_led(const char *name, const char *driverstr,
	    const char * const *options, int lineno, struct absout *eout);

/* Search for a LED by name.  This will increment the refcount. */
struct led_s *find_led(const char *name);

/* Decrement the LED's refcount and free if it reaches 0. */
void free_led(struct led_s *led);

/* Free all registered LEDs in the system */
void free_leds(void);

/* Turn LED on / off */
int led_enable(struct led_s *led, int value);

/* Flash the given LED */
int led_flash(struct led_s *led);

#endif /* LED_H */
