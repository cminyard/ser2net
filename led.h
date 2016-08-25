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

#ifndef LED_H
#define LED_H

struct led_driver_s;

struct led_s
{
    struct led_s *next;
    char *name;

    struct led_driver_s *driver;
    void *drv_data;
};

struct led_driver_s {
    struct led_driver_s *next;
    const char *name;

    /* required: parse the parameters from config file */
    int (*init)(struct led_s *led, char *config, int lineno);

    /* optional, but required when drv_data is malloced in init */
    int (*free)(struct led_s *led);

    /* optional: called once during initialization, prepares the LED */
    int (*configure)(void *drv_data);

    /* required: called when data transfer should be signaled */
    int (*flash)(void *drv_data);

    /* optional: called during deinitialization, could switch the LED off */
    int (*deconfigure)(void *drv_data);
};

/* Initializes and registers all LED drivers */
int led_driver_init(void);

/* Callback to register a given LED driver in the system */
int led_driver_register(struct led_driver_s *led_driver);

/* Handle an LED config line */
void handle_led(const char *name, char *cfg, int lineno);

/* Search for a LED by name */
struct led_s *find_led(const char *name);

/* Free all registered LEDs in the system */
void free_leds(void);

/* Flash the given LED */
int led_flash(struct led_s *led);

#endif /* LED_H */
