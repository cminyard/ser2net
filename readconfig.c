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

/* This file holds the code that reads the configuration file and
   calls the code in dataxfer to actually create all the ports in the
   configuration file. */

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdarg.h>
#include <limits.h>
#include <gensio/gensio.h>
#include <gensio/argvutils.h>

#include "ser2net.h"
#include "dataxfer.h"
#include "readconfig.h"
#include "led.h"
#include "defaults.h"

int
readconfig_init(void)
{
    int err = setup_defaults();

    if (err)
	return err;
    free_leds();

    free_rotators();
    return 0;
}
