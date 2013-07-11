/*
 *  ser2net - A program for allowing telnet connection to serial ports
 *  Copyright (C) 2001  Corey Minyard <minyard@acm.org>
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

#ifndef DEVCFG
#define DEVCFG

#include <termios.h>
#include "controller.h"

/* Called to initially configure a terminal. */
void devinit(struct termios *termctl);

typedef struct trace_info_s
{
    int            hexdump;     /* output each block as a hexdump */
    int            timestamp;   /* preceed each line with a timestamp */
    char          *file;        /* open file.  NULL if not used */
} trace_info_t;

typedef struct dev_info {
    /* The termios information to set for the device. */
    struct termios termctl;

    /* Allow RFC 2217 mode */
    int allow_2217;

    /* Disable break-commands */
    int disablebreak;

    /* Banner to display at startup, or NULL if none. */
    char *banner;

    /* RFC 2217 signature. */
    char *signature;

    /* String to send to device at startup, or NULL if none. */
    char *openstr;

    /* String to send to device at close, or NULL if none. */
    char *closestr;

    /*
     * File to read/write trace, NULL if none.  If the same, then
     * trace information is in the same file, only one open is done.
     */
    trace_info_t trace_read;
    trace_info_t trace_write;
    trace_info_t trace_both;
} dev_info_t;

/* Called to change the configuration of a device based upon the
   string parameters. */
int devconfig(char *instr, dev_info_t *info);

/* Prints the configuration of a device to a controller. */
void show_devcfg(struct controller_info *cntlr, struct termios *termctl);

/* Sets the DTR and RTS lines dynamically. */
int setdevcontrol(char *instr, int fd);

/* Show the state of the DTR and RTS lines. */
void show_devcontrol(struct controller_info *cntlr, int fd);

/* Convert the serial parameters to a string. */
void serparm_to_str(char *str, int strlen, struct termios *termctl);

#endif /* DEVCFG */
