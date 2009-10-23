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

/* This file holds the code that reads the configuration file and
   calls the code in dataxfer to actually create all the ports in the
   configuration file. */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>

#include "dataxfer.h"
#include "readconfig.h"

#define MAX_LINE_SIZE 256	/* Maximum line length in the config file. */

#define MAX_BANNER_SIZE 256

static int config_num = 0;

static int banner_continued = 0;
static char *working_banner_name = NULL;
static char working_banner[MAX_BANNER_SIZE+1];
static int working_banner_len = 0;
static int banner_truncated = 0;

static int lineno = 0;

struct banner_s
{
    char *name;
    char *str;
    struct banner_s *next;
};

/* All the banners in the system. */
struct banner_s *banners = NULL;

static void
handle_new_banner(void)
{
    struct banner_s *new_banner;

    working_banner[working_banner_len] = '\0';
    
    if (banner_truncated)
	syslog(LOG_ERR, "banner ending on line %d was truncated, max length"
	       " is %d characters", lineno, MAX_BANNER_SIZE);

    if (!working_banner_name) {
	syslog(LOG_ERR, "Out of memory handling banner on %d", lineno);
	goto out;
    }

    new_banner = malloc(sizeof(*new_banner));
    if (!new_banner) {
	syslog(LOG_ERR, "Out of memory handling banner on %d", lineno);
	free(working_banner_name);
	goto out;
    }

    new_banner->name = working_banner_name;
    new_banner->str = strdup(working_banner);
    if (!new_banner->str) {
	syslog(LOG_ERR, "Out of memory handling banner on %d", lineno);
	free(new_banner->name);
	free(new_banner);
	return;
    }

    new_banner->next = banners;
    banners = new_banner;

 out:
    working_banner_name = NULL;
    working_banner_len = 0;
    banner_truncated = 0;
    banner_continued = 0;
}

/* Parse the incoming banner, it may be on multiple lines. */
static void
handle_banner(char *name, char *line)
{
    int line_len = strlen(line);
    int real_line_len = line_len;

    /* handle a NULL return later. */
    working_banner_name = strdup(name);

    if (line_len >= MAX_BANNER_SIZE) {
	banner_truncated = 1;
	line_len = MAX_BANNER_SIZE;
    }
    memcpy(working_banner, line, line_len);
    working_banner_len = line_len;

    if ((real_line_len > 0) && (line[real_line_len-1] == '\\')) {
	/* remove the '\' */
	working_banner_len--;
	banner_continued = 1;
    } else {
	handle_new_banner();
    }

}

static void
handle_continued_banner(char *line)
{
    int line_len = strlen(line);
    int real_line_len = line_len;

    if ((line_len + working_banner_len) > MAX_BANNER_SIZE) {
	banner_truncated = 1;
	line_len = MAX_BANNER_SIZE - working_banner_len;
    }
    memcpy(working_banner+working_banner_len, line, line_len);
    working_banner_len += line_len;

    if ((real_line_len == 0) || (line[real_line_len-1] != '\\')) {
	handle_new_banner();
    } else {
	/* remove the '\' */
	working_banner_len--;
    }
}

char *
find_banner(char *name)
{
    struct banner_s *banner = banners;

    while (banner) {
	if (strcmp(name, banner->name) == 0)
	    return banner->str;
	banner = banner->next;
    }
    return NULL;
}

static void
free_banners(void)
{
    struct banner_s *banner;

    if (working_banner_name)
	free(working_banner_name);
    working_banner_name = NULL;
    working_banner_len = 0;
    banner_truncated = 0;
    banner_continued = 0;

    while (banners) {
	banner = banners;
	banners = banners->next;
	free(banner->name);
	free(banner->str);
	free(banner);
    }
}

struct tracefile_s
{
    char *name;
    char *str;
    struct tracefile_s *next;
};

/* All the tracefiles in the system. */
struct tracefile_s *tracefiles = NULL;

static void
handle_tracefile(char *name, char *fname)
{
    struct tracefile_s *new_tracefile;

    new_tracefile = malloc(sizeof(*new_tracefile));
    if (!new_tracefile) {
	syslog(LOG_ERR, "Out of memory handling tracefile on %d", lineno);
	return;
    }

    new_tracefile->name = strdup(name);
    if (!new_tracefile->name) {
	syslog(LOG_ERR, "Out of memory handling tracefile on %d", lineno);
	free(new_tracefile);
	return;
    }

    new_tracefile->str = strdup(fname);
    if (!new_tracefile->str) {
	syslog(LOG_ERR, "Out of memory handling tracefile on %d", lineno);
	free(new_tracefile->name);
	free(new_tracefile);
	return;
    }

    new_tracefile->next = tracefiles;
    tracefiles = new_tracefile;
}

char *
find_tracefile(char *name)
{
    struct tracefile_s *tracefile = tracefiles;

    while (tracefile) {
	if (strcmp(name, tracefile->name) == 0)
	    return tracefile->str;
	tracefile = tracefile->next;
    }
    syslog(LOG_ERR, "Tracefile %s not found, it will be ignored", name);
    return NULL;
}

static void
free_tracefiles(void)
{
    struct tracefile_s *tracefile;

    while (tracefiles) {
	tracefile = tracefiles;
	tracefiles = tracefiles->next;
	free(tracefile->name);
	free(tracefile->str);
	free(tracefile);
    }
}


void
handle_config_line(char *inbuf)
{
    char *portnum, *state, *timeout, *devname, *devcfg;
    char *strtok_data = NULL;
    char *errstr;

    lineno++;

    if (banner_continued) {
	char *str = strtok_r(inbuf, "\n", &strtok_data);
	if (!str)
	    str = "";
	handle_continued_banner(str);
	return;
    }

    if (inbuf[0] == '#') {
	/* Ignore comments. */
	return;
    }

    portnum = strtok_r(inbuf, ":", &strtok_data);
    if (portnum == NULL) {
	/* An empty line is ok. */
	return;
    }

    if (strcmp(portnum, "BANNER") == 0) {
	char *name = strtok_r(NULL, ":", &strtok_data);
	char *str = strtok_r(NULL, "\n", &strtok_data);
	if (name == NULL) {
	    syslog(LOG_ERR, "No banner name given on line %d", lineno);
	    return;
	}
	handle_banner(name, str);
	return;
    }

    if (strcmp(portnum, "TRACEFILE") == 0) {
	char *name = strtok_r(NULL, ":", &strtok_data);
	char *str = strtok_r(NULL, "\n", &strtok_data);
	if (name == NULL) {
	    syslog(LOG_ERR, "No tracefile name given on line %d", lineno);
	    return;
	}
	if ((str == NULL) || (strlen(str) == 0)) {
	    syslog(LOG_ERR, "No tracefile given on line %d", lineno);
	    return;
	}
	handle_tracefile(name, str);
	return;
    }

    state = strtok_r(NULL, ":", &strtok_data);
    if (state == NULL) {
	syslog(LOG_ERR, "No state given on line %d", lineno);
	return;
    }

    timeout = strtok_r(NULL, ":", &strtok_data);
    if (timeout == NULL) {
	syslog(LOG_ERR, "No timeout given on line %d", lineno);
	return;
    }

    devname = strtok_r(NULL, ":", &strtok_data);
    if (devname == NULL) {
	syslog(LOG_ERR, "No device name given on line %d", lineno);
	return;
    }

    devcfg = strtok_r(NULL, ":", &strtok_data);
    if (devcfg == NULL) {
	/* An empty device config is ok. */
	devcfg = "";
    }

    errstr = portconfig(portnum, state, timeout, devname, devcfg,
			config_num);
    if (errstr != NULL) {
	syslog(LOG_ERR, "Error on line %d, %s", lineno, errstr);
    }
}

/* Read the specified configuration file and call the routine to
   create the ports. */
int
readconfig(char *filename)
{
    FILE *instream;
    char inbuf[MAX_LINE_SIZE];
    int  rv = 0;

    lineno = 0;

    instream = fopen(filename, "r");
    if (instream == NULL) {
	syslog(LOG_ERR, "Unable to open config file '%s': %m", filename);
	return -1;
    }

    free_banners();
    free_tracefiles();

    config_num++;

    while (fgets(inbuf, MAX_LINE_SIZE, instream) != NULL) {
	int len = strlen(inbuf);
	if (inbuf[len-1] != '\n') {
	    lineno++;
	    syslog(LOG_ERR, "line %d is too long in config file", lineno);
	    continue;
	}
	/* Remove the '\n' */
	inbuf[len-1] = '\0';
	handle_config_line(inbuf);
    }

    /* Delete anything that wasn't in the new config file. */
    clear_old_port_config(config_num);

    fclose(instream);
    return rv;
}

