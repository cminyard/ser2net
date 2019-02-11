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

#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <limits.h>
#include <errno.h>
#include <gensio/gensio.h>

/*
 * The next few functions are for authentication handling.
 */
static int
handle_auth_begin(struct gensio *net, const char *authdir)
{
    gensiods len;
    char username[100];
    int err;

    len = sizeof(username);
    err = gensio_control(net, 0, true, GENSIO_CONTROL_USERNAME, username,
			 &len);
    if (err) {
	syslog(LOG_ERR, "No username provided by remote: %s",
	       gensio_err_to_str(err));
	return GE_AUTHREJECT;
    }

    return GE_NOTSUP;
}

static int
handle_precert(struct gensio *net, const char *authdir)
{
    gensiods len;
    char username[100];
    char filename[PATH_MAX];
    int err;
    char *s = username;

    len = sizeof(username);
    err = gensio_control(net, 0, true, GENSIO_CONTROL_USERNAME, username,
			 &len);
    if (err) {
	/* Try to get the username from the cert common name. */
	snprintf(username, sizeof(username), "-1,CN");
	len = sizeof(username);
	err = gensio_control(net, 0, true, GENSIO_CONTROL_GET_PEER_CERT_NAME,
			     username, &len);
	if (err) {
	    syslog(LOG_ERR, "No username provided by remote or cert: %s",
		   gensio_err_to_str(err));
	    return GE_AUTHREJECT;
	}
	/* Skip over the <n>,CN, in the username output. */
	s = strchr(username, ',');
	if (s)
	    s = strchr(s + 1, ',');
	if (!s) {
	    syslog(LOG_ERR, "Got invalid username: %s", username);
	    return GE_AUTHREJECT;
	}
	s++;

	/* Set the username so it's available later. */
	err = gensio_control(net, 0, false, GENSIO_CONTROL_USERNAME, s,
			     NULL);
	if (err) {
	    syslog(LOG_ERR, "Unable to set username to %s: %s", s,
		   gensio_err_to_str(err));
	    return GE_AUTHREJECT;
	}
    }

    snprintf(filename, sizeof(filename), "%s/%s/allowed_certs/",
	     authdir, s);
    err = gensio_control(net, 0, false, GENSIO_CONTROL_CERT_AUTH,
			 filename, &len);
    if (err && err != GE_CERTNOTFOUND) {
	syslog(LOG_ERR, "Unable to set authdir to %s: %s", filename,
	       gensio_err_to_str(err));
    }
    return GE_NOTSUP;
}

static int
handle_password(struct gensio *net, const char *authdir, const char *password)
{
    gensiods len;
    char username[100];
    char filename[PATH_MAX];
    FILE *pwfile;
    char readpw[100], *s;
    int err;

    len = sizeof(username);
    err = gensio_control(net, 0, true, GENSIO_CONTROL_USERNAME, username,
			 &len);
    if (err) {
	syslog(LOG_ERR, "No username provided by remote: %s",
	       gensio_err_to_str(err));
	return GE_AUTHREJECT;
    }

    snprintf(filename, sizeof(filename), "%s/%s/password",
	     authdir, username);
    pwfile = fopen(filename, "r");
    if (!pwfile) {
	syslog(LOG_ERR, "Can't open password file %s: %s", filename,
	       strerror(errno));
	return GE_AUTHREJECT;
    }
    s = fgets(readpw, sizeof(readpw), pwfile);
    fclose(pwfile);
    if (!s) {
	syslog(LOG_ERR, "Can't read password file %s: %s", filename,
	       strerror(errno));
	return GE_AUTHREJECT;
    }
    s = strchr(readpw, '\n');
    if (s)
	*s = '\0';
    if (strcmp(readpw, password) == 0)
	return 0;
    return GE_NOTSUP;
}

int
handle_acc_auth_event(const char *authdir, int event, void *data)
{
    switch (event) {
    case GENSIO_ACC_EVENT_AUTH_BEGIN:
	if (!authdir)
	    return 0;
	return handle_auth_begin(data, authdir);

    case GENSIO_ACC_EVENT_PRECERT_VERIFY:
	if (!authdir)
	    return 0;
	return handle_precert(data, authdir);

    case GENSIO_ACC_EVENT_PASSWORD_VERIFY: {
	struct gensio_acc_password_verify_data *pwdata;
	if (!authdir)
	    return 0;
	pwdata = (struct gensio_acc_password_verify_data *) data;
	return handle_password(pwdata->io, authdir, pwdata->password);
    }

    default:
	return GE_NOTSUP;
    }
}
