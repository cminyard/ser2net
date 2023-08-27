/*
 *  ser2net - A program for allowing telnet connection to serial ports
 *  Copyright (C) 2001=2020  Corey Minyard <minyard@acm.org>
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

#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <dirent.h>
#include <gensio/gensio.h>
#include <gensio/gensio_list.h>
#include "ser2net.h"

#if defined(USE_PAM)
#include <pwd.h>
#include <security/pam_appl.h>
#endif

/*
 * Ambiguity in spec: is it an array of pointers or a pointer to an array?
 * Stolen from openssh.
 */
#ifdef PAM_SUN_CODEBASE
# define PAM_MSG_MEMBER(msg, n, member) ((*(msg))[(n)].member)
#else
# define PAM_MSG_MEMBER(msg, n, member) ((msg)[(n)]->member)
#endif

struct user {
    struct gensio_link link;
    char *name;
};

int
add_allowed_users(struct gensio_list **users, const char *istr,
		  struct absout *eout)
{
    char *name, *strtok_data, *str = NULL;

    if (!*users) {
	*users = malloc(sizeof(**users));
	if (!*users)
	    goto out_nomem;
	gensio_list_init(*users);
    }

    str = strdup(istr);
    if (!str)
	goto out_nomem;

    name = strtok_r(str, " \t", &strtok_data);
    while (name) {
	struct user *user = malloc(sizeof(*user));

	if (!user)
	    goto out_nomem;
	memset(user, 0, sizeof(*user));
	user->name = strdup(name);
	if (!user->name) {
	    free(user);
	    goto out_nomem;
	}
	gensio_list_add_tail(*users, &user->link);

	name = strtok_r(NULL, " \t", &strtok_data);
    }
    free(str);
    return 0;

 out_nomem:
    if (str)
	free(str);
    eout->out(eout, "Out of memory allocating allowed user list");
    return GE_NOMEM;
}

static bool
is_user_present(const struct gensio_list *users, char *name)
{
    struct gensio_link *u;

    if (!users)
	return true;

    gensio_list_for_each(users, u) {
	struct user *user = gensio_container_of(u, struct user, link);

	if (strcmp(user->name, name) == 0)
	    return true;
    }
    return false;
}

void
free_user_list(struct gensio_list *users)
{
    struct gensio_link *u, *u2;

    if (!users)
	return;
    gensio_list_for_each_safe(users, u, u2) {
	struct user *user = gensio_container_of(u, struct user, link);

	gensio_list_rm(users, u);
	free(user->name);
	free(user);
    }
    free(users);
}

/*
 * The next few functions are for authentication handling.
 */
static int
handle_auth_begin(struct gensio *net, const char *authdir, const char *pamauth,
		  const struct gensio_list *allowed_users)
{
    gensiods len;
    char username[100];
    int err;

    len = sizeof(username);
    err = gensio_control(net, 0, true, GENSIO_CONTROL_USERNAME, username,
			 &len);
    if (err) {
	seout.out(&seout, "No username provided by remote: %s",
		  gensio_err_to_str(err));
	return GE_AUTHREJECT;
    }
    if (!is_user_present(allowed_users, username)) {
	seout.out(&seout,
		  "Username not allowed for this connection: %s",
		  username);
	return GE_AUTHREJECT;
    }

#if defined(USE_PAM)
    /* set user-specific authdir if it exists. */
    if (pamauth) {
	char userauthdir[1000];
	DIR *dir;
	struct passwd *pw;

	pw = getpwnam(username);
	if (pw) {
	    len = snprintf(userauthdir, sizeof(userauthdir),
		"%s/.gtlssh/allowed_certs/", pw->pw_dir);
	    dir = opendir(userauthdir);
	    if (dir) {
		closedir(dir);

		err = gensio_control(net, 0, GENSIO_CONTROL_SET,
				     GENSIO_CONTROL_CERT_AUTH, userauthdir, &len);
		if (err) {
		    seout.out(&seout,
			      "Could not set authdir %s: %s",
			      userauthdir, gensio_err_to_str(err));
		    return GE_NOTSUP;
		}
	    }
	}
    }
#endif

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
	    seout.out(&seout,
		      "No username provided by remote or cert: %s",
		      gensio_err_to_str(err));
	    return GE_AUTHREJECT;
	}
	/* Skip over the <n>,CN, in the username output. */
	s = strchr(username, ',');
	if (s)
	    s = strchr(s + 1, ',');
	if (!s) {
	    seout.out(&seout, "Got invalid username: %s",
		      username);
	    return GE_AUTHREJECT;
	}
	s++;

	/* Set the username so it's available later. */
	err = gensio_control(net, 0, false, GENSIO_CONTROL_USERNAME, s,
			     NULL);
	if (err) {
	    seout.out(&seout, "Unable to set username to %s: %s", s,
		      gensio_err_to_str(err));
	    return GE_AUTHREJECT;
	}
    }

    snprintf(filename, sizeof(filename), "%s%c%s%callowed_certs%c",
	     authdir, DIRSEP, s, DIRSEP, DIRSEP);
    err = gensio_control(net, 0, false, GENSIO_CONTROL_CERT_AUTH,
			 filename, &len);
    if (err && err != GE_CERTNOTFOUND) {
	seout.out(&seout,
		  "Unable to set authdir to %s: %s", filename,
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
	seout.out(&seout, "No username provided by remote: %s",
		  gensio_err_to_str(err));
	return GE_AUTHREJECT;
    }

    snprintf(filename, sizeof(filename), "%s/%s/password",
	     authdir, username);
    pwfile = fopen(filename, "r");
    if (!pwfile) {
	seout.out(&seout, "Can't open password file %s", filename);
	return GE_AUTHREJECT;
    }
    s = fgets(readpw, sizeof(readpw), pwfile);
    fclose(pwfile);
    if (!s) {
	seout.out(&seout, "Can't read password file %s", filename);
	return GE_AUTHREJECT;
    }
    s = strchr(readpw, '\n');
    if (s)
	*s = '\0';
    if (strcmp(readpw, password) == 0)
	return 0;
    return GE_NOTSUP;
}

#if defined(USE_PAM)
static int
pam_conversation_cb(int num_msg, const struct pam_message **msg,
		    struct pam_response **pam_response, void *appdata_ptr)
{
    int i;
    const char *password = appdata_ptr;
    struct pam_response *resp = NULL;

    if (password == NULL) {
	return PAM_CONV_ERR;
    }

    resp = calloc(num_msg, sizeof(struct pam_response));
    if (resp == NULL) {
	return PAM_BUF_ERR;
    }

    for (i = 0; i < num_msg; i++) {
	resp[i].resp_retcode = 0;

	switch(PAM_MSG_MEMBER(msg, i, msg_style)) {
	case PAM_PROMPT_ECHO_ON:
	case PAM_PROMPT_ECHO_OFF:
	    resp[i].resp = strdup(password);
	    if(resp[i].resp == NULL) {
		goto error;
	    }
	}
    }

    *pam_response = resp;
    return PAM_SUCCESS;

error:
    if (resp) {
	for (i = 0; i < num_msg; i++) {
	    free(resp[i].resp);
	}
	free(resp);
    }
    return PAM_BUF_ERR;
}

static int
handle_password_pam(struct gensio *net, const char *pamauth, const char *password)
{
    int ret = GE_AUTHREJECT;
    char username[100];
    gensiods len;
    int err, pam_err = 0;
    pam_handle_t *pamh = NULL;
    struct pam_conv pam_conv;

    len = sizeof(username);
    err = gensio_control(net, 0, true, GENSIO_CONTROL_USERNAME, username,
			 &len);
    if (err) {
	seout.out(&seout, "No username provided by remote: %s",
		  gensio_err_to_str(err));
	goto exit;
    }

    pam_conv.conv = pam_conversation_cb;
    pam_conv.appdata_ptr = (char *)password;
    pam_err = pam_start(pamauth, username, &pam_conv, &pamh);
    if (pam_err != PAM_SUCCESS) {
	seout.out(&seout, "Unable to start PAM transaction: %s",
		  pam_strerror(pamh, pam_err));
	goto exit;
    }

    pam_err = pam_authenticate(pamh, PAM_SILENT);
    if (pam_err != PAM_SUCCESS) {
	seout.out(&seout, "PAM authentication failed: %s",
		  pam_strerror(pamh, pam_err)
	);
	goto exit;
    } else {
	seout.out(&seout, "Accepted password for %s\n", username);
    }

    pam_err = pam_acct_mgmt(pamh, 0);
    if (pam_err == PAM_NEW_AUTHTOK_REQD) {
	seout.out(&seout, "user %s password expired", username);
	goto exit;
    }
    if (pam_err != PAM_SUCCESS) {
	seout.out(&seout, "pam_acct_mgmt failed for %s: %s",
		  username, pam_strerror(pamh, pam_err));
	goto exit;
    }

    ret = 0;

exit:
    if (pamh) {
	pam_end(pamh, pam_err);
    }
    return ret;
}
#endif

int
handle_acc_auth_event(const char *authdir, const char *pamauth,
		      const struct gensio_list *allowed_users,
		      int event, void *data)
{
    switch (event) {
    case GENSIO_ACC_EVENT_AUTH_BEGIN:
	if (!authdir)
	    return 0;
	return handle_auth_begin(data, authdir, pamauth, allowed_users);

    case GENSIO_ACC_EVENT_PRECERT_VERIFY:
	if (!authdir)
	    return 0;
	return handle_precert(data, authdir);

    case GENSIO_ACC_EVENT_PASSWORD_VERIFY: {
	struct gensio_acc_password_verify_data *pwdata;
	pwdata = (struct gensio_acc_password_verify_data *) data;
#if defined(USE_PAM)
	if (pamauth) {
	    return handle_password_pam(pwdata->io, pamauth, pwdata->password);
	} else
#endif
	if (authdir) {
	    return handle_password(pwdata->io, authdir, pwdata->password);
	} else {
	    return 0;
	}
    }

    default:
	return GE_NOTSUP;
    }
}
