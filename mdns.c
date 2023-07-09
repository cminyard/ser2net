/*
 *  ser2net - A program for allowing telnet connection to serial ports
 *  Copyright (C) 2023  Corey Minyard <minyard@acm.org>
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
#include <stdlib.h>

#include "mdns.h"
#include "defaults.h"

#ifdef DO_MDNS
#include <gensio/gensio_mdns.h>

struct gensio_mdns *mdns;
struct gensio_enum_val mdns_nettypes[] = {
    { "unspec", GENSIO_NETTYPE_UNSPEC },
    { "ipv4", GENSIO_NETTYPE_IPV4 },
    { "ipv6", GENSIO_NETTYPE_IPV6 },
    { NULL }
};

void
msnd_info_init(struct mdns_info *m)
{
    memset(m, 0, sizeof(*m));
    m->mdns_interface = -1;
    m->mdns_nettype = GENSIO_NETTYPE_UNSPEC;
}

int
mdns_info_getdefaults(struct mdns_info *m, const char *str, struct absout *eout)
{
    msnd_info_init(m);

    m->mdns_interface = find_default_int("mdns-interface");
    if (find_default_str("mdns-type", &m->mdns_type)) {
	eout->out(eout, "Can't get default value for mdns-type for %s:"
		  " out of memory", str);
	return -1;
    }
    if (find_default_str("mdns-domain", &m->mdns_domain)) {
	eout->out(eout, "Can't get default value for mdns-domain for %s:"
		  " out of memory", str);
	return -1;
    }
    if (find_default_str("mdns-host", &m->mdns_host)) {
	eout->out(eout, "Can't get default value for mdns-host for %s:"
		  " out of memory", str);
	return -1;
    }
    return 0;
}

int
mdns_checkoption(const char *option, struct mdns_info *m, const char *name,
		 struct absout *eout)
{
    const char *val;
    char *fval;

    if (gensio_check_keybool(option, "mdns", &m->mdns) > 0)
	return 1;
    if (gensio_check_keyuint(option, "mdns-port", &m->mdns_port) > 0)
	return 1;
    if (gensio_check_keyint(option, "mdns-interface",
			    &m->mdns_interface) > 0)
	return 1;
    if (gensio_check_keyenum(option, "mdns-nettype",
			     mdns_nettypes,
			     &m->mdns_nettype) > 0)
	return 1;
    if (gensio_check_keyvalue(option, "mdns-name", &val) > 0) {
	fval = strdup(val);
	if (!fval) {
	    eout->out(eout, "Out of memory allocating %s mdns-name", name);
	    return -1;
	}
	if (m->mdns_name)
	    free(m->mdns_name);
	m->mdns_name = fval;
	return 1;
    }
    if (gensio_check_keyvalue(option, "mdns-type", &val) > 0) {
	fval = strdup(val);
	if (!fval) {
	    eout->out(eout, "Out of memory allocating %s mdns-type", name);
	    return -1;
	}
	if (m->mdns_type)
	    free(m->mdns_type);
	m->mdns_type = fval;
	return 1;
    }
    if (gensio_check_keyvalue(option, "mdns-domain", &val) > 0) {
	fval = strdup(val);
	if (!fval) {
	    eout->out(eout, "Out of memory allocating %s mdns-domain", name);
	    return -1;
	}
	if (m->mdns_domain)
	    free(m->mdns_domain);
	m->mdns_domain = fval;
	return 1;
    }
    if (gensio_check_keyvalue(option, "mdns-host", &val) > 0) {
	fval = strdup(val);
	if (!fval) {
	    eout->out(eout, "Out of memory allocating %s mdns-host", name);
	    return -1;
	}
	if (m->mdns_host)
	    free(m->mdns_host);
	m->mdns_host = fval;
	return 1;
    }
    if (gensio_check_keyvalue(option, "mdns-txt", &val) > 0) {
	int err = gensio_argv_append(so, &m->mdns_txt, val,
				     &m->mdns_txt_args,
				     &m->mdns_txt_argc,
				     true);

	if (err) {
	    eout->out(eout, "Out of memory allocating %s mdns-txt: %s", name,
		      gensio_err_to_str(err));
	    return -1;
	}
	return 1;
    }

    return 0;
}

static void
cleanup_mdns_data(struct mdns_info *m)
{
    m->mdns = false;
    m->mdns_port = 0;
    m->mdns_interface = -1;
    m->mdns_nettype = GENSIO_NETTYPE_UNSPEC;
    if (m->mdns_name) {
	free(m->mdns_name);
	m->mdns_name = NULL;
    }
    if (m->mdns_type) {
	free(m->mdns_type);
	m->mdns_type = NULL;
    }
    if (m->mdns_domain) {
	free(m->mdns_domain);
	m->mdns_domain = NULL;
    }
    if (m->mdns_host) {
	free(m->mdns_host);
	m->mdns_host = NULL;
    }

    if (m->mdns_txt) {
	gensio_argv_free(so, m->mdns_txt);
	m->mdns_txt = NULL;
    }
    m->mdns_txt_argc = 0;
    m->mdns_txt_args = 0;
}

static char *
derive_mdns_type(struct gensio_accepter *acc)
{
    /* Get a mdns type based on the gensio. */
    unsigned int i;
    const char *type, *ntype = "_iostream._tcp";

    type = gensio_acc_get_type(acc, 0);
    for (i = 1; type; i++) {
	if (strcmp(type, "tcp") == 0)
	    break;
	if (strcmp(type, "udp") == 0) {
	    ntype = "_iostream._udp";
	    break;
	}
	type = gensio_acc_get_type(acc, i);
    }
    return strdup(ntype);
}

static void
mdns_addprovider(struct mdns_info *m, const char *name, struct absout *eout)
{
    gensiods i;
    static char *provstr = "provider=";
    char *tmps = NULL;

    for (i = 0; i < m->mdns_txt_argc; i++) {
	if (strncmp(m->mdns_txt[i], provstr, strlen(provstr)) == 0)
	    /* User already specified it, don't override. */
	    return;
    }

    tmps = gensio_alloc_sprintf(so, "%s%s", provstr, "ser2net");
    if (!tmps)
	goto out_nomem;

    if (gensio_argv_append(so, &m->mdns_txt, tmps,
			   &m->mdns_txt_args, &m->mdns_txt_argc,
			   false))
	goto out_nomem;
    return;

 out_nomem:
    eout->out(eout, "Error allocating %s mdns provider: out of memory", name);
    if (tmps)
	so->free(so, tmps);
}

static void
mdns_addstack(struct mdns_info *m, const char *name, struct absout *eout)
{
    gensiods i;
    static char *stackstr = "gensiostack=";
    const char *type;
    char *stack = NULL, *tmps = NULL;

    for (i = 0; i < m->mdns_txt_argc; i++) {
	if (strncmp(m->mdns_txt[i], stackstr, strlen(stackstr)) == 0)
	    /* User already specified it, don't override. */
	    return;
    }

    for (i = 0; ; i++) {
	type = gensio_acc_get_type(m->acc, i);
	if (!type)
	    break;

	if (strcmp(type, "telnet") == 0) {
	    tmps = gensio_alloc_sprintf(so, "%s%s%s",
					stack ? stack : "", stack ? "," : "",
					type);
	} else {
	    tmps = gensio_alloc_sprintf(so, "%s%s%s",
					stack ? stack : "", stack ? "," : "",
					type);
	}
	if (!tmps)
	    goto out_nomem;
	if (stack)
	    so->free(so, stack);
	stack = tmps;
    }

    if (!stack)
	return;

    tmps = gensio_alloc_sprintf(so, "%s%s", stackstr, stack);
    if (!tmps)
	goto out_nomem;
    stack = tmps;

    if (gensio_argv_append(so, &m->mdns_txt, stack,
			   &m->mdns_txt_args, &m->mdns_txt_argc,
			   false))
	goto out_nomem;
    return;

 out_nomem:
    eout->out(eout, "Error allocating %s mdns stack: out of memory", name);
    if (stack)
	so->free(so, stack);
}

void
mdns_setup(struct mdns_info *m, const char *name, struct gensio_accepter *acc,
	   struct absout *eout)
{
    int err;
    char portnum_str[20];
    gensiods portnum_len = sizeof(portnum_str);

    if (!m->mdns)
	return;

    if (!m->mdns_name && !name) {
	eout->out(eout, "%s mdns enabled, but no name given", name);
	return;
    }

    if (!mdns) {
	eout->out(eout, "mdns requested for %s port, but mdns failed"
		  " to start or is disabled in gensio.", name);
	return;
    }

    m->acc = acc;

    if (!m->mdns_port) {
	strcpy(portnum_str, "0");
	err = gensio_acc_control(m->acc,
				 GENSIO_CONTROL_DEPTH_FIRST,
				 true, GENSIO_ACC_CONTROL_LPORT, portnum_str,
				 &portnum_len);
	if (err) {
	    eout->out(eout, "Can't get %s mdns port: %s", name,
		      gensio_err_to_str(err));
	    goto out_cleanup;
	}
	m->mdns_port = strtoul(portnum_str, NULL, 0);
    }

    if (!m->mdns_type) {
	m->mdns_type = derive_mdns_type(m->acc);
	if (!m->mdns_type) {
	    eout->out(eout, "Can't alloc %s mdns type: out of memory", name);
	    goto out_cleanup;
	}
    }

    if (!m->mdns_name) {
	m->mdns_name = strdup(name);
	if (!m->mdns_name) {
	    eout->out(eout, "Can't alloc %s mdns name: out of memory", name);
	    goto out_cleanup;
	}
    }

    mdns_addprovider(m, name, eout);
    mdns_addstack(m, name, eout);

    /*
     * Always stick on the NULL, that doesn't update argc so it's safe,
     * a new txt will just write over the NULL we added.
     */
    err = gensio_argv_append(so, &m->mdns_txt, NULL,
			     &m->mdns_txt_args, &m->mdns_txt_argc, true);
    if (err) {
	eout->out(eout, "Error terminating %s mdns-txt: %s", name,
		  gensio_err_to_str(err));
	goto out_cleanup;
    }

    err = gensio_mdns_add_service(mdns, m->mdns_interface,
				  m->mdns_nettype,
				  m->mdns_name, m->mdns_type,
				  m->mdns_domain, m->mdns_host,
				  m->mdns_port, m->mdns_txt,
				  &m->mdns_service);
    if (err) {
	eout->out(eout, "Can't add %s mdns service: %s", name,
		  gensio_err_to_str(err));
	goto out_cleanup;
    }
    return;

 out_cleanup:
    cleanup_mdns_data(m);
    return;
}

void
mdns_shutdown(struct mdns_info *m)
{
    if (m->mdns_service)
	gensio_mdns_remove_service(m->mdns_service);
    m->mdns_service = NULL;
    cleanup_mdns_data(m);
}

void
init_mdns(void)
{
    int err = gensio_alloc_mdns(so, &mdns);
    /*
     * If gensio doesn't support MDNS, that's not reportable unless
     * the user tries to use it.
     */
    if (err && err != GE_NOTSUP)
	/* Not fatal */
	fprintf(stderr, "Unable to start mdns: %s\n", gensio_err_to_str(err));
}

#else

void
init_mdns(void)
{
}

#endif
