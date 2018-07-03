/*
 *  ser2net - A program for allowing telnet connection to serial ports
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
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

%module genio

%{
#include <string.h>
#include "genio/genio.h"
#include "utils/selector.h"
#include "utils/waiter.h"

#include "genio_python.h"

static struct selector_s *genio_sel;

static void setup_genio_sel(void)
{
    if (!genio_sel)
	sel_alloc_selector_nothread(&genio_sel);
}

static int
genio_do_wait(struct waiter_s *waiter, struct timeval *timeout)
{
    int err;

    do {
	err = wait_for_waiter_timeout_intr(waiter, 1, timeout);
	if (check_for_err())
	    break;
	if (err)
	    break;
    } while (1);

    return err;
}

%}

%include "genio_python.i"

%include <typemaps.i>

struct genio { };
struct genio_acceptor { };
struct waiter_s { };

%extend genio {
    genio(char *str, int max_read_size, swig_cb *handler) {
	int rv;
	struct genio_data *data;
	struct genio *io = NULL;

	setup_genio_sel();

	data = malloc(sizeof(*data));
	if (!data)
	    return NULL;

	data->handler_val = ref_swig_cb(handler, read_callback);

	rv = str_to_genio(str, genio_sel, max_read_size, &gen_cbs,
			  data, &io);
	if (rv) {
	    deref_swig_cb_val(data->handler_val);
	    free(data);
	}
			  
	return io;
    }

    ~genio()
    {
	struct genio_data *data = genio_get_user_data(self);

	genio_free(self);
	deref_swig_cb_val(data->handler_val);
	free(data);
    }

    %rename (remote_id) remote_idt;
    int remote_idt() {
	int remid;

	err_handle("remote_id", genio_remote_id(self, &remid));
	return remid;
    }
    %rename(open) opent;
    void opent() {
	err_handle("open", genio_open(self));
    }

    %rename(close) closet;
    void closet(swig_cb *done) {
	swig_cb_val *done_val = NULL;
	void (*close_done)(struct genio *io, void *cb_data) = NULL;
	int rv;
	
	if (!nil_swig_cb(done)) {
	    close_done = genio_close_done;
	    done_val = ref_swig_cb(done, close_done);
	}
	rv = genio_close(self, close_done, done_val);
	if (rv && done_val)
	    deref_swig_cb_val(done_val);

	err_handle("close", rv);
    }

    %rename(write) writet;
    %apply (char *STRING, size_t LENGTH) { (char *str, size_t len) };
    unsigned int writet(char *str, size_t len) {
	unsigned int wr = 0;
	int rv;

	rv = genio_write(self, &wr, str, len);
	err_handle("write", rv);
	return wr;
    }

    void read_cb_enable(bool enable) {
	genio_set_read_callback_enable(self, enable);
    }

    void write_cb_enable(bool enable) {
	genio_set_write_callback_enable(self, enable);
    }
}

%nodefaultctor genio_acceptor;
%extend genio_acceptor {
    genio_acceptor(char *str, int max_read_size, swig_cb *handler) {
	struct genio_acc_data *data;
	struct genio_acceptor *acc;
	int rv;

	setup_genio_sel();

	data = malloc(sizeof(*data));
	if (!data)
	    return NULL;

	data->handler_val = ref_swig_cb(handler, new_connection);

	rv = str_to_genio_acceptor(str, genio_sel, max_read_size, &gen_acc_cbs,
			  data, &acc);
	if (rv) {
	    deref_swig_cb_val(data->handler_val);
	    free(data);
	}

	return acc;
    }

    ~genio_acceptor()
    {
	struct genio_acc_data *data = genio_acceptor_get_user_data(self);

	genio_acc_free(self);
	deref_swig_cb_val(data->handler_val);
	free(data);
    }

    void shutdown(swig_cb *done) {
	swig_cb_val *done_val = NULL;
	int rv;

	if (!nil_swig_cb(done))
	    done_val = ref_swig_cb(done, shutdown);
	rv = genio_acc_shutdown(self, genio_acc_shutdown_done, done_val);
	if (rv && done_val)
	    deref_swig_cb_val(done_val);

	err_handle("shutdown", rv);
    }
}

%nodefaultctor genio_acceptor;
%extend waiter_s {
    waiter_s() {
	setup_genio_sel();
	return alloc_waiter(genio_sel, 0);
    }

    ~waiter_s() {
	free_waiter(self);
    }

    int wait_timeout(int timeout) {
	struct timeval tv = { timeout / 1000, timeout % 1000 };

	return genio_do_wait(self, &tv);
    }

    void wait() {
	genio_do_wait(self, NULL);
    }

    void wake() {
	wake_waiter(self);
    }
}
