/*
 *  gensio - A library for abstracting stream I/O
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

typedef PyObject swig_cb;
typedef PyObject swig_cb_val;
typedef struct swig_ref {
    PyObject *val;
} swig_ref;

#define nil_swig_cb(v) ((v) == NULL)
#define invalidate_swig_cb(v) ((v) = NULL)

#ifdef WITH_THREAD
static void gensio_swig_init_lang(void)
{
    PyEval_InitThreads();
}
#define OI_PY_STATE PyGILState_STATE
#define OI_PY_STATE_GET() PyGILState_Ensure()
#define OI_PY_STATE_PUT(s) PyGILState_Release(s)

/* We do need to work about blocking, though. */
#define GENSIO_SWIG_C_BLOCK_ENTRY Py_BEGIN_ALLOW_THREADS
#define GENSIO_SWIG_C_BLOCK_EXIT Py_END_ALLOW_THREADS
#else
static void gensio_swig_init_lang(void)
{
}
#define OI_PY_STATE int
#define OI_PY_STATE_GET() 0
#define OI_PY_STATE_PUT(s) do { } while(s)

/* No threads */
#define GENSIO_SWIG_C_BLOCK_ENTRY
#define GENSIO_SWIG_C_BLOCK_EXIT
#endif

static swig_cb_val *
ref_swig_cb_i(swig_cb *cb)
{
    OI_PY_STATE gstate;

    gstate = OI_PY_STATE_GET();
    Py_INCREF(cb);
    OI_PY_STATE_PUT(gstate);
    return cb;
}
#define ref_swig_cb(cb, func) ref_swig_cb_i(cb)

static swig_ref
swig_make_ref_i(void *item, swig_type_info *class)
{
    swig_ref    rv;
    OI_PY_STATE gstate;

    gstate = OI_PY_STATE_GET();
    rv.val = SWIG_NewPointerObj(item, class, 0);
    OI_PY_STATE_PUT(gstate);
    return rv;
}
#define swig_make_ref(item, name) \
	swig_make_ref_i(item, SWIGTYPE_p_ ## name)

static void
swig_free_ref(swig_ref ref)
{
    OI_PY_STATE gstate;

    gstate = OI_PY_STATE_GET();
    Py_DECREF(ref.val);
    OI_PY_STATE_PUT(gstate);
}

static swig_cb_val *
deref_swig_cb_val(swig_cb_val *cb)
{
    OI_PY_STATE gstate;

    gstate = OI_PY_STATE_GET();
    Py_DECREF(cb);
    OI_PY_STATE_PUT(gstate);
    return cb;
}

/* No way to check the refcount in Python. */
#define swig_free_ref_check(r, c) \
	do {								\
	    swig_free_ref(r);						\
	} while(0)

static PyObject *
swig_finish_call_rv(swig_cb_val *cb, const char *method_name, PyObject *args)
{
    PyObject *p, *o = NULL;

    p = PyObject_GetAttrString(cb, method_name);
    if (p) {
	o = PyObject_CallObject(p, args);
	Py_DECREF(p);
	if (PyErr_Occurred())
	    wake_curr_waiter();
    } else {
	PyObject *t = PyObject_GetAttrString(cb, "__class__");
	PyObject *c = PyObject_GetAttrString(t, "__name__");
	char *class = PyString_AsString(c);

	PyErr_Format(PyExc_RuntimeError,
		     "gensio callback: Class '%s' has no method '%s'\n",
		     class, method_name);
	wake_curr_waiter();
    }
    Py_DECREF(args);

    return o;
}

static void
swig_finish_call(swig_cb_val *cb, const char *method_name, PyObject *args)
{
    PyObject *o;

    o = swig_finish_call_rv(cb, method_name, args);
    if (o)
	Py_DECREF(o);
}

#if PY_VERSION_HEX >= 0x03000000
#define OI_PI_FromStringAndSize PyUnicode_FromStringAndSize
#define OI_PI_FromString PyUnicode_FromString
#else
#define OI_PI_FromStringAndSize PyString_FromStringAndSize
#define OI_PI_FromString PyString_FromString
#endif

struct gensio_data {
    int refcount;
    swig_cb_val *handler_val;
    struct gensio_os_funcs *o;
};

static void
gensio_open_done(struct gensio *io, int err, void *cb_data) {
    swig_cb_val *cb = cb_data;
    swig_ref io_ref;
    PyObject *args, *o;
    OI_PY_STATE gstate;

    gstate = OI_PY_STATE_GET();

    io_ref = swig_make_ref(io, gensio);
    args = PyTuple_New(2);
    Py_INCREF(io_ref.val);
    PyTuple_SET_ITEM(args, 0, io_ref.val);
    o = PyInt_FromLong(err);
    PyTuple_SET_ITEM(args, 1, o);

    swig_finish_call(cb, "open_done", args);

    swig_free_ref_check(io_ref, accepter);
    deref_swig_cb_val(cb);
    OI_PY_STATE_PUT(gstate);
}

static void
gensio_close_done(struct gensio *io, void *cb_data) {
    swig_cb_val *cb = cb_data;
    swig_ref io_ref;
    PyObject *args;
    OI_PY_STATE gstate;

    gstate = OI_PY_STATE_GET();

    io_ref = swig_make_ref(io, gensio);
    args = PyTuple_New(1);
    Py_INCREF(io_ref.val);
    PyTuple_SET_ITEM(args, 0, io_ref.val);

    swig_finish_call(cb, "close_done", args);

    swig_free_ref_check(io_ref, accepter);
    deref_swig_cb_val(cb);
    OI_PY_STATE_PUT(gstate);
}

static void
sgensio_call(struct sergensio *sio, long val, char *func)
{
    struct gensio_data *data = sergensio_get_user_data(sio);
    swig_ref sio_ref;
    PyObject *args, *o;
    OI_PY_STATE gstate;

    gstate = OI_PY_STATE_GET();

    if (!data->handler_val) {
	PyErr_Format(PyExc_RuntimeError, "sergensio callback: "
		     "gensio handler was not set");
	wake_curr_waiter();
	goto out_put;
    }

    sio_ref = swig_make_ref(sio, sergensio);
    args = PyTuple_New(2);
    Py_INCREF(sio_ref.val);
    PyTuple_SET_ITEM(args, 0, sio_ref.val);
    o = PyInt_FromLong(val);
    PyTuple_SET_ITEM(args, 1, o);

    swig_finish_call(data->handler_val, func, args);

    swig_free_ref_check(sio_ref, accepter);
 out_put:
    OI_PY_STATE_PUT(gstate);
}

static void
sgensio_modemstate(struct sergensio *sio, unsigned int modemstate)
{
    sgensio_call(sio, modemstate, "modemstate");
}

static void
sgensio_linestate(struct sergensio *sio, unsigned int linestate)
{
    sgensio_call(sio, linestate, "linestate");
}

static void
sgensio_signature(struct sergensio *sio, char *sig, unsigned int len)
{
    struct gensio_data *data = sergensio_get_user_data(sio);
    swig_ref sio_ref;
    PyObject *args, *o;
    OI_PY_STATE gstate;

    gstate = OI_PY_STATE_GET();

    if (!data->handler_val) {
	PyErr_Format(PyExc_RuntimeError, "sergensio_signature callback: "
		     "gensio handler was not set");
	wake_curr_waiter();
	goto out_put;
    }

    sio_ref = swig_make_ref(sio, sergensio);
    args = PyTuple_New(2);
    Py_INCREF(sio_ref.val);
    PyTuple_SET_ITEM(args, 0, sio_ref.val);
    o = OI_PI_FromStringAndSize(sig, len);
    PyTuple_SET_ITEM(args, 1, o);

    swig_finish_call(data->handler_val, "signature", args);

    swig_free_ref_check(sio_ref, accepter);
 out_put:
    OI_PY_STATE_PUT(gstate);
}

static void
sgensio_sync(struct sergensio *sio)
{
    struct gensio_data *data = sergensio_get_user_data(sio);
    swig_ref sio_ref;
    PyObject *args;
    OI_PY_STATE gstate;

    gstate = OI_PY_STATE_GET();

    if (!data->handler_val) {
	PyErr_Format(PyExc_RuntimeError, "sergensio_signature callback: "
		     "gensio handler was not set");
	wake_curr_waiter();
	goto out_put;
    }

    sio_ref = swig_make_ref(sio, sergensio);
    args = PyTuple_New(1);
    Py_INCREF(sio_ref.val);
    PyTuple_SET_ITEM(args, 0, sio_ref.val);

    swig_finish_call(data->handler_val, "sync", args);

    swig_free_ref_check(sio_ref, accepter);
 out_put:
    OI_PY_STATE_PUT(gstate);
}

static void
sgensio_flowcontrol_state(struct sergensio *sio, bool val)
{
    struct gensio_data *data = sergensio_get_user_data(sio);
    swig_ref sio_ref;
    PyObject *args, *o;
    OI_PY_STATE gstate;

    gstate = OI_PY_STATE_GET();

    if (!data->handler_val) {
	PyErr_Format(PyExc_RuntimeError, "sergensio callback: "
		     "gensio handler was not set");
	wake_curr_waiter();
	goto out_put;
    }

    sio_ref = swig_make_ref(sio, sergensio);
    args = PyTuple_New(2);
    Py_INCREF(sio_ref.val);
    PyTuple_SET_ITEM(args, 0, sio_ref.val);
    o = PyBool_FromLong(val);
    PyTuple_SET_ITEM(args, 1, o);

    swig_finish_call(data->handler_val, "flowcontrol_state", args);

    swig_free_ref_check(sio_ref, accepter);
 out_put:
    OI_PY_STATE_PUT(gstate);
}

static void
sgensio_flush(struct sergensio *sio, int val)
{
    sgensio_call(sio, val, "sflush");
}

static void
sgensio_baud(struct sergensio *sio, int baud)
{
    sgensio_call(sio, baud, "sbaud");
}

static void
sgensio_datasize(struct sergensio *sio, int datasize)
{
    sgensio_call(sio, datasize, "sdatasize");
}

static void
sgensio_parity(struct sergensio *sio, int parity)
{
    sgensio_call(sio, parity, "sparity");
}

static void
sgensio_stopbits(struct sergensio *sio, int stopbits)
{
    sgensio_call(sio, stopbits, "sstopbits");
}

static void
sgensio_flowcontrol(struct sergensio *sio, int flowcontrol)
{
    sgensio_call(sio, flowcontrol, "sflowcontrol");
}

static void
sgensio_iflowcontrol(struct sergensio *sio, int iflowcontrol)
{
    sgensio_call(sio, iflowcontrol, "siflowcontrol");
}

static void
sgensio_sbreak(struct sergensio *sio, int breakv)
{
    sgensio_call(sio, breakv, "ssbreak");
}

static void
sgensio_dtr(struct sergensio *sio, int dtr)
{
    sgensio_call(sio, dtr, "sdtr");
}

static void
sgensio_rts(struct sergensio *sio, int rts)
{
    sgensio_call(sio, rts, "srts");
}

static int
gensio_child_event(struct gensio *io, int event, int readerr,
		   unsigned char *buf, unsigned int *buflen, void *auxdata)
{
    struct gensio_data *data = gensio_get_user_data(io);
    swig_ref io_ref = { .val = NULL };
    PyObject *args, *o;
    OI_PY_STATE gstate;
    unsigned int rv = 0;

    gstate = OI_PY_STATE_GET();

    if (!data->handler_val) {
	PyErr_Format(PyExc_RuntimeError, "gensio callback: "
		     "gensio handler was not set");
	wake_curr_waiter();
	rv = ENOTSUP;
	goto out_put;
    }

    switch (event) {
    case GENSIO_EVENT_READ:
	args = PyTuple_New(3);

	io_ref = swig_make_ref(io, gensio);
	Py_INCREF(io_ref.val);
	PyTuple_SET_ITEM(args, 0, io_ref.val);

	if (readerr) {
	    o = OI_PI_FromString(strerror(readerr));
	} else {
	    Py_INCREF(Py_None);
	    o = Py_None;
	}
	PyTuple_SET_ITEM(args, 1, o);

	o = OI_PI_FromStringAndSize((char *) buf, *buflen);
	PyTuple_SET_ITEM(args, 2, o);

	o = swig_finish_call_rv(data->handler_val, "read_callback", args);
	if (o) {
	    *buflen = PyLong_AsUnsignedLong(o);
	    if (PyErr_Occurred()) {
		PyObject *t = PyObject_GetAttrString(data->handler_val,
						     "__class__");
		PyObject *c = PyObject_GetAttrString(t, "__name__");
		char *class = PyString_AsString(c);

		PyErr_Format(PyExc_RuntimeError, "gensio callback: "
			     "Class '%s' method 'read_callback' did not return "
			     "an integer\n", class);
		wake_curr_waiter();
	    }
	    Py_DECREF(o);
	}
	break;

    case GENSIO_EVENT_WRITE_READY:
	io_ref = swig_make_ref(io, gensio);
	args = PyTuple_New(1);
	Py_INCREF(io_ref.val);
	PyTuple_SET_ITEM(args, 0, io_ref.val);

	swig_finish_call(data->handler_val, "write_callback", args);
	break;

    case GENSIO_EVENT_URGENT:
	io_ref = swig_make_ref(io, gensio);
	args = PyTuple_New(1);
	Py_INCREF(io_ref.val);
	PyTuple_SET_ITEM(args, 0, io_ref.val);

	swig_finish_call(data->handler_val, "urgent_callback", args);
	rv = 0;
	break;

    case GENSIO_EVENT_SER_MODEMSTATE:
	sgensio_modemstate(gensio_to_sergensio(io), *((unsigned int *) buf));
	break;

    case GENSIO_EVENT_SER_LINESTATE:
	sgensio_linestate(gensio_to_sergensio(io), *((unsigned int *) buf));
	break;

    case GENSIO_EVENT_SER_SIGNATURE:
	sgensio_signature(gensio_to_sergensio(io), (char *) buf, *buflen);
	break;

    case GENSIO_EVENT_SER_FLOW_STATE:
	sgensio_flowcontrol_state(gensio_to_sergensio(io), *((int *) buf));
	break;

    case GENSIO_EVENT_SER_FLUSH:
	sgensio_flush(gensio_to_sergensio(io), *((int *) buf));
	break;

    case GENSIO_EVENT_SER_SYNC:
	sgensio_sync(gensio_to_sergensio(io));
	break;

    case GENSIO_EVENT_SER_BAUD:
	sgensio_baud(gensio_to_sergensio(io), *((int *) buf));
	break;

    case GENSIO_EVENT_SER_DATASIZE:
	sgensio_datasize(gensio_to_sergensio(io), *((int *) buf));
	break;

    case GENSIO_EVENT_SER_PARITY:
	sgensio_parity(gensio_to_sergensio(io), *((int *) buf));
	break;

    case GENSIO_EVENT_SER_STOPBITS:
	sgensio_stopbits(gensio_to_sergensio(io), *((int *) buf));
	break;

    case GENSIO_EVENT_SER_FLOWCONTROL:
	sgensio_flowcontrol(gensio_to_sergensio(io), *((int *) buf));
	break;

    case GENSIO_EVENT_SER_IFLOWCONTROL:
	sgensio_iflowcontrol(gensio_to_sergensio(io), *((int *) buf));
	break;

    case GENSIO_EVENT_SER_SBREAK:
	sgensio_sbreak(gensio_to_sergensio(io), *((int *) buf));
	break;

    case GENSIO_EVENT_SER_DTR:
	sgensio_dtr(gensio_to_sergensio(io), *((int *) buf));
	break;

    case GENSIO_EVENT_SER_RTS:
	sgensio_rts(gensio_to_sergensio(io), *((int *) buf));
	break;

    default:
	rv = ENOTSUP;
	break;
    }

    if (io_ref.val)
	swig_free_ref_check(io_ref, accepter);
 out_put:
    OI_PY_STATE_PUT(gstate);

    return rv;
}

struct gensio_acc_data {
    swig_cb_val *handler_val;
    struct gensio_os_funcs *o;
};

static void
gensio_acc_shutdown_done(struct gensio_accepter *accepter, void *cb_data)
{
    swig_cb_val *cb = cb_data;
    swig_ref acc_ref;
    PyObject *args;
    OI_PY_STATE gstate;

    gstate = OI_PY_STATE_GET();

    acc_ref = swig_make_ref(accepter, gensio_accepter);
    args = PyTuple_New(1);
    Py_INCREF(acc_ref.val);
    PyTuple_SET_ITEM(args, 0, acc_ref.val);

    swig_finish_call(cb, "shutdown_done", args);

    swig_free_ref_check(acc_ref, accepter);
    deref_swig_cb_val(cb);
    OI_PY_STATE_PUT(gstate);
}

const char *gensio_log_level_to_str(int gloglevel)
{
    switch (gloglevel) {
    case GENSIO_LOG_FATAL:
	return "fatal";
    case GENSIO_LOG_ERR:
	return "error";
    case GENSIO_LOG_WARNING:
	return "warning";
    case GENSIO_LOG_INFO:
	return "info";
    }
    return "error";
}

static int
gensio_acc_child_event(struct gensio_accepter *accepter, int event, void *cdata)
{
    struct gensio_acc_data *data = gensio_acc_get_user_data(accepter);
    swig_ref acc_ref, io_ref;
    PyObject *args, *o;
    OI_PY_STATE gstate;
    struct gensio_data *iodata;
    struct gensio *io;

    if (event == GENSIO_ACC_EVENT_LOG) {
	struct gensio_loginfo *i = cdata;
	char buf[256];

	gstate = OI_PY_STATE_GET();

	acc_ref = swig_make_ref(accepter, gensio_accepter);
	args = PyTuple_New(3);
	Py_INCREF(acc_ref.val);
	PyTuple_SET_ITEM(args, 0, acc_ref.val);
	o = OI_PI_FromString(gensio_log_level_to_str(i->level));
	PyTuple_SET_ITEM(args, 1, o);
	vsnprintf(buf, sizeof(buf), i->str, i->args);
	o = OI_PI_FromString(buf);
	PyTuple_SET_ITEM(args, 2, o);

	swig_finish_call(data->handler_val, "accepter_log", args);

	swig_free_ref_check(acc_ref, accepter);
	OI_PY_STATE_PUT(gstate);
	return 0;
    }

    if (event == GENSIO_ACC_EVENT_NEW_CONNECTION) {
	io = cdata;
	iodata = malloc(sizeof(*data));
	if (!iodata)
	    return 0;
	iodata->refcount = 1;
	iodata->handler_val = NULL;
	iodata->o = data->o;
	gensio_set_callback(io, gensio_child_event, iodata);

	gstate = OI_PY_STATE_GET();

	acc_ref = swig_make_ref(accepter, gensio_accepter);
	io_ref = swig_make_ref(io, gensio);
	args = PyTuple_New(2);
	Py_INCREF(acc_ref.val);
	Py_INCREF(io_ref.val);
	PyTuple_SET_ITEM(args, 0, acc_ref.val);
	PyTuple_SET_ITEM(args, 1, io_ref.val);

	swig_finish_call(data->handler_val, "new_connection", args);

	swig_free_ref_check(acc_ref, accepter);
	swig_free_ref_check(io_ref, accepter);
	OI_PY_STATE_PUT(gstate);
	return 0;
    }

    return ENOTSUP;
}

struct sergensio_cbdata {
    const char *cbname;
    swig_cb_val *h_val;
};

#define stringify_1(x...)     #x
#define stringify(x...)       stringify_1(x)

#define sergensio_cbdata(name, h) \
({							\
    struct sergensio_cbdata *cbd = malloc(sizeof(*cbd));	\
    if (cbd) {						\
	cbd->cbname = stringify(name);			\
	cbd->h_val = ref_swig_cb(h, name);		\
    }							\
    cbd;						\
 })

static void
cleanup_sergensio_cbdata(struct sergensio_cbdata *cbd)
{
    deref_swig_cb_val(cbd->h_val);
    free(cbd);
}

static void
sergensio_cb(struct sergensio *sio, int err, unsigned int val, void *cb_data)
{
    struct sergensio_cbdata *cbd = cb_data;
    swig_ref sio_ref;
    PyObject *o, *args;
    OI_PY_STATE gstate;

    gstate = OI_PY_STATE_GET();

    sio_ref = swig_make_ref(sio, gensio);
    args = PyTuple_New(3);
    Py_INCREF(sio_ref.val);
    PyTuple_SET_ITEM(args, 0, sio_ref.val);
    if (err) {
	o = OI_PI_FromString(strerror(err));
    } else {
	Py_INCREF(Py_None);
	o = Py_None;
    }
    PyTuple_SET_ITEM(args, 1, o);
    o = PyInt_FromLong(val);
    PyTuple_SET_ITEM(args, 2, o);

    swig_finish_call(cbd->h_val, cbd->cbname, args);

    cleanup_sergensio_cbdata(cbd);
    OI_PY_STATE_PUT(gstate);
}

static PyObject *
add_python_result(PyObject *result, PyObject *val)
{
    if ((result == Py_None)) {
	Py_XDECREF(result);
	result = val;
    } else {
	PyObject *seq, *o2;

	if (!PyTuple_Check(result)) {
	    PyObject *tmpr = result;

	    result = PyTuple_New(1);
	    PyTuple_SetItem(result, 0, tmpr);
	}
	seq = PyTuple_New(1);
	PyTuple_SetItem(seq, 0, val);
	o2 = result;
	result = PySequence_Concat(o2, seq);
	Py_DECREF(o2);
	Py_DECREF(seq);
    }
    return result;
}

static bool check_for_err(int err)
{
    bool rv;

    if (err == EINTR)
	PyErr_CheckSignals();
    rv = (bool) PyErr_Occurred();
    return rv;
};

static void err_handle(char *name, int rv)
{
    if (!rv)
	return;
    PyErr_Format(PyExc_Exception, "gensio:%s: %s", name, strerror(rv));
}

static void ser_err_handle(char *name, int rv)
{
    if (!rv)
	return;
    PyErr_Format(PyExc_Exception, "sergensio:%s: %s", name, strerror(rv));
}

static void cast_error(char *to, char *from)
{
    PyErr_Format(PyExc_RuntimeError, "Error casting from %s to %s", from, to);
}

static void oom_err(void)
{
    PyErr_Format(PyExc_MemoryError, "Out of memory");
}
