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

%typemap(in) swig_cb * {
    if ($input == Py_None)
	$1 = NULL;
    else
	$1 = $input;
}

%exception {
    $action
    if (PyErr_Occurred())
	SWIG_fail;
}

%typemap(in, numinputs=0) char **rbuffer (char *temp),
                          size_t *rbuffer_len (size_t temp) {
    $1 = &temp;
}

%typemap(argout) (char **rbuffer, size_t *rbuffer_len) {
    PyObject *r = PyString_FromStringAndSize(*$1, *$2);

    if (($result == Py_None)) {
	Py_XDECREF($result);
	$result = r;
    } else {
	PyObject *seq, *o2;

	if (!PyTuple_Check($result)) {
	    PyObject *tmpr = $result;
	    $result = PyTuple_New(1);
	    PyTuple_SetItem($result, 0, tmpr);
	}
	seq = PyTuple_New(1);
	PyTuple_SetItem(seq, 0, r);
	o2 = $result;
	$result = PySequence_Concat(o2, seq);
	Py_DECREF(o2);
	Py_DECREF(seq);
    }
    free(*$1);
}
