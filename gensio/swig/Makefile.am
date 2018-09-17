
EXTRA_DIST = gensio.i

SUBDIRS = . $(PYTHON_DIR)
DIST_SUBDIRS = python

AM_CFLAGS = -I $(top_srcdir)
noinst_lib_LTLIBRARIES = libgensio_swig.la
noinst_libdir = $(shell readlink -f $(top_builddir)/dummy_install)

libgensio_swig_la_SOURCES = termios.c
