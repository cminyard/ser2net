
EXTRA_DIST = genio.i

SUBDIRS = . $(PYTHON_DIR)
DIST_SUBDIRS = python

AM_CFLAGS = -I $(top_srcdir)
noinst_lib_LTLIBRARIES = libser2net_swig.la
noinst_libdir = $(shell readlink -f $(top_builddir)/dummy_install)

libser2net_swig_la_SOURCES = termios.c
