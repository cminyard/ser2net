
AM_CFLAGS = -I$(top_srcdir)

noinst_LIBRARIES = libgenio.a

noinst_HEADERS = genio.h genio_internal.h sergenio.h sergenio_internal.h

MY_SOURCES = genio.c genio_tcp.c genio_udp.c genio_stdio.c \
	sergenio.c sergenio_telnet.c sergenio_termios.c

noinst_lib_LTLIBRARIES = libser2net_genio.la
noinst_libdir = $(shell readlink -f $(top_builddir)/dummy_install)

libser2net_genio_la_SOURCES = $(MY_SOURCES)

libgenio_a_SOURCES = $(MY_SOURCES)
libgenio_a_CFLAGS = $(AM_CFLAGS)

SUBDIRS = . $(SWIG_DIR)

DIST_SUBDIRS = swig
