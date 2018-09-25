
AM_CFLAGS = -I$(top_srcdir) $(OPENSSL_INCLUDES)

noinst_LIBRARIES = libgensio.a

noinst_HEADERS = gensio.h gensio_class.h sergensio.h sergensio_class.h \
	gensio_selector.h gensio_base.h telnet.h

MY_SOURCES = gensio.c gensio_tcp.c gensio_udp.c gensio_stdio.c \
	sergensio.c sergensio_telnet.c sergensio_termios.c \
	gensio_selector.c gensio_ssl.c gensio_base.c gensio_filter_ssl.c \
	gensio_filter_telnet.c telnet.c \
	gensio_ll_fd.c gensio_ll_gensio.c gensio_acc_gensio.c

noinst_lib_LTLIBRARIES = libgensio.la
noinst_libdir = $(shell readlink -f $(top_builddir)/dummy_install)

libgensio_la_SOURCES = $(MY_SOURCES)

libgensio_a_SOURCES = $(MY_SOURCES)
libgensio_a_CFLAGS = $(AM_CFLAGS)

SUBDIRS = . $(SWIG_DIR)

DIST_SUBDIRS = swig
