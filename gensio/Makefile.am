
AM_CFLAGS = -I$(top_srcdir) $(OPENSSL_INCLUDES)

lib_LTLIBRARIES = libgensio.la

pkginclude_HEADERS = gensio.h gensio_class.h sergensio.h sergensio_class.h \
	gensio_selector.h waiter.h gensio_base.h gensio_acc_gensio.h \
	gensio_ll_fd.h gensio_ll_gensio.h selector.h argvutils.h

noinst_HEADERS = telnet.h heap.h utils.h uucplock.h buffer.h \
	gensio_filter_ssl.h gensio_filter_telnet.h gensio_ll_ipmisol.h

libgensio_la_SOURCES = \
	gensio.c gensio_tcp.c gensio_udp.c gensio_stdio.c \
	sergensio.c sergensio_telnet.c sergensio_termios.c uucplock.c \
	gensio_selector.c waiter.c \
	gensio_ssl.c gensio_base.c gensio_filter_ssl.c \
	gensio_filter_telnet.c telnet.c buffer.c \
	gensio_ll_fd.c gensio_ll_gensio.c gensio_acc_gensio.c \
	gensio_ll_ipmisol.c sergensio_ipmisol.c \
	utils.c selector.c

SUBDIRS = . $(SWIG_DIR)

DIST_SUBDIRS = swig
