
AM_CFLAGS = $(PYTHON_CPPFLAGS) \
	    -I $(top_srcdir) \
	    -DPYTHON_HAS_POSIX_THREADS=@PYTHON_HAS_POSIX_THREADS@

pythonlibdir=$(PYTHON_INSTALL_LIB_DIR)
PYPATH=$(top_builddir)/swig/python:$(top_builddir)/swig/python/.libs
pythonlib_LTLIBRARIES = _gensio.la

gensio_wrap.c gensio.py: $(top_srcdir)/gensio/swig/gensio.i \
		$(top_srcdir)/gensio/swig/python/gensio_python.h \
		$(top_srcdir)/gensio/swig/python/gensio_python.i
	$(SWIG) $(DEFS) -python $(PYTHON_SWIG_FLAGS) -o gensio_wrap.c \
		-I$(top_srcdir)/gensio/swig/python $<

EXTRA_DIST = gensio_python.i

nodist__gensio_la_SOURCES = gensio_wrap.c
_gensio_la_LIBADD = \
	$(top_builddir)/utils/utils.lo $(top_builddir)/utils/selector.lo \
	$(top_builddir)/gensio/telnet.lo $(top_builddir)/gensio/buffer.lo \
	$(top_builddir)/gensio/gensio.lo $(top_builddir)/gensio/gensio_tcp.lo \
	$(top_builddir)/gensio/waiter.lo $(top_builddir)/gensio/uucplock.lo \
	$(top_builddir)/gensio/gensio_base.lo \
	$(top_builddir)/gensio/gensio_filter_ssl.lo \
	$(top_builddir)/gensio/gensio_filter_telnet.lo \
	$(top_builddir)/gensio/gensio_ll_fd.lo \
	$(top_builddir)/gensio/gensio_ll_gensio.lo \
	$(top_builddir)/gensio/gensio_acc_gensio.lo \
	$(top_builddir)/gensio/gensio_udp.lo \
	$(top_builddir)/gensio/gensio_stdio.lo \
	$(top_builddir)/gensio/gensio_ssl.lo \
	$(top_builddir)/gensio/sergensio.lo \
	$(top_builddir)/gensio/sergensio_telnet.lo \
	$(top_builddir)/gensio/sergensio_termios.lo \
	$(top_builddir)/gensio/gensio_selector.lo \
	$(top_builddir)/gensio/swig/termios.lo \
	$(OPENSSL_LIBS)
_gensio_la_LDFLAGS = -module -avoid-version $(OPENSSL_LDFLAGS)

clean-local:
	rm -rf __pycache__ gensio_wrap.c

install-exec-local: _gensio.la gensio.py
	$(INSTALL) -d $(DESTDIR)$(PYTHON_INSTALL_DIR)
	$(INSTALL_DATA) gensio.py "$(DESTDIR)$(PYTHON_INSTALL_DIR)"

uninstall-local:
	$(LIBTOOL) --mode=uninstall rm -f "$(DESTDIR)$(PYTHON_INSTALL_LIB_DIR)/_gensio.so"
	rm -f "$(DESTDIR)$(PYTHON_INSTALL_DIR)/gensio.py"
