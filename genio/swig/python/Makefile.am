
AM_CFLAGS = $(PYTHON_CPPFLAGS) \
	    -I $(top_srcdir) \
	    -DPYTHON_HAS_POSIX_THREADS=@PYTHON_HAS_POSIX_THREADS@

pythonlibdir=$(PYTHON_INSTALL_LIB_DIR)
PYPATH=$(top_builddir)/swig/python:$(top_builddir)/swig/python/.libs
pythonlib_LTLIBRARIES = _genio.la

genio_wrap.c genio.py: $(top_srcdir)/genio/swig/genio.i \
		$(top_srcdir)/genio/swig/python/genio_python.h \
		$(top_srcdir)/genio/swig/python/genio_python.i
	$(SWIG) $(DEFS) -python $(PYTHON_SWIG_FLAGS) -o genio_wrap.c \
		-I$(top_srcdir)/genio/swig/python $<

EXTRA_DIST = genio_python.i

nodist__genio_la_SOURCES = genio_wrap.c
_genio_la_LIBADD = \
	$(top_builddir)/utils/utils.lo $(top_builddir)/utils/selector.lo \
	$(top_builddir)/utils/telnet.lo $(top_builddir)/utils/buffer.lo \
	$(top_builddir)/utils/waiter.lo $(top_builddir)/utils/uucplock.lo \
	$(top_builddir)/genio/genio.lo $(top_builddir)/genio/genio_tcp.lo \
	$(top_builddir)/genio/genio_udp.lo \
	$(top_builddir)/genio/genio_stdio.lo \
	$(top_builddir)/genio/sergenio.lo \
	$(top_builddir)/genio/sergenio_telnet.lo \
	$(top_builddir)/genio/sergenio_termios.lo \
	$(top_builddir)/genio/swig/termios.lo
_genio_la_LDFLAGS = -module -avoid-version

clean-local:
	rm -rf __pycache__ genio_wrap.c

install-exec-local: _genio.la genio.py
	$(INSTALL) -d $(DESTDIR)$(PYTHON_INSTALL_DIR)
	$(INSTALL_DATA) genio.py "$(DESTDIR)$(PYTHON_INSTALL_DIR)"

uninstall-local:
	$(LIBTOOL) --mode=uninstall rm -f "$(DESTDIR)$(PYTHON_INSTALL_LIB_DIR)/_genio.so"
	rm -f "$(DESTDIR)$(PYTHON_INSTALL_DIR)/genio.py"
