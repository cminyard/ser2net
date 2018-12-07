
AM_CFLAGS = $(PYTHON_CPPFLAGS) \
	    -I $(top_srcdir) \
	    -DPYTHON_HAS_POSIX_THREADS=@PYTHON_HAS_POSIX_THREADS@

pythonlibdir=$(PYTHON_INSTALL_LIB_DIR)
PYPATH=$(top_builddir)/swig/python:$(top_builddir)/swig/python/.libs
pythonlib_LTLIBRARIES = _gensio.la

noinst_HEADERS = gensio_python.h

gensio_wrap.c gensio.py: $(top_srcdir)/gensio/swig/gensio.i \
		$(top_srcdir)/gensio/swig/python/gensio_python.h \
		$(top_srcdir)/gensio/swig/python/gensio_python.i
	$(SWIG) $(DEFS) -python $(PYTHON_SWIG_FLAGS) -o gensio_wrap.c \
		-I$(top_srcdir)/gensio/swig/python $<

EXTRA_DIST = gensio_python.i

nodist__gensio_la_SOURCES = gensio_wrap.c
_gensio_la_LIBADD = ../../libgensio.la ../termios.lo $(OPENSSL_LIBS)
_gensio_la_LDFLAGS = -module -avoid-version $(OPENSSL_LDFLAGS)

clean-local:
	rm -rf __pycache__ gensio_wrap.c

install-exec-local: _gensio.la gensio.py
	$(INSTALL) -d $(DESTDIR)$(PYTHON_INSTALL_DIR)
	$(INSTALL_DATA) gensio.py "$(DESTDIR)$(PYTHON_INSTALL_DIR)"

uninstall-local:
	$(LIBTOOL) --mode=uninstall rm -f "$(DESTDIR)$(PYTHON_INSTALL_LIB_DIR)/_gensio.so"
	rm -f "$(DESTDIR)$(PYTHON_INSTALL_DIR)/gensio.py"
