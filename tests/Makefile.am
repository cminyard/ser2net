
AM_CFLAGS = -I$(top_srcdir)

noinst_PROGRAMS = sertest

sertest_SOURCES = sertest.c

sertest_LDADD = $(top_builddir)/genio/libgenio.a \
		$(top_builddir)/utils/libutils.a \
		-lreadline -lssl -lcrypto

can_builddir = $(shell readlink -f $(top_builddir))

AM_TESTS_ENVIRONMENT = PYTHONPATH=$(can_builddir)/genio/swig/python:$(can_builddir)/genio/swig/python/.libs TESTPATH=$(can_srcdir)/tests SER2NET_EXEC=$(can_builddir)/ser2net

TESTS = test_genio.py \
	test_xfer_basic_tcp.py test_xfer_basic_udp.py test_xfer_basic_stdio.py \
	test_tty_base.py test_rfc2217.py \
	test_xfer_small_tcp.py test_xfer_small_udp.py test_xfer_small_stdio.py \
	test_xfer_large_stdio.py test_xfer_large_tcp.py \
	test_xfer_large_telnet.py
