
AM_CFLAGS = -I$(top_srcdir)

noinst_PROGRAMS = sertest

sertest_SOURCES = sertest.c

sertest_LDADD = $(top_builddir)/genio/libgenio.a \
		$(top_builddir)/utils/libutils.a \
		-lreadline

AM_TESTS_ENVIRONMENT = PYTHONPATH=$(top_builddir)/genio/swig/python:$(top_builddir)/genio/swig/python/.libs TESTPATH=$(top_srcdir)/tests SER2NET_EXEC=$(top_builddir)/ser2net

TESTS = run_tests
