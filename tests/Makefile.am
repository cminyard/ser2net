
AM_CFLAGS = -I$(top_srcdir)

noinst_PROGRAMS = sertest

sertest_SOURCES = sertest.c

sertest_LDADD = $(top_builddir)/genio/libgenio.a \
		$(top_builddir)/utils/libutils.a \
		-lreadline
