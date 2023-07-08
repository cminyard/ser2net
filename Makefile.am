sbin_PROGRAMS = ser2net
ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS=-Wall -I$(top_srcdir)
AM_CPPFLAGS = -DSYSCONFDIR="\"${sysconfdir}\"" -DDATAROOT="\"${datarootdir}\""
ser2net_SOURCES = controller.c dataxfer.c readconfig.c port.c \
	ser2net.c led.c led_sysfs.c yamlconf.c auth.c gbuf.c trace.c \
	portconfig.c ser2net_str.c portinfo.c rotator.c defaults.c \
	addsysattrs.c mdns.c timeproc.c fileio.c
noinst_HEADERS = controller.h dataxfer.h readconfig.h defaults.h \
	ser2net.h led.h led_sysfs.h absout.h gbuf.h port.h mdns.h \
	timeproc.h fileio.h
man_MANS = ser2net.8 ser2net.yaml.5
EXTRA_DIST = $(man_MANS) ser2net.yaml ser2net.spec ser2net.init reconf \
	     ser2net.service.in

SUBDIRS = tests

DIST_SUBDIRS = $(SUBDIRS)

noinst_DATA = ser2net.service

ser2net.service: ${srcdir}/ser2net.service.in
	sed "s%@ser2netbindir@%${sbindir}%" $< >$@

clean-local:
	rm -f ser2net.service
