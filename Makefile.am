sbin_PROGRAMS = ser2net
AM_CFLAGS=-Wall
ser2net_SOURCES = controller.c dataxfer.c devcfg.c readconfig.c selector.c \
	ser2net.c utils.c telnet.c
noinst_HEADERS = controller.h dataxfer.h devcfg.h readconfig.h selector.h \
	utils.h telnet.h
man_MANS = ser2net.8
EXTRA_DIST = $(man_MANS) ser2net.conf ser2net.spec ser2net.init

