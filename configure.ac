AC_INIT(ser2net.c)
AM_INIT_AUTOMAKE(ser2net, 2.9.1)
AC_PROG_CC
AM_PROG_LIBTOOL
AC_ARG_WITH(uucp-locking,
 [  --with-uucp-locking     Enable UUCP-style locking],
 uucp_locking_flag="$withval",
 uucp_locking_flag=yes)
if test "$uucp_locking_flag" = yes; then
  AC_DEFINE(USE_UUCP_LOCKING)
fi
AC_ARG_WITH(tcp-wrappers,
 [  --with-tcp-wrappers     Enable tcpwrappers support],
 tcp_wrappers="$withval",
 tcp_wrappers="no")
if test "$tcp_wrappers" != "no"
then
  AC_HAVE_HEADERS(tcpd.h)
  AC_CHECK_LIB(wrap,main)
fi
AC_CONFIG_MACRO_DIR([m4])
AC_STDC_HEADERS
AC_CHECK_LIB(nsl,main)
AC_OUTPUT([Makefile ser2net.spec])
