AC_INIT([ser2net], [3.5], [minyard@acm.org])
AM_INIT_AUTOMAKE([-Wall])
AC_PROG_CC
AM_PROG_LIBTOOL
AC_ARG_WITH(uucp-locking,
 [  --with-uucp-locking        Enable UUCP-style locking],
 uucp_locking_flag="$withval",
 uucp_locking_flag=yes)
if test "$uucp_locking_flag" = yes; then
  AC_DEFINE(USE_UUCP_LOCKING)
fi
AC_ARG_WITH(tcp-wrappers,
 [  --with-tcp-wrappers        Enable tcpwrappers support],
 tcp_wrappers="$withval",
 tcp_wrappers="no")
if test "$tcp_wrappers" != "no"
then
  AC_HAVE_HEADERS(tcpd.h)
  AC_CHECK_LIB(wrap,main)
fi

AC_ARG_WITH(sysfs-led-support,
 [  --with-sysfs-led-support   Enable LED support (Linux only)],
 sysfs_led_support_flag="$withval",
 sysfs_led_support_flag=check)
if test "x$sysfs_led_support_flag" = "xcheck"; then
  case "$host_os" in
    linux*) sysfs_led_support_flag=yes ;;
    *) sysfs_led_support_flag=no ;;
  esac
fi
if test "x$sysfs_led_support_flag" = "xyes"; then
  AC_DEFINE(USE_SYSFS_LED_FEATURE)
fi

AX_HAVE_EPOLL_PWAIT(
   [AX_CONFIG_FEATURE_ENABLE(epoll_pwait)],
   [AX_CONFIG_FEATURE_DISABLE(epoll_pwait)])
AX_CONFIG_FEATURE(
   [epoll_pwait], [This platform supports epoll(7) with epoll_pwait(2)],
   [HAVE_EPOLL_PWAIT], [This platform supports epoll(7) with epoll_pwait(2).])

use_pthreads=yes
AC_ARG_WITH(pthreads,
[  --with-pthreads=yes|no      Use pthreads or not.],
    if test "x$withval" = "xyes"; then
      use_pthreads=yes
    elif test "x$withval" = "xno"; then
      use_pthreads=no
    fi,
)

tryopenipmi=yes
AC_ARG_WITH(openipmi,
[  --with-openipmi=yes|no      Look for openipmi.],
    if test "x$withval" = "xyes"; then
      tryopenipmi=yes
    elif test "x$withval" = "xno"; then
      tryopenipmi=no
    fi,
)
if test "x$use_pthreads" != "xno"; then
   LIBS="$LIBS -lpthread"
   AC_DEFINE(USE_PTHREADS)
fi

AC_ARG_WITH(openipmiflags,
[  --with-openipmiflags=flags  Set the flags to compile with OpenIPMI.],
    CPPFLAGS="$CPPFLAGS $withval"
)

AC_ARG_WITH(openipmilibs,
[  --with-openipmilibs=libs    Set the libraries to link with OpenIPMI.],
    LIBS="$LIBS $withval"
)

# Handle OpenIPMI support
HAVE_OPENIPMI=no
if test "x$tryopenipmi" != "xno"; then
   found_ipmiif=no
   AC_CHECK_HEADER(OpenIPMI/ipmiif.h, found_ipmiif=yes; )
   if test "x$found_ipmiif" == "xyes"; then
      AC_CHECK_LIB(OpenIPMI, ipmi_alloc_os_handler, HAVE_OPENIPMI=yes)
   fi
fi

if test "x$HAVE_OPENIPMI" != "xno"; then
   if test "x$use_pthreads" == "xyes"; then
      LIBS="$LIBS -lOpenIPMI -lOpenIPMIpthread"
   else
      LIBS="$LIBS -lOpenIPMI -lOpenIPMIposix"
   fi
   AC_DEFINE(HAVE_OPENIPMI)
fi

LIBS="$LIBS -lrt"

# Handle RS485 support
AC_CHECK_DECLS([TIOCSRS485], [], [], [[#include <sys/ioctl.h>]])

# enable silent build
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_CONFIG_MACRO_DIR([m4])
AC_STDC_HEADERS
AC_CHECK_LIB(nsl,main)
AC_OUTPUT([Makefile ser2net.spec])
