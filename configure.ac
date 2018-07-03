AC_INIT([ser2net], [3.5], [minyard@acm.org])
AM_INIT_AUTOMAKE([-Wall])
AC_PROG_CC
AM_PROG_AR
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

tryswig=yes
swigprog=
AC_ARG_WITH(swig,
[  --with-swig[[=yes|no|PATH]]       Look for swig, with the optional path.],
    if test "x$withval" = "x"; then
      tryswig=yes
    elif test "x$withval" = "xyes"; then
      tryswig=yes
    elif test "x$withval" = "xno"; then
      tryswig=no
    else
      swigprog=$withval
    fi,
)

pythonprog=
trypython=yes
AC_ARG_WITH(python,
[  --with-python[[=yes|no|PATH]]     Look for python, with the optional path.],
    if test "x$withval" = "x"; then
      trypython=yes
    elif test "x$withval" = "xyes"; then
      trypython=yes
    elif test "x$withval" = "xno"; then
      trypython=no
    else
      pythonprog="$withval"
      trypython=yes
    fi,
)

pythoninstalldir=
AC_ARG_WITH(pythoninstall,
[  --with-pythoninstall=PATH       Install python modules in the given location.],
    pythoninstalldir="$withval",
)

pythoninstalllibdir=
AC_ARG_WITH(pythoninstalllib,
[  --with-pythoninstalllib=PATH       Install python libraries in the given location.],
    pythoninstalllibdir="$withval",
)

pythoncflags=
AC_ARG_WITH(pythoncflags,
[  --with-pythoncflags=PATH        Use the given flags when compiling python parts.],
    pythoncflags="$withval",
)

pythonusepthreads=
AC_ARG_WITH(pythonusepthreads,
[  --with-pythonusepthreads[[=yes|no]] Use threads with python.],
   if test "x$withval" = "xyes"; then
      pythonusepthreads="yes"
   elif test "x$withval" = "xno"; then
      pythonusepthreads="no"
   elif test "x$withval" = "x"; then
      pythonusepthreads="yes"
   fi,
)

AC_SEARCH_LIBS([clock_gettime], [rt posix4])

# Handle RS485 support
AC_CHECK_DECLS([TIOCSRS485], [], [], [[#include <sys/ioctl.h>]])

# enable silent build
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_CONFIG_MACRO_DIR([m4])
AC_STDC_HEADERS
AC_CHECK_LIB(nsl,main)

# Now check for swig
SWIG_DIR=
SWIG=
if test "x$tryswig" = "xyes"; then
   if test "x$swigprog" != "x"; then
      SWIG="$swigprog"
   fi
   AX_PKG_SWIG([1.3.21])
   if test "x$SWIG" != "x"; then
      AC_DEFINE([HAVE_SWIG], [], [Have swig installed])
      SWIG_DIR=swig
   fi
fi
AC_SUBST(SWIG_DIR)
AC_SUBST(SWIG)

# Handle PYTHON support
PYTHON_DIR=
PYTHON_INSTALL_DIR=
PYTHON_INSTALL_LIB_DIR=
PYTHON_SWIG_FLAGS=
if test "x$trypython" = "xyes"; then
   if test "x$pythonprog" != "x"; then
      PYTHON="$pythonprog"
   fi
   if test "x$pythoncflags" != "x"; then
      PYTHON_CPPFLAGS="$pythoncflags"
   fi
   AX_PYTHON_DEVEL
fi
if test "x$PYTHON" != "x"; then
   AX_PROG_PYTHON_VERSION([3.0.0], [PYTHON_SWIG_FLAGS=-py3], [])
   PYTHON_DIR=python
   if test "x$pythoninstalldir" = "x"; then
      PYTHON_INSTALL_DIR="$PYTHON_SITE_PKG"
   else
      PYTHON_INSTALL_DIR="$pythoninstalldir"
   fi
   if test "x$pythoninstalllibdir" = "x"; then
      PYTHON_INSTALL_LIB_DIR="$PYTHON_INSTALL_DIR"
   else
      PYTHON_INSTALL_LIB_DIR="$pythoninstalllibdir"
   fi

   if test "x$pythonusepthreads" = "x"; then
      cat - <<_ACEOF >conftest.py
try:
  import threading
  print('yes')
except:
  print('no')
_ACEOF
      pythonusepthreads=`$PYTHON conftest.py`
      rm -f conftest.py
   fi
   echo "checking for python threads... $pythonusepthreads"

   if test "x$pythonusepthreads" = "xyes"; then
      PYTHON_HAS_POSIX_THREADS=1
   else
      PYTHON_HAS_POSIX_THREADS=0
   fi
fi

AC_SUBST(PYTHON_DIR)
AC_SUBST(PYTHON_INSTALL_DIR)
AC_SUBST(PYTHON_INSTALL_LIB_DIR)
AC_SUBST(PYTHON_HAS_POSIX_THREADS)
AC_SUBST(PYTHON_SWIG_FLAGS)

AC_OUTPUT([Makefile ser2net.spec
	utils/Makefile
	tests/Makefile
	genio/Makefile
	genio/swig/Makefile
	genio/swig/python/Makefile])
