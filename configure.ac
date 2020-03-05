AC_INIT([ser2net], [4.1.3], [minyard@acm.org])
AM_INIT_AUTOMAKE([-Wall])
AC_PROG_CC
AM_PROG_AR
AM_PROG_LIBTOOL

use_pthreads=yes
AC_ARG_WITH(pthreads,
[  --with-pthreads=yes|no      Use pthreads or not.],
    if test "x$withval" = "xyes"; then
      use_pthreads=yes
    elif test "x$withval" = "xno"; then
      use_pthreads=no
    fi,
)

if test "x$use_pthreads" != "xno"; then
   AX_PTHREAD
   if test "x$use_pthreads$ax_pthread_ok" = "xyesno"; then
      AC_MSG_FAILURE([--with-pthreads was given, but no working pthread library was found])
   fi
   AM_CONDITIONAL([USE_PTHREADS], [test "x$ax_pthread_ok" = "xyes"])
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

# enable silent build
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_CONFIG_MACRO_DIR([m4])
AC_STDC_HEADERS
AC_CHECK_LIB(nsl,main)

PKG_CHECK_MODULES(GENSIO, libgensio, [LIBS=$GENSIO_LIBS],
   [AC_CHECK_HEADER(gensio/gensio.h, [],
      [AC_MSG_ERROR([gensio.h not found, please install gensio dev package])])
   AC_CHECK_LIB(gensio, str_to_gensio, [],
      [AC_MSG_ERROR([libgensio won't link, please install gensio dev package])])])

AC_CHECK_HEADER(yaml.h, [],
   [AC_MSG_ERROR([yaml.h not found, please install libyaml dev package])])
AC_CHECK_LIB(yaml, yaml_document_initialize, [],
   [AC_MSG_ERROR([libyaml won't link, please install gensio dev package])])

AC_OUTPUT([Makefile tests/Makefile])
