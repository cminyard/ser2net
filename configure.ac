AC_INIT([ser2net], [4.2.0], [minyard@acm.org])
AM_INIT_AUTOMAKE([-Wall])
AC_PROG_CC
AM_PROG_AR
AM_PROG_LIBTOOL

use_pthreads=yes
use_pthreads_set=false
AC_ARG_WITH(pthreads,
[  --with-pthreads=yes|no      Use pthreads or not.],
    use_pthreads_set=true
    if test "x$withval" = "xyes"; then
      use_pthreads=yes
    elif test "x$withval" = "xno"; then
      use_pthreads=no
    fi,
)

if test "x$use_pthreads" != "xno"; then
   AX_PTHREAD(
      [LIBS="$LIBS $PTHREAD_LIBS"
       CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
       CC="$PTHREAD_CC"
       AC_DEFINE([USE_PTHREADS], [], [Enable multithreaded support])],
      [if $use_pthreads_set; then
          AC_MSG_FAILURE([--with-pthreads was given, but no working pthread library was found])
       fi])
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
