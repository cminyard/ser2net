AC_INIT([ser2net], [4.3.11], [minyard@acm.org])
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

use_pam=check
AC_ARG_WITH(pam,
[  --with-pam=yes|no           Support PAM authentication or not.],
    if test "x$withval" = "xyes"; then
      use_pam=yes
    elif test "x$withval" = "xno"; then
      use_pam=no
    else
      [AC_MSG_FAILURE([Unknown option to --with-pam, use yes or no])]
    fi,
)

if test "$use_pam" != "no"; then
  have_pam=yes
  AC_CHECK_HEADER(security/pam_appl.h, [], [have_pam=no])
  if test "$have_pam" = "yes"; then
    AC_CHECK_LIB(pam, pam_start, [], [have_pam=no])
  fi
  if test "$use_pam" = "yes" -a "$have_pam" = "no"; then
    AC_MSG_ERROR([Pam enabled, but no pam support found])
  fi
  use_pam=$have_pam
fi
if test "x$use_pam" != "xno"; then
    LIBS="$LIBS -lpam"
    AC_DEFINE([USE_PAM], [], [Enable PAM support])
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
AC_CHECK_HEADERS([wordexp.h])
AC_CHECK_FUNCS(wordexp)

PKG_CHECK_MODULES(GENSIO, libgensio, [LIBS="$LIBS $GENSIO_LIBS"],
   [AC_CHECK_HEADER(gensio/gensio.h, [],
      [AC_MSG_ERROR([gensio.h not found, please install gensio dev package])])
   AC_CHECK_LIB(gensio, str_to_gensio, [],
      [AC_MSG_ERROR([libgensio won't link, please install gensio dev package])])])

AC_CHECK_LIB(gensio, gensio_list_add_tail, [],
   [PKG_CHECK_MODULES(GENSIOOSH, libgensioosh, [LIBS="$LIBS $GENSIOOSH_LIBS"],
      [AC_CHECK_LIB(gensioosh, gensio_list_add_tail, [],
         [AC_MSG_ERROR([libgensioosh won't link, please install gensio dev package])])])])

AC_CHECK_LIB(gensio, gensio_alloc_mdns, [],
   [PKG_CHECK_MODULES(GENSIOMDNS, libgensiomdns, [LIBS="$LIBS $GENSIOMDNS_LIBS"],
      [AC_CHECK_LIB(gensiomdns, gensio_alloc_mdns, [],
         [AC_MSG_ERROR([libgensiomdns won't link, please install gensio dev package])])])])

AC_CHECK_HEADER(yaml.h, [],
   [AC_MSG_ERROR([yaml.h not found, please install libyaml dev package])])
AC_CHECK_LIB(yaml, yaml_document_initialize, [],
   [AC_MSG_ERROR([libyaml won't link, please install libyaml dev package])])

AC_OUTPUT([Makefile tests/Makefile])
