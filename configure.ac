AC_INIT([libfluid_base], [1.0], [allanv@cpqd.com.br], [libfluid_base], [http://www.cpqd.com.br/])
AC_PREREQ([2.59])
AM_INIT_AUTOMAKE([1.10 no-define foreign])
AC_CONFIG_HEADERS([config.h])
AC_PROG_CXX
AC_PROG_LIBTOOL

AC_SUBST([LIBFLUID_BASE_SO_VERSION], [0:0:0])

AC_CONFIG_FILES([Makefile libfluid_base.pc])

PKG_CHECK_MODULES([libevent], [libevent >= 2.0.16-stable])
PKG_CHECK_MODULES([libevent_pthreads], [libevent_pthreads >= 2.0.16-stable])

AC_ARG_ENABLE([tls],
     AS_HELP_STRING(--disable-tls, Disable TLS support),
        [], [enable_tls=yes])

AM_CONDITIONAL(TLS, false)
if test x$enable_tls != xno; then
  PKG_CHECK_MODULES([libevent_openssl], [libevent_openssl >= 2.0.16-stable])
  AC_DEFINE(HAVE_TLS, 1, [Define if the system has OpenSSL TLS support])
  AM_CONDITIONAL(TLS, true)
fi

AC_OUTPUT
