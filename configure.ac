AC_INIT([SheepWool],[6.0.0],[sheepwool@ido50.net],[sheepwool],[https://github.com/ido50/sheepwool])
AC_CONFIG_SRCDIR([src/sheepwool.c])
AC_CONFIG_AUX_DIR([vendor])
AC_CONFIG_HEADERS([src/config.h])

AX_IS_RELEASE([git-directory])
AX_CHECK_ENABLE_DEBUG([info],[DEBUG],[NDEBUG])

AM_INIT_AUTOMAKE()

LT_INIT

AX_PERL_EXT_FLAGS([PERLXS_CFLAGS], [PERLXS_LDFLAGS])
CFLAGS="$CFLAGS $PERLXS_CFLAGS"
LDFLAGS="$LDFLAGS $PERLXS_LDFLAGS"
AC_SUBST([PERLXS_CFLAGS])
AC_SUBST([PERLXS_LDFLAGS])

AC_PROG_INSTALL

PKG_CHECK_MODULES([LIBMAGIC], [libmagic])
PKG_CHECK_MODULES([LIBMICROHTTPD], [libmicrohttpd])
PKG_CHECK_MODULES([LIBCONFIG], [libconfig])
PKG_CHECK_MODULES([LIBCURL], [libcurl])
PKG_CHECK_MODULES([LIBPCRE], [libpcre])
AX_CHECK_ZLIB()

AC_ARG_WITH([brotli], AS_HELP_STRING([--with-brotli], [Build with brotli compression support]))
AS_IF([test "x$with_brotli" = "xyes"], [
   PKG_CHECK_MODULES([LIBBROTLIENC], [libbrotlienc])
   AC_DEFINE(HAVE_BROTLI, 1, [Define to 1 if brotli is available])
])

AC_HEADER_STDBOOL
AC_CHECK_HEADERS([unistd.h])
AC_CHECK_HEADERS([uthash.h])
AC_CHECK_HEADERS([utarray.h])
AC_CHECK_FUNCS([strtol])
AC_CHECK_FUNCS([strerror])
AC_CHECK_FUNCS([getcwd])
AC_CHECK_FUNCS(
               pledge,
               AC_DEFINE(HAVE_PLEDGE, 1, [Define to 1 if pledge is available]),
               AC_DEFINE(HAVE_PLEDGE, 0))
AC_CHECK_FUNCS(
               unveil,
               AC_DEFINE(HAVE_UNVEIL, 1, [Define to 1 if unveil is available]),
               AC_DEFINE(HAVE_UNVEIL, 0))

AC_MSG_WARN([CFLAGS are: ${CFLAGS}])
AC_MSG_WARN([LDFLAGS are: ${LDFLAGS}])

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 ])
AC_OUTPUT
