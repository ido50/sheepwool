AC_INIT([SheepWool],[6.0.0],[sheepwool@ido50.net],[sheepwool],[https://github.com/ido50/sheepwool])
AC_CONFIG_SRCDIR([src/main.c])
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

AC_MSG_WARN([CFLAGS are: ${CFLAGS}])
AC_MSG_WARN([LDFLAGS are: ${LDFLAGS}])

AC_PROG_INSTALL

PKG_CHECK_MODULES([LIBMAGIC], [libmagic])
PKG_CHECK_MODULES([LIBMICROHTTPD], [libmicrohttpd])

AC_HEADER_STDBOOL
AC_CHECK_HEADERS([unistd.h])
AC_CHECK_FUNCS([strtol])
AC_CHECK_FUNCS([strerror])
AC_CHECK_FUNCS([getcwd])
AC_CHECK_FUNCS(pledge, AC_DEFINE(HAVE_PLEDGE, 1, [Define to 1 if pledge is available]), AC_DEFINE(HAVE_PLEDGE, 0))
AC_CHECK_FUNCS(unveil, AC_DEFINE(HAVE_UNVEIL, 1, [Define to 1 if unveil is available]), AC_DEFINE(HAVE_UNVEIL, 0))


AX_HAVE_EPOLL(
              [AX_CONFIG_FEATURE_ENABLE(epoll)],
              [AX_CONFIG_FEATURE_DISABLE(epoll)])
AX_CONFIG_FEATURE(
                  [epoll], [This platform supports epoll(7)],
                  [HAVE_EPOLL], [This platform supports epoll(7).])
AX_HAVE_POLL(
             [AX_CONFIG_FEATURE_ENABLE(poll)],
             [AX_CONFIG_FEATURE_DISABLE(poll)])
AX_CONFIG_FEATURE(
                  [poll], [This platform supports poll(7)],
                  [HAVE_POLL], [This platform supports poll(7).])

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 ])
AC_OUTPUT
