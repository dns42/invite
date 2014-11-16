#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([invite], [0.1], [daniel.stodden@gmail.com])
AC_CONFIG_SRCDIR([src/invite.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([foreign dist-xz])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h syslog.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
PKG_CHECK_MODULES([SOFIASIP], [sofia-sip-ua >= 1.12],,
	          AC_MSG_ERROR(sofio-sip required))

AC_CONFIG_FILES([Makefile
		 src/Makefile])
AC_OUTPUT
