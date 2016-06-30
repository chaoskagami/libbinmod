#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([libbinmod], [0.1], [chaos.kagami@gmail.com], [libbinmod], [http://github.com/chaoskagami/libbinmod])
AC_CONFIG_SRCDIR([blib.h])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_RANLIB

# Checks for header files.
# AC_CHECK_HEADERS([sys/types.h], [sys/stat.h], [fcntl.h], [sys/mman.h], [stdio.h], [stdlib.h], [stdint.h], [string.h], [unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UINT64_T

# Checks for library functions.
AC_FUNC_MMAP
AC_CHECK_FUNCS([munmap])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
