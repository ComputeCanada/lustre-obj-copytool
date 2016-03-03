AC_PREREQ(2.59)
AC_INIT(lustre-s3-copytool, 0.1)
AC_CONFIG_SRCDIR([src/lhsmtool_s3.c])
AM_INIT_AUTOMAKE

#Enable silent build by default
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

#AC_PROG_MKDIR_P
AC_PROG_CC
AC_PROG_RANLIB

AC_CHECK_LIB(lz4, LZ4_compressBound)
AC_CHECK_LIB(pthread, pthread_exit)
AC_CHECK_LIB(config, config_init)
AC_CHECK_LIB(crypto, MD5_Init)
AC_CHECK_LIB(lustreapi, llapi_error)

AC_ARG_WITH( [lustre], AS_HELP_STRING([--with-lustre=<lustre_src_dir>],[indicate alternative location for lustre sources]),
             LDIR="$withval", LDIR="lustre-release")
AC_CHECK_FILE("$LDIR/lustre/include/lustre/lustre_idl.h",,
             AC_MSG_ERROR("Could not find Lustre source tree.  Use --with-lustre=<lustre_src_dir>"))

AC_ARG_ENABLE( [rados], [AS_HELP_STRING([--enable-rados], [build with rados])],
            [with_rados=yes],[])
AC_ARG_ENABLE( [s3], [AS_HELP_STRING([--enable-s3], [build with s3])],
            [with_s3=yes],[])

AS_IF([test "x$with_rados" == "xyes"], [
    AC_CHECK_LIB([rados], [rados_create2])
])
AS_IF([test "x$with_s3" == "xyes"], [
    AC_CHECK_LIB([s3], [S3_initialize])
])

AM_CONDITIONAL([ENABLE_S3], [test "$with_s3" = "yes"])
AM_CONDITIONAL([ENABLE_RADOS], [test "$with_rados" = "yes"])

AC_SUBST(LDIR)
AC_CONFIG_FILES(Makefile src/Makefile)
AC_OUTPUT

