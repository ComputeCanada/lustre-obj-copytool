#CFLAGS = --pedantic -Wall
#LDFLAGS =
AM_CFLAGS = -I@LDIR@/libcfs/include -I@LDIR@/lustre/include -I@LDIR@/lnet/include

noinst_LIBRARIES = libct.a
libct_a_SOURCES = ct_common.c ct_common.h

bin_PROGRAMS =
if ENABLE_S3
bin_PROGRAMS += copytoolS3
endif
copytoolS3_SOURCES = lhsmtool_s3.c lhsmtool_s3.h ct_common.h
copytoolS3_LDADD = libct.a

if ENABLE_RADOS
bin_PROGRAMS += copytoolRados
endif
copytoolRados_SOURCES = lhsmtool_rados.c lhsmtool_rados.h ct_common.h
copytoolRados_LDADD = libct.a
