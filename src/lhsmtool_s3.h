/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.htm
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2015, 2016, Universite Laval
 * Authors: Simon Guilbault, Frederick Lefebvre
 *          
 * 
 * Part of this file include code from file lhsmtool_posix.c (licensed under
 * a GPLv2 license) that can be found in Lustre's git repository here :
 * git://git.hpdd.intel.com/fs/lustre-release.git
 */
/* HSM copytool program for S3 object storage.
 *
 * An HSM copytool daemon acts on action requests from Lustre to copy files
 * to and from an HSM archive system.
 *
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <libcfs/util/string.h>
#include <lustre/lustre_idl.h>
#include <lustre/lustreapi.h>
#include <libs3.h>


#define RETRYCOUNT 5

#define MD5_ASCII 32+1

//struct ct_s3_options {
//    int  o_copy_attrs;
//    int  o_daemonize;
//    int  o_dry_run;
//    int  o_abort_on_error;
//    int  o_verbose;
//    int  o_archive_cnt;
//    int  o_archive_id[LL_HSM_MAX_ARCHIVE];
//    int  o_report_int;
//    char *o_config;
//    char *o_event_fifo;
//    char *o_mnt;
//    int  o_mnt_fd;
//};

char access_key[S3_MAX_KEY_SIZE];
char secret_key[S3_MAX_KEY_SIZE];
char host[S3_MAX_HOSTNAME_SIZE];
char bucket_prefix[S3_MAX_BUCKET_NAME_SIZE];

int bucket_count;

#ifndef MIN_SLEEP_SECOND
#define MIN_SLEEP_SECOND 1
#endif

S3BucketContext bucketContext =
{
    host,
    bucket_prefix,
    S3ProtocolHTTP,
    S3UriStylePath,
    access_key,
    secret_key
};

typedef struct put_object_callback_data
{
    long long unsigned int contentLength;
    long long unsigned int buffer_offset;
    S3Status               status;
    char                   *buffer;
} put_object_callback_data;

typedef struct get_object_callback_data
{
    long long unsigned int buffer_offset;
    long long unsigned int totalLength;
    long long unsigned int chunk_size;
    long long unsigned int contentLength;
    char                   *buffer;
    S3Status               status;
    char                   md5[MD5_ASCII];
} get_object_callback_data;

S3Status responsePropertiesCallback(const S3ResponseProperties *properties,
                                    void *callbackData);
static void getResponseCompleteCallback(S3Status status,
                                        const S3ErrorDetails *error,
                                        void *callbackData);

static void putResponseCompleteCallback(S3Status status,
                                        const S3ErrorDetails *error,
                                        void *callbackData);
S3ResponseHandler getResponseHandler =
{
    &responsePropertiesCallback,
    &getResponseCompleteCallback
};

S3ResponseHandler putResponseHandler =
{
    &responsePropertiesCallback,
    &putResponseCompleteCallback
};

S3ResponseHandler headResponseHandler =
{
    &responsePropertiesCallback,
    &getResponseCompleteCallback
};

S3ResponseHandler deleteResponseHandler =
{
    &responsePropertiesCallback,
    &getResponseCompleteCallback
};

static int putObjectDataCallback(int bufferSize, char *buffer,
                                 void *callbackData);

static S3Status getObjectDataCallback(int bufferSize, const char *buffer,
    void *callbackData);

static void getBucketName(int bucketNameSize, char *bucketName,
                          char *objectName);

static int get_s3_object(char *objectName, get_object_callback_data *data,
                         S3GetObjectHandler *getObjectHandler);

static void usage(const char *name, int rc);

static int ct_parseopts(int argc, char * const *argv);

static int ct_archive_data(struct hsm_copyaction_private *hcp, const char *src,
                           const char *dst, int src_fd,
                           const struct hsm_action_item *hai, long hal_flags);

static int ct_restore_data(struct hsm_copyaction_private *hcp, const char *src,
                           const char *dst, int dst_fd,
                           const struct hsm_action_item *hai, long hal_flags);

int ct_archive(const struct hsm_action_item *hai, const long hal_flags);

int ct_restore(const struct hsm_action_item *hai, const long hal_flags);

int ct_remove(const struct hsm_action_item *hai, const long hal_flags);

static int ct_s3_cleanup(void);

