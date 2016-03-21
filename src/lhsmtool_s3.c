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

#include "lhsmtool_s3.h"
#include "ct_common.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/xattr.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <libconfig.h>
#include <libs3.h>
#include <lz4.h>
#include <assert.h>
#include <openssl/md5.h>
#include <libcfs/util/string.h> /* To get strlcpy */

/* everything else is zeroed */
//struct ct_s3_options ct_s3_opt = {
//    .o_verbose = LLAPI_MSG_INFO,
//    .o_report_int = REPORT_INTERVAL_DEFAULT,
//    .o_config = "config.cfg",
//};
extern struct ct_options ct_opt;

S3Status responsePropertiesCallback(const S3ResponseProperties *properties,
                                    void *callbackData)
{
    uint i;
    get_object_callback_data *data = (get_object_callback_data *) callbackData;

    assert(data && properties);

    data->contentLength = properties->contentLength;

    if(properties->eTag){
        strncpy(data->md5, properties->eTag+1, MD5_ASCII - 1);
    }

    for (i = 0; i < properties->metaDataCount; i++) {
        if (strcmp(properties->metaData[i].name, "chunksize") == 0) {
            char* err;
            data->chunk_size = strtoll(properties->metaData[i].value, &err, 10);
            if(*err){
                printf("Error while parsing chunk_size, non-covertible part: %s\r\n", err);
                return S3StatusAbortedByCallback;
            }
        }
        else if (strcmp(properties->metaData[i].name, "totallength") == 0) {
            char* err;
            data->totalLength = strtoll(properties->metaData[i].value, &err, 10);
            if(*err){
                printf("Error while parsing totalLength, non-covertible part: %s\r\n", err);
                return S3StatusAbortedByCallback;
            }
        }
    }
    return S3StatusOK;
}

static void getResponseCompleteCallback(S3Status status,
                                        const S3ErrorDetails *error,
                                        void *callbackData)
{
    get_object_callback_data *data = (get_object_callback_data *) callbackData;
    assert(data);
    data->status = status;
    return;
}

static void putResponseCompleteCallback(S3Status status,
                                        const S3ErrorDetails *error,
                                        void *callbackData)
{
    put_object_callback_data *data = (put_object_callback_data *) callbackData;
    assert(data);
    data->status = status;
    return;
}

static int putObjectDataCallback(int bufferSize, char *buffer,
                                 void *callbackData)
{
    put_object_callback_data *data = (put_object_callback_data *) callbackData;
    int size = 0;

    assert(data && buffer);

    if (data->contentLength) {
        if (data->contentLength > bufferSize) {
            // Limited by bufferSize
            size = bufferSize;
        }
        else {
            // Last chunk
            size = data->contentLength;
        }
        memcpy(buffer, data->buffer + data->buffer_offset, size);
        data->buffer_offset += size;
    }

    data->contentLength -= size;
    return size;
}

static S3Status getObjectDataCallback(int bufferSize, const char *buffer,
    void *callbackData)
{
    get_object_callback_data *data = (get_object_callback_data *) callbackData;
    int size = 0;

    assert(data && buffer);

    if (data->contentLength) {
        if (data->buffer == NULL) {
            // Allocate memory for the buffer
            data->buffer = malloc(data->contentLength);
            if (data->buffer == NULL) {
                // Allocation error
                return S3StatusAbortedByCallback;
            }
        }

        if (data->contentLength > bufferSize) {
            // Limited by bufferSize
            size = bufferSize;
        }
        else {
            // Last chunk
            size = data->contentLength;
        }
        memcpy(data->buffer + data->buffer_offset, buffer, size);
        data->buffer_offset += size;
    }
    return ((size < (size_t) bufferSize) ? S3StatusAbortedByCallback : S3StatusOK);
}

static void getBucketName(int bucketNameSize,
                          char *bucketName,
                          char *objectName)
{
    /* This function will hash the object name and modify bucketName to
     * point the request to the correct bucket. The number of shard is defined
     * with bucket_count */
    if (bucket_count > 1) {
        unsigned long bucket_id = hash(objectName) % bucket_count;
        snprintf(bucketName, bucketNameSize, "%s_%lu", bucket_prefix, bucket_id);
    }
    else {
        // do not add a numbered suffix to the bucket name
        snprintf(bucketName, bucketNameSize, "%s", bucket_prefix);
    }
}

static int get_s3_object(char *objectName,
                         get_object_callback_data *data,
                         S3GetObjectHandler *getObjectHandler){

    assert(objectName && data && getObjectHandler);
    memset(data, 0, sizeof(get_object_callback_data));

    char bucket_name[S3_MAX_BUCKET_NAME_SIZE];
    getBucketName(sizeof(bucket_name), bucket_name, objectName);

    // Get a local copy of the general bucketContext than overwrite the
    // pointer to the bucket_name
    S3BucketContext localbucketContext;
    memcpy(&localbucketContext, &bucketContext, sizeof(S3BucketContext));
    localbucketContext.bucketName = bucket_name;

    data->buffer_offset = 0;
    data->buffer = NULL;

    double before_s3_get = ct_now();
    int retry_count = RETRYCOUNT;

    do {
        S3_get_object(&localbucketContext, objectName, NULL, 0, 0, NULL, getObjectHandler, data);
    } while (S3_status_is_retryable(data->status) && should_retry(&retry_count));

    CT_TRACE("S3 get of %s took %fs", objectName, ct_now() - before_s3_get);

    if (data->buffer == NULL) {
       return -ENOMEM;
    }
    if (data->status != S3StatusOK) {
        CT_ERROR(-EIO, "S3Error %s", S3_get_status_name(data->status));
        return -EIO;
    }

    double before_checksum = ct_now();
    unsigned char md5[MD5_DIGEST_LENGTH];
    char md5_s[MD5_ASCII];
    MD5_CTX mdContext;
    MD5_Init (&mdContext);
    MD5_Update (&mdContext, data->buffer, data->contentLength);
    MD5_Final (md5, &mdContext);
    int i;

    for(i = 0; i < MD5_DIGEST_LENGTH; i++){
        sprintf(&md5_s[i*2], "%02x", md5[i]);
    }

    if(strcmp(md5_s, data->md5) != 0){
        CT_ERROR(-EIO, "Bad MD5 checksum for %s, computed %s, expected %s",
            objectName, md5_s, data->md5);
        return -EIO;
    }
    CT_TRACE("Checksum of %s took %fs", objectName, ct_now() - before_checksum);
    return 0;
}

static void usage(const char *name, int rc)
{
    //TODO correct the usage help for s3
    fprintf(stdout,
    " Usage: %s [options]... <mode> <lustre_mount_point>\n"
    "The Lustre HSM S3 copy tool can be used as a daemon or "
    "as a command line tool\n"
    "The Lustre HSM daemon acts on action requests from Lustre\n"
    "to copy files to and from an HSM archive system.\n"
    "   --daemon            Daemon mode, run in background\n"
    " Options:\n"
    "The Lustre HSM tool performs administrator-type actions\n"
    "on a Lustre HSM archive.\n"
    "   --abort-on-error          Abort operation on major error\n"
    "   -A, --archive <#>         Archive number (repeatable)\n"
    "   -c, --config <path>       Path to the config file\n"
    "   --dry-run                 Don't run, just show what would be done\n"
    "   -f, --event-fifo <path>   Write events stream to fifo\n"
    "   -q, --quiet               Produce less verbose output\n"
    "   -u, --update-interval <s> Interval between progress reports sent\n"
    "                             to Coordinator\n"
    "   -v, --verbose             Produce more verbose output\n",
    cmd_name);

    exit(rc);
}

static int ct_parseopts(int argc, char * const *argv)
{
    struct option long_opts[] = {
        {"abort-on-error",  no_argument,       &ct_opt.o_abort_on_error, 1},
        {"abort_on_error",  no_argument,       &ct_opt.o_abort_on_error, 1},
        {"archive",         required_argument, NULL,                  'A'},
        {"config",          required_argument, NULL,                  'c'},
        {"daemon",          no_argument,       &ct_opt.o_daemonize,      1},
        {"event-fifo",      required_argument, NULL,                  'f'},
        {"event_fifo",      required_argument, NULL,                  'f'},
        {"dry-run",         no_argument,       &ct_opt.o_dry_run,        1},
        {"help",            no_argument,       NULL,                  'h'},
        {"quiet",           no_argument,       NULL,                  'q'},
        {"rebind",          no_argument,       NULL,                  'r'},
        {"update-interval", required_argument, NULL,                  'u'},
        {"update_interval", required_argument, NULL,                  'u'},
        {"verbose",         no_argument,       NULL,                  'v'},
        {0, 0, 0, 0}
    };
    int c, rc;
    config_t cfg;
    const char *config_str;

    optind = 0;
    while ((c = getopt_long(argc, argv, "A:b:c:f:hp:qu:v",
                            long_opts, NULL)) != -1) {
        switch (c) {
        case 'A':
            if ((ct_opt.o_archive_cnt >= LL_HSM_MAX_ARCHIVE) ||
                    (atoi(optarg) >= LL_HSM_MAX_ARCHIVE)) {
                rc = -E2BIG;
                CT_ERROR(rc, "archive number must be less"
                         "than %zu", LL_HSM_MAX_ARCHIVE);
                return rc;
            }
            ct_opt.o_archive_id[ct_opt.o_archive_cnt] = atoi(optarg);
            ct_opt.o_archive_cnt++;
            break;
        case 'b': /* -b and -c have both a number with unit as arg */
        case 'c':
            ct_opt.o_config = optarg;
            break;
        case 'f':
            ct_opt.o_event_fifo = optarg;
            break;
        case 'h':
            usage(argv[0], 0);
        case 'q':
            ct_opt.o_verbose--;
            break;
        case 'u':
            ct_opt.o_report_int = atoi(optarg);
            if (ct_opt.o_report_int < 0) {
                rc = -EINVAL;
                CT_ERROR(rc, "bad value for -%c '%s'", c, optarg);
                return rc;
            }
            break;
        case 'v':
            ++ct_opt.o_verbose;
            break;
        case 0:
            break;
        default:
            return -EINVAL;
        }
    }

    if (argc != optind + 1) {
        rc = -EINVAL;
        CT_ERROR(rc, "no mount point specified");
        return rc;
    }

    ct_opt.o_mnt = argv[optind];
    ct_opt.o_mnt_fd = -1;

    CT_TRACE("mount_point=%s", ct_opt.o_mnt);

    config_init(&cfg);
    if (! config_read_file(&cfg, ct_opt.o_config)) {
        CT_ERROR(-EINVAL, "error while reading config file\r\n%s:%d - %s",
                 config_error_file(&cfg),
                 config_error_line(&cfg),
                 config_error_text(&cfg));
        return -EINVAL;
    }

    if (config_lookup_string(&cfg, "access_key", &config_str)) {
        strncpy(access_key, config_str, sizeof(access_key));
    }
    else {
        CT_ERROR(-EINVAL, "could not find access_key");
        return -EINVAL;
    }

    if (config_lookup_string(&cfg, "secret_key", &config_str)) {
        strncpy(secret_key, config_str, sizeof(secret_key));
    }
    else {
        CT_ERROR(-EINVAL, "could not find secret_key");
        return -EINVAL;
    }

    if (config_lookup_string(&cfg, "host", &config_str)) {
        strncpy(host, config_str, sizeof(host));
    }
    else {
        CT_ERROR(-EINVAL, "could not find host");
        return -EINVAL;
    }

    if (config_lookup_string(&cfg, "bucket_prefix", &config_str)) {
        strncpy(bucket_prefix, config_str, sizeof(host));
    }
    else {
        CT_ERROR(-EINVAL, "could not find bucket_prefix");
        return -EINVAL;
    }

    if (config_lookup_int(&cfg, "chunk_size", &chunk_size)) {
        if (chunk_size < 0) {
            CT_ERROR(-EINVAL, "chunk_size cannot be negative");
            return -EINVAL;
        }
    }
    else {
        CT_ERROR(-EINVAL, "could not find chunk_size");
        return -EINVAL;
    }

    if (config_lookup_int(&cfg, "bucket_count", &bucket_count)) {
        if (bucket_count < 0) {
            CT_ERROR(-EINVAL, "bucket_count cannot be negative");
            return -EINVAL;
        }
    }
    else {
        CT_ERROR(-EINVAL, "could not find bucket_count");
        return -EINVAL;
    }

    int ssl_enabled;
    if (config_lookup_bool(&cfg, "ssl", &ssl_enabled)){
        if(ssl_enabled){
            bucketContext.protocol = S3ProtocolHTTPS;
        }
        else{
            bucketContext.protocol = S3ProtocolHTTP;
        }
    }
    else{
        CT_ERROR(-EINVAL, "could not find ssl");
        return -EINVAL;
    }

    return 0;
}

static int ct_archive_data(struct hsm_copyaction_private *hcp, const char *src,
                           const char *dst, int src_fd,
                           const struct hsm_action_item *hai, long hal_flags)
{
    struct hsm_extent he;
    __u64             file_offset = hai->hai_extent.offset;
    struct stat       src_st;
    char              *uncompress_buf = NULL;
    char              *compress_buf = NULL;
    __u64             write_total = 0;
    __u64             length = hai->hai_extent.length;
    time_t            last_report_time;
    int               rc = 0;
    double            start_ct_now = ct_now();
    time_t            now;
    int               compression_bound = LZ4_compressBound(chunk_size);

    // Archiving a file from Lustre to the object store
    CT_TRACE("Archiving %s to %s", src, dst);
    if (fstat(src_fd, &src_st) < 0) {
        rc = -errno;
        CT_ERROR(rc, "cannot stat '%s'", src);
        return rc;
    }

    if (!S_ISREG(src_st.st_mode)) {
        rc = -EINVAL;
        CT_ERROR(rc, "'%s' is not a regular file", src);
        return rc;
    }

    if (hai->hai_extent.offset > (__u64)src_st.st_size) {
        rc = -EINVAL;
        CT_ERROR(rc, "Trying to start reading past end ("LPU64" > "
                 "%jd) of '%s' source file", hai->hai_extent.offset,
                 (intmax_t)src_st.st_size, src);
        return rc;
    }

    strippingInfo stripping_params;
    stripping_params.lmm_stripe_count = 1;
    stripping_params.lmm_stripe_size = ONE_MB;

    if (ct_save_stripe(src_fd, src, &stripping_params)) {
        return -1;
    }

    /* Don't read beyond a given extent */
    if (length > src_st.st_size - hai->hai_extent.offset)
        length = src_st.st_size - hai->hai_extent.offset;

    last_report_time = time(NULL);

    he.offset = file_offset;
    he.length = 0;
    rc = llapi_hsm_action_progress(hcp, &he, length, 0);
    if (rc < 0) {
        /* Action has been canceled or something wrong
         * is happening. Stop copying data. */
        CT_ERROR(rc, "progress ioctl for copy '%s'->'%s' failed",
                 src, dst);
        goto out;
    }

    errno = 0;

    uncompress_buf = malloc(chunk_size);
    if (uncompress_buf == NULL) {
        rc = -ENOMEM;
        goto out;
    }

    compress_buf = malloc(compression_bound);
    if (compress_buf == NULL) {
        rc = -ENOMEM;
        goto out;
    }

    int chunk_id = -1;

    const char totalLength[] = "totallength";
    const char chunksize[] = "chunksize";
    const char stripe_size[] = "stripesize";
    const char stripe_count[] = "stripecount";
    const char path[] = "path";
    const char uid[] = "uid";
    const char gid[] = "gid";

    char totalLength_s[TOTALLENGTH];
    char chunksize_s[TOTALLENGTH];
    char stripe_size_s[TOTALLENGTH];
    char stripe_count_s[TOTALLENGTH];
    char path_s[PATH_MAX];
    char uid_s[TOTALLENGTH];
    char gid_s[TOTALLENGTH];

    snprintf(totalLength_s, sizeof(totalLength_s), "%llu", length);
    snprintf(chunksize_s, sizeof(chunksize_s), "%i", chunk_size);
    snprintf(stripe_size_s, sizeof(stripe_size_s), "%i", stripping_params.lmm_stripe_size);
    snprintf(stripe_count_s, sizeof(stripe_count_s), "%i", stripping_params.lmm_stripe_count);
    snprintf(path_s, sizeof(path_s), "%s", src); // FIXME should use fid2path to get the normal path
    snprintf(uid_s, sizeof(uid_s), "%i", src_st.st_uid);
    snprintf(gid_s, sizeof(gid_s), "%i", src_st.st_gid);

    // Saving some metadata for disaster recovery
    S3NameValue metadata[7] =
    {
        {
            totalLength,
            totalLength_s,
        },
        {
            chunksize,
            chunksize_s,
        },
        {
            stripe_size,
            stripe_size_s,
        },
        {
            stripe_count,
            stripe_count_s,
        },
        {
            path,
            path_s
        },
        {
            uid,
            uid_s
        },
        {
            gid,
            gid_s
        }
    };

    S3PutProperties putProperties =
    {
        // application/x-lz4 does not officially exist
        "application/x-lz4", // contentType
        NULL, // md5
        NULL, // cacheControl
        NULL, // contentDispositionFilename
        NULL, // contentEncoding
        -1, // expires
        0, // cannedAcl
        sizeof(metadata) / sizeof(S3NameValue), // metaDataCount
        metadata, // S3NameValue *metaData
        0, // useServerSideEncryption
    };

    do {
        // Uploading to object store

        if (chunk_id == -1) {
            CT_TRACE("start copy of "LPU64" bytes from '%s' to '%s'",
                     length, src, dst);
        }

        // size of the current chunk, limited by chunk_size
        long long unsigned int  chunk;

        if (length - write_total > chunk_size) {
            // upper bound is the chunk_size
            chunk = chunk_size;
        }
        else {
            // limited by the file
            chunk = length - write_total;
        }

        chunk_id = file_offset / chunk_size;

        put_object_callback_data data;

        data.buffer_offset = 0;
        double before_lustre_read = ct_now();
        pread(src_fd, uncompress_buf, chunk, file_offset);
        CT_TRACE("Reading a chunk from %s of %llu bytes offset %llu from lustre took %fs",
            src, chunk, file_offset, ct_now() - before_lustre_read);

        double before_compression = ct_now();
        int compressed_size = LZ4_compress_default(uncompress_buf, compress_buf, chunk, compression_bound);
        CT_TRACE("Compressing a chunk from %s took %fs and the compressed size is %i bytes",
            src,  ct_now() - before_compression, compressed_size);

        if (compressed_size <= 0) {
            rc = -1;
            CT_ERROR(rc, "Compression error");
            goto out;
        }
        data.contentLength = compressed_size;
        data.buffer = compress_buf;

        S3PutObjectHandler putObjectHandler =
        {
            putResponseHandler,
            &putObjectDataCallback
        };

        char dst_chunk_s[S3_MAX_KEY_SIZE];
        snprintf(dst_chunk_s, sizeof(dst_chunk_s), "%s.%i", dst, chunk_id);

        char bucket_name[S3_MAX_BUCKET_NAME_SIZE];
        getBucketName(sizeof(bucket_name), bucket_name, dst_chunk_s);

        // Get a local copy of the general bucketContext than overwrite the
        // pointer to the bucket_name
        S3BucketContext localbucketContext;
        memcpy(&localbucketContext, &bucketContext, sizeof(S3BucketContext));
        localbucketContext.bucketName = bucket_name;

        double before_s3_put = ct_now();
        int retry_count = RETRYCOUNT;
        do {
            S3_put_object(&localbucketContext, dst_chunk_s, compressed_size, &putProperties, NULL, &putObjectHandler, &data);
        } while (S3_status_is_retryable(data.status) && should_retry(&retry_count));
        CT_TRACE("S3 put of %s took %fs",
            dst_chunk_s, ct_now() - before_s3_put);

        if (data.status != S3StatusOK) {
            rc = -EIO;
            CT_ERROR(rc, "S3Error %s", S3_get_status_name(data.status));
            goto out;
        }

        he.offset = file_offset;
        he.length = chunk;

        now = time(NULL);
        if (now >= last_report_time + ct_opt.o_report_int) {
            last_report_time = now;
            CT_TRACE("sending progress report for archiving %s", src);
            rc = llapi_hsm_action_progress(hcp, &he, length, 0);
            if (rc < 0) {
                /* Action has been canceled or something wrong
                 * is happening. Stop copying data. */
                CT_ERROR(rc, "progress ioctl for copy '%s'->'%s' failed",
                         src, dst);
                goto out;
            }
        }

        write_total += chunk;
        file_offset += chunk;
    } while (file_offset < length);
    rc = 0;

    // We need to delete every chunk of higher chunk_id if they
    // exists, this can happen if the new file is smaller
    // TODO only delete objects if this is a dirty write

    chunk_id += 1;
    do {
        char dst_s[S3_MAX_KEY_SIZE];
        int retry_count;

        snprintf(dst_s, sizeof(dst_s), "%s.%i", dst, chunk_id);
        get_object_callback_data head_data;
        get_object_callback_data delete_data;

        char bucket_name[S3_MAX_BUCKET_NAME_SIZE];
        getBucketName(sizeof(bucket_name), bucket_name, dst_s);

        // Get a local copy of the general bucketContext than overwrite the
        // pointer to the bucket_name
        S3BucketContext localbucketContext;
        memcpy(&localbucketContext, &bucketContext, sizeof(S3BucketContext));
        localbucketContext.bucketName = bucket_name;

        CT_TRACE("Checking if chunk %i exists", chunk_id);
        retry_count = RETRYCOUNT;
        do {
            S3_head_object(&localbucketContext, dst_s, NULL, &headResponseHandler, &head_data);
        } while (S3_status_is_retryable(head_data.status) && should_retry(&retry_count));

        if (head_data.status == S3StatusHttpErrorNotFound) {
            // Object do not exist, this mean we stop deleting chunks
            CT_TRACE("Chunk %i do not exists", chunk_id);
            break;
        }

        if (head_data.status != S3StatusOK) {
            rc = -EIO;
            CT_ERROR(rc, "S3Error %s", S3_get_status_name(head_data.status));
            goto out;
        }

        CT_TRACE("Deleting chunk %i", chunk_id);
        retry_count = RETRYCOUNT;
        do {
            S3_delete_object(&localbucketContext, dst_s, NULL, &deleteResponseHandler, &delete_data);
        } while (S3_status_is_retryable(delete_data.status) && should_retry(&retry_count));

        if (delete_data.status != S3StatusOK) {
            rc = -EIO;
            CT_ERROR(rc, "S3Error %s", S3_get_status_name(delete_data.status));
            goto out;
        }

        chunk_id++;
    } while (true);

out:
    if (uncompress_buf != NULL)
        free(uncompress_buf);
    if (compress_buf != NULL)
        free(compress_buf);

    CT_TRACE("copied "LPU64" bytes in %f seconds",
             length, ct_now() - start_ct_now);

    return rc;
}

static int ct_restore_data(struct hsm_copyaction_private *hcp, const char *src,
                           const char *dst, int dst_fd,
                           const struct hsm_action_item *hai, long hal_flags)
{
    struct hsm_extent he;
    __u64             file_offset = hai->hai_extent.offset;
    struct stat       dst_st;
    __u64             write_total = 0;
    __u64             length = hai->hai_extent.length;
    time_t            last_report_time;
    time_t            now;
    int               rc = 0;
    double            start_ct_now = ct_now();

    // Restore a file from the object store back to Lustre

    CT_TRACE("Restoring %s to %s", src, dst);
    if (fstat(dst_fd, &dst_st) < 0) {
        rc = -errno;
        CT_ERROR(rc, "cannot stat '%s'", dst);
        return rc;
    }

    if (!S_ISREG(dst_st.st_mode)) {
        rc = -EINVAL;
        CT_ERROR(rc, "'%s' is not a regular file", dst);
        return rc;
    }

    he.offset = file_offset;
    he.length = 0;
    rc = llapi_hsm_action_progress(hcp, &he, length, 0);
    if (rc < 0) {
        /* Action has been canceled or something wrong
         * is happening. Stop copying data. */
        CT_ERROR(rc, "progress ioctl for copy '%s'->'%s' failed",
                 src, dst);
        goto out;
    }

    errno = 0;

    last_report_time = time(NULL);

    long long int object_chunk_size = chunk_size; // will be assigned the correct value based on the metadata

    do {
        // Downloading from the object store

        char src_chunk_s[S3_MAX_KEY_SIZE];

        S3GetObjectHandler getObjectHandler =
        {
            getResponseHandler,
            &getObjectDataCallback
        };

        if (length == -1) {
            // Discover length and chunk size from the first object's metadata
            snprintf(src_chunk_s, sizeof(src_chunk_s), "%s.0", src);
            if (file_offset == 0) {
                // Download data and metadata from the first chunk
                get_object_callback_data data;
                rc = get_s3_object(src_chunk_s, &data, &getObjectHandler);
                if(rc < 0){
                    goto out;
                }

                length = data.totalLength;
                object_chunk_size = data.chunk_size;

                char *uncompress_buf = NULL;
                uncompress_buf = malloc(object_chunk_size);
                if (uncompress_buf == NULL) {
                    rc = -ENOMEM;
                    goto out;
                }

                double before_decompression = ct_now();
                int decompressed_size = LZ4_decompress_safe(data.buffer, uncompress_buf, data.contentLength, object_chunk_size);
                if (decompressed_size < 0) {
                    rc = -1;
                    CT_ERROR(rc, "Decompression error");
                    goto out;
                }
                CT_TRACE("Decompressing a chunk from %s of %llu bytes took %fs and the uncompressed size is %i bytes",
                    src, data.contentLength, ct_now() - before_decompression, decompressed_size);

                double before_lustre_write = ct_now();
                pwrite(dst_fd, uncompress_buf, decompressed_size, file_offset);
                CT_TRACE("Writing a chunk from %s of %llu bytes offset %llu to lustre took %fs",
                    src_chunk_s, object_chunk_size, file_offset, ct_now() - before_lustre_write);

                if (uncompress_buf != NULL)
                    free(uncompress_buf);
                if (data.buffer != NULL)
                    free(data.buffer);

                write_total = decompressed_size;
                file_offset += decompressed_size;

                he.offset = file_offset;
                he.length = data.contentLength;
                rc = llapi_hsm_action_progress(hcp, &he, length, 0);
                if (rc < 0) {
                    /* Action has been canceled or something wrong
                     * is happening. Stop copying data. */
                    CT_ERROR(rc, "progress ioctl for copy '%s'->'%s' failed",
                             src, dst);
                    goto out;
                }

                if (write_total == length) {
                    // Completed the full write with the first object
                    rc = 0;
                    break;
                }
            }
            else {
                // Only make a head request to get the metadata of the first object
                get_object_callback_data data;

                char bucket_name[S3_MAX_BUCKET_NAME_SIZE];
                getBucketName(sizeof(bucket_name), bucket_name, src_chunk_s);

                // Get a local copy of the general bucketContext than overwrite the
                // pointer to the bucket_name
                S3BucketContext localbucketContext;
                memcpy(&localbucketContext, &bucketContext, sizeof(S3BucketContext));
                localbucketContext.bucketName = bucket_name;

                int retry_count = RETRYCOUNT;
                do {
                    S3_head_object(&localbucketContext, src_chunk_s, NULL, &headResponseHandler, &data);
                } while (S3_status_is_retryable(data.status) && should_retry(&retry_count));

                if (data.status != S3StatusOK) {
                    rc = -EIO;
                    CT_ERROR(rc, "S3Error %s", S3_get_status_name(data.status));
                    goto out;
                }
                object_chunk_size = data.chunk_size;
                length = data.totalLength;
            }
        }
        else {
            snprintf(src_chunk_s, sizeof(src_chunk_s), "%s.%llu", src, file_offset / object_chunk_size);

            long long unsigned int chunk;
            if (length - write_total > object_chunk_size) {
                // upper bound is the chunk_size
                chunk = object_chunk_size;
            }
            else {
                // limited by the file
                chunk = length - write_total;
            }

            get_object_callback_data data;
            rc = get_s3_object(src_chunk_s, &data, &getObjectHandler);
            if(rc < 0){
                goto out;
            }

            char *uncompress_buf = NULL;
            uncompress_buf = malloc(object_chunk_size);
            if (uncompress_buf == NULL) {
                rc = -ENOMEM;
                goto out;
            }

            double before_decompression = ct_now();
            int decompressed_size = LZ4_decompress_safe(data.buffer, uncompress_buf, data.contentLength, object_chunk_size);
            if (decompressed_size < 0) {
                rc = -1;
                CT_ERROR(rc, "Decompression error");
                goto out;
            }
            CT_TRACE("Decompressing a chunk from %s of %llu bytes took %fs and the uncompressed size is %i",
                src, data.contentLength, ct_now() - before_decompression, decompressed_size);

            double before_lustre_write = ct_now();
            pwrite(dst_fd, uncompress_buf, decompressed_size, file_offset);
            CT_TRACE("Writing a chunk from %s of %llu bytes offset %llu to lustre took %fs",
                src_chunk_s, chunk, file_offset, ct_now() - before_lustre_write);

            if (uncompress_buf != NULL)
                free(uncompress_buf);
            if (data.buffer != NULL)
                free(data.buffer);

            now = time(NULL);
            if (now >= last_report_time + ct_opt.o_report_int) {
                last_report_time = now;
                CT_TRACE("sending progress report for restoring %s", src);
                rc = llapi_hsm_action_progress(hcp, &he, length, 0);
                if (rc < 0) {
                    /* Action has been canceled or something wrong
                     * is happening. Stop copying data. */
                    CT_ERROR(rc, "progress ioctl for copy '%s'->'%s' failed",
                             src, dst);
                    goto out;
                }
            }

            write_total += decompressed_size;
            file_offset += decompressed_size;
        }
        rc = 0;
    } while (file_offset < length);

    if (hai->hai_action == HSMA_RESTORE) {
        /*
         * truncate restored file
         * size is taken from the archive this is done to support
         * restore after a force release which leaves the file with the
         * wrong size (can big bigger than the new size)
         * make sure the file is on disk before reporting success.
         */
        rc = ftruncate(dst_fd, length);
        if (rc < 0) {
            rc = -errno;
            CT_ERROR(rc, "cannot truncate '%s' to size %llu",
                     dst, length);
            err_major++;
        }
    }

out:
    CT_TRACE("copied "LPU64" bytes in %f seconds",
             length, ct_now() - start_ct_now);

    return rc;
}

int ct_archive(const struct hsm_action_item *hai, const long hal_flags)
{
    struct hsm_copyaction_private *hcp = NULL;
    char src[PATH_MAX];
    char dst[PATH_MAX] = "";
    int  rc;
    int  rcf = 0;
    int  hp_flags = 0;
    int  open_flags;
    int  src_fd = -1;

    rc = ct_begin(&hcp, hai);
    if (rc < 0)
        goto end_ct_archive;

    /* we fill archive so:
     * source = data FID
     * destination = lustre FID
     */
    ct_path_lustre(src, sizeof(src), ct_opt.o_mnt, &hai->hai_dfid);
    ct_path_archive(dst, sizeof(dst), &hai->hai_fid);

    CT_TRACE("archiving '%s' to '%s'", src, dst);

    if (ct_opt.o_dry_run) {
        rc = 0;
        goto end_ct_archive;
    }

    src_fd = llapi_hsm_action_get_fd(hcp);
    if (src_fd < 0) {
        rc = src_fd;
        CT_ERROR(rc, "cannot open '%s' for read", src);
        goto end_ct_archive;
    }

    open_flags = O_WRONLY | O_NOFOLLOW;
    /* If extent is specified, don't truncate an old archived copy */
    open_flags |= ((hai->hai_extent.length == -1) ? O_TRUNC : 0) | O_CREAT;

    rc = ct_archive_data(hcp, src, dst, src_fd, hai, hal_flags);
    if (rc < 0) {
        CT_ERROR(rc, "data copy failed from '%s' to '%s'", src, dst);
        goto end_ct_archive;
    }

    CT_TRACE("data archiving for '%s' to '%s' done", src, dst);

end_ct_archive:
    err_major++;

    unlink(dst);
    if (ct_is_retryable(rc))
        hp_flags |= HP_FLAG_RETRY;

    rcf = rc;

    if (!(src_fd < 0))
        close(src_fd);

    rc = ct_action_done(&hcp, hai, hp_flags, rcf);

    return rc;
}

int ct_restore(const struct hsm_action_item *hai, const long hal_flags)
{
    struct hsm_copyaction_private *hcp = NULL;
    struct lu_fid                 dfid;
    char src[PATH_MAX];
    char dst[PATH_MAX];
    int  rc;
    int  hp_flags = 0;
    int  dst_fd = -1;
    int  mdt_index = -1;
    int  open_flags = 0;
    /* we fill lustre so:
     * source = lustre FID in the backend
     * destination = data FID = volatile file
     */

    /* build backend file name from released file FID */
    ct_path_archive(src, sizeof(src), &hai->hai_fid);

    rc = llapi_get_mdt_index_by_fid(ct_opt.o_mnt_fd, &hai->hai_fid,
                                    &mdt_index);
    if (rc < 0) {
        CT_ERROR(rc, "cannot get mdt index "DFID"",
                 PFID(&hai->hai_fid));
        return rc;
    }

    rc = ct_begin_restore(&hcp, hai, mdt_index, open_flags);
    if (rc < 0)
        goto end_ct_restore;

    /* get the FID of the volatile file */
    rc = llapi_hsm_action_get_dfid(hcp, &dfid);
    if (rc < 0) {
        CT_ERROR(rc, "restoring "DFID
                 ", cannot get FID of created volatile file",
                 PFID(&hai->hai_fid));
        goto end_ct_restore;
    }

    /* build volatile "file name", for messages */
    snprintf(dst, sizeof(dst), "{VOLATILE}="DFID, PFID(&dfid));

    CT_TRACE("restoring data from '%s' to '%s'", src, dst);

    if (ct_opt.o_dry_run) {
        rc = 0;
        goto end_ct_restore;
    }

    dst_fd = llapi_hsm_action_get_fd(hcp);
    if (dst_fd < 0) {
        rc = dst_fd;
        CT_ERROR(rc, "cannot open '%s' for write", dst);
        goto end_ct_restore;
    }

    rc = ct_restore_data(hcp, src, dst, dst_fd, hai, hal_flags);
    if (rc < 0) {
        CT_ERROR(rc, "cannot copy data from '%s' to '%s'",
                 src, dst);
        err_major++;
        if (ct_is_retryable(rc))
            hp_flags |= HP_FLAG_RETRY;
        goto end_ct_restore;
    }

    CT_TRACE("data restore from '%s' to '%s' done", src, dst);

end_ct_restore:
    rc = ct_action_done(&hcp, hai, hp_flags, rc);

    /* object swaping is done by cdt at copy end, so close of volatile file
     * cannot be done before */

    if (!(dst_fd < 0))
        close(dst_fd);

    return rc;
}

int ct_remove(const struct hsm_action_item *hai, const long hal_flags)
{
    struct hsm_copyaction_private *hcp = NULL;
    char dst[PATH_MAX];
    int  rc;
    int  retry_count;
    char dst_s[S3_MAX_KEY_SIZE];

    rc = ct_begin(&hcp, hai);
    if (rc < 0)
        goto end_ct_remove;

    ct_path_archive(dst, sizeof(dst), &hai->hai_fid);

    CT_TRACE("removing file '%s'", dst);

    if (ct_opt.o_dry_run) {
        rc = 0;
        goto end_ct_remove;
    }

    // Get the metadata from the first object to get the number of chunks
    get_object_callback_data data;

    snprintf(dst_s, sizeof(dst_s), "%s.0", dst);

    char bucket_name[S3_MAX_BUCKET_NAME_SIZE];
    getBucketName(sizeof(bucket_name), bucket_name, dst_s);

    // Get a local copy of the general bucketContext than overwrite the
    // pointer to the bucket_name
    S3BucketContext localbucketContext;
    memcpy(&localbucketContext, &bucketContext, sizeof(S3BucketContext));
    localbucketContext.bucketName = bucket_name;

    retry_count = RETRYCOUNT;
    do {
        S3_head_object(&localbucketContext, dst_s, NULL, &headResponseHandler, &data);
    } while (S3_status_is_retryable(data.status) && should_retry(&retry_count));

    if (data.status != S3StatusOK) {
        rc = -EIO;
        CT_ERROR(rc, "S3Error %s", S3_get_status_name(data.status));
        goto end_ct_remove;
    }

    int chunk;
    for (chunk = data.totalLength / data.chunk_size; chunk >= 0; chunk--) {
        snprintf(dst_s, sizeof(dst_s), "%s.%i", dst, chunk);
        get_object_callback_data delete_data;

        CT_TRACE("Deleting chunk '%s'", dst_s);

        char bucket_name[S3_MAX_BUCKET_NAME_SIZE];
        getBucketName(sizeof(bucket_name), bucket_name, dst_s);

        // Get a local copy of the general bucketContext than overwrite the
        // pointer to the bucket_name
        S3BucketContext localbucketContext;
        memcpy(&localbucketContext, &bucketContext, sizeof(S3BucketContext));
        localbucketContext.bucketName = bucket_name;

        retry_count = RETRYCOUNT;
        do {
            S3_delete_object(&localbucketContext, dst_s, NULL, &deleteResponseHandler, &delete_data);
        } while (S3_status_is_retryable(delete_data.status) && should_retry(&retry_count));

        if (delete_data.status != S3StatusOK) {
            rc = -EIO;
            CT_ERROR(rc, "S3Error %s", S3_get_status_name(delete_data.status));
            goto end_ct_remove;
        }
    }
    rc = 0;

end_ct_remove:
    rc = ct_action_done(&hcp, hai, 0, rc);

    return rc;
}

int ct_cancel(const struct hsm_action_item *hai, const long hal_flags)
{
    CT_TRACE("cancel not implemented for file system '%s'", ct_opt.o_mnt);
    /* Don't report progress to coordinator for this cookie:
     * the copy function will get ECANCELED when reporting
     * progress. */
    return 0;
}

static int ct_s3_cleanup(void)
{
    int rc = 0;

    rc = ct_cleanup();
    if (rc == 0) {
        S3_deinitialize();
    }

    return rc;
}

int main(int argc, char **argv)
{
    int rc;

    strlcpy(cmd_name, basename(argv[0]), sizeof(cmd_name));
    rc = ct_parseopts(argc, argv);
    if (rc < 0) {
        CT_WARN("try '%s --help' for more information", cmd_name);
        return -rc;
    }

    rc = ct_setup();
    if (rc < 0)
        goto error_cleanup;

    rc = S3_initialize(NULL, S3_INIT_ALL, host);
    if(rc != 0){
        CT_ERROR(rc, "Error in S3 init");
        goto error_cleanup;
    }

    rc = ct_run();

error_cleanup:
    ct_s3_cleanup();

    return -rc;
}

