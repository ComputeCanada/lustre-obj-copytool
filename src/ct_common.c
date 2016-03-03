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
/*
 * A library to encapsulate functions and data structures to be reuse
 * by HSM copytool daemons for Lustre
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "ct_common.h"
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>
#include <assert.h>
#include <sys/xattr.h>

/* everything else is zeroed */
struct ct_options ct_opt = {
    .o_verbose = LLAPI_MSG_INFO,
    .o_report_int = REPORT_INTERVAL_DEFAULT,
    .o_config = "config.cfg",
};

int should_retry(int *retry_count)
{
    if ((*retry_count)--) {
        // Sleep before next retry; start out with a 1 second sleep
        static int retrySleepInterval = MIN_SLEEP_SECOND;
        sleep(retrySleepInterval);
        // Next sleep 1 second longer
        ++retrySleepInterval;
        return 1;
    }

    return 0;
}

// djb2 hash function for strings
// http://www.cse.yorku.ca/~oz/hash.html
unsigned long hash(char* str)
{
    unsigned long hash = 5381;
    int c;
    while ((c = *str++) != 0)
    hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    return hash;
}


inline double ct_now(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + 0.000001 * tv.tv_usec;
}

int ct_save_stripe(int src_fd, const char *src, strippingInfo *params)
{
    char    lov_buf[XATTR_SIZE_MAX];
    struct  lov_user_md  *lum;
    int     rc;
    ssize_t xattr_size;

    assert(src && params);

    CT_TRACE("saving stripe info of '%s'", src);

    xattr_size = fgetxattr(src_fd, XATTR_LUSTRE_LOV, lov_buf, sizeof(lov_buf));
    if (xattr_size < 0) {
        rc = -errno;
        CT_ERROR(rc, "cannot get stripe info on '%s'", src);
        return rc;
    }

    lum = (struct lov_user_md *)lov_buf;

    params->lmm_stripe_size = lum->lmm_stripe_size;
    params->lmm_stripe_count = lum->lmm_stripe_count;

    return 0;
}

int ct_path_lustre(char *buf, int sz, const char *mnt,
                   const lustre_fid *fid)
{
    return snprintf(buf, sz, "%s/%s/fid/"DFID_NOBRACE, mnt,
                    dot_lustre_name, PFID(fid));
}

int ct_path_archive(char *buf, int sz, const lustre_fid *fid)
{
    __u64 sequence_id = (fid)->f_seq;
    __u32 object_id   = (fid)->f_oid;
    __u32 version     = (fid)->f_ver;
    return snprintf(buf, sz, "%016llx_%08x_%08x",
                    sequence_id, object_id, version);
}

bool ct_is_retryable(int err)
{
    return err == -ETIMEDOUT;
}

int ct_action_done(struct hsm_copyaction_private **phcp,
            const struct hsm_action_item *hai, int hp_flags, int ct_rc)
{
    struct hsm_copyaction_private *hcp;
    char lstr[PATH_MAX];
    int  rc;

    assert(hai);

    CT_TRACE("Action completed, notifying coordinator "
             "cookie="LPX64", FID="DFID", hp_flags=%d err=%d",
             hai->hai_cookie, PFID(&hai->hai_fid),
             hp_flags, -ct_rc);

    ct_path_lustre(lstr, sizeof(lstr), ct_opt.o_mnt, &hai->hai_fid);

    if (phcp == NULL || *phcp == NULL) {
        rc = llapi_hsm_action_begin(&hcp, ctdata, hai, -1, 0, true);
        if (rc < 0) {
            CT_ERROR(rc, "llapi_hsm_action_begin() on '%s' failed",
                     lstr);
            return rc;
        }
        phcp = &hcp;
    }

    rc = llapi_hsm_action_end(phcp, &hai->hai_extent, hp_flags, abs(ct_rc));
    if (rc == -ECANCELED)
        CT_ERROR(rc, "completed action on '%s' has been canceled: "
                 "cookie="LPX64", FID="DFID, lstr, hai->hai_cookie,
                 PFID(&hai->hai_fid));
    else if (rc < 0)
        CT_ERROR(rc, "llapi_hsm_action_end() on '%s' failed", lstr);
    else
        CT_TRACE("llapi_hsm_action_end() on '%s' ok (rc=%d)",
                 lstr, rc);

    return rc;
}

void handler(int signal)
{
    psignal(signal, "exiting");
    /* If we don't clean up upon interrupt, umount thinks there's a ref
     * and doesn't remove us from mtab (EINPROGRESS). The lustre client
     * does successfully unmount and the mount is actually gone, but the
     * mtab entry remains. So this just makes mtab happier. */
    llapi_hsm_copytool_unregister(&ctdata);

    /* Also remove fifo upon signal as during normal/error exit */
    if (ct_opt.o_event_fifo != NULL)
        llapi_hsm_unregister_event_fifo(ct_opt.o_event_fifo);
    _exit(1);
}

int ct_begin_restore(struct hsm_copyaction_private **phcp,
                     const struct hsm_action_item *hai,
                     int mdt_index, int open_flags)
{
    char src[PATH_MAX];
    int  rc;

    assert(hai);

    rc = llapi_hsm_action_begin(phcp, ctdata, hai, mdt_index, open_flags,
                                false);
    if (rc < 0) {
        ct_path_lustre(src, sizeof(src), ct_opt.o_mnt, &hai->hai_fid);
        CT_ERROR(rc, "llapi_hsm_action_begin() on '%s' failed", src);
    }

    return rc;
}

int ct_begin(struct hsm_copyaction_private **phcp, const struct hsm_action_item *hai)
{
    /* Restore takes specific parameters. Call the same function w/ default
     * values for all other operations. */
    return ct_begin_restore(phcp, hai, -1, 0);
}

int ct_setup(void)
{
    int rc;

    /* set llapi message level */
    llapi_msg_set_level(ct_opt.o_verbose);

    rc = llapi_search_fsname(ct_opt.o_mnt, fs_name);
    if (rc < 0) {
        CT_ERROR(rc, "cannot find a Lustre filesystem mounted at '%s'",
                 ct_opt.o_mnt);
        return rc;
    }

    ct_opt.o_mnt_fd = open(ct_opt.o_mnt, O_RDONLY);
    if (ct_opt.o_mnt_fd < 0) {
        rc = -errno;
        CT_ERROR(rc, "cannot open mount point at '%s'",
                 ct_opt.o_mnt);
        return rc;
    }

    return rc;
}

int ct_cleanup(void)
{
    int rc;

    if (ct_opt.o_mnt_fd >= 0) {
        rc = close(ct_opt.o_mnt_fd);
        if (rc < 0) {
            rc = -errno;
            CT_ERROR(rc, "cannot close mount point");
            return rc;
        }
    }

    return 0;
}

int ct_process_item(struct hsm_action_item *hai, const long hal_flags)
{
    int rc = 0;
    assert(hai);

    if (ct_opt.o_verbose >= LLAPI_MSG_INFO || ct_opt.o_dry_run) {
        /* Print the original path */
        char      fid[128];
        char      path[PATH_MAX];
        long long recno = -1;
        int       linkno = 0;

        sprintf(fid, DFID, PFID(&hai->hai_fid));
        CT_TRACE("'%s' action %s reclen %d, cookie="LPX64,
                 fid, hsm_copytool_action2name(hai->hai_action),
                 hai->hai_len, hai->hai_cookie);
        rc = llapi_fid2path(ct_opt.o_mnt, fid, path,
                            sizeof(path), &recno, &linkno);
        if (rc < 0)
            CT_ERROR(rc, "cannot get path of FID %s", fid);
        else
            CT_TRACE("processing file '%s'", path);
    }

    switch (hai->hai_action) {
    /* set err_major, minor inside these functions */
    case HSMA_ARCHIVE:
        rc = ct_archive(hai, hal_flags);
        break;
    case HSMA_RESTORE:
        rc = ct_restore(hai, hal_flags);
        break;
    case HSMA_REMOVE:
        rc = ct_remove(hai, hal_flags);
        break;
    case HSMA_CANCEL:
        rc = ct_cancel(hai, hal_flags);
        break;
    default:
        rc = -EINVAL;
        CT_ERROR(rc, "unknown action %d, on '%s'", hai->hai_action,
                 ct_opt.o_mnt);
        ct_action_done(NULL, hai, 0, rc);
    }

    return 0;
}

void *ct_thread(void *data)
{
    struct ct_th_data *cttd = data;
    int rc;

    rc = ct_process_item(cttd->hai, cttd->hal_flags);

    free(cttd->hai);
    free(cttd);
    pthread_exit((void *)(intptr_t)rc);
}

int ct_process_item_async(const struct hsm_action_item *hai,
                                 long hal_flags)
{
    pthread_attr_t attr;
    pthread_t      thread;
    struct         ct_th_data *data;
    int rc;
    assert(hai);

    data = malloc(sizeof(*data));
    if (data == NULL)
        return -ENOMEM;

    data->hai = malloc(hai->hai_len);
    if (data->hai == NULL) {
        free(data);
        return -ENOMEM;
    }

    memcpy(data->hai, hai, hai->hai_len);
    data->hal_flags = hal_flags;

    rc = pthread_attr_init(&attr);
    if (rc != 0) {
        CT_ERROR(rc, "pthread_attr_init failed for '%s' service",
                 ct_opt.o_mnt);
        free(data->hai);
        free(data);
        return -rc;
    }

    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    rc = pthread_create(&thread, &attr, ct_thread, data);
    if (rc != 0)
        CT_ERROR(rc, "cannot create thread for '%s' service",
                 ct_opt.o_mnt);

    pthread_attr_destroy(&attr);
    return 0;
}

/* Daemon waits for messages from the kernel; run it in the background. */
int ct_run(void)
{
    int rc;

    if (ct_opt.o_daemonize) {
        rc = daemon(1, 1);
        if (rc < 0) {
            rc = -errno;
            CT_ERROR(rc, "cannot daemonize");
            return rc;
        }
    }

    setbuf(stdout, NULL);

    if (ct_opt.o_event_fifo != NULL) {
        rc = llapi_hsm_register_event_fifo(ct_opt.o_event_fifo);
        if (rc < 0) {
            CT_ERROR(rc, "failed to register event fifo");
            return rc;
        }
        llapi_error_callback_set(llapi_hsm_log_error);
    }

    rc = llapi_hsm_copytool_register(&ctdata, ct_opt.o_mnt,
                                     ct_opt.o_archive_cnt,
                                     ct_opt.o_archive_id, 0);
    if (rc < 0) {
        CT_ERROR(rc, "cannot start copytool interface");
        return rc;
    }

    signal(SIGINT, handler);
    signal(SIGTERM, handler);

    while (1) {
        struct hsm_action_list *hal;
        struct hsm_action_item *hai;
        int msgsize;
        int i = 0;

        CT_TRACE("waiting for message from kernel");

        rc = llapi_hsm_copytool_recv(ctdata, &hal, &msgsize);
        if (rc == -ESHUTDOWN) {
            CT_TRACE("shutting down");
            break;
        }
        else if (rc < 0) {
            CT_WARN("cannot receive action list: %s",
                    strerror(-rc));
            err_major++;
            if (ct_opt.o_abort_on_error)
                break;
            else
                continue;
        }

        CT_TRACE("copytool fs=%s archive#=%d item_count=%d",
                 hal->hal_fsname, hal->hal_archive_id, hal->hal_count);

        if (strcmp(hal->hal_fsname, fs_name) != 0) {
            rc = -EINVAL;
            CT_ERROR(rc, "'%s' invalid fs name, expecting: %s",
                     hal->hal_fsname, fs_name);
            err_major++;
            if (ct_opt.o_abort_on_error)
                break;
            else
                continue;
        }

        hai = hai_first(hal);
        while (++i <= hal->hal_count) {
            if ((char *)hai - (char *)hal > msgsize) {
                rc = -EPROTO;
                CT_ERROR(rc,
                         "'%s' item %d past end of message!",
                         ct_opt.o_mnt, i);
                err_major++;
                break;
            }
            rc = ct_process_item_async(hai, hal->hal_flags);
            if (rc < 0)
                CT_ERROR(rc, "'%s' item %d process",
                         ct_opt.o_mnt, i);
            if (ct_opt.o_abort_on_error && err_major)
                break;
            hai = hai_next(hai);
        }

        if (ct_opt.o_abort_on_error && err_major)
            break;
    }

    llapi_hsm_copytool_unregister(&ctdata);
    if (ct_opt.o_event_fifo != NULL)
        llapi_hsm_unregister_event_fifo(ct_opt.o_event_fifo);

    return rc;
}
