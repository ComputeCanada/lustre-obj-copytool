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
/* HSM copytool program for rados (ceph) object storage.
 *
 * An HSM copytool daemon acts on action requests from Lustre to copy files
 * to and from an HSM archive system.
 *
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <string.h>
#include <lustre/lustre_idl.h>
#include <lustre/lustreapi.h>
#include <rados/librados.h>

// number of ascii characters needed to represent the size of a big file
#define TOTALLENGTH 24

#define RADOS_PARAMETER_LENGTH 128
#define OID_LENGTH 128

static int err_major;
//static int err_minor;

char cluster_name[RADOS_PARAMETER_LENGTH];
char user_name[RADOS_PARAMETER_LENGTH];
char pool_name[RADOS_PARAMETER_LENGTH];
char rados_config_file[RADOS_PARAMETER_LENGTH];
rados_t cluster;
rados_ioctx_t io;

static int init_rados();

static void usage(const char *name, int rc);

static int ct_parseopts(int argc, char * const *argv);

static int ct_archive_data(struct hsm_copyaction_private *hcp, const char *src,
                           const char *dst, int src_fd,
                           const struct hsm_action_item *hai, long hal_flags);

static int ct_restore_data(struct hsm_copyaction_private *hcp, const char *src,
                           const char *dst, int dst_fd,
                           const struct hsm_action_item *hai, long hal_flags);
