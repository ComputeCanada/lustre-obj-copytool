lustre-s3-copytool
==================
Features
--------

- Compression with LZ4
- Stripping across multiple objects and buckets
- Verifing checksum when restoring

Patching libs3
--------------
The copytool will segfault if libs3 is not patched, the fault mostly occur in
large files restore (Writing on Lustre/Reading on S3).

This patch remove the low speed limit, that limit will normally cause a timeout
if the transfer is slower than 1kb/s for 15 seconds.

```
$ git clone https://github.com/bji/libs3.git
$ cd libs3
$ patch -p1 < ~/lustre-s3-copytool/patches/libs3_low_speed_limit.patch
```

Configuration
-------------
### lustre-s3-copytool
A basic configuration is available in config.cfg.dist, this file can be copied
as config.cfg. The path of the config file can also be passed as a runtime
parameter.

__access_key__ (string)
AWS access key

__secret_key__ (string)
AWS Secret key

__host__ (string)
Hostname of the S3 endpoint

__bucket_count__ (int)
The number of buckets used to spread the indexing load. With radosgw, PUT operation will slow down proportionally to the number of objects in the same bucket. If a bucket_count > 2 is used, the bucket_prefix will be appended an ID.

__bucket_prefix__ (string)
This prefix will prepended to each bucketID. For example, if the bucket_prefix is __hsm__, then each bucket will named hsm_0, hsm_1, hsm_2 ...

__chunk_size__ (int)
This represent the size of the largest object stored to S3. A large file in Lustre will be stripped in multiple objects if the file size > chunk_size. Because compression is used, this parameter need to be set according to the available memory. Each thread will use twice the chunk_size. For incompressible data, each object will take a few extra bytes on S3.

__ssl__ (bool)
If the S3 endpoint should use SSL

### Lustre HSM
#### Quick howto
Enable HSM on the MDS server

```
# lctl set_param mdt.lustre-MDT0000.hsm.max_requests=10
# lctl set_param mdt.lustre-MDT0000.hsm_control=enabled
```

Start the copytool on a DTN node

```
# ./copytool_d /lustre/
1456506103.926649 copytool_d[31507]: mount_point=/lustre/
1456506103.932785 copytool_d[31507]: waiting for message from kernel
```
You can use __lfs hsm_state__ to get the current status of a file

Move a file to HSM and remove it from Lustre

```
# lfs hsm_state test
test: (0x00000000)
# lfs hsm_archive test
# lfs hsm_state
test: (0x00000009) exists archived, archive_id:1
# lfs hsm_release test
# lfs hsm_state test
test: (0x0000000d) released exists archived, archive_id:1
```

Restore the file implicitly

```
# md5sum test
33e3e3bdb7f6f847e06ae2a8abad0b85  test
# lfs hsm_state test
test: (0x00000009) exists archived, archive_id:1
```

Remove the file from S3

```
# lfs hsm_remove test
# lfs hsm_state test
test: (0x00000000), archive_id:1
```

### Example with radosgw
```
# radosgw-admin user create --uid=lustre_hsm --display-name="lustre_hsm"
[...]
# radosgw-admin user modify --uid=lustre_hsm --max_buckets=10000
[...]
```

Grab the access_key and the secret_key from the previous command

Install and configure s3cmd (can also use any other s3 compatible tool)

Create some buckets with s3cmd

```
# for i in {0..256} ; do s3cmd mb s3://lustre_hsm_$i ; done
Bucket 's3://lustre_hsm_0/' created
[...]
```

Update the config.cfg with the keys, bucket_prefix and bucket_count
