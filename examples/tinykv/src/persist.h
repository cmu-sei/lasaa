// persist.h - snapshots (binary dump of the keyspace) and the append-only
// file (AOF) of write commands.
//
// Snapshot format (all integers little-endian):
//     header: magic "TKVSNAP1" (8 bytes), u32 version, u64 created_ms
//     records: u8 type, varint keylen, key, [u64 expire_at if type has
//              REC_FLAG_TTL], value
//         string value: varint len, bytes
//         list value:   varint count, then count x (varint len, bytes)
//     trailer: u8 REC_EOF, u32 crc32 of everything before the crc
//
// <legal>
// LASAA tool
//
// Copyright 2026 Carnegie Mellon University.
//
// NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
// INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
// UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS
// TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE
// OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE
// MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND
// WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
//
// Licensed under a MIT (SEI)-style license, please see License.txt or contact
// permission@sei.cmu.edu for full terms.
//
// [DISTRIBUTION STATEMENT A] This material has been approved for public
// release and unlimited distribution.  Please see Copyright notice for
// non-US Government use and distribution.
//
// This Software includes and/or makes use of Third-Party Software each subject
// to its own license.
//
// DM26-0426
// </legal>
#ifndef TKV_PERSIST_H
#define TKV_PERSIST_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "sbuf.h"

struct store;
struct entry;
struct request;

#define SNAP_MAGIC "TKVSNAP1"
#define SNAP_VERSION 2

enum {
    REC_STRING = 1,
    REC_LIST = 2,
    REC_EOF = 0xff,
    REC_FLAG_TTL = 0x80
};

int snapshot_save(struct store *s, const char *path, char *err,
                  size_t errlen);
int snapshot_load(struct store *s, const char *path, char *err,
                  size_t errlen);

// Serialize one entry (used by DUMP) and restore it (RESTORE).  The
// serialized form is a record as above, without the key, followed by a
// u16 version and a u32 crc32.
int entry_dump(const struct entry *e, sbuf *out);
int entry_restore(struct store *s, const char *key, size_t keylen,
                  const char *buf, size_t len, uint64_t expire_at,
                  char *err, size_t errlen);

struct aof {
    FILE *fp;
    char *path;
    int fsync_mode;     // enum aof_fsync
    uint64_t last_fsync_ms;
    sbuf pending;       // encoded commands not yet written
    uint64_t size;      // bytes written to the file
};

struct aof *aof_open(const char *path, int fsync_mode, char *err,
                     size_t errlen);
void aof_close(struct aof *a);
void aof_append(struct aof *a, int argc, char **argv, const size_t *argvlen);
// Write pending data and fsync according to the policy.  Returns 0 or -1.
int aof_flush(struct aof *a, uint64_t now_ms);
// Replay every command in the file through apply().  Returns the number of
// commands applied, or -1 on a malformed file.
long aof_replay(const char *path, int (*apply)(void *ctx, struct request *req),
                void *ctx, char *err, size_t errlen);

#endif
