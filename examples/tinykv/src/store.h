// store.h - the keyspace: string and list values, expiry, eviction.
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
#ifndef TKV_STORE_H
#define TKV_STORE_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "hashtable.h"
#include "lru.h"
#include "ttlheap.h"

struct vlist;

enum val_type {
    VT_STRING,
    VT_LIST
};

struct entry {
    char *key;
    size_t keylen;
    int type;               // enum val_type
    union {
        struct {
            char *ptr;
            size_t len;
        } str;
        struct vlist *list;
    } v;
    uint64_t expire_at;     // absolute ms, 0 = no expiry
    size_t heap_idx;        // TTL_NO_INDEX when not in the heap
    uint64_t last_access;   // ms
    struct lru_node lru;
};

struct store_stats {
    uint64_t hits;
    uint64_t misses;
    uint64_t expired;
    uint64_t evicted;
    uint64_t writes;
    uint64_t deletes;
};

// Called after a key is removed by expiry or eviction (for AOF propagation).
typedef void (*store_remove_cb)(void *ctx, const char *key, size_t keylen,
                                int reason);
enum { STORE_REMOVED_EXPIRED = 1, STORE_REMOVED_EVICTED = 2 };

struct store {
    hashtable *ht;
    struct lru_list lru;
    struct ttlheap ttl;
    size_t used_bytes;
    size_t max_bytes;       // 0 = unlimited
    int policy;             // enum evict_policy
    int samples;
    uint64_t rng;
    uint64_t dirty;         // changes since last snapshot
    struct store_stats stats;
    store_remove_cb on_remove;
    void *on_remove_ctx;
};

// Error codes returned by store operations.
enum {
    STORE_OK = 0,
    STORE_ERR_OOM = -1,       // over max_memory and nothing to evict
    STORE_ERR_WRONGTYPE = -2,
    STORE_ERR_NOTFOUND = -3,
    STORE_ERR_RANGE = -4
};

struct store *store_create(size_t max_bytes, int policy, int samples);
void store_destroy(struct store *s);
void store_flush(struct store *s);
size_t store_count(const struct store *s);

// Find a live key.  Returns NULL if the key does not exist or has expired
// (an expired key is deleted as a side effect).  Updates LRU and stats.
struct entry *store_lookup(struct store *s, const char *key, size_t keylen);
// Like store_lookup but does not touch LRU order or hit/miss stats.
struct entry *store_peek(struct store *s, const char *key, size_t keylen);

// Set a string value (copied).  expire_at == 0 means no expiry.  Any
// existing value (of any type) is replaced.
int store_set_string(struct store *s, const char *key, size_t keylen,
                     const char *val, size_t vlen, uint64_t expire_at);
// Replace the string value of an existing entry, keeping its TTL.
int store_update_string(struct store *s, struct entry *e,
                        const char *val, size_t vlen);
// Return the list at key, creating an empty one if missing.  Returns NULL and
// sets *err (STORE_ERR_WRONGTYPE or STORE_ERR_OOM) on failure.
struct entry *store_get_or_create_list(struct store *s, const char *key,
                                       size_t keylen, int *err);
// Returns 1 if the key was deleted, 0 if it did not exist.
int store_delete(struct store *s, const char *key, size_t keylen);
int store_rename(struct store *s, const char *from, size_t fromlen,
                 const char *to, size_t tolen);

int store_set_expire(struct store *s, struct entry *e, uint64_t when);
// Expire up to max_work keys whose time has passed.  Returns how many.
int store_expire_cycle(struct store *s, uint64_t now, int max_work);
// Evict keys until used_bytes <= max_bytes.  Returns 0, or STORE_ERR_OOM.
int store_evict_if_needed(struct store *s);
// Adjust used_bytes after an in-place change of an entry's value.
void store_account(struct store *s, ssize_t delta);
void store_touch(struct store *s, struct entry *e);

size_t entry_mem_usage(const struct entry *e);
const char *entry_type_name(const struct entry *e);

// Call cb for each live entry; stop early if cb returns nonzero (and return
// that value).
int store_foreach(struct store *s, int (*cb)(struct entry *e, void *arg),
                  void *arg);

#endif
