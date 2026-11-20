// store.c - the keyspace: string and list values, expiry, eviction.
//
// Every entry lives in three structures: the hash table (lookup by key),
// the LRU list (all entries, most recently used first), and, if it has a
// TTL, the expiry heap.  Memory accounting is approximate: entry_mem_usage()
// estimates what an entry costs, and used_bytes is the sum over all entries.
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
#include "store.h"

#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "log.h"
#include "util.h"
#include "vlist.h"

#define DEFAULT_EVICT_SAMPLES 5
#define INITIAL_BUCKETS 64
// Rough per-key cost beyond the key and value bytes.
#define ENTRY_OVERHEAD (sizeof(struct entry) + sizeof(ht_entry))

// Zero-length string values all share this buffer instead of each getting a
// one-byte allocation.  Use dup_value()/free_value() for string values.
static char empty_value[1];

static char *dup_value(const char *val, size_t vlen)
{
    if (vlen == 0)
        return empty_value;
    return xmemdup0(val, vlen);
}

static void free_value(char *p)
{
    if (p != empty_value)
        free(p);
}

static void set_heap_index(void *owner, size_t idx)
{
    struct entry *e = owner;

    e->heap_idx = idx;
}

size_t entry_mem_usage(const struct entry *e)
{
    // The key is stored twice: in the entry and in the hash table.
    size_t n = ENTRY_OVERHEAD + 2 * (e->keylen + 1);

    if (e->type == VT_STRING) {
        if (e->v.str.len > 0)
            n += e->v.str.len + 1;
    } else if (e->v.list != NULL) {
        n += vlist_mem_usage(e->v.list);
    }
    return n;
}

const char *entry_type_name(const struct entry *e)
{
    switch (e->type) {
    case VT_STRING:
        return "string";
    case VT_LIST:
        return "list";
    default:
        return "unknown";
    }
}

static struct entry *entry_new(const char *key, size_t keylen)
{
    struct entry *e = xcalloc(1, sizeof(*e));

    e->key = xmemdup0(key, keylen);
    e->keylen = keylen;
    e->type = VT_STRING;
    e->v.str.ptr = empty_value;
    e->v.str.len = 0;
    e->expire_at = 0;
    e->heap_idx = TTL_NO_INDEX;
    e->last_access = now_ms();
    lru_node_init(&e->lru);
    return e;
}

static void release_value(struct entry *e)
{
    if (e->type == VT_STRING) {
        free_value(e->v.str.ptr);
        e->v.str.ptr = empty_value;
        e->v.str.len = 0;
    } else {
        vlist_free(e->v.list);
        e->v.list = NULL;
    }
}

static void entry_free(struct entry *e)
{
    release_value(e);
    free(e->key);
    free(e);
}

struct store *store_create(size_t max_bytes, int policy, int samples)
{
    struct store *s = xcalloc(1, sizeof(*s));

    s->ht = ht_create(INITIAL_BUCKETS);
    if (s->ht == NULL) {
        free(s);
        return NULL;
    }
    lru_init(&s->lru);
    ttlheap_init(&s->ttl, set_heap_index);
    s->used_bytes = 0;
    s->max_bytes = max_bytes;
    s->policy = policy;
    s->samples = samples > 0 ? samples : DEFAULT_EVICT_SAMPLES;
    s->rng = now_us() | 1;
    return s;
}

void store_flush(struct store *s)
{
    ht_iter it;
    ht_entry *he;

    ht_iter_init(&it, s->ht);
    while ((he = ht_iter_next(&it)) != NULL)
        entry_free(he->val);
    ht_iter_release(&it);
    ht_clear(s->ht);

    lru_init(&s->lru);
    ttlheap_free(&s->ttl);
    ttlheap_init(&s->ttl, set_heap_index);
    s->used_bytes = 0;
    s->dirty++;
}

void store_destroy(struct store *s)
{
    if (s == NULL)
        return;
    store_flush(s);
    ht_destroy(s->ht);
    ttlheap_free(&s->ttl);
    free(s);
}

size_t store_count(const struct store *s)
{
    return ht_count(s->ht);
}

void store_account(struct store *s, ssize_t delta)
{
    if (delta < 0 && (size_t)-delta > s->used_bytes)
        s->used_bytes = 0;
    else
        s->used_bytes += (size_t)delta;
}

void store_touch(struct store *s, struct entry *e)
{
    e->last_access = now_ms();
    if (lru_node_linked(&e->lru))
        lru_touch(&s->lru, &e->lru);
}

// Add a new entry to the hash table and the LRU list.
static void link_entry(struct store *s, struct entry *e)
{
    ht_put(s->ht, e->key, e->keylen, e, NULL);
    lru_push_front(&s->lru, &e->lru);
    store_account(s, (ssize_t)entry_mem_usage(e));
}

// Remove an entry from every index and from the memory accounting.
static void unlink_entry(struct store *s, struct entry *e)
{
    ht_remove(s->ht, e->key, e->keylen, NULL);
    lru_remove(&s->lru, &e->lru);
    if (e->heap_idx != TTL_NO_INDEX)
        ttlheap_remove(&s->ttl, e->heap_idx);
    store_account(s, -(ssize_t)entry_mem_usage(e));
}

static void store_remove_entry(struct store *s, struct entry *e)
{
    unlink_entry(s, e);
    entry_free(e);
}

static void expire_entry(struct store *s, struct entry *e)
{
    if (s->on_remove != NULL)
        s->on_remove(s->on_remove_ctx, e->key, e->keylen,
                     STORE_REMOVED_EXPIRED);
    store_remove_entry(s, e);
    s->stats.expired++;
    s->dirty++;
}

// Delete e if its TTL has passed.  Returns 1 if it was deleted.
static int expire_if_needed(struct store *s, struct entry *e, uint64_t now)
{
    if (e->expire_at == 0 || e->expire_at > now)
        return 0;
    expire_entry(s, e);
    return 1;
}

// Pick a key according to the eviction policy and remove it.  Returns 0 if
// a key was evicted, -1 if nothing can be evicted.
static int evict_one(struct store *s)
{
    struct entry *victim = NULL;

    switch (s->policy) {
    case EVICT_VOLATILE_TTL:
        victim = ttlheap_peek(&s->ttl, NULL);
        if (victim == NULL)
            return -1;
        break;

    case EVICT_ALLKEYS_LRU: {
        // Approximated LRU: sample a few random keys and evict the one that
        // has been idle the longest.
        int n = s->samples > 0 ? s->samples : 1;

        if (ht_count(s->ht) == 0)
            return -1;
        for (int i = 0; i < n; i++) {
            ht_entry *he = ht_random_entry(s->ht, &s->rng);
            struct entry *e;

            if (he == NULL)
                continue;
            e = he->val;
            if (victim == NULL || e->last_access < victim->last_access)
                victim = e;
        }
        break;
    }

    default:
        return -1;
    }

    log_debug("evicting key '%.*s' (%zu bytes)", (int)victim->keylen,
              victim->key, entry_mem_usage(victim));
    store_remove_entry(s, victim);
    s->stats.evicted++;
    s->dirty++;
    if (s->on_remove != NULL)
        s->on_remove(s->on_remove_ctx, victim->key, victim->keylen,
                     STORE_REMOVED_EVICTED);
    return 0;
}

// Evict keys until `need` more bytes fit under max_bytes.
static int make_room(struct store *s, size_t need)
{
    if (s->max_bytes == 0)
        return STORE_OK;
    while (s->used_bytes + need > s->max_bytes) {
        if (evict_one(s) != 0) {
            log_debug("cannot free memory: used %zu, need %zu, max %zu",
                      s->used_bytes, need, s->max_bytes);
            return STORE_ERR_OOM;
        }
    }
    return STORE_OK;
}

int store_evict_if_needed(struct store *s)
{
    return make_room(s, 0);
}

struct entry *store_peek(struct store *s, const char *key, size_t keylen)
{
    struct entry *e = ht_get(s->ht, key, keylen);

    if (e == NULL)
        return NULL;
    if (expire_if_needed(s, e, now_ms()))
        return NULL;
    return e;
}

struct entry *store_lookup(struct store *s, const char *key, size_t keylen)
{
    struct entry *e = store_peek(s, key, keylen);

    if (e == NULL) {
        s->stats.misses++;
        return NULL;
    }
    s->stats.hits++;
    store_touch(s, e);
    return e;
}

int store_set_expire(struct store *s, struct entry *e, uint64_t when)
{
    if (when == 0) {
        if (e->heap_idx != TTL_NO_INDEX)
            ttlheap_remove(&s->ttl, e->heap_idx);
        e->expire_at = 0;
        return STORE_OK;
    }
    if (e->heap_idx != TTL_NO_INDEX) {
        ttlheap_update(&s->ttl, e->heap_idx, when);
    } else if (ttlheap_push(&s->ttl, when, e) != 0) {
        return STORE_ERR_OOM;
    }
    e->expire_at = when;
    s->dirty++;
    return STORE_OK;
}

int store_set_string(struct store *s, const char *key, size_t keylen,
                     const char *val, size_t vlen, uint64_t expire_at)
{
    struct entry *e;
    char *copy;

    copy = dup_value(val, vlen);
    if (make_room(s, keylen + vlen + ENTRY_OVERHEAD) != STORE_OK) {
        free(copy);
        return STORE_ERR_OOM;
    }

    e = store_peek(s, key, keylen);
    if (e != NULL) {
        size_t before = entry_mem_usage(e);

        release_value(e);
        e->type = VT_STRING;
        e->v.str.ptr = copy;
        e->v.str.len = vlen;
        store_account(s, (ssize_t)entry_mem_usage(e) - (ssize_t)before);
        store_touch(s, e);
    } else {
        e = entry_new(key, keylen);
        e->v.str.ptr = copy;
        e->v.str.len = vlen;
        link_entry(s, e);
    }

    // A plain SET discards any previous TTL.
    if (store_set_expire(s, e, expire_at) != STORE_OK) {
        store_remove_entry(s, e);
        return STORE_ERR_OOM;
    }
    s->stats.writes++;
    s->dirty++;
    return STORE_OK;
}

// Eviction is left to the next write, so that e stays valid for the caller.
int store_update_string(struct store *s, struct entry *e,
                        const char *val, size_t vlen)
{
    size_t before;
    char *copy;

    if (e->type != VT_STRING)
        return STORE_ERR_WRONGTYPE;
    before = entry_mem_usage(e);
    // Copy first: val may point into the current value.
    copy = dup_value(val, vlen);
    free_value(e->v.str.ptr);
    e->v.str.ptr = copy;
    e->v.str.len = vlen;
    store_account(s, (ssize_t)entry_mem_usage(e) - (ssize_t)before);
    store_touch(s, e);
    s->stats.writes++;
    s->dirty++;
    return STORE_OK;
}

struct entry *store_get_or_create_list(struct store *s, const char *key,
                                       size_t keylen, int *err)
{
    struct entry *e = store_lookup(s, key, keylen);

    if (e != NULL) {
        if (e->type != VT_LIST) {
            *err = STORE_ERR_WRONGTYPE;
            return NULL;
        }
        *err = STORE_OK;
        return e;
    }
    if (make_room(s, keylen + ENTRY_OVERHEAD) != STORE_OK) {
        *err = STORE_ERR_OOM;
        return NULL;
    }
    e = entry_new(key, keylen);
    e->type = VT_LIST;
    e->v.list = vlist_new();
    link_entry(s, e);
    s->stats.writes++;
    s->dirty++;
    *err = STORE_OK;
    return e;
}

int store_delete(struct store *s, const char *key, size_t keylen)
{
    struct entry *e = store_peek(s, key, keylen);

    if (e == NULL)
        return 0;
    store_remove_entry(s, e);
    s->stats.deletes++;
    s->dirty++;
    return 1;
}

int store_rename(struct store *s, const char *from, size_t fromlen,
                 const char *to, size_t tolen)
{
    struct entry *e = store_peek(s, from, fromlen);
    size_t before;

    if (e == NULL)
        return STORE_ERR_NOTFOUND;
    if (fromlen == tolen && memcmp(from, to, fromlen) == 0)
        return STORE_OK;

    store_delete(s, to, tolen);

    // The entry object is reused, so its LRU position and TTL carry over.
    before = entry_mem_usage(e);
    ht_remove(s->ht, e->key, e->keylen, NULL);
    free(e->key);
    e->key = xmemdup0(to, tolen);
    e->keylen = tolen;
    ht_put(s->ht, e->key, e->keylen, e, NULL);
    store_account(s, (ssize_t)entry_mem_usage(e) - (ssize_t)before);
    s->stats.writes++;
    s->dirty++;
    return STORE_OK;
}

int store_expire_cycle(struct store *s, uint64_t now, int max_work)
{
    int expired = 0;

    while (expired < max_work) {
        uint64_t when;
        struct entry *e = ttlheap_peek(&s->ttl, &when);

        if (e == NULL || when > now)
            break;
        expire_entry(s, e);
        expired++;
    }

    // Use the idle time to make progress on rehashing, and shrink the table
    // once a rehash has finished if many keys are gone.
    if (ht_rehash_step(s->ht, 1) == 0)
        ht_maybe_resize(s->ht);
    return expired;
}

// Visit entries from least to most recently used.  cb may delete the entry
// it is given, but must not look up other keys (that reorders the list).
int store_foreach(struct store *s, int (*cb)(struct entry *e, void *arg),
                  void *arg)
{
    uint64_t now = now_ms();
    struct lru_node *n = lru_tail(&s->lru);

    while (n != NULL) {
        struct lru_node *prev = lru_prev(&s->lru, n);
        struct entry *e = container_of(n, struct entry, lru);

        if (e->expire_at == 0 || e->expire_at > now) {
            int rc = cb(e, arg);

            if (rc != 0)
                return rc;
        }
        n = prev;
    }
    return 0;
}
