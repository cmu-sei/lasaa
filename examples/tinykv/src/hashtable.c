// hashtable.c - chained hash table with incremental rehashing.
//
// The design follows the Redis dict: when the table needs to grow or shrink,
// a second bucket array is allocated and entries migrate to it a few buckets
// at a time, piggybacking on lookups and updates, so that no single
// operation pays for a full rehash.
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
#include "hashtable.h"

#include <stdlib.h>
#include <string.h>

#include "util.h"

#define HT_MIN_SIZE 4
#define HT_MAX_LOAD 1       // grow when used / size reaches this
#define HT_MIN_FILL_PCT 10  // shrink when fewer than this % of slots are used

uint64_t ht_hash_bytes(const void *p, size_t n, uint64_t seed)
{
    // FNV-1a with the seed folded into the offset basis, followed by the
    // splitmix64 finalizer so that the low bits (used for bucket selection)
    // depend on every input byte.
    const unsigned char *s = p;
    uint64_t h = 0xcbf29ce484222325ULL ^ seed;

    for (size_t i = 0; i < n; i++) {
        h ^= s[i];
        h *= 0x100000001b3ULL;
    }
    h ^= h >> 30;
    h *= 0xbf58476d1ce4e5b9ULL;
    h ^= h >> 27;
    h *= 0x94d049bb133111ebULL;
    h ^= h >> 31;
    return h;
}

static void table_reset(ht_table *tab)
{
    tab->buckets = NULL;
    tab->size = 0;
    tab->mask = 0;
    tab->used = 0;
}

static int is_rehashing(const hashtable *t)
{
    return t->rehash_idx != -1;
}

static size_t next_power(size_t n)
{
    size_t size = HT_MIN_SIZE;
    size_t limit = (size_t)1 << (sizeof(size_t) * 8 - 1);

    if (n >= limit)
        return limit;
    while (size < n)
        size <<= 1;
    return size;
}

// Allocate a bucket array with room for at least `size` entries.  If the
// table has no buckets yet, the new array becomes the main table; otherwise
// it becomes the rehash target and incremental rehashing starts.
// Returns 0, or -1 if the table cannot be resized now.
static int ht_expand(hashtable *t, size_t size)
{
    ht_table n;
    size_t realsize = next_power(size);

    if (realsize < t->tab[0].used || realsize == t->tab[0].size)
        return -1;

    n.buckets = calloc(realsize, sizeof(*n.buckets));
    if (n.buckets == NULL)
        return -1;
    n.size = realsize;
    n.mask = realsize - 1;
    n.used = 0;

    if (is_rehashing(t))
        return -1;

    if (t->tab[0].buckets == NULL) {
        t->tab[0] = n;
        return 0;
    }
    t->tab[1] = n;
    t->rehash_idx = 0;
    return 0;
}

static void expand_if_needed(hashtable *t)
{
    if (is_rehashing(t))
        return;
    if (t->tab[0].size == 0) {
        if (ht_expand(t, HT_MIN_SIZE) < 0)
            die_oom(HT_MIN_SIZE * sizeof(ht_entry *));
        return;
    }
    // If growing fails we keep going with a higher load factor; chains get
    // longer but everything still works.
    if (t->tab[0].used >= t->tab[0].size * HT_MAX_LOAD)
        (void)ht_expand(t, t->tab[0].used * 2);
}

hashtable *ht_create(size_t initial_size)
{
    hashtable *t = xcalloc(1, sizeof(*t));

    table_reset(&t->tab[0]);
    table_reset(&t->tab[1]);
    t->rehash_idx = -1;
    t->iterators = 0;
    t->seed = now_us() ^ (uint64_t)(uintptr_t)t;
    if (ht_expand(t, initial_size) < 0) {
        free(t);
        return NULL;
    }
    return t;
}

void ht_clear(hashtable *t)
{
    for (int i = 0; i < 2; i++) {
        ht_table *tab = &t->tab[i];

        for (size_t j = 0; j < tab->size && tab->used > 0; j++) {
            ht_entry *e = tab->buckets[j];

            while (e != NULL) {
                ht_entry *next = e->next;
                free(e->key);
                free(e);
                tab->used--;
                e = next;
            }
            tab->buckets[j] = NULL;
        }
        free(tab->buckets);
        table_reset(tab);
    }
    t->rehash_idx = -1;
}

void ht_destroy(hashtable *t)
{
    if (t == NULL)
        return;
    ht_clear(t);
    free(t);
}

size_t ht_count(const hashtable *t)
{
    return t->tab[0].used + t->tab[1].used;
}

int ht_rehash_step(hashtable *t, int n)
{
    // Bound the number of empty buckets visited, so a sparse table does not
    // make one step arbitrarily slow.
    size_t empty_visits = (size_t)n * 10;

    if (!is_rehashing(t))
        return 0;

    while (n-- > 0 && t->tab[0].used != 0) {
        ht_entry *e, *next;

        while (t->tab[0].buckets[t->rehash_idx] == NULL) {
            t->rehash_idx++;
            if (--empty_visits == 0)
                return 1;
        }
        for (e = t->tab[0].buckets[t->rehash_idx]; e != NULL; e = next) {
            size_t idx = e->hash & t->tab[1].mask;

            next = e->next;
            e->next = t->tab[1].buckets[idx];
            t->tab[1].buckets[idx] = e;
            t->tab[0].used--;
            t->tab[1].used++;
        }
        t->tab[0].buckets[t->rehash_idx] = NULL;
        t->rehash_idx++;
    }

    if (t->tab[0].used == 0) {
        free(t->tab[0].buckets);
        t->tab[0] = t->tab[1];
        table_reset(&t->tab[1]);
        t->rehash_idx = -1;
        return 0;
    }
    return 1;
}

void ht_maybe_resize(hashtable *t)
{
    size_t used = ht_count(t);
    size_t size = t->tab[0].size;

    if (size == 0) {
        (void)ht_expand(t, HT_MIN_SIZE);
        return;
    }
    if (used >= size * HT_MAX_LOAD)
        (void)ht_expand(t, used * 2);
    else if (size > HT_MIN_SIZE && used * 100 / size < HT_MIN_FILL_PCT)
        (void)ht_expand(t, used);
}

static void rehash_on_access(hashtable *t)
{
    // Moving entries while an iterator is active could make it skip or
    // repeat entries.
    if (is_rehashing(t) && t->iterators == 0)
        ht_rehash_step(t, 1);
}

static int key_matches(const ht_entry *e, uint64_t h, const void *key,
                       size_t keylen)
{
    return e->hash == h && e->keylen == keylen &&
           memcmp(e->key, key, keylen) == 0;
}

ht_entry *ht_find(hashtable *t, const void *key, size_t keylen)
{
    uint64_t h;

    if (ht_count(t) == 0)
        return NULL;
    rehash_on_access(t);

    h = ht_hash_bytes(key, keylen, t->seed);
    for (int i = 0; i <= 1; i++) {
        ht_table *tab = &t->tab[i];

        for (ht_entry *e = tab->buckets[h & tab->mask]; e != NULL;
             e = e->next) {
            if (key_matches(e, h, key, keylen))
                return e;
        }
        if (!is_rehashing(t))
            break;
    }
    return NULL;
}

void *ht_get(hashtable *t, const void *key, size_t keylen)
{
    ht_entry *e = ht_find(t, key, keylen);

    return e != NULL ? e->val : NULL;
}

int ht_put(hashtable *t, const void *key, size_t keylen, void *val,
           void **old_val)
{
    ht_entry *e = ht_find(t, key, keylen);
    ht_table *tab;
    size_t idx;

    if (e != NULL) {
        if (old_val != NULL)
            *old_val = e->val;
        e->val = val;
        return 0;
    }

    expand_if_needed(t);
    // During a rehash, new entries go straight into the new table.
    tab = is_rehashing(t) ? &t->tab[1] : &t->tab[0];

    e = xmalloc(sizeof(*e));
    e->key = xmemdup0(key, keylen);
    e->keylen = keylen;
    e->hash = ht_hash_bytes(key, keylen, t->seed);
    e->val = val;
    idx = e->hash & tab->mask;
    e->next = tab->buckets[idx];
    tab->buckets[idx] = e;
    tab->used++;
    return 1;
}

int ht_remove(hashtable *t, const void *key, size_t keylen, void **val_out)
{
    uint64_t h;

    if (ht_count(t) == 0)
        return 0;
    rehash_on_access(t);

    h = ht_hash_bytes(key, keylen, t->seed);
    for (int i = 0; i <= 1; i++) {
        ht_table *tab = &t->tab[i];
        ht_entry **pp = &tab->buckets[h & tab->mask];

        for (ht_entry *e = *pp; e != NULL; pp = &e->next, e = e->next) {
            if (!key_matches(e, h, key, keylen))
                continue;
            *pp = e->next;
            if (val_out != NULL)
                *val_out = e->val;
            free(e->key);
            free(e);
            tab->used--;
            return 1;
        }
        if (!is_rehashing(t))
            break;
    }
    return 0;
}

ht_entry *ht_random_entry(hashtable *t, uint64_t *rng)
{
    ht_entry *e, *head;
    size_t len, i;

    if (ht_count(t) == 0)
        return NULL;
    rehash_on_access(t);

    // Probe random buckets until a nonempty one turns up.  While rehashing,
    // the buckets of tab[0] below rehash_idx have already been emptied, so
    // sample from the rest of tab[0] and all of tab[1].
    if (is_rehashing(t)) {
        size_t lo = (size_t)t->rehash_idx;
        size_t span = t->tab[0].size - lo + t->tab[1].size;

        do {
            i = lo + (size_t)(rng_next(rng) % span);
            if (i < t->tab[0].size)
                e = t->tab[0].buckets[i];
            else
                e = t->tab[1].buckets[i - t->tab[0].size];
        } while (e == NULL);
    } else {
        do {
            e = t->tab[0].buckets[rng_next(rng) & t->tab[0].mask];
        } while (e == NULL);
    }

    // Then pick a random entry of that chain.
    head = e;
    len = 0;
    for (; e != NULL; e = e->next)
        len++;
    i = (size_t)(rng_next(rng) % len);
    for (e = head; i > 0; i--)
        e = e->next;
    return e;
}

void ht_iter_init(ht_iter *it, hashtable *t)
{
    it->t = t;
    it->table = 0;
    it->idx = 0;
    it->cur = NULL;
    it->next = NULL;
    it->started = 0;
}

ht_entry *ht_iter_next(ht_iter *it)
{
    hashtable *t = it->t;

    if (!it->started) {
        it->started = 1;
        t->iterators++;
    }
    for (;;) {
        ht_table *tab;

        // `next` is fetched before the current entry is returned, so the
        // caller may remove the current entry.
        if (it->next != NULL) {
            it->cur = it->next;
            it->next = it->cur->next;
            return it->cur;
        }
        tab = &t->tab[it->table];
        if (it->idx >= tab->size) {
            if (it->table == 0 && is_rehashing(t)) {
                it->table = 1;
                it->idx = 0;
                continue;
            }
            it->cur = NULL;
            return NULL;
        }
        it->next = tab->buckets[it->idx++];
    }
}

void ht_iter_release(ht_iter *it)
{
    if (it->started) {
        it->t->iterators--;
        it->started = 0;
    }
}
