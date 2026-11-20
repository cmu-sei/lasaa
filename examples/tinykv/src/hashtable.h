// hashtable.h - chained hash table with incremental rehashing.
//
// Keys are binary-safe byte strings that the table copies.  Values are
// opaque pointers owned by the caller (the table never frees them).
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
#ifndef TKV_HASHTABLE_H
#define TKV_HASHTABLE_H

#include <stddef.h>
#include <stdint.h>

typedef struct ht_entry {
    char *key;
    size_t keylen;
    uint64_t hash;
    void *val;
    struct ht_entry *next;
} ht_entry;

// Two bucket arrays: while a rehash is in progress, entries are moved from
// tab[0] to tab[1] a few buckets at a time, and lookups check both.
typedef struct ht_table {
    ht_entry **buckets;
    size_t size;     // number of buckets (power of two, or 0)
    size_t mask;     // size - 1
    size_t used;     // number of entries
} ht_table;

typedef struct hashtable {
    ht_table tab[2];
    long rehash_idx;  // -1 when not rehashing
    int iterators;    // safe iterators active; pauses rehashing
    uint64_t seed;
} hashtable;

typedef struct ht_iter {
    hashtable *t;
    int table;
    size_t idx;
    ht_entry *cur;
    ht_entry *next;
    int started;
} ht_iter;

hashtable *ht_create(size_t initial_size);
void ht_destroy(hashtable *t);
void ht_clear(hashtable *t);

// Returns the value, or NULL if the key is not present.
void *ht_get(hashtable *t, const void *key, size_t keylen);
// Returns the stored entry, or NULL if the key is not present.
ht_entry *ht_find(hashtable *t, const void *key, size_t keylen);
// Insert or replace.  Returns 1 if the key was added, 0 if an existing value
// was replaced (the old value is stored in *old_val when old_val != NULL).
int ht_put(hashtable *t, const void *key, size_t keylen, void *val,
           void **old_val);
// Returns 1 and stores the value in *val_out if the key was removed,
// 0 if it was not present.
int ht_remove(hashtable *t, const void *key, size_t keylen, void **val_out);

size_t ht_count(const hashtable *t);
// Return a random entry, or NULL if the table is empty.
ht_entry *ht_random_entry(hashtable *t, uint64_t *rng);
// Perform up to n steps of incremental rehashing.  Returns 1 if more work
// remains.
int ht_rehash_step(hashtable *t, int n);
// Grow or shrink the table if the load factor calls for it.
void ht_maybe_resize(hashtable *t);

// Iteration.  The table must not be modified during iteration except by
// removing the entry most recently returned.
void ht_iter_init(ht_iter *it, hashtable *t);
ht_entry *ht_iter_next(ht_iter *it);
void ht_iter_release(ht_iter *it);

uint64_t ht_hash_bytes(const void *p, size_t n, uint64_t seed);

#endif
