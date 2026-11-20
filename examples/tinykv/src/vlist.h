// vlist.h - list values (LPUSH/RPUSH/LPOP/RPOP/LRANGE/...).
//
// A ring buffer of byte strings, so pushes and pops at either end are O(1).
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
#ifndef TKV_VLIST_H
#define TKV_VLIST_H

#include <stddef.h>

struct vlist_item {
    char *ptr;
    size_t len;
};

struct vlist {
    struct vlist_item *items;
    size_t head;   // index of the first element
    size_t len;
    size_t cap;    // power of two, or 0
    size_t bytes;  // sum of item lengths
};

struct vlist *vlist_new(void);
void vlist_free(struct vlist *l);

// Push a copy of p[0..n).  left != 0 pushes at the head.  Returns 0 or -1.
int vlist_push(struct vlist *l, int left, const char *p, size_t n);
// Pop into *p/*n (the caller frees *p).  Returns 0, or -1 if empty.
int vlist_pop(struct vlist *l, int left, char **p, size_t *n);
// Element at index idx; negative indexes count from the end.  NULL if out
// of range.
struct vlist_item *vlist_at(struct vlist *l, long idx);
// Convert an inclusive Redis-style [start, stop] range to a first index and
// a count.  Returns 0 if the range is empty.
size_t vlist_range(const struct vlist *l, long start, long stop,
                   size_t *first);
// Keep only the elements in [start, stop].
void vlist_trim(struct vlist *l, long start, long stop);
// Remove up to count occurrences of p[0..n) (count < 0: from the tail,
// count == 0: all).  Returns the number removed.
size_t vlist_remove(struct vlist *l, long count, const char *p, size_t n);
// Replace the element at idx.  Returns 0, or -1 if out of range.
int vlist_set(struct vlist *l, long idx, const char *p, size_t n);
size_t vlist_len(const struct vlist *l);
size_t vlist_mem_usage(const struct vlist *l);

#endif
