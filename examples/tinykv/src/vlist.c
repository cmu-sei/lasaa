// vlist.c - list values stored in a ring buffer.
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
#include "vlist.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

#define VLIST_MIN_CAP 4

// Slot holding logical element i (0 = head).  cap is a power of two.
static struct vlist_item *slot(const struct vlist *l, size_t i)
{
    return &l->items[(l->head + i) & (l->cap - 1)];
}

struct vlist *vlist_new(void)
{
    struct vlist *l = xcalloc(1, sizeof(*l));

    return l;
}

void vlist_free(struct vlist *l)
{
    if (l == NULL)
        return;
    for (size_t i = 0; i < l->len; i++)
        free(slot(l, i)->ptr);
    free(l->items);
    free(l);
}

// Double the capacity, unwrapping the ring so that the head is at 0.
static void grow(struct vlist *l)
{
    size_t ncap = l->cap ? l->cap * 2 : VLIST_MIN_CAP;
    struct vlist_item *items = xmalloc(ncap * sizeof(*items));

    for (size_t i = 0; i < l->len; i++)
        items[i] = *slot(l, i);
    free(l->items);
    l->items = items;
    l->cap = ncap;
    l->head = 0;
}

int vlist_push(struct vlist *l, int left, const char *p, size_t n)
{
    struct vlist_item item;

    if (l->len == l->cap)
        grow(l);
    item.ptr = xmemdup0(p, n);
    item.len = n;
    if (left) {
        l->head = (l->head + l->cap - 1) & (l->cap - 1);
        l->items[l->head] = item;
    } else {
        *slot(l, l->len) = item;
    }
    l->len++;
    l->bytes += n;
    return 0;
}

int vlist_pop(struct vlist *l, int left, char **p, size_t *n)
{
    struct vlist_item *item;

    if (l->len == 0)
        return -1;
    if (left) {
        item = slot(l, 0);
        l->head = (l->head + 1) & (l->cap - 1);
    } else {
        item = slot(l, l->len - 1);
    }
    l->len--;
    l->bytes -= item->len;
    *p = item->ptr;
    *n = item->len;
    item->ptr = NULL;
    item->len = 0;
    return 0;
}

struct vlist_item *vlist_at(struct vlist *l, long idx)
{
    if (idx < 0)
        idx += (long)l->len;
    if (idx < 0 || (size_t)idx >= l->len)
        return NULL;
    return slot(l, (size_t)idx);
}

size_t vlist_range(const struct vlist *l, long start, long stop,
                   size_t *first)
{
    long len = (long)l->len;

    if (start < 0)
        start += len;
    if (stop < 0)
        stop += len;
    if (start < 0)
        start = 0;
    if (start > stop || start >= len)
        return 0;
    if (stop >= len)
        stop = len - 1;
    *first = (size_t)start;
    return (size_t)(stop - start + 1);
}

void vlist_trim(struct vlist *l, long start, long stop)
{
    size_t first = 0;
    size_t count = vlist_range(l, start, stop, &first);
    size_t i;

    for (i = 0; i < l->len; i++) {
        struct vlist_item *item;

        if (i >= first && i < first + count)
            continue;
        item = slot(l, i);
        l->bytes -= item->len;
        free(item->ptr);
        item->ptr = NULL;
        item->len = 0;
    }
    if (count == 0) {
        l->head = 0;
        l->len = 0;
        return;
    }
    l->head = (l->head + first) & (l->cap - 1);
    l->len = count;
}

static int item_equals(const struct vlist_item *item, const char *p, size_t n)
{
    return item->len == n && memcmp(item->ptr, p, n) == 0;
}

size_t vlist_remove(struct vlist *l, long count, const char *p, size_t n)
{
    size_t limit = count == 0 ? SIZE_MAX
                 : count < 0 ? (size_t)-(count + 1) + 1 : (size_t)count;
    size_t removed = 0;
    size_t r, w;

    if (count >= 0) {
        // Scan from the head, compacting kept elements toward the head.
        for (r = 0, w = 0; r < l->len; r++) {
            struct vlist_item item = *slot(l, r);

            if (removed < limit && item_equals(&item, p, n)) {
                l->bytes -= item.len;
                free(item.ptr);
                removed++;
            } else {
                *slot(l, w++) = item;
            }
        }
        l->len = w;
    } else {
        // Scan from the tail, compacting kept elements toward the tail.
        for (r = l->len, w = l->len; r-- > 0;) {
            struct vlist_item item = *slot(l, r);

            if (removed < limit && item_equals(&item, p, n)) {
                l->bytes -= item.len;
                free(item.ptr);
                removed++;
            } else {
                *slot(l, --w) = item;
            }
        }
        // Kept elements now occupy logical positions [w, len).
        if (l->cap != 0)
            l->head = (l->head + w) & (l->cap - 1);
        l->len -= w;
    }
    return removed;
}

int vlist_set(struct vlist *l, long idx, const char *p, size_t n)
{
    struct vlist_item *item = vlist_at(l, idx);
    char *copy;

    if (item == NULL)
        return -1;
    copy = xmemdup0(p, n);
    free(item->ptr);
    l->bytes = l->bytes - item->len + n;
    item->ptr = copy;
    item->len = n;
    return 0;
}

size_t vlist_len(const struct vlist *l)
{
    return l->len;
}

size_t vlist_mem_usage(const struct vlist *l)
{
    // Each element costs its bytes, the NUL we add, and a slot.
    return sizeof(*l) + l->cap * sizeof(struct vlist_item) + l->bytes +
           l->len;
}
