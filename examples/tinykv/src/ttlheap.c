// ttlheap.c - binary min-heap of expiry times.
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
#include "ttlheap.h"

#include <stdlib.h>

#define TTLHEAP_INITIAL_CAP 16

void ttlheap_init(struct ttlheap *h, void (*set_index)(void *, size_t))
{
    h->slots = NULL;
    h->len = 0;
    h->cap = 0;
    h->set_index = set_index;
}

void ttlheap_free(struct ttlheap *h)
{
    free(h->slots);
    h->slots = NULL;
    h->len = 0;
    h->cap = 0;
}

// Store slot s at position i and tell its owner.
static void place(struct ttlheap *h, size_t i, struct ttl_slot s)
{
    h->slots[i] = s;
    if (h->set_index != NULL)
        h->set_index(s.owner, i);
}

static void sift_up(struct ttlheap *h, size_t i)
{
    struct ttl_slot s = h->slots[i];

    while (i > 0) {
        size_t parent = (i - 1) / 2;

        if (h->slots[parent].when <= s.when)
            break;
        place(h, i, h->slots[parent]);
        i = parent;
    }
    place(h, i, s);
}

static void sift_down(struct ttlheap *h, size_t i)
{
    struct ttl_slot s = h->slots[i];

    for (;;) {
        size_t left = 2 * i + 1;
        size_t right = left + 1;
        size_t child;

        if (left >= h->len)
            break;
        child = left;
        if (right < h->len && h->slots[right].when < h->slots[left].when)
            child = right;
        if (h->slots[child].when >= s.when)
            break;
        place(h, i, h->slots[child]);
        i = child;
    }
    place(h, i, s);
}

int ttlheap_push(struct ttlheap *h, uint64_t when, void *owner)
{
    if (h->len == h->cap) {
        size_t ncap = h->cap ? h->cap * 2 : TTLHEAP_INITIAL_CAP;
        struct ttl_slot *ns = realloc(h->slots, ncap * sizeof(*ns));

        if (ns == NULL)
            return -1;
        h->slots = ns;
        h->cap = ncap;
    }
    h->slots[h->len].when = when;
    h->slots[h->len].owner = owner;
    h->len++;
    sift_up(h, h->len - 1);
    return 0;
}

void *ttlheap_peek(const struct ttlheap *h, uint64_t *when)
{
    if (h->len == 0)
        return NULL;
    if (when != NULL)
        *when = h->slots[0].when;
    return h->slots[0].owner;
}

void *ttlheap_pop(struct ttlheap *h, uint64_t *when)
{
    void *owner;

    if (h->len == 0)
        return NULL;
    owner = h->slots[0].owner;
    if (when != NULL)
        *when = h->slots[0].when;
    ttlheap_remove(h, 0);
    return owner;
}

void ttlheap_remove(struct ttlheap *h, size_t idx)
{
    void *owner;
    size_t last;

    if (idx >= h->len)
        return;
    owner = h->slots[idx].owner;
    last = --h->len;
    if (idx != last) {
        // Move the last slot into the hole, then restore the heap property
        // in whichever direction it is violated.
        h->slots[idx] = h->slots[last];
        if (idx > 0 && h->slots[idx].when < h->slots[(idx - 1) / 2].when)
            sift_up(h, idx);
        else
            sift_down(h, idx);
    }
    if (h->set_index != NULL)
        h->set_index(owner, TTL_NO_INDEX);
}

void ttlheap_update(struct ttlheap *h, size_t idx, uint64_t when)
{
    uint64_t old;

    if (idx >= h->len)
        return;
    old = h->slots[idx].when;
    h->slots[idx].when = when;
    if (when < old)
        sift_up(h, idx);
    else
        sift_down(h, idx);
}

size_t ttlheap_len(const struct ttlheap *h)
{
    return h->len;
}

int ttlheap_verify(const struct ttlheap *h)
{
    for (size_t i = 1; i < h->len; i++) {
        if (h->slots[(i - 1) / 2].when > h->slots[i].when)
            return -1;
    }
    return 0;
}
