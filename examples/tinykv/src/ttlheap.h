// ttlheap.h - binary min-heap of expiry times.
//
// Each heap slot points at an owner object (a store entry).  The heap tells
// the owner where it lives via the set_index callback, so that the owner can
// later be removed or rescheduled in O(log n).
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
#ifndef TKV_TTLHEAP_H
#define TKV_TTLHEAP_H

#include <stddef.h>
#include <stdint.h>

#define TTL_NO_INDEX ((size_t)-1)

struct ttl_slot {
    uint64_t when;
    void *owner;
};

struct ttlheap {
    struct ttl_slot *slots;
    size_t len;
    size_t cap;
    void (*set_index)(void *owner, size_t idx);
};

void ttlheap_init(struct ttlheap *h, void (*set_index)(void *, size_t));
void ttlheap_free(struct ttlheap *h);
// Returns 0, or -1 if the heap could not grow.
int ttlheap_push(struct ttlheap *h, uint64_t when, void *owner);
// Return the owner with the smallest time (and the time in *when), or NULL.
void *ttlheap_peek(const struct ttlheap *h, uint64_t *when);
void *ttlheap_pop(struct ttlheap *h, uint64_t *when);
void ttlheap_remove(struct ttlheap *h, size_t idx);
void ttlheap_update(struct ttlheap *h, size_t idx, uint64_t when);
size_t ttlheap_len(const struct ttlheap *h);
// Debug check of the heap property; returns 0 if it holds.
int ttlheap_verify(const struct ttlheap *h);

#endif
