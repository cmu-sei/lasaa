// lru.h - intrusive doubly linked list used to order keys by recency.
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
#ifndef TKV_LRU_H
#define TKV_LRU_H

#include <stddef.h>

struct lru_node {
    struct lru_node *prev;
    struct lru_node *next;
};

// Circular list with a sentinel head: head.next is the most recently used
// node, head.prev the least recently used.
struct lru_list {
    struct lru_node head;
    size_t len;
};

void lru_init(struct lru_list *l);
void lru_node_init(struct lru_node *n);
int lru_node_linked(const struct lru_node *n);
void lru_push_front(struct lru_list *l, struct lru_node *n);
void lru_remove(struct lru_list *l, struct lru_node *n);
// Move n to the front (most recently used).
void lru_touch(struct lru_list *l, struct lru_node *n);
// Least recently used node, or NULL if the list is empty.
struct lru_node *lru_tail(struct lru_list *l);
// The node before n in recency order (more recently used), or NULL.
struct lru_node *lru_prev(struct lru_list *l, struct lru_node *n);
size_t lru_len(const struct lru_list *l);

#endif
