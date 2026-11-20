// lru.c - intrusive doubly linked list used to order keys by recency.
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
#include "lru.h"

#include <stddef.h>

void lru_init(struct lru_list *l)
{
    l->head.prev = &l->head;
    l->head.next = &l->head;
    l->len = 0;
}

void lru_node_init(struct lru_node *n)
{
    n->prev = NULL;
    n->next = NULL;
}

int lru_node_linked(const struct lru_node *n)
{
    return n->next != NULL;
}

void lru_push_front(struct lru_list *l, struct lru_node *n)
{
    n->prev = &l->head;
    n->next = l->head.next;
    l->head.next->prev = n;
    l->head.next = n;
    l->len++;
}

void lru_remove(struct lru_list *l, struct lru_node *n)
{
    if (!lru_node_linked(n))
        return;
    n->prev->next = n->next;
    n->next->prev = n->prev;
    n->prev = NULL;
    n->next = NULL;
    l->len--;
}

void lru_touch(struct lru_list *l, struct lru_node *n)
{
    if (l->head.next == n)
        return;
    lru_remove(l, n);
    lru_push_front(l, n);
}

struct lru_node *lru_tail(struct lru_list *l)
{
    if (l->len == 0)
        return NULL;
    return l->head.prev;
}

struct lru_node *lru_prev(struct lru_list *l, struct lru_node *n)
{
    if (n->prev == &l->head)
        return NULL;
    return n->prev;
}

size_t lru_len(const struct lru_list *l)
{
    return l->len;
}
