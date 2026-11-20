// sbuf.c - growable byte buffer.
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
#include "sbuf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SBUF_MIN_CAP 64

void sbuf_init(sbuf *b)
{
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

void sbuf_free(sbuf *b)
{
    free(b->data);
    sbuf_init(b);
}

void sbuf_reset(sbuf *b)
{
    b->len = 0;
    if (b->data != NULL)
        b->data[0] = '\0';
}

// Make room for `extra` more bytes plus the terminating NUL.
int sbuf_reserve(sbuf *b, size_t extra)
{
    size_t need, newcap;
    char *p;

    if (extra > (size_t)-1 - b->len - 1)
        return -1;
    need = b->len + extra + 1;
    if (need <= b->cap)
        return 0;

    newcap = b->cap ? b->cap : SBUF_MIN_CAP;
    while (newcap < need) {
        if (newcap > (size_t)-1 / 2) {
            newcap = need;
            break;
        }
        newcap *= 2;
    }

    p = realloc(b->data, newcap);
    if (p == NULL)
        return -1;
    if (b->data == NULL)
        p[0] = '\0';
    b->data = p;
    b->cap = newcap;
    return 0;
}

int sbuf_append(sbuf *b, const void *p, size_t n)
{
    if (sbuf_reserve(b, n) != 0)
        return -1;
    if (n > 0)
        memcpy(b->data + b->len, p, n);
    b->len += n;
    b->data[b->len] = '\0';
    return 0;
}

int sbuf_append_str(sbuf *b, const char *s)
{
    return sbuf_append(b, s, strlen(s));
}

int sbuf_append_char(sbuf *b, char c)
{
    return sbuf_append(b, &c, 1);
}

int sbuf_vappendf(sbuf *b, const char *fmt, va_list ap)
{
    va_list ap2;
    int n;

    // Try to format into the existing free space first; most messages fit.
    if (sbuf_reserve(b, 32) != 0)
        return -1;
    va_copy(ap2, ap);
    n = vsnprintf(b->data + b->len, b->cap - b->len, fmt, ap2);
    va_end(ap2);
    if (n < 0)
        return -1;

    if ((size_t)n >= b->cap - b->len) {
        if (sbuf_reserve(b, (size_t)n) != 0)
            return -1;
        va_copy(ap2, ap);
        n = vsnprintf(b->data + b->len, b->cap - b->len, fmt, ap2);
        va_end(ap2);
        if (n < 0)
            return -1;
    }
    b->len += (size_t)n;
    return 0;
}

int sbuf_appendf(sbuf *b, const char *fmt, ...)
{
    va_list ap;
    int rc;

    va_start(ap, fmt);
    rc = sbuf_vappendf(b, fmt, ap);
    va_end(ap);
    return rc;
}

void sbuf_consume(sbuf *b, size_t n)
{
    if (n >= b->len) {
        sbuf_reset(b);
        return;
    }
    memmove(b->data, b->data + n, b->len - n);
    b->len -= n;
    b->data[b->len] = '\0';
}

void sbuf_truncate(sbuf *b, size_t n)
{
    if (n < b->len) {
        b->len = n;
        b->data[n] = '\0';
    }
}

char *sbuf_detach(sbuf *b, size_t *len_out)
{
    char *p = b->data;

    if (len_out != NULL)
        *len_out = b->len;
    sbuf_init(b);
    return p;
}

void sbuf_shrink(sbuf *b)
{
    size_t newcap;
    char *p;

    if (b->data == NULL || b->cap <= SBUF_MIN_CAP * 4 || b->len >= b->cap / 4)
        return;
    newcap = b->len + 1 < SBUF_MIN_CAP ? SBUF_MIN_CAP : b->len + 1;
    p = realloc(b->data, newcap);
    if (p == NULL)
        return;  // keeping the larger buffer is fine
    b->data = p;
    b->cap = newcap;
}
