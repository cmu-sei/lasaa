// util.h - allocation wrappers, string and number helpers, clocks.
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
#ifndef TKV_UTIL_H
#define TKV_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))
#define TKV_MIN(a, b) ((a) < (b) ? (a) : (b))
#define TKV_MAX(a, b) ((a) > (b) ? (a) : (b))
#define UNUSED(x) ((void)(x))

#define container_of(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))

// Print a message and abort.  Used when an allocation fails: the server
// cannot do anything useful without memory.
void die_oom(size_t n) __attribute__((noreturn));
void die(const char *fmt, ...) __attribute__((noreturn, format(printf, 1, 2)));

static inline void *xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1);
    if (p == NULL)
        die_oom(n);
    return p;
}

static inline void *xcalloc(size_t nmemb, size_t size)
{
    void *p = calloc(nmemb ? nmemb : 1, size ? size : 1);
    if (p == NULL)
        die_oom(nmemb * size);
    return p;
}

static inline void *xrealloc(void *old, size_t n)
{
    void *p = realloc(old, n ? n : 1);
    if (p == NULL)
        die_oom(n);
    return p;
}

static inline char *xstrdup(const char *s)
{
    char *p = strdup(s);
    if (p == NULL)
        die_oom(strlen(s) + 1);
    return p;
}

// Copy n bytes and add a terminating NUL (so binary-safe values can also be
// used as C strings when they contain no NUL).
static inline char *xmemdup0(const void *src, size_t n)
{
    char *p = xmalloc(n + 1);
    memcpy(p, src, n);
    p[n] = '\0';
    return p;
}

// Strings and numbers (util.c).
char *str_trim(char *s);
int str_ieq(const char *a, size_t alen, const char *b);
int str_to_ll(const char *s, size_t len, long long *out);
int str_to_ull(const char *s, size_t len, unsigned long long *out);
int parse_size(const char *s, unsigned long long *out);
int parse_bool(const char *s, int *out);
int parse_duration_ms(const char *s, long long *out);
size_t ll_to_str(char *buf, size_t cap, long long v);
int str_split(char *s, char sep, char **fields, int max_fields);
char *str_escape(const char *s, size_t len);
size_t str_lcpy(char *dst, const char *src, size_t cap);
void fmt_bytes(char *buf, size_t cap, unsigned long long n);

// Clocks (util.c).
uint64_t now_ms(void);
uint64_t now_us(void);

// Small fast PRNG (xorshift64*).  *state must be nonzero.
uint64_t rng_next(uint64_t *state);

#endif
