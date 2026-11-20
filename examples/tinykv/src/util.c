// util.c - string and number helpers, clocks, fatal errors.
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
#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <strings.h>
#include <time.h>

void die_oom(size_t n)
{
    fprintf(stderr, "tinykv: out of memory allocating %zu bytes\n", n);
    fflush(stderr);
    abort();
}

void die(const char *fmt, ...)
{
    va_list ap;

    fputs("tinykv: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    fflush(stderr);
    exit(1);
}

// Strip leading and trailing whitespace in place.  Returns a pointer into s.
char *str_trim(char *s)
{
    char *end;

    while (*s != '\0' && isspace((unsigned char)*s))
        s++;
    if (*s == '\0')
        return s;
    end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end))
        end--;
    end[1] = '\0';
    return s;
}

// Case-insensitive comparison of a (length alen, not necessarily
// NUL-terminated) with the C string b.  Returns nonzero if equal.
int str_ieq(const char *a, size_t alen, const char *b)
{
    size_t i;

    for (i = 0; i < alen; i++) {
        if (b[i] == '\0')
            return 0;
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i]))
            return 0;
    }
    return b[alen] == '\0';
}

// Parse a decimal integer occupying exactly s[0..len).  No whitespace, no
// leading '+', and no leading zeros (except "0" itself), so that every value
// has exactly one representation.  Returns 0 on success, -1 otherwise.
int str_to_ll(const char *s, size_t len, long long *out)
{
    unsigned long long v = 0;
    unsigned long long limit;
    int neg = 0;
    size_t i = 0;

    if (len == 0 || len > 20)
        return -1;
    if (s[0] == '-') {
        neg = 1;
        i = 1;
        if (len == 1)
            return -1;
    }
    if (s[i] == '0' && len - i > 1)
        return -1;
    if (neg && s[i] == '0')
        return -1;

    limit = neg ? (unsigned long long)LLONG_MAX + 1 : (unsigned long long)LLONG_MAX;
    for (; i < len; i++) {
        unsigned d;

        if (s[i] < '0' || s[i] > '9')
            return -1;
        d = (unsigned)(s[i] - '0');
        if (v > (limit - d) / 10)
            return -1;
        v = v * 10 + d;
    }

    if (neg)
        *out = (v == (unsigned long long)LLONG_MAX + 1) ? LLONG_MIN : -(long long)v;
    else
        *out = (long long)v;
    return 0;
}

int str_to_ull(const char *s, size_t len, unsigned long long *out)
{
    unsigned long long v = 0;
    size_t i;

    if (len == 0 || len > 20)
        return -1;
    if (s[0] == '0' && len > 1)
        return -1;
    for (i = 0; i < len; i++) {
        unsigned d;

        if (s[i] < '0' || s[i] > '9')
            return -1;
        d = (unsigned)(s[i] - '0');
        if (v > (ULLONG_MAX - d) / 10)
            return -1;
        v = v * 10 + d;
    }
    *out = v;
    return 0;
}

// Parse a size such as "512", "64kb", "10M", or "1gb" (powers of 1024).
int parse_size(const char *s, unsigned long long *out)
{
    unsigned long long n = 0, mult = 1;
    const char *p = s;

    if (!isdigit((unsigned char)*p))
        return -1;
    while (isdigit((unsigned char)*p)) {
        unsigned d = (unsigned)(*p - '0');

        if (n > (ULLONG_MAX - d) / 10)
            return -1;
        n = n * 10 + d;
        p++;
    }

    if (*p != '\0') {
        switch (tolower((unsigned char)*p)) {
        case 'k': mult = 1024ULL; break;
        case 'm': mult = 1024ULL * 1024; break;
        case 'g': mult = 1024ULL * 1024 * 1024; break;
        case 'b': mult = 1; p--; break;
        default: return -1;
        }
        p++;
        if (tolower((unsigned char)*p) == 'b')
            p++;
        if (*p != '\0')
            return -1;
    }

    if (n != 0 && mult > ULLONG_MAX / n)
        return -1;
    *out = n * mult;
    return 0;
}

int parse_bool(const char *s, int *out)
{
    static const char *const yes[] = { "yes", "on", "true", "1" };
    static const char *const no[] = { "no", "off", "false", "0" };
    size_t i;

    for (i = 0; i < ARRAY_LEN(yes); i++) {
        if (strcasecmp(s, yes[i]) == 0) {
            *out = 1;
            return 0;
        }
        if (strcasecmp(s, no[i]) == 0) {
            *out = 0;
            return 0;
        }
    }
    return -1;
}

// Parse a duration such as "1500ms", "30s", "5m", "2h", or a bare number of
// seconds.  The result is in milliseconds.
int parse_duration_ms(const char *s, long long *out)
{
    long long n = 0, mult = 1000;
    const char *p = s;

    if (!isdigit((unsigned char)*p))
        return -1;
    while (isdigit((unsigned char)*p)) {
        int d = *p - '0';

        if (n > (LLONG_MAX - d) / 10)
            return -1;
        n = n * 10 + d;
        p++;
    }

    if (strcmp(p, "ms") == 0)
        mult = 1;
    else if (*p == '\0' || strcmp(p, "s") == 0)
        mult = 1000;
    else if (strcmp(p, "m") == 0)
        mult = 60 * 1000;
    else if (strcmp(p, "h") == 0)
        mult = 60 * 60 * 1000;
    else
        return -1;

    if (n > LLONG_MAX / mult)
        return -1;
    *out = n * mult;
    return 0;
}

// Format v in decimal.  Returns the length, or 0 if buf is too small.
size_t ll_to_str(char *buf, size_t cap, long long v)
{
    char tmp[24];
    unsigned long long u;
    size_t n = 0, i;
    int neg = v < 0;

    u = neg ? (unsigned long long)(-(v + 1)) + 1 : (unsigned long long)v;
    do {
        tmp[n++] = (char)('0' + u % 10);
        u /= 10;
    } while (u != 0);
    if (neg)
        tmp[n++] = '-';

    if (n + 1 > cap)
        return 0;
    for (i = 0; i < n; i++)
        buf[i] = tmp[n - 1 - i];
    buf[n] = '\0';
    return n;
}

// Split s in place at each sep.  Stores up to max_fields pointers in
// fields[] and returns the number of fields found (which may exceed
// max_fields; the extra fields are not stored).
int str_split(char *s, char sep, char **fields, int max_fields)
{
    int n = 0;
    char *p = s;

    for (;;) {
        char *q = strchr(p, sep);

        if (n < max_fields)
            fields[n] = p;
        n++;
        if (q == NULL)
            break;
        *q = '\0';
        p = q + 1;
    }
    return n;
}

// Return a newly allocated printable version of s[0..len), with quotes,
// backslashes, and non-printable bytes escaped.
char *str_escape(const char *s, size_t len)
{
    static const char hex[] = "0123456789abcdef";
    char *out = xmalloc(len * 4 + 1);
    char *o = out;
    size_t i;

    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];

        switch (c) {
        case '\\': *o++ = '\\'; *o++ = '\\'; break;
        case '"':  *o++ = '\\'; *o++ = '"'; break;
        case '\n': *o++ = '\\'; *o++ = 'n'; break;
        case '\r': *o++ = '\\'; *o++ = 'r'; break;
        case '\t': *o++ = '\\'; *o++ = 't'; break;
        default:
            if (isprint(c)) {
                *o++ = (char)c;
            } else {
                *o++ = '\\';
                *o++ = 'x';
                *o++ = hex[c >> 4];
                *o++ = hex[c & 0xf];
            }
        }
    }
    *o = '\0';
    return out;
}

// Copy src into dst (capacity cap), always NUL-terminating when cap > 0.
// Returns strlen(src), so truncation happened if the result is >= cap.
size_t str_lcpy(char *dst, const char *src, size_t cap)
{
    size_t n = strlen(src);

    if (cap > 0) {
        size_t m = n < cap - 1 ? n : cap - 1;
        memcpy(dst, src, m);
        dst[m] = '\0';
    }
    return n;
}

// Human-readable byte count, e.g. "1.50M".
void fmt_bytes(char *buf, size_t cap, unsigned long long n)
{
    static const char units[] = "BKMGTP";
    double d = (double)n;
    size_t u = 0;

    while (d >= 1024.0 && u + 1 < sizeof(units) - 1) {
        d /= 1024.0;
        u++;
    }
    if (u == 0)
        snprintf(buf, cap, "%lluB", n);
    else
        snprintf(buf, cap, "%.2f%c", d, units[u]);
}

uint64_t now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

uint64_t now_us(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000 + (uint64_t)ts.tv_nsec / 1000;
}

uint64_t rng_next(uint64_t *state)
{
    uint64_t x = *state;

    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    return x * 0x2545F4914F6CDD1DULL;
}
