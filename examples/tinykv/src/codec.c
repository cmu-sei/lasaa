// codec.c - CRC32, base64, varints, and glob matching.
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
#include "codec.h"

#include <ctype.h>
#include <string.h>

// ---- CRC32 (IEEE 802.3, reflected, polynomial 0xEDB88320) ----

static uint32_t crc_table[256];
static int crc_table_ready;

static void crc32_init_table(void)
{
    uint32_t i, j, c;

    for (i = 0; i < 256; i++) {
        c = i;
        for (j = 0; j < 8; j++)
            c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
        crc_table[i] = c;
    }
    crc_table_ready = 1;
}

uint32_t crc32_update(uint32_t crc, const void *p, size_t n)
{
    const uint8_t *b = p;
    size_t i;

    if (!crc_table_ready)
        crc32_init_table();
    crc = ~crc;
    for (i = 0; i < n; i++)
        crc = crc_table[(crc ^ b[i]) & 0xff] ^ (crc >> 8);
    return ~crc;
}

uint32_t crc32_buf(const void *p, size_t n)
{
    return crc32_update(0, p, n);
}

// ---- Base64 (RFC 4648, with padding) ----

static const char b64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t base64_encoded_len(size_t n)
{
    return (n + 2) / 3 * 4;
}

size_t base64_encode(const unsigned char *src, size_t n, char *dst)
{
    size_t i, o = 0;

    for (i = 0; i + 2 < n; i += 3) {
        uint32_t v = (uint32_t)src[i] << 16 | (uint32_t)src[i + 1] << 8 |
                     src[i + 2];

        dst[o++] = b64_chars[(v >> 18) & 0x3f];
        dst[o++] = b64_chars[(v >> 12) & 0x3f];
        dst[o++] = b64_chars[(v >> 6) & 0x3f];
        dst[o++] = b64_chars[v & 0x3f];
    }

    if (i < n) {
        uint32_t v = (uint32_t)src[i] << 16;

        if (i + 1 < n)
            v |= (uint32_t)src[i + 1] << 8;
        dst[o++] = b64_chars[(v >> 18) & 0x3f];
        dst[o++] = b64_chars[(v >> 12) & 0x3f];
        dst[o++] = (i + 1 < n) ? b64_chars[(v >> 6) & 0x3f] : '=';
        dst[o++] = '=';
    }
    dst[o] = '\0';
    return o;
}

static int b64_value(unsigned char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}

long base64_decode(const char *src, size_t n, unsigned char *dst)
{
    size_t i, o = 0;

    if (n % 4 != 0)
        return -1;

    for (i = 0; i < n; i += 4) {
        int a = b64_value((unsigned char)src[i]);
        int b = b64_value((unsigned char)src[i + 1]);
        int c, d;
        int last = (i + 4 == n);

        if (a < 0 || b < 0)
            return -1;

        // Padding is only allowed in the final quantum.
        if (last && src[i + 2] == '=') {
            if (src[i + 3] != '=')
                return -1;
            dst[o++] = (unsigned char)(a << 2 | b >> 4);
            break;
        }
        c = b64_value((unsigned char)src[i + 2]);
        if (c < 0)
            return -1;
        if (last && src[i + 3] == '=') {
            dst[o++] = (unsigned char)(a << 2 | b >> 4);
            dst[o++] = (unsigned char)((b & 0xf) << 4 | c >> 2);
            break;
        }
        d = b64_value((unsigned char)src[i + 3]);
        if (d < 0)
            return -1;

        dst[o++] = (unsigned char)(a << 2 | b >> 4);
        dst[o++] = (unsigned char)((b & 0xf) << 4 | c >> 2);
        dst[o++] = (unsigned char)((c & 0x3) << 6 | d);
    }
    return (long)o;
}

// ---- Varints (unsigned LEB128) ----

size_t varint_put(uint8_t *p, uint64_t v)
{
    size_t n = 0;

    while (v >= 0x80) {
        p[n++] = (uint8_t)(v | 0x80);
        v >>= 7;
    }
    p[n++] = (uint8_t)v;
    return n;
}

size_t varint_get(const uint8_t *p, size_t n, uint64_t *v)
{
    uint64_t result = 0;
    unsigned shift = 0;
    size_t i;

    for (i = 0; i < n && i < 10; i++) {
        uint64_t byte = p[i];

        // The tenth byte may only contribute the top bit of a 64-bit value.
        if (i == 9 && byte > 1)
            return 0;
        result |= (byte & 0x7f) << shift;
        if ((byte & 0x80) == 0) {
            *v = result;
            return i + 1;
        }
        shift += 7;
    }
    return 0;
}

// ---- Glob matching ----

static int fold(int c, int nocase)
{
    return nocase ? tolower(c) : c;
}

// Match a [...] class starting just after the '['.  On return *used is
// the number of pattern bytes consumed, including the closing ']'.
static int match_class(const char *pat, size_t plen, unsigned char c,
                       int nocase, size_t *used)
{
    size_t i = 0;
    int negate = 0, matched = 0;

    if (i < plen && pat[i] == '^') {
        negate = 1;
        i++;
    }
    while (i < plen && pat[i] != ']') {
        if (pat[i] == '\\' && i + 1 < plen) {
            i++;
            if (fold((unsigned char)pat[i], nocase) == fold(c, nocase))
                matched = 1;
            i++;
        } else if (i + 2 < plen && pat[i + 1] == '-' && pat[i + 2] != ']') {
            int lo = fold((unsigned char)pat[i], nocase);
            int hi = fold((unsigned char)pat[i + 2], nocase);
            int x = fold(c, nocase);

            if (lo > hi) {
                int t = lo;
                lo = hi;
                hi = t;
            }
            if (x >= lo && x <= hi)
                matched = 1;
            i += 3;
        } else {
            if (fold((unsigned char)pat[i], nocase) == fold(c, nocase))
                matched = 1;
            i++;
        }
    }
    // An unterminated class matches as if it were closed at the end.
    *used = i < plen ? i + 1 : i;
    return negate ? !matched : matched;
}

int glob_match(const char *pat, size_t plen, const char *s, size_t slen,
               int nocase)
{
    while (plen > 0) {
        switch (pat[0]) {
        case '*':
            while (plen > 1 && pat[1] == '*') {
                pat++;
                plen--;
            }
            if (plen == 1)
                return 1;
            for (;;) {
                if (glob_match(pat + 1, plen - 1, s, slen, nocase))
                    return 1;
                if (slen == 0)
                    return 0;
                s++;
                slen--;
            }

        case '?':
            if (slen == 0)
                return 0;
            s++;
            slen--;
            break;

        case '[': {
            size_t used;

            if (slen == 0)
                return 0;
            if (!match_class(pat + 1, plen - 1, (unsigned char)s[0], nocase,
                             &used))
                return 0;
            pat += used;
            plen -= used;
            s++;
            slen--;
            break;
        }

        case '\\':
            if (plen >= 2) {
                pat++;
                plen--;
            }
            /* fall through */
        default:
            if (slen == 0 ||
                fold((unsigned char)pat[0], nocase) !=
                    fold((unsigned char)s[0], nocase))
                return 0;
            s++;
            slen--;
            break;
        }
        pat++;
        plen--;
    }
    return slen == 0;
}
