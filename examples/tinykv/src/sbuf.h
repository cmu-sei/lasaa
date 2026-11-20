// sbuf.h - growable byte buffer.
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
#ifndef TKV_SBUF_H
#define TKV_SBUF_H

#include <stdarg.h>
#include <stddef.h>

// The buffer is always NUL-terminated when data != NULL, but it may also
// contain embedded NULs; len is authoritative.
typedef struct sbuf {
    char *data;
    size_t len;
    size_t cap;
} sbuf;

#define SBUF_INIT { NULL, 0, 0 }

void sbuf_init(sbuf *b);
void sbuf_free(sbuf *b);
void sbuf_reset(sbuf *b);

// Each of these returns 0 on success and -1 if memory could not be grown
// (the buffer is left unchanged in that case).
int sbuf_reserve(sbuf *b, size_t extra);
int sbuf_append(sbuf *b, const void *p, size_t n);
int sbuf_append_str(sbuf *b, const char *s);
int sbuf_append_char(sbuf *b, char c);
int sbuf_appendf(sbuf *b, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
int sbuf_vappendf(sbuf *b, const char *fmt, va_list ap);

// Remove the first n bytes (n is clamped to len).
void sbuf_consume(sbuf *b, size_t n);
// Drop everything after the first n bytes.
void sbuf_truncate(sbuf *b, size_t n);
// Give the caller ownership of the data; the buffer becomes empty.
char *sbuf_detach(sbuf *b, size_t *len_out);
// Release excess capacity if the buffer is mostly empty.
void sbuf_shrink(sbuf *b);

#endif
