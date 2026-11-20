// codec.h - CRC32, base64, varints, and glob matching.
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
#ifndef TKV_CODEC_H
#define TKV_CODEC_H

#include <stddef.h>
#include <stdint.h>

uint32_t crc32_update(uint32_t crc, const void *p, size_t n);
uint32_t crc32_buf(const void *p, size_t n);

// Encoded length (without NUL) for n input bytes.
size_t base64_encoded_len(size_t n);
// Writes base64 of src to dst (which must hold base64_encoded_len(n) + 1
// bytes) and NUL-terminates it.  Returns the encoded length.
size_t base64_encode(const unsigned char *src, size_t n, char *dst);
// Decodes src into dst (which must hold at least 3 * (n / 4) bytes).
// Returns the decoded length, or -1 if src is not valid base64.
long base64_decode(const char *src, size_t n, unsigned char *dst);

// Unsigned LEB128.  varint_put writes at most 10 bytes and returns the
// count.  varint_get returns bytes consumed, or 0 if p[0..n) is truncated
// or the value is too large.
size_t varint_put(uint8_t *p, uint64_t v);
size_t varint_get(const uint8_t *p, size_t n, uint64_t *v);

// Glob-style match supporting *, ?, [abc], [a-z], [^x], and \ escapes.
int glob_match(const char *pat, size_t plen, const char *s, size_t slen,
               int nocase);

#endif
