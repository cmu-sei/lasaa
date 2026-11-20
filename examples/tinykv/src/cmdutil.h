// cmdutil.h - argument parsing helpers shared by command handlers.
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
#ifndef TKV_CMDUTIL_H
#define TKV_CMDUTIL_H

#include <stddef.h>
#include <stdint.h>

struct request;

// Case-insensitive comparison of argument i with a keyword.
int arg_is(const struct request *req, int i, const char *kw);
// Parse argument i as a signed integer.  Returns 0, or -1 if not a number.
int arg_ll(const struct request *req, int i, long long *out);
// Parse argument i as an integer in [lo, hi].
int arg_ll_range(const struct request *req, int i, long long lo,
                 long long hi, long long *out);

// Options of SET key value [EX s | PX ms | EXAT ts | PXAT ts]
// [NX | XX] [KEEPTTL] [GET].
enum set_flags {
    SET_NX = 1 << 0,
    SET_XX = 1 << 1,
    SET_EX = 1 << 2,
    SET_PX = 1 << 3,
    SET_EXAT = 1 << 4,
    SET_PXAT = 1 << 5,
    SET_KEEPTTL = 1 << 6,
    SET_GET = 1 << 7
};

struct set_opts {
    int flags;
    long long ttl_ms;       // relative, for EX/PX
    long long expire_at_ms; // absolute, for EXAT/PXAT
};

// Parse options starting at argument `first`.  Returns 0, or -1 with a
// message in err.
int parse_set_options(const struct request *req, int first,
                      struct set_opts *o, char *err, size_t errlen);
// Nonzero if the options specify an expiry time.
int set_opts_has_expiry(const struct set_opts *o);
// Absolute expiry time in ms for options that have one.
uint64_t set_opts_expire_at(const struct set_opts *o, uint64_t now);

// SCAN-style cursor helpers: encode/decode a cursor string.
int parse_cursor(const char *s, size_t len, unsigned long long *out);

#endif
