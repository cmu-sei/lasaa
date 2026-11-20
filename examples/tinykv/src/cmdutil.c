// cmdutil.c - argument parsing helpers shared by command handlers.
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
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "cmdutil.h"
#include "protocol.h"
#include "util.h"

int arg_is(const struct request *req, int i, const char *kw)
{
    if (i < 0 || i >= req->argc)
        return 0;
    return str_ieq(req->argv[i], req->argvlen[i], kw);
}

int arg_ll(const struct request *req, int i, long long *out)
{
    if (i < 0 || i >= req->argc)
        return -1;
    return str_to_ll(req->argv[i], req->argvlen[i], out);
}

int arg_ll_range(const struct request *req, int i, long long lo,
                 long long hi, long long *out)
{
    long long v;

    if (arg_ll(req, i, &v) != 0 || v < lo || v > hi)
        return -1;
    *out = v;
    return 0;
}

#define SET_EXPIRY_FLAGS (SET_EX | SET_PX | SET_EXAT | SET_PXAT)

int parse_set_options(const struct request *req, int first,
                      struct set_opts *o, char *err, size_t errlen)
{
    int i;

    memset(o, 0, sizeof(*o));
    for (i = first; i < req->argc; i++) {
        int has_next = i + 1 < req->argc;
        int unit_flag = 0;

        if (arg_is(req, i, "NX") && !(o->flags & SET_XX)) {
            o->flags |= SET_NX;
        } else if (arg_is(req, i, "XX") && !(o->flags & SET_NX)) {
            o->flags |= SET_XX;
        } else if (arg_is(req, i, "GET")) {
            o->flags |= SET_GET;
        } else if (arg_is(req, i, "KEEPTTL") &&
                   !(o->flags & SET_EXPIRY_FLAGS)) {
            o->flags |= SET_KEEPTTL;
        } else if (arg_is(req, i, "EX")) {
            unit_flag = SET_EX;
        } else if (arg_is(req, i, "PX")) {
            unit_flag = SET_PX;
        } else if (arg_is(req, i, "EXAT")) {
            unit_flag = SET_EXAT;
        } else if (arg_is(req, i, "PXAT")) {
            unit_flag = SET_PXAT;
        } else {
            snprintf(err, errlen, "syntax error");
            return -1;
        }

        if (unit_flag != 0) {
            long long v;

            if (!has_next ||
                (o->flags & (SET_EXPIRY_FLAGS | SET_KEEPTTL)) != 0) {
                snprintf(err, errlen, "syntax error");
                return -1;
            }
            if (arg_ll(req, i + 1, &v) != 0 || v <= 0) {
                snprintf(err, errlen, "invalid expire time in 'set' command");
                return -1;
            }
            if ((unit_flag == SET_EX || unit_flag == SET_EXAT) &&
                v > LLONG_MAX / 1000) {
                snprintf(err, errlen, "invalid expire time in 'set' command");
                return -1;
            }
            switch (unit_flag) {
            case SET_EX:   o->ttl_ms = v * 1000; break;
            case SET_PX:   o->ttl_ms = v; break;
            case SET_EXAT: o->expire_at_ms = v * 1000; break;
            case SET_PXAT: o->expire_at_ms = v; break;
            }
            o->flags |= unit_flag;
            i++;
        }
    }
    return 0;
}

int set_opts_has_expiry(const struct set_opts *o)
{
    return (o->flags & (SET_EX | SET_PX | SET_EXAT | SET_PXAT)) != 0;
}

uint64_t set_opts_expire_at(const struct set_opts *o, uint64_t now)
{
    if (o->flags & (SET_EXAT | SET_PXAT))
        return (uint64_t)o->expire_at_ms;
    if (o->flags & (SET_EX | SET_PX)) {
        if ((uint64_t)o->ttl_ms > UINT64_MAX - now)
            return UINT64_MAX;
        return now + (uint64_t)o->ttl_ms;
    }
    return 0;
}

int parse_cursor(const char *s, size_t len, unsigned long long *out)
{
    return str_to_ull(s, len, out);
}
