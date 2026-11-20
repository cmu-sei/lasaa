// protocol.h - wire protocol (RESP-style requests and replies).
//
// Requests are either arrays of bulk strings
//     *2\r\n$3\r\nGET\r\n$3\r\nfoo\r\n
// or inline commands (space-separated words ending in \n), for telnet use.
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
#ifndef TKV_PROTOCOL_H
#define TKV_PROTOCOL_H

#include <stddef.h>
#include "sbuf.h"

struct request {
    int argc;
    int cap;
    char **argv;      // each argument is NUL-terminated (and binary-safe)
    size_t *argvlen;
};

struct proto_limits {
    size_t max_inline;  // longest inline command line
    size_t max_bulk;    // longest single argument
    int max_args;
};

enum parse_result {
    PARSE_OK,
    PARSE_INCOMPLETE,
    PARSE_ERROR
};

void request_init(struct request *req);
void request_reset(struct request *req);  // free args, keep arrays
void request_free(struct request *req);
// Append an argument (copied).  Returns 0 or -1.
int request_add_arg(struct request *req, const char *p, size_t n);

// Parse one request from buf[0..len).  On PARSE_OK, *consumed is set to the
// number of bytes used.  On PARSE_ERROR a message is written to err.
int proto_parse_request(const char *buf, size_t len, struct request *req,
                        size_t *consumed, const struct proto_limits *lim,
                        char *err, size_t errlen);

// Reply encoding.
void reply_simple(sbuf *out, const char *s);
void reply_error(sbuf *out, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
void reply_int(sbuf *out, long long v);
void reply_bulk(sbuf *out, const char *p, size_t n);
void reply_bulk_str(sbuf *out, const char *s);
void reply_null(sbuf *out);
void reply_array_header(sbuf *out, long n);
void reply_ok(sbuf *out);

// Encode a request (used for the AOF and by the CLI).
void proto_encode_request(sbuf *out, int argc, char **argv,
                          const size_t *argvlen);

// Decoded reply, used by the CLI.
enum reply_type {
    RT_SIMPLE,
    RT_ERROR,
    RT_INT,
    RT_BULK,
    RT_NULL,
    RT_ARRAY
};

struct reply_val {
    int type;                 // enum reply_type
    long long ival;
    char *str;                // RT_SIMPLE, RT_ERROR, RT_BULK
    size_t len;
    struct reply_val *elems;  // RT_ARRAY
    size_t nelems;
};

// Same return convention as proto_parse_request.
int proto_parse_reply(const char *buf, size_t len, struct reply_val *out,
                      size_t *consumed, int depth);
void reply_val_free(struct reply_val *r);

#endif
