// protocol.c - request parsing and reply encoding.
//
// The parser is stateless: proto_parse_request() is called with everything
// the client has sent so far and either consumes one complete request or
// reports that more input is needed.  Requests are small in practice, so
// re-scanning a partial request on the next read is cheap, and the input
// buffer size is capped by max_request_bytes in the caller.
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
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "protocol.h"
#include "util.h"

#define REQ_INITIAL_ARGS 8
// Longest "*<count>\r\n" or "$<len>\r\n" header we are willing to wait for.
#define MAX_HEADER_LEN 32
// Limits applied when decoding replies (client side).
#define MAX_REPLY_DEPTH 32
#define MAX_REPLY_ELEMS (1L << 24)
#define MAX_REPLY_BULK (512L * 1024 * 1024)

void request_init(struct request *req)
{
    req->argc = 0;
    req->cap = 0;
    req->argv = NULL;
    req->argvlen = NULL;
}

void request_reset(struct request *req)
{
    int i;

    for (i = 0; i < req->argc; i++) {
        free(req->argv[i]);
        req->argv[i] = NULL;
    }
    req->argc = 0;
}

void request_free(struct request *req)
{
    request_reset(req);
    free(req->argv);
    free(req->argvlen);
    request_init(req);
}

static void request_reserve(struct request *req, int need)
{
    int ncap;

    if (need <= req->cap)
        return;
    ncap = req->cap ? req->cap : REQ_INITIAL_ARGS;
    while (ncap < need)
        ncap *= 2;
    req->argv = xrealloc(req->argv, (size_t)ncap * sizeof(*req->argv));
    req->argvlen = xrealloc(req->argvlen,
                            (size_t)ncap * sizeof(*req->argvlen));
    req->cap = ncap;
}

// Append an argument whose buffer is already allocated; the request takes
// ownership of it.
static void request_push_owned(struct request *req, char *arg, size_t n)
{
    request_reserve(req, req->argc + 1);
    req->argv[req->argc] = arg;
    req->argvlen[req->argc] = n;
    req->argc++;
}

int request_add_arg(struct request *req, const char *p, size_t n)
{
    request_push_owned(req, xmemdup0(p, n), n);
    return 0;
}

// Find "\r\n" in p[0..n).  Returns a pointer to the '\r', or NULL.
static const char *find_crlf(const char *p, size_t n)
{
    const char *end = p + n;

    while (p < end) {
        const char *cr = memchr(p, '\r', (size_t)(end - p));

        if (cr == NULL || cr + 1 >= end)
            return NULL;
        if (cr[1] == '\n')
            return cr;
        p = cr + 1;
    }
    return NULL;
}

// Parse the decimal length in a "*<n>" or "$<n>" header.  Only "-1" is
// accepted as a negative value (it denotes a null array or bulk string).
static int parse_len(const char *p, size_t n, long long *out)
{
    char tmp[24];
    char *end;
    long long v;

    if (n == 0 || n >= sizeof(tmp))
        return -1;
    if (p[0] != '-' && (p[0] < '0' || p[0] > '9'))
        return -1;
    memcpy(tmp, p, n);
    tmp[n] = '\0';
    errno = 0;
    v = strtoll(tmp, &end, 10);
    if (errno != 0 || *end != '\0' || v < -1)
        return -1;
    *out = v;
    return 0;
}

// Parse one "$<len>\r\n<data>\r\n" argument starting at buf[*pos] and append
// it to req.  Advances *pos past it on success.
static int parse_bulk_arg(const char *buf, size_t len, size_t *pos,
                          struct request *req,
                          const struct proto_limits *lim,
                          char *err, size_t errlen)
{
    const char *p = buf + *pos;
    size_t avail = len - *pos;
    const char *eol;
    size_t hdrlen;
    long long n;
    char *arg;

    if (avail == 0)
        return PARSE_INCOMPLETE;
    if (p[0] != '$') {
        snprintf(err, errlen, "expected '$', got '%c'",
                 (p[0] >= 32 && p[0] < 127) ? p[0] : '?');
        return PARSE_ERROR;
    }
    eol = find_crlf(p, avail);
    if (eol == NULL) {
        if (avail > MAX_HEADER_LEN) {
            snprintf(err, errlen, "bulk length header too long");
            return PARSE_ERROR;
        }
        return PARSE_INCOMPLETE;
    }
    if (parse_len(p + 1, (size_t)(eol - p - 1), &n) != 0)
        snprintf(err, errlen, "invalid bulk length");
    if (n < 0 || (unsigned long long)n > lim->max_bulk) {
        snprintf(err, errlen, "bulk length out of range");
        return PARSE_ERROR;
    }

    hdrlen = (size_t)(eol - p) + 2;
    if (avail - hdrlen < (size_t)n + 2)
        return PARSE_INCOMPLETE;

    arg = xmalloc((size_t)n + 1);
    memcpy(arg, p + hdrlen, (size_t)n);
    arg[n] = '\0';
    if (p[hdrlen + n] != '\r' || p[hdrlen + n + 1] != '\n') {
        snprintf(err, errlen, "expected CRLF after bulk data");
        return PARSE_ERROR;
    }
    request_push_owned(req, arg, (size_t)n);
    *pos += hdrlen + (size_t)n + 2;
    return PARSE_OK;
}

static int parse_multibulk(const char *buf, size_t len, struct request *req,
                           size_t *consumed, const struct proto_limits *lim,
                           char *err, size_t errlen)
{
    const char *eol = find_crlf(buf, len);
    long long count;
    size_t pos;

    if (eol == NULL) {
        if (len > MAX_HEADER_LEN) {
            snprintf(err, errlen, "multibulk header too long");
            return PARSE_ERROR;
        }
        return PARSE_INCOMPLETE;
    }
    if (parse_len(buf + 1, (size_t)(eol - buf - 1), &count) != 0) {
        snprintf(err, errlen, "invalid multibulk length");
        return PARSE_ERROR;
    }
    if (count > lim->max_args) {
        snprintf(err, errlen, "too many arguments (max %d)", lim->max_args);
        return PARSE_ERROR;
    }

    pos = (size_t)(eol - buf) + 2;
    request_reset(req);
    // "*-1" and "*0" are empty requests; the caller skips them.
    while (req->argc < count) {
        int rc = parse_bulk_arg(buf, len, &pos, req, lim, err, errlen);

        if (rc != PARSE_OK) {
            request_reset(req);
            return rc;
        }
    }
    *consumed = pos;
    return PARSE_OK;
}

static int hex_digit(char ch)
{
    if (ch >= '0' && ch <= '9')
        return ch - '0';
    if (ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F')
        return ch - 'A' + 10;
    return -1;
}

// Split an inline command line into words.  Supports "double quotes" with
// C-style escapes (\n \r \t \\ \" \xHH) and 'single quotes' (only \'
// is special).  A closing quote must be followed by a space or the end.
static int split_inline(const char *p, size_t n, struct request *req,
                        char *err, size_t errlen)
{
    const char *end = p + n;
    sbuf word = SBUF_INIT;

    for (;;) {
        while (p < end && (*p == ' ' || *p == '\t'))
            p++;
        if (p == end)
            break;

        sbuf_reset(&word);
        if (*p == '"') {
            for (p++;; p++) {
                if (p == end)
                    goto unbalanced;
                if (*p == '"') {
                    p++;
                    break;
                }
                if (*p == '\\' && p + 1 < end) {
                    int hi, lo;
                    char ch;

                    p++;
                    switch (*p) {
                    case 'n': ch = '\n'; break;
                    case 'r': ch = '\r'; break;
                    case 't': ch = '\t'; break;
                    case 'x':
                        if (p + 2 < end && (hi = hex_digit(p[1])) >= 0 &&
                            (lo = hex_digit(p[2])) >= 0) {
                            ch = (char)(hi * 16 + lo);
                            p += 2;
                        } else {
                            ch = 'x';
                        }
                        break;
                    default: ch = *p; break;
                    }
                    sbuf_append_char(&word, ch);
                } else {
                    sbuf_append_char(&word, *p);
                }
            }
        } else if (*p == '\'') {
            for (p++;; p++) {
                if (p == end)
                    goto unbalanced;
                if (*p == '\'') {
                    p++;
                    break;
                }
                if (*p == '\\' && p + 1 < end && p[1] == '\'')
                    p++;
                sbuf_append_char(&word, *p);
            }
        } else {
            while (p < end && *p != ' ' && *p != '\t')
                sbuf_append_char(&word, *p++);
        }
        if (p < end && *p != ' ' && *p != '\t')
            goto unbalanced;
        request_add_arg(req, word.data ? word.data : "", word.len);
    }
    sbuf_free(&word);
    return 0;

unbalanced:
    sbuf_free(&word);
    request_reset(req);
    snprintf(err, errlen, "unbalanced quotes in request");
    return -1;
}

static int parse_inline(const char *buf, size_t len, struct request *req,
                        size_t *consumed, const struct proto_limits *lim,
                        char *err, size_t errlen)
{
    const char *nl = memchr(buf, '\n', len);
    size_t linelen;

    if (nl == NULL) {
        if (len > lim->max_inline) {
            snprintf(err, errlen, "inline request too long");
            return PARSE_ERROR;
        }
        return PARSE_INCOMPLETE;
    }
    linelen = (size_t)(nl - buf);
    if (linelen > lim->max_inline) {
        snprintf(err, errlen, "inline request too long");
        return PARSE_ERROR;
    }

    request_reset(req);
    if (split_inline(buf, (linelen > 0 && buf[linelen - 1] == '\r') ?
                     linelen - 1 : linelen, req, err, errlen) != 0)
        return PARSE_ERROR;
    if (req->argc > lim->max_args) {
        request_reset(req);
        snprintf(err, errlen, "too many arguments (max %d)", lim->max_args);
        return PARSE_ERROR;
    }
    *consumed = linelen + 1;
    return PARSE_OK;
}

int proto_parse_request(const char *buf, size_t len, struct request *req,
                        size_t *consumed, const struct proto_limits *lim,
                        char *err, size_t errlen)
{
    if (len == 0)
        return PARSE_INCOMPLETE;
    if (buf[0] == '*')
        return parse_multibulk(buf, len, req, consumed, lim, err, errlen);
    return parse_inline(buf, len, req, consumed, lim, err, errlen);
}

// ---------------------------------------------------------------------
// Reply encoding

// Simple strings and errors may not contain CR or LF.
static void append_line_safe(sbuf *out, const char *s, size_t n)
{
    size_t i, start = out->len;

    if (sbuf_append(out, s, n) != 0)
        return;
    for (i = start; i < out->len; i++) {
        if (out->data[i] == '\r' || out->data[i] == '\n')
            out->data[i] = ' ';
    }
}

void reply_simple(sbuf *out, const char *s)
{
    sbuf_append_char(out, '+');
    append_line_safe(out, s, strlen(s));
    sbuf_append(out, "\r\n", 2);
}

// The message should start with an error code such as "ERR" or
// "WRONGTYPE".
void reply_error(sbuf *out, const char *fmt, ...)
{
    char msg[512];
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    if (n < 0)
        n = 0;
    if ((size_t)n >= sizeof(msg))
        n = sizeof(msg) - 1;

    sbuf_append_char(out, '-');
    append_line_safe(out, msg, (size_t)n);
    sbuf_append(out, "\r\n", 2);
}

void reply_int(sbuf *out, long long v)
{
    sbuf_appendf(out, ":%lld\r\n", v);
}

void reply_bulk(sbuf *out, const char *p, size_t n)
{
    sbuf_appendf(out, "$%zu\r\n", n);
    sbuf_append(out, p, n);
    sbuf_append(out, "\r\n", 2);
}

void reply_bulk_str(sbuf *out, const char *s)
{
    reply_bulk(out, s, strlen(s));
}

void reply_null(sbuf *out)
{
    sbuf_append(out, "$-1\r\n", 5);
}

void reply_array_header(sbuf *out, long n)
{
    sbuf_appendf(out, "*%ld\r\n", n);
}

void reply_ok(sbuf *out)
{
    sbuf_append(out, "+OK\r\n", 5);
}

void proto_encode_request(sbuf *out, int argc, char **argv,
                          const size_t *argvlen)
{
    int i;

    reply_array_header(out, argc);
    for (i = 0; i < argc; i++)
        reply_bulk(out, argv[i], argvlen[i]);
}

// ---------------------------------------------------------------------
// Reply decoding (client side)

void reply_val_free(struct reply_val *r)
{
    size_t i;

    if (r == NULL)
        return;
    free(r->str);
    for (i = 0; i < r->nelems; i++)
        reply_val_free(&r->elems[i]);
    free(r->elems);
    memset(r, 0, sizeof(*r));
}

// Parse a signed decimal integer in p[0..n): the value of a ':' reply or
// the length in a '$' or '*' header.
static int parse_reply_num(const char *p, size_t n, long long *out)
{
    return str_to_ll(p, n, out);
}

int proto_parse_reply(const char *buf, size_t len, struct reply_val *out,
                      size_t *consumed, int depth)
{
    const char *eol;
    size_t hdrlen;
    long long n;

    memset(out, 0, sizeof(*out));
    if (len == 0)
        return PARSE_INCOMPLETE;
    if (depth > MAX_REPLY_DEPTH)
        return PARSE_ERROR;
    eol = find_crlf(buf, len);
    if (eol == NULL)
        return PARSE_INCOMPLETE;
    hdrlen = (size_t)(eol - buf) + 2;

    switch (buf[0]) {
    case '+':
    case '-':
        out->type = buf[0] == '+' ? RT_SIMPLE : RT_ERROR;
        out->len = hdrlen - 3;
        out->str = xmemdup0(buf + 1, out->len);
        *consumed = hdrlen;
        return PARSE_OK;

    case ':':
        if (parse_reply_num(buf + 1, hdrlen - 3, &out->ival) != 0)
            return PARSE_ERROR;
        out->type = RT_INT;
        *consumed = hdrlen;
        return PARSE_OK;

    case '$':
        if (parse_reply_num(buf + 1, hdrlen - 3, &n) != 0 || n < -1 ||
            n > MAX_REPLY_BULK)
            return PARSE_ERROR;
        if (n < 0) {
            out->type = RT_NULL;
            *consumed = hdrlen;
            return PARSE_OK;
        }
        if (len - hdrlen < (size_t)n + 2)
            return PARSE_INCOMPLETE;
        if (buf[hdrlen + n] != '\r' || buf[hdrlen + n + 1] != '\n')
            return PARSE_ERROR;
        out->type = RT_BULK;
        out->len = (size_t)n;
        out->str = xmemdup0(buf + hdrlen, (size_t)n);
        *consumed = hdrlen + (size_t)n + 2;
        return PARSE_OK;

    case '*': {
        size_t pos = hdrlen;
        size_t i;

        if (parse_reply_num(buf + 1, hdrlen - 3, &n) != 0 || n < -1 ||
            n > MAX_REPLY_ELEMS)
            return PARSE_ERROR;
        if (n < 0) {
            out->type = RT_NULL;
            *consumed = hdrlen;
            return PARSE_OK;
        }
        // Every element takes at least 3 bytes; don't allocate for elements
        // that cannot have arrived yet.
        if ((size_t)n > (len - hdrlen) / 3)
            return PARSE_INCOMPLETE;

        out->type = RT_ARRAY;
        out->elems = xcalloc((size_t)n, sizeof(*out->elems));
        out->nelems = (size_t)n;
        for (i = 0; i < (size_t)n; i++) {
            size_t used = 0;
            int rc = proto_parse_reply(buf + pos, len - pos, &out->elems[i],
                                       &used, depth + 1);

            if (rc != PARSE_OK) {
                reply_val_free(out);
                return rc;
            }
            pos += used;
        }
        *consumed = pos;
        return PARSE_OK;
    }

    default:
        return PARSE_ERROR;
    }
}
