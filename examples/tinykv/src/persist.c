// persist.c - snapshot files, DUMP/RESTORE serialization, and the AOF.
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
#include "persist.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "codec.h"
#include "config.h"
#include "log.h"
#include "protocol.h"
#include "store.h"
#include "util.h"
#include "vlist.h"

// Upper bound on a single key or value read from a snapshot, so that a
// corrupt length can't make us allocate absurd amounts of memory.
#define SNAP_MAX_BLOB (512u * 1024 * 1024)
#define SNAP_MAX_LIST_ITEMS (64u * 1024 * 1024)

#define DUMP_VERSION 1

struct snap_header {
    char magic[8];
    uint32_t version;
    uint64_t created_ms;
};

/* ------------------------------------------------------------------------
 * Little-endian helpers
 * ------------------------------------------------------------------------ */

static void put_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static void put_u32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

static void put_u64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

static uint16_t get_u16(const uint8_t *p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}

static uint32_t get_u32(const uint8_t *p)
{
    uint32_t v = 0;
    for (int i = 3; i >= 0; i--)
        v = (v << 8) | p[i];
    return v;
}

static uint64_t get_u64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--)
        v = (v << 8) | p[i];
    return v;
}

/* ------------------------------------------------------------------------
 * Writing
 * ------------------------------------------------------------------------ */

struct snap_writer {
    FILE *fp;
    uint32_t crc;
    uint64_t bytes;
    int error;          // errno of the first failed write, or 0
    size_t nkeys;
};

static int snap_write(struct snap_writer *w, const void *p, size_t n)
{
    if (w->error)
        return -1;
    if (n == 0)
        return 0;
    if (fwrite(p, 1, n, w->fp) != n) {
        w->error = errno ? errno : EIO;
        return -1;
    }
    w->crc = crc32_update(w->crc, p, n);
    w->bytes += n;
    return 0;
}

static int snap_write_u8(struct snap_writer *w, uint8_t v)
{
    return snap_write(w, &v, 1);
}

static int snap_write_u64(struct snap_writer *w, uint64_t v)
{
    uint8_t buf[8];

    put_u64(buf, v);
    return snap_write(w, buf, sizeof(buf));
}

static int snap_write_varint(struct snap_writer *w, uint64_t v)
{
    uint8_t buf[10];
    size_t n = varint_put(buf, v);

    return snap_write(w, buf, n);
}

static int snap_write_blob(struct snap_writer *w, const char *p, size_t n)
{
    if (snap_write_varint(w, n) < 0)
        return -1;
    return snap_write(w, p, n);
}

static int write_header(struct snap_writer *w, const struct snap_header *h)
{
    uint8_t buf[12];

    if (snap_write(w, h->magic, sizeof(h->magic)) < 0)
        return -1;
    put_u32(buf, h->version);
    put_u64(buf + 4, h->created_ms);
    return snap_write(w, buf, sizeof(buf));
}

static int write_value(struct snap_writer *w, const struct entry *e)
{
    if (e->type == VT_STRING)
        return snap_write_blob(w, e->v.str.ptr, e->v.str.len);

    struct vlist *l = e->v.list;
    size_t n = vlist_len(l);

    if (snap_write_varint(w, n) < 0)
        return -1;
    for (size_t i = 0; i < n; i++) {
        struct vlist_item *it = vlist_at(l, (long)i);
        if (it == NULL)
            return -1;
        if (snap_write_blob(w, it->ptr, it->len) < 0)
            return -1;
    }
    return 0;
}

static int write_entry_cb(struct entry *e, void *arg)
{
    struct snap_writer *w = arg;
    uint8_t type = e->type == VT_LIST ? REC_LIST : REC_STRING;

    if (e->expire_at != 0)
        type |= REC_FLAG_TTL;
    if (snap_write_u8(w, type) < 0 ||
        snap_write_blob(w, e->key, e->keylen) < 0)
        return -1;
    if (e->expire_at != 0 && snap_write_u64(w, e->expire_at) < 0)
        return -1;
    if (write_value(w, e) < 0)
        return -1;
    w->nkeys++;
    return 0;
}

int snapshot_save(struct store *s, const char *path, char *err,
                  size_t errlen)
{
    struct snap_writer w;
    struct snap_header h;
    char *tmp;
    size_t tmplen;
    uint8_t crcbuf[4];
    uint64_t start = now_ms();

    tmplen = strlen(path) + 32;
    tmp = xmalloc(tmplen);
    snprintf(tmp, tmplen, "%s.tmp-%ld", path, (long)getpid());

    memset(&w, 0, sizeof(w));
    w.fp = fopen(tmp, "wb");
    if (w.fp == NULL) {
        snprintf(err, errlen, "open %s: %s", tmp, strerror(errno));
        free(tmp);
        return -1;
    }

    memset(&h, 0, sizeof(h));
    memcpy(h.magic, SNAP_MAGIC, sizeof(SNAP_MAGIC));
    h.version = SNAP_VERSION;
    h.created_ms = start;
    if (write_header(&w, &h) < 0) {
        snprintf(err, errlen, "write %s: %s", tmp, strerror(w.error));
        unlink(tmp);
        free(tmp);
        return -1;
    }

    if (store_foreach(s, write_entry_cb, &w) != 0 || w.error) {
        snprintf(err, errlen, "write %s: %s", tmp,
                 strerror(w.error ? w.error : EIO));
        goto fail;
    }

    if (snap_write_u8(&w, REC_EOF) < 0)
        goto fail_io;
    put_u32(crcbuf, w.crc);
    if (fwrite(crcbuf, 1, sizeof(crcbuf), w.fp) != sizeof(crcbuf))
        goto fail_io;
    if (fflush(w.fp) != 0 || fsync(fileno(w.fp)) != 0)
        goto fail_io;
    if (fclose(w.fp) != 0) {
        w.fp = NULL;
        goto fail_io;
    }
    w.fp = NULL;

    if (rename(tmp, path) != 0) {
        snprintf(err, errlen, "rename %s -> %s: %s", tmp, path,
                 strerror(errno));
        goto fail;
    }
    log_info("snapshot saved to %s: %zu keys, %llu bytes in %llu ms", path,
             w.nkeys, (unsigned long long)w.bytes + sizeof(crcbuf),
             (unsigned long long)(now_ms() - start));
    free(tmp);
    return 0;

fail_io:
    snprintf(err, errlen, "write %s: %s", tmp, strerror(errno ? errno : EIO));
fail:
    if (w.fp != NULL)
        fclose(w.fp);
    unlink(tmp);
    free(tmp);
    return -1;
}

/* ------------------------------------------------------------------------
 * Reading
 * ------------------------------------------------------------------------ */

struct snap_reader {
    FILE *fp;
    uint32_t crc;
    uint64_t offset;
};

static int read_exact(struct snap_reader *r, void *buf, size_t n)
{
    if (n == 0)
        return 0;
    if (fread(buf, 1, n, r->fp) != n)
        return -1;
    r->crc = crc32_update(r->crc, buf, n);
    r->offset += n;
    return 0;
}

static int read_u8(struct snap_reader *r, uint8_t *v)
{
    return read_exact(r, v, 1);
}

static int read_u64(struct snap_reader *r, uint64_t *v)
{
    uint8_t buf[8];

    if (read_exact(r, buf, sizeof(buf)) < 0)
        return -1;
    *v = get_u64(buf);
    return 0;
}

static int read_varint(struct snap_reader *r, uint64_t *v)
{
    uint8_t buf[10];
    size_t i;

    for (i = 0; i < sizeof(buf); i++) {
        if (read_u8(r, &buf[i]) < 0)
            return -1;
        if ((buf[i] & 0x80) == 0)
            break;
    }
    if (i == sizeof(buf))
        return -1;
    return varint_get(buf, i + 1, v) == i + 1 ? 0 : -1;
}

// Read a length-prefixed byte string into a newly allocated, NUL-terminated
// buffer.
static int read_blob(struct snap_reader *r, char **out, size_t *outlen)
{
    uint64_t n;
    char *buf;

    if (read_varint(r, &n) < 0)
        return -1;
    if (n > SNAP_MAX_BLOB)
        return -1;
    buf = malloc((size_t)n + 1);
    if (buf == NULL)
        return -1;
    if (fread(buf, 1, (size_t)n, r->fp) != (size_t)n)
        return -1;
    r->crc = crc32_update(r->crc, buf, (size_t)n);
    r->offset += n;
    buf[n] = '\0';
    *out = buf;
    *outlen = (size_t)n;
    return 0;
}

static int load_list(struct snap_reader *r, struct store *s, const char *key,
                     size_t keylen, uint64_t expire_at)
{
    uint64_t count;
    struct entry *e;
    int serr = 0;

    if (read_varint(r, &count) < 0 || count > SNAP_MAX_LIST_ITEMS)
        return -1;

    store_delete(s, key, keylen);
    e = store_get_or_create_list(s, key, keylen, &serr);
    if (e == NULL)
        return -1;

    for (uint64_t i = 0; i < count; i++) {
        char *item;
        size_t itemlen;
        size_t before = vlist_mem_usage(e->v.list);

        if (read_blob(r, &item, &itemlen) < 0)
            return -1;
        if (vlist_push(e->v.list, 0, item, itemlen) < 0) {
            free(item);
            return -1;
        }
        free(item);
        store_account(s, (ssize_t)(vlist_mem_usage(e->v.list) - before));
    }
    if (count == 0) {
        // An empty list is never stored; drop the placeholder.
        store_delete(s, key, keylen);
        return 0;
    }
    if (expire_at != 0)
        store_set_expire(s, e, expire_at);
    return 0;
}

int snapshot_load(struct store *s, const char *path, char *err,
                  size_t errlen)
{
    struct snap_reader r;
    uint8_t hdr[20];
    uint8_t crcbuf[4];
    uint64_t now = now_ms();
    size_t loaded = 0, skipped = 0;
    char *key = NULL;
    size_t keylen = 0;

    memset(&r, 0, sizeof(r));
    r.fp = fopen(path, "rb");
    if (r.fp == NULL) {
        if (errno == ENOENT)
            return 0;
        snprintf(err, errlen, "open %s: %s", path, strerror(errno));
        return -1;
    }

    if (read_exact(&r, hdr, sizeof(hdr)) < 0) {
        snprintf(err, errlen, "%s: truncated header", path);
        goto fail;
    }
    if (memcmp(hdr, SNAP_MAGIC, 8) != 0) {
        snprintf(err, errlen, "%s: not a tinykv snapshot", path);
        goto fail;
    }
    if (get_u32(hdr + 8) > SNAP_VERSION) {
        snprintf(err, errlen, "%s: unsupported snapshot version %u", path,
                 (unsigned)get_u32(hdr + 8));
        goto fail;
    }

    for (;;) {
        uint8_t type;
        uint64_t expire_at = 0;

        if (read_u8(&r, &type) < 0)
            goto truncated;
        if (type == REC_EOF)
            break;
        if (read_blob(&r, &key, &keylen) < 0)
            goto truncated;
        if ((type & REC_FLAG_TTL) && read_u64(&r, &expire_at) < 0)
            goto truncated;

        switch (type & ~REC_FLAG_TTL) {
        case REC_STRING: {
            char *val;
            size_t vlen;
            if (read_blob(&r, &val, &vlen) < 0)
                goto truncated;
            if (expire_at != 0 && expire_at <= now) {
                skipped++;
            } else if (store_set_string(s, key, keylen, val, vlen,
                                        expire_at) != STORE_OK) {
                free(val);
                snprintf(err, errlen, "%s: out of memory loading key", path);
                goto fail;
            } else {
                loaded++;
            }
            free(val);
            break;
        }
        case REC_LIST:
            if (load_list(&r, s, key, keylen, expire_at) < 0)
                goto truncated;
            if (expire_at != 0 && expire_at <= now) {
                store_delete(s, key, keylen);
                skipped++;
            } else {
                loaded++;
            }
            break;
        default:
            snprintf(err, errlen, "%s: unknown record type 0x%02x at offset %llu",
                     path, type, (unsigned long long)r.offset);
            goto fail;
        }
        free(key);
        key = NULL;
    }

    if (fread(crcbuf, 1, sizeof(crcbuf), r.fp) != sizeof(crcbuf))
        goto truncated;
    if (get_u32(crcbuf) != r.crc) {
        snprintf(err, errlen, "%s: checksum mismatch", path);
        goto fail;
    }
    fclose(r.fp);
    log_info("loaded %zu keys from %s (%zu expired)", loaded, path, skipped);
    return 0;

truncated:
    snprintf(err, errlen, "%s: truncated or corrupt at offset %llu", path,
             (unsigned long long)r.offset);
fail:
    free(key);
    fclose(r.fp);
    return -1;
}

/* ------------------------------------------------------------------------
 * DUMP / RESTORE
 * ------------------------------------------------------------------------ */

static void sbuf_put_varint(sbuf *out, uint64_t v)
{
    uint8_t buf[10];
    size_t n = varint_put(buf, v);

    sbuf_append(out, buf, n);
}

static void sbuf_put_blob(sbuf *out, const char *p, size_t n)
{
    sbuf_put_varint(out, n);
    sbuf_append(out, p, n);
}

int entry_dump(const struct entry *e, sbuf *out)
{
    size_t start = out->len;
    uint8_t trailer[6];
    uint32_t crc;

    if (e->type == VT_STRING) {
        sbuf_append_char(out, (char)REC_STRING);
        sbuf_put_blob(out, e->v.str.ptr, e->v.str.len);
    } else {
        struct vlist *l = e->v.list;
        size_t n = vlist_len(l);

        sbuf_append_char(out, (char)REC_LIST);
        sbuf_put_varint(out, n);
        for (size_t i = 0; i < n; i++) {
            struct vlist_item *it = vlist_at(l, (long)i);
            if (it == NULL)
                return -1;
            sbuf_put_blob(out, it->ptr, it->len);
        }
    }

    put_u16(trailer, DUMP_VERSION);
    sbuf_append(out, trailer, 2);
    crc = crc32_buf(out->data + start, out->len - start);
    put_u32(trailer + 2, crc);
    return sbuf_append(out, trailer + 2, 4);
}

// Bounds-checked cursor over a DUMP payload.
struct cursor {
    const uint8_t *p;
    size_t left;
};

static int cur_varint(struct cursor *c, uint64_t *v)
{
    size_t n = varint_get(c->p, c->left, v);

    if (n == 0)
        return -1;
    c->p += n;
    c->left -= n;
    return 0;
}

static int cur_blob(struct cursor *c, const char **p, size_t *len)
{
    uint64_t n;

    if (cur_varint(c, &n) < 0 || n > c->left)
        return -1;
    *p = (const char *)c->p;
    *len = (size_t)n;
    c->p += n;
    c->left -= (size_t)n;
    return 0;
}

// Check that a DUMP list payload is well formed before touching the store.
static int validate_list(struct cursor c, uint64_t *count)
{
    if (cur_varint(&c, count) < 0)
        return -1;
    for (uint64_t i = 0; i < *count; i++) {
        const char *p;
        size_t n;
        if (cur_blob(&c, &p, &n) < 0)
            return -1;
    }
    return c.left == 0 ? 0 : -1;
}

int entry_restore(struct store *s, const char *key, size_t keylen,
                  const char *buf, size_t len, uint64_t expire_at,
                  char *err, size_t errlen)
{
    const uint8_t *ubuf = (const uint8_t *)buf;
    struct cursor c;
    uint64_t count;
    uint8_t type;

    if (len < 1 + 6) {
        snprintf(err, errlen, "DUMP payload version or checksum are wrong");
        return -1;
    }
    if (crc32_buf(buf, len - 4) != get_u32(ubuf + len - 4) ||
        get_u16(ubuf + len - 6) > DUMP_VERSION) {
        snprintf(err, errlen, "DUMP payload version or checksum are wrong");
        return -1;
    }

    type = ubuf[0];
    c.p = ubuf + 1;
    c.left = len - 1 - 6;

    if (type == REC_STRING) {
        const char *p;
        size_t n;
        if (cur_blob(&c, &p, &n) < 0 || c.left != 0) {
            snprintf(err, errlen, "Bad data format");
            return -1;
        }
        if (store_set_string(s, key, keylen, p, n, expire_at) != STORE_OK) {
            snprintf(err, errlen, "OOM command not allowed when used memory > 'maxmemory'");
            return -1;
        }
        return 0;
    }

    if (type != REC_LIST || validate_list(c, &count) < 0 || count == 0) {
        snprintf(err, errlen, "Bad data format");
        return -1;
    }

    int serr = 0;
    struct entry *e;

    store_delete(s, key, keylen);
    e = store_get_or_create_list(s, key, keylen, &serr);
    if (e == NULL) {
        snprintf(err, errlen, "OOM command not allowed when used memory > 'maxmemory'");
        return -1;
    }
    cur_varint(&c, &count);
    for (uint64_t i = 0; i < count; i++) {
        const char *p;
        size_t n;
        size_t before = vlist_mem_usage(e->v.list);

        cur_blob(&c, &p, &n);
        if (vlist_push(e->v.list, 0, p, n) < 0) {
            store_delete(s, key, keylen);
            snprintf(err, errlen, "out of memory");
            return -1;
        }
        store_account(s, (ssize_t)(vlist_mem_usage(e->v.list) - before));
    }
    if (expire_at != 0)
        store_set_expire(s, e, expire_at);
    return 0;
}

/* ------------------------------------------------------------------------
 * Append-only file
 * ------------------------------------------------------------------------ */

struct aof *aof_open(const char *path, int fsync_mode, char *err,
                     size_t errlen)
{
    struct aof *a;
    struct stat st;
    FILE *fp;

    fp = fopen(path, "ab");
    if (fp == NULL) {
        snprintf(err, errlen, "open %s: %s", path, strerror(errno));
        return NULL;
    }

    a = xcalloc(1, sizeof(*a));
    a->fp = fp;
    a->path = xstrdup(path);
    a->fsync_mode = fsync_mode;
    a->last_fsync_ms = now_ms();
    sbuf_init(&a->pending);
    if (fstat(fileno(fp), &st) == 0)
        a->size = (uint64_t)st.st_size;
    return a;
}

void aof_close(struct aof *a)
{
    if (a == NULL)
        return;
    if (a->pending.len > 0 && aof_flush(a, now_ms()) < 0)
        log_error("AOF: lost %zu bytes of pending writes on close",
                  a->pending.len);
    if (a->fp != NULL) {
        fflush(a->fp);
        fsync(fileno(a->fp));
        fclose(a->fp);
    }
    sbuf_free(&a->pending);
    free(a->path);
    free(a);
}

void aof_append(struct aof *a, int argc, char **argv, const size_t *argvlen)
{
    proto_encode_request(&a->pending, argc, argv, argvlen);
}

int aof_flush(struct aof *a, uint64_t now)
{
    if (a->pending.len > 0) {
        size_t n = fwrite(a->pending.data, 1, a->pending.len, a->fp);
        if (n != a->pending.len) {
            log_error("AOF: write to %s failed: %s", a->path, strerror(errno));
            // Keep what wasn't written; it will be retried.
            sbuf_consume(&a->pending, n);
            a->size += n;
            return -1;
        }
        a->size += n;
        sbuf_reset(&a->pending);
        if (fflush(a->fp) != 0) {
            log_error("AOF: flush of %s failed: %s", a->path, strerror(errno));
            return -1;
        }
    }

    if (a->fsync_mode == AOF_FSYNC_ALWAYS ||
        (a->fsync_mode == AOF_FSYNC_EVERYSEC &&
         now - a->last_fsync_ms >= 1000)) {
        if (fsync(fileno(a->fp)) != 0) {
            log_error("AOF: fsync of %s failed: %s", a->path, strerror(errno));
            return -1;
        }
        a->last_fsync_ms = now;
    }
    return 0;
}

long aof_replay(const char *path, int (*apply)(void *ctx, struct request *req),
                void *ctx, char *err, size_t errlen)
{
    struct proto_limits lim = { 64 * 1024, SNAP_MAX_BLOB, 1024 * 1024 };
    struct request req;
    sbuf data = SBUF_INIT;
    char buf[65536];
    char perr[128];
    size_t pos = 0, n;
    long count = 0;
    FILE *fp;

    fp = fopen(path, "rb");
    if (fp == NULL) {
        if (errno == ENOENT)
            return 0;
        snprintf(err, errlen, "open %s: %s", path, strerror(errno));
        return -1;
    }
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        if (sbuf_append(&data, buf, n) < 0) {
            snprintf(err, errlen, "%s: out of memory", path);
            fclose(fp);
            sbuf_free(&data);
            return -1;
        }
    }
    if (ferror(fp)) {
        snprintf(err, errlen, "read %s: %s", path, strerror(errno));
        fclose(fp);
        sbuf_free(&data);
        return -1;
    }
    fclose(fp);

    request_init(&req);
    while (pos < data.len) {
        size_t used = 0;
        int rc;

        request_reset(&req);
        rc = proto_parse_request(data.data + pos, data.len - pos, &req, &used,
                                 &lim, perr, sizeof(perr));
        if (rc == PARSE_INCOMPLETE) {
            log_warn("AOF %s: ignoring truncated command at offset %zu "
                     "(%zu bytes)", path, pos, data.len - pos);
            break;
        }
        if (rc == PARSE_ERROR) {
            snprintf(err, errlen, "%s: bad command at offset %zu: %s", path,
                     pos, perr);
            count = -1;
            break;
        }
        pos += used;
        if (req.argc == 0)
            continue;
        if (apply(ctx, &req) < 0) {
            snprintf(err, errlen, "%s: command %ld (%s) failed", path,
                     count + 1, req.argv[0]);
            count = -1;
            break;
        }
        count++;
    }
    request_free(&req);
    sbuf_free(&data);
    return count;
}
