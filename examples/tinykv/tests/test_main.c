// test_main.c - unit tests for the tinykv core modules.
//
// Run with `make test`.  Each test function uses CHECK(), which records a
// failure and keeps going, so one run reports every broken assertion.
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
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "codec.h"
#include "hashtable.h"
#include "log.h"
#include "persist.h"
#include "protocol.h"
#include "sbuf.h"
#include "store.h"
#include "ttlheap.h"
#include "util.h"
#include "vlist.h"

static int checks;
static int failures;

#define CHECK(cond)                                                       \
    do {                                                                  \
        checks++;                                                         \
        if (!(cond)) {                                                    \
            failures++;                                                   \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__,        \
                    __LINE__, #cond);                                     \
        }                                                                 \
    } while (0)

#define CHECK_STR(got, want) CHECK((got) != NULL && strcmp((got), (want)) == 0)

/* ------------------------------------------------------------------------ */

static void test_util(void)
{
    long long v;
    unsigned long long u;
    char buf[32];
    char line[] = "a,b,,c";
    char *fields[8];

    CHECK(str_to_ll("12345", 5, &v) == 0 && v == 12345);
    CHECK(str_to_ll("-42", 3, &v) == 0 && v == -42);
    CHECK(str_to_ll("0", 1, &v) == 0 && v == 0);
    CHECK(str_to_ll("12a", 3, &v) < 0);
    CHECK(str_to_ll("", 0, &v) < 0);
    CHECK(str_to_ll("99999999999999999999", 20, &v) < 0);
    CHECK(str_to_ll("123", 2, &v) == 0 && v == 12);

    CHECK(parse_size("512", &u) == 0 && u == 512);
    CHECK(parse_size("64kb", &u) == 0 && u == 64 * 1024);
    CHECK(parse_size("1gb", &u) == 0 && u == 1024ULL * 1024 * 1024);
    CHECK(parse_size("lots", &u) < 0);

    CHECK(ll_to_str(buf, sizeof(buf), -9876) == 5);
    CHECK_STR(buf, "-9876");
    CHECK(ll_to_str(buf, 3, 12345) == 0);

    CHECK(str_split(line, ',', fields, 8) == 4);
    CHECK_STR(fields[0], "a");
    CHECK_STR(fields[2], "");
    CHECK_STR(fields[3], "c");

    CHECK(str_lcpy(buf, "hello world", 6) == 11);
    CHECK_STR(buf, "hello");
}

static void test_sbuf(void)
{
    sbuf b = SBUF_INIT;
    size_t len;
    char *s;

    CHECK(sbuf_append_str(&b, "hello") == 0);
    CHECK(sbuf_appendf(&b, " %d-%s", 42, "x") == 0);
    CHECK(b.len == 10);
    CHECK_STR(b.data, "hello 42-x");
    sbuf_consume(&b, 6);
    CHECK_STR(b.data, "42-x");
    for (int i = 0; i < 1000; i++)
        sbuf_append_char(&b, 'z');
    CHECK(b.len == 1004);
    s = sbuf_detach(&b, &len);
    CHECK(len == 1004 && s[1003] == 'z');
    CHECK(b.len == 0);
    free(s);
    sbuf_free(&b);
}

static void test_codec(void)
{
    const char *msg = "123456789";
    unsigned char out[64];
    char enc[64];
    uint8_t vb[10];
    uint64_t v;
    long n;

    CHECK(crc32_buf(msg, 9) == 0xCBF43926u);
    CHECK(crc32_update(crc32_update(0, msg, 4), msg + 4, 5) == 0xCBF43926u);

    CHECK(base64_encode((const unsigned char *)"foobar", 6, enc) == 8);
    CHECK_STR(enc, "Zm9vYmFy");
    CHECK(base64_encode((const unsigned char *)"fo", 2, enc) == 4);
    CHECK_STR(enc, "Zm8=");
    n = base64_decode("Zm9vYmE=", 8, out);
    CHECK(n == 5 && memcmp(out, "fooba", 5) == 0);
    CHECK(base64_decode("Zm9v!mE=", 8, out) < 0);

    uint64_t samples[] = { 0, 1, 127, 128, 300, 1ULL << 35, UINT64_MAX };
    for (size_t i = 0; i < ARRAY_LEN(samples); i++) {
        size_t w = varint_put(vb, samples[i]);
        CHECK(w >= 1 && w <= 10);
        CHECK(varint_get(vb, w, &v) == w && v == samples[i]);
        CHECK(varint_get(vb, w - 1, &v) == 0);
    }

    CHECK(glob_match("h*llo", 5, "hello", 5, 0));
    CHECK(glob_match("h?llo", 5, "hallo", 5, 0));
    CHECK(glob_match("h[ae]llo", 8, "hello", 5, 0));
    CHECK(!glob_match("h[^e]llo", 8, "hello", 5, 0));
    CHECK(glob_match("h[a-c]llo", 9, "hbllo", 5, 0));
    CHECK(glob_match("user:*", 6, "USER:42", 7, 1));
    CHECK(!glob_match("user:*", 6, "USER:42", 7, 0));
    CHECK(glob_match("a\\*b", 4, "a*b", 3, 0));
    CHECK(glob_match("*", 1, "", 0, 0));
}

static void test_hashtable(void)
{
    hashtable *t = ht_create(4);
    char key[32];
    ht_iter it;
    ht_entry *he;
    void *old;
    size_t seen = 0;
    uint64_t rng = 0x9e3779b97f4a7c15ULL;

    for (long i = 0; i < 5000; i++) {
        int n = snprintf(key, sizeof(key), "key:%ld", i);
        CHECK(ht_put(t, key, (size_t)n, (void *)(i + 1), NULL) == 1);
        ht_rehash_step(t, 1);
    }
    CHECK(ht_count(t) == 5000);
    CHECK(ht_put(t, "key:7", 5, (void *)99, &old) == 0 && old == (void *)8);
    CHECK(ht_get(t, "key:7", 5) == (void *)99);
    CHECK(ht_get(t, "key:5000", 8) == NULL);

    for (long i = 0; i < 5000; i += 2) {
        int n = snprintf(key, sizeof(key), "key:%ld", i);
        CHECK(ht_remove(t, key, (size_t)n, &old) == 1);
    }
    CHECK(ht_remove(t, "key:0", 5, NULL) == 0);
    CHECK(ht_count(t) == 2500);

    for (int i = 0; i < 100; i++)
        CHECK(ht_random_entry(t, &rng) != NULL);

    ht_iter_init(&it, t);
    while ((he = ht_iter_next(&it)) != NULL)
        seen++;
    ht_iter_release(&it);
    CHECK(seen == 2500);

    ht_clear(t);
    CHECK(ht_count(t) == 0);
    CHECK(ht_random_entry(t, &rng) == NULL);
    ht_destroy(t);
}

static void test_vlist(void)
{
    struct vlist *l = vlist_new();
    char *p;
    size_t n, first;
    struct vlist_item *it;

    for (int i = 0; i < 10; i++) {
        char buf[8];
        int len = snprintf(buf, sizeof(buf), "%d", i);
        CHECK(vlist_push(l, 0, buf, (size_t)len) == 0);
    }
    CHECK(vlist_push(l, 1, "head", 4) == 0);
    CHECK(vlist_len(l) == 11);

    it = vlist_at(l, 0);
    CHECK(it != NULL && it->len == 4 && memcmp(it->ptr, "head", 4) == 0);
    it = vlist_at(l, -1);
    CHECK(it != NULL && it->len == 1 && it->ptr[0] == '9');
    CHECK(vlist_at(l, 11) == NULL);
    CHECK(vlist_at(l, -12) == NULL);

    CHECK(vlist_range(l, 0, -1, &first) == 11 && first == 0);
    CHECK(vlist_range(l, 2, 4, &first) == 3 && first == 2);
    CHECK(vlist_range(l, 5, 2, &first) == 0);
    CHECK(vlist_range(l, -3, 100, &first) == 3 && first == 8);

    CHECK(vlist_pop(l, 1, &p, &n) == 0 && n == 4 && memcmp(p, "head", 4) == 0);
    free(p);
    CHECK(vlist_pop(l, 0, &p, &n) == 0 && n == 1 && p[0] == '9');
    free(p);

    vlist_trim(l, 1, 3);
    CHECK(vlist_len(l) == 3);
    it = vlist_at(l, 0);
    CHECK(it != NULL && it->ptr[0] == '1');

    CHECK(vlist_set(l, 1, "two", 3) == 0);
    it = vlist_at(l, 1);
    CHECK(it != NULL && it->len == 3 && memcmp(it->ptr, "two", 3) == 0);
    CHECK(vlist_set(l, 5, "x", 1) < 0);

    vlist_push(l, 0, "1", 1);
    CHECK(vlist_remove(l, 0, "1", 1) == 2);
    CHECK(vlist_len(l) == 2);
    vlist_free(l);
}

struct heap_item {
    uint64_t when;
    size_t idx;
};

static void heap_set_index(void *owner, size_t idx)
{
    ((struct heap_item *)owner)->idx = idx;
}

static void test_ttlheap(void)
{
    struct ttlheap h;
    struct heap_item items[200];
    uint64_t rng = 12345, when, prev = 0;
    void *owner;

    ttlheap_init(&h, heap_set_index);
    for (size_t i = 0; i < ARRAY_LEN(items); i++) {
        items[i].when = rng_next(&rng) % 100000;
        CHECK(ttlheap_push(&h, items[i].when, &items[i]) == 0);
    }
    CHECK(ttlheap_verify(&h) == 0);

    // Reschedule and remove a few, then drain in order.
    ttlheap_update(&h, items[10].idx, 5);
    items[10].when = 5;
    ttlheap_remove(&h, items[20].idx);
    CHECK(items[20].idx == TTL_NO_INDEX);
    CHECK(ttlheap_verify(&h) == 0);
    CHECK(ttlheap_len(&h) == ARRAY_LEN(items) - 1);

    owner = ttlheap_peek(&h, &when);
    CHECK(owner != NULL && when <= 5);
    while ((owner = ttlheap_pop(&h, &when)) != NULL) {
        CHECK(when >= prev);
        CHECK(((struct heap_item *)owner)->when == when);
        prev = when;
    }
    CHECK(ttlheap_len(&h) == 0);
    ttlheap_free(&h);
}

static void test_store(void)
{
    struct store *s = store_create(0, 0, 5);
    struct entry *e;
    int err = 0;
    uint64_t now = now_ms();

    CHECK(store_set_string(s, "a", 1, "alpha", 5, 0) == STORE_OK);
    CHECK(store_set_string(s, "b", 1, "", 0, 0) == STORE_OK);
    CHECK(store_count(s) == 2);
    e = store_lookup(s, "a", 1);
    CHECK(e != NULL && e->type == VT_STRING && e->v.str.len == 5 &&
          memcmp(e->v.str.ptr, "alpha", 5) == 0);
    e = store_lookup(s, "b", 1);
    CHECK(e != NULL && e->v.str.len == 0);
    CHECK(store_lookup(s, "c", 1) == NULL);

    e = store_lookup(s, "a", 1);
    CHECK(e != NULL && store_update_string(s, e, "beta", 4) == STORE_OK);
    e = store_lookup(s, "a", 1);
    CHECK(e != NULL && e->v.str.len == 4);

    e = store_get_or_create_list(s, "l", 1, &err);
    CHECK(e != NULL && e->type == VT_LIST);
    CHECK(store_get_or_create_list(s, "a", 1, &err) == NULL &&
          err == STORE_ERR_WRONGTYPE);

    CHECK(store_set_string(s, "tmp", 3, "x", 1, now + 1) == STORE_OK);
    CHECK(store_set_string(s, "keep", 4, "x", 1, now + 3600 * 1000) == STORE_OK);
    CHECK(store_expire_cycle(s, now + 10, 100) == 1);
    CHECK(store_peek(s, "tmp", 3) == NULL);
    CHECK(store_peek(s, "keep", 4) != NULL);

    CHECK(store_rename(s, "keep", 4, "kept", 4) == STORE_OK);
    CHECK(store_peek(s, "keep", 4) == NULL);
    e = store_peek(s, "kept", 4);
    CHECK(e != NULL && e->expire_at == now + 3600 * 1000);

    CHECK(store_delete(s, "a", 1) == 1);
    CHECK(store_delete(s, "a", 1) == 0);

    store_flush(s);
    CHECK(store_count(s) == 0);
    store_destroy(s);
}

static void test_protocol(void)
{
    struct proto_limits lim = { 1024, 1024, 16 };
    struct request req;
    struct reply_val r;
    char err[128];
    size_t used;
    sbuf out = SBUF_INIT;
    const char *mb = "*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$5\r\nv\0lue\r\n";
    size_t mblen = 31;

    request_init(&req);
    CHECK(proto_parse_request(mb, mblen, &req, &used, &lim, err,
                              sizeof(err)) == PARSE_OK);
    CHECK(used == mblen && req.argc == 3);
    CHECK_STR(req.argv[0], "SET");
    CHECK(req.argvlen[2] == 5 && memcmp(req.argv[2], "v\0lue", 5) == 0);

    for (size_t cut = 1; cut < mblen; cut++) {
        request_reset(&req);
        CHECK(proto_parse_request(mb, cut, &req, &used, &lim, err,
                                  sizeof(err)) == PARSE_INCOMPLETE);
    }

    request_reset(&req);
    CHECK(proto_parse_request("GET  foo\r\n", 10, &req, &used, &lim, err,
                              sizeof(err)) == PARSE_OK);
    CHECK(used == 10 && req.argc == 2);
    CHECK_STR(req.argv[1], "foo");

    request_reset(&req);
    CHECK(proto_parse_request("*1\r\n:5\r\n", 8, &req, &used, &lim, err,
                              sizeof(err)) == PARSE_ERROR);
    request_reset(&req);
    CHECK(proto_parse_request("*99\r\n", 5, &req, &used, &lim, err,
                              sizeof(err)) == PARSE_ERROR);
    request_free(&req);

    reply_array_header(&out, 3);
    reply_int(&out, -7);
    reply_bulk(&out, "hi", 2);
    reply_null(&out);
    CHECK(proto_parse_reply(out.data, out.len, &r, &used, 0) == PARSE_OK);
    CHECK(used == out.len && r.type == RT_ARRAY && r.nelems == 3);
    if (r.type == RT_ARRAY && r.nelems == 3) {
        CHECK(r.elems[0].type == RT_INT && r.elems[0].ival == -7);
        CHECK(r.elems[1].type == RT_BULK && r.elems[1].len == 2);
        CHECK(r.elems[2].type == RT_NULL);
    }
    reply_val_free(&r);
    CHECK(proto_parse_reply(out.data, out.len - 1, &r, &used, 0) ==
          PARSE_INCOMPLETE);

    sbuf_reset(&out);
    reply_error(&out, "ERR bad %s", "thing");
    CHECK(proto_parse_reply(out.data, out.len, &r, &used, 0) == PARSE_OK);
    CHECK(r.type == RT_ERROR && r.len == 13 &&
          memcmp(r.str, "ERR bad thing", 13) == 0);
    reply_val_free(&r);
    sbuf_free(&out);
}

static void test_snapshot(void)
{
    struct store *a = store_create(0, 0, 5);
    struct store *b = store_create(0, 0, 5);
    char path[] = "/tmp/tinykv-test-XXXXXX";
    char err[256];
    struct entry *e;
    int serr = 0;
    uint64_t later = now_ms() + 3600 * 1000;
    int fd = mkstemp(path);

    CHECK(fd >= 0);
    if (fd < 0)
        return;
    close(fd);

    store_set_string(a, "s1", 2, "value-one", 9, 0);
    store_set_string(a, "bin", 3, "a\0b\xff", 4, later);
    store_set_string(a, "empty", 5, "", 0, 0);
    e = store_get_or_create_list(a, "list", 4, &serr);
    CHECK(e != NULL);
    if (e != NULL) {
        vlist_push(e->v.list, 0, "x", 1);
        vlist_push(e->v.list, 0, "yy", 2);
        vlist_push(e->v.list, 0, "", 0);
    }

    CHECK(snapshot_save(a, path, err, sizeof(err)) == 0);
    CHECK(snapshot_load(b, path, err, sizeof(err)) == 0);
    CHECK(store_count(b) == 4);

    e = store_peek(b, "bin", 3);
    CHECK(e != NULL && e->v.str.len == 4 &&
          memcmp(e->v.str.ptr, "a\0b\xff", 4) == 0 && e->expire_at == later);
    e = store_peek(b, "list", 4);
    CHECK(e != NULL && e->type == VT_LIST && vlist_len(e->v.list) == 3);
    e = store_peek(b, "empty", 5);
    CHECK(e != NULL && e->v.str.len == 0);

    // DUMP/RESTORE round trip, and a corrupted payload is rejected.
    sbuf d = SBUF_INIT;
    e = store_peek(a, "list", 4);
    CHECK(e != NULL && entry_dump(e, &d) == 0);
    CHECK(entry_restore(b, "copy", 4, d.data, d.len, 0, err,
                        sizeof(err)) == 0);
    e = store_peek(b, "copy", 4);
    CHECK(e != NULL && e->type == VT_LIST && vlist_len(e->v.list) == 3);
    if (d.len > 2) {
        d.data[1] ^= 0x40;
        CHECK(entry_restore(b, "bad", 3, d.data, d.len, 0, err,
                            sizeof(err)) < 0);
    }
    sbuf_free(&d);

    unlink(path);
    store_destroy(a);
    store_destroy(b);
}

int main(void)
{
    log_open(NULL, LOG_WARN);

    test_util();
    test_sbuf();
    test_codec();
    test_hashtable();
    test_vlist();
    test_ttlheap();
    test_store();
    test_protocol();
    test_snapshot();

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
