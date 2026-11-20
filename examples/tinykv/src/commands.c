// commands.c - command table, dispatch, and command implementations.
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
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "cmdutil.h"
#include "codec.h"
#include "commands.h"
#include "config.h"
#include "log.h"
#include "persist.h"
#include "protocol.h"
#include "server.h"
#include "store.h"
#include "util.h"
#include "vlist.h"

// Largest string value a command may create.
#define MAX_STRING_LEN (512UL * 1024 * 1024)
// Command flag (local to this file): the command may add data, so it is
// refused when the memory limit is reached and nothing can be evicted.
#define CMD_DENY_OOM (1 << 8)
// Commands slower than this are logged.
#define SLOW_COMMAND_US 10000

// Set by handlers that wrote their own (rewritten) AOF record, so that the
// dispatcher doesn't also append the original command.
static int handler_propagated;

// ---------------------------------------------------------------------
// Reply helpers

static void reply_wrongtype(struct client *c)
{
    reply_error(&c->out, "WRONGTYPE Operation against a key holding the "
                "wrong kind of value");
}

static void reply_not_integer(struct client *c)
{
    reply_error(&c->out, "ERR value is not an integer or out of range");
}

static void reply_syntax(struct client *c)
{
    reply_error(&c->out, "ERR syntax error");
}

static void reply_store_error(struct client *c, int rc)
{
    switch (rc) {
    case STORE_ERR_OOM:
        reply_error(&c->out, "OOM command not allowed when used memory > "
                    "'maxmemory'");
        break;
    case STORE_ERR_WRONGTYPE:
        reply_wrongtype(c);
        break;
    case STORE_ERR_NOTFOUND:
        reply_error(&c->out, "ERR no such key");
        break;
    case STORE_ERR_RANGE:
        reply_error(&c->out, "ERR index out of range");
        break;
    default:
        reply_error(&c->out, "ERR internal error (%d)", rc);
        break;
    }
}

// ---------------------------------------------------------------------
// AOF propagation

static void propagate(struct server *srv, int argc, char **argv,
                      const size_t *argvlen)
{
    handler_propagated = 1;
    if (srv->aof == NULL || srv->loading)
        return;
    aof_append(srv->aof, argc, argv, argvlen);
}

// Propagate "<cmd> <key> <when>" with an absolute time in ms, used for
// commands whose relative expiry must not be re-evaluated on replay.
static void propagate_key_time(struct server *srv, const char *cmd,
                               const char *key, size_t keylen, uint64_t when)
{
    char num[24];
    char *argv[3];
    size_t lens[3];

    lens[2] = ll_to_str(num, sizeof(num), (long long)when);
    argv[0] = (char *)cmd;
    lens[0] = strlen(cmd);
    argv[1] = (char *)key;
    lens[1] = keylen;
    argv[2] = num;
    propagate(srv, 3, argv, lens);
}

static void propagate_del(struct server *srv, const char *key, size_t keylen)
{
    char *argv[2] = { (char *)"DEL", (char *)key };
    size_t lens[2] = { 3, keylen };

    propagate(srv, 2, argv, lens);
}

// Called after a list was modified in place: fix memory accounting, and
// delete the key if the list became empty.
static void list_changed(struct store *db, struct entry *e, size_t mem_before)
{
    store_account(db, (ssize_t)entry_mem_usage(e) - (ssize_t)mem_before);
    db->dirty++;
    if (vlist_len(e->v.list) == 0)
        store_delete(db, e->key, e->keylen);
}

// ---------------------------------------------------------------------
// Connection and server commands

static void cmd_ping(struct server *srv, struct client *c,
                     struct request *req)
{
    if (req->argc > 2) {
        reply_error(&c->out, "ERR wrong number of arguments for 'ping' "
                    "command");
        return;
    }
    if (req->argc == 2)
        reply_bulk(&c->out, req->argv[1], req->argvlen[1]);
    else
        reply_simple(&c->out, "PONG");
}

static void cmd_echo(struct server *srv, struct client *c,
                     struct request *req)
{
    reply_bulk(&c->out, req->argv[1], req->argvlen[1]);
}

static void cmd_quit(struct server *srv, struct client *c,
                     struct request *req)
{
    c->flags |= CLIENT_CLOSE_AFTER_REPLY;
    reply_ok(&c->out);
}

// Compare without an early exit, so response time doesn't reveal how much
// of the password matched.
static int password_matches(const char *given, size_t glen,
                            const char *expected)
{
    size_t elen = strlen(expected);
    unsigned char diff = glen != elen;
    size_t i;

    for (i = 0; i < glen; i++)
        diff |= (unsigned char)(given[i] ^ expected[i % (elen ? elen : 1)]);
    return diff == 0;
}

static void cmd_auth(struct server *srv, struct client *c,
                     struct request *req)
{
    if (srv->cfg.requirepass == NULL) {
        reply_error(&c->out, "ERR AUTH called without any password "
                    "configured");
        return;
    }
    if (!password_matches(req->argv[1], req->argvlen[1],
                          srv->cfg.requirepass)) {
        c->authed = 0;
        log_warn("failed AUTH from %s", c->addr);
        reply_error(&c->out, "WRONGPASS invalid password");
        return;
    }
    c->authed = 1;
    reply_ok(&c->out);
}

static void cmd_dbsize(struct server *srv, struct client *c,
                       struct request *req)
{
    reply_int(&c->out, (long long)store_count(srv->db));
}

static void cmd_flushall(struct server *srv, struct client *c,
                         struct request *req)
{
    store_flush(srv->db);
    srv->db->dirty++;
    log_info("FLUSHALL from %s", c->addr);
    reply_ok(&c->out);
}

static void cmd_save(struct server *srv, struct client *c,
                     struct request *req)
{
    if (server_save_snapshot(srv) != 0) {
        reply_error(&c->out, "ERR snapshot failed, see the server log");
        return;
    }
    reply_ok(&c->out);
}

static void cmd_bgsave(struct server *srv, struct client *c,
                       struct request *req)
{
    reply_error(&c->out, "ERR BGSAVE is not supported, use SAVE");
}

static void cmd_shutdown(struct server *srv, struct client *c,
                         struct request *req)
{
    int save = srv->cfg.save_interval_sec > 0;

    if (req->argc > 2) {
        reply_syntax(c);
        return;
    }
    if (req->argc == 2) {
        if (arg_is(req, 1, "SAVE"))
            save = 1;
        else if (arg_is(req, 1, "NOSAVE"))
            save = 0;
        else {
            reply_syntax(c);
            return;
        }
    }
    if (save && server_save_snapshot(srv) != 0) {
        reply_error(&c->out, "ERR errors trying to SHUTDOWN, see the "
                    "server log");
        return;
    }
    log_info("shutdown requested by %s", c->addr);
    srv->shutdown_requested = 1;
    c->flags |= CLIENT_CLOSE_AFTER_REPLY;
    reply_ok(&c->out);
}

static void cmd_info(struct server *srv, struct client *c,
                     struct request *req)
{
    const char *section = req->argc > 1 ? req->argv[1] : NULL;
    sbuf body = SBUF_INIT;

    if (req->argc > 2) {
        reply_syntax(c);
        return;
    }
    if (strcasecmp(section, "default") == 0 ||
        strcasecmp(section, "all") == 0)
        section = NULL;
    server_info(srv, &body, section);
    reply_bulk(&c->out, body.data ? body.data : "", body.len);
    sbuf_free(&body);
}

static int has_glob_chars(const char *s, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        if (s[i] == '*' || s[i] == '?' || s[i] == '[' || s[i] == '\\')
            return 1;
    }
    return 0;
}

static void config_cmd_get(struct server *srv, struct client *c,
                           const char *pat, size_t plen)
{
    sbuf body = SBUF_INIT;
    sbuf val = SBUF_INIT;
    const char **names;
    size_t n, i;
    long count = 0;

    if (!has_glob_chars(pat, plen)) {
        if (config_get(&srv->cfg, pat, &val) != 0) {
            reply_array_header(&c->out, 0);
            return;
        }
        reply_array_header(&c->out, 2);
        reply_bulk(&c->out, pat, plen);
        reply_bulk(&c->out, val.data ? val.data : "", val.len);
        sbuf_free(&val);
        return;
    }

    n = config_option_names(NULL, 0);
    names = xcalloc(n, sizeof(*names));
    n = config_option_names(names, n);
    for (i = 0; i < n; i++) {
        if (!glob_match(pat, plen, names[i], strlen(names[i]), 1))
            continue;
        sbuf_reset(&val);
        if (config_get(&srv->cfg, names[i], &val) != 0)
            continue;
        reply_bulk_str(&body, names[i]);
        reply_bulk(&body, val.data ? val.data : "", val.len);
        count += 2;
    }
    free(names);

    reply_array_header(&c->out, count);
    sbuf_append(&c->out, body.data, body.len);
    sbuf_free(&body);
    sbuf_free(&val);
}

// Apply configuration that the running server caches elsewhere.
static void config_apply(struct server *srv)
{
    log_set_level(srv->cfg.log_level);
    srv->db->max_bytes = (size_t)srv->cfg.max_memory;
    srv->db->policy = srv->cfg.eviction_policy;
    srv->db->samples = srv->cfg.evict_samples;
}

static void config_cmd_set(struct server *srv, struct client *c,
                           const char *name, const char *value)
{
    char err[256];

    if (!config_is_mutable(name)) {
        reply_error(&c->out, "ERR Unsupported CONFIG parameter: %.64s",
                    name);
        return;
    }
    if (config_set(&srv->cfg, name, value, err, sizeof(err)) != 0) {
        reply_error(&c->out, "ERR %s", err);
        return;
    }
    config_apply(srv);
    log_info("CONFIG SET %s by %s", name, c->addr);
    reply_ok(&c->out);
}

static void cmd_config(struct server *srv, struct client *c,
                       struct request *req)
{
    if (arg_is(req, 1, "GET") && req->argc == 3) {
        config_cmd_get(srv, c, req->argv[2], req->argvlen[2]);
    } else if (arg_is(req, 1, "SET") && req->argc == 4) {
        config_cmd_set(srv, c, req->argv[2], req->argv[3]);
    } else if (arg_is(req, 1, "RESETSTAT") && req->argc == 2) {
        memset(&srv->db->stats, 0, sizeof(srv->db->stats));
        srv->total_commands = 0;
        srv->total_connections = 0;
        srv->rejected_connections = 0;
        srv->net_in_bytes = 0;
        srv->net_out_bytes = 0;
        reply_ok(&c->out);
    } else if (arg_is(req, 1, "REWRITE")) {
        reply_error(&c->out, "ERR CONFIG REWRITE is not supported");
    } else {
        reply_error(&c->out, "ERR unknown CONFIG subcommand or wrong "
                    "number of arguments");
    }
}

static void client_list_line(sbuf *out, const struct client *c,
                             uint64_t now)
{
    sbuf_appendf(out, "id=%llu addr=%s name=%s age=%llu idle=%llu "
                 "cmds=%llu qbuf=%zu obuf=%zu cmd=%s\n",
                 (unsigned long long)c->id, c->addr,
                 c->name ? c->name : "",
                 (unsigned long long)((now - c->created_ms) / 1000),
                 (unsigned long long)((now - c->last_active_ms) / 1000),
                 (unsigned long long)c->ncommands,
                 c->in.len, c->out.len - c->out_pos,
                 c->last_cmd ? c->last_cmd : "NULL");
}

static int valid_client_name(const char *s, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        if (s[i] <= ' ' || s[i] > '~')
            return 0;
    }
    return 1;
}

static void cmd_client(struct server *srv, struct client *c,
                       struct request *req)
{
    if (arg_is(req, 1, "ID") && req->argc == 2) {
        reply_int(&c->out, (long long)c->id);
    } else if (arg_is(req, 1, "GETNAME") && req->argc == 2) {
        if (c->name == NULL)
            reply_null(&c->out);
        else
            reply_bulk_str(&c->out, c->name);
    } else if (arg_is(req, 1, "SETNAME") && req->argc == 3) {
        if (!valid_client_name(req->argv[2], req->argvlen[2])) {
            reply_error(&c->out, "ERR Client names cannot contain spaces, "
                        "newlines or special characters.");
            return;
        }
        free(c->name);
        c->name = req->argvlen[2] ? xstrdup(req->argv[2]) : NULL;
        reply_ok(&c->out);
    } else if (arg_is(req, 1, "LIST") && req->argc == 2) {
        sbuf body = SBUF_INIT;
        uint64_t now = now_ms();
        size_t i;

        for (i = 0; i < srv->nclients; i++)
            client_list_line(&body, srv->clients[i], now);
        reply_bulk(&c->out, body.data ? body.data : "", body.len);
        sbuf_free(&body);
    } else if (arg_is(req, 1, "KILL") && req->argc == 3) {
        long long id;
        struct client *target;

        if (arg_ll(req, 2, &id) != 0 || id < 0) {
            reply_not_integer(c);
            return;
        }
        target = server_find_client(srv, (uint64_t)id);
        if (target == NULL) {
            reply_error(&c->out, "ERR No such client");
            return;
        }
        // The event loop closes the connection once pending output (if
        // any) has been written.
        target->flags |= CLIENT_CLOSE_AFTER_REPLY;
        reply_ok(&c->out);
    } else {
        reply_error(&c->out, "ERR unknown CLIENT subcommand or wrong "
                    "number of arguments");
    }
}

static void cmd_command(struct server *srv, struct client *c,
                        struct request *req)
{
    size_t i, n = command_count();

    if (req->argc == 2 && arg_is(req, 1, "COUNT")) {
        reply_int(&c->out, (long long)n);
        return;
    }
    if (req->argc != 1) {
        reply_syntax(c);
        return;
    }
    reply_array_header(&c->out, (long)n);
    for (i = 0; i < n; i++) {
        const struct command *cmd = command_at(i);
        long nflags = 0;

        reply_array_header(&c->out, 4);
        reply_bulk_str(&c->out, cmd->name);
        reply_int(&c->out, cmd->arity);
        nflags += (cmd->flags & CMD_WRITE) != 0;
        nflags += (cmd->flags & CMD_ADMIN) != 0;
        nflags += (cmd->flags & CMD_NOAUTH) != 0;
        reply_array_header(&c->out, nflags);
        if (cmd->flags & CMD_WRITE)
            reply_simple(&c->out, "write");
        if (cmd->flags & CMD_ADMIN)
            reply_simple(&c->out, "admin");
        if (cmd->flags & CMD_NOAUTH)
            reply_simple(&c->out, "noauth");
        reply_bulk_str(&c->out, cmd->summary);
    }
}

// ---------------------------------------------------------------------
// String commands

static void cmd_get(struct server *srv, struct client *c,
                    struct request *req)
{
    struct entry *e = store_lookup(srv->db, req->argv[1], req->argvlen[1]);

    if (e == NULL) {
        reply_null(&c->out);
        return;
    }
    if (e->type != VT_STRING) {
        reply_wrongtype(c);
        return;
    }
    reply_bulk(&c->out, e->v.str.ptr, e->v.str.len);
}

static void cmd_set(struct server *srv, struct client *c,
                    struct request *req)
{
    struct store *db = srv->db;
    struct set_opts o;
    struct entry *old;
    char err[128];
    uint64_t expire_at;
    uint64_t keep = 0;
    uint64_t when;
    size_t out_before = c->out.len;
    int rc;

    if (parse_set_options(req, 3, &o, err, sizeof(err)) != 0) {
        reply_error(&c->out, "ERR %s", err);
        return;
    }
    if (set_opts_has_expiry(&o))
        expire_at = set_opts_expire_at(&o, now_ms());

    old = store_lookup(db, req->argv[1], req->argvlen[1]);
    if (((o.flags & SET_NX) && old != NULL) ||
        ((o.flags & SET_XX) && old == NULL)) {
        if ((o.flags & SET_GET) && old != NULL && old->type == VT_STRING)
            reply_bulk(&c->out, old->v.str.ptr, old->v.str.len);
        else
            reply_null(&c->out);
        handler_propagated = 1;   // nothing changed
        return;
    }
    if (o.flags & SET_GET) {
        if (old != NULL && old->type != VT_STRING) {
            reply_wrongtype(c);
            return;
        }
        // Reply with the old value now: the store frees it on overwrite.
        if (old != NULL)
            reply_bulk(&c->out, old->v.str.ptr, old->v.str.len);
        else
            reply_null(&c->out);
    }
    if ((o.flags & SET_KEEPTTL) && old != NULL)
        keep = old->expire_at;

    when = (o.flags & (SET_EX | SET_PX | SET_EXAT | SET_PXAT)) ?
           expire_at : keep;
    rc = store_set_string(db, req->argv[1], req->argvlen[1],
                          req->argv[2], req->argvlen[2], when);
    if (rc != STORE_OK) {
        sbuf_truncate(&c->out, out_before);
        reply_store_error(c, rc);
        return;
    }
    if (!(o.flags & SET_GET))
        reply_ok(&c->out);

    // Replicate with an absolute expiry so that replaying the AOF later
    // doesn't extend the key's lifetime.
    if (when != 0) {
        char num[24];
        char *argv[5] = { (char *)"SET", req->argv[1], req->argv[2],
                          (char *)"PXAT", num };
        size_t lens[5] = { 3, req->argvlen[1], req->argvlen[2], 4, 0 };

        lens[4] = ll_to_str(num, sizeof(num), (long long)when);
        propagate(srv, 5, argv, lens);
    } else {
        propagate(srv, 3, req->argv, req->argvlen);
    }
}

static void cmd_setnx(struct server *srv, struct client *c,
                      struct request *req)
{
    int rc;

    if (store_lookup(srv->db, req->argv[1], req->argvlen[1]) != NULL) {
        reply_int(&c->out, 0);
        handler_propagated = 1;
        return;
    }
    rc = store_set_string(srv->db, req->argv[1], req->argvlen[1],
                          req->argv[2], req->argvlen[2], 0);
    if (rc != STORE_OK) {
        reply_store_error(c, rc);
        return;
    }
    reply_int(&c->out, 1);
}

static void cmd_getset(struct server *srv, struct client *c,
                       struct request *req)
{
    struct entry *e = store_lookup(srv->db, req->argv[1], req->argvlen[1]);
    size_t out_before = c->out.len;
    int rc;

    if (e != NULL && e->type != VT_STRING) {
        reply_wrongtype(c);
        return;
    }
    if (e != NULL)
        reply_bulk(&c->out, e->v.str.ptr, e->v.str.len);
    else
        reply_null(&c->out);
    rc = store_set_string(srv->db, req->argv[1], req->argvlen[1],
                          req->argv[2], req->argvlen[2], 0);
    if (rc != STORE_OK) {
        sbuf_truncate(&c->out, out_before);
        reply_store_error(c, rc);
    }
}

static void cmd_getdel(struct server *srv, struct client *c,
                       struct request *req)
{
    struct entry *e = store_lookup(srv->db, req->argv[1], req->argvlen[1]);

    if (e == NULL) {
        reply_null(&c->out);
        handler_propagated = 1;
        return;
    }
    if (e->type != VT_STRING) {
        reply_wrongtype(c);
        return;
    }
    reply_bulk(&c->out, e->v.str.ptr, e->v.str.len);
    store_delete(srv->db, req->argv[1], req->argvlen[1]);
    propagate_del(srv, req->argv[1], req->argvlen[1]);
}

static void cmd_mget(struct server *srv, struct client *c,
                     struct request *req)
{
    int i;

    reply_array_header(&c->out, req->argc - 1);
    for (i = 1; i < req->argc; i++) {
        struct entry *e = store_lookup(srv->db, req->argv[i],
                                       req->argvlen[i]);

        if (e == NULL || e->type != VT_STRING)
            reply_null(&c->out);
        else
            reply_bulk(&c->out, e->v.str.ptr, e->v.str.len);
    }
}

static void cmd_mset(struct server *srv, struct client *c,
                     struct request *req)
{
    int i;

    if (req->argc % 2 != 1) {
        reply_error(&c->out, "ERR wrong number of arguments for 'mset' "
                    "command");
        return;
    }
    for (i = 1; i < req->argc; i += 2) {
        int rc = store_set_string(srv->db, req->argv[i], req->argvlen[i],
                                  req->argv[i + 1], req->argvlen[i + 1], 0);

        if (rc != STORE_OK) {
            // Keep the AOF consistent with the keys that were set.
            if (i > 1)
                propagate(srv, i, req->argv, req->argvlen);
            else
                handler_propagated = 1;
            reply_store_error(c, rc);
            return;
        }
    }
    reply_ok(&c->out);
}

static void cmd_del(struct server *srv, struct client *c,
                    struct request *req)
{
    long long n = 0;
    int i;

    for (i = 1; i < req->argc; i++)
        n += store_delete(srv->db, req->argv[i], req->argvlen[i]);
    reply_int(&c->out, n);
}

static void cmd_exists(struct server *srv, struct client *c,
                       struct request *req)
{
    long long n = 0;
    int i;

    for (i = 1; i < req->argc; i++) {
        if (store_lookup(srv->db, req->argv[i], req->argvlen[i]) != NULL)
            n++;
    }
    reply_int(&c->out, n);
}

static void incr_by(struct server *srv, struct client *c,
                    struct request *req, long long delta)
{
    struct entry *e = store_lookup(srv->db, req->argv[1], req->argvlen[1]);
    long long v = 0;
    char buf[24];
    size_t n;
    int rc;

    if (e != NULL) {
        if (e->type != VT_STRING) {
            reply_wrongtype(c);
            return;
        }
        if (str_to_ll(e->v.str.ptr, e->v.str.len, &v) != 0) {
            reply_not_integer(c);
            return;
        }
    }
    if ((delta > 0 && v > LLONG_MAX - delta) ||
        (delta < 0 && v < LLONG_MIN - delta)) {
        reply_error(&c->out, "ERR increment or decrement would overflow");
        return;
    }
    v += delta;
    n = ll_to_str(buf, sizeof(buf), v);
    if (e != NULL)
        rc = store_update_string(srv->db, e, buf, n);
    else
        rc = store_set_string(srv->db, req->argv[1], req->argvlen[1],
                              buf, n, 0);
    if (rc != STORE_OK) {
        reply_store_error(c, rc);
        return;
    }
    reply_int(&c->out, v);
}

static void cmd_incr(struct server *srv, struct client *c,
                     struct request *req)
{
    incr_by(srv, c, req, 1);
}

static void cmd_decr(struct server *srv, struct client *c,
                     struct request *req)
{
    incr_by(srv, c, req, -1);
}

static void cmd_incrby(struct server *srv, struct client *c,
                       struct request *req)
{
    long long delta;

    if (arg_ll(req, 2, &delta) != 0) {
        reply_not_integer(c);
        return;
    }
    incr_by(srv, c, req, delta);
}

static void cmd_decrby(struct server *srv, struct client *c,
                       struct request *req)
{
    long long delta;

    if (arg_ll(req, 2, &delta) != 0 || delta == LLONG_MIN) {
        reply_not_integer(c);
        return;
    }
    incr_by(srv, c, req, -delta);
}

static void cmd_append(struct server *srv, struct client *c,
                       struct request *req)
{
    struct entry *e = store_lookup(srv->db, req->argv[1], req->argvlen[1]);
    const char *add = req->argv[2];
    size_t addlen = req->argvlen[2];
    size_t newlen;
    char *buf;
    int rc;

    if (e == NULL) {
        rc = store_set_string(srv->db, req->argv[1], req->argvlen[1],
                              add, addlen, 0);
        if (rc != STORE_OK)
            reply_store_error(c, rc);
        else
            reply_int(&c->out, (long long)addlen);
        return;
    }
    if (e->type != VT_STRING) {
        reply_wrongtype(c);
        return;
    }
    if (e->v.str.len > MAX_STRING_LEN ||
        addlen > MAX_STRING_LEN - e->v.str.len) {
        reply_error(&c->out, "ERR string exceeds maximum allowed size");
        return;
    }
    newlen = e->v.str.len + addlen;
    buf = xmalloc(newlen);
    memcpy(buf, e->v.str.ptr, e->v.str.len);
    memcpy(buf + e->v.str.len, add, addlen);
    rc = store_update_string(srv->db, e, buf, newlen);
    free(buf);
    if (rc != STORE_OK) {
        reply_store_error(c, rc);
        return;
    }
    reply_int(&c->out, (long long)newlen);
}

static void cmd_strlen(struct server *srv, struct client *c,
                       struct request *req)
{
    struct entry *e = store_lookup(srv->db, req->argv[1], req->argvlen[1]);

    if (e == NULL) {
        reply_int(&c->out, 0);
        return;
    }
    if (e->type != VT_STRING) {
        reply_wrongtype(c);
        return;
    }
    reply_int(&c->out, (long long)e->v.str.len);
}

static void cmd_getrange(struct server *srv, struct client *c,
                         struct request *req)
{
    long long start, end;

    if (arg_ll(req, 2, &start) != 0 || arg_ll(req, 3, &end) != 0) {
        reply_not_integer(c);
        return;
    }

    struct entry *e = store_lookup(srv->db, req->argv[1], req->argvlen[1]);
    long long len = (long long)e->v.str.len;
    const char *val = e->v.str.ptr;

    if (e == NULL) {
        reply_bulk(&c->out, "", 0);
        return;
    }
    if (e->type != VT_STRING) {
        reply_wrongtype(c);
        return;
    }

    if (start < 0)
        start = len + start;
    if (end < 0)
        end = len + end;
    if (start < 0)
        start = 0;
    if (end < 0)
        end = 0;
    if (end >= len)
        end = len - 1;
    if (len == 0 || start > end) {
        reply_bulk(&c->out, "", 0);
        return;
    }
    reply_bulk(&c->out, val + start, (size_t)(end - start + 1));
}

static void cmd_setrange(struct server *srv, struct client *c,
                         struct request *req)
{
    struct entry *e;
    long long offset;
    const char *val = req->argv[3];
    size_t vlen = req->argvlen[3];
    size_t oldlen, newlen;
    char *buf;
    int rc;

    if (arg_ll(req, 2, &offset) != 0 || offset < 0) {
        reply_error(&c->out, "ERR offset is out of range");
        return;
    }
    if ((unsigned long long)offset > MAX_STRING_LEN ||
        vlen > MAX_STRING_LEN - (size_t)offset) {
        reply_error(&c->out, "ERR string exceeds maximum allowed size");
        return;
    }

    e = store_lookup(srv->db, req->argv[1], req->argvlen[1]);
    if (e != NULL && e->type != VT_STRING) {
        reply_wrongtype(c);
        return;
    }
    oldlen = e != NULL ? e->v.str.len : 0;
    if (vlen == 0) {
        // Nothing to write; the key is not created.
        reply_int(&c->out, (long long)oldlen);
        handler_propagated = 1;
        return;
    }

    newlen = TKV_MAX(oldlen, (size_t)offset + vlen);
    buf = xcalloc(newlen, 1);
    if (e != NULL)
        memcpy(buf, e->v.str.ptr, oldlen);
    memcpy(buf + offset, val, vlen);
    if (e != NULL)
        rc = store_update_string(srv->db, e, buf, newlen);
    else
        rc = store_set_string(srv->db, req->argv[1], req->argvlen[1],
                              buf, newlen, 0);
    free(buf);
    if (rc != STORE_OK) {
        reply_store_error(c, rc);
        return;
    }
    reply_int(&c->out, (long long)newlen);
}

// ---------------------------------------------------------------------
// Keyspace commands

// Shared by EXPIRE, PEXPIRE, EXPIREAT, and PEXPIREAT.  `unit` is 1000 for
// seconds and 1 for milliseconds.
static void expire_generic(struct server *srv, struct client *c,
                           struct request *req, long long unit,
                           int absolute)
{
    struct entry *e;
    long long v;
    uint64_t now = now_ms();
    uint64_t when;

    if (arg_ll(req, 2, &v) != 0 ||
        (v > 0 && v > LLONG_MAX / unit) || (v < 0 && v < LLONG_MIN / unit)) {
        reply_not_integer(c);
        return;
    }
    v *= unit;

    e = store_lookup(srv->db, req->argv[1], req->argvlen[1]);
    if (e == NULL) {
        reply_int(&c->out, 0);
        handler_propagated = 1;
        return;
    }

    if (absolute)
        when = v > 0 ? (uint64_t)v : 0;
    else if (v <= 0)
        when = 0;
    else
        when = (uint64_t)v > UINT64_MAX - now ? UINT64_MAX : now + (uint64_t)v;

    // A time in the past deletes the key immediately.
    if (when <= now) {
        store_delete(srv->db, req->argv[1], req->argvlen[1]);
        propagate_del(srv, req->argv[1], req->argvlen[1]);
        reply_int(&c->out, 1);
        return;
    }
    store_set_expire(srv->db, e, when);
    srv->db->dirty++;
    propagate_key_time(srv, "PEXPIREAT", req->argv[1], req->argvlen[1],
                       when);
    reply_int(&c->out, 1);
}

static void cmd_expire(struct server *srv, struct client *c,
                       struct request *req)
{
    expire_generic(srv, c, req, 1000, 0);
}

static void cmd_pexpire(struct server *srv, struct client *c,
                        struct request *req)
{
    expire_generic(srv, c, req, 1, 0);
}

static void cmd_expireat(struct server *srv, struct client *c,
                         struct request *req)
{
    expire_generic(srv, c, req, 1000, 1);
}

static void cmd_pexpireat(struct server *srv, struct client *c,
                          struct request *req)
{
    expire_generic(srv, c, req, 1, 1);
}

static void ttl_generic(struct server *srv, struct client *c,
                        struct request *req, int in_ms)
{
    struct entry *e = store_lookup(srv->db, req->argv[1], req->argvlen[1]);
    uint64_t now, left;

    if (e == NULL) {
        reply_int(&c->out, -2);
        return;
    }
    if (e->expire_at == 0) {
        reply_int(&c->out, -1);
        return;
    }
    now = now_ms();
    left = e->expire_at > now ? e->expire_at - now : 0;
    if (!in_ms)
        left = (left + 500) / 1000;
    reply_int(&c->out, left > LLONG_MAX ? LLONG_MAX : (long long)left);
}

static void cmd_ttl(struct server *srv, struct client *c,
                    struct request *req)
{
    ttl_generic(srv, c, req, 0);
}

static void cmd_pttl(struct server *srv, struct client *c,
                     struct request *req)
{
    ttl_generic(srv, c, req, 1);
}

static void cmd_persist(struct server *srv, struct client *c,
                        struct request *req)
{
    struct entry *e = store_lookup(srv->db, req->argv[1], req->argvlen[1]);

    if (e == NULL || e->expire_at == 0) {
        reply_int(&c->out, 0);
        handler_propagated = 1;
        return;
    }
    store_set_expire(srv->db, e, 0);
    srv->db->dirty++;
    reply_int(&c->out, 1);
}

static void cmd_type(struct server *srv, struct client *c,
                     struct request *req)
{
    struct entry *e = store_lookup(srv->db, req->argv[1], req->argvlen[1]);

    reply_simple(&c->out, e != NULL ? entry_type_name(e) : "none");
}

static void cmd_rename(struct server *srv, struct client *c,
                       struct request *req)
{
    int rc = store_rename(srv->db, req->argv[1], req->argvlen[1],
                          req->argv[2], req->argvlen[2]);

    if (rc != STORE_OK) {
        reply_store_error(c, rc);
        return;
    }
    reply_ok(&c->out);
}

struct key_match {
    const char *pat;
    size_t plen;
    int match_all;
    sbuf body;
    long count;

    // SCAN only
    unsigned long long skip;
    unsigned long long seen;
    long limit;
    long examined;
};

static int keys_cb(struct entry *e, void *arg)
{
    struct key_match *m = arg;

    if (m->match_all || glob_match(m->pat, m->plen, e->key, e->keylen, 0)) {
        reply_bulk(&m->body, e->key, e->keylen);
        m->count++;
    }
    return 0;
}

static void cmd_keys(struct server *srv, struct client *c,
                     struct request *req)
{
    struct key_match m;

    memset(&m, 0, sizeof(m));
    sbuf_init(&m.body);
    m.pat = req->argv[1];
    m.plen = req->argvlen[1];
    m.match_all = m.plen == 1 && m.pat[0] == '*';
    store_foreach(srv->db, keys_cb, &m);

    reply_array_header(&c->out, m.count);
    sbuf_append(&c->out, m.body.data, m.body.len);
    sbuf_free(&m.body);
}

static int scan_cb(struct entry *e, void *arg)
{
    struct key_match *m = arg;

    if (m->seen++ < m->skip)
        return 0;
    if (m->examined == m->limit)
        return 1;
    m->examined++;
    return keys_cb(e, arg);
}

// SCAN cursor [MATCH pattern] [COUNT n]
//
// The cursor is the number of entries visited so far in iteration order.
// Keys added or removed between calls may be missed or returned twice.
static void cmd_scan(struct server *srv, struct client *c,
                     struct request *req)
{
    struct key_match m;
    unsigned long long cursor, next;
    char num[24];
    size_t numlen;
    int i, stopped;

    if (parse_cursor(req->argv[1], req->argvlen[1], &cursor) != 0) {
        reply_error(&c->out, "ERR invalid cursor");
        return;
    }
    memset(&m, 0, sizeof(m));
    m.match_all = 1;
    m.limit = 10;
    for (i = 2; i < req->argc; i += 2) {
        long long n;

        if (i + 1 >= req->argc) {
            reply_syntax(c);
            return;
        }
        if (arg_is(req, i, "MATCH")) {
            m.pat = req->argv[i + 1];
            m.plen = req->argvlen[i + 1];
            m.match_all = m.plen == 1 && m.pat[0] == '*';
        } else if (arg_is(req, i, "COUNT")) {
            if (arg_ll_range(req, i + 1, 1, 100000, &n) != 0) {
                reply_syntax(c);
                return;
            }
            m.limit = (long)n;
        } else {
            reply_syntax(c);
            return;
        }
    }

    sbuf_init(&m.body);
    m.skip = cursor;
    stopped = store_foreach(srv->db, scan_cb, &m);

    next = stopped ? cursor + (unsigned long long)m.examined : 0;
    numlen = ll_to_str(num, sizeof(num), (long long)next);
    reply_array_header(&c->out, 2);
    reply_bulk(&c->out, num, numlen);
    reply_array_header(&c->out, m.count);
    sbuf_append(&c->out, m.body.data, m.body.len);
    sbuf_free(&m.body);
}

static void cmd_dump(struct server *srv, struct client *c,
                     struct request *req)
{
    struct entry *e = store_lookup(srv->db, req->argv[1], req->argvlen[1]);
    sbuf payload = SBUF_INIT;

    if (e == NULL) {
        reply_null(&c->out);
        return;
    }
    if (entry_dump(e, &payload) != 0) {
        sbuf_free(&payload);
        reply_error(&c->out, "ERR failed to serialize value");
        return;
    }
    reply_bulk(&c->out, payload.data, payload.len);
    sbuf_free(&payload);
}

// RESTORE key ttl serialized-value [REPLACE] [ABSTTL]
static void cmd_restore(struct server *srv, struct client *c,
                        struct request *req)
{
    long long ttl;
    int replace = 0, absttl = 0;
    uint64_t when = 0;
    char err[128];
    int i;

    if (arg_ll(req, 2, &ttl) != 0 || ttl < 0) {
        reply_error(&c->out, "ERR Invalid TTL value, must be >= 0");
        return;
    }
    for (i = 4; i < req->argc; i++) {
        if (arg_is(req, i, "REPLACE"))
            replace = 1;
        else if (arg_is(req, i, "ABSTTL"))
            absttl = 1;
        else {
            reply_syntax(c);
            return;
        }
    }
    if (ttl > 0) {
        uint64_t now = now_ms();

        when = absttl ? (uint64_t)ttl : now + (uint64_t)ttl;
        if (absttl && when <= now) {
            // Already expired: accept and do nothing, like Redis.
            reply_ok(&c->out);
            handler_propagated = 1;
            return;
        }
    }

    if (store_peek(srv->db, req->argv[1], req->argvlen[1]) != NULL) {
        if (!replace) {
            reply_error(&c->out, "BUSYKEY Target key name already exists.");
            return;
        }
        store_delete(srv->db, req->argv[1], req->argvlen[1]);
    }
    if (entry_restore(srv->db, req->argv[1], req->argvlen[1], req->argv[3],
                      req->argvlen[3], when, err, sizeof(err)) != 0) {
        reply_error(&c->out, "ERR %s", err);
        return;
    }
    reply_ok(&c->out);

    if (when != 0) {
        char num[24];
        char *argv[6] = { (char *)"RESTORE", req->argv[1], num, req->argv[3],
                          (char *)"REPLACE", (char *)"ABSTTL" };
        size_t lens[6] = { 7, req->argvlen[1], 0, req->argvlen[3], 7, 6 };

        lens[2] = ll_to_str(num, sizeof(num), (long long)when);
        propagate(srv, 6, argv, lens);
    }
}

// ---------------------------------------------------------------------
// List commands

static struct entry *lookup_list(struct server *srv, struct client *c,
                                 struct request *req, int *wrongtype)
{
    struct entry *e = store_lookup(srv->db, req->argv[1], req->argvlen[1]);

    *wrongtype = 0;
    if (e != NULL && e->type != VT_LIST) {
        reply_wrongtype(c);
        *wrongtype = 1;
        return NULL;
    }
    return e;
}

static void push_generic(struct server *srv, struct client *c,
                         struct request *req, int left)
{
    struct entry *e;
    size_t before;
    int err = 0;
    int i;

    e = store_get_or_create_list(srv->db, req->argv[1], req->argvlen[1],
                                 &err);
    if (e == NULL) {
        reply_store_error(c, err);
        return;
    }
    before = entry_mem_usage(e);
    for (i = 2; i < req->argc; i++) {
        if (vlist_push(e->v.list, left, req->argv[i], req->argvlen[i]) != 0)
            break;
    }
    if (i < req->argc) {
        // Keep the AOF consistent with the elements that were pushed.
        if (i > 2)
            propagate(srv, i, req->argv, req->argvlen);
        else
            handler_propagated = 1;
        list_changed(srv->db, e, before);
        reply_store_error(c, STORE_ERR_OOM);
        return;
    }
    reply_int(&c->out, (long long)vlist_len(e->v.list));
    list_changed(srv->db, e, before);
}

static void cmd_lpush(struct server *srv, struct client *c,
                      struct request *req)
{
    push_generic(srv, c, req, 1);
}

static void cmd_rpush(struct server *srv, struct client *c,
                      struct request *req)
{
    push_generic(srv, c, req, 0);
}

static void pop_generic(struct server *srv, struct client *c,
                        struct request *req, int left)
{
    struct entry *e;
    long long count = 1;
    size_t before;
    int wrongtype;
    long long i;

    if (req->argc > 3) {
        reply_syntax(c);
        return;
    }
    if (req->argc == 3 && arg_ll_range(req, 2, 0, LONG_MAX, &count) != 0) {
        reply_error(&c->out, "ERR value is out of range, must be positive");
        return;
    }
    e = lookup_list(srv, c, req, &wrongtype);
    if (wrongtype)
        return;
    if (e == NULL) {
        reply_null(&c->out);
        handler_propagated = 1;
        return;
    }

    before = entry_mem_usage(e);
    if (req->argc == 3) {
        size_t n = TKV_MIN((size_t)count, vlist_len(e->v.list));

        reply_array_header(&c->out, (long)n);
        for (i = 0; i < (long long)n; i++) {
            char *p;
            size_t plen;

            if (vlist_pop(e->v.list, left, &p, &plen) != 0)
                break;
            reply_bulk(&c->out, p, plen);
            free(p);
        }
    } else {
        char *p;
        size_t plen;

        if (vlist_pop(e->v.list, left, &p, &plen) != 0) {
            reply_null(&c->out);
        } else {
            reply_bulk(&c->out, p, plen);
            free(p);
        }
    }
    list_changed(srv->db, e, before);
}

static void cmd_lpop(struct server *srv, struct client *c,
                     struct request *req)
{
    pop_generic(srv, c, req, 1);
}

static void cmd_rpop(struct server *srv, struct client *c,
                     struct request *req)
{
    pop_generic(srv, c, req, 0);
}

static void cmd_llen(struct server *srv, struct client *c,
                     struct request *req)
{
    int wrongtype;
    struct entry *e = lookup_list(srv, c, req, &wrongtype);

    if (wrongtype)
        return;
    reply_int(&c->out, e ? (long long)vlist_len(e->v.list) : 0);
}

static void cmd_lrange(struct server *srv, struct client *c,
                       struct request *req)
{
    struct entry *e;
    long long start, stop;
    size_t first, n, i;
    int wrongtype;

    if (arg_ll(req, 2, &start) != 0 || arg_ll(req, 3, &stop) != 0 ||
        start < LONG_MIN || start > LONG_MAX ||
        stop < LONG_MIN || stop > LONG_MAX) {
        reply_not_integer(c);
        return;
    }
    e = lookup_list(srv, c, req, &wrongtype);
    if (wrongtype)
        return;
    if (e == NULL) {
        reply_array_header(&c->out, 0);
        return;
    }
    n = vlist_range(e->v.list, (long)start, (long)stop, &first);
    reply_array_header(&c->out, (long)n);
    for (i = 0; i < n; i++) {
        struct vlist_item *it = vlist_at(e->v.list, (long)(first + i));

        if (it == NULL)
            reply_null(&c->out);
        else
            reply_bulk(&c->out, it->ptr, it->len);
    }
}

static void cmd_lindex(struct server *srv, struct client *c,
                       struct request *req)
{
    struct entry *e;
    struct vlist_item *it;
    long long idx;
    int wrongtype;

    if (arg_ll(req, 2, &idx) != 0 || idx < LONG_MIN || idx > LONG_MAX) {
        reply_not_integer(c);
        return;
    }
    e = lookup_list(srv, c, req, &wrongtype);
    if (wrongtype)
        return;
    it = e != NULL ? vlist_at(e->v.list, (long)idx) : NULL;
    if (it == NULL)
        reply_null(&c->out);
    else
        reply_bulk(&c->out, it->ptr, it->len);
}

static void cmd_lset(struct server *srv, struct client *c,
                     struct request *req)
{
    struct entry *e;
    long long idx;
    size_t before;
    int wrongtype;

    if (arg_ll(req, 2, &idx) != 0 || idx < LONG_MIN || idx > LONG_MAX) {
        reply_not_integer(c);
        return;
    }
    e = lookup_list(srv, c, req, &wrongtype);
    if (wrongtype)
        return;
    if (e == NULL) {
        reply_store_error(c, STORE_ERR_NOTFOUND);
        return;
    }
    before = entry_mem_usage(e);
    if (vlist_set(e->v.list, (long)idx, req->argv[3], req->argvlen[3]) != 0) {
        reply_store_error(c, STORE_ERR_RANGE);
        return;
    }
    list_changed(srv->db, e, before);
    reply_ok(&c->out);
}

static void cmd_lrem(struct server *srv, struct client *c,
                     struct request *req)
{
    struct entry *e;
    long long count;
    size_t before, removed;
    int wrongtype;

    if (arg_ll(req, 2, &count) != 0 || count < LONG_MIN || count > LONG_MAX) {
        reply_not_integer(c);
        return;
    }
    e = lookup_list(srv, c, req, &wrongtype);
    if (wrongtype)
        return;
    if (e == NULL) {
        reply_int(&c->out, 0);
        handler_propagated = 1;
        return;
    }
    before = entry_mem_usage(e);
    removed = vlist_remove(e->v.list, (long)count, req->argv[3],
                           req->argvlen[3]);
    reply_int(&c->out, (long long)removed);
    if (removed > 0)
        list_changed(srv->db, e, before);
    else
        handler_propagated = 1;
}

static void cmd_ltrim(struct server *srv, struct client *c,
                      struct request *req)
{
    struct entry *e;
    long long start, stop;
    size_t before;
    int wrongtype;

    if (arg_ll(req, 2, &start) != 0 || arg_ll(req, 3, &stop) != 0 ||
        start < LONG_MIN || start > LONG_MAX ||
        stop < LONG_MIN || stop > LONG_MAX) {
        reply_not_integer(c);
        return;
    }
    e = lookup_list(srv, c, req, &wrongtype);
    if (wrongtype)
        return;
    if (e != NULL) {
        before = entry_mem_usage(e);
        vlist_trim(e->v.list, (long)start, (long)stop);
        list_changed(srv->db, e, before);
    }
    reply_ok(&c->out);
}

// ---------------------------------------------------------------------
// Command table (sorted by name for binary search)

#define CMD_WRITE_GROW (CMD_WRITE | CMD_DENY_OOM | CMD_DENY_LOADING)

static const struct command command_table[] = {
    { "append",    cmd_append,    3, CMD_WRITE_GROW,
      "Append a value to a string" },
    { "auth",      cmd_auth,      2, CMD_NOAUTH,
      "Authenticate the connection" },
    { "bgsave",    cmd_bgsave,    1, CMD_ADMIN,
      "Not supported" },
    { "client",    cmd_client,   -2, 0,
      "Inspect or manage client connections" },
    { "command",   cmd_command,  -1, 0,
      "List commands" },
    { "config",    cmd_config,   -2, CMD_ADMIN,
      "Get or set configuration options" },
    { "dbsize",    cmd_dbsize,    1, 0,
      "Number of keys" },
    { "decr",      cmd_decr,      2, CMD_WRITE_GROW,
      "Decrement an integer by one" },
    { "decrby",    cmd_decrby,    3, CMD_WRITE_GROW,
      "Decrement an integer" },
    { "del",       cmd_del,      -2, CMD_WRITE,
      "Delete keys" },
    { "dump",      cmd_dump,      2, 0,
      "Serialize a value" },
    { "echo",      cmd_echo,      2, 0,
      "Echo the argument" },
    { "exists",    cmd_exists,   -2, 0,
      "Count existing keys" },
    { "expire",    cmd_expire,    3, CMD_WRITE,
      "Set a timeout in seconds" },
    { "expireat",  cmd_expireat,  3, CMD_WRITE,
      "Set an expiry as a Unix time in seconds" },
    { "flushall",  cmd_flushall,  1, CMD_WRITE | CMD_ADMIN,
      "Delete all keys" },
    { "get",       cmd_get,       2, 0,
      "Get a string value" },
    { "getdel",    cmd_getdel,    2, CMD_WRITE,
      "Get a string value and delete the key" },
    { "getrange",  cmd_getrange,  4, 0,
      "Get a substring of a string value" },
    { "getset",    cmd_getset,    3, CMD_WRITE_GROW,
      "Set a string value and return the old one" },
    { "incr",      cmd_incr,      2, CMD_WRITE_GROW,
      "Increment an integer by one" },
    { "incrby",    cmd_incrby,    3, CMD_WRITE_GROW,
      "Increment an integer" },
    { "info",      cmd_info,     -1, 0,
      "Server information and statistics" },
    { "keys",      cmd_keys,      2, 0,
      "Find keys matching a pattern" },
    { "lindex",    cmd_lindex,    3, 0,
      "Get a list element by index" },
    { "llen",      cmd_llen,      2, 0,
      "Length of a list" },
    { "lpop",      cmd_lpop,     -2, CMD_WRITE,
      "Remove and return elements from the head of a list" },
    { "lpush",     cmd_lpush,    -3, CMD_WRITE_GROW,
      "Prepend elements to a list" },
    { "lrange",    cmd_lrange,    4, 0,
      "Get a range of list elements" },
    { "lrem",      cmd_lrem,      4, CMD_WRITE,
      "Remove elements from a list" },
    { "lset",      cmd_lset,      4, CMD_WRITE_GROW,
      "Set a list element by index" },
    { "ltrim",     cmd_ltrim,     4, CMD_WRITE,
      "Trim a list to a range" },
    { "mget",      cmd_mget,     -2, 0,
      "Get several string values" },
    { "mset",      cmd_mset,     -3, CMD_WRITE_GROW,
      "Set several string values" },
    { "persist",   cmd_persist,   2, CMD_WRITE,
      "Remove the expiry of a key" },
    { "pexpire",   cmd_pexpire,   3, CMD_WRITE,
      "Set a timeout in milliseconds" },
    { "pexpireat", cmd_pexpireat, 3, CMD_WRITE,
      "Set an expiry as a Unix time in milliseconds" },
    { "ping",      cmd_ping,     -1, CMD_NOAUTH,
      "Check the connection" },
    { "pttl",      cmd_pttl,      2, 0,
      "Time to live in milliseconds" },
    { "quit",      cmd_quit,      1, CMD_NOAUTH,
      "Close the connection" },
    { "rename",    cmd_rename,    3, CMD_WRITE,
      "Rename a key" },
    { "restore",   cmd_restore,  -4, CMD_WRITE_GROW,
      "Create a key from a DUMP payload" },
    { "rpop",      cmd_rpop,     -2, CMD_WRITE,
      "Remove and return elements from the tail of a list" },
    { "rpush",     cmd_rpush,    -3, CMD_WRITE_GROW,
      "Append elements to a list" },
    { "save",      cmd_save,      1, CMD_ADMIN,
      "Write a snapshot to disk" },
    { "scan",      cmd_scan,     -2, 0,
      "Incrementally iterate over keys" },
    { "set",       cmd_set,      -3, CMD_WRITE_GROW,
      "Set a string value" },
    { "setnx",     cmd_setnx,     3, CMD_WRITE_GROW,
      "Set a string value if the key does not exist" },
    { "setrange",  cmd_setrange,  4, CMD_WRITE_GROW,
      "Overwrite part of a string value" },
    { "shutdown",  cmd_shutdown, -1, CMD_ADMIN,
      "Save and stop the server" },
    { "strlen",    cmd_strlen,    2, 0,
      "Length of a string value" },
    { "ttl",       cmd_ttl,       2, 0,
      "Time to live in seconds" },
    { "type",      cmd_type,      2, 0,
      "Type of the value at a key" },
};

size_t command_count(void)
{
    return ARRAY_LEN(command_table);
}

const struct command *command_at(size_t i)
{
    return i < ARRAY_LEN(command_table) ? &command_table[i] : NULL;
}

// Compare a command name typed by the client (any case, not
// NUL-terminated) with a table entry.
static int name_cmp(const char *name, size_t len, const char *entry)
{
    size_t i;

    for (i = 0; i < len; i++) {
        int a = name[i] >= 'A' && name[i] <= 'Z' ? name[i] + 32 : name[i];
        int b = (unsigned char)entry[i];

        if (b == '\0' || a != b)
            return a - b;
    }
    return entry[len] == '\0' ? 0 : -1;
}

const struct command *command_lookup(const char *name, size_t len)
{
    size_t lo = 0, hi = ARRAY_LEN(command_table);

    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int cmp = name_cmp(name, len, command_table[mid].name);

        if (cmp == 0)
            return &command_table[mid];
        if (cmp < 0)
            hi = mid;
        else
            lo = mid + 1;
    }
    return NULL;
}

static int arity_ok(const struct command *cmd, int argc)
{
    if (cmd->arity > 0)
        return argc == cmd->arity;
    return argc >= -cmd->arity;
}

static void log_slow_command(const struct client *c,
                             const struct request *req, uint64_t elapsed_us)
{
    char *key = req->argc > 1 ? str_escape(req->argv[1],
                                           TKV_MIN(req->argvlen[1], 64))
                              : NULL;

    log_warn("slow command from %s: %s %s (%llu us)", c->addr,
             c->last_cmd ? c->last_cmd : "?", key ? key : "",
             (unsigned long long)elapsed_us);
    free(key);
}

static void call_command(struct server *srv, struct client *c,
                         const struct command *cmd, struct request *req)
{
    size_t out_before = c->out.len;
    uint64_t start = now_us();
    uint64_t elapsed;
    int failed;

    handler_propagated = 0;
    cmd->fn(srv, c, req);
    elapsed = now_us() - start;
    srv->total_commands++;

    failed = c->out.len > out_before && c->out.data[out_before] == '-';
    if ((cmd->flags & CMD_WRITE) && !failed && !handler_propagated)
        propagate(srv, req->argc, req->argv, req->argvlen);

    if (elapsed >= SLOW_COMMAND_US && c != NULL &&
        !(c->flags & CLIENT_FAKE))
        log_slow_command(c, req, elapsed);
}

void command_dispatch(struct server *srv, struct client *c,
                      struct request *req)
{
    const struct command *cmd;

    if (req->argc == 0)
        return;

    cmd = command_lookup(req->argv[0], req->argvlen[0]);
    if (cmd == NULL) {
        reply_error(&c->out, "ERR unknown command '%.*s'",
                    (int)TKV_MIN(req->argvlen[0], 64), req->argv[0]);
        return;
    }
    if (!arity_ok(cmd, req->argc)) {
        reply_error(&c->out, "ERR wrong number of arguments for '%s' "
                    "command", cmd->name);
        return;
    }
    if (srv->cfg.requirepass != NULL && !c->authed &&
        !(c->flags & CLIENT_FAKE) && !(cmd->flags & CMD_NOAUTH)) {
        reply_error(&c->out, "NOAUTH Authentication required.");
        return;
    }
    if (srv->loading && (cmd->flags & CMD_DENY_LOADING) &&
        !(c->flags & CLIENT_FAKE)) {
        reply_error(&c->out, "LOADING tinykv is loading the dataset in "
                    "memory");
        return;
    }
    // Make room before running a command that may allocate.
    if (srv->cfg.max_memory > 0 &&
        !(c->flags & CLIENT_FAKE) &&
        (cmd->flags & CMD_DENY_OOM) &&
        store_evict_if_needed(srv->db) != STORE_OK) {
        reply_store_error(c, STORE_ERR_OOM);
        return;
    }

    c->last_cmd = cmd->name;
    c->ncommands++;
    c->last_active_ms = now_ms();
    call_command(srv, c, cmd, req);
}
