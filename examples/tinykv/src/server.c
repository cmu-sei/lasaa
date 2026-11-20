// server.c - tinykv server: startup, event loop, clients, INFO, cron.
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
#include "server.h"

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#include "commands.h"
#include "log.h"
#include "net.h"
#include "persist.h"
#include "store.h"
#include "util.h"

#define TKV_VERSION "0.9.3"

#define READ_CHUNK (16 * 1024)
#define MAX_ACCEPTS_PER_TICK 64
#define CRON_INTERVAL_MS 100
#define EXPIRE_WORK_PER_TICK 200
// Output beyond this is a client that isn't reading its replies.
#define MAX_PENDING_OUTPUT (64u * 1024 * 1024)

static volatile sig_atomic_t got_shutdown_signal;
static volatile sig_atomic_t got_reopen_signal;

/* ------------------------------------------------------------------------
 * Clients
 * ------------------------------------------------------------------------ */

static void clients_add(struct server *srv, struct client *c)
{
    if (srv->nclients == srv->clients_cap) {
        size_t ncap = srv->clients_cap ? srv->clients_cap * 2 : 16;
        srv->clients = xrealloc(srv->clients, ncap * sizeof(*srv->clients));
        srv->clients_cap = ncap;
    }
    srv->clients[srv->nclients++] = c;
}

static void clients_remove(struct server *srv, struct client *c)
{
    for (size_t i = 0; i < srv->nclients; i++) {
        if (srv->clients[i] == c) {
            srv->clients[i] = srv->clients[--srv->nclients];
            return;
        }
    }
}

struct client *client_create(struct server *srv, int fd, const char *addr)
{
    struct client *c = xcalloc(1, sizeof(*c));
    uint64_t now = now_ms();

    c->id = ++srv->next_client_id;
    c->fd = fd;
    str_lcpy(c->addr, addr ? addr : "", sizeof(c->addr));
    c->authed = srv->cfg.requirepass == NULL;
    sbuf_init(&c->in);
    sbuf_init(&c->out);
    request_init(&c->req);
    c->created_ms = now;
    c->last_active_ms = now;
    if (fd >= 0)
        clients_add(srv, c);
    return c;
}

// A client with no connection, used to replay the AOF.
static struct client *client_create_fake(struct server *srv)
{
    struct client *c = client_create(srv, -1, "aof");

    c->flags |= CLIENT_FAKE;
    c->authed = 1;
    return c;
}

void client_free(struct server *srv, struct client *c)
{
    if (c->fd >= 0) {
        clients_remove(srv, c);
        close(c->fd);
    }
    sbuf_free(&c->in);
    sbuf_free(&c->out);
    request_free(&c->req);
    free(c->name);
    free(c);
}

struct client *server_find_client(struct server *srv, uint64_t id)
{
    for (size_t i = 0; i < srv->nclients; i++)
        if (srv->clients[i]->id == id)
            return srv->clients[i];
    return NULL;
}

static int client_has_output(const struct client *c)
{
    return c->out.len > c->out_pos;
}

// Write pending output.  Returns 0 if the client is still alive, -1 if it
// was freed.
static int client_write(struct server *srv, struct client *c)
{
    while (client_has_output(c)) {
        ssize_t n = net_write_some(c->fd, c->out.data + c->out_pos,
                                   c->out.len - c->out_pos);
        if (n < 0) {
            log_debug("write error to client %llu (%s): %s",
                      (unsigned long long)c->id, c->addr, strerror(errno));
            client_free(srv, c);
            return -1;
        }
        if (n == 0)
            break;
        c->out_pos += (size_t)n;
        srv->net_out_bytes += (uint64_t)n;
    }

    if (!client_has_output(c)) {
        sbuf_reset(&c->out);
        c->out_pos = 0;
        if (c->flags & CLIENT_CLOSE_AFTER_REPLY) {
            client_free(srv, c);
            return -1;
        }
    } else if (c->out_pos > c->out.cap / 2) {
        sbuf_consume(&c->out, c->out_pos);
        c->out_pos = 0;
    }
    return 0;
}

// Parse and execute as many complete requests as the input buffer holds.
static void client_process_input(struct server *srv, struct client *c)
{
    struct proto_limits lim;
    char err[128];
    size_t pos = 0;

    lim.max_inline = srv->cfg.max_request_bytes;
    lim.max_bulk = srv->cfg.max_bulk_len;
    lim.max_args = srv->cfg.max_args;

    while (pos < c->in.len && !(c->flags & CLIENT_CLOSE_AFTER_REPLY)) {
        size_t used = 0;
        int rc;

        request_reset(&c->req);
        rc = proto_parse_request(c->in.data + pos, c->in.len - pos, &c->req,
                                 &used, &lim, err, sizeof(err));
        if (rc == PARSE_INCOMPLETE)
            break;
        if (rc == PARSE_ERROR) {
            reply_error(&c->out, "ERR Protocol error: %s", err);
            c->flags |= CLIENT_CLOSE_AFTER_REPLY;
            log_debug("protocol error from client %llu (%s): %s",
                      (unsigned long long)c->id, c->addr, err);
            break;
        }
        pos += used;
        if (c->req.argc > 0) {
            command_dispatch(srv, c, &c->req);
            srv->total_commands++;
        }
        request_reset(&c->req);
        if (c->out.len > MAX_PENDING_OUTPUT) {
            log_warn("client %llu (%s) exceeded the output limit; closing",
                     (unsigned long long)c->id, c->addr);
            c->flags |= CLIENT_CLOSE_AFTER_REPLY;
            sbuf_reset(&c->out);
            c->out_pos = 0;
        }
    }
    sbuf_consume(&c->in, pos);

    if (c->in.len > srv->cfg.max_request_bytes) {
        reply_error(&c->out, "ERR Protocol error: request too large");
        c->flags |= CLIENT_CLOSE_AFTER_REPLY;
        sbuf_reset(&c->in);
    }
}

static void client_handle_readable(struct server *srv, struct client *c)
{
    ssize_t n = net_read_into(c->fd, &c->in, READ_CHUNK);

    if (n == 0) {
        client_free(srv, c);
        log_debug("client %llu closed the connection",
                  (unsigned long long)c->id);
        return;
    }
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            return;
        log_info("read error from client %llu (%s): %s",
                 (unsigned long long)c->id, c->addr, strerror(errno));
        client_free(srv, c);
        return;
    }

    srv->net_in_bytes += (uint64_t)n;
    c->last_active_ms = now_ms();
    client_process_input(srv, c);
    if (client_has_output(c) || (c->flags & CLIENT_CLOSE_AFTER_REPLY))
        client_write(srv, c);
}

static void accept_clients(struct server *srv)
{
    static const char too_many[] = "-ERR max number of clients reached\r\n";
    char addr[64];

    for (int i = 0; i < MAX_ACCEPTS_PER_TICK; i++) {
        int fd = net_accept(srv->listen_fd, addr, sizeof(addr));
        if (fd < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK)
                log_warn("accept: %s", strerror(errno));
            return;
        }
        if (srv->nclients >= (size_t)srv->cfg.max_clients) {
            (void)net_write_some(fd, too_many, sizeof(too_many) - 1);
            close(fd);
            srv->rejected_connections++;
            continue;
        }
        struct client *c = client_create(srv, fd, addr);
        srv->total_connections++;
        log_debug("accepted client %llu from %s",
                  (unsigned long long)c->id, addr);
    }
}

/* ------------------------------------------------------------------------
 * INFO
 * ------------------------------------------------------------------------ */

static const char *fmt_duration(uint64_t ms)
{
    char buf[48];
    uint64_t s = ms / 1000;

    snprintf(buf, sizeof(buf), "%llud %02lluh %02llum %02llus",
             (unsigned long long)(s / 86400),
             (unsigned long long)(s / 3600 % 24),
             (unsigned long long)(s / 60 % 60),
             (unsigned long long)(s % 60));
    return buf;
}

static const char *policy_name(int policy)
{
    switch (policy) {
    case EVICT_NONE: return "noeviction";
    case EVICT_ALLKEYS_LRU: return "allkeys-lru";
    case EVICT_VOLATILE_TTL: return "volatile-ttl";
    default: return "unknown";
    }
}

static int want_section(const char *section, const char *name)
{
    if (section == NULL || strcasecmp(section, "default") == 0 ||
        strcasecmp(section, "all") == 0 ||
        strcasecmp(section, "everything") == 0)
        return 1;
    return strcasecmp(section, name) == 0;
}

void server_info(struct server *srv, sbuf *out, const char *section)
{
    struct store *db = srv->db;
    uint64_t now = now_ms();
    int verbose = section != NULL && strcasecmp(section, "everything") == 0;
    char human[32];

    if (want_section(section, "server")) {
        sbuf_appendf(out, "# Server\r\n");
        sbuf_appendf(out, "tinykv_version:%s\r\n", TKV_VERSION);
        sbuf_appendf(out, "process_id:%ld\r\n", (long)getpid());
        sbuf_appendf(out, "tcp_port:%d\r\n", srv->cfg.port);
        sbuf_appendf(out, "uptime_in_seconds:%llu\r\n",
                     (unsigned long long)((now - srv->start_ms) / 1000));
        sbuf_appendf(out, "uptime:%s\r\n", fmt_duration(now - srv->start_ms));
        sbuf_appendf(out, "config_file:%s\r\n",
                     srv->config_path ? srv->config_path : "");
        sbuf_appendf(out, "\r\n");
    }

    if (want_section(section, "clients")) {
        sbuf_appendf(out, "# Clients\r\n");
        sbuf_appendf(out, "connected_clients:%zu\r\n", srv->nclients);
        sbuf_appendf(out, "maxclients:%d\r\n", srv->cfg.max_clients);
        sbuf_appendf(out, "\r\n");
    }

    if (want_section(section, "memory")) {
        sbuf_appendf(out, "# Memory\r\n");
        fmt_bytes(human, sizeof(human), db->used_bytes);
        sbuf_appendf(out, "used_memory:%zu\r\n", db->used_bytes);
        sbuf_appendf(out, "used_memory_human:%s\r\n", human);
        fmt_bytes(human, sizeof(human), db->max_bytes);
        sbuf_appendf(out, "maxmemory:%zu\r\n", db->max_bytes);
        sbuf_appendf(out, "maxmemory_human:%s\r\n", human);
        sbuf_appendf(out, "maxmemory_policy:%s\r\n", policy_name(db->policy));
        sbuf_appendf(out, "\r\n");
    }

    if (want_section(section, "persistence")) {
        sbuf_appendf(out, "# Persistence\r\n");
        sbuf_appendf(out, "loading:%d\r\n", srv->loading);
        sbuf_appendf(out, "changes_since_last_save:%llu\r\n",
                     (unsigned long long)db->dirty);
        sbuf_appendf(out, "last_save_time:%llu\r\n",
                     (unsigned long long)(srv->last_save_ms / 1000));
        sbuf_appendf(out, "aof_enabled:%d\r\n", srv->aof != NULL);
        if (srv->aof != NULL) {
            sbuf_appendf(out, "aof_current_size:%llu\r\n",
                         (unsigned long long)srv->aof->size);
            sbuf_appendf(out, "aof_pending_bytes:%zu\r\n",
                         srv->aof->pending.len);
        }
        sbuf_appendf(out, "\r\n");
    }

    if (want_section(section, "stats")) {
        sbuf_appendf(out, "# Stats\r\n");
        sbuf_appendf(out, "total_connections_received:%llu\r\n",
                     (unsigned long long)srv->total_connections);
        sbuf_appendf(out, "total_commands_processed:%llu\r\n",
                     (unsigned long long)srv->total_commands);
        sbuf_appendf(out, "total_net_input_bytes:%llu\r\n",
                     (unsigned long long)srv->net_in_bytes);
        sbuf_appendf(out, "total_net_output_bytes:%llu\r\n",
                     (unsigned long long)srv->net_out_bytes);
        sbuf_appendf(out, "rejected_connections:%llu\r\n",
                     (unsigned long long)srv->rejected_connections);
        sbuf_appendf(out, "expired_keys:%llu\r\n",
                     (unsigned long long)db->stats.expired);
        sbuf_appendf(out, "evicted_keys:%llu\r\n",
                     (unsigned long long)db->stats.evicted);
        sbuf_appendf(out, "keyspace_hits:%llu\r\n",
                     (unsigned long long)db->stats.hits);
        sbuf_appendf(out, "keyspace_misses:%llu\r\n",
                     (unsigned long long)db->stats.misses);
        sbuf_appendf(out, "\r\n");
    }

    if (want_section(section, "keyspace")) {
        size_t nkeys = store_count(db);

        sbuf_appendf(out, "# Keyspace\r\n");
        if (nkeys > 0 || verbose) {
            sbuf_appendf(out, "db0:keys=%zu,expires=%zu", nkeys,
                         ttlheap_len(&db->ttl));
            if (verbose)
                sbuf_appendf(out, ",avg_size=%zu", db->used_bytes / nkeys);
            sbuf_appendf(out, "\r\n");
        }
    }
}

/* ------------------------------------------------------------------------
 * Persistence glue
 * ------------------------------------------------------------------------ */

int server_save_snapshot(struct server *srv)
{
    char err[256];
    char *path = config_data_path(&srv->cfg, srv->cfg.snapshot_file);
    int rc;

    rc = snapshot_save(srv->db, path, err, sizeof(err));
    if (rc == 0) {
        srv->last_save_ms = now_ms();
        srv->db->dirty = 0;
    } else {
        log_error("snapshot failed: %s", err);
    }
    free(path);
    return rc;
}

// Expired and evicted keys are written to the AOF as DEL so that a replay
// doesn't resurrect them.
static void on_key_removed(void *ctx, const char *key, size_t keylen,
                           int reason)
{
    struct server *srv = ctx;
    char del[] = "DEL";
    char *argv[2];
    size_t lens[2];

    if (srv->aof == NULL || srv->loading)
        return;
    argv[0] = del;
    argv[1] = (char *)key;
    lens[0] = 3;
    lens[1] = keylen;
    aof_append(srv->aof, 2, argv, lens);
}

struct replay_ctx {
    struct server *srv;
    struct client *fake;
};

static int replay_apply(void *arg, struct request *req)
{
    struct replay_ctx *rc = arg;
    int failed;

    command_dispatch(rc->srv, rc->fake, req);
    failed = rc->fake->out.len > 0 && rc->fake->out.data[0] == '-';
    if (failed)
        log_warn("AOF replay: %s: %.*s", req->argv[0],
                 (int)strcspn(rc->fake->out.data, "\r\n"),
                 rc->fake->out.data);
    sbuf_reset(&rc->fake->out);
    return 0;
}

static int load_data(struct server *srv)
{
    char err[256];
    char *path;

    srv->loading = 1;
    if (srv->cfg.aof_enabled) {
        struct replay_ctx rc;
        long n;

        path = config_data_path(&srv->cfg, srv->cfg.aof_file);
        rc.srv = srv;
        rc.fake = client_create_fake(srv);
        n = aof_replay(path, replay_apply, &rc, err, sizeof(err));
        client_free(srv, rc.fake);
        if (n < 0) {
            log_error("cannot load AOF: %s", err);
            free(path);
            srv->loading = 0;
            return -1;
        }
        log_info("replayed %ld commands from %s", n, path);
        free(path);
    } else {
        path = config_data_path(&srv->cfg, srv->cfg.snapshot_file);
        if (snapshot_load(srv->db, path, err, sizeof(err)) < 0) {
            log_error("cannot load snapshot: %s", err);
            free(path);
            srv->loading = 0;
            return -1;
        }
        free(path);
    }
    srv->db->dirty = 0;
    srv->loading = 0;
    return 0;
}

/* ------------------------------------------------------------------------
 * Cron
 * ------------------------------------------------------------------------ */

static void close_idle_clients(struct server *srv, uint64_t now)
{
    uint64_t limit = (uint64_t)srv->cfg.idle_timeout_sec * 1000;

    if (limit == 0)
        return;
    // Walk backwards: client_free moves the last client into the freed slot.
    for (size_t i = srv->nclients; i > 0; i--) {
        struct client *c = srv->clients[i - 1];
        if (now - c->last_active_ms > limit && !client_has_output(c)) {
            log_debug("closing idle client %llu (%s)",
                      (unsigned long long)c->id, c->addr);
            client_free(srv, c);
        }
    }
}

static void server_cron(struct server *srv, uint64_t now)
{
    store_expire_cycle(srv->db, now, EXPIRE_WORK_PER_TICK);
    close_idle_clients(srv, now);

    if (srv->aof != NULL)
        aof_flush(srv->aof, now);

    if (srv->cfg.save_interval_sec > 0 &&
        srv->db->dirty >= (uint64_t)srv->cfg.save_min_changes &&
        now - srv->last_save_ms >= (uint64_t)srv->cfg.save_interval_sec * 1000)
        server_save_snapshot(srv);

    if (got_reopen_signal) {
        got_reopen_signal = 0;
        if (log_reopen() < 0)
            log_warn("could not reopen the log file");
    }
}

/* ------------------------------------------------------------------------
 * Event loop
 * ------------------------------------------------------------------------ */

static void run_event_loop(struct server *srv)
{
    struct pollfd *pfds = NULL;
    uint64_t *ids = NULL;
    size_t cap = 0;
    uint64_t next_cron = now_ms();

    while (!srv->shutdown_requested && !got_shutdown_signal) {
        size_t n = srv->nclients + 1;
        uint64_t now;
        int timeout, rc;

        if (n > cap) {
            cap = n * 2;
            pfds = xrealloc(pfds, cap * sizeof(*pfds));
            ids = xrealloc(ids, cap * sizeof(*ids));
        }
        pfds[0].fd = srv->listen_fd;
        pfds[0].events = POLLIN;
        pfds[0].revents = 0;
        for (size_t i = 0; i < srv->nclients; i++) {
            struct client *c = srv->clients[i];
            pfds[i + 1].fd = c->fd;
            pfds[i + 1].events = POLLIN;
            if (client_has_output(c))
                pfds[i + 1].events |= POLLOUT;
            pfds[i + 1].revents = 0;
            ids[i + 1] = c->id;
        }

        now = now_ms();
        timeout = next_cron > now ? (int)(next_cron - now) : 0;
        rc = poll(pfds, (nfds_t)n, timeout);
        if (rc < 0 && errno != EINTR) {
            log_error("poll: %s", strerror(errno));
            break;
        }

        if (rc > 0) {
            if (pfds[0].revents & POLLIN)
                accept_clients(srv);
            for (size_t i = 1; i < n; i++) {
                struct client *c;
                if (pfds[i].revents == 0)
                    continue;
                // An earlier client's command may have closed this one.
                c = server_find_client(srv, ids[i]);
                if (c == NULL)
                    continue;
                if (pfds[i].revents & (POLLIN | POLLHUP | POLLERR)) {
                    client_handle_readable(srv, c);
                    c = server_find_client(srv, ids[i]);
                    if (c == NULL)
                        continue;
                }
                if ((pfds[i].revents & POLLOUT) && client_has_output(c))
                    client_write(srv, c);
            }
        }

        now = now_ms();
        if (now >= next_cron) {
            server_cron(srv, now);
            next_cron = now + CRON_INTERVAL_MS;
        }
    }
    free(pfds);
    free(ids);
}

/* ------------------------------------------------------------------------
 * Startup and shutdown
 * ------------------------------------------------------------------------ */

static void handle_signal(int sig)
{
    if (sig == SIGHUP)
        got_reopen_signal = 1;
    else
        got_shutdown_signal = 1;
}

static void install_signal_handlers(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);
}

static void usage(FILE *fp, const char *prog)
{
    fprintf(fp,
            "Usage: %s [config-file] [--option value ...]\n"
            "       %s --test-config [config-file]\n"
            "       %s --version | --help\n"
            "\n"
            "Any config file option can be given on the command line, e.g.\n"
            "  %s --port 7000 --loglevel debug --maxmemory 64mb\n",
            prog, prog, prog, prog);
}

static int ensure_data_dir(const char *dir)
{
    struct stat st;

    if (stat(dir, &st) == 0)
        return S_ISDIR(st.st_mode) ? 0 : -1;
    if (errno != ENOENT)
        return -1;
    return mkdir(dir, 0755);
}

static void server_shutdown(struct server *srv)
{
    log_info("shutting down");
    if (srv->cfg.save_interval_sec > 0 && srv->db->dirty > 0)
        server_save_snapshot(srv);
    if (srv->aof != NULL) {
        aof_close(srv->aof);
        srv->aof = NULL;
    }
    while (srv->nclients > 0)
        client_free(srv, srv->clients[srv->nclients - 1]);
    free(srv->clients);
    srv->clients = NULL;
    if (srv->listen_fd >= 0)
        close(srv->listen_fd);
    store_destroy(srv->db);
    srv->db = NULL;
}

int main(int argc, char **argv)
{
    static struct server srv;
    char err[256];
    int test_config = 0;
    int i = 1;

    config_set_defaults(&srv.cfg);
    srv.listen_fd = -1;

    if (i < argc && (strcmp(argv[i], "--help") == 0 ||
                     strcmp(argv[i], "-h") == 0)) {
        usage(stdout, argv[0]);
        return 0;
    }
    if (i < argc && (strcmp(argv[i], "--version") == 0 ||
                     strcmp(argv[i], "-v") == 0)) {
        printf("tinykv-server %s\n", TKV_VERSION);
        return 0;
    }
    if (i < argc && strcmp(argv[i], "--test-config") == 0) {
        test_config = 1;
        i++;
    }
    if (i < argc && strncmp(argv[i], "--", 2) != 0) {
        srv.config_path = argv[i++];
        if (config_load_file(&srv.cfg, srv.config_path, err,
                             sizeof(err)) < 0) {
            fprintf(stderr, "error: %s\n", err);
            return 1;
        }
    }
    for (; i < argc; i += 2) {
        if (strncmp(argv[i], "--", 2) != 0 || i + 1 >= argc) {
            usage(stderr, argv[0]);
            return 1;
        }
        if (config_set(&srv.cfg, argv[i] + 2, argv[i + 1], err,
                       sizeof(err)) < 0) {
            fprintf(stderr, "error: %s\n", err);
            return 1;
        }
    }
    if (config_validate(&srv.cfg, err, sizeof(err)) < 0) {
        fprintf(stderr, "error: %s\n", err);
        return 1;
    }
    if (test_config) {
        printf("configuration OK\n");
        config_free(&srv.cfg);
        return 0;
    }

    if (log_open(srv.cfg.log_file, srv.cfg.log_level) < 0) {
        fprintf(stderr, "error: cannot open log file %s: %s\n",
                srv.cfg.log_file, strerror(errno));
        return 1;
    }
    install_signal_handlers();
    srv.start_ms = now_ms();
    srv.last_save_ms = srv.start_ms;

    if (ensure_data_dir(srv.cfg.data_dir) < 0) {
        log_error("data directory %s is not usable: %s", srv.cfg.data_dir,
                  strerror(errno));
        return 1;
    }

    srv.db = store_create((size_t)srv.cfg.max_memory,
                          srv.cfg.eviction_policy, srv.cfg.evict_samples);
    srv.db->on_remove = on_key_removed;
    srv.db->on_remove_ctx = &srv;

    if (load_data(&srv) < 0)
        return 1;

    if (srv.cfg.aof_enabled) {
        char *path = config_data_path(&srv.cfg, srv.cfg.aof_file);
        srv.aof = aof_open(path, srv.cfg.aof_fsync, err, sizeof(err));
        free(path);
        if (srv.aof == NULL) {
            log_error("cannot open AOF: %s", err);
            return 1;
        }
    }

    srv.listen_fd = net_listen(srv.cfg.bind_addr, srv.cfg.port,
                               srv.cfg.tcp_backlog, err, sizeof(err));
    if (srv.listen_fd < 0) {
        log_error("cannot listen: %s", err);
        return 1;
    }
    log_info("tinykv %s ready on %s:%d (pid %ld, %zu keys)", TKV_VERSION,
             srv.cfg.bind_addr, srv.cfg.port, (long)getpid(),
             store_count(srv.db));

    run_event_loop(&srv);

    server_shutdown(&srv);
    config_free(&srv.cfg);
    log_close();
    return 0;
}
