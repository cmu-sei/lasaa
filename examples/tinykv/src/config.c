// config.c - server configuration: defaults, config file, CONFIG GET/SET.
//
// The config file has one directive per line:
//
//     # comment
//     port 7379
//     dir "/var/lib/tinykv"
//     include /etc/tinykv/local.conf
//
// Values may be quoted with double quotes, in which case the escapes \n, \r,
// \t, \", \\, and \xHH are recognized.
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
#include "config.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "log.h"
#include "util.h"

#define MAX_LINE 1024
#define MAX_INCLUDE_DEPTH 8

enum opt_type {
    OPT_STR,
    OPT_INT,
    OPT_ULL_SIZE,
    OPT_SIZE,
    OPT_BOOL,
    OPT_ENUM,
    OPT_LOGLEVEL
};

enum opt_flags {
    OPT_MUTABLE = 1 << 0,   // may be changed with CONFIG SET
    OPT_NULLABLE = 1 << 1,  // an empty string means "unset"
    OPT_SECRET = 1 << 2,    // never shown by CONFIG GET
    OPT_FILENAME = 1 << 3   // a bare file name, no directories
};

struct enum_name {
    const char *name;
    int value;
};

struct option {
    const char *name;
    int type;
    size_t offset;
    long long min, max;
    const struct enum_name *enums;
    int flags;
};

static const struct enum_name policy_names[] = {
    { "noeviction", EVICT_NONE },
    { "allkeys-lru", EVICT_ALLKEYS_LRU },
    { "volatile-ttl", EVICT_VOLATILE_TTL },
    { NULL, 0 }
};

static const struct enum_name fsync_names[] = {
    { "no", AOF_FSYNC_NO },
    { "everysec", AOF_FSYNC_EVERYSEC },
    { "always", AOF_FSYNC_ALWAYS },
    { NULL, 0 }
};

#define OFF(field) offsetof(struct tkv_config, field)

static const struct option options[] = {
    { "bind", OPT_STR, OFF(bind_addr), 0, 0, NULL, 0 },
    { "port", OPT_INT, OFF(port), 0, 65535, NULL, 0 },
    { "maxclients", OPT_INT, OFF(max_clients), 1, 100000, NULL, OPT_MUTABLE },
    { "tcp-backlog", OPT_INT, OFF(tcp_backlog), 1, 65535, NULL, 0 },
    { "timeout", OPT_INT, OFF(idle_timeout_sec), 0, INT_MAX, NULL, OPT_MUTABLE },
    { "maxmemory", OPT_ULL_SIZE, OFF(max_memory), 0, 0, NULL, OPT_MUTABLE },
    { "maxmemory-policy", OPT_ENUM, OFF(eviction_policy), 0, 0, policy_names,
      OPT_MUTABLE },
    { "maxmemory-samples", OPT_INT, OFF(evict_samples), 1, 64, NULL,
      OPT_MUTABLE },
    { "dir", OPT_STR, OFF(data_dir), 0, 0, NULL, 0 },
    { "dbfilename", OPT_STR, OFF(snapshot_file), 0, 0, NULL, OPT_FILENAME },
    { "save-interval", OPT_INT, OFF(save_interval_sec), 0, INT_MAX, NULL,
      OPT_MUTABLE },
    { "save-min-changes", OPT_INT, OFF(save_min_changes), 0, INT_MAX, NULL,
      OPT_MUTABLE },
    { "appendonly", OPT_BOOL, OFF(aof_enabled), 0, 1, NULL, 0 },
    { "appendfilename", OPT_STR, OFF(aof_file), 0, 0, NULL, OPT_FILENAME },
    { "appendfsync", OPT_ENUM, OFF(aof_fsync), 0, 0, fsync_names, OPT_MUTABLE },
    { "logfile", OPT_STR, OFF(log_file), 0, 0, NULL, OPT_NULLABLE },
    { "loglevel", OPT_LOGLEVEL, OFF(log_level), 0, 0, NULL, OPT_MUTABLE },
    { "requirepass", OPT_STR, OFF(requirepass), 0, 0, NULL,
      OPT_MUTABLE | OPT_NULLABLE | OPT_SECRET },
    { "max-request-bytes", OPT_SIZE, OFF(max_request_bytes), 1024, 0, NULL,
      OPT_MUTABLE },
    { "proto-max-bulk-len", OPT_SIZE, OFF(max_bulk_len), 1, 0, NULL,
      OPT_MUTABLE },
    { "max-args", OPT_INT, OFF(max_args), 1, 1024 * 1024, NULL, OPT_MUTABLE },
};

void config_set_defaults(struct tkv_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->bind_addr = xstrdup("127.0.0.1");
    cfg->port = 7379;
    cfg->max_clients = 1000;
    cfg->tcp_backlog = 128;
    cfg->idle_timeout_sec = 0;
    cfg->max_memory = 0;
    cfg->eviction_policy = EVICT_NONE;
    cfg->evict_samples = 5;
    cfg->data_dir = xstrdup(".");
    cfg->snapshot_file = xstrdup("dump.tkv");
    cfg->save_interval_sec = 300;
    cfg->save_min_changes = 1;
    cfg->aof_enabled = 0;
    cfg->aof_file = xstrdup("appendonly.aof");
    cfg->aof_fsync = AOF_FSYNC_EVERYSEC;
    cfg->log_file = NULL;
    cfg->log_level = LOG_INFO;
    cfg->requirepass = NULL;
    cfg->max_request_bytes = 64 * 1024 * 1024;
    cfg->max_bulk_len = 16 * 1024 * 1024;
    cfg->max_args = 64 * 1024;
}

void config_free(struct tkv_config *cfg)
{
    size_t i;

    for (i = 0; i < ARRAY_LEN(options); i++) {
        if (options[i].type == OPT_STR) {
            char **field = (char **)((char *)cfg + options[i].offset);
            free(*field);
            *field = NULL;
        }
    }
}

static const struct option *find_option(const char *name)
{
    size_t i;

    if (name == NULL || name[0] == '\0')
        return NULL;
    for (i = 0; i < ARRAY_LEN(options); i++) {
        if (strcasecmp(options[i].name, name) == 0)
            return &options[i];
    }
    return NULL;
}

static int parse_enum(const struct enum_name *names, const char *value,
                      int *out)
{
    const struct enum_name *e;

    for (e = names; e->name != NULL; e++) {
        if (strcasecmp(e->name, value) == 0) {
            *out = e->value;
            return 0;
        }
    }
    return -1;
}

static const char *enum_to_name(const struct enum_name *names, int value)
{
    const struct enum_name *e;

    for (e = names; e->name != NULL; e++) {
        if (e->value == value)
            return e->name;
    }
    return "unknown";
}

static void enum_choices(const struct enum_name *names, char *buf, size_t len)
{
    const struct enum_name *e;
    size_t used = 0;

    buf[0] = '\0';
    for (e = names; e->name != NULL && used < len; e++) {
        int n = snprintf(buf + used, len - used, "%s%s",
                         e == names ? "" : ", ", e->name);
        if (n < 0)
            break;
        used += (size_t)n;
    }
}

static int set_option(struct tkv_config *cfg, const struct option *o,
                      const char *value, char *err, size_t errlen)
{
    char *field = (char *)cfg + o->offset;
    long long n;
    unsigned long long u;
    int b, lvl;

    switch (o->type) {
    case OPT_STR: {
        char **sp = (char **)field;

        if ((o->flags & OPT_FILENAME) && (value[0] == '\0' ||
                                          strchr(value, '/') != NULL ||
                                          strcmp(value, "..") == 0)) {
            snprintf(err, errlen, "'%s' must be a plain file name", o->name);
            return -1;
        }
        free(*sp);
        if ((o->flags & OPT_NULLABLE) && value[0] == '\0')
            *sp = NULL;
        else
            *sp = xstrdup(value);
        return 0;
    }

    case OPT_INT:
        if (str_to_ll(value, strlen(value), &n) != 0 || n < o->min ||
            n > o->max) {
            snprintf(err, errlen, "'%s' must be an integer in [%lld, %lld]",
                     o->name, o->min, o->max);
            return -1;
        }
        *(int *)field = (int)n;
        return 0;

    case OPT_ULL_SIZE:
        if (parse_size(value, &u) != 0) {
            snprintf(err, errlen, "'%s' must be a size like 100mb", o->name);
            return -1;
        }
        *(unsigned long long *)field = u;
        return 0;

    case OPT_SIZE:
        if (parse_size(value, &u) != 0 || u < (unsigned long long)o->min ||
            u > SIZE_MAX) {
            snprintf(err, errlen, "'%s' must be a size of at least %lld",
                     o->name, o->min);
            return -1;
        }
        *(size_t *)field = (size_t)u;
        return 0;

    case OPT_BOOL:
        if (parse_bool(value, &b) != 0) {
            snprintf(err, errlen, "'%s' must be yes or no", o->name);
            return -1;
        }
        *(int *)field = b;
        return 0;

    case OPT_ENUM:
        if (parse_enum(o->enums, value, &b) != 0) {
            char choices[128];

            enum_choices(o->enums, choices, sizeof(choices));
            snprintf(err, errlen, "'%s' must be one of: %s", o->name, choices);
            return -1;
        }
        *(int *)field = b;
        return 0;

    case OPT_LOGLEVEL:
        lvl = log_level_from_name(value);
        if (lvl < 0) {
            if (str_to_ll(value, strlen(value), &n) != 0 || n < 0 ||
                n > LOG_NLEVELS) {
                snprintf(err, errlen,
                         "'%s' must be debug, info, warn, error, or 0-%d",
                         o->name, LOG_NLEVELS);
                return -1;
            }
            lvl = (int)n;
        }
        *(int *)field = lvl;
        return 0;
    }

    snprintf(err, errlen, "internal error: bad type for '%s'", o->name);
    return -1;
}

int config_set(struct tkv_config *cfg, const char *name, const char *value,
               char *err, size_t errlen)
{
    const struct option *o = find_option(name);

    if (o == NULL) {
        snprintf(err, errlen, "unknown option '%s'", name);
        return -1;
    }
    return set_option(cfg, o, value, err, errlen);
}

int config_is_mutable(const char *name)
{
    const struct option *o = find_option(name);

    return o != NULL && (o->flags & OPT_MUTABLE) != 0;
}

int config_get(const struct tkv_config *cfg, const char *name, sbuf *out)
{
    const struct option *o = find_option(name);
    const char *field;

    // Names used by releases before 1.2.
    if (o == NULL && strcasecmp(name, "log-level") == 0)
        o = find_option("loglevel");
    else if (o == NULL && strcasecmp(name, "data-dir") == 0)
        o = find_option("dir");

    if (o->flags & OPT_SECRET) {
        const char *const *sp = (const char *const *)((const char *)cfg +
                                                       o->offset);
        sbuf_append_str(out, *sp != NULL ? "********" : "");
        return 0;
    }
    if (o == NULL)
        return -1;

    field = (const char *)cfg + o->offset;
    switch (o->type) {
    case OPT_STR: {
        const char *s = *(const char *const *)field;

        sbuf_append_str(out, s != NULL ? s : "");
        return 0;
    }
    case OPT_INT:
        sbuf_appendf(out, "%d", *(const int *)field);
        return 0;
    case OPT_ULL_SIZE:
        sbuf_appendf(out, "%llu", *(const unsigned long long *)field);
        return 0;
    case OPT_SIZE:
        sbuf_appendf(out, "%zu", *(const size_t *)field);
        return 0;
    case OPT_BOOL:
        sbuf_append_str(out, *(const int *)field ? "yes" : "no");
        return 0;
    case OPT_ENUM:
        sbuf_append_str(out, enum_to_name(o->enums, *(const int *)field));
        return 0;
    case OPT_LOGLEVEL: {
        const char *lv = log_level_name(*(const int *)field);

        while (*lv != '\0')
            sbuf_append_char(out, (char)tolower((unsigned char)*lv++));
        return 0;
    }
    }
    return -1;
}

size_t config_option_names(const char **names, size_t max)
{
    size_t i;

    for (i = 0; i < ARRAY_LEN(options) && i < max; i++)
        names[i] = options[i].name;
    return ARRAY_LEN(options);
}

int config_validate(const struct tkv_config *cfg, char *err, size_t errlen)
{
    if (cfg->bind_addr == NULL || cfg->bind_addr[0] == '\0') {
        snprintf(err, errlen, "'bind' must not be empty");
        return -1;
    }
    if (cfg->data_dir == NULL || cfg->data_dir[0] == '\0') {
        snprintf(err, errlen, "'dir' must not be empty");
        return -1;
    }
    if (cfg->aof_enabled && strcmp(cfg->aof_file, cfg->snapshot_file) == 0) {
        snprintf(err, errlen,
                 "'appendfilename' and 'dbfilename' must be different");
        return -1;
    }
    if (cfg->max_bulk_len > cfg->max_request_bytes) {
        snprintf(err, errlen,
                 "'proto-max-bulk-len' exceeds 'max-request-bytes'");
        return -1;
    }
    if (cfg->eviction_policy != EVICT_NONE && cfg->max_memory == 0)
        log_warn("maxmemory-policy is set but maxmemory is 0 (unlimited)");
    return 0;
}

char *config_data_path(const struct tkv_config *cfg, const char *file)
{
    size_t dlen, flen;
    char *path;

    if (file[0] == '/')
        return xstrdup(file);
    dlen = strlen(cfg->data_dir);
    flen = strlen(file);
    while (dlen > 1 && cfg->data_dir[dlen - 1] == '/')
        dlen--;
    path = xmalloc(dlen + 1 + flen + 1);
    memcpy(path, cfg->data_dir, dlen);
    path[dlen] = '/';
    memcpy(path + dlen + 1, file, flen + 1);
    return path;
}

// ---- Config file parsing ----

static int hex_digit(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    c = tolower(c);
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return -1;
}

// Parse the value part of a directive: either a bare word (the rest of the
// line, already trimmed) or a double-quoted string with escapes.  On
// success, *out is a newly allocated string.
static int parse_value(const char *p, char **out, char *err, size_t errlen)
{
    char *val = xmalloc(strlen(p) + 1);
    char *o = val;

    if (*p != '"') {
        strcpy(val, p);
        *out = val;
        return 0;
    }

    p++;
    while (*p != '"') {
        if (*p == '\0') {
            snprintf(err, errlen, "unterminated quoted value");
            free(val);
            goto fail;
        }
        if (*p != '\\') {
            *o++ = *p++;
            continue;
        }
        p++;
        switch (*p) {
        case 'n': *o++ = '\n'; break;
        case 'r': *o++ = '\r'; break;
        case 't': *o++ = '\t'; break;
        case '"': *o++ = '"'; break;
        case '\\': *o++ = '\\'; break;
        case 'x': {
            int hi = hex_digit((unsigned char)p[1]);
            int lo = hi < 0 ? -1 : hex_digit((unsigned char)p[2]);

            if (lo < 0) {
                snprintf(err, errlen, "bad \\x escape in quoted value");
                goto fail;
            }
            *o++ = (char)(hi * 16 + lo);
            p += 2;
            break;
        }
        default:
            snprintf(err, errlen, "unknown escape '\\%c' in quoted value",
                     *p ? *p : '0');
            goto fail;
        }
        p++;
    }
    p++;

    while (isspace((unsigned char)*p))
        p++;
    if (*p != '\0') {
        snprintf(err, errlen, "unexpected text after closing quote");
        goto fail;
    }
    *o = '\0';
    *out = val;
    return 0;

fail:
    free(val);
    return -1;
}

// Resolve an include path relative to the directory of the including file.
static char *include_path(const char *parent, const char *path)
{
    const char *slash;
    size_t dlen;
    char *full;

    if (path[0] == '/' || (slash = strrchr(parent, '/')) == NULL)
        return xstrdup(path);
    dlen = (size_t)(slash - parent);
    full = xmalloc(dlen + 1 + strlen(path) + 1);
    memcpy(full, parent, dlen);
    full[dlen] = '/';
    strcpy(full + dlen + 1, path);
    return full;
}

static int load_file(struct tkv_config *cfg, const char *path, int depth,
                     char *err, size_t errlen);

// Handle one directive.  name and rest point into the line buffer.
static int apply_directive(struct tkv_config *cfg, const char *path,
                           int depth, char *name, char *rest,
                           char *err, size_t errlen)
{
    char *value = NULL;
    char msg[256];
    int rc;

    if (rest[0] == '\0') {
        snprintf(err, errlen, "missing value for '%s'", name);
        return -1;
    }
    if (parse_value(rest, &value, msg, sizeof(msg)) != 0) {
        snprintf(err, errlen, "%s", msg);
        return -1;
    }

    if (strcasecmp(name, "include") == 0) {
        char *inc = include_path(path, value);

        rc = load_file(cfg, inc, depth + 1, err, errlen);
        free(inc);
        free(value);
        return rc;
    }

    rc = config_set(cfg, name, value, msg, sizeof(msg));
    if (rc != 0)
        snprintf(err, errlen, "%s", msg);
    free(value);
    return rc;
}

static int load_file(struct tkv_config *cfg, const char *path, int depth,
                     char *err, size_t errlen)
{
    char line[MAX_LINE];
    char msg[512];
    FILE *fp;
    int lineno = 0;

    if (depth > MAX_INCLUDE_DEPTH) {
        snprintf(err, errlen, "%s: includes nested too deeply", path);
        return -1;
    }

    fp = fopen(path, "r");
    if (fp == NULL) {
        snprintf(err, errlen, "%s: %s", path, strerror(errno));
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        size_t len = strlen(line);
        char *p, *name;

        lineno++;
        if (len == sizeof(line) - 1 && line[len - 1] != '\n' && !feof(fp)) {
            snprintf(err, errlen, "%s:%d: line too long (max %d)", path,
                     lineno, MAX_LINE - 2);
            return -1;
        }

        p = str_trim(line);
        if (*p == '\0' || *p == '#')
            continue;

        name = p;
        while (*p != '\0' && !isspace((unsigned char)*p))
            p++;
        if (*p != '\0')
            *p++ = '\0';
        p = str_trim(p);

        if (apply_directive(cfg, path, depth, name, p, msg,
                            sizeof(msg)) != 0) {
            if (strcasecmp(name, "include") == 0)
                snprintf(err, errlen, "%s", msg);
            else
                snprintf(err, errlen, "%s:%d: %s", path, lineno, msg);
            goto fail;
        }
    }

    if (ferror(fp)) {
        snprintf(err, errlen, "%s: read error", path);
        goto fail;
    }
    fclose(fp);
    return 0;

fail:
    fclose(fp);
    return -1;
}

int config_load_file(struct tkv_config *cfg, const char *path,
                     char *err, size_t errlen)
{
    return load_file(cfg, path, 0, err, errlen);
}
