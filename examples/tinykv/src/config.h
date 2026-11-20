// config.h - server configuration: defaults, config file, CONFIG GET/SET.
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
#ifndef TKV_CONFIG_H
#define TKV_CONFIG_H

#include <stddef.h>
#include "sbuf.h"

enum evict_policy {
    EVICT_NONE,          // reject writes when over max_memory
    EVICT_ALLKEYS_LRU,   // evict approximately least recently used keys
    EVICT_VOLATILE_TTL   // evict keys with the nearest expiry first
};

enum aof_fsync {
    AOF_FSYNC_NO,
    AOF_FSYNC_EVERYSEC,
    AOF_FSYNC_ALWAYS
};

struct tkv_config {
    char *bind_addr;
    int port;
    int max_clients;
    int tcp_backlog;
    int idle_timeout_sec;          // 0 = never

    unsigned long long max_memory; // 0 = unlimited
    int eviction_policy;           // enum evict_policy
    int evict_samples;             // keys sampled per eviction, >= 1

    char *data_dir;
    char *snapshot_file;           // relative to data_dir
    int save_interval_sec;         // 0 = no periodic snapshots
    int save_min_changes;

    int aof_enabled;
    char *aof_file;                // relative to data_dir
    int aof_fsync;                 // enum aof_fsync

    char *log_file;                // NULL = stderr
    int log_level;                 // enum log_level

    char *requirepass;             // NULL = no AUTH needed

    size_t max_request_bytes;      // limit on one buffered request
    size_t max_bulk_len;           // limit on one argument
    int max_args;                  // limit on argc
};

void config_set_defaults(struct tkv_config *cfg);
void config_free(struct tkv_config *cfg);

// Each returns 0 on success, -1 on error with a message in err.
int config_load_file(struct tkv_config *cfg, const char *path,
                     char *err, size_t errlen);
int config_set(struct tkv_config *cfg, const char *name, const char *value,
               char *err, size_t errlen);
int config_validate(const struct tkv_config *cfg, char *err, size_t errlen);

// Append the current value of option `name` to out, formatted as it would
// appear in a config file.  Returns 0, or -1 for an unknown option.
int config_get(const struct tkv_config *cfg, const char *name, sbuf *out);

// Fill names[] with up to max option names; returns the total count.
size_t config_option_names(const char **names, size_t max);
// Nonzero if the option can be changed at runtime with CONFIG SET.
int config_is_mutable(const char *name);

// Join data_dir and a file name into a newly allocated path.
char *config_data_path(const struct tkv_config *cfg, const char *file);

#endif
