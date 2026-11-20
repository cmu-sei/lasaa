// server.h - server and client state shared by the event loop and commands.
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
#ifndef TKV_SERVER_H
#define TKV_SERVER_H

#include <stddef.h>
#include <stdint.h>

#include "config.h"
#include "protocol.h"
#include "sbuf.h"

struct store;
struct aof;

enum client_flags {
    CLIENT_CLOSE_AFTER_REPLY = 1 << 0,
    CLIENT_FAKE = 1 << 1,     // AOF replay: no socket, replies discarded
    CLIENT_MONITOR = 1 << 2
};

struct client {
    uint64_t id;
    int fd;                   // -1 for a fake client
    char addr[64];            // "ip:port"
    char *name;               // CLIENT SETNAME, or NULL
    int flags;
    int authed;
    sbuf in;                  // unparsed input
    sbuf out;                 // pending output
    size_t out_pos;           // bytes of out already written
    struct request req;
    uint64_t created_ms;
    uint64_t last_active_ms;
    uint64_t ncommands;
    const char *last_cmd;     // static name of the last command
};

struct server {
    struct tkv_config cfg;
    char *config_path;
    struct store *db;
    struct aof *aof;
    int listen_fd;

    struct client **clients;
    size_t nclients;
    size_t clients_cap;
    uint64_t next_client_id;

    uint64_t start_ms;
    uint64_t last_save_ms;
    uint64_t total_commands;
    uint64_t total_connections;
    uint64_t rejected_connections;
    uint64_t net_in_bytes;
    uint64_t net_out_bytes;
    int shutdown_requested;
    int loading;              // replaying the AOF
};

// server.c
struct client *client_create(struct server *srv, int fd, const char *addr);
void client_free(struct server *srv, struct client *c);
void server_info(struct server *srv, sbuf *out, const char *section);
int server_save_snapshot(struct server *srv);
struct client *server_find_client(struct server *srv, uint64_t id);

#endif
