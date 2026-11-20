// commands.h - command table and dispatch.
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
#ifndef TKV_COMMANDS_H
#define TKV_COMMANDS_H

#include <stddef.h>

struct server;
struct client;
struct request;

typedef void (*cmd_fn)(struct server *srv, struct client *c,
                       struct request *req);

enum cmd_flags {
    CMD_WRITE = 1 << 0,    // modifies the keyspace (propagated to the AOF)
    CMD_NOAUTH = 1 << 1,   // allowed before AUTH
    CMD_ADMIN = 1 << 2,
    CMD_DENY_LOADING = 1 << 3
};

struct command {
    const char *name;
    cmd_fn fn;
    int arity;      // >0: exact argc; <0: at least -arity
    int flags;
    const char *summary;
};

const struct command *command_lookup(const char *name, size_t len);
// Execute req for client c, writing the reply to c->out.  Also propagates
// write commands to the AOF.
void command_dispatch(struct server *srv, struct client *c,
                      struct request *req);
size_t command_count(void);
const struct command *command_at(size_t i);

#endif
