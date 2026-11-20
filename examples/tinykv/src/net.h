// net.h - socket helpers.
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
#ifndef TKV_NET_H
#define TKV_NET_H

#include <stddef.h>
#include <sys/types.h>

#include "sbuf.h"

// Each returns a file descriptor, or -1 with a message in err.
int net_listen(const char *addr, int port, int backlog, char *err,
               size_t errlen);
int net_connect(const char *host, int port, int timeout_ms, char *err,
                size_t errlen);

// Accept a connection.  Writes "ip:port" into addrbuf.  Returns the new fd,
// or -1 (errno is EAGAIN when there is nothing to accept).
int net_accept(int lfd, char *addrbuf, size_t addrlen);
int net_set_nonblock(int fd);
int net_set_nodelay(int fd);

// Read up to max bytes into b.  Returns bytes read, 0 on EOF, -1 on error
// (with errno EAGAIN when nothing is available).
ssize_t net_read_into(int fd, sbuf *b, size_t max);
// Write as much as possible without blocking.  Returns bytes written or -1.
ssize_t net_write_some(int fd, const char *p, size_t n);
// Blocking write of all n bytes.  Returns 0 or -1.
int net_write_all(int fd, const void *p, size_t n);

// Format a sockaddr as "ip:port".
struct sockaddr;
void net_format_addr(const struct sockaddr *sa, char *buf, size_t len);

#endif
