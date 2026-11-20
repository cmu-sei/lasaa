// net.c - socket helpers: listening, connecting, nonblocking I/O.
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
#include "net.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "util.h"

static void set_err(char *err, size_t errlen, const char *what, int errnum)
{
    if (err != NULL && errlen > 0)
        snprintf(err, errlen, "%s: %s", what, strerror(errnum));
}

// Fill *ss from a numeric IPv4 or IPv6 address.  "*" and "" mean any IPv4
// address; "::" means any IPv6 address.
static int parse_bind_addr(const char *addr, int port,
                           struct sockaddr_storage *ss, socklen_t *sslen)
{
    memset(ss, 0, sizeof(*ss));
    if (addr == NULL || addr[0] == '\0' || strcmp(addr, "*") == 0)
        addr = "0.0.0.0";

    if (strchr(addr, ':') != NULL) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons((uint16_t)port);
        if (inet_pton(AF_INET6, addr, &sin6->sin6_addr) != 1)
            return -1;
        *sslen = sizeof(*sin6);
    } else {
        struct sockaddr_in *sin = (struct sockaddr_in *)ss;
        sin->sin_family = AF_INET;
        sin->sin_port = htons((uint16_t)port);
        if (inet_pton(AF_INET, addr, &sin->sin_addr) != 1)
            return -1;
        *sslen = sizeof(*sin);
    }
    return 0;
}

int net_listen(const char *addr, int port, int backlog, char *err,
               size_t errlen)
{
    struct sockaddr_storage ss;
    socklen_t sslen = 0;
    int fd;
    int on = 1;

    if (port <= 0 || port > 65535) {
        snprintf(err, errlen, "invalid port %d", port);
        return -1;
    }
    if (parse_bind_addr(addr, port, &ss, &sslen) != 0) {
        snprintf(err, errlen, "invalid bind address '%s'", addr);
        return -1;
    }

    fd = socket(ss.ss_family, SOCK_STREAM, 0);
    if (fd < 0) {
        set_err(err, errlen, "socket", errno);
        return -1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        set_err(err, errlen, "setsockopt(SO_REUSEADDR)", errno);
        close(fd);
        return -1;
    }
    if (bind(fd, (struct sockaddr *)&ss, sslen) < 0) {
        snprintf(err, errlen, "bind %s:%d: %s", addr ? addr : "*", port,
                 strerror(errno));
        return -1;
    }
    if (listen(fd, backlog > 0 ? backlog : 128) < 0) {
        set_err(err, errlen, "listen", errno);
        close(fd);
        return -1;
    }
    if (net_set_nonblock(fd) < 0) {
        set_err(err, errlen, "fcntl(O_NONBLOCK)", errno);
        close(fd);
        return -1;
    }
    return fd;
}

// Wait for a nonblocking connect() to finish.  Returns 0 on success, or -1
// with errno set.
static int wait_connected(int fd, int timeout_ms)
{
    struct pollfd pfd;
    int soerr = 0;
    socklen_t len = sizeof(soerr);
    int rc;

    pfd.fd = fd;
    pfd.events = POLLOUT;
    pfd.revents = 0;
    do {
        rc = poll(&pfd, 1, timeout_ms > 0 ? timeout_ms : -1);
    } while (rc < 0 && errno == EINTR);
    if (rc < 0)
        return -1;
    if (rc == 0) {
        errno = ETIMEDOUT;
        return -1;
    }
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &len) < 0)
        return -1;
    if (soerr != 0) {
        errno = soerr;
        return -1;
    }
    return 0;
}

int net_connect(const char *host, int port, int timeout_ms, char *err,
                size_t errlen)
{
    struct addrinfo hints, *res = NULL, *ai;
    char portstr[16];
    int fd = -1;
    int last_errno = 0;
    int rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof(portstr), "%d", port);

    rc = getaddrinfo(host, portstr, &hints, &res);
    if (rc != 0) {
        snprintf(err, errlen, "%s: %s", host, gai_strerror(rc));
        return -1;
    }

    for (ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            last_errno = errno;
            continue;
        }
        if (net_set_nonblock(fd) == 0) {
            rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
            if (rc == 0 ||
                (errno == EINPROGRESS && wait_connected(fd, timeout_ms) == 0)) {
                int flags = fcntl(fd, F_GETFL);
                if (flags >= 0)
                    fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
                break;
            }
        }
        last_errno = errno;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0) {
        snprintf(err, errlen, "connect %s:%d: %s", host, port,
                 strerror(last_errno ? last_errno : ECONNREFUSED));
        return -1;
    }
    return fd;
}

void net_format_addr(const struct sockaddr *sa, char *buf, size_t len)
{
    char ip[INET6_ADDRSTRLEN];

    if (len == 0)
        return;
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;
        if (inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip)) == NULL)
            str_lcpy(ip, "?", sizeof(ip));
        snprintf(buf, len, "%s:%u", ip, (unsigned)ntohs(sin->sin_port));
    } else if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)sa;
        if (inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip)) == NULL)
            str_lcpy(ip, "?", sizeof(ip));
        snprintf(buf, len, "[%s]:%u", ip, (unsigned)ntohs(sin6->sin6_port));
    } else {
        snprintf(buf, len, "unknown");
    }
}

int net_accept(int lfd, char *addrbuf, size_t addrlen)
{
    struct sockaddr_storage ss;
    socklen_t sslen = sizeof(ss);
    int fd;

    do {
        fd = accept(lfd, (struct sockaddr *)&ss, &sslen);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0)
        return -1;

    if (net_set_nonblock(fd) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    net_set_nodelay(fd);
    if (addrbuf != NULL)
        net_format_addr((struct sockaddr *)&ss, addrbuf, addrlen);
    return fd;
}

int net_set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL);

    if (flags < 0)
        return -1;
    if (flags & O_NONBLOCK)
        return 0;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int net_set_nodelay(int fd)
{
    int on = 1;

    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
}

ssize_t net_read_into(int fd, sbuf *b, size_t max)
{
    ssize_t n;

    if (max == 0)
        return 0;
    if (sbuf_reserve(b, max) < 0) {
        errno = ENOMEM;
        return -1;
    }
    do {
        n = read(fd, b->data + b->len, max);
    } while (n < 0 && errno == EINTR);
    if (n > 0) {
        b->len += (size_t)n;
        b->data[b->len] = '\0';
    }
    return n;
}

ssize_t net_write_some(int fd, const char *p, size_t n)
{
    size_t done = 0;

    while (done < n) {
        ssize_t w = write(fd, p + done, n - done);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            return -1;
        }
        if (w == 0)
            break;
        done += (size_t)w;
    }
    return (ssize_t)done;
}

int net_write_all(int fd, const void *p, size_t n)
{
    const char *cp = p;

    while (n > 0) {
        ssize_t w = write(fd, cp, n);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct pollfd pfd = { fd, POLLOUT, 0 };
                if (poll(&pfd, 1, -1) < 0 && errno != EINTR)
                    return -1;
                continue;
            }
            return -1;
        }
        cp += w;
        n -= (size_t)w;
    }
    return 0;
}
