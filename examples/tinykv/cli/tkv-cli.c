// tkv-cli.c - command-line client for tinykv.
//
//     tkv-cli [-h host] [-p port] [-a password] [--raw] [cmd [arg ...]]
//
// With a command, sends it and prints the reply.  Without one, starts an
// interactive prompt.
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
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "net.h"
#include "protocol.h"
#include "sbuf.h"
#include "util.h"

#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT 6480
#define CONNECT_TIMEOUT_MS 5000
#define MAX_REPLY_DEPTH 32

struct cli {
    const char *host;
    int port;
    const char *password;
    int raw;            // print bulk strings verbatim, no quoting
    int fd;
    sbuf in;            // received but not yet parsed
};

/* ------------------------------------------------------------------------
 * Connection
 * ------------------------------------------------------------------------ */

static int cli_connect(struct cli *cli)
{
    char err[256];

    cli->fd = net_connect(cli->host, cli->port, CONNECT_TIMEOUT_MS, err,
                          sizeof(err));
    if (cli->fd < 0) {
        fprintf(stderr, "Could not connect to tinykv at %s:%d: %s\n",
                cli->host, cli->port, err);
        return -1;
    }
    sbuf_reset(&cli->in);
    return 0;
}

static void cli_disconnect(struct cli *cli)
{
    if (cli->fd >= 0) {
        close(cli->fd);
        cli->fd = -1;
    }
}

static int cli_send(struct cli *cli, int argc, char **argv,
                    const size_t *argvlen)
{
    sbuf out = SBUF_INIT;
    int rc;

    proto_encode_request(&out, argc, argv, argvlen);
    rc = net_write_all(cli->fd, out.data, out.len);
    sbuf_free(&out);
    if (rc < 0)
        fprintf(stderr, "Error writing to server: %s\n", strerror(errno));
    return rc;
}

// Read one complete reply.  Returns 0, or -1 on I/O or protocol error.
static int cli_read_reply(struct cli *cli, struct reply_val *r)
{
    for (;;) {
        size_t used = 0;
        int rc = PARSE_INCOMPLETE;

        if (cli->in.len > 0)
            rc = proto_parse_reply(cli->in.data, cli->in.len, r, &used, 0);
        if (rc == PARSE_OK) {
            sbuf_consume(&cli->in, used);
            return 0;
        }
        if (rc == PARSE_ERROR) {
            fprintf(stderr, "Protocol error in server reply\n");
            return -1;
        }

        ssize_t n = net_read_into(cli->fd, &cli->in, 16384);
        if (n == 0) {
            fprintf(stderr, "Server closed the connection\n");
            return -1;
        }
        if (n < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "Error reading from server: %s\n",
                    strerror(errno));
            return -1;
        }
    }
}

/* ------------------------------------------------------------------------
 * Output
 * ------------------------------------------------------------------------ */

static void print_quoted(FILE *fp, const char *s, size_t n)
{
    fputc('"', fp);
    for (size_t i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)s[i];
        switch (ch) {
        case '\\': fputs("\\\\", fp); break;
        case '"':  fputs("\\\"", fp); break;
        case '\n': fputs("\\n", fp); break;
        case '\r': fputs("\\r", fp); break;
        case '\t': fputs("\\t", fp); break;
        default:
            if (isprint(ch))
                fputc(ch, fp);
            else
                fprintf(fp, "\\x%02x", ch);
        }
    }
    fputc('"', fp);
}

static void print_reply(const struct cli *cli, const struct reply_val *r,
                        int indent)
{
    switch (r->type) {
    case RT_SIMPLE:
        fwrite(r->str, 1, r->len, stdout);
        break;
    case RT_ERROR:
        if (!cli->raw)
            fputs("(error) ", stdout);
        fwrite(r->str, 1, r->len, stdout);
        break;
    case RT_INT:
        printf(cli->raw ? "%lld" : "(integer) %lld", r->ival);
        break;
    case RT_NULL:
        if (!cli->raw)
            fputs("(nil)", stdout);
        break;
    case RT_BULK:
        if (cli->raw)
            fwrite(r->str, 1, r->len, stdout);
        else
            print_quoted(stdout, r->str, r->len);
        break;
    case RT_ARRAY:
        if (r->nelems == 0) {
            if (!cli->raw)
                fputs("(empty array)", stdout);
            break;
        }
        for (size_t i = 0; i < r->nelems; i++) {
            if (cli->raw) {
                print_reply(cli, &r->elems[i], 0);
            } else {
                // Width of the largest index, so nested items line up.
                int width = snprintf(NULL, 0, "%zu", r->nelems);
                if (i > 0)
                    printf("%*s", indent, "");
                printf("%*zu) ", width, i + 1);
                print_reply(cli, &r->elems[i], indent + width + 2);
            }
            if (i + 1 < r->nelems)
                fputc('\n', stdout);
        }
        break;
    default:
        printf("(unknown reply type %d)", r->type);
    }
}

/* ------------------------------------------------------------------------
 * Commands
 * ------------------------------------------------------------------------ */

// Send one command and print its reply.  Returns 0 on a non-error reply,
// 1 on an error reply, -1 on a connection problem.
static int cli_run_command(struct cli *cli, int argc, char **argv,
                           const size_t *argvlen)
{
    struct reply_val r;
    int status;

    if (cli->fd < 0 && cli_connect(cli) < 0)
        return -1;
    if (cli_send(cli, argc, argv, argvlen) < 0 ||
        cli_read_reply(cli, &r) < 0) {
        cli_disconnect(cli);
        return -1;
    }
    print_reply(cli, &r, 0);
    fputc('\n', stdout);
    fflush(stdout);
    status = r.type == RT_ERROR ? 1 : 0;
    reply_val_free(&r);
    return status;
}

static int cli_auth(struct cli *cli)
{
    char auth[] = "AUTH";
    char *argv[2];
    size_t lens[2];
    struct reply_val r;
    int ok;

    argv[0] = auth;
    argv[1] = (char *)cli->password;
    lens[0] = 4;
    lens[1] = strlen(cli->password);
    if (cli_send(cli, 2, argv, lens) < 0 || cli_read_reply(cli, &r) < 0)
        return -1;
    ok = r.type != RT_ERROR;
    if (!ok)
        fprintf(stderr, "AUTH failed: %.*s\n", (int)r.len, r.str);
    reply_val_free(&r);
    return ok ? 0 : -1;
}

/* ------------------------------------------------------------------------
 * Interactive mode
 * ------------------------------------------------------------------------ */

static int hex_value(int ch)
{
    if (ch >= '0' && ch <= '9')
        return ch - '0';
    ch = tolower(ch);
    if (ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;
    return -1;
}

// Split a command line into arguments.  Double quotes allow \n, \t, \",
// \\ and \xHH escapes; single quotes are literal except for \'.  Returns
// 0, or -1 for unbalanced quotes.
static int split_line(const char *line, struct request *req)
{
    const char *p = line;
    sbuf arg = SBUF_INIT;

    request_reset(req);
    for (;;) {
        while (isspace((unsigned char)*p))
            p++;
        if (*p == '\0')
            break;

        sbuf_reset(&arg);
        int in_dq = 0, in_sq = 0, done = 0;
        while (!done) {
            if (in_dq) {
                if (*p == '\0')
                    goto unbalanced;
                if (*p == '\\' && p[1] == 'x' && hex_value(p[2]) >= 0 &&
                    hex_value(p[3]) >= 0) {
                    sbuf_append_char(&arg,
                                     (char)(hex_value(p[2]) * 16 + hex_value(p[3])));
                    p += 4;
                } else if (*p == '\\' && p[1] != '\0') {
                    char c;
                    p++;
                    switch (*p) {
                    case 'n': c = '\n'; break;
                    case 'r': c = '\r'; break;
                    case 't': c = '\t'; break;
                    case 'a': c = '\a'; break;
                    case 'b': c = '\b'; break;
                    default: c = *p; break;
                    }
                    sbuf_append_char(&arg, c);
                    p++;
                } else if (*p == '"') {
                    // A closing quote must be followed by a space or the end.
                    if (p[1] != '\0' && !isspace((unsigned char)p[1]))
                        goto unbalanced;
                    done = 1;
                    p++;
                } else {
                    sbuf_append_char(&arg, *p++);
                }
            } else if (in_sq) {
                if (*p == '\0')
                    goto unbalanced;
                if (*p == '\\' && p[1] == '\'') {
                    sbuf_append_char(&arg, '\'');
                    p += 2;
                } else if (*p == '\'') {
                    if (p[1] != '\0' && !isspace((unsigned char)p[1]))
                        goto unbalanced;
                    done = 1;
                    p++;
                } else {
                    sbuf_append_char(&arg, *p++);
                }
            } else {
                switch (*p) {
                case ' ': case '\n': case '\r': case '\t': case '\0':
                    done = 1;
                    break;
                case '"':
                    in_dq = 1;
                    p++;
                    break;
                case '\'':
                    in_sq = 1;
                    p++;
                    break;
                default:
                    sbuf_append_char(&arg, *p++);
                }
            }
        }
        if (request_add_arg(req, arg.data ? arg.data : "", arg.len) < 0)
            goto unbalanced;
    }
    sbuf_free(&arg);
    return 0;

unbalanced:
    sbuf_free(&arg);
    request_reset(req);
    return -1;
}

static void print_help(void)
{
    puts("tkv-cli: type a command and its arguments, e.g.\n"
         "    SET greeting \"hello world\"\n"
         "    GET greeting\n"
         "Quote arguments with \"...\" (supports \\n \\t \\xHH) or '...'.\n"
         "Type COMMAND for the list of server commands, quit to exit.");
}

static int interactive(struct cli *cli)
{
    struct request req;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int tty = isatty(STDIN_FILENO);

    request_init(&req);
    for (;;) {
        if (tty) {
            if (cli->fd >= 0)
                printf("%s:%d> ", cli->host, cli->port);
            else
                printf("not connected> ");
            fflush(stdout);
        }
        n = getline(&line, &cap, stdin);
        if (n < 0)
            break;
        if (split_line(line, &req) < 0) {
            fprintf(stderr, "Invalid argument(s): unbalanced quotes\n");
            continue;
        }
        if (req.argc == 0)
            continue;
        if (strcasecmp(req.argv[0], "quit") == 0 ||
            strcasecmp(req.argv[0], "exit") == 0)
            break;
        if (strcasecmp(req.argv[0], "help") == 0 && req.argc == 1) {
            print_help();
            continue;
        }
        if (strcasecmp(req.argv[0], "connect") == 0 && req.argc >= 2) {
            long long port = cli->port;
            if (req.argc >= 3 &&
                (str_to_ll(req.argv[2], req.argvlen[2], &port) < 0 ||
                 port <= 0 || port > 65535)) {
                fprintf(stderr, "Invalid port\n");
                continue;
            }
            cli_disconnect(cli);
            // The host string must outlive req, which is reused per line.
            static char hostbuf[256];
            str_lcpy(hostbuf, req.argv[1], sizeof(hostbuf));
            cli->host = hostbuf;
            cli->port = (int)port;
            if (cli_connect(cli) == 0 && cli->password != NULL)
                cli_auth(cli);
            continue;
        }
        if (cli_run_command(cli, req.argc, req.argv, req.argvlen) < 0 &&
            cli->fd < 0) {
            // Connection lost: try once to reconnect for the next command.
            if (cli_connect(cli) == 0 && cli->password != NULL)
                cli_auth(cli);
        }
    }
    free(line);
    request_free(&req);
    if (tty)
        fputc('\n', stdout);
    return 0;
}

/* ------------------------------------------------------------------------
 * main
 * ------------------------------------------------------------------------ */

static void usage(FILE *fp)
{
    fprintf(fp,
            "Usage: tkv-cli [OPTIONS] [cmd [arg ...]]\n"
            "  -h <host>      Server hostname (default: %s)\n"
            "  -p <port>      Server port (default: %d)\n"
            "  -a <password>  Password for AUTH (or set TKV_PASSWORD)\n"
            "  --raw          Print raw replies (no quotes or type prefixes)\n"
            "  --help         Show this help\n",
            DEFAULT_HOST, DEFAULT_PORT);
}

int main(int argc, char **argv)
{
    struct cli cli;
    int i;
    int rc;

    memset(&cli, 0, sizeof(cli));
    cli.host = DEFAULT_HOST;
    cli.port = DEFAULT_PORT;
    cli.fd = -1;
    cli.password = getenv("TKV_PASSWORD");
    sbuf_init(&cli.in);

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        int has_next = i + 1 < argc;

        if (strcmp(a, "-h") == 0 && has_next) {
            cli.host = argv[++i];
        } else if (strcmp(a, "-p") == 0 && has_next) {
            long long port;
            const char *s = argv[++i];
            if (str_to_ll(s, strlen(s), &port) < 0 || port <= 0 ||
                port > 65535) {
                fprintf(stderr, "Invalid port: %s\n", s);
                return 1;
            }
            cli.port = (int)port;
        } else if (strcmp(a, "-a") == 0 && has_next) {
            cli.password = argv[++i];
        } else if (strcmp(a, "--raw") == 0) {
            cli.raw = 1;
        } else if (strcmp(a, "--help") == 0) {
            usage(stdout);
            return 0;
        } else if (a[0] == '-' && a[1] != '\0') {
            fprintf(stderr, "Unknown option: %s\n", a);
            usage(stderr);
            return 1;
        } else {
            break;
        }
    }

    if (cli_connect(&cli) < 0 && i < argc)
        return 1;
    if (cli.fd >= 0 && cli.password != NULL && cli_auth(&cli) < 0 && i < argc)
        return 1;

    if (i < argc) {
        int nargs = argc - i;
        size_t *lens = xmalloc((size_t)nargs * sizeof(*lens));
        for (int j = 0; j < nargs; j++)
            lens[j] = strlen(argv[i + j]);
        rc = cli_run_command(&cli, nargs, argv + i, lens);
        free(lens);
        rc = rc == 0 ? 0 : 1;
    } else {
        if (!isatty(STDIN_FILENO) && cli.fd < 0)
            return 1;
        rc = interactive(&cli);
    }

    cli_disconnect(&cli);
    sbuf_free(&cli.in);
    return rc;
}
