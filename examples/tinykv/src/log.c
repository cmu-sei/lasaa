// log.c - leveled logging to stderr or a file.
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
#include "log.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "util.h"

static const char *const level_names[LOG_NLEVELS] = {
    "DEBUG", "INFO", "WARN", "ERROR"
};

static const char level_chars[LOG_NLEVELS] = { '.', '-', '*', '#' };

static struct {
    FILE *fp;
    char *path;
    int level;
    int is_tty;
} logger = { NULL, NULL, LOG_INFO, 0 };

static FILE *log_stream(void)
{
    return logger.fp != NULL ? logger.fp : stderr;
}

int log_open(const char *path, int level)
{
    FILE *fp;

    log_close();
    logger.level = level;
    if (path == NULL || path[0] == '\0') {
        logger.is_tty = isatty(STDERR_FILENO);
        return 0;
    }

    fp = fopen(path, "a");
    if (fp == NULL)
        return -1;
    setvbuf(fp, NULL, _IOLBF, 0);
    logger.fp = fp;
    logger.path = xstrdup(path);
    logger.is_tty = 0;
    return 0;
}

void log_close(void)
{
    if (logger.fp != NULL) {
        fclose(logger.fp);
        logger.fp = NULL;
    }
    free(logger.path);
    logger.path = NULL;
}

int log_reopen(void)
{
    FILE *fp;

    if (logger.path == NULL)
        return 0;
    fp = fopen(logger.path, "a");
    if (fp == NULL)
        return -1;  // keep writing to the old file
    setvbuf(fp, NULL, _IOLBF, 0);
    fclose(logger.fp);
    logger.fp = fp;
    return 0;
}

void log_set_level(int level)
{
    if (level >= 0 && level < LOG_NLEVELS)
        logger.level = level;
}

int log_get_level(void)
{
    return logger.level;
}

int log_level_from_name(const char *name)
{
    int i;

    for (i = 0; i < LOG_NLEVELS; i++) {
        if (strcasecmp(name, level_names[i]) == 0)
            return i;
    }
    if (strcasecmp(name, "warning") == 0)
        return LOG_WARN;
    if (strcasecmp(name, "verbose") == 0)
        return LOG_DEBUG;
    return -1;
}

const char *log_level_name(int level)
{
    if (level < 0 || level > LOG_NLEVELS)
        return "unknown";
    return level_names[level];
}

static void log_prefix(FILE *fp, int level)
{
    struct timeval tv;
    struct tm tm;
    char ts[32];

    gettimeofday(&tv, NULL);
    localtime_r(&tv.tv_sec, &tm);
    strftime(ts, sizeof(ts), "%d %b %Y %H:%M:%S", &tm);
    fprintf(fp, "%d:%s.%03d %c ", (int)getpid(), ts,
            (int)(tv.tv_usec / 1000), level_chars[level]);
}

void log_msg(int level, const char *fmt, ...)
{
    FILE *fp;
    va_list ap;

    if (level < logger.level || level >= LOG_NLEVELS)
        return;

    fp = log_stream();
    log_prefix(fp, level);
    if (logger.is_tty && level >= LOG_WARN)
        fputs(level == LOG_ERROR ? "\033[31m" : "\033[33m", fp);
    va_start(ap, fmt);
    vfprintf(fp, fmt, ap);
    va_end(ap);
    if (logger.is_tty && level >= LOG_WARN)
        fputs("\033[0m", fp);
    fputc('\n', fp);
}

// Log a classic 16-bytes-per-line hex dump, for debugging protocol issues.
void log_hexdump(int level, const char *label, const void *p, size_t n)
{
    const unsigned char *b = p;
    char line[80];
    size_t off, i;

    if (level < logger.level || level >= LOG_NLEVELS)
        return;

    log_msg(level, "%s (%zu bytes):", label, n);
    for (off = 0; off < n; off += 16) {
        size_t len = 0;
        size_t cnt = n - off < 16 ? n - off : 16;

        len += (size_t)snprintf(line + len, sizeof(line) - len, "%08zx ", off);
        for (i = 0; i < 16; i++) {
            if (i < cnt)
                len += (size_t)snprintf(line + len, sizeof(line) - len,
                                        " %02x", b[off + i]);
            else
                len += (size_t)snprintf(line + len, sizeof(line) - len, "   ");
        }
        len += (size_t)snprintf(line + len, sizeof(line) - len, "  |");
        for (i = 0; i < cnt; i++)
            line[len++] = isprint(b[off + i]) ? (char)b[off + i] : '.';
        line[len++] = '|';
        line[len] = '\0';
        log_msg(level, "%s", line);
    }
}
