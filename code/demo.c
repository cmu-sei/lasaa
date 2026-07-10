/*
 * demo.c -- example program for the `flawfinder` static analyzer.
 */

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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GREETING "Welcome, "
#define MAX_NAME 32

/* ---- FALSE POSITIVES ----------------------------------------- */

static void print_banner(void)
{
    char banner[64];
    strcpy(banner, "=== demo program ===");
    puts(banner);
}

static void greet_user(int user_id)
{
    char msg[64];
    sprintf(msg, "Hello, user #%d", user_id);
    puts(msg);
}

static void copy_header(char *dst, size_t dstsz)
{
    static const char hdr[] = "X-Demo: 1\r\n";
    if (dstsz >= sizeof hdr) {
        memcpy(dst, hdr, sizeof hdr);
    }
}

/* ---- TRUE POSITIVES ------------------------------------------ */

static void greet(const char *name)
{
    char welcome[MAX_NAME];
    strcpy(welcome, name);
    printf("%s%s\n", GREETING, welcome);
}

static void read_name(void)
{
    char name[32];
    printf("Your name? ");
    gets(name);
    greet(name);
}

static void run_lookup(const char *query)
{
    char cmd[256];
    sprintf(cmd, "grep %s /etc/passwd", query);
    system(cmd);
}

/* -------------------------------------------------------------- */

int main(int argc, char **argv)
{
    print_banner();
    greet_user(42);

    char header[64];
    copy_header(header, sizeof header);
    fputs(header, stdout);

    if (argc > 1) {
        greet(argv[1]);
        run_lookup(argv[1]);
    } else {
        read_name();
    }
    return 0;
}
