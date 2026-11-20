# Makefile for tinykv: a small in-memory key-value server and its CLI.
#
# <legal>
# LASAA tool
#
# Copyright 2026 Carnegie Mellon University.
#
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
# INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
# UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS
# TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE
# OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE
# MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND
# WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
#
# Licensed under a MIT (SEI)-style license, please see License.txt or contact
# permission@sei.cmu.edu for full terms.
#
# [DISTRIBUTION STATEMENT A] This material has been approved for public
# release and unlimited distribution.  Please see Copyright notice for
# non-US Government use and distribution.
#
# This Software includes and/or makes use of Third-Party Software each subject
# to its own license.
#
# DM26-0426
# </legal>

CC      ?= cc
CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -D_GNU_SOURCE -Wall -Wextra -Wno-unused-parameter -Isrc
LDFLAGS ?=

CORE_SRCS = src/util.c src/sbuf.c src/log.c src/codec.c src/net.c \
            src/protocol.c
SERVER_SRCS = $(CORE_SRCS) src/config.c src/hashtable.c src/lru.c \
              src/ttlheap.c src/vlist.c src/store.c src/cmdutil.c \
              src/commands.c src/persist.c src/server.c
CLI_SRCS  = $(CORE_SRCS) cli/tkv-cli.c
TEST_SRCS = $(CORE_SRCS) src/config.c src/hashtable.c src/lru.c \
            src/ttlheap.c src/vlist.c src/store.c src/persist.c \
            tests/test_main.c

all: tinykv-server tkv-cli

tinykv-server: $(SERVER_SRCS:.c=.o)
	$(CC) $(LDFLAGS) -o $@ $^

tkv-cli: $(CLI_SRCS:.c=.o)
	$(CC) $(LDFLAGS) -o $@ $^

tests/test_main: $(TEST_SRCS:.c=.o)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c src/*.h
	$(CC) $(CFLAGS) -c -o $@ $<

test: tests/test_main
	./tests/test_main

clean:
	rm -f src/*.o cli/*.o tests/*.o tinykv-server tkv-cli tests/test_main

.PHONY: all test clean
