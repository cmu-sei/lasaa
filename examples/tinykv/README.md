# tinykv

<legal>
LASAA tool

Copyright 2026 Carnegie Mellon University.

NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS
TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE
OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE
MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND
WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.

Licensed under a MIT (SEI)-style license, please see License.txt or contact
permission@sei.cmu.edu for full terms.

[DISTRIBUTION STATEMENT A] This material has been approved for public
release and unlimited distribution.  Please see Copyright notice for
non-US Government use and distribution.

This Software includes and/or makes use of Third-Party Software each subject
to its own license.

DM26-0426
</legal>

## About tinykv

A small in-memory key-value server that speaks a Redis-style protocol, plus
a command-line client.

This code base was written by Claude Opus 5.5 as a demo target for LASAA, and
it contains deliberate defects.  See `lasaa_demo/README.md`.

Features:
- String and list values, key expiry (`EXPIRE`, `SET ... EX`), and
  approximate-LRU or nearest-TTL eviction under a memory limit.
- Persistence through binary snapshots (`SAVE`, periodic saves) and an
  append-only file (AOF) of write commands.
- A single-threaded `poll()` event loop, `AUTH`, `CONFIG GET/SET`, `INFO`,
  `CLIENT`, `KEYS`/`SCAN`, and `DUMP`/`RESTORE`.

## Build and run

```bash
make                 # builds tinykv-server and tkv-cli
make test            # unit tests
./tinykv-server tinykv.conf --port 7379 --loglevel debug
./tkv-cli -p 7379 SET greeting hello
./tkv-cli -p 7379    # interactive mode
```

Run `./tinykv-server --help` for the command-line options.
`tinykv.conf` documents every configuration option.

## Layout

| Path                 | Contents                                                    |
| ---                  | ---                                                         |
| `src/server.c`       | `main()`, the event loop, clients, `INFO`, periodic tasks   |
| `src/commands.c`, `src/cmdutil.c` | Command table and implementations              |
| `src/protocol.c`     | Request parsing and reply encoding                          |
| `src/store.c`        | Keyspace: lookup, expiry, eviction                          |
| `src/hashtable.c`, `src/lru.c`, `src/ttlheap.c`, `src/vlist.c` | Data structures   |
| `src/persist.c`      | Snapshots, `DUMP`/`RESTORE`, and the AOF                    |
| `src/config.c`, `src/log.c`, `src/net.c`   | Configuration, logging, and sockets   |
| `src/util.c`, `src/sbuf.c`, `src/codec.c`  | Strings, buffers, CRC32, base64, varints, and glob matching |
| `cli/tkv-cli.c`      | Client                                                      |
| `tests/test_main.c`  | Unit tests                                                  |
