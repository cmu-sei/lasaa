#!/usr/bin/env python3
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
"""Start the LASAA web UI's server (see web-ui-design.md).

  ./lasaa_webui_serve.py --workspace DIR [--port N] [--host ADDR]

It prints a URL containing a one-time token; open that URL in a browser
on the same machine.  In Docker, use --host 0.0.0.0 and publish the port
on loopback only:
    docker run -p 127.0.0.1:8000:8000 ...

--workspace DIR is required: the directory that holds the UI's database,
snapshots, and LASAA output (for example ~/.lasaa-ui).  It is created if
it doesn't exist.  To bring in alerts made on the command line, see
lasaa_webui_import.py.

--model-configs FILE saves the model configs in FILE (a JSON list; see
lasaa_webui/model_configs.py and model_configs.example.json), so that they
are under "Saved" in the run form's model list, replacing saved configs with
the same names.  --mock-llm saves a config ("Mock: MODEL (EFFORT)") for each
model and effort in mock_llm_server.py's reply cache, for offline demos (see
lasaa_webui/README.md, "Offline demos with a mock LLM").
"""

import argparse
import ipaddress
import os
import sys

from lasaa_webui import mock_llm, model_configs, models
from lasaa_webui.runs import API_KEY_ENV
from lasaa_webui.workspace import Workspace, new_token


def parse_args(argv):
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--workspace", required=True,
                   help="workspace directory (e.g. ~/.lasaa-ui)")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--host", default="127.0.0.1",
                   help="address to listen on (default 127.0.0.1)")
    p.add_argument("--allow-remote", action="store_true",
                   help="allow --host to be an address other than loopback or, in "
                        "Docker, 0.0.0.0")
    p.add_argument("--allowed-host", action="append", default=[], metavar="NAME",
                   help="also accept this hostname in the Host header")
    p.add_argument("--editor-url", default="vscode://file/{path}:{line}",
                   help="template for 'Open in editor' links")
    p.add_argument("--editor-path-map", action="append", default=[], metavar="FROM=TO",
                   help="rewrite path prefix FROM to TO in editor links (e.g. when "
                        "the server runs in Docker and the editor on the host)")
    p.add_argument("--allow-builds-as-server-user", action="store_true",
                   help="when the server isn't root (as outside Docker), let snapshots "
                        "run build commands anyway, as the server's own user, with all "
                        "of its access; only for code whose build you trust")
    p.add_argument("--blind-mode", action="store_true",
                   help="show the blind-mode toggle, which hides LLM verdicts until "
                        "you review each alert")
    p.add_argument("--model-configs", action="append", default=[], metavar="FILE",
                   help="save the model configs in FILE (a JSON list; see "
                        "model_configs.example.json), replacing saved configs with the "
                        "same names; may be given more than once")
    p.add_argument("--mock-llm", action="store_true",
                   help="save a model config for each model and effort in the mock LLM's "
                        "reply cache (mock_llm_server.py), replacing ones with the same "
                        "names")
    p.add_argument("--mock-llm-url", default=mock_llm.DEFAULT_URL, metavar="URL",
                   help=f"the mock's base URL (default {mock_llm.DEFAULT_URL})")
    p.add_argument("--mock-llm-cache", default=mock_llm.DEFAULT_CACHE, metavar="FILE",
                   help=f"the mock's reply cache (default {mock_llm.DEFAULT_CACHE})")
    return p.parse_args(argv)


def in_docker():
    return os.path.exists("/.dockerenv")


def mock_configs(args):
    """--mock-llm: [(name, spec)] for the mock's cache."""
    try:
        named, skipped = mock_llm.specs(mock_llm.cached_pairs(args.mock_llm_cache),
                                        args.mock_llm_url)
    except FileNotFoundError:
        sys.exit(f"Error: --mock-llm: no cache at {args.mock_llm_cache}; build it with "
                 "mock_llm_build_cache.py.")
    except (OSError, ValueError) as e:
        sys.exit(f"Error: --mock-llm: {e}")
    for model, effort, why in skipped:
        print(f"Note: --mock-llm: no config for {model} ({effort}): {why}", file=sys.stderr)
    if not named:
        sys.exit(f"Error: --mock-llm: {args.mock_llm_cache} has no usable model and effort.")
    return named


def startup_configs(args):
    """[(name, spec)] from --model-configs and --mock-llm, checked (so that
    a bad one stops the server before anything is saved)."""
    named = []
    for path in args.model_configs:
        try:
            named += model_configs.load(path)
        except FileNotFoundError:
            sys.exit(f"Error: --model-configs: no file {path}.")
        except (OSError, ValueError) as e:
            sys.exit(f"Error: --model-configs: {e}")
    if args.mock_llm:
        named += mock_configs(args)
    try:
        model_configs.check_unique(named)
    except ValueError as e:
        sys.exit(f"Error: --model-configs/--mock-llm: {e}.")
    return named


def save_configs(ws, args, named):
    """Save the startup configs, set the mock's dummy key, and say which
    configs' keys aren't set."""
    conn = ws.connect()
    try:
        model_configs.install(conn, named)
    finally:
        conn.close()
    if args.mock_llm:
        os.environ.setdefault(mock_llm.KEY_VAR, "mock")
    print(f"Saved model configs: {', '.join(name for name, _ in named)}.", flush=True)
    for name, spec in named:
        var = models.key_var(spec)
        if var and not os.environ.get(var):
            print(f"Note: {var} isn't set, so runs of the config {name!r} will fail.",
                  file=sys.stderr)


def serve(args):
    import uvicorn
    from lasaa_webui.app import Settings, create_app

    try:
        addr = ipaddress.ip_address(args.host)
        loopback = addr.is_loopback
    except ValueError:
        loopback = args.host == "localhost"
    if not loopback and not args.allow_remote and not (args.host == "0.0.0.0" and in_docker()):
        sys.exit(f"Error: --host {args.host} would expose the server to the network. "
                 "Pass --allow-remote if you mean it.")
    if not loopback:
        print(f"Note: listening on {args.host}.  Anyone who can reach this port and "
              "has the token can run builds and spend API money.", file=sys.stderr)
        if in_docker():
            print("In Docker, publish the port on loopback only: "
                  f"docker run -p 127.0.0.1:{args.port}:{args.port} ...", file=sys.stderr)

    path_map = []
    for item in args.editor_path_map:
        src, sep, dst = item.partition("=")
        if not sep:
            sys.exit(f"Error: --editor-path-map {item!r} isn't FROM=TO.")
        path_map.append((src, dst))
    aws_files = any(os.path.exists(os.path.expanduser(f"~/.aws/{f}"))
                    for f in ("credentials", "config"))
    named = startup_configs(args)
    config_keys = {models.key_var(spec) for _, spec in named} - {None}
    if (not any(os.environ.get(k) for k in API_KEY_ENV) and not aws_files
            and not args.mock_llm and not any(os.environ.get(k) for k in config_keys)):
        print("\nWarning: no API key is set (none of "
              f"{', '.join(API_KEY_ENV)}), and there is no ~/.aws/credentials or "
              "~/.aws/config.  LASAA runs from the UI will fail.", file=sys.stderr)
    ws = Workspace(args.workspace)
    if named:
        save_configs(ws, args, named)
    token = new_token()
    token_file = ws.write_token(token)
    app = create_app(ws, token, Settings(
        args.editor_url, path_map, args.allowed_host, blind_mode=args.blind_mode,
        allow_builds_as_server_user=args.allow_builds_as_server_user))
    print(f"\nLASAA UI, workspace {ws.root}\n"
          f"Open this URL in a browser on this machine:\n\n"
          f"    http://localhost:{args.port}/?token={token}\n\n"
          f"(The token is also in {token_file}.)\n", flush=True)
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning",
                server_header=False, proxy_headers=False)


def main(argv=None):
    serve(parse_args(sys.argv[1:] if argv is None else argv))


if __name__ == "__main__":
    main()
