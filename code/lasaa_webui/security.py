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
"""Security middleware: startup token, Host check, CSRF, and response headers.

See web-ui-design.md, "Security".  In short:

- The first request carries ?token=... (printed at startup); it's exchanged
  for a session cookie (HttpOnly, SameSite=Strict) and a redirect to the same
  URL without the token.  Requests without a valid session get 403.
- The Host header's hostname must be localhost, 127.0.0.1, or ::1 (or one
  given with --allowed-host).  The port isn't checked, since Docker port
  mappings and SSH tunnels change it; the hostname alone defeats DNS
  rebinding.
- Every request other than GET and HEAD needs an Origin header matching the
  Host header and the session's anti-CSRF token, in an X-CSRF-Token header
  or a csrf_token form field.
"""

import hashlib
import hmac
import secrets
from urllib.parse import parse_qsl, urlencode

LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "::1")
SAFE_METHODS = ("GET", "HEAD")
MAX_FORM_BYTES = 10 * 1024 * 1024
CSP = ("default-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
       "form-action 'self'; object-src 'none'")
SECURITY_HEADERS = [
    (b"content-security-policy", CSP.encode()),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    # Not "no-referrer": under it, browsers send "Origin: null" on form POSTs,
    # which the Origin check would reject.  Other sites still get no referrer.
    (b"referrer-policy", b"same-origin"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
]
NO_SESSION_MESSAGE = (
    "Not signed in.  Open the URL that lasaa_webui_serve.py printed at startup "
    "(it contains a token).  The token is also in the file 'token' in the workspace.")


def hostname_of(host):
    """Return the hostname part of a Host header value, lowercased."""
    host = host.strip().lower()
    if host.startswith("["):
        end = host.find("]")
        return host[1:end] if end > 0 else None
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else (host if ":" not in host else None)


class SecurityMiddleware:
    def __init__(self, app, token, allowed_hosts=()):
        self.app = app
        self.token = token
        self.allowed_hosts = set(LOOPBACK_HOSTS) | {h.lower() for h in allowed_hosts}
        self.cookie_name = "lasaa_" + hashlib.sha256(token.encode()).hexdigest()[:8]
        self.sessions = {}      # session ID -> anti-CSRF token

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            return await self.app(scope, receive, send)
        if scope["type"] != "http":
            return await self._reject(scope, send, 403, "Not supported.")
        headers = {}
        for k, v in scope["headers"]:
            headers.setdefault(k.decode("latin-1").lower(), v.decode("latin-1"))
        host = headers.get("host", "")
        if hostname_of(host) not in self.allowed_hosts:
            return await self._reject(scope, send, 403, "Bad Host header.")

        query = parse_qsl(scope.get("query_string", b"").decode("latin-1"), keep_blank_values=True)
        token = next((v for k, v in query if k == "token"), None)
        if token is not None:
            if not hmac.compare_digest(token.encode(), self.token.encode()):
                return await self._reject(scope, send, 403, "Wrong token.")
            sid = secrets.token_urlsafe(32)
            self.sessions[sid] = secrets.token_urlsafe(32)
            rest = urlencode([(k, v) for k, v in query if k != "token"])
            location = (scope.get("root_path", "") + scope["path"]) + (f"?{rest}" if rest else "")
            cookie = f"{self.cookie_name}={sid}; HttpOnly; SameSite=Strict; Path=/"
            return await self._respond(send, 303, b"", [
                (b"location", location.encode("latin-1")),
                (b"set-cookie", cookie.encode("latin-1")),
                (b"cache-control", b"no-store")])

        sid = None
        for part in headers.get("cookie", "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == self.cookie_name:
                sid = value
        csrf = self.sessions.get(sid) if sid else None
        if csrf is None:
            return await self._reject(scope, send, 403, NO_SESSION_MESSAGE)

        if scope["method"] not in SAFE_METHODS:
            origin = headers.get("origin")
            if not origin or origin.lower() not in (f"http://{host.lower()}",
                                                    f"https://{host.lower()}"):
                return await self._reject(scope, send, 403, "Bad or missing Origin header.")
            sent = headers.get("x-csrf-token")
            if sent is None and headers.get("content-type", "").startswith(
                    "application/x-www-form-urlencoded"):
                body = await self._read_body(receive)
                if body is None:
                    return await self._reject(scope, send, 413, "Form too large.")
                sent = next((v for k, v in parse_qsl(body.decode("latin-1"),
                                                     keep_blank_values=True)
                             if k == "csrf_token"), None)
                receive = self._replay(body)
            if sent is None or not hmac.compare_digest(sent.encode(), csrf.encode()):
                return await self._reject(scope, send, 403, "Missing or wrong anti-CSRF token.")

        scope.setdefault("state", {})["csrf_token"] = csrf

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                message = dict(message)
                message["headers"] = list(message.get("headers", [])) + SECURITY_HEADERS
            await send(message)
        await self.app(scope, receive, send_with_headers)

    @staticmethod
    async def _read_body(receive):
        chunks, size = [], 0
        while True:
            message = await receive()
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > MAX_FORM_BYTES:
                return None
            chunks.append(chunk)
            if not message.get("more_body"):
                return b"".join(chunks)

    @staticmethod
    def _replay(body):
        sent = False

        async def receive():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.disconnect"}
        return receive

    async def _reject(self, scope, send, status, text):
        await self._respond(send, status, (text + "\n").encode(),
                            [(b"content-type", b"text/plain; charset=utf-8")])

    @staticmethod
    async def _respond(send, status, body, headers):
        await send({"type": "http.response.start", "status": status,
                    "headers": headers + SECURITY_HEADERS})
        await send({"type": "http.response.body", "body": body})
