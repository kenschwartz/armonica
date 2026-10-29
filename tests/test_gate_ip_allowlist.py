"""P10 gating tests: IP allowlist middleware on /mcp, /token and every
/.well-known/* path.

Contract for armonica.server.IPAllowlistMiddleware, an ASGI wrapper
constructed as IPAllowlistMiddleware(app) and consulted per request:
- the client IP is the LAST X-Forwarded-For entry when the header is
  present, and that entry must fall inside 160.79.104.0/21 (Anthropic's
  connector egress) or the middleware answers 403 itself and the wrapped
  app never runs
- a request with NO X-Forwarded-For is refused 403 even from loopback
  (F2/F02 fail-closed: every Funnel request reaches uvicorn from the
  on-host proxy's 127.0.0.1, so loopback-without-XFF must not satisfy the
  guard); env ALLOW_LOCAL=1 is the local-test escape that lets a loopback
  peer (127.0.0.1 or ::1) through to the app; a remote peer without XFF
  stays 403
- env IP_ALLOWLIST_CIDR replaces the default range; env IP_ALLOWLIST=0
  disables the guard entirely
- /authorize, /login and /healthz are exempt

The middleware is driven directly with constructed ASGI scopes.
"""

from __future__ import annotations

import asyncio
import os
import unittest
from unittest import mock

INSIDE_1 = "160.79.104.5"
INSIDE_2 = "160.79.111.254"
JUST_OUTSIDE = "160.79.112.1"
OUTSIDE = "8.8.8.8"
HOST = "vault-test.example"


def load_middleware():
    try:
        from armonica.server import IPAllowlistMiddleware
    except ImportError as exc:
        raise AssertionError(
            "P10 property absent: armonica.server has no IPAllowlistMiddleware "
            f"yet ({exc})"
        ) from exc
    return IPAllowlistMiddleware


class CaptureApp:
    """Records whether the middleware let the request through."""

    def __init__(self):
        self.called = False

    async def __call__(self, scope, receive, send):
        self.called = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})


def guard_scope(path, *, xff=None, client=("127.0.0.1", 41040), method="POST"):
    headers = [(b"host", HOST.encode())]
    if xff is not None:
        headers.append((b"x-forwarded-for", xff.encode()))
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "method": method,
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": headers,
        "scheme": "https",
        "server": (HOST, 443),
        "client": client,
        "root_path": "",
        "http_version": "1.1",
    }


class GateIpAllowlist(unittest.TestCase):
    def guard(self, *, path, xff=None, client=("127.0.0.1", 41041), env_over=None, expect_pass):
        middleware_cls = load_middleware()
        # ALLOW_LOCAL is dropped from the ambient copy too: an inherited
        # value would flip the fail-closed default case; only env_over
        # may turn it on
        env = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith(("IP_", "ALLOW_LOCAL"))
        }
        env.update(env_over or {})
        capture = CaptureApp()
        scope = guard_scope(path, xff=xff, client=client)

        async def run():
            sent = []

            async def receive():
                return {"type": "http.request", "body": b"", "more_body": False}

            async def send(message):
                sent.append(message)

            with mock.patch.dict(os.environ, env, clear=True):
                middleware = middleware_cls(capture)
                await middleware(scope, receive, send)
            start = next((m for m in sent if m["type"] == "http.response.start"), None)
            self.assertIsNotNone(start, "the middleware produced no response")
            return start["status"]

        status = asyncio.run(run())
        if expect_pass:
            self.assertTrue(capture.called, f"{path} must reach the wrapped app")
            self.assertEqual(200, status)
        else:
            self.assertFalse(capture.called, "a blocked request must not reach the wrapped app")
            self.assertEqual(403, status)

    def test_xff_inside_range_passes_on_guarded_paths(self):
        for path in ("/mcp", "/token", "/.well-known/oauth-authorization-server"):
            with self.subTest(path=path):
                self.guard(path=path, xff=INSIDE_1, expect_pass=True)

    def test_xff_outside_range_blocked_on_guarded_paths(self):
        cases = (
            ("/mcp", OUTSIDE),
            ("/token", JUST_OUTSIDE),
            ("/.well-known/oauth-authorization-server", OUTSIDE),
            ("/.well-known/oauth-protected-resource/mcp", OUTSIDE),
        )
        for path, ip in cases:
            with self.subTest(path=path, ip=ip):
                self.guard(path=path, xff=ip, expect_pass=False)

    def test_only_the_last_xff_entry_counts(self):
        self.guard(path="/token", xff=f"{INSIDE_1}, {OUTSIDE}", expect_pass=False)
        self.guard(path="/token", xff=f"{OUTSIDE}, {INSIDE_2}", expect_pass=True)

    def test_no_xff_loopback_blocked_by_default(self):
        # F2/F02: the on-host proxy is a loopback peer carrying no XFF
        # provenance, so loopback alone must not satisfy the guard
        self.guard(path="/mcp", client=("127.0.0.1", 41042), expect_pass=False)

    def test_no_xff_loopback_passes_under_allow_local(self):
        self.guard(
            path="/mcp",
            client=("127.0.0.1", 41042),
            env_over={"ALLOW_LOCAL": "1"},
            expect_pass=True,
        )

    def test_no_xff_remote_blocked(self):
        self.guard(path="/mcp", client=("10.1.2.3", 41043), expect_pass=False)

    def test_exempt_paths_bypass_the_guard(self):
        for path in ("/login", "/healthz", "/authorize"):
            with self.subTest(path=path):
                self.guard(path=path, xff=OUTSIDE, expect_pass=True)

    def test_ip_allowlist_zero_disables_the_guard(self):
        self.guard(
            path="/mcp",
            client=("10.1.2.3", 41044),
            env_over={"IP_ALLOWLIST": "0"},
            expect_pass=True,
        )

    def test_cidr_env_override_replaces_default_range(self):
        env = {"IP_ALLOWLIST_CIDR": "192.0.2.0/24"}
        self.guard(path="/mcp", xff="192.0.2.10", env_over=env, expect_pass=True)
        self.guard(path="/mcp", xff=INSIDE_1, env_over=env, expect_pass=False)


if __name__ == "__main__":
    unittest.main()
