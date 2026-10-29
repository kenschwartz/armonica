"""P8 gating tests: cross-origin POSTs to /login are refused.

Driven through the full ASGI app (GET /authorize to mint a fresh txn, then
POST /login), so the check is exercised wherever the build puts it, handler
or middleware. A POST carrying an Origin different from the server's public
URL is refused with a 4xx. A POST with no Origin header, or with an Origin
equal to the public URL, proceeds through sign-in to the Claude callback
with a code.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

CLAUDE_CALLBACK = "https://claude.ai/api/mcp/auth_callback"
PUBLIC_URL = "https://vault-test.example"
HOST = "vault-test.example"
PASSPHRASE = "unit test passphrase that is long enough"


def load_auth():
    try:
        from armonica import auth
    except ImportError as exc:
        raise AssertionError(
            f"P8 gates packaged behavior: armonica.auth does not exist yet ({exc})"
        ) from exc
    return auth


def load_server():
    try:
        from armonica import server
    except ImportError as exc:
        raise AssertionError(
            f"P8 gates packaged behavior: armonica.server does not exist yet ({exc})"
        ) from exc
    return server


def write_passphrase(state_dir: Path, passphrase: str) -> None:
    record = load_auth().hash_passphrase(passphrase)
    fd = os.open(state_dir / "passphrase.json", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(record, f)


def code_challenge_pair():
    verifier = "unit-test-verifier-" + "o" * 24
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return verifier, challenge


async def asgi_call(app, method, path, *, form=None, headers=(), query=b""):
    body = b""
    header_pairs = [(k.lower().encode(), v.encode()) for k, v in headers]
    if form is not None:
        body = urlencode(form).encode()
        header_pairs.append((b"content-type", b"application/x-www-form-urlencoded"))
    if not any(k == b"host" for k, _ in header_pairs):
        header_pairs.append((b"host", HOST.encode()))
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "method": method,
        "path": path,
        "raw_path": path.encode(),
        "query_string": query,
        "headers": header_pairs,
        "scheme": "https",
        "server": (HOST, 443),
        "client": ("127.0.0.1", 41030),
        "root_path": "",
        "http_version": "1.1",
    }
    sent = []
    supplied = False

    async def receive():
        nonlocal supplied
        if supplied:
            return {"type": "http.disconnect"}
        supplied = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        sent.append(message)

    await app(scope, receive, send)
    start = next((m for m in sent if m["type"] == "http.response.start"), None)
    assert start is not None, "the app produced no response start message"
    headers_out = {k.decode(): v.decode() for k, v in start.get("headers", [])}
    body_out = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return start["status"], headers_out, body_out


class GateOriginCheck(unittest.TestCase):
    def setUp(self):
        load_auth()
        load_server()
        base = tempfile.TemporaryDirectory()
        self.addCleanup(base.cleanup)
        self.base = Path(base.name)
        self.state_dir = self.base / "state"
        self.state_dir.mkdir()
        self.vault_root = self.base / "vault"
        self.vault_root.mkdir()
        write_passphrase(self.state_dir, PASSPHRASE)
        self.client_id, _ = load_auth().preregister_client(self.state_dir)

    def build_app(self):
        server = load_server()
        return server.build_app(
            server.Config(
                vault_root=self.vault_root, public_url=PUBLIC_URL, state_dir=self.state_dir
            )
        )

    def login_with_origin(self, origin: str | None):
        app = self.build_app()
        _, challenge = code_challenge_pair()
        authorize_query = urlencode(
            {
                "response_type": "code",
                "client_id": self.client_id,
                "redirect_uri": CLAUDE_CALLBACK,
                "state": "st-p8",
                "scope": "vault.read",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
        )

        async def flow():
            status, headers, _ = await asgi_call(
                app, "GET", "/authorize", query=authorize_query.encode()
            )
            assert status == 302, f"authorize returned {status}"
            txn = parse_qs(urlparse(headers["location"]).query)["txn"][0]
            post_headers = [("origin", origin)] if origin else []
            return await asgi_call(
                app,
                "POST",
                "/login",
                form={"txn": txn, "passphrase": PASSPHRASE, "action": "approve"},
                headers=post_headers,
            )

        return asyncio.run(flow())

    def test_cross_origin_post_login_refused(self):
        status, _, _ = self.login_with_origin("https://evil.example")
        self.assertGreaterEqual(status, 400, "a foreign Origin must be refused")
        self.assertLess(status, 500, "a refused Origin is a 4xx, not a crash")

    def test_same_origin_post_login_proceeds(self):
        status, headers, _ = self.login_with_origin(PUBLIC_URL)
        self.assertEqual(302, status)
        self.assertTrue(headers["location"].startswith(CLAUDE_CALLBACK))
        self.assertIn("code=", headers["location"])

    def test_post_login_without_origin_header_proceeds(self):
        status, headers, _ = self.login_with_origin(None)
        self.assertEqual(302, status)
        self.assertTrue(headers["location"].startswith(CLAUDE_CALLBACK))
        self.assertIn("code=", headers["location"])


if __name__ == "__main__":
    unittest.main()
