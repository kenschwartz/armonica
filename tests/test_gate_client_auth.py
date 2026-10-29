"""P5 gating tests: the confidential client authenticates on /token both ways.

Contract:
- the real ClientAuthenticator from the SDK, run against the provider with
  the pre-registered client: Basic auth with the correct secret
  authenticates, a wrong secret raises AuthenticationError, and a request
  with no secret raises AuthenticationError
- armonica.server.normalize_client_secret_post(request) -> Request is
  the middleware core: given a /token form post carrying client_id and
  client_secret with no Authorization header it returns a request that
  carries the equivalent Basic header and still exposes the form body to
  downstream readers
- end to end through the app: a full authorize + login + token exchange that
  posts the client secret in the form (client_secret_post, no Basic header)
  returns 200 with tokens, proving the normalization is wired into /token
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
from unittest import mock
from urllib.parse import parse_qs, urlencode, urlparse

from starlette.requests import Request

from mcp.server.auth.middleware.client_auth import AuthenticationError, ClientAuthenticator

CLAUDE_CALLBACK = "https://claude.ai/api/mcp/auth_callback"
PUBLIC_URL = "https://vault-test.example"
HOST = "vault-test.example"
PASSPHRASE = "unit test passphrase that is long enough"


def load_auth():
    try:
        from armonica import auth
    except ImportError as exc:
        raise AssertionError(
            f"P5 gates packaged behavior: armonica.auth does not exist yet ({exc})"
        ) from exc
    return auth


def load_server():
    try:
        from armonica import server
    except ImportError as exc:
        raise AssertionError(
            f"P5 gates packaged behavior: armonica.server does not exist yet ({exc})"
        ) from exc
    return server


def write_passphrase(state_dir: Path, passphrase: str) -> None:
    record = load_auth().hash_passphrase(passphrase)
    fd = os.open(state_dir / "passphrase.json", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(record, f)


async def read_form(request: Request):
    # starlette 1.10 form() returns an awaitable wrapper, not a coroutine,
    # so it must be awaited inside a coroutine rather than handed to asyncio.run
    return await request.form()


def basic_header(client_id: str, secret: str) -> str:
    raw = f"{client_id}:{secret}".encode()
    return "Basic " + base64.b64encode(raw).decode()


def code_challenge_pair():
    verifier = "unit-test-verifier-" + "v" * 24
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return verifier, challenge


def form_request(form: dict, *, path: str = "/token", auth_header: str | None = None) -> Request:
    body = urlencode(form).encode()
    headers = [(b"host", HOST.encode()), (b"content-type", b"application/x-www-form-urlencoded")]
    if auth_header is not None:
        headers.append((b"authorization", auth_header.encode()))
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "method": "POST",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": headers,
        "scheme": "https",
        "server": (HOST, 443),
        "client": ("127.0.0.1", 41001),
        "root_path": "",
        "http_version": "1.1",
    }

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(scope, receive)


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
        "client": ("127.0.0.1", 41002),
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


class GateClientAuth(unittest.TestCase):
    def setUp(self):
        load_auth()
        base = tempfile.TemporaryDirectory()
        self.addCleanup(base.cleanup)
        self.base = Path(base.name)
        self.state_dir = self.base / "state"
        self.state_dir.mkdir()
        self.vault_root = self.base / "vault"
        self.vault_root.mkdir()
        write_passphrase(self.state_dir, PASSPHRASE)
        self.client_id, self.client_secret = load_auth().preregister_client(self.state_dir)
        self.provider = load_auth().VaultOAuthProvider(
            PUBLIC_URL, f"{PUBLIC_URL}/mcp", self.state_dir
        )
        self.authenticator = ClientAuthenticator(self.provider)

    def token_form(self, **extra) -> dict:
        form = {
            "grant_type": "authorization_code",
            "code": "unused-code",
            "redirect_uri": CLAUDE_CALLBACK,
            "client_id": self.client_id,
            "code_verifier": "unused-verifier",
        }
        form.update(extra)
        return form

    def test_basic_auth_with_correct_secret_authenticates(self):
        request = form_request(
            self.token_form(), auth_header=basic_header(self.client_id, self.client_secret)
        )
        client = asyncio.run(self.authenticator.authenticate_request(request))
        self.assertEqual(self.client_id, client.client_id)

    def test_basic_auth_with_wrong_secret_raises(self):
        request = form_request(
            self.token_form(), auth_header=basic_header(self.client_id, "wrong-secret")
        )

        async def attempt():
            with self.assertRaises(AuthenticationError):
                await self.authenticator.authenticate_request(request)

        asyncio.run(attempt())

    def test_request_without_secret_raises(self):
        request = form_request(self.token_form())

        async def attempt():
            with self.assertRaises(AuthenticationError):
                await self.authenticator.authenticate_request(request)

        asyncio.run(attempt())

    def test_posted_secret_normalizes_to_basic_and_authenticates(self):
        request = form_request(self.token_form(client_secret=self.client_secret))
        rewritten = asyncio.run(load_server().normalize_client_secret_post(request))
        self.assertTrue(
            rewritten.headers.get("authorization", "").startswith("Basic "),
            "the normalized request must carry a Basic Authorization header",
        )
        client = asyncio.run(self.authenticator.authenticate_request(rewritten))
        self.assertEqual(self.client_id, client.client_id)
        still_readable = asyncio.run(read_form(rewritten))
        self.assertEqual(self.client_id, still_readable.get("client_id"))

    def test_full_flow_through_app_accepts_posted_secret(self):
        # ALLOW_LOCAL=1: this driver reaches /token from a loopback client with
        # no XFF, which the fail-closed allowlist refuses by default
        with mock.patch.dict(os.environ, {"ALLOW_LOCAL": "1"}):
            self._full_flow_body()

    def _full_flow_body(self):
        server = load_server()
        app = server.build_app(
            server.Config(
                vault_root=self.vault_root, public_url=PUBLIC_URL, state_dir=self.state_dir
            )
        )
        verifier, challenge = code_challenge_pair()
        authorize_query = urlencode(
            {
                "response_type": "code",
                "client_id": self.client_id,
                "redirect_uri": CLAUDE_CALLBACK,
                "state": "st-p5",
                "scope": "vault.read",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
        )

        async def sign_in() -> str:
            status, headers, _ = await asgi_call(
                app, "GET", "/authorize", query=authorize_query.encode()
            )
            self.assertEqual(302, status)
            login_url = headers["location"]
            self.assertIn("/login?txn=", login_url)
            txn = parse_qs(urlparse(login_url).query)["txn"][0]
            status, headers, _ = await asgi_call(
                app,
                "POST",
                "/login",
                form={"txn": txn, "passphrase": PASSPHRASE, "action": "approve"},
            )
            self.assertEqual(302, status)
            return headers["location"]

        callback = asyncio.run(sign_in())
        self.assertTrue(callback.startswith(CLAUDE_CALLBACK), callback)
        code = parse_qs(urlparse(callback).query)["code"][0]

        async def exchange():
            return await asgi_call(
                app,
                "POST",
                "/token",
                form={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": CLAUDE_CALLBACK,
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "code_verifier": verifier,
                },
            )

        status, _, body = asyncio.run(exchange())
        self.assertEqual(200, status, body)
        tokens = json.loads(body)
        self.assertTrue(tokens.get("access_token"))


if __name__ == "__main__":
    unittest.main()
