"""P7 gating tests: no secret material lands on disk in the clear.

A full successful sign-in and token issue, driven at the provider level
through the exact hooks the SDK routes call: authorize, login_page,
load_authorization_code, exchange_authorization_code. After it:
- state.json contains no substring of the raw access or refresh token
- passphrase.json is written by the real `set-passphrase --generate` CLI
  (contract: the generated passphrase is the second non-empty line it
  prints) and holds scrypt fields only, never the passphrase
- state.json and passphrase.json both have mode 600
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlencode, urlparse

from starlette.requests import Request

from mcp.server.auth.provider import AuthorizationParams

CLAUDE_CALLBACK = "https://claude.ai/api/mcp/auth_callback"
PUBLIC_URL = "https://vault-test.example"


def load_auth():
    try:
        from armonica import auth
    except ImportError as exc:
        raise AssertionError(
            f"P7 gates packaged behavior: armonica.auth does not exist yet ({exc})"
        ) from exc
    return auth


def load_main():
    try:
        from armonica.__main__ import main
    except ImportError as exc:
        raise AssertionError(
            f"P7 gates packaged behavior: armonica.__main__ does not exist yet ({exc})"
        ) from exc
    return main


def cli_set_passphrase(state_dir: Path) -> str:
    """Run set-passphrase --generate against a temp STATE_DIR, return the phrase."""
    env = dict(os.environ)
    env["STATE_DIR"] = str(state_dir)
    out = io.StringIO()
    with contextlib.redirect_stdout(out), mock.patch.dict(os.environ, env, clear=True):
        load_main()(["set-passphrase", "--generate"])
    lines = [line.strip() for line in out.getvalue().splitlines() if line.strip()]
    phrase = lines[1]
    assert phrase and not phrase.startswith("Passphrase"), f"unexpected CLI output: {lines}"
    return phrase


async def drive_login_and_exchange(provider, client, passphrase: str):
    params = AuthorizationParams(
        state="st-p7",
        scopes=["vault.read"],
        code_challenge="",
        redirect_uri=CLAUDE_CALLBACK,
        redirect_uri_provided_explicitly=True,
    )
    login_url = await provider.authorize(client, params)
    txn = parse_qs(urlparse(login_url).query)["txn"][0]
    body = urlencode({"txn": txn, "passphrase": passphrase, "action": "approve"}).encode()
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "method": "POST",
        "path": "/login",
        "raw_path": b"/login",
        "query_string": b"",
        "headers": [(b"host", b"vault-test.example"), (b"content-type", b"application/x-www-form-urlencoded")],
        "scheme": "https",
        "server": ("vault-test.example", 443),
        "client": ("127.0.0.1", 41020),
        "root_path": "",
        "http_version": "1.1",
    }

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    resp = await provider.login_page(Request(scope, receive))
    assert resp.status_code == 302, f"login failed with {resp.status_code}"
    callback = resp.headers["location"]
    code_value = parse_qs(urlparse(callback).query)["code"][0]
    loaded = await provider.load_authorization_code(client, code_value)
    assert loaded is not None, "authorization code did not load"
    return await provider.exchange_authorization_code(client, loaded)


class GateSecretsHygiene(unittest.TestCase):
    def test_no_secret_plaintext_on_disk_after_full_flow(self):
        base = tempfile.TemporaryDirectory()
        self.addCleanup(base.cleanup)
        state_dir = Path(base.name) / "state"
        state_dir.mkdir()
        passphrase = cli_set_passphrase(state_dir)

        auth = load_auth()
        client_id, _ = auth.preregister_client(state_dir)
        provider = auth.VaultOAuthProvider(PUBLIC_URL, f"{PUBLIC_URL}/mcp", state_dir)
        client = asyncio.run(provider.get_client(client_id))
        tokens = asyncio.run(drive_login_and_exchange(provider, client, passphrase))

        self.assertTrue(tokens.access_token)
        self.assertTrue(tokens.refresh_token)
        state_raw = (state_dir / "state.json").read_bytes()
        self.assertNotIn(tokens.access_token.encode(), state_raw)
        self.assertNotIn(tokens.refresh_token.encode(), state_raw)

        pass_raw = (state_dir / "passphrase.json").read_text()
        self.assertNotIn(passphrase, pass_raw)
        record = json.loads(pass_raw)
        self.assertEqual("scrypt", record.get("algo"))
        for key in ("n", "r", "p", "salt", "hash"):
            self.assertIn(key, record)

        self.assertEqual(0o600, os.stat(state_dir / "state.json").st_mode & 0o777)
        self.assertEqual(0o600, os.stat(state_dir / "passphrase.json").st_mode & 0o777)


if __name__ == "__main__":
    unittest.main()
