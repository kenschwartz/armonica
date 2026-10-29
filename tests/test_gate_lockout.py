"""P6 gating tests: passphrase lockout must persist across provider restarts.

Five wrong passphrase attempts lock the sign-in page, and the lock survives
a fresh VaultOAuthProvider constructed on the same state_dir: lock state is
persisted on disk, not held only in process memory. Login is driven directly
against the provider (authorize to mint a txn, then login_page with a
constructed form request), so no HTTP client is needed. No sleeps: the lock
window is 15 minutes of wall time and the whole test runs inside it.
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

from starlette.requests import Request

from mcp.server.auth.provider import AuthorizationParams

CLAUDE_CALLBACK = "https://claude.ai/api/mcp/auth_callback"
PUBLIC_URL = "https://vault-test.example"
PASSPHRASE = "unit test passphrase that is long enough"


def load_auth():
    try:
        from armonica import auth
    except ImportError as exc:
        raise AssertionError(
            f"P6 gates packaged behavior: armonica.auth does not exist yet ({exc})"
        ) from exc
    return auth


def write_passphrase(state_dir: Path, passphrase: str) -> None:
    record = load_auth().hash_passphrase(passphrase)
    fd = os.open(state_dir / "passphrase.json", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(record, f)


async def new_txn(provider, client) -> str:
    params = AuthorizationParams(
        state="st-p6",
        scopes=["vault.read"],
        code_challenge="",
        redirect_uri=CLAUDE_CALLBACK,
        redirect_uri_provided_explicitly=True,
    )
    login_url = await provider.authorize(client, params)
    return parse_qs(urlparse(login_url).query)["txn"][0]


async def post_login(provider, txn: str, passphrase: str):
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
        "client": ("127.0.0.1", 41010),
        "root_path": "",
        "http_version": "1.1",
    }

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    return await provider.login_page(Request(scope, receive))


class GateLockoutPersistence(unittest.TestCase):
    def setUp(self):
        load_auth()
        base = tempfile.TemporaryDirectory()
        self.addCleanup(base.cleanup)
        self.state_dir = Path(base.name) / "state"
        self.state_dir.mkdir()
        write_passphrase(self.state_dir, PASSPHRASE)
        self.client_id, _ = load_auth().preregister_client(self.state_dir)
        self.provider = load_auth().VaultOAuthProvider(
            PUBLIC_URL, f"{PUBLIC_URL}/mcp", self.state_dir
        )
        self.client = asyncio.run(self.provider.get_client(self.client_id))

    def test_lock_survives_fresh_provider(self):
        for attempt in range(5):
            txn = asyncio.run(new_txn(self.provider, self.client))
            resp = asyncio.run(post_login(self.provider, txn, f"wrong passphrase {attempt}"))
            self.assertEqual(401, resp.status_code, f"attempt {attempt + 1} should just fail")

        txn = asyncio.run(new_txn(self.provider, self.client))
        resp = asyncio.run(post_login(self.provider, txn, PASSPHRASE))
        self.assertEqual(429, resp.status_code, "five failures must lock sign-in")

        fresh = load_auth().VaultOAuthProvider(PUBLIC_URL, f"{PUBLIC_URL}/mcp", self.state_dir)
        client = asyncio.run(fresh.get_client(self.client_id))
        txn = asyncio.run(new_txn(fresh, client))
        resp = asyncio.run(post_login(fresh, txn, PASSPHRASE))
        self.assertEqual(
            429,
            resp.status_code,
            "a fresh provider on the same state dir must stay locked",
        )


if __name__ == "__main__":
    unittest.main()
