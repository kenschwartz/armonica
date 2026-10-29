"""Gating tests: the passphrase lockout is PER-IP and bounded, not global.

A stranger who holds the client id can submit wrong passphrases, but that must
lock only THEIR ip, never the owner signing in from a different ip (the old
global lock let any such stranger deny the owner). The per-ip state is bounded
by a fixed-capacity FIFO so a rotating attacker cannot grow it without limit,
and eviction may only ever CLEAR a lockout, never create one. The ip is keyed
on the trusted last X-Forwarded-For entry (the hop the reverse proxy appends),
so a spoofed earlier entry cannot frame another ip.

HTTP-level tests drive login_page directly (authorize -> txn -> POST /login)
and FAIL on the current global lock for the right reason: the owner's ip is
wrongly locked. Unit-level tests exercise the bound/eviction/window through the
provider's is_locked(ip)/record_failure(ip) surface and the derive_client_ip
helper the build must expose.
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from starlette.requests import Request

from mcp.server.auth.provider import AuthorizationParams

CLAUDE_CALLBACK = "https://claude.ai/api/mcp/auth_callback"
PUBLIC_URL = "https://vault-test.example"
PASSPHRASE = "unit test passphrase that is long enough"
OWNER_IP = "203.0.113.7"
ATTACKER_IP = "198.51.100.9"


def load_auth():
    from armonica import auth
    return auth


def write_passphrase(state_dir: Path, passphrase: str) -> None:
    record = load_auth().hash_passphrase(passphrase)
    fd = os.open(state_dir / "passphrase.json", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(record, f)


async def new_txn(provider, client) -> str:
    params = AuthorizationParams(
        state="st-perip",
        scopes=["vault.read"],
        code_challenge="",
        redirect_uri=CLAUDE_CALLBACK,
        redirect_uri_provided_explicitly=True,
    )
    login_url = await provider.authorize(client, params)
    return parse_qs(urlparse(login_url).query)["txn"][0]


async def post_login(provider, txn: str, passphrase: str, xff: str | None = None,
                     peer: str = "127.0.0.1"):
    body = b"txn=" + txn.encode() + b"&passphrase=" + passphrase.encode().replace(b" ", b"+") + b"&action=approve"
    headers = [(b"host", b"vault-test.example"),
               (b"content-type", b"application/x-www-form-urlencoded")]
    if xff is not None:
        headers.append((b"x-forwarded-for", xff.encode()))
    scope = {
        "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
        "method": "POST", "path": "/login", "raw_path": b"/login", "query_string": b"",
        "headers": headers, "scheme": "https", "server": ("vault-test.example", 443),
        "client": (peer, 41010), "root_path": "", "http_version": "1.1",
    }

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    return await provider.login_page(Request(scope, receive))


class PerIpLockout(unittest.TestCase):
    def setUp(self):
        base = tempfile.TemporaryDirectory()
        self.addCleanup(base.cleanup)
        self.state_dir = Path(base.name) / "state"
        self.state_dir.mkdir()
        write_passphrase(self.state_dir, PASSPHRASE)
        self.client_id, _ = load_auth().preregister_client(self.state_dir)
        self.provider = load_auth().VaultOAuthProvider(PUBLIC_URL, f"{PUBLIC_URL}/mcp", self.state_dir)
        self.client = asyncio.run(self.provider.get_client(self.client_id))

    def _fail_five(self, xff):
        for i in range(5):
            txn = asyncio.run(new_txn(self.provider, self.client))
            resp = asyncio.run(post_login(self.provider, txn, f"wrong+{i}", xff=xff))
            self.assertEqual(401, resp.status_code, f"attempt {i + 1} should just fail")

    # --- HTTP-level: per-ip isolation and no framing (fail on the current global lock) ---

    def test_attacker_ip_is_locked_but_owner_ip_is_not(self):
        self._fail_five(ATTACKER_IP)
        # The attacker's own ip is locked even with the right passphrase.
        txn = asyncio.run(new_txn(self.provider, self.client))
        resp = asyncio.run(post_login(self.provider, txn, PASSPHRASE, xff=ATTACKER_IP))
        self.assertEqual(429, resp.status_code, "the failing ip must be locked")
        # The owner, from a different ip, must still sign in (this is what the
        # global lock broke: it returned 429 here).
        txn = asyncio.run(new_txn(self.provider, self.client))
        resp = asyncio.run(post_login(self.provider, txn, PASSPHRASE, xff=OWNER_IP))
        self.assertEqual(302, resp.status_code, "a different ip must not be locked by the attacker")

    def test_spoofed_earlier_xff_entry_cannot_frame_another_ip(self):
        # Attacker sends "OWNER, ATTACKER": the trusted key is the LAST entry
        # (the proxy-appended hop), so only ATTACKER is locked, never OWNER.
        self._fail_five(f"{OWNER_IP}, {ATTACKER_IP}")
        txn = asyncio.run(new_txn(self.provider, self.client))
        resp = asyncio.run(post_login(self.provider, txn, PASSPHRASE, xff=OWNER_IP))
        self.assertEqual(302, resp.status_code, "the spoofed victim ip must not be framed")
        txn = asyncio.run(new_txn(self.provider, self.client))
        resp = asyncio.run(post_login(self.provider, txn, PASSPHRASE, xff=f"whatever, {ATTACKER_IP}"))
        self.assertEqual(429, resp.status_code, "the real last-hop ip must be the one locked")

    # --- unit-level: the derive helper, the bound, eviction, the window ---

    def test_derive_client_ip_uses_last_xff_entry_then_peer(self):
        auth = load_auth()
        self.assertEqual("1.2.3.4", auth.derive_client_ip("10.0.0.99, 1.2.3.4", "127.0.0.1"))
        self.assertEqual("1.2.3.4", auth.derive_client_ip("1.2.3.4", None))
        self.assertEqual("127.0.0.1", auth.derive_client_ip("", "127.0.0.1"))
        self.assertEqual("127.0.0.1", auth.derive_client_ip(None, "127.0.0.1"))

    def test_stored_ip_map_is_bounded_under_a_flood(self):
        auth = load_auth()
        cap = auth.LOCKOUT_MAX_IPS
        for n in range(cap + 200):
            self.provider.record_failure(f"192.0.2.{n // 256}.{n % 256}")
        rec = self.provider.store.get("lockout", "ips") or {}
        self.assertLessEqual(len(rec), cap, "the per-ip map must never exceed the cap")

    def test_eviction_never_creates_a_lockout(self):
        auth = load_auth()
        cap = auth.LOCKOUT_MAX_IPS
        # One failure each for a flood of distinct ips: none reaches the
        # threshold, so after all the eviction churn none may be locked.
        for n in range(cap + 200):
            self.provider.record_failure(f"198.18.{n // 256}.{n % 256}")
        self.assertFalse(self.provider.is_locked("198.18.0.0"), "one failure is below threshold")
        self.assertFalse(self.provider.is_locked("10.11.12.13"), "a never-seen ip is never locked")

    def test_evicting_a_locked_ip_clears_it_only(self):
        auth = load_auth()
        cap = auth.LOCKOUT_MAX_IPS
        for _ in range(5):
            self.provider.record_failure("172.16.5.5")
        self.assertTrue(self.provider.is_locked("172.16.5.5"), "five failures lock an ip")
        # Flood past the cap so 172.16.5.5 is evicted; eviction only clears.
        for n in range(cap + 50):
            self.provider.record_failure(f"203.0.113.{n // 256}.{n % 256}")
        self.assertFalse(self.provider.is_locked("172.16.5.5"), "eviction clears a lockout, never keeps it")

    def test_failures_outside_the_window_do_not_count(self):
        auth = load_auth()
        now = 1_000_000.0
        for _ in range(5):
            self.provider.record_failure("192.0.2.200", now=now - auth.LOCKOUT_WINDOW_S - 1)
        self.assertFalse(self.provider.is_locked("192.0.2.200", now=now), "expired failures must not lock")
        for _ in range(5):
            self.provider.record_failure("192.0.2.201", now=now - 1)
        self.assertTrue(self.provider.is_locked("192.0.2.201", now=now), "recent failures lock")


if __name__ == "__main__":
    unittest.main()
