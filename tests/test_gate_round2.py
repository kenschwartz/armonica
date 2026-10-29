"""Round 2 gating tests: spec-QA findings F12 through F15.

Every test here is red until the build lands its property:

- F15 serve guard: serve with a passphrase set and an empty clients table
  must exit non-zero naming register-client instead of starting the server
- F15 revoke-all contract: revoke-all clears the access and refresh tables
  but keeps the registered clients row
- F13 store concurrency through delete_where: an instance that loaded before
  another instance's delete must not resurrect the deleted row when it saves
- F12 ohs merge: confined hybrid hits come first, then substring-only hits,
  deduped, with the outside-vault hit dropped; a hybrid result with nothing
  confined reports "ohs-empty" (round 4: three-value backend) while the
  substring scan still answers; a backend slower than OHS_TIMEOUT_S falls
  back
- F14 IPv6 loopback (amended round 3, findings F2/F02): a request with no
  X-Forwarded-For and remote address ::1 is refused 403 by default (the
  guard fails closed on the on-host proxy's loopback peer) and reaches the
  wrapped app only under env ALLOW_LOCAL=1, the local-test escape

Until the build moves the flat modules into a armonica package,
activate_package() aliases the repo root as that package so these gates
drive today's code and fail on the property rather than on a missing
module. The alias is dropped after every test; the rest of the suite never
sees it.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import os
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

from mcp.shared.auth import OAuthClientInformationFull

REPO_ROOT = Path(__file__).resolve().parent.parent
CLAUDE_CALLBACK = "https://claude.ai/api/mcp/auth_callback"
PUBLIC_URL = "https://vault-test.example"
HOST = "vault-test.example"
PASSPHRASE = "round two gating passphrase that is long enough"
SENTINEL = "round2 sentinel: uvicorn.run reached"

# Real ohs output shape (ohs 0.15.1, re-pointed round 4): with --json the
# binary prints a JSON LIST of objects whose "path" is vault-relative.
# OHS_STUB_RESULTS carries that list verbatim.
RESULTS_STUB = """
import json
import os
import sys

items = json.loads(os.environ.get("OHS_STUB_RESULTS", "[]"))
json.dump(items, sys.stdout)
sys.stdout.write("\\n")
"""

SLOW_STUB = """
import json
import os
import sys
import time

time.sleep(0.4)
items = json.loads(os.environ.get("OHS_STUB_RESULTS", "[]"))
json.dump(items, sys.stdout)
sys.stdout.write("\\n")
"""


def activate_package(test: unittest.TestCase) -> None:
    """Make armonica importable for this one test.

    Prefers the real package. Before the build creates it, the flat modules
    at the repo root are aliased in as the package; the alias and every
    submodule imported under it are dropped again on cleanup.
    """
    try:
        import armonica  # noqa: F401

        return
    except ImportError:
        pass
    before = set(sys.modules)
    pkg = types.ModuleType("armonica")
    pkg.__path__ = [str(REPO_ROOT)]
    sys.modules["armonica"] = pkg

    def drop_alias():
        gone = [
            k
            for k in sys.modules
            if (k == "armonica" or k.startswith("armonica.")) and k not in before
        ]
        for key in gone:
            del sys.modules[key]

    test.addCleanup(drop_alias)


def write_passphrase(auth, state_dir: Path, passphrase: str) -> None:
    record = auth.hash_passphrase(passphrase)
    fd = os.open(state_dir / "passphrase.json", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(record, f)


def cli_env(**over) -> dict:
    # ALLOW_LOCAL is stripped from the ambient copy too: an inherited value
    # would flip the fail-closed default case; only an explicit override
    # may turn it on
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("OHS_", "IP_", "ALLOW_LOCAL"))
    }
    env.update({k: str(v) for k, v in over.items()})
    return env


def write_stub(path: Path, body: str) -> Path:
    path.write_text("#!/usr/bin/env python3\n" + body)
    path.chmod(0o755)
    return path


class GateServeEmptyClientsGuard(unittest.TestCase):
    """F15: serve refuses to start when no client can ever authenticate."""

    def test_serve_with_passphrase_and_empty_clients_exits_naming_register_client(self):
        activate_package(self)
        from armonica import __main__ as cli
        from armonica import auth

        base = tempfile.TemporaryDirectory()
        self.addCleanup(base.cleanup)
        state = Path(base.name) / "state"
        state.mkdir()
        vault_root = Path(base.name) / "vault"
        vault_root.mkdir()
        write_passphrase(auth, state, PASSPHRASE)
        # no state.json: the clients table exists and is empty

        fake_uvicorn = types.ModuleType("uvicorn")

        def fail_run(*args, **kwargs):
            raise RuntimeError(SENTINEL)

        fake_uvicorn.run = fail_run
        stderr = io.StringIO()
        try:
            with mock.patch.dict(sys.modules, {"uvicorn": fake_uvicorn}), mock.patch.dict(
                os.environ,
                cli_env(STATE_DIR=state, VAULT_ROOT=vault_root, PUBLIC_URL=PUBLIC_URL),
                clear=True,
            ), mock.patch.object(
                sys, "argv", ["armonica", "serve"]
            ), contextlib.redirect_stderr(stderr):
                cli.main()
        except SystemExit as exc:
            self.assertNotIn(exc.code, (None, 0), "F15: the refusal must exit non-zero")
            self.assertIn(
                "register-client",
                f"{exc.code} {stderr.getvalue()}",
                "F15: the refusal must tell the operator to run register-client",
            )
        except RuntimeError as exc:
            if SENTINEL in str(exc):
                self.fail(
                    "F15: serve reached uvicorn.run with a passphrase set and zero"
                    " registered clients: the empty-clients guard is absent"
                )
            raise
        else:
            self.fail("F15: serve returned instead of refusing to start")


class GateRevokeAllKeepsClients(unittest.TestCase):
    """F15: revoke-all revokes tokens, not the registered client itself."""

    def setUp(self):
        activate_package(self)
        from armonica import auth

        self.auth = auth
        base = tempfile.TemporaryDirectory()
        self.addCleanup(base.cleanup)
        self.state = Path(base.name) / "state"
        self.state.mkdir()
        if hasattr(auth, "preregister_client"):
            self.client_id, _secret = auth.preregister_client(self.state)
        else:
            # register through the real provider so the row is a genuine
            # client record even before preregister_client exists
            provider = auth.VaultOAuthProvider(PUBLIC_URL, f"{PUBLIC_URL}/mcp", self.state)
            info = OAuthClientInformationFull(
                client_id="cid-round2",
                client_name="round2 gate",
                redirect_uris=[CLAUDE_CALLBACK],
            )
            asyncio.run(provider.register_client(info))
            self.client_id = "cid-round2"
        store = auth.Store(self.state / "state.json")
        now = time.time()
        record = {
            "client_id": self.client_id,
            "scopes": ["vault.read"],
            "family": "fam",
            "issued_at": now,
        }
        store.put("access", "h-access", {**record, "expires_at": now + 3600})
        store.put("refresh", "h-refresh", {**record, "expires_at": now + 30 * 24 * 3600})

    def test_revoke_all_clears_tokens_and_keeps_the_one_client(self):
        from armonica import __main__ as cli

        with mock.patch.dict(
            os.environ, cli_env(STATE_DIR=self.state), clear=True
        ), mock.patch.object(
            sys, "argv", ["armonica", "revoke-all"]
        ), contextlib.redirect_stdout(io.StringIO()):
            cli.main()

        fresh = self.auth.Store(self.state / "state.json")
        self.assertEqual({}, fresh.data["access"], "revoke-all must clear the access table")
        self.assertEqual({}, fresh.data["refresh"], "revoke-all must clear the refresh table")
        self.assertEqual(
            [self.client_id],
            sorted(fresh.data["clients"]),
            "F15: revoke-all deleted the registered clients row;"
            " the client outlives token revocation",
        )


class GateStoreDeleteWhereCollision(unittest.TestCase):
    """F13: a save must not resurrect a row another instance deleted."""

    def test_put_after_external_delete_keeps_the_row_deleted(self):
        activate_package(self)
        from armonica import auth

        base = tempfile.TemporaryDirectory()
        self.addCleanup(base.cleanup)
        path = Path(base.name) / "state.json"

        a = auth.Store(path)
        b = auth.Store(path)
        expiry = time.time() + 3600
        a.put("access", "key-doom", {"client_id": "c", "expires_at": expiry})
        mtime_a_saw = path.stat().st_mtime_ns
        b.delete_where("access", lambda k, v: k == "key-doom")
        # force the timestamp collision window A already cached
        os.utime(path, ns=(mtime_a_saw, mtime_a_saw))
        a.put("access", "key-new", {"client_id": "c", "expires_at": expiry})

        fresh = auth.Store(path)
        self.assertIn("key-new", fresh.data["access"], "A's own new row was lost")
        self.assertNotIn(
            "key-doom",
            fresh.data["access"],
            "F13: A's save resurrected the row B deleted; the mtime cache hid B's write",
        )


class GateOhsMergeOrderFallbackTimeout(unittest.TestCase):
    """F12: merge order, confined-empty ohs-empty and timeout for the ohs backend."""

    def setUp(self):
        base = tempfile.TemporaryDirectory()
        self.addCleanup(base.cleanup)
        self.base = Path(base.name)
        self.root = self.base / "vault"
        (self.root / "notes").mkdir(parents=True)
        # the query term never appears in this note or its path: only the
        # hybrid backend can surface it
        (self.root / "notes" / "ohs-only.md").write_text(
            "found only through the hybrid index\n"
        )
        (self.root / "notes" / "substring-hit.md").write_text(
            "the substring scan finds roundtwo-needle on its own\n"
        )
        self.outside = self.base / "outside"
        self.outside.mkdir()
        (self.outside / "leaked.md").write_text("must never surface\n")
        self.ohs_db = self.base / "ohs" / "index.db"
        self.ohs_db.parent.mkdir()
        self.stub = write_stub(self.base / "ohs_results_stub.py", RESULTS_STUB)
        self.slow_stub = write_stub(self.base / "ohs_slow_stub.py", SLOW_STUB)

    def test_confined_ohs_hit_first_then_substring_hit_deduped(self):
        activate_package(self)
        from armonica import vault

        # a realistic ohs hit: the query term really is in the note text,
        # so the all-terms contract passes and the substring scan finds it
        # too (the dedup below has a genuinely dual-found note to work on)
        (self.root / "notes" / "ohs-hit.md").write_text(
            "an indexed note whose text carries roundtwo-needle\n"
        )
        env = cli_env(
            OHS_BIN=self.stub,
            OHS_DB=self.ohs_db,
            OHS_STUB_RESULTS=json.dumps(
                [
                    {"path": "notes/ohs-hit.md", "score": 0.9},
                    # the real binary emits vault-relative paths; a ".."
                    # escape probes the confinement drop
                    {"path": "../outside/leaked.md", "score": 0.4},
                ]
            ),
        )
        with mock.patch.dict(os.environ, env, clear=True):
            result = vault.Vault(self.root).search_notes("roundtwo-needle")
        self.assertEqual(
            "ohs",
            result.get("backend"),
            'F12: a hybrid hit that confines must report backend "ohs"',
        )
        self.assertEqual(
            ["notes/ohs-hit.md", "notes/substring-hit.md"],
            [r["path"] for r in result["results"]],
            "F12: confined ohs hit first, then the substring-only hit,"
            " outside hit dropped, the dual-found note listed once",
        )

    def test_ohs_hit_without_all_terms_is_dropped(self):
        activate_package(self)
        from armonica import vault

        # notes/ohs-only.md is in the vault but neither its text nor its
        # path holds the query term: ohs may recall it, never widen the
        # term semantics (the round 5 all-terms contract)
        env = cli_env(
            OHS_BIN=self.stub,
            OHS_DB=self.ohs_db,
            OHS_STUB_RESULTS=json.dumps(
                [{"path": "notes/ohs-only.md", "score": 0.9}]
            ),
        )
        with mock.patch.dict(os.environ, env, clear=True):
            result = vault.Vault(self.root).search_notes("roundtwo-needle")
        self.assertEqual(
            "ohs-empty",
            result.get("backend"),
            'F12 (round 5): an ohs hit failing the all-terms contract must'
            ' report backend "ohs-empty", not "ohs"',
        )
        self.assertNotIn(
            "notes/ohs-only.md",
            [r["path"] for r in result["results"]],
            "F12 (round 5): an ohs hit without every query term surfaced",
        )
        self.assertEqual(
            ["notes/substring-hit.md"],
            [r["path"] for r in result["results"]],
            "F12 (round 5): the substring results must survive the drop",
        )

    def test_ohs_result_with_nothing_confined_reports_ohs_empty(self):
        activate_package(self)
        from armonica import vault

        env = cli_env(
            OHS_BIN=self.stub,
            OHS_DB=self.ohs_db,
            OHS_STUB_RESULTS=json.dumps(
                [{"path": str(self.outside / "leaked.md"), "score": 0.4}]
            ),
        )
        with mock.patch.dict(os.environ, env, clear=True):
            result = vault.Vault(self.root).search_notes("roundtwo-needle")
        self.assertEqual(
            "ohs-empty",
            result.get("backend"),
            'F12 (round 4): rc 0 with nothing confined must report backend'
            ' "ohs-empty", not "fallback"',
        )
        self.assertEqual(
            ["notes/substring-hit.md"],
            [r["path"] for r in result["results"]],
            "F12: the outside-vault hit must be dropped and the substring results kept",
        )

    def test_slow_backend_times_out_and_falls_back(self):
        activate_package(self)
        from armonica import vault as vault_module

        if not hasattr(vault_module, "OHS_TIMEOUT_S"):
            self.fail(
                "F12: armonica.vault has no OHS_TIMEOUT_S constant:"
                " the hybrid backend timeout property is absent"
            )
        env = cli_env(
            OHS_BIN=self.slow_stub,
            OHS_DB=self.ohs_db,
            OHS_STUB_RESULTS=json.dumps([{"path": "notes/ohs-only.md", "score": 0.9}]),
        )
        with self.assertLogs("armonica.vault") as logs:
            with mock.patch.object(vault_module, "OHS_TIMEOUT_S", 0.1), mock.patch.dict(
                os.environ, env, clear=True
            ):
                result = vault_module.Vault(self.root).search_notes("roundtwo-needle")
        self.assertEqual(
            "fallback",
            result.get("backend"),
            "F12: a backend slower than OHS_TIMEOUT_S must be abandoned for the substring scan",
        )
        self.assertIn(
            "notes/substring-hit.md",
            [r["path"] for r in result["results"]],
            "F12: the substring scan must still answer when the backend times out",
        )
        self.assertIn(
            "timeout",
            "\n".join(logs.output).lower(),
            "every fallback must be logged; a timeout names the timeout",
        )


class CaptureApp:
    """Records whether the middleware let the request through."""

    def __init__(self):
        self.called = False

    async def __call__(self, scope, receive, send):
        self.called = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})


class GateIpv6Loopback(unittest.TestCase):
    """F14, amended round 3 (F2/F02): IPv6 loopback fails closed without XFF.

    ::1 with no X-Forwarded-For is refused 403 by default: the on-host
    proxy speaks from loopback carrying no provenance, so loopback alone
    must not satisfy the guard. Env ALLOW_LOCAL=1 is the local-test escape
    and lets ::1 through to the wrapped app.
    """

    def setUp(self):
        activate_package(self)
        try:
            from armonica.server import IPAllowlistMiddleware
        except ImportError as exc:
            self.fail(f"F14: armonica.server has no IPAllowlistMiddleware yet ({exc})")
        self.middleware = IPAllowlistMiddleware

    def _guard(self, path, client, env):
        """Drive the middleware with one no-XFF request; return (status, called)."""
        capture = CaptureApp()
        # no x-forwarded-for header: the direct remote address decides
        scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "method": "POST",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "headers": [(b"host", HOST.encode())],
            "scheme": "https",
            "server": (HOST, 443),
            "client": client,
            "root_path": "",
            "http_version": "1.1",
        }

        async def run():
            sent = []

            async def receive():
                return {"type": "http.request", "body": b"", "more_body": False}

            async def send(message):
                sent.append(message)

            with mock.patch.dict(os.environ, env, clear=True):
                middleware = self.middleware(capture)
                await middleware(scope, receive, send)
            start = next((m for m in sent if m["type"] == "http.response.start"), None)
            self.assertIsNotNone(start, "the middleware produced no response")
            return start["status"]

        return asyncio.run(run()), capture.called

    def test_no_xff_ipv6_loopback_blocked_by_default(self):
        for path in ("/mcp", "/token", "/.well-known/oauth-authorization-server"):
            with self.subTest(path=path):
                status, called = self._guard(path, ("::1", 41061), cli_env())
                self.assertFalse(
                    called,
                    "F02: no-XFF ::1 must not reach the wrapped app by default;"
                    " the guard fails closed on the proxy's loopback peer",
                )
                self.assertEqual(403, status)

    def test_no_xff_ipv6_loopback_passes_under_allow_local(self):
        for path in ("/mcp", "/token", "/.well-known/oauth-authorization-server"):
            with self.subTest(path=path):
                status, called = self._guard(path, ("::1", 41061), cli_env(ALLOW_LOCAL="1"))
                self.assertTrue(
                    called,
                    "F14: with ALLOW_LOCAL=1 the local-test escape must let"
                    f" {path} from ::1 reach the wrapped app",
                )
                self.assertEqual(200, status)


if __name__ == "__main__":
    unittest.main()
