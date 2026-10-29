"""P4 gating tests: dynamic client registration removed, one confidential
client pre-registered.

Contract:
- ClientRegistrationOptions(enabled=False): the app built by build_app has
  no route matching "register" anywhere, and provider.register_client always
  raises RegistrationError no matter what is submitted
- provider.get_client returns None for unknown client ids
- armonica.auth.preregister_client(state_dir) is the engine behind
  `register-client --generate`: it stores exactly one client record and
  returns (client_id, client_secret)
- the stored record: token_endpoint_auth_method "client_secret_basic",
  redirect_uris exactly [Claude's callback], and the stored client_secret
  equals the returned secret so the SDK ClientAuthenticator can verify it
"""

from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

from mcp.server.auth.provider import RegistrationError
from mcp.shared.auth import OAuthClientInformationFull

CLAUDE_CALLBACK = "https://claude.ai/api/mcp/auth_callback"
PUBLIC_URL = "https://vault-test.example"


def load_auth():
    try:
        from armonica import auth
    except ImportError as exc:
        raise AssertionError(
            f"P4 gates packaged behavior: armonica.auth does not exist yet ({exc})"
        ) from exc
    return auth


def load_server():
    try:
        from armonica import server
    except ImportError as exc:
        raise AssertionError(
            f"P4 gates packaged behavior: armonica.server does not exist yet ({exc})"
        ) from exc
    return server


class GateConfidentialClient(unittest.TestCase):
    def setUp(self):
        load_auth()
        base = tempfile.TemporaryDirectory()
        self.addCleanup(base.cleanup)
        self.base = Path(base.name)
        self.state_dir = self.base / "state"
        self.state_dir.mkdir()
        self.vault_root = self.base / "vault"
        self.vault_root.mkdir()

    def provider(self):
        return load_auth().VaultOAuthProvider(PUBLIC_URL, f"{PUBLIC_URL}/mcp", self.state_dir)

    def test_unknown_client_id_returns_none(self):
        self.assertIsNone(asyncio.run(self.provider().get_client("no-such-client")))

    def test_register_client_always_refused(self):
        rogue = OAuthClientInformationFull(
            client_id="rogue-1",
            client_name="rogue",
            redirect_uris=[CLAUDE_CALLBACK],
            token_endpoint_auth_method="none",
        )
        with self.assertRaises(RegistrationError):
            asyncio.run(self.provider().register_client(rogue))

    def test_preregistered_client_record_shape(self):
        auth = load_auth()
        client_id, client_secret = auth.preregister_client(self.state_dir)
        self.assertIsInstance(client_id, str)
        self.assertTrue(client_id)
        self.assertIsInstance(client_secret, str)
        self.assertTrue(client_secret)
        stored = auth.Store(self.state_dir / "state.json").data["clients"]
        self.assertEqual(1, len(stored), "exactly one client may exist")
        client = asyncio.run(self.provider().get_client(client_id))
        self.assertIsNotNone(client)
        self.assertEqual("client_secret_basic", client.token_endpoint_auth_method)
        self.assertEqual([CLAUDE_CALLBACK], [str(u) for u in client.redirect_uris])
        self.assertEqual(client_secret, client.client_secret)

    def test_app_route_table_has_no_register_path(self):
        server = load_server()
        app = server.build_app(
            server.Config(
                vault_root=self.vault_root, public_url=PUBLIC_URL, state_dir=self.state_dir
            )
        )
        paths = sorted({getattr(route, "path", "") for route in app.routes})
        self.assertFalse(
            any("register" in p for p in paths),
            f"no route may expose dynamic registration, found: {paths}",
        )
        for expected in ("/authorize", "/token", "/login", "/healthz"):
            self.assertIn(expected, paths)


if __name__ == "__main__":
    unittest.main()
