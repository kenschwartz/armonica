"""Fixes from the 2026-10-29 pre-publication reviews.

- /revoke sits behind the IP allowlist like /token (red team R1).
- setup refuses a public URL with a path, query, login or markup, and escapes
  every value it writes into the launchd plist and the systemd unit (R5).
- the systemd unit runs as the user who ran setup and points at their state
  directory, instead of running as root with no state.
- setup prints how to start the server (R3).
- serve refuses a malformed IP_ALLOWLIST_CIDR at startup instead of 500ing
  every request (R6).
- the text Claude sees on connect names nobody, and VAULT_INSTRUCTIONS
  replaces it.
"""

import asyncio
import contextlib
import getpass
import io
import os
import plistlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from armonica.__main__ import main
from armonica.auth import hash_passphrase, preregister_client
from armonica.server import INSTRUCTIONS, IPAllowlistMiddleware

HOSTILE = 'My Vault & <x> ]]> 100% "q" $HOME `id`'


def run_cli(argv, env):
    out, err = io.StringIO(), io.StringIO()
    code = None
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
            mock.patch.dict(os.environ, env, clear=True):
        try:
            main(argv)
        except SystemExit as exc:
            code = 0 if exc.code is None else exc.code
    return code, out.getvalue(), err.getvalue()


def systemd_values(unit_text):
    """Environment="K=V" lines back to {K: V}, undoing the setup escaping."""
    found = {}
    for line in unit_text.splitlines():
        if line.startswith('Environment="') and line.endswith('"'):
            body = line[len('Environment="'):-1]
            body = body.replace("%%", "%")
            out, i = [], 0
            while i < len(body):
                if body[i] == "\\" and i + 1 < len(body):
                    out.append(body[i + 1])
                    i += 2
                else:
                    out.append(body[i])
                    i += 1
            key, _, value = "".join(out).partition("=")
            found[key] = value
    return found


class RevokeIsAllowlisted(unittest.TestCase):
    def status_for(self, path, xff):
        async def app(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        scope = {"type": "http", "method": "POST", "path": path, "client": ("127.0.0.1", 40000),
                 "headers": [(b"x-forwarded-for", xff.encode())]}
        sent = []

        async def receive():
            return {"type": "http.request", "body": b""}

        async def send(message):
            sent.append(message)

        env = {k: v for k, v in os.environ.items() if not k.startswith(("IP_ALLOWLIST", "ALLOW_LOCAL"))}
        with mock.patch.dict(os.environ, env, clear=True):
            asyncio.run(IPAllowlistMiddleware(app)(scope, receive, send))
        return sent[0]["status"]

    def test_revoke_from_outside_the_range_is_refused(self):
        self.assertEqual(403, self.status_for("/revoke", "8.8.8.8"))

    def test_revoke_from_inside_the_range_passes(self):
        self.assertEqual(200, self.status_for("/revoke", "160.79.104.10"))


class SetupWritesSafeUnits(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.state = self.root / "state"
        self.env = {"PATH": os.environ.get("PATH", ""), "HOME": str(self.root), "STATE_DIR": str(self.state)}

    def setup(self, vault, url="https://vault.example.com", extra=()):
        argv = ["setup", "--vault-root", str(vault), "--public-url", url, "--generate-secrets",
                "--non-interactive", *extra]
        return run_cli(argv, self.env)

    def test_hostile_vault_path_survives_plist_and_unit_exactly(self):
        vault = self.root / HOSTILE
        vault.mkdir()
        plist, unit = self.root / "vc.plist", self.root / "vc.service"
        code, out, err = self.setup(vault, extra=["--plist-out", str(plist), "--systemd-out", str(unit)])
        self.assertIn(code, (None, 0), err)
        env = plistlib.loads(plist.read_bytes())["EnvironmentVariables"]
        self.assertEqual(str(vault.resolve()), env["VAULT_ROOT"])
        self.assertEqual(str(self.state.resolve()), env["STATE_DIR"])
        self.assertEqual({"VAULT_ROOT", "PUBLIC_URL", "STATE_DIR", "PORT", "IP_ALLOWLIST"}, set(env))
        values = systemd_values(unit.read_text())
        self.assertEqual(str(vault.resolve()), values["VAULT_ROOT"])
        self.assertEqual(str(self.state.resolve()), values["STATE_DIR"])

    def test_unit_runs_as_the_setup_user_not_root(self):
        unit = self.root / "vc.service"
        vault = self.root / "v"
        vault.mkdir()
        self.setup(vault, extra=["--systemd-out", str(unit)])
        self.assertIn(f"User={getpass.getuser()}", unit.read_text().splitlines())

    def test_next_steps_say_how_to_start_the_server(self):
        vault = self.root / "v"
        vault.mkdir()
        plist, unit = self.root / "vc.plist", self.root / "vc.service"
        _, out, _ = self.setup(vault, extra=["--plist-out", str(plist), "--systemd-out", str(unit)])
        self.assertIn("launchctl bootstrap gui/$(id -u)", out)
        self.assertIn("systemctl enable --now armonica", out)
        self.assertLess(out.index("Start the server"), out.index("tailscale funnel"))

    def test_public_url_with_path_markup_or_login_is_refused(self):
        vault = self.root / "v"
        vault.mkdir()
        for url in ("http://vault.example.com", "https://vault.example.com/mcp", "https://a@vault.example.com",
                    "https://vault.example.com?x=1", "https://x.example</string><key>Injected</key><string>y",
                    "https://", "https://vault.example.com:99999"):
            plist = self.root / "refused.plist"
            code, _, err = self.setup(vault, url=url, extra=["--plist-out", str(plist)])
            with self.subTest(url=url):
                self.assertEqual(1, code)
                self.assertIn("https", err.lower())
                self.assertFalse(plist.exists(), "a refused setup must not write a plist")

    def test_vault_path_with_a_newline_is_refused(self):
        vault = self.root / "bad\nname"
        vault.mkdir()
        code, _, err = self.setup(vault)
        self.assertEqual(1, code)
        self.assertIn("control character", err)


class ServeChecksConfig(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.state = root / "state"
        self.state.mkdir()
        (self.state / "passphrase.json").write_text(__import__("json").dumps(hash_passphrase("x" * 24)))
        preregister_client(self.state)
        self.vault = root / "vault"
        self.vault.mkdir()

    def serve(self, **extra):
        env = {"PATH": os.environ.get("PATH", ""), "VAULT_ROOT": str(self.vault),
               "PUBLIC_URL": "https://vault.example.com", "STATE_DIR": str(self.state), **extra}
        seen = {}
        with mock.patch("uvicorn.run") as run, \
                mock.patch("armonica.server.build_app", side_effect=lambda cfg: seen.setdefault("cfg", cfg)):
            code, out, err = run_cli(["serve"], env)
        return code, err, run, seen.get("cfg")

    def test_malformed_cidr_list_stops_startup(self):
        code, err, run, _ = self.serve(IP_ALLOWLIST_CIDR="not-a-cidr")
        self.assertEqual(1, code)
        self.assertIn("IP_ALLOWLIST_CIDR", err)
        run.assert_not_called()

    def test_valid_cidr_list_starts(self):
        code, err, run, _ = self.serve(IP_ALLOWLIST_CIDR="160.79.104.0/21, 10.0.0.0/8")
        self.assertIn(code, (None, 0), err)
        run.assert_called_once()

    def test_default_instructions_name_nobody_and_can_be_replaced(self):
        self.assertNotIn("Ken", INSTRUCTIONS)
        _, _, _, cfg = self.serve()
        self.assertEqual(INSTRUCTIONS, cfg.instructions)
        _, _, _, cfg = self.serve(VAULT_INSTRUCTIONS="My vault keeps projects under Projects/.")
        self.assertEqual("My vault keeps projects under Projects/.", cfg.instructions)


if __name__ == "__main__":
    unittest.main()
