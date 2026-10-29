"""P1 gating tests: the armonica package and its CLI surface.

What the build must deliver:
- the flat root modules move into the armonica package, runnable as
  `python -m armonica`
- CLI subcommands: serve, set-passphrase, revoke-all, status, register-client
- top level --help and each subcommand --help exit 0
- serve exits non-zero when VAULT_ROOT or PUBLIC_URL is missing, before
  binding any port

main() must accept an argv list (main(argv) or main(argv=None)) so the CLI is
drivable in-process; this suite spawns no subprocesses. Red today because the
armonica package does not exist while the modules sit flat at the repo
root, so `python -m armonica` cannot run at all.
"""

from __future__ import annotations

import contextlib
import io
import os
import unittest
from unittest import mock

SUBCOMMANDS = ("serve", "set-passphrase", "revoke-all", "status", "register-client")


def load_main():
    try:
        from armonica.__main__ import main
    except ImportError as exc:
        raise AssertionError(
            "P1 property absent: `python -m armonica` cannot run because the "
            f"armonica package does not exist yet ({exc})"
        ) from exc
    if not callable(main):
        raise AssertionError("armonica.__main__ must expose a callable main()")
    return main


class GatePackagingCli(unittest.TestCase):
    def test_help_exits_zero_and_lists_every_subcommand(self):
        main = load_main()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            with self.assertRaises(SystemExit) as caught:
                main(["--help"])
        self.assertEqual(0, caught.exception.code)
        for cmd in SUBCOMMANDS:
            self.assertIn(cmd, out.getvalue(), f"--help must list the {cmd} subcommand")

    def test_every_subcommand_help_exits_zero(self):
        main = load_main()
        for cmd in SUBCOMMANDS:
            with self.subTest(cmd=cmd):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    with self.assertRaises(SystemExit) as caught:
                        main([cmd, "--help"])
                self.assertEqual(0, caught.exception.code)

    def test_serve_without_vault_root_exits_nonzero(self):
        main = load_main()
        env = {k: v for k, v in os.environ.items() if k != "VAULT_ROOT"}
        env["PUBLIC_URL"] = "https://vault-test.example"
        with mock.patch.dict(os.environ, env, clear=True):
            with self.assertRaises(SystemExit) as caught:
                main(["serve"])
        self.assertNotEqual(0, caught.exception.code)

    def test_serve_without_public_url_exits_nonzero(self):
        main = load_main()
        env = {k: v for k, v in os.environ.items() if k != "PUBLIC_URL"}
        env["VAULT_ROOT"] = os.getcwd()
        with mock.patch.dict(os.environ, env, clear=True):
            with self.assertRaises(SystemExit) as caught:
                main(["serve"])
        self.assertNotEqual(0, caught.exception.code)


if __name__ == "__main__":
    unittest.main()
