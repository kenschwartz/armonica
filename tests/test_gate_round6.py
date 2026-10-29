"""Round 6 gating tests: community generalization, red until the build lands it.

The repo heads toward open-source release with no behavior change. Three new
properties, each red today:

- P12 path scrub: no private path or hostname may appear in the CONTENT of
  any git-tracked file outside tests/. The default needles are generic home
  directory prefixes; an operator adds their own machine-specific strings in
  the untracked file tests/private_strings.local (one per line, gitignored)
  or the PRIVATE_STRINGS env var (comma separated). Skips with a clear
  message when git is unavailable.
- P13 setup wizard, non-interactive: a new setup subcommand driven through
  the main(argv) seam with --vault-root, an https --public-url,
  --generate-secrets, --non-interactive and --plist-out must exit clean,
  leave passphrase.json plus exactly one client record under STATE_DIR,
  write a plist that parses, carries Label local.armonica, names the
  public url and the vault root, and holds no "__" placeholder markers, and
  print the tailscale funnel command plus the claude.ai paste step. A second
  identical run also completes cleanly (rotation allowed). An http:// public
  url is refused non-zero with a clear message. Red today: setup does not
  exist as a subcommand.
- P14 setup refuses incomplete non-interactive: dropping --vault-root or
  --public-url from the non-interactive invocation exits non-zero, names the
  missing argument, and writes nothing (no state files, no plist).
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import plistlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent

# P12 needles. The defaults are generic; operator-specific strings (home
# path, tailnet hostname, service label) live OUTSIDE the tree so the test
# itself never publishes them. tests/ is excluded because the gates quote
# the strings themselves.
DEFAULT_PRIVATE_STRINGS = ("/Users/", "/home/", "C:\\Users\\")


def private_strings() -> tuple[str, ...]:
    needles = list(DEFAULT_PRIVATE_STRINGS)
    local = REPO_ROOT / "tests" / "private_strings.local"
    if local.exists():
        needles += [ln.strip() for ln in local.read_text().splitlines() if ln.strip() and not ln.startswith("#")]
    env = os.environ.get("PRIVATE_STRINGS", "")
    needles += [x.strip() for x in env.split(",") if x.strip()]
    return tuple(dict.fromkeys(needles))


PRIVATE_STRINGS = private_strings()


def load_main():
    try:
        from armonica.__main__ import main
    except ImportError as exc:
        raise AssertionError(
            f"round 6 gates the packaged CLI: armonica.__main__ does not exist yet ({exc})"
        ) from exc
    return main


def make_vault(root: Path) -> Path:
    vault = root / "vault"
    vault.mkdir()
    (vault / "Welcome.md").write_text("# Vault\n\nOne note so the root is non-empty.\n")
    return vault


def plist_strings(node):
    """Every string in a parsed plist, keys included."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield key
            yield from plist_strings(value)
    elif isinstance(node, (list, tuple)):
        for item in node:
            yield from plist_strings(item)


class GatePathScrub(unittest.TestCase):
    """P12: the released tree carries no private paths or machine names."""

    maxDiff = None  # every offender must be visible in one run

    def test_tracked_files_outside_tests_carry_no_private_strings(self):
        try:
            proc = subprocess.run(
                ["git", "ls-files", "-z"], cwd=str(REPO_ROOT), capture_output=True, text=True
            )
        except FileNotFoundError:
            self.skipTest("git is not available, so tracked files cannot be listed")
        if proc.returncode != 0:
            self.skipTest(f"git ls-files failed with exit {proc.returncode}: not a git checkout?")
        tracked = [name for name in proc.stdout.split("\0") if name]
        self.assertTrue(tracked, "git ls-files listed nothing; refusing to pass the scrub vacuously")

        violations = []
        for rel in tracked:
            if rel.startswith("tests/"):
                continue
            blob = (REPO_ROOT / rel).read_bytes()
            for needle in PRIVATE_STRINGS:
                if needle.encode() in blob:
                    violations.append(f"{rel} contains {needle!r}")
        self.assertEqual(
            [],
            violations,
            f"P12: {len(violations)} private-string hits in tracked files outside tests/, "
            "scrub them before release",
        )


class GateSetupWizard(unittest.TestCase):
    """P13: non-interactive setup writes state, a concrete plist, and the two manual steps."""

    def build_case(self):
        base = tempfile.TemporaryDirectory()
        self.addCleanup(base.cleanup)
        root = Path(base.name)
        vault = make_vault(root)
        state = root / "state"
        state.mkdir()
        plist_path = root / "vc.plist"
        return vault, state, plist_path

    def run_setup(self, vault, state, plist_path, public_url):
        """Run the CLI in-process; returns (exit, stdout, stderr).

        exit is None when main() returned normally, otherwise the SystemExit
        code (argparse errors arrive here as 2).
        """
        main = load_main()
        argv = [
            "setup",
            "--vault-root", str(vault),
            "--public-url", public_url,
            "--generate-secrets",
            "--non-interactive",
            "--plist-out", str(plist_path),
        ]
        env = dict(os.environ)
        env["STATE_DIR"] = str(state)
        out, err = io.StringIO(), io.StringIO()
        code = None
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                mock.patch.dict(os.environ, env, clear=True):
            try:
                main(argv)
            except SystemExit as exc:
                code = 0 if exc.code is None else exc.code
        return code, out.getvalue(), err.getvalue()

    def test_setup_writes_state_plist_and_next_steps(self):
        vault, state, plist_path = self.build_case()
        code, out, err = self.run_setup(vault, state, plist_path, "https://x.example")
        self.assertIn(
            code, (None, 0),
            f"P13: non-interactive setup must exit clean, got {code}; stderr: {err}",
        )

        passphrase = json.loads((state / "passphrase.json").read_text())
        self.assertIsInstance(passphrase, dict, "setup must write passphrase.json under STATE_DIR")
        state_data = json.loads((state / "state.json").read_text())
        self.assertEqual(
            1, len(state_data.get("clients", {})), "setup must leave exactly one client record"
        )

        self.assertTrue(plist_path.is_file(), "setup must write the plist at --plist-out")
        # A generated plist must be concrete: a leftover __VAULT_ROOT__ style
        # marker means the wizard never filled the template, and nothing in a
        # fresh install legitimately needs a double underscore.
        self.assertNotIn("__", plist_path.read_text(), "the plist must carry no placeholder markers")
        plist = plistlib.loads(plist_path.read_bytes())
        self.assertEqual("local.armonica", plist.get("Label"))
        strings = list(plist_strings(plist))
        self.assertTrue(
            any("https://x.example" in s for s in strings), "the plist must name the public url"
        )
        self.assertTrue(
            any(str(vault) in s for s in strings), "the plist must name the vault root"
        )

        spoken = out.getvalue().lower()
        self.assertIn("tailscale", spoken, "setup must print the tailscale funnel command")
        self.assertIn("funnel", spoken, "setup must print the tailscale funnel command")
        self.assertIn("claude.ai", spoken, "setup must print the claude.ai paste step")

    def test_second_run_with_same_args_completes_cleanly(self):
        vault, state, plist_path = self.build_case()
        for attempt in (1, 2):
            code, out, err = self.run_setup(vault, state, plist_path, "https://x.example")
            self.assertIn(
                code, (None, 0),
                f"P13: setup run {attempt} must exit clean, got {code}; stderr: {err}",
            )
        state_data = json.loads((state / "state.json").read_text())
        self.assertEqual(
            1, len(state_data.get("clients", {})),
            "rotation must replace the single client, not append a second",
        )
        self.assertTrue((state / "passphrase.json").is_file(), "the passphrase must survive rotation")

    def test_http_public_url_is_refused_nonzero_with_clear_message(self):
        vault, state, plist_path = self.build_case()
        code, out, err = self.run_setup(vault, state, plist_path, "http://x.example")
        self.assertTrue(
            code not in (None, 0),
            "P13: an http public url must be refused, setup exited clean",
        )
        spoken = (out + err).lower()
        self.assertIn("https", spoken, "the refusal must say the public url has to be https")


class GateSetupRefusesIncomplete(unittest.TestCase):
    """P14: incomplete non-interactive setup fails loudly and writes nothing."""

    MISSING_CASES = {
        "--vault-root": ("vault-root", "vault_root"),
        "--public-url": ("public-url", "public_url"),
    }

    def test_missing_argument_is_named_and_nothing_is_written(self):
        main = load_main()
        for missing, spellings in self.MISSING_CASES.items():
            with self.subTest(missing=missing):
                base = tempfile.TemporaryDirectory()
                self.addCleanup(base.cleanup)
                root = Path(base.name)
                vault = make_vault(root)
                state = root / "state"
                state.mkdir()
                plist_path = root / "vc.plist"
                argv = [
                    "setup",
                    "--non-interactive",
                    "--generate-secrets",
                    "--plist-out", str(plist_path),
                ]
                if missing != "--vault-root":
                    argv += ["--vault-root", str(vault)]
                if missing != "--public-url":
                    argv += ["--public-url", "https://x.example"]
                env = dict(os.environ)
                env["STATE_DIR"] = str(state)
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                        mock.patch.dict(os.environ, env, clear=True):
                    with self.assertRaises(SystemExit) as caught:
                        main(argv)
                self.assertNotIn(
                    caught.exception.code, (None, 0),
                    f"P14: missing {missing} must exit non-zero",
                )
                spoken = (out.getvalue() + err.getvalue()).lower()
                self.assertTrue(
                    any(s in spoken for s in spellings),
                    f"P14: the refusal must name the missing argument {missing}, got: {spoken!r}",
                )
                self.assertEqual([], os.listdir(state), "the refusal must write no state files")
                self.assertFalse(plist_path.exists(), "the refusal must not write the plist")


if __name__ == "__main__":
    unittest.main()
