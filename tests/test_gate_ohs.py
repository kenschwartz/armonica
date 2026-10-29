"""P11 gating tests: optional hybrid search backend (OHS) behind
search_notes.

Contract for armonica.vault.Vault.search_notes when env OHS_BIN is
set. Re-pointed round 4 to the REAL binary output (ohs 0.15.1, verified
by running it); the previous round stubbed a guessed contract and the
guess was wrong:

- argv: the binary is invoked with list args (never a shell), subcommand
  "search", "--mode hybrid", "--limit N", "--db" plus the vault side
  SQLite path (env OHS_DB names that path), "--json", then "--" as the
  final argument with the raw query right after it. "--" must be final:
  the real binary reads every argument after the separator as a query
  operand, so an option placed after it (--json included) is silently
  ignored and the invocation returns rc 0 with no JSON on stdout. "--"
  also keeps a query that begins with "-" from being read as an option.
- with --json the binary prints a JSON LIST of objects on stdout:
  [{"path": ..., "title": ..., "tags": [...], "aliases": [...],
  "snippet": ..., "score": ...}, ...] with "path" vault-relative
- every returned path is resolved through Vault.resolve and anything that
  does not confine inside the vault root is dropped
- the result dict reports a three-value backend: "ohs" when the binary
  ran rc 0 and produced at least one confined hit, "ohs-empty" when it
  ran rc 0 with zero confined hits (substring results still returned),
  "fallback" when it is missing, exits non-zero, times out, or prints
  nothing parseable (substring results still returned)
- every "fallback" is logged through
  logging.getLogger("armonica.vault") carrying the returncode plus
  the first 200 chars of stderr, or the exception type

The timeout path is driven in test_gate_round2 (slow stub under a patched
OHS_TIMEOUT_S). tests/fixtures still holds the exit-1 fail stub; the
results stub is written inline below because the fixture pair encodes the
old guessed {"results": [...]} envelope, which the real binary never
prints. One test runs the REAL binary when present (skips otherwise) and
its docstring states exactly what it verifies.
"""

from __future__ import annotations

import json
import os
import py_compile
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

FIXTURES = Path(__file__).resolve().parent / "fixtures"
FAIL_STUB = FIXTURES / "ohs_stub_fail.py"

# Real ohs output shape (ohs 0.15.1): with --json the binary prints a JSON
# LIST of objects whose "path" is vault-relative. OHS_STUB_RESULTS carries
# that list verbatim; OHS_STUB_ARGV_FILE records the exact argv received.
LIST_STUB = """
import json
import os
import sys

argv_file = os.environ.get("OHS_STUB_ARGV_FILE")
if argv_file:
    with open(argv_file, "w") as f:
        json.dump(sys.argv, f)
items = json.loads(os.environ.get("OHS_STUB_RESULTS", "[]"))
json.dump(items, sys.stdout)
sys.stdout.write("\\n")
"""

# rc 0 with stdout the real binary only produces WITHOUT --json: a colored
# table no parser should accept. Drives the unparseable-output branch.
GARBAGE_STUB = """
import sys

sys.stdout.write("  score  path\\n")
sys.stdout.write("\\x1b[31m0.98  notes/hybrid.md\\x1b[0m\\n")
"""


def load_vault():
    try:
        from armonica import vault as vault_module
    except ImportError as exc:
        raise AssertionError(
            f"P11 gates packaged behavior: armonica.vault does not exist yet ({exc})"
        ) from exc
    return vault_module


def ohs_env(**over):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("OHS_", "IP_"))}
    env.update({k: str(v) for k, v in over.items()})
    return env


def write_stub(path: Path, body: str) -> Path:
    path.write_text("#!/usr/bin/env python3\n" + body)
    path.chmod(0o755)
    return path


class GateOhsIntegration(unittest.TestCase):
    def setUp(self):
        # no load_vault() here: the stub self-check below must run even
        # before the package exists
        base = tempfile.TemporaryDirectory()
        self.addCleanup(base.cleanup)
        self.base = Path(base.name)
        self.root = self.base / "vault"
        (self.root / "notes").mkdir(parents=True)
        (self.root / "notes" / "hybrid.md").write_text("hybrid backend note\n")
        (self.root / "notes" / "plain.md").write_text("plain substring needle\n")
        self.outside = self.base / "outside"
        self.outside.mkdir()
        (self.outside / "leaked.md").write_text("must never surface\n")
        self.ohs_db = self.base / "ohs" / "index.db"
        self.ohs_db.parent.mkdir()
        self.argv_path = self.base / "argv.json"
        self.stub = write_stub(self.base / "ohs_list_stub.py", LIST_STUB)
        self.garbage_stub = write_stub(self.base / "ohs_garbage_stub.py", GARBAGE_STUB)

    def assert_real_argv(self, argv, query):
        """The argv shape verified against the real binary (ohs 0.15.1)."""
        self.assertIn("--json", argv, "the JSON list only comes out under --json")
        self.assertIn("--db", argv)
        self.assertEqual(
            str(self.ohs_db), argv[argv.index("--db") + 1], "the --db path must follow the flag"
        )
        self.assertIn("--", argv, '"--" must separate the options from the query')
        sep = argv.index("--")
        self.assertEqual(query, argv[sep + 1], 'the query must sit right after "--"')
        self.assertEqual(
            len(argv),
            sep + 2,
            '"--" must be the FINAL argument: the real binary reads every'
            " argument after the separator as a query operand, so options"
            ' placed after "--" (--json included) are silently ignored and'
            " the invocation returns rc 0 with no JSON on stdout",
        )

    def test_fixture_fail_stub_is_sound(self):
        # Only the exit-1 fail stub still comes from tests/fixtures: it has
        # no output-shape dependency. The old results fixture encodes the
        # guessed {"results": [...]} envelope and is superseded by the
        # inline LIST_STUB above.
        self.assertTrue(FAIL_STUB.exists(), f"missing fixture {FAIL_STUB}")
        py_compile.compile(str(FAIL_STUB), doraise=True)
        self.assertTrue(os.access(FAIL_STUB, os.X_OK), f"{FAIL_STUB} must be executable")

    def test_ohs_hits_are_confined_and_backend_reported(self):
        vault = load_vault().Vault(self.root)
        items = [
            {"path": "notes/hybrid.md", "title": "hybrid", "snippet": "hybrid backend note", "score": 0.98},
            # the real binary emits vault-relative paths; a ".." escape and
            # an absolute outside path both probe the confinement drop
            {"path": "../outside/leaked.md", "score": 0.5},
            {"path": str(self.outside / "leaked.md"), "score": 0.5},
        ]
        env = ohs_env(
            OHS_BIN=self.stub,
            OHS_DB=self.ohs_db,
            OHS_STUB_RESULTS=json.dumps(items),
            OHS_STUB_ARGV_FILE=self.argv_path,
        )
        with mock.patch.dict(os.environ, env, clear=True):
            result = vault.search_notes("hybrid")
        self.assertEqual("ohs", result.get("backend"))
        paths = [r["path"] for r in result["results"]]
        self.assertIn("notes/hybrid.md", paths)
        self.assertFalse([p for p in paths if "leaked" in p], paths)
        self.assert_real_argv(json.loads(self.argv_path.read_text()), "hybrid")

    def test_rc0_with_zero_hits_reports_ohs_empty_and_keeps_substring_results(self):
        vault = load_vault().Vault(self.root)
        env = ohs_env(OHS_BIN=self.stub, OHS_DB=self.ohs_db, OHS_STUB_RESULTS="[]")
        with mock.patch.dict(os.environ, env, clear=True):
            result = vault.search_notes("needle")
        self.assertEqual(
            "ohs-empty",
            result.get("backend"),
            'rc 0 with zero confined hits is "ohs-empty", not "fallback"',
        )
        self.assertIn("notes/plain.md", [r["path"] for r in result["results"]])

    def test_missing_binary_falls_back_to_substring_scan_and_logs(self):
        vault = load_vault().Vault(self.root)
        env = ohs_env(OHS_BIN=self.base / "no-such-binary")
        with self.assertLogs("armonica.vault") as logs:
            with mock.patch.dict(os.environ, env, clear=True):
                result = vault.search_notes("needle")
        self.assertEqual("fallback", result.get("backend"))
        self.assertIn("notes/plain.md", [r["path"] for r in result["results"]])
        self.assertIn(
            "FileNotFoundError",
            "\n".join(logs.output),
            "every fallback must be logged naming the exception type",
        )

    def test_failing_binary_falls_back_to_substring_scan_and_logs(self):
        vault = load_vault().Vault(self.root)
        env = ohs_env(OHS_BIN=FAIL_STUB, OHS_DB=self.ohs_db)
        with self.assertLogs("armonica.vault") as logs:
            with mock.patch.dict(os.environ, env, clear=True):
                result = vault.search_notes("needle")
        self.assertEqual("fallback", result.get("backend"))
        self.assertIn("notes/plain.md", [r["path"] for r in result["results"]])
        self.assertIn(
            "stub failure",
            "\n".join(logs.output),
            "every fallback must be logged carrying the returncode and the"
            " first 200 chars of stderr",
        )

    def test_unparseable_output_falls_back_to_substring_scan_and_logs(self):
        vault = load_vault().Vault(self.root)
        env = ohs_env(OHS_BIN=self.garbage_stub, OHS_DB=self.ohs_db)
        with self.assertLogs("armonica.vault") as logs:
            with mock.patch.dict(os.environ, env, clear=True):
                result = vault.search_notes("needle")
        self.assertEqual("fallback", result.get("backend"))
        self.assertIn("notes/plain.md", [r["path"] for r in result["results"]])
        self.assertIn(
            "JSONDecodeError",
            "\n".join(logs.output),
            "unparseable output is a fallback: the log must name the exception type",
        )

    @unittest.skipUnless(
        shutil.which("ohs") or os.environ.get("OHS_REAL_BIN"),
        "no ohs binary on this host (set OHS_REAL_BIN to point at one)",
    )
    def test_real_binary_version_and_argv_shape(self):
        """Runs only where the real ohs binary is present.

        Actually verified: the real binary executes and answers --version
        with rc 0, and the implementation's argument construction matches
        the shape verified by hand against ohs 0.15.1 (--json present,
        "--" final with the query right after it, the --db pair).

        NOT verified: a real search against a real index. Building a real
        index needs the embedding API, which is unavailable on this host
        (each ohs call stalls roughly 12 s on the probe), so no real DB is
        created and no real search is faked: the search below drives the
        recording stub for the argv, never the real binary.
        """
        real_bin = os.environ.get("OHS_REAL_BIN") or shutil.which("ohs")
        proc = subprocess.run(
            [real_bin, "--version"], capture_output=True, text=True, timeout=10
        )
        self.assertEqual(0, proc.returncode, f"ohs --version failed: {proc.stderr[:200]}")
        self.assertTrue(proc.stdout.strip(), "--version must print a version")

        vault = load_vault().Vault(self.root)
        items = [{"path": "notes/hybrid.md", "title": "hybrid", "score": 0.98}]
        env = ohs_env(
            OHS_BIN=self.stub,
            OHS_DB=self.ohs_db,
            OHS_STUB_RESULTS=json.dumps(items),
            OHS_STUB_ARGV_FILE=self.argv_path,
        )
        with mock.patch.dict(os.environ, env, clear=True):
            result = vault.search_notes("hybrid")
        self.assertEqual("ohs", result.get("backend"))
        self.assert_real_argv(json.loads(self.argv_path.read_text()), "hybrid")


if __name__ == "__main__":
    unittest.main()
