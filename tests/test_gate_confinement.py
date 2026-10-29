"""P2 gating tests: vault confinement survives the repackage unchanged.

Today's refusal behavior, pinned so the move into armonica.vault
cannot change it: relative .md notes are listable, readable and searchable;
absolute paths, tilde, "..", dotfile or dot-folder components, symlinks that
leave the vault, symlinks into a dot-folder and non-.md files are refused
with VaultError. A note over 256 KB reads as a partial page with
next_start_line, and list_folder past its cap reports truncated.

Red today only because armonica.vault does not exist yet; after the
move every assertion here must hold against the packaged Vault unchanged.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock


def load_vault():
    try:
        from armonica import vault as vault_module
    except ImportError as exc:
        raise AssertionError(
            f"P2 gates packaged behavior: armonica.vault does not exist yet ({exc})"
        ) from exc
    return vault_module


def big_note_text() -> str:
    lines = [f"filler line {i:06d} " + "x" * 40 for i in range(6000)]
    return "\n".join(lines) + "\n"


class GateConfinement(unittest.TestCase):
    def setUp(self):
        load_vault()  # fail on the missing package before building fixtures
        base = tempfile.TemporaryDirectory()
        self.addCleanup(base.cleanup)
        self.base = Path(base.name)
        self.root = self.base / "vault"
        (self.root / "notes" / "sub").mkdir(parents=True)
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "secret.md").write_text("content outside the vault\n")
        (self.root / "notes" / "hello.md").write_text(
            "---\ntitle: Hello\n---\n\nhello vault needle one\n"
        )
        (self.root / "notes" / "sub" / "deep.md").write_text("deep note\n")
        (self.root / "other.txt").write_text("not markdown\n")
        (self.root / ".hidden.md").write_text("dotfile note\n")
        (self.root / ".dotdir").mkdir()
        (self.root / ".dotdir" / "secret.md").write_text("hidden folder note\n")
        (self.root / "symlink-out.md").symlink_to(outside / "secret.md")
        (self.root / "notes" / "into-dot.md").symlink_to(self.root / ".dotdir" / "secret.md")
        (self.root / "linkdir").symlink_to(outside)
        self.vault = load_vault().Vault(self.root)

    def test_normal_note_readable_end_to_end(self):
        # Negative control: a plain .md note must come back complete.
        text = (self.root / "notes" / "hello.md").read_text()
        res = self.vault.read_note("notes/hello.md")
        self.assertEqual("\n".join(text.splitlines()), res["content"])
        self.assertEqual(len(text.splitlines()), res["total_lines"])
        self.assertNotIn("next_start_line", res)
        self.assertEqual("Hello", res["frontmatter"]["fields"]["title"])

    def test_list_folder_shows_only_visible_entries(self):
        root_listing = self.vault.list_folder("")
        self.assertIn("notes", root_listing["folders"])
        self.assertNotIn(".dotdir", root_listing["folders"])
        all_paths = root_listing["folders"] + [n["path"] for n in root_listing["notes"]]
        for bad in (".hidden.md", "other.txt", "symlink-out.md", ".dotdir"):
            self.assertNotIn(bad, all_paths)
        notes_listing = self.vault.list_folder("notes")
        self.assertEqual(["notes/sub"], notes_listing["folders"])
        self.assertEqual(["notes/hello.md"], [n["path"] for n in notes_listing["notes"]])

    def test_search_finds_visible_notes_only(self):
        res = self.vault.search_notes("needle")
        self.assertEqual(["notes/hello.md"], [r["path"] for r in res["results"]])
        for hidden_query in ("hidden folder note", "not markdown", "content outside"):
            with self.subTest(query=hidden_query):
                empty = self.vault.search_notes(hidden_query)
                self.assertEqual([], empty["results"])
                self.assertEqual(0, empty["total_matches"])

    def test_resolve_and_read_refuse_every_escape(self):
        vault_module = load_vault()
        bad_paths = [
            "/etc/passwd.md",
            "~/notes.md",
            "..",
            "notes/../..",
            "notes/sub/../../escape.md",
            ".hidden.md",
            "notes/.h.md",
            ".dotdir/secret.md",
            "notes/.sub/x.md",
            "other.txt",
            "symlink-out.md",
            "notes/into-dot.md",
            "missing.md",
        ]
        for path in bad_paths:
            with self.subTest(path=path):
                with self.assertRaises(vault_module.VaultError):
                    self.vault.resolve(path, kind="note")
                with self.assertRaises(vault_module.VaultError):
                    self.vault.read_note(path)
        for folder in (".dotdir", "..", "linkdir", "missing"):
            with self.subTest(folder=folder):
                with self.assertRaises(vault_module.VaultError):
                    self.vault.list_folder(folder)

    def test_note_over_256kb_reads_as_partial_page(self):
        (self.root / "big.md").write_text(big_note_text())
        self.assertGreater((self.root / "big.md").stat().st_size, 256 * 1024)
        res = self.vault.read_note("big.md")
        self.assertIn("next_start_line", res)
        self.assertLess(res["end_line"], res["total_lines"])
        self.assertLessEqual(len(res["content"].encode()), 256 * 1024)
        second = self.vault.read_note("big.md", start_line=res["next_start_line"])
        self.assertEqual(res["next_start_line"], second["start_line"])
        self.assertGreater(second["end_line"], second["start_line"])

    def test_list_folder_past_cap_reports_truncated(self):
        vault_module = load_vault()
        many = self.root / "many"
        many.mkdir()
        for i in range(12):
            (many / f"note-{i:02d}.md").write_text(f"note {i}\n")
        with mock.patch.object(vault_module, "MAX_LIST_ENTRIES", 10):
            res = self.vault.list_folder("many")
        self.assertTrue(res["truncated"])
        self.assertLessEqual(len(res["folders"]) + len(res["notes"]), 10)


if __name__ == "__main__":
    unittest.main()
