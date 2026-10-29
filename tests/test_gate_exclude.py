"""P3 gating tests: exclude entries match under Unicode normalization.

macOS filenames arrive in either NFC or NFD form depending on which tool
wrote them, so an exclude entry stored one way must hide a folder stored the
other way, case-insensitively, from all four tools: list_folder, read_note,
search_notes and get_links. The fix normalizes both sides (unicodedata NFC)
before the casefold comparison.

Every case also has a positive control in a fresh vault: without the exclude
entry the folder is visible, readable and linkable, so the hiding comes from
the exclude match and not from a broken fixture. Each case gets its own
tempdir because APFS treats the NFC and NFD spellings of one name as the
same directory.
"""

from __future__ import annotations

import os
import tempfile
import unicodedata
import unittest
from pathlib import Path


def load_vault():
    try:
        from armonica import vault as vault_module
    except ImportError as exc:
        raise AssertionError(
            f"P3 gates packaged behavior: armonica.vault does not exist yet ({exc})"
        ) from exc
    return vault_module


def nfc(s: str) -> str:
    return unicodedata.normalize("NFC", s)


def nfd(s: str) -> str:
    return unicodedata.normalize("NFD", s)


CASES = [
    ("nfd_on_disk_nfc_exclude", nfd("Café"), nfc("Café")),
    ("nfc_on_disk_nfd_exclude", nfc("Café"), nfd("Café")),
    ("case_insensitive_match", nfd("Café"), "CAFÉ"),
    ("second_family_diacritics", nfd("Naïve"), nfc("Naïve")),
]


class GateExcludeNormalization(unittest.TestCase):
    def _make_vault(self, folder: str, marker: str) -> Path:
        base = tempfile.TemporaryDirectory()
        self.addCleanup(base.cleanup)
        root = Path(base.name) / "vault"
        (root / "normal").mkdir(parents=True)
        (root / "normal" / "hello.md").write_text("hello target note\n")
        (root / "normal" / "linker.md").write_text("[[Secret]] points at the hidden note\n")
        hidden = root / folder
        hidden.mkdir()
        (hidden / "Secret.md").write_text(f"{marker}\n[[Hello]]\n")
        # the on disk name must be exactly the form this case asked for
        self.assertIn(folder, os.listdir(root))
        return root

    def _assert_hidden_from_all_four_tools(self, root: Path, folder: str, exclude: str, marker: str):
        vault_module = load_vault()
        vault = vault_module.Vault(root, exclude=[exclude])

        listing = vault.list_folder("")
        self.assertNotIn(folder, listing["folders"])
        with self.assertRaises(vault_module.VaultError):
            vault.read_note(f"{folder}/Secret.md")
        search = vault.search_notes(marker)
        self.assertEqual([], search["results"])
        self.assertEqual(0, search["total_matches"])
        # a note inside the excluded folder links to hello: it must not
        # surface as a backlink
        self.assertEqual([], vault.get_links("normal/hello.md")["backlinks"])
        # a link aimed at the excluded note must resolve to nothing
        outgoing = vault.get_links("normal/linker.md")["outgoing"]
        self.assertEqual([], [r["resolved"] for r in outgoing if r["resolved"]])

    def _assert_visible_without_exclude(self, root: Path, folder: str, marker: str):
        vault_module = load_vault()
        vault = vault_module.Vault(root)
        self.assertIn(folder, vault.list_folder("")["folders"])
        self.assertIn(marker, vault.read_note(f"{folder}/Secret.md")["content"])
        self.assertIn(f"{folder}/Secret.md", vault.search_notes(marker)["results"][0]["path"])
        outgoing = vault.get_links("normal/linker.md")["outgoing"]
        self.assertEqual([f"{folder}/Secret.md"], outgoing[0]["resolved"])

    def test_exclude_matches_across_normalization_forms(self):
        for label, folder, exclude in CASES:
            with self.subTest(case=label):
                marker = f"{label}-marker"
                root = self._make_vault(folder, marker)
                self._assert_visible_without_exclude(root, folder, marker)
                self._assert_hidden_from_all_four_tools(root, folder, exclude, marker)


if __name__ == "__main__":
    unittest.main()
