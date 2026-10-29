"""Hard-linked files are refused by every tool (Ken, 2026-10-29).

A hard link is the same file as a second name that may sit outside the vault,
so it is treated like an outbound symlink: not readable, not listed, not
searched, and not a backlink source. An ordinary note beside it is the control.
"""

import os
import tempfile
import unittest
from pathlib import Path

from armonica.vault import Vault, VaultError


class HardLinksAreRefused(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name).resolve()
        self.root = base / "vault"
        self.root.mkdir()
        outside = base / "outside.md"
        outside.write_text("zebrafish secret [[Target]]\n")
        os.link(outside, self.root / "linked.md")
        (self.root / "Target.md").write_text("target note\n")
        (self.root / "plain.md").write_text("zebrafish plain [[Target]]\n")
        self.vault = Vault(self.root)

    def test_read_note_refuses_a_hard_link(self):
        with self.assertRaises(VaultError):
            self.vault.read_note("linked.md")
        self.assertIn("zebrafish plain", str(self.vault.read_note("plain.md")))

    def test_list_folder_hides_a_hard_link(self):
        listed = [n["path"] for n in self.vault.list_folder("")["notes"]]
        self.assertNotIn("linked.md", listed)
        self.assertIn("plain.md", listed)

    def test_search_never_returns_a_hard_link(self):
        found = str(self.vault.search_notes("zebrafish"))
        self.assertNotIn("linked.md", found)
        self.assertNotIn("secret", found)
        self.assertIn("plain.md", found)

    def test_a_hard_link_is_not_a_backlink(self):
        back = self.vault.get_links("Target.md")["backlinks"]
        self.assertNotIn("linked.md", back)
        self.assertIn("plain.md", back)


if __name__ == "__main__":
    unittest.main()
