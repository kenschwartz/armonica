"""Read-only access to an Obsidian vault, confined to the vault root.

Nothing here writes to disk. Every path a caller supplies goes through
Vault.resolve(), which rejects absolute paths, "..", dotfiles/dot-folders
(.obsidian, .trash, .git), excluded folders, symlinks that leave the vault,
hard-linked files, and anything that is not a Markdown note or a folder.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shlex
import subprocess
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

NOTE_SUFFIXES = {".md"}
MAX_READ_BYTES = 256 * 1024  # most text returned by one read_note call
MAX_NOTE_BYTES = 5 * 1024 * 1024  # notes larger than this are never opened
MAX_SEARCH_RESULTS = 50
SEARCH_TIME_BUDGET_S = 8.0  # Claude gives up on slow tools; stay well under
MAX_LIST_ENTRIES = 500
MAX_BACKLINKS = 200
OHS_TIMEOUT_S = 10  # seconds to wait for the optional hybrid search binary

_log = logging.getLogger("armonica.vault")

WIKILINK_RE = re.compile(r"!?\[\[([^\]\|#\^]+)(?:[#\^][^\]\|]*)?(?:\|[^\]]*)?\]\]")
MDLINK_RE = re.compile(r"\]\(([^)\s]+?\.md)(?:#[^)]*)?\)")


class VaultError(Exception):
    """A request the vault refuses. The message is safe to show to the caller."""


@dataclass(frozen=True)
class Note:
    path: Path  # absolute, resolved
    rel: PurePosixPath  # relative to the vault root


class Vault:
    def __init__(self, root: str | Path, exclude: list[str] | None = None):
        self.root = Path(root).expanduser().resolve(strict=True)
        if not self.root.is_dir():
            raise ValueError(f"vault root is not a directory: {self.root}")
        # Folder prefixes relative to the root, compared case-insensitively
        # because APFS is case-insensitive by default. NFC normalizes unicode
        # so NFD and NFC spellings of the same folder name both match.
        self.exclude = [
            unicodedata.normalize("NFC", e.strip().strip("/")).casefold()
            for e in (exclude or [])
            if e.strip().strip("/")
        ]

    # ---- path safety -------------------------------------------------

    def _blocked(self, rel: PurePosixPath) -> bool:
        if any(part.startswith(".") for part in rel.parts):
            return True
        s = unicodedata.normalize("NFC", rel.as_posix()).casefold()
        return any(s == e or s.startswith(e + "/") for e in self.exclude)

    def resolve(self, rel_path: str, *, kind: str) -> Note:
        """Map a caller-supplied vault path to a real file or folder inside the vault.

        kind is "note" or "folder". Raises VaultError for anything else.
        """
        raw = (rel_path or "").strip()
        if "\x00" in raw or "\\" in raw:
            raise VaultError("invalid path")
        if raw.startswith(("/", "~")):
            raise VaultError("paths are relative to the vault root")
        raw = raw.strip("/")
        rel = PurePosixPath(raw) if raw else PurePosixPath()
        if any(part == ".." for part in rel.parts):
            raise VaultError("'..' is not allowed")
        if self._blocked(rel):
            raise VaultError("not found")
        try:
            real = (self.root / rel).resolve(strict=True)
        except (FileNotFoundError, NotADirectoryError):
            raise VaultError("not found") from None
        except (OSError, RuntimeError):
            raise VaultError("not found") from None
        if not real.is_relative_to(self.root):
            raise VaultError("not found")  # symlink pointing outside the vault
        real_rel = PurePosixPath(real.relative_to(self.root).as_posix())
        if self._blocked(real_rel):
            raise VaultError("not found")  # symlink into .obsidian or an excluded folder
        if kind == "folder":
            if not real.is_dir():
                raise VaultError("not a folder")
        elif kind == "note":
            if not real.is_file() or real.suffix.lower() not in NOTE_SUFFIXES:
                raise VaultError("not a Markdown note")
            if _hard_linked(real):
                raise VaultError("not found")  # same file as a name we cannot see, maybe outside the vault
        else:  # pragma: no cover
            raise ValueError(kind)
        return Note(real, real_rel)

    def iter_notes(self, start: Path | None = None):
        """Yield every visible note under start. Symlinks and hard links are skipped."""
        start = start or self.root
        for dirpath, dirnames, filenames in os.walk(start, followlinks=False):
            dp = Path(dirpath)
            rel_dir = PurePosixPath(dp.relative_to(self.root).as_posix())
            dirnames[:] = sorted(
                d for d in dirnames if not self._blocked(rel_dir / d) and not (dp / d).is_symlink()
            )
            for name in sorted(filenames):
                rel = rel_dir / name
                p = dp / name
                if self._blocked(rel) or p.suffix.lower() not in NOTE_SUFFIXES or p.is_symlink() or _hard_linked(p):
                    continue
                yield Note(p, rel)

    # ---- tools -------------------------------------------------------

    def list_folder(self, path: str = "") -> dict:
        folder = self.resolve(path, kind="folder")
        folders, notes = [], []
        with os.scandir(folder.path) as it:
            for entry in sorted(it, key=lambda e: e.name.casefold()):
                rel = folder.rel / entry.name
                if self._blocked(rel) or entry.is_symlink():
                    continue
                if entry.is_dir():
                    folders.append(rel.as_posix())
                elif entry.is_file() and Path(entry.name).suffix.lower() in NOTE_SUFFIXES:
                    st = entry.stat()
                    if st.st_nlink > 1:
                        continue
                    notes.append({"path": rel.as_posix(), "bytes": st.st_size, "modified": _iso(st.st_mtime)})
        total = len(folders) + len(notes)
        return {
            "folder": folder.rel.as_posix() if folder.rel.parts else "",
            "folders": folders[:MAX_LIST_ENTRIES],
            "notes": notes[: max(0, MAX_LIST_ENTRIES - len(folders))],
            "truncated": total > MAX_LIST_ENTRIES,
        }

    def read_note(self, path: str, start_line: int = 1, max_lines: int | None = None) -> dict:
        note = self.resolve(path, kind="note")
        size = note.path.stat().st_size
        if size > MAX_NOTE_BYTES:
            raise VaultError(f"note is {size} bytes, over the {MAX_NOTE_BYTES} byte limit")
        text = note.path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        start_line = max(1, int(start_line))
        out, used = [], 0
        end = len(lines) if max_lines is None else min(len(lines), start_line - 1 + max(1, int(max_lines)))
        for i in range(start_line - 1, end):
            cost = len(lines[i].encode("utf-8")) + 1
            if used + cost > MAX_READ_BYTES and out:
                break
            out.append(lines[i])
            used += cost
        last = start_line - 1 + len(out)
        result = {
            "path": note.rel.as_posix(),
            "modified": _iso(note.path.stat().st_mtime),
            "total_lines": len(lines),
            "start_line": start_line,
            "end_line": last,
            "content": "\n".join(out),
        }
        if start_line == 1:
            fm = _frontmatter(lines)
            if fm is not None:
                result["frontmatter"] = fm
        if last < len(lines):
            result["next_start_line"] = last + 1
        return result

    def search_notes(self, query: str, folder: str = "", limit: int = 20) -> dict:
        terms = _terms(query)
        if not terms:
            raise VaultError("empty query")
        limit = max(1, min(int(limit), MAX_SEARCH_RESULTS))
        base = self.resolve(folder, kind="folder")
        deadline = time.monotonic() + SEARCH_TIME_BUDGET_S

        # Optional hybrid search backend (the only subprocess in this package).
        # Contract verified against the real binary (ohs 0.15.1): --json prints
        # a JSON LIST of objects whose "path" is vault-relative. "--" guards a
        # query that begins with "-" from being read as an option.
        ohs_paths: list[str] = []
        backend = "fallback"
        ohs_bin = os.environ.get("OHS_BIN")
        if ohs_bin:
            ohs_db = os.environ.get("OHS_DB", str(self.root / ".obsidian-hybrid-search.db"))
            try:
                proc = subprocess.run(
                    [ohs_bin, "search", "--mode", "hybrid", "--limit", str(limit),
                     "--db", ohs_db, "--json", "--", query],
                    capture_output=True,
                    timeout=OHS_TIMEOUT_S,
                    text=True,
                    env={**os.environ, "OBSIDIAN_VAULT_PATH": str(self.root)},
                )
                if proc.returncode != 0:
                    _log.warning("ohs fallback: rc=%s stderr=%.200s", proc.returncode, proc.stderr or "")
                else:
                    data = json.loads(proc.stdout[:64 * 1024])
                    items = data if isinstance(data, list) else []
                    for item in items:
                        if not isinstance(item, dict):
                            continue
                        p = str(item.get("path", ""))
                        try:
                            abs_path = Path(p)
                            if abs_path.is_absolute():
                                # resolve first: on macOS a tempdir path may carry
                                # an unresolved /var symlink the resolved root lacks
                                abs_path = abs_path.resolve()
                                if not abs_path.is_relative_to(self.root):
                                    continue
                                rel = abs_path.relative_to(self.root).as_posix()
                                note = self.resolve(rel, kind="note")
                            else:
                                note = self.resolve(p, kind="note")
                            ohs_paths.append(note.rel.as_posix())
                        except (VaultError, ValueError):
                            pass
                    backend = "ohs" if ohs_paths else "ohs-empty"
            except subprocess.TimeoutExpired:
                _log.warning("ohs fallback: timeout after %ss", OHS_TIMEOUT_S)
            except Exception as exc:
                _log.warning("ohs fallback: %s", type(exc).__name__)

        hits, scanned, timed_out = [], 0, False
        seen = set(ohs_paths)
        for note in self.iter_notes(base.path):
            if time.monotonic() > deadline:
                timed_out = True
                break
            if note.rel.as_posix() in seen:
                scanned += 1
                continue
            if time.monotonic() > deadline:
                timed_out = True
                break
            try:
                if note.path.stat().st_size > MAX_NOTE_BYTES:
                    continue
                if time.monotonic() > deadline:
                    timed_out = True
                    break
                text = note.path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            scanned += 1
            path_cf = note.rel.as_posix().casefold()
            text_cf = text.casefold()
            if not all(t in text_cf or t in path_cf for t in terms):
                continue
            matches = []
            for n, line in enumerate(text.splitlines(), 1):
                lcf = line.casefold()
                if any(t in lcf for t in terms):
                    matches.append({"line": n, "text": _snippet(line, terms)})
                    if len(matches) >= 3:
                        break
            score = sum(text_cf.count(t) for t in terms) + 10 * sum(t in path_cf for t in terms)
            hits.append((score, note.path.stat().st_mtime, note.rel.as_posix(), matches))
        hits.sort(key=lambda h: (-h[0], -h[1]))

        # Merge: ohs hits first, then substring-only hits after, deduped, capped at limit.
        # Every ohs hit must still satisfy the all-terms contract (the same
        # predicate the substring pass applies): ohs ranks and recalls, it
        # never widens the term semantics. Without this filter a multi-term
        # query returned notes matching only one term.
        merged: list[tuple[float, float, str, list[dict]]] = []
        ohs_landed = False
        for p in ohs_paths:
            if len(merged) >= limit:
                break
            try:
                note = self.resolve(p, kind="note")
            except VaultError:
                continue
            text = note.path.read_text(encoding="utf-8", errors="replace")
            rel_cf = note.rel.as_posix().casefold()
            if not all(t in text.casefold() or t in rel_cf for t in terms):
                continue
            matches = []
            for n, line in enumerate(text.splitlines(), 1):
                lcf = line.casefold()
                if any(t in lcf for t in terms):
                    matches.append({"line": n, "text": _snippet(line, terms)})
                    if len(matches) >= 3:
                        break
            merged.append((1_000_000, note.path.stat().st_mtime, note.rel.as_posix(), matches))
            ohs_landed = True
        if backend == "ohs" and not ohs_landed:
            backend = "ohs-empty"
        merged.extend(hits)
        merged = merged[:limit]

        return {
            "query": query,
            "results": [{"path": p, "modified": _iso(m), "matches": ms} for _, m, p, ms in merged],
            "total_matches": len(merged),
            "notes_scanned": scanned,
            "timed_out": timed_out,
            "backend": backend,
        }

    def get_links(self, path: str, include_backlinks: bool = True) -> dict:
        note = self.resolve(path, kind="note")
        index = self._name_index()
        text = note.path.read_text(encoding="utf-8", errors="replace")
        outgoing, seen = [], set()
        for target in _link_targets(text):
            if target in seen:
                continue
            seen.add(target)
            outgoing.append({"target": target, "resolved": self._resolve_link(target, note.rel, index)})
        result = {"path": note.rel.as_posix(), "outgoing": outgoing}
        if include_backlinks:
            me = note.rel.as_posix()
            back = []
            deadline = time.monotonic() + SEARCH_TIME_BUDGET_S
            for other in self.iter_notes():
                if other.rel == note.rel:
                    continue
                if time.monotonic() > deadline:
                    result["timed_out"] = True
                    break
                try:
                    if other.path.stat().st_size > MAX_NOTE_BYTES:
                        continue
                    otext = other.path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if any(me in self._resolve_link(t, other.rel, index) for t in _link_targets(otext)):
                    back.append(other.rel.as_posix())
                    if len(back) >= MAX_BACKLINKS:
                        break
            result["backlinks"] = back
        return result

    # ---- link resolution (Obsidian-style, best effort) ----------------

    def _name_index(self) -> dict[str, list[str]]:
        index: dict[str, list[str]] = {}
        for n in self.iter_notes():
            index.setdefault(n.rel.stem.casefold(), []).append(n.rel.as_posix())
        return index

    def _resolve_link(self, target: str, source: PurePosixPath, index: dict[str, list[str]]) -> list[str]:
        t = target.strip()
        if t.lower().endswith(".md"):
            t = t[:-3]
        if "/" not in t:
            return index.get(t.casefold(), [])
        # Path-style link: try relative to the source note, then to the vault root.
        candidates = []
        for base in (source.parent, PurePosixPath()):
            parts = []
            for part in (base / t).parts:
                if part == "..":
                    if not parts:
                        parts = None
                        break
                    parts.pop()
                elif part != ".":
                    parts.append(part)
            if parts:
                candidates.append(PurePosixPath(*parts).with_suffix(".md").as_posix().casefold())
        found = []
        for paths in index.values():
            for p in paths:
                if p.casefold() in candidates:
                    found.append(p)
        return found


def _hard_linked(path: Path) -> bool:
    """A hard link is the same file under a second name, which may sit outside
    the vault and cannot be found from here; refuse it like an outbound symlink."""
    try:
        return path.stat().st_nlink > 1
    except OSError:
        return True


def _snippet(line: str, terms: list[str]) -> str:
    """Cite the term, not the line start: window a long line around its first term hit.

    A 200-char left-truncation can cut the matching terms out of the snippet
    entirely, handing the caller a citation with no visible evidence.
    """
    s = line.strip()
    if len(s) <= 200:
        return s
    lcf = s.casefold()
    idx = min((i for i in (lcf.find(t) for t in terms) if i >= 0), default=-1)
    if idx < 0:
        return s[:200]
    start = max(0, idx - 60)
    end = min(len(s), idx + 140)
    return ("..." if start > 0 else "") + s[start:end] + ("..." if end < len(s) else "")


def _terms(query: str) -> list[str]:
    try:
        parts = shlex.split(query or "")
    except ValueError:
        parts = (query or "").split()
    return [p.casefold() for p in parts if p.strip()]


def _link_targets(text: str) -> list[str]:
    targets = [m.group(1).strip() for m in WIKILINK_RE.finditer(text)]
    targets += [m.group(1).strip() for m in MDLINK_RE.finditer(text) if "://" not in m.group(1)]
    return [t for t in targets if t]


def _frontmatter(lines: list[str]) -> dict | None:
    """Return the raw YAML frontmatter and a shallow parse of top-level keys.

    Shallow on purpose: no YAML dependency. Lists in "- item" form and
    inline [a, b] form are handled; anything nested stays in "raw".
    """
    if not lines or lines[0].strip() != "---":
        return None
    try:
        end = next(i for i in range(1, len(lines)) if lines[i].strip() in ("---", "..."))
    except StopIteration:
        return None
    body = lines[1:end]
    fields: dict[str, object] = {}
    key = None
    for line in body:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.startswith((" ", "\t")) or line.startswith("- "):
            item = line.strip()
            if key and item.startswith("- "):
                cur = fields.get(key)
                if not isinstance(cur, list):
                    cur = [] if cur in ("", None) else [cur]
                cur.append(_scalar(item[2:]))
                fields[key] = cur
            continue
        if ":" in line:
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()
            if value.startswith("[") and value.endswith("]"):
                fields[key] = [_scalar(v) for v in value[1:-1].split(",") if v.strip()]
            else:
                fields[key] = _scalar(value)
    return {"raw": "\n".join(body), "fields": fields, "end_line": end + 1}


def _scalar(v: str) -> str:
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
        return v[1:-1]
    return v


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ts))
