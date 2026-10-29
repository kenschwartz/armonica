"""P9 gating tests: Store.put must not silently drop rows written by
another instance between this instance's load and its save.

Two Store instances on one state file: A loads, B writes, A writes. A must
re-read the file under a lock before saving, so B's row survives.

Deterministic without threads: after B's write the file's mtime is reset to
the value A last saw, which is exactly the window a fast second write hits
when filesystem timestamps collide. A store that trusts the mtime cache to
notice external writes drops B's row here; the fixed store re-reads
unconditionally under the lock and keeps both rows.
"""

from __future__ import annotations

import os
import tempfile
import time
import unittest
from pathlib import Path


def load_auth():
    try:
        from armonica import auth
    except ImportError as exc:
        raise AssertionError(
            f"P9 gates packaged behavior: armonica.auth does not exist yet ({exc})"
        ) from exc
    return auth


class GateStoreConcurrency(unittest.TestCase):
    def test_put_after_external_write_keeps_both_rows(self):
        auth = load_auth()
        base = tempfile.TemporaryDirectory()
        self.addCleanup(base.cleanup)
        path = Path(base.name) / "state.json"

        a = auth.Store(path)
        b = auth.Store(path)
        expiry = time.time() + 3600

        a.put("access", "key-a", {"client_id": "c", "expires_at": expiry})
        mtime_a_saw = path.stat().st_mtime_ns
        b.put("access", "key-b", {"client_id": "c", "expires_at": expiry})
        # force the timestamp collision window A already cached
        os.utime(path, ns=(mtime_a_saw, mtime_a_saw))
        a.put("access", "key-c", {"client_id": "c", "expires_at": expiry})

        fresh = auth.Store(path)
        for key in ("key-a", "key-b", "key-c"):
            self.assertIn(key, fresh.data["access"], f"row {key} was lost on A's save")


if __name__ == "__main__":
    unittest.main()
