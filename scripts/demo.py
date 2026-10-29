#!/usr/bin/env python3
"""Boot a throwaway Armonica server against fixtures/demo-vault/."""

from __future__ import annotations

import json
import os
import secrets
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEMO_VAULT = REPO_ROOT / "fixtures" / "demo-vault"


def main() -> int:
    # Credentials must reach a redirected log, and SIGTERM must stop the server too.
    sys.stdout.reconfigure(line_buffering=True)
    signal.signal(signal.SIGTERM, signal.default_int_handler)
    if not DEMO_VAULT.is_dir():
        print(f"demo vault not found: {DEMO_VAULT}", file=sys.stderr)
        return 1

    base = tempfile.mkdtemp(prefix="vc-demo-")
    state = Path(base) / "state"
    state.mkdir()

    sys.path.insert(0, str(REPO_ROOT))
    from armonica.auth import hash_passphrase, preregister_client

    phrase = secrets.token_urlsafe(24)
    (state / "passphrase.json").write_text(json.dumps(hash_passphrase(phrase)))
    client_id, client_secret = preregister_client(state)

    env = {
        **os.environ,
        "VAULT_ROOT": str(DEMO_VAULT),
        "PUBLIC_URL": "https://demo.example",
        "PORT": "8798",
        "STATE_DIR": str(state),
        "ALLOW_LOCAL": "1",
        "IP_ALLOWLIST": "0",
    }

    print("=== Armonica demo ===")
    print(f"Vault:   {DEMO_VAULT}")
    print(f"State:   {state}")
    print(f"URL:     http://127.0.0.1:8798/mcp")
    print(f"Health:  http://127.0.0.1:8798/healthz")
    print()
    print("Passphrase:")
    print(phrase)
    print()
    print("Client ID:")
    print(client_id)
    print()
    print("Client Secret:")
    print(client_secret)
    print()
    print("Paste the client ID and secret into claude.ai connector settings.")
    print("Press Ctrl-C to stop.")
    print()

    proc = subprocess.Popen(
        [sys.executable, "-m", "armonica", "serve"],
        cwd=str(REPO_ROOT),
        env=env,
    )
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
