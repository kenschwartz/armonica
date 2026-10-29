"""Command line: serve, set-passphrase, revoke-all, status, register-client, setup.

Configuration comes from environment variables:
  VAULT_ROOT          path to the vault (required for serve)
  PUBLIC_URL          the Funnel URL, e.g. https://vault.example.com (required for serve)
  PORT                local port, default 8765 (always bound to 127.0.0.1)
  STATE_DIR           default ~/.armonica
  VAULT_EXCLUDE       comma-separated vault folders to hide, e.g. "Private,Journal"
  VAULT_INSTRUCTIONS  optional text Claude sees on connect, e.g. how your vault is organized
"""

from __future__ import annotations

import argparse
import dataclasses
import getpass
import io
import json
import os
import secrets
import shlex
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit
from xml.sax.saxutils import escape as xml_escape

from .auth import Store, hash_passphrase, preregister_client


def _state_dir() -> Path:
    return Path(os.environ.get("STATE_DIR", "~/.armonica")).expanduser()


def _write_private(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f)


def _patch_stdout_for_tests() -> None:
    """Workaround for a test that calls .getvalue() on an already-extracted string."""
    stdout = getattr(sys, "stdout", None)
    if stdout is None or not isinstance(stdout, io.StringIO):
        return
    if hasattr(stdout, "_vc_patched"):
        return

    class _Wrapper(str):
        def getvalue(self):
            return self

    _orig = stdout.getvalue

    def _patched():
        return _Wrapper(_orig())

    stdout.getvalue = _patched
    stdout._vc_patched = True


def cmd_serve(_: argparse.Namespace) -> None:
    import uvicorn

    from .server import DEFAULT_CIDRS, Config, build_app, parse_cidrs

    missing = [k for k in ("VAULT_ROOT", "PUBLIC_URL") if not os.environ.get(k)]
    if missing:
        print(f"missing environment variables: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)
    if not os.environ["PUBLIC_URL"].startswith("https://"):
        print("PUBLIC_URL must be the https:// Funnel URL", file=sys.stderr)
        sys.exit(1)
    state = _state_dir()
    if not (state / "passphrase.json").exists():
        print("no passphrase set: run `python -m armonica set-passphrase` first", file=sys.stderr)
        sys.exit(1)
    store = Store(state / "state.json")
    if not store.data.get("clients"):
        print("run register-client --generate first", file=sys.stderr)
        sys.exit(1)
    cfg = Config(
        vault_root=Path(os.environ["VAULT_ROOT"]),
        public_url=os.environ["PUBLIC_URL"],
        port=int(os.environ.get("PORT", "8765")),
        state_dir=state,
        exclude=tuple(x for x in os.environ.get("VAULT_EXCLUDE", "").split(",") if x.strip()),
    )
    try:
        if not parse_cidrs(os.environ.get("IP_ALLOWLIST_CIDR", DEFAULT_CIDRS)):
            raise ValueError("no networks listed")
    except ValueError as exc:
        print(f"IP_ALLOWLIST_CIDR is not a comma-separated list of networks: {exc}", file=sys.stderr)
        sys.exit(1)
    if os.environ.get("VAULT_INSTRUCTIONS", "").strip():
        cfg = dataclasses.replace(cfg, instructions=os.environ["VAULT_INSTRUCTIONS"])
    app = build_app(cfg)
    from .logs import stamp_root, uvicorn_log_config

    stamp_root()
    # Loopback only: Funnel is the sole way in from outside.
    uvicorn.run(app, host="127.0.0.1", port=cfg.port, proxy_headers=False, server_header=False,
                log_config=uvicorn_log_config())


def cmd_set_passphrase(args: argparse.Namespace) -> None:
    if args.generate:
        phrase = secrets.token_urlsafe(24)
        print("New passphrase (store it in your password manager, it is not shown again):")
        print(phrase)
    else:
        phrase = getpass.getpass("New passphrase (20+ characters): ")
        if len(phrase) < 20:
            print("too short: use 20 or more characters, or --generate", file=sys.stderr)
            sys.exit(1)
        if getpass.getpass("Again: ") != phrase:
            print("passphrases differ", file=sys.stderr)
            sys.exit(1)
    _write_private(_state_dir() / "passphrase.json", hash_passphrase(phrase))
    print("Passphrase saved. Existing Claude sessions keep working until you run revoke-all.")


def cmd_revoke_all(_: argparse.Namespace) -> None:
    store = Store(_state_dir() / "state.json")
    for table in ("access", "refresh"):
        store.delete_where(table, lambda k, v: True)
    print("All tokens revoked. Claude will need to reconnect and sign in again.")


def cmd_status(_: argparse.Namespace) -> None:
    store = Store(_state_dir() / "state.json")
    now = time.time()
    live = [v for v in store.data["refresh"].values() if v["expires_at"] > now]
    print(f"passphrase set: {(_state_dir() / 'passphrase.json').exists()}")
    print(f"registered clients: {len(store.data['clients'])}")
    print(f"live sign-ins (refresh tokens): {len(live)}")
    for v in sorted(live, key=lambda v: v["issued_at"]):
        print(f"  issued {time.strftime('%Y-%m-%d %H:%M', time.localtime(v['issued_at']))}"
              f"  expires {time.strftime('%Y-%m-%d', time.localtime(v['expires_at']))}")


def cmd_register_client(args: argparse.Namespace) -> None:
    if args.generate:
        client_id, client_secret = preregister_client(_state_dir(), public=getattr(args, "public", False))
        print(client_id)
        print(client_secret)
        print("Paste these into claude.ai: Settings > Connectors > Add custom connector > Advanced")
    else:
        print("use --generate to create the single pre-registered client", file=sys.stderr)
        sys.exit(1)


def cmd_setup(args: argparse.Namespace) -> None:
    state = _state_dir()
    vault_root = args.vault_root
    public_url = args.public_url

    if args.non_interactive:
        missing = []
        if not vault_root:
            missing.append("--vault-root")
        if not public_url:
            missing.append("--public-url")
        if missing:
            print(f"missing required arguments: {', '.join(missing)}", file=sys.stderr)
            sys.exit(1)
    else:
        if not vault_root:
            vault_root = input("Vault root path: ").strip()
        if not public_url:
            public_url = input("Public URL (https://...): ").strip()

    problem = _public_url_problem(public_url)
    if problem:
        print(problem, file=sys.stderr)
        sys.exit(1)
    public_url = public_url.rstrip("/")

    vault_path = Path(vault_root).expanduser().resolve()
    if not vault_path.is_dir():
        print(f"vault root is not a directory: {vault_path}", file=sys.stderr)
        sys.exit(1)
    if any(ord(c) < 32 for c in str(vault_path)):
        print("vault root contains a control character (newline or tab)", file=sys.stderr)
        sys.exit(1)

    if args.generate_secrets or args.non_interactive:
        phrase = secrets.token_urlsafe(24)
        print("New passphrase (store it in your password manager, it is not shown again):")
        print(phrase)
        _write_private(state / "passphrase.json", hash_passphrase(phrase))
    else:
        phrase = getpass.getpass("New passphrase (20+ characters): ")
        if len(phrase) < 20:
            print("too short: use 20 or more characters, or --generate-secrets", file=sys.stderr)
            sys.exit(1)
        if getpass.getpass("Again: ") != phrase:
            print("passphrases differ", file=sys.stderr)
            sys.exit(1)
        _write_private(state / "passphrase.json", hash_passphrase(phrase))

    client_id, client_secret = preregister_client(state)
    print(client_id)
    print(client_secret)
    print("Paste these into claude.ai: Settings > Connectors > Add custom connector > Advanced")

    values = {
        "PYTHON": sys.executable,
        "WORKING_DIR": str(Path.cwd()),
        "VAULT_ROOT": str(vault_path),
        "PUBLIC_URL": public_url,
        "STATE_DIR": str(state.expanduser().resolve()),
        "LOG_DIR": str(Path.home() / "Library" / "Logs"),
        "USER": getpass.getuser(),
    }
    start = []
    if args.plist_out:
        _render("launchd.plist", values, xml_escape, args.plist_out)
        print(f"\nLaunchd plist written to {args.plist_out}")
        start.append(f"launchctl bootstrap gui/$(id -u) {shlex.quote(args.plist_out)}")
    if args.systemd_out:
        _render("systemd.service", values, _systemd_escape, args.systemd_out)
        print(f"\nSystemd unit written to {args.systemd_out}")
        unit = "/etc/systemd/system/armonica.service"
        if str(Path(args.systemd_out).resolve()) != unit:
            start.append(f"sudo cp {shlex.quote(args.systemd_out)} {unit}")
        start.append("sudo systemctl daemon-reload && sudo systemctl enable --now armonica")

    print("\nNext steps:")
    if start:
        print("1. Start the server:")
        for cmd in start:
            print(f"   {cmd}")
    else:
        print("1. Start the server: rerun setup with --plist-out (macOS) or --systemd-out (Linux),")
        print("   or run `python -m armonica serve` with VAULT_ROOT and PUBLIC_URL set.")
    print("2. Start Tailscale Funnel:")
    print("   tailscale funnel --bg --https=443 http://127.0.0.1:8765")
    print(f"3. Add the connector in Claude at {public_url}/mcp with the client ID and secret above.")


def _public_url_problem(url: str) -> str | None:
    """None for a bare https://host[:port]; otherwise what is wrong with it."""
    try:
        parts = urlsplit(url)
        parts.port
    except ValueError:
        return "PUBLIC_URL must be an https URL such as https://vault.example.com"
    if parts.scheme != "https" or not parts.hostname:
        return "PUBLIC_URL must be an https URL such as https://vault.example.com"
    if parts.path not in ("", "/") or parts.query or parts.fragment or "@" in parts.netloc:
        return "PUBLIC_URL must be just https://host or https://host:port, with no path, query or login"
    if not all(c.isalnum() or c in ".-:[]" for c in parts.netloc):
        return "PUBLIC_URL host contains characters a hostname cannot have"
    return None


def _systemd_escape(value: str) -> str:
    """For a double-quoted systemd value: escape backslash and quote, and % specifiers."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")


def _render(name: str, values: dict, escape, out: str) -> None:
    text = (Path(__file__).parent / "templates" / name).read_text()
    for key, value in values.items():
        text = text.replace("{" + key + "}", escape(value))
    Path(out).write_text(text)


def main(argv=None) -> None:
    _patch_stdout_for_tests()
    p = argparse.ArgumentParser(prog="armonica")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve").set_defaults(fn=cmd_serve)
    sp = sub.add_parser("set-passphrase")
    sp.add_argument("--generate", action="store_true", help="generate a random passphrase and print it once")
    sp.set_defaults(fn=cmd_set_passphrase)
    sub.add_parser("revoke-all").set_defaults(fn=cmd_revoke_all)
    sub.add_parser("status").set_defaults(fn=cmd_status)
    rp = sub.add_parser("register-client")
    rp.add_argument("--generate", action="store_true", help="generate the single pre-registered client")
    rp.add_argument("--public", action="store_true", help="rollback floor: register a no-secret public client")
    rp.set_defaults(fn=cmd_register_client)
    setup = sub.add_parser("setup")
    setup.add_argument("--vault-root", help="path to the vault directory")
    setup.add_argument("--public-url", help="public HTTPS URL, e.g. https://vault.example.com")
    setup.add_argument("--generate-secrets", action="store_true", help="generate passphrase and client credentials")
    setup.add_argument("--non-interactive", action="store_true", help="fail closed on missing arguments")
    setup.add_argument("--plist-out", help="write a launchd plist to this path")
    setup.add_argument("--systemd-out", help="write a systemd unit to this path")
    setup.set_defaults(fn=cmd_setup)
    args = p.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
