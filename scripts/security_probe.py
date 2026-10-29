#!/usr/bin/env python3
"""Security probe battery for Armonica. Run before any deployment.

Two phases:
1. In-process ASGI matrix against build_app() under a real app lifespan:
   endpoint sweep, OAuth flows, lockout, origin, XFF allowlist, token
   hygiene, confinement vectors.
2. Live server: real uvicorn on a loopback port, key checks over HTTP,
   egress check via lsof, vault write-surface proof via checksums.

Exit code 0 only if every check passes. No em dashes anywhere (repo rule).
Usage: .venv/bin/python scripts/security_probe.py [--skip-live]
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
import unicodedata
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  [{detail}]" if detail else ""))


async def asgi_call(app, method, path, *, form=None, headers=(), query=b"", raw_body=None):
    body = b""
    header_pairs = [(k.lower().encode(), v.encode()) for k, v in headers]
    if form is not None:
        body = urlencode(form).encode()
        header_pairs.append((b"content-type", b"application/x-www-form-urlencoded"))
    if raw_body is not None:
        body = raw_body
    if not any(k == b"host" for k, _ in header_pairs):
        header_pairs.append((b"host", b"vault-probe.example"))
    scope = {
        "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
        "method": method, "path": path, "raw_path": path.encode(),
        "query_string": query, "headers": header_pairs, "scheme": "https",
        "server": ("vault-probe.example", 443), "client": ("127.0.0.1", 41010),
        "root_path": "", "http_version": "1.1",
    }
    state = {"supplied": False}
    sent: list[dict] = []

    async def receive():
        if state["supplied"]:
            return {"type": "http.disconnect"}
        state["supplied"] = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        sent.append(message)

    await app(scope, receive, send)
    start = next((m for m in sent if m["type"] == "http.response.start"), None)
    assert start is not None, "no response produced"
    headers_out = {k.decode(): v.decode() for k, v in start.get("headers", [])}
    body_out = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return start["status"], headers_out, body_out


class LifespanDriver:
    """Run the app's lifespan as a live task: startup once, park, shutdown once."""

    def __init__(self, app):
        self.app = app
        self.in_q: asyncio.Queue | None = None
        self.out_q: asyncio.Queue | None = None
        self.task = None

    async def _receive(self):
        return await self.in_q.get()

    async def _send(self, message):
        await self.out_q.put(message)

    async def start(self):
        self.in_q = asyncio.Queue()
        self.out_q = asyncio.Queue()
        self.task = asyncio.create_task(
            self.app({"type": "lifespan", "asgi": {"version": "3.0", "spec_version": "2.0"}},
                     self._receive, self._send)
        )
        await self.in_q.put({"type": "lifespan.startup"})
        msg = await asyncio.wait_for(self.out_q.get(), timeout=10)
        if msg.get("type") != "lifespan.startup.complete":
            raise RuntimeError(f"lifespan startup failed: {msg}")

    async def stop(self):
        await self.in_q.put({"type": "lifespan.shutdown"})
        msg = await asyncio.wait_for(self.out_q.get(), timeout=10)
        if msg.get("type") != "lifespan.shutdown.complete":
            raise RuntimeError(f"lifespan shutdown failed: {msg}")
        await asyncio.wait_for(self.task, timeout=10)


async def lifespan_boot(app) -> None:
    drv = getattr(app, "_probe_lifespan", None)
    if drv is None:
        drv = LifespanDriver(app)
        app._probe_lifespan = drv
    await drv.start()


async def lifespan_shutdown(app) -> None:
    drv = getattr(app, "_probe_lifespan", None)
    if drv is not None:
        await drv.stop()


def pkce_pair():
    verifier = "probe-verifier-" + "v" * 24
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge


async def oauth_flow(app, client_id, client_secret, passphrase, *, post_secret=False, origin=None):
    """Drive authorize -> login approve -> token exchange. Returns (status, tokens)."""
    verifier, challenge = pkce_pair()
    q = urlencode({
        "response_type": "code", "client_id": client_id,
        "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
        "state": "probe", "scope": "vault.read",
        "code_challenge": challenge, "code_challenge_method": "S256",
    })
    status, headers, _ = await asgi_call(app, "GET", "/authorize", query=q.encode())
    if status != 302:
        return status, None
    txn = parse_qs(urlparse(headers["location"]).query)["txn"][0]
    login_headers = [("Origin", "https://vault-probe.example")] if origin is None else [origin]
    status, headers, _ = await asgi_call(
        app, "POST", "/login",
        form={"txn": txn, "passphrase": passphrase, "action": "approve"},
        headers=login_headers,
    )
    if status != 302:
        return status, None
    code = parse_qs(urlparse(headers["location"]).query)["code"][0]
    form = {
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
        "client_id": client_id, "code_verifier": verifier,
    }
    if post_secret:
        form["client_secret"] = client_secret
        status, _, body = await asgi_call(app, "POST", "/token", form=form)
    else:
        basic = "Basic " + base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
        status, _, body = await asgi_call(app, "POST", "/token", form=form, headers=[("Authorization", basic)])
    tokens = json.loads(body) if status == 200 else None
    return status, tokens


def build_fixtures(root: Path, outside: Path):
    (root / "notes").mkdir(parents=True)
    (root / "notes" / "alpha.md").write_text("alpha needle note\n")
    (root / "notes" / "beta.md").write_text("beta note with no marker\n")
    (root / ".obsidian").mkdir()
    (root / ".obsidian" / "workspace.md").write_text("secret dotfolder note\n")
    nfd = unicodedata.normalize("NFD", "Café")
    (root / nfd).mkdir()
    (root / nfd / "hidden.md").write_text("excluded folder note\n")
    (root / "notes" / "out.md").symlink_to(outside / "canary.md")
    (outside / "canary.md").write_text("CANARY outside the vault, must never surface\n")


def tree_digest(root: Path) -> str:
    sha = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        rel = str(p.relative_to(root))
        sha.update(rel.encode())
        if p.is_file() and not p.is_symlink():
            sha.update(p.read_bytes())
    return sha.hexdigest()


async def phase1(app, root, outside, state_dir, phrase, client_id, client_secret, A, Vault, VaultError, Config, build_app, public_url):
    status, _, body = await asgi_call(app, "GET", "/healthz")
    check("healthz 200", status == 200, str(status))

    status, _, _ = await asgi_call(app, "POST", "/mcp", form={"x": "1"})
    check("unauth /mcp rejected 401", status == 401, str(status))

    for method in ("POST", "GET"):
        status, _, _ = await asgi_call(app, method, "/register", form={"a": "1"})
        check(f"/register absent ({method})", status in (404, 405), str(status))

    status, _, body = await asgi_call(app, "GET", "/.well-known/oauth-authorization-server")
    check("metadata 200 and no registration_endpoint", status == 200 and b"registration_endpoint" not in body, str(status))

    q = urlencode({"response_type": "code", "client_id": "bogus-" + secrets.token_hex(4),
                   "redirect_uri": "https://claude.ai/api/mcp/auth_callback", "state": "x",
                   "scope": "vault.read", "code_challenge": pkce_pair()[1], "code_challenge_method": "S256"})
    status, headers, _ = await asgi_call(app, "GET", "/authorize", query=q.encode())
    check("authorize unknown client refused", status >= 400 or (status == 302 and "error" in headers.get("location", "")), str(status))

    status, _, _ = await asgi_call(app, "GET", "/login", query=b"txn=nonexistent")
    check("login bad txn 400", status == 400, str(status))

    status, tokens = await oauth_flow(app, client_id, client_secret, phrase)
    check("oauth flow basic secret 200", status == 200 and bool(tokens and tokens.get("access_token")), str(status))

    status, tokens_post = await oauth_flow(app, client_id, client_secret, phrase, post_secret=True)
    check("oauth flow posted secret 200", status == 200 and bool(tokens_post and tokens_post.get("access_token")), str(status))

    status, _ = await oauth_flow(app, client_id, "wrong-secret", phrase)
    check("wrong client secret rejected", status in (400, 401), str(status))

    raw_state = (state_dir / "state.json").read_text()
    atok = tokens["access_token"] if tokens else ""
    check("no raw access token in state.json", atok == "" or atok not in raw_state)
    check("no raw refresh token in state.json", tokens.get("refresh_token", "") not in raw_state)
    mode = oct((state_dir / "state.json").stat().st_mode & 0o777)
    check("state.json mode 600", mode == "0o600", mode)

    for i in range(5):
        s, _, _ = await asgi_call(app, "POST", "/login",
                                  form={"txn": "deadbeef", "passphrase": f"wrong-{i}", "action": "approve"})
    check("bad-txn login refused", s == 400, str(s))

    async def fresh_txn(client):
        q = urlencode({"response_type": "code", "client_id": client,
                       "redirect_uri": "https://claude.ai/api/mcp/auth_callback", "state": "p", "scope": "vault.read",
                       "code_challenge": pkce_pair()[1], "code_challenge_method": "S256"})
        _, h, _ = await asgi_call(app, "GET", "/authorize", query=q.encode())
        return parse_qs(urlparse(h["location"]).query)["txn"][0]

    live_txn = await fresh_txn(client_id)
    lock_status = None
    for i in range(5):
        lock_status, _, _ = await asgi_call(app, "POST", "/login",
                                            form={"txn": live_txn, "passphrase": f"wrong-{i}", "action": "approve"})
    check("five wrong passphrases trigger lock", lock_status in (401, 429), str(lock_status))
    second_txn = await fresh_txn(client_id)
    status, _, _ = await asgi_call(app, "POST", "/login",
                                   form={"txn": second_txn, "passphrase": phrase, "action": "approve"})
    check("correct passphrase also locked out", status in (401, 429), str(status))
    fresh = build_app(Config(vault_root=root, public_url=public_url, state_dir=state_dir))
    await lifespan_boot(fresh)
    fq = urlencode({"response_type": "code", "client_id": client_id,
                    "redirect_uri": "https://claude.ai/api/mcp/auth_callback", "state": "f", "scope": "vault.read",
                    "code_challenge": pkce_pair()[1], "code_challenge_method": "S256"})
    _, fh, _ = await asgi_call(fresh, "GET", "/authorize", query=fq.encode())
    fresh_txn_v = parse_qs(urlparse(fh["location"]).query)["txn"][0]
    status, _, _ = await asgi_call(fresh, "POST", "/login",
                                   form={"txn": fresh_txn_v, "passphrase": phrase, "action": "approve"})
    check("lockout survives fresh provider", status in (401, 429), str(status))
    await lifespan_shutdown(fresh)

    lock_base = tempfile.mkdtemp(prefix="vc-probe-lock-")
    lb_state = Path(lock_base)
    (lb_state / "passphrase.json").write_text(json.dumps(A.hash_passphrase(phrase)))
    lb_id, lb_sec = A.preregister_client(lb_state)
    lb_app = build_app(Config(vault_root=root, public_url=public_url, state_dir=lb_state))
    await lifespan_boot(lb_app)
    q = urlencode({"response_type": "code", "client_id": lb_id,
                   "redirect_uri": "https://claude.ai/api/mcp/auth_callback", "state": "s", "scope": "vault.read",
                   "code_challenge": pkce_pair()[1], "code_challenge_method": "S256"})
    _, h, _ = await asgi_call(lb_app, "GET", "/authorize", query=q.encode())
    txn = parse_qs(urlparse(h["location"]).query)["txn"][0]
    async def lb_txn():
        q2 = urlencode({"response_type": "code", "client_id": lb_id,
                        "redirect_uri": "https://claude.ai/api/mcp/auth_callback", "state": "s2", "scope": "vault.read",
                        "code_challenge": pkce_pair()[1], "code_challenge_method": "S256"})
        _, h2, _ = await asgi_call(lb_app, "GET", "/authorize", query=q2.encode())
        return parse_qs(urlparse(h2["location"]).query)["txn"][0]

    status, _, _ = await asgi_call(lb_app, "POST", "/login",
                                   form={"txn": await lb_txn(), "passphrase": phrase, "action": "approve"},
                                   headers=[("Origin", "https://evil.example")])
    check("cross-origin login refused", status == 403, str(status))
    status, _, _ = await asgi_call(lb_app, "POST", "/login",
                                   form={"txn": await lb_txn(), "passphrase": phrase, "action": "approve"},
                                   headers=[("Origin", "null")])
    check("origin null (webview) proceeds", status == 302, str(status))
    status, _, _ = await asgi_call(lb_app, "POST", "/login",
                                   form={"txn": txn, "passphrase": phrase, "action": "approve"})
    check("no-origin login proceeds", status == 302, str(status))
    await lifespan_shutdown(lb_app)

    xff_cases = [
        ("160.79.104.5", 401, "single inside XFF passes guard to auth"),
        ("8.8.8.8", 403, "outside XFF blocked"),
        ("1.1.1.1, 160.79.104.5", 401, "last entry inside passes"),
        ("160.79.104.5, 8.8.8.8", 403, "last entry outside blocked"),
        ("160.79.104.5:9443", 403, "port-suffixed XFF blocked"),
        ("::ffff:160.79.104.5", None, "ipv6-mapped form never crashes, 401 or 403"),
    ]
    for xff, expected, label in xff_cases:
        status, _, _ = await asgi_call(app, "POST", "/mcp", form={"x": "1"}, headers=[("X-Forwarded-For", xff)])
        if expected is None:
            check(f"xff {label}", status in (401, 403), str(status))
        else:
            check(f"xff {label}", status == expected, str(status))

    status, _, _ = await asgi_call(app, "POST", "/mcp", form={"x": "1"}, headers=[("X-Forwarded-For", "8.8.8.8, 127.0.0.1")])
    check("xff ending in loopback not special-cased", status == 403, str(status))
    status, _, _ = await asgi_call(app, "POST", "//token", form={"a": "1"})
    check("non-normalized guarded path refused", status == 403, str(status))
    saved_allow_local = os.environ.pop("ALLOW_LOCAL", None)
    status, _, _ = await asgi_call(app, "POST", "/mcp", form={"x": "1"})
    check("no-xff loopback refused by default (fail closed)", status == 403, str(status))
    os.environ["ALLOW_LOCAL"] = "1"
    status, _, _ = await asgi_call(app, "POST", "/mcp", form={"x": "1"})
    check("ALLOW_LOCAL=1 admits local no-xff testing", status == 401, str(status))

    status, _, _ = await asgi_call(app, "GET", "/healthz", headers=[("X-Forwarded-For", "8.8.8.8")])
    check("healthz exempt from allowlist", status == 200, str(status))

    bearer = tokens["access_token"]
    init = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                       "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                                  "clientInfo": {"name": "probe", "version": "0"}}}).encode()
    status, _, _ = await asgi_call(app, "POST", "/mcp", raw_body=init,
                                   headers=[("Authorization", f"Bearer {bearer}"),
                                            ("Content-Type", "application/json"),
                                            ("Accept", "application/json, text/event-stream")])
    check("bearer token accepted at /mcp (not 401/403)", status not in (401, 403), str(status))

    vault = Vault(root, exclude=["Café"])
    vectors = [
        "../outside/canary.md", "..%2Foutside%2Fcanary.md", "/etc/passwd", "~/../../canary.md",
        "notes/out.md", ".obsidian/workspace.md", "notes/../../../outside/canary.md",
        "notes/alpha.md/", "notes//alpha.md", "notes/alpha.md%00.md",
    ]
    leaked = []
    for v in vectors:
        for kind, fn in (("read", lambda p: vault.read_note(p)), ("resolve", lambda p: vault.resolve(p, kind="note"))):
            try:
                res = fn(v)
                text = json.dumps(res, default=str) if not isinstance(res, str) else res
                if "CANARY" in text or "secret dotfolder" in text or "excluded folder" in text:
                    leaked.append((kind, v))
            except Exception:
                pass
    check("traversal battery leaks nothing", not leaked, str(leaked[:3]))

    hits = vault.search_notes("CANARY")
    check("search never surfaces canary text", all("outside" not in r["path"] for r in hits["results"]))
    listed = json.dumps(vault.list_folder(""))
    check("NFD-excluded folder hidden from list",
          unicodedata.normalize("NFD", "Café") not in listed and unicodedata.normalize("NFC", "Café") not in listed)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-live", action="store_true")
    args = parser.parse_args()

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from armonica import auth as A
    from armonica.server import Config, build_app
    from armonica.vault import Vault, VaultError

    base = tempfile.mkdtemp(prefix="vc-probe-")
    root = Path(base) / "vault"
    outside = Path(base) / "outside"
    outside.mkdir()
    root.mkdir()
    state_dir = Path(base) / "state"
    state_dir.mkdir()
    build_fixtures(root, outside)

    phrase = "probe passphrase long enough to matter"
    (state_dir / "passphrase.json").write_text(json.dumps(A.hash_passphrase(phrase)))
    client_id, client_secret = A.preregister_client(state_dir)

    public_url = "https://vault-probe.example"
    app = build_app(Config(vault_root=root, public_url=public_url, state_dir=state_dir))

    print(f"probe vault: {root}")
    print("--- phase 1: ASGI matrix (local no-xff test mode on) ---")
    os.environ["ALLOW_LOCAL"] = "1"

    async def run_phase1():
        await lifespan_boot(app)
        try:
            await phase1(app, root, outside, state_dir, phrase, client_id, client_secret,
                         A, Vault, VaultError, Config, build_app, public_url)
        finally:
            await lifespan_shutdown(app)

    asyncio.run(run_phase1())

    before = tree_digest(root)

    if not args.skip_live:
        print("--- phase 2: live server ---")
        env = {k: v for k, v in os.environ.items() if k != "OHS_BIN"}
        env.update({
            "VAULT_ROOT": str(root), "PUBLIC_URL": public_url, "PORT": "8799",
            "STATE_DIR": str(state_dir), "IP_ALLOWLIST": "1", "ALLOW_LOCAL": "1",
        })
        proc = subprocess.Popen(
            [sys.executable, "-m", "armonica", "serve"],
            cwd=str(Path(__file__).resolve().parent.parent), env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        try:
            base_url = "http://127.0.0.1:8799"
            up = False
            for _ in range(40):
                try:
                    with urllib.request.urlopen(base_url + "/healthz", timeout=1) as r:
                        up = r.status == 200
                        break
                except Exception:
                    time.sleep(0.25)
            if not up:
                proc.terminate()
                try:
                    out = proc.communicate(timeout=5)[0] or b""
                except subprocess.TimeoutExpired:
                    proc.kill()
                    out = proc.communicate()[0] or b""
                check("live server came up", False, out.decode(errors="replace")[:400])
            else:
                check("live server came up", True)
            if up:
                for label, headers, want in [
                    ("live unauth /mcp 401", {"Content-Type": "application/json"}, 401),
                    ("live spoofed XFF 403", {"Content-Type": "application/json", "X-Forwarded-For": "8.8.8.8"}, 403),
                ]:
                    req = urllib.request.Request(base_url + "/mcp", data=b"{}", method="POST", headers=headers)
                    try:
                        urllib.request.urlopen(req, timeout=3)
                        check(label, False, "no error raised")
                    except urllib.error.HTTPError as e:
                        check(label, e.code == want, str(e.code))
                lsof = subprocess.run(["lsof", "-nP", "-p", str(proc.pid)], capture_output=True, text=True).stdout
                bad_egress = [line for line in lsof.splitlines()
                              if "ESTABLISHED" in line and "127.0.0.1" not in line and "::1" not in line]
                check("no outbound egress while serving", not bad_egress, str(bad_egress[:2]))
                listen = [line for line in lsof.splitlines() if "LISTEN" in line]
                check("listens only on 127.0.0.1", all("127.0.0.1:8799" in line for line in listen), str(listen[:2]))
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    after = tree_digest(root)
    check("vault tree unchanged after battery", before == after)

    failed = [r for r in RESULTS if not r[1]]
    print(f"--- verdict: {len(RESULTS) - len(failed)}/{len(RESULTS)} passed, {len(failed)} failed ---")
    for name, _, detail in failed:
        print(f"  FAILED: {name} [{detail}]")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
