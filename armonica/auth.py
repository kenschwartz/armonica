"""A single-user OAuth 2.1 authorization server for Armonica.

Claude's custom connectors sign in with OAuth (one pre-registered confidential
client + PKCE). The MCP SDK implements the protocol endpoints; this module
supplies the provider behind them plus a passphrase page, so the only person
who can finish the sign-in is whoever knows the passphrase.

Hardening, in order of importance:
- Sign-in is gated by a passphrase stored only as a scrypt hash.
- The single pre-registered client uses client_secret_basic and Claude's callback.
- Tokens are random, stored only as SHA-256 hashes, short-lived (1 h access,
  30 d rotating refresh) and bound to this server's resource URL.
- Failed passphrase attempts lock the sign-in page for 15 minutes after 5 tries.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import hmac
import html
import itertools
import json
import os
import secrets
import time
from pathlib import Path
from urllib.parse import urlparse

from pydantic import AnyUrl
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    RegistrationError,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

SCOPE = "vault.read"
CLAUDE_CALLBACK = "https://claude.ai/api/mcp/auth_callback"
ACCESS_TTL_S = 60 * 60
REFRESH_TTL_S = 30 * 24 * 60 * 60
CODE_TTL_S = 5 * 60
PENDING_TTL_S = 10 * 60
MAX_PENDING = 100
LOCKOUT_FAILURES = 5
LOCKOUT_WINDOW_S = 15 * 60
LOCKOUT_MAX_IPS = 4096
SCRYPT = {"n": 2**15, "r": 8, "p": 1}
SUBJECT = "vault-owner"


def derive_client_ip(xff: str | None, peer: str | None) -> str:
    """Trusted client ip for lockout keying: the LAST X-Forwarded-For entry
    (the hop the reverse proxy appends), else the socket peer. Mirrors the
    allowlist's last-entry rule; a spoofed earlier entry cannot be the key."""
    if xff:
        last = xff.split(",")[-1].strip()
        if last:
            return last
    return peer or ""


def _h(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# ---- passphrase ------------------------------------------------------


def hash_passphrase(passphrase: str) -> dict:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(passphrase.encode(), salt=salt, maxmem=2**26, dklen=32, **SCRYPT)
    return {"algo": "scrypt", **SCRYPT, "salt": salt.hex(), "hash": digest.hex()}


def check_passphrase(passphrase: str, record: dict) -> bool:
    digest = hashlib.scrypt(
        passphrase.encode(),
        salt=bytes.fromhex(record["salt"]),
        n=record["n"],
        r=record["r"],
        p=record["p"],
        maxmem=2**26,
        dklen=32,
    )
    return hmac.compare_digest(digest.hex(), record["hash"])


# ---- persistent state ------------------------------------------------


class Store:
    """Clients and token hashes in one JSON file (mode 600).

    Re-read whenever the file changes on disk, so `revoke-all` from the CLI
    takes effect on a running server without a restart.
    """

    def __init__(self, path: Path):
        self.path = path
        self._mtime = None
        self.data = {"clients": {}, "access": {}, "refresh": {}, "lockout": {}}
        self._tmpc = itertools.count()
        self._lockfile = self.path.with_suffix(".json.lock")
        self._reload(force=True)

    def _reload(self, force: bool = False) -> None:
        try:
            mtime = self.path.stat().st_mtime_ns
        except FileNotFoundError:
            if force or self._mtime is not None:
                self.data = {"clients": {}, "access": {}, "refresh": {}, "lockout": {}}
                self._mtime = None
            return
        if force or mtime != self._mtime:
            self.data = json.loads(self.path.read_text())
            for k in ("clients", "access", "refresh", "lockout"):
                self.data.setdefault(k, {})
            self._mtime = mtime

    def get(self, table: str, key: str) -> dict | None:
        with self._locked():
            self._reload()
            return self.data[table].get(key)

    def put(self, table: str, key: str, value: dict) -> None:
        with self._locked():
            self._reload(force=True)
            self.data[table][key] = value
            self._save()

    def update(self, table: str, key: str, fn) -> None:
        """Atomic read-modify-write: fn(current dict or None) -> new dict, all under one lock hold."""
        with self._locked():
            self._reload(force=True)
            self.data[table][key] = fn(self.data[table].get(key))
            self._save()

    def delete_where(self, table: str, pred) -> None:
        with self._locked():
            self._reload(force=True)
            self.data[table] = {k: v for k, v in self.data[table].items() if not pred(k, v)}
            self._save()

    @contextlib.contextmanager
    def _locked(self):
        self._lockfile.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self._lockfile, os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _save(self) -> None:
        now = time.time()
        for table in ("access", "refresh"):
            self.data[table] = {k: v for k, v in self.data[table].items() if v["expires_at"] > now}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = f"{self.path}.tmp.{os.getpid()}.{next(self._tmpc)}"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(self.data, f, indent=1)
        os.replace(tmp, self.path)
        self._mtime = self.path.stat().st_mtime_ns


# ---- provider --------------------------------------------------------


class VaultOAuthProvider:
    def __init__(self, public_url: str, resource_url: str, state_dir: Path):
        self.public_url = public_url.rstrip("/")
        self.resource_url = resource_url
        self.state_dir = state_dir
        self.store = Store(state_dir / "state.json")
        self.passphrase_file = state_dir / "passphrase.json"
        self._pending: dict[str, tuple[str, AuthorizationParams, float]] = {}
        self._codes: dict[str, AuthorizationCode] = {}

    # -- registration --

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        raw = self.store.get("clients", client_id)
        return OAuthClientInformationFull.model_validate(raw) if raw else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        raise RegistrationError(
            "invalid_client_metadata", "registration is disabled; the single client is pre-registered"
        )

    # -- authorization --

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        if params.resource and params.resource.rstrip("/") != self.resource_url.rstrip("/"):
            raise AuthorizeError("invalid_target", "unknown resource")
        now = time.time()
        self._pending = {k: v for k, v in self._pending.items() if v[2] > now}
        while len(self._pending) >= MAX_PENDING:  # /authorize is public; keep memory bounded
            self._pending.pop(min(self._pending, key=lambda k: self._pending[k][2]))
        txn = secrets.token_urlsafe(32)
        self._pending[txn] = (client.client_id, params, now + PENDING_TTL_S)
        return f"{self.public_url}/login?txn={txn}"

    def is_locked(self, ip: str, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        rec = self.store.get("lockout", "ips") or {}
        recent = [t for t in rec.get(ip, []) if t > now - LOCKOUT_WINDOW_S]
        return len(recent) >= LOCKOUT_FAILURES

    def record_failure(self, ip: str, now: float | None = None) -> None:
        now = time.time() if now is None else now
        def _fn(rec):
            rec = dict(rec or {})
            # prune expired, drop empties
            pruned = {}
            for k, ts in rec.items():
                kept = [t for t in ts if t > now - LOCKOUT_WINDOW_S]
                if kept:
                    pruned[k] = kept
            pruned.setdefault(ip, []).append(now)
            # bounded FIFO: evict oldest-by-last-failure until within cap.
            # eviction only ever REMOVES entries, so it can only CLEAR a
            # lockout, never create one.
            if len(pruned) > LOCKOUT_MAX_IPS:
                victims = sorted(pruned, key=lambda k: max(pruned[k]))[:len(pruned) - LOCKOUT_MAX_IPS]
                for k in victims:
                    del pruned[k]
            return pruned
        self.store.update("lockout", "ips", _fn)

    async def login_page(self, request: Request) -> Response:
        if request.method == "GET":
            txn = request.query_params.get("txn", "")
            pending = self._pending.get(txn)
            if not pending or pending[2] < time.time():
                return _page("This sign-in link has expired. Start again from Claude.", status=400)
            client = await self.get_client(pending[0])
            name = (client.client_name if client else None) or "Unknown client"
            host = urlparse(str(pending[1].redirect_uri)).netloc
            return _page(_form(txn, name, host))

        form = await request.form()
        txn = str(form.get("txn", ""))
        pending = self._pending.get(txn)
        if not pending or pending[2] < time.time():
            return _page("This sign-in link has expired. Start again from Claude.", status=400)
        client_id, params, _ = pending
        redirect_uri = str(params.redirect_uri)

        origin = request.headers.get("origin")
        # Browsers send Origin: null from opaque contexts (sandboxed iframes,
        # webviews); claude.ai opens the sign-in page that way. Treat null as
        # absent: the txn secret is the CSRF defense, the Origin check only
        # rejects concrete foreign origins.
        if origin and origin != "null" and origin != self.public_url:
            return _page("bad origin", status=403)

        if form.get("action") == "deny":
            self._pending.pop(txn, None)
            return RedirectResponse(
                construct_redirect_uri(redirect_uri, error="access_denied", state=params.state), status_code=302
            )
        ip = derive_client_ip(request.headers.get("x-forwarded-for"),
                              request.client.host if request.client else None)
        if self.is_locked(ip):
            return _page("Too many wrong passphrases. Sign-in is locked for 15 minutes.", status=429)
        record = self._passphrase_record()
        if record is None:
            return _page("No passphrase is set on the server. Run set-passphrase first.", status=503)
        if not check_passphrase(str(form.get("passphrase", "")), record):
            self.record_failure(ip)
            client = await self.get_client(client_id)
            name = (client.client_name if client else None) or "Unknown client"
            host = urlparse(redirect_uri).netloc
            return _page(_form(txn, name, host, error="Wrong passphrase."), status=401)

        self._pending.pop(txn, None)
        code = secrets.token_urlsafe(32)
        # PKCE is enforced by the SDK token endpoint (S256 compare in
        # mcp/server/auth/handlers/token.py) before exchange_authorization_code
        # runs; do not loosen the mcp pin without re-reviewing that file.
        self._codes[code] = AuthorizationCode(
            code=code,
            scopes=params.scopes or [SCOPE],
            expires_at=time.time() + CODE_TTL_S,
            client_id=client_id,
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=self.resource_url,
            subject=SUBJECT,
        )
        return RedirectResponse(construct_redirect_uri(redirect_uri, code=code, state=params.state), status_code=302)

    def _passphrase_record(self) -> dict | None:
        try:
            return json.loads(self.passphrase_file.read_text())
        except FileNotFoundError:
            return None

    # -- tokens --

    async def load_authorization_code(self, client: OAuthClientInformationFull, authorization_code: str):
        code = self._codes.get(authorization_code)
        if not code or code.client_id != client.client_id or code.expires_at < time.time():
            return None
        return code

    async def exchange_authorization_code(self, client: OAuthClientInformationFull, authorization_code) -> OAuthToken:
        if self._codes.pop(authorization_code.code, None) is None:
            raise TokenError("invalid_grant", "authorization code already used")
        return self._issue(client.client_id, authorization_code.scopes, secrets.token_hex(8))

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str):
        rec = self.store.get("refresh", _h(refresh_token))
        if not rec or rec["client_id"] != client.client_id or rec["expires_at"] < time.time():
            return None
        return RefreshToken(
            token=refresh_token,
            client_id=rec["client_id"],
            scopes=rec["scopes"],
            expires_at=int(rec["expires_at"]),
            resource=self.resource_url,
            subject=SUBJECT,
        )

    async def exchange_refresh_token(self, client, refresh_token, scopes: list[str]) -> OAuthToken:
        rec = self.store.get("refresh", _h(refresh_token.token))
        if not rec:
            raise TokenError("invalid_grant", "refresh token is no longer valid")
        if scopes and not set(scopes).issubset(rec["scopes"]):
            raise TokenError("invalid_scope", "cannot widen scopes on refresh")
        # Rotate: the old refresh token and its access token die here.
        self._drop_tokens(lambda v: v.get("family") == rec["family"])
        return self._issue(client.client_id, scopes or rec["scopes"], rec["family"])

    async def load_access_token(self, token: str) -> AccessToken | None:
        rec = self.store.get("access", _h(token))
        if not rec or rec["expires_at"] < time.time():
            return None
        return AccessToken(
            token=token,
            client_id=rec["client_id"],
            scopes=rec["scopes"],
            expires_at=int(rec["expires_at"]),
            resource=self.resource_url,
            subject=SUBJECT,
        )

    async def revoke_token(self, token) -> None:
        table = "refresh" if isinstance(token, RefreshToken) else "access"
        rec = self.store.get(table, _h(token.token))
        if rec:
            self._drop_tokens(lambda v: v.get("family") == rec["family"])

    def _issue(self, client_id: str, scopes: list[str], family: str) -> OAuthToken:
        now = time.time()
        access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        base = {"client_id": client_id, "scopes": scopes, "family": family, "issued_at": now}
        self.store.put("access", _h(access), {**base, "expires_at": now + ACCESS_TTL_S})
        self.store.put("refresh", _h(refresh), {**base, "expires_at": now + REFRESH_TTL_S})
        return OAuthToken(
            access_token=access, expires_in=ACCESS_TTL_S, scope=" ".join(scopes), refresh_token=refresh
        )

    def _drop_tokens(self, pred) -> None:
        self.store.delete_where("access", lambda _, v: pred(v))
        self.store.delete_where("refresh", lambda _, v: pred(v))


# ---- sign-in page ----------------------------------------------------

_CSS = """
body{font:16px/1.5 -apple-system,system-ui,sans-serif;max-width:28rem;margin:4rem auto;padding:0 1rem;color:#222}
h1{font-size:1.25rem}input[type=password]{width:100%;padding:.5rem;font-size:1rem;box-sizing:border-box}
button{padding:.5rem 1rem;font-size:1rem;margin:.75rem .5rem 0 0}.err{color:#b00}.muted{color:#666;font-size:.9rem}
@media (prefers-color-scheme:dark){body{background:#111;color:#eee}.muted{color:#aaa}}
"""


def _form(txn: str, client_name: str, redirect_host: str, error: str = "") -> str:
    e = html.escape
    err = f'<p class="err">{e(error)}</p>' if error else ""
    return f"""<h1>Armonica sign-in</h1>
<p><b>{e(client_name)}</b> is asking for read-only access to your Obsidian vault.</p>
<p class="muted">After you approve, you'll be sent to <b>{e(redirect_host)}</b>. If that isn't Claude, deny.</p>
{err}
<form method="post" action="/login">
<input type="hidden" name="txn" value="{e(txn)}">
<label>Passphrase<br><input type="password" name="passphrase" autocomplete="current-password" autofocus></label><br>
<button type="submit" name="action" value="approve">Approve</button>
<button type="submit" name="action" value="deny" formnovalidate>Deny</button>
</form>"""


def _page(body: str, status: int = 200) -> HTMLResponse:
    if not body.lstrip().startswith("<"):
        body = f"<p>{html.escape(body)}</p>"
    doc = f"<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>Armonica</title><style>{_CSS}</style>{body}"
    return HTMLResponse(
        doc,
        status_code=status,
        headers={
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
        },
    )


# ---- preregister -----------------------------------------------------


def preregister_client(state_dir: Path, public: bool = False) -> tuple[str, str]:
    """Create or rotate the single OAuth client. Returns (client_id, client_secret).

    public=True registers a no-secret client (the rollback floor if claude.ai
    cannot complete a confidential handshake); the returned secret is "".
    """
    client_id = secrets.token_urlsafe(16)
    client_secret = "" if public else secrets.token_urlsafe(32)
    info = OAuthClientInformationFull(
        client_id=client_id,
        client_secret=client_secret or None,
        client_name="claude.ai",
        redirect_uris=[AnyUrl(CLAUDE_CALLBACK)],
        token_endpoint_auth_method="none" if public else "client_secret_basic",
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        scope=SCOPE,
    )
    store = Store(state_dir / "state.json")
    # Replace any prior client record (rotation)
    store.delete_where("clients", lambda k, v: True)
    store.put("clients", client_id, info.model_dump(mode="json"))
    return client_id, client_secret
