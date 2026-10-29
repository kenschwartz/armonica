"""MCP server exposing read-only vault tools behind the single-user OAuth server."""

from __future__ import annotations

import base64
import ipaddress
import logging
import os
import posixpath
import threading
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations

from .auth import SCOPE, VaultOAuthProvider
from .vault import Vault, VaultError

# Shown to Claude when it connects. VAULT_INSTRUCTIONS replaces it, so an owner
# can describe how their own vault is organized.
INSTRUCTIONS = """Read-only access to an Obsidian vault.
Start with search_notes or list_folder, then read_note. Cite notes by path and line number.
Use get_links to follow a note's outgoing links or find what links to it."""

READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)

_VAULT_SEMAPHORE = threading.Semaphore(2)

MAX_FORM_BODY = 64 * 1024  # /token form posts larger than this are refused before buffering
MAX_REQUEST_BODY = 1024 * 1024  # 1 MB hard ceiling on every request body (env MAX_REQUEST_BODY overrides)

logger = logging.getLogger("armonica")


@dataclass
class Config:
    vault_root: Path
    public_url: str  # e.g. https://your-host.tail1234.ts.net (no trailing slash, no path)
    port: int = 8765
    state_dir: Path = Path("~/.armonica").expanduser()
    exclude: tuple[str, ...] = ()
    instructions: str = INSTRUCTIONS


def replay(body: bytes):
    """Return an async receive callable that serves the complete body on every call.

    Idempotent by design: a downstream reader that asks twice gets the same
    complete http.request message, so double reads cannot truncate the body.
    """
    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    return receive


def replay_once(body: bytes, original_receive):
    """Serve the buffered body once, then delegate to the real receive.

    Unlike replay(), this does NOT keep returning the body. After the body is
    delivered, further receive() calls fall through to the ASGI server's own
    receive, so a downstream disconnect watcher on a long-lived connection (the
    MCP streamable-http transport keeps one) blocks and eventually sees
    http.disconnect, instead of busy-spinning on an endless http.request. Used
    by the outermost body cap, which wraps every request including /mcp.
    """
    delivered = False

    async def receive():
        nonlocal delivered
        if not delivered:
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}
        return await original_receive()

    return receive


async def normalize_client_secret_post(request: Request) -> Request:
    """Drain a /token form post and rewrite client_id + client_secret into a Basic header."""
    body = b""
    while True:
        msg = await request.receive()
        if msg.get("type") == "http.disconnect":
            break
        body += msg.get("body", b"")
        if len(body) > MAX_FORM_BODY:
            return Request(request.scope, replay(body))
        if not msg.get("more_body", False):
            break

    if request.headers.get("authorization"):
        return Request(request.scope, replay(body))

    parsed = parse_qs(body.decode("utf-8", errors="replace"))
    cid = parsed.get("client_id", [None])[0]
    sec = parsed.get("client_secret", [None])[0]
    if cid is None or sec is None:
        return Request(request.scope, replay(body))

    auth_str = "Basic " + base64.b64encode(f"{unquote(cid)}:{unquote(sec)}".encode()).decode()
    new_headers = list(request.scope["headers"]) + [(b"authorization", auth_str.encode())]
    return Request({**request.scope, "headers": new_headers}, replay(body))


class TokenNormalizeMiddleware:
    def __init__(self, app):
        self.app = app
        self.routes = getattr(app, "routes", [])

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http" and scope.get("method") == "POST" and scope.get("path") == "/token":
            body = b""
            oversized = False
            while True:
                msg = await receive()
                if msg.get("type") == "http.disconnect":
                    break
                body += msg.get("body", b"")
                if len(body) > MAX_FORM_BODY:
                    oversized = True
                    break
                if not msg.get("more_body", False):
                    break
            if oversized:
                await send({"type": "http.response.start", "status": 413,
                            "headers": [(b"content-type", b"application/json")]})
                await send({"type": "http.response.body", "body": b'{"error":"payload too large"}'})
                return
            req = Request(scope, replay(body))
            rewritten = await normalize_client_secret_post(req)
            await self.app(rewritten.scope, replay(body), send)
        else:
            await self.app(scope, receive, send)


GUARDED_PATHS = ("/mcp", "/token", "/revoke")
DEFAULT_CIDRS = "160.79.104.0/21"  # Anthropic connector egress


def parse_cidrs(value: str) -> list:
    """IP_ALLOWLIST_CIDR as networks; ValueError names the bad entry."""
    return [ipaddress.ip_network(c.strip()) for c in value.split(",") if c.strip()]


class IPAllowlistMiddleware:
    """ASGI middleware that blocks requests from IPs outside the allowed CIDRs.

    Guards /mcp, /token, /revoke, and every path starting /.well-known/.
    Exempts /login, /authorize, /healthz.
    Env IP_ALLOWLIST=0 disables the guard.
    """

    def __init__(self, app):
        self.app = app
        self.routes = getattr(app, "routes", [])
        self._logged: set[str] = set()

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        raw_path = scope.get("path", "")
        # Fail closed on non-normalized paths: a guard bypass via /token/,
        # //token or /.well-known/../mcp must 403, not fall through. POSIX
        # normpath keeps a double leading slash, so reject it explicitly.
        path = posixpath.normpath(raw_path)
        if "//" in raw_path or (raw_path != path and path + "/" != raw_path):
            await self._forbid(send)
            return

        if path in ("/login", "/authorize", "/healthz"):
            await self.app(scope, receive, send)
            return

        if not (path in GUARDED_PATHS or path.startswith("/.well-known/")):
            await self.app(scope, receive, send)
            return

        if os.environ.get("IP_ALLOWLIST") == "0":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        xff = headers.get(b"x-forwarded-for", b"").decode("utf-8", errors="replace").strip()
        if xff:
            derived = xff.split(",")[-1].strip()
        else:
            client = scope.get("client", ("", 0))
            derived = client[0] if client else ""
            # No XFF: the only direct peer is the on-host proxy, which carries no
            # provenance. Fail closed unless local testing is explicitly enabled.
            allow_local = os.environ.get("ALLOW_LOCAL") == "1"
            if allow_local and derived in ("127.0.0.1", "::1"):
                await self.app(scope, receive, send)
                return
            await self._forbid(send)
            return

        networks = parse_cidrs(os.environ.get("IP_ALLOWLIST_CIDR", DEFAULT_CIDRS))
        try:
            addr = ipaddress.ip_address(derived)
        except ValueError:
            await self._forbid(send)
            return

        if not any(addr in net for net in networks):
            await self._forbid(send)
            return

        if derived not in self._logged:
            self._logged.add(derived)
            safe_xff = "".join(ch if ch.isprintable() else "?" for ch in xff)[:200]
            logger.info("IP allowlist pass: derived=%s xff=%s", derived, safe_xff)

        await self.app(scope, receive, send)

    async def _forbid(self, send):
        await send({"type": "http.response.start", "status": 403, "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": b'{"error":"forbidden"}'})


class BodyLimitMiddleware:
    """Refuse any request body larger than the cap before it is buffered.

    starlette's form parser accepts up to 1000 fields x 1MB (~1GB) per request,
    and /login is exempt from the IP allowlist, so without this an
    unauthenticated stranger could exhaust server memory with one or a few large
    posts. A declared Content-Length over the cap is refused at once; a body with
    no declared length is counted as it streams and cut off the same way. The
    body is buffered to the cap and replayed, which is safe because every
    legitimate request (sign-in form, OAuth posts, JSON-RPC tool calls) is far
    under it; SSE is a response stream and is untouched.
    """

    def __init__(self, app, max_body: int = MAX_REQUEST_BODY):
        self.app = app
        self.max_body = max_body
        self.routes = getattr(app, "routes", [])

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        declared = dict(scope.get("headers", [])).get(b"content-length")
        if declared is not None:
            try:
                too_big = int(declared) > self.max_body
            except ValueError:
                too_big = True
            if too_big:
                await self._too_large(send)
                return

        body = b""
        while True:
            msg = await receive()
            if msg.get("type") == "http.disconnect":
                return
            body += msg.get("body", b"")
            if len(body) > self.max_body:
                await self._too_large(send)
                return
            if not msg.get("more_body", False):
                break

        await self.app(scope, replay_once(body, receive), send)

    async def _too_large(self, send):
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": b'{"error":"payload too large"}'})


def build_app(cfg: Config):
    public_url = cfg.public_url.rstrip("/")
    resource_url = f"{public_url}/mcp"
    vault = Vault(cfg.vault_root, list(cfg.exclude))
    provider = VaultOAuthProvider(public_url, resource_url, cfg.state_dir)

    mcp = MCPServer(
        name="armonica",
        title="Obsidian vault (read-only)",
        instructions=cfg.instructions,
        auth_server_provider=provider,
        auth=AuthSettings(
            issuer_url=public_url,
            resource_server_url=resource_url,
            validate_token_resource=True,
            required_scopes=[SCOPE],
            client_registration_options=ClientRegistrationOptions(
                enabled=False, valid_scopes=[SCOPE], default_scopes=[SCOPE]
            ),
            revocation_options=RevocationOptions(enabled=True),
        ),
    )

    def guarded(fn, *args, **kwargs) -> dict:
        with _VAULT_SEMAPHORE:
            try:
                return fn(*args, **kwargs)
            except VaultError as e:
                return {"error": str(e)}

    @mcp.tool(annotations=READ_ONLY)
    def search_notes(query: str, folder: str = "", limit: int = 20) -> dict:
        """Search note text and paths. All terms must match (case-insensitive); use "quotes" for a phrase.
        folder limits the search to a vault folder. Returns paths with matching line numbers."""
        return guarded(vault.search_notes, query, folder, limit)

    @mcp.tool(annotations=READ_ONLY)
    def read_note(path: str, start_line: int = 1, max_lines: int | None = None) -> dict:
        """Read a note by its vault path (e.g. "Projects/Roadmap.md"). Returns frontmatter on the first page.
        Long notes are paged: pass next_start_line from the result to continue."""
        return guarded(vault.read_note, path, start_line, max_lines)

    @mcp.tool(annotations=READ_ONLY)
    def list_folder(path: str = "") -> dict:
        """List subfolders and notes in a vault folder. Empty path means the vault root."""
        return guarded(vault.list_folder, path)

    @mcp.tool(annotations=READ_ONLY)
    def get_links(path: str, include_backlinks: bool = True) -> dict:
        """Outgoing [[wikilinks]] and Markdown links of a note, resolved to vault paths,
        plus the notes that link to it (backlinks)."""
        return guarded(vault.get_links, path, include_backlinks)

    @mcp.custom_route("/login", methods=["GET", "POST"])
    async def login(request: Request) -> Response:
        return await provider.login_page(request)

    @mcp.custom_route("/healthz", methods=["GET"])
    async def healthz(request: Request) -> Response:
        return JSONResponse({"ok": True, "ip_allowlist": os.environ.get("IP_ALLOWLIST") != "0"})

    host = urlparse(public_url).netloc
    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[host, f"{host}:*", "127.0.0.1:*", "localhost:*"],
        allowed_origins=[public_url, "https://claude.ai", "http://127.0.0.1:*", "http://localhost:*"],
    )
    app = mcp.streamable_http_app(
        streamable_http_path="/mcp",
        stateless_http=True,
        json_response=True,
        transport_security=security,
        host="127.0.0.1",
    )
    app = TokenNormalizeMiddleware(app)
    app = IPAllowlistMiddleware(app)
    app = BodyLimitMiddleware(app, max_body=_max_request_body())
    return app


def _max_request_body() -> int:
    """MAX_REQUEST_BODY env override, falling back to the 1 MB default."""
    raw = os.environ.get("MAX_REQUEST_BODY")
    if not raw:
        return MAX_REQUEST_BODY
    try:
        value = int(raw)
    except ValueError:
        return MAX_REQUEST_BODY
    return value if value > 0 else MAX_REQUEST_BODY
