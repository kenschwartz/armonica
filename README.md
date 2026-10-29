# Armonica

Let Claude read your Obsidian vault from anywhere. Armonica is a read-only MCP server for claude.ai, Claude Desktop, mobile, and Claude Duet, including Duet's scheduled runs. Every tool is read-only. Every path is confined to the vault root. Authentication is real OAuth 2.1 with a passphrase gate, not a secret URL.

The name is Benjamin Franklin's glass armonica: Obsidian is volcanic glass, and Claude plays the other part. Armonica is an independent project, not affiliated with Anthropic or Obsidian.

## Design in one screen

- **Tools (all read-only):** `search_notes` (all-terms or "phrase" match, returns path + line numbers), `read_note` (paged, frontmatter on page 1), `list_folder`, `get_links` (outgoing wikilinks/Markdown links resolved to paths, plus backlinks, so MOCs can be walked). Nothing in the server writes to the vault.
- **Confinement:** every path is resolved and must stay inside `VAULT_ROOT`. Refused: absolute paths, `..`, any dotfile or dot-folder (`.obsidian`, `.trash`, `.git`), symlinks that leave the vault or point into a hidden folder, non-`.md` files, and folders listed in `VAULT_EXCLUDE`. Hard-linked files are refused too: a hard link is the same file as another name that may sit outside the vault, and nothing can tell which name is the original. Reads are capped at 256 KB per call (paged); notes over 5 MB are never opened; search stops after 8 s.
- **Network:** binds to `127.0.0.1:8765` only. A reverse proxy is the single way in from outside; it terminates TLS and carries the real client IP in `X-Forwarded-For`.
- **Auth:** OAuth 2.1 with PKCE and one pre-registered confidential client, served by this process. The sign-in page asks for a passphrase that only you hold (stored as a scrypt hash). Only Claude's callback (`https://claude.ai/api/mcp/auth_callback`) is registered, so a code cannot be sent anywhere else. (`register-client --generate --public` swaps in a client with no secret, as a fallback if Claude ever rejects the confidential one; the passphrase and PKCE still apply, the secret does not.) Tokens are random, stored only as SHA-256 hashes, bound to this server, 1 h access / 30 d rotating refresh. Five wrong passphrases from the same IP lock that IP for 15 minutes. The lock is keyed on the trusted last X-Forwarded-For entry and stored in a bounded map.

## Quick start

```bash
git clone <repo-url>
cd armonica
uv venv .venv && uv pip install --python .venv/bin/python -r requirements.txt
```

`--public-url` is the HTTPS address your front will serve, with no path. With Tailscale Funnel it is `https://<machine>.<tailnet>.ts.net` (`tailscale status --json | jq -r .Self.DNSName` prints it, minus the trailing dot).

macOS (launchd):

```bash
.venv/bin/python -m armonica setup --vault-root /path/to/your/vault --public-url https://your-host.example --generate-secrets --non-interactive --plist-out ~/Library/LaunchAgents/local.armonica.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/local.armonica.plist
```

Linux (systemd, runs as your user):

```bash
.venv/bin/python -m armonica setup --vault-root /path/to/your/vault --public-url https://your-host.example --generate-secrets --non-interactive --systemd-out armonica.service
sudo cp armonica.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now armonica
```

Then:

```bash
tailscale funnel --bg --https=443 http://127.0.0.1:8765
curl -s https://your-host.example/healthz      # {"ok": true, ...}
```

`setup` generates a passphrase and OAuth client credentials and prints them once: save all three in your password manager. In claude.ai, open Settings > Connectors > Add custom connector, enter `https://your-host.example/mcp`, and paste the client ID and secret under Advanced. Claude opens the sign-in page; enter the passphrase.

## Deploy fronts

You need one way for the internet to reach the loopback server.

| Front | Recommendation | Notes |
|---|---|---|
| **Tailscale Funnel** | Recommended for most users | Terminates TLS on your tailnet. No open ports on your router. Run `tailscale funnel --bg --https=443 http://127.0.0.1:8765`. |
| **Any reverse proxy** | Works if it appends the real client address to `X-Forwarded-For` | The IP allowlist reads the last entry of `X-Forwarded-For`. A proxy that passes the client's own header through unchanged lets anyone pick that entry, which defeats the allowlist. A request with no header is refused 403 (fail closed). |
| **Loopback only** | For local clients | Set `ALLOW_LOCAL=1` so the server accepts requests from `127.0.0.1` without an `X-Forwarded-For` header. Never combine it with a public front: a proxy that omits the header would then skip the allowlist. |

## Security summary

| Control | What it does |
|---|---|
| Vault confinement | Every path is resolved inside `VAULT_ROOT`. `..`, absolute paths, dotfiles, non-`.md` files, symlinks that leave the vault or point into a hidden folder, and hard-linked files are rejected. |
| OAuth 2.1 + PKCE | Codes are short-lived and bound to Claude's callback. Tokens are hashed at rest. |
| Passphrase gate | Scrypt hash, not plaintext. Five failures from one IP trigger a 15-minute lockout for that IP only. |
| IP allowlist | `/mcp`, `/token`, `/revoke` and `/.well-known/*` accept Anthropic connector egress only (`160.79.104.0/21`; `IP_ALLOWLIST_CIDR` takes a comma-separated list to change it). `/authorize` and `/login` stay open because your own browser does the sign-in; the passphrase and lockout guard them. `IP_ALLOWLIST=0` turns the check off: loopback testing only. |
| Loopback binding | The server never binds to a public interface. TLS is terminated by the reverse proxy. |

For the full threat model, see [docs/SECURITY.md](docs/SECURITY.md).

## Optional hybrid search (OHS)

If `OHS_BIN` points to an executable, `search_notes` runs it as a hybrid backend before the substring scan. It is invoked with list arguments (never a shell):

```
OHS_BIN search --mode hybrid --limit <limit> --db <OHS_DB> --json -- <query>
```

The contract is verified against the real binary (ohs 0.15.1): with `--json` it prints a JSON list of objects whose `path` is vault-relative; every hit goes back through `Vault.resolve` and anything that does not confine is dropped. The `--` separator comes LAST: options after it are read as query operands by the real binary, which returns rc 0 with empty stdout and silently degrades the backend to permanent fallback.

- `OHS_DB` defaults to `<vault_root>/.obsidian-hybrid-search.db`.
- The timeout is `vault.vault.OHS_TIMEOUT_S` seconds (default 10).
- `"backend"` reports three states: `"ohs"` (ran, at least one confined hit), `"ohs-empty"` (ran clean, nothing confined; substring results still returned), `"fallback"` (missing, non-zero exit, timeout, or unparseable; substring results still returned). Every fallback is logged with the returncode, the first 200 chars of stderr, or the exception type.

## Demo vault

A six-note demo vault is included in `fixtures/demo-vault/`. Run it locally with:

```bash
.venv/bin/python scripts/demo.py
```

This boots the server on `127.0.0.1:8798` with a throwaway state and prints the URL.

## FAQ

### Why OAuth instead of a static header?

Claude's connector docs list three options: OAuth, a static request header, or no auth. Static headers are a limited beta restricted to some organizations, so most users cannot rely on having the field. No auth means anyone who learns the URL reads the vault, and public URLs can appear in Certificate Transparency logs. OAuth is the only option that is both widely available and actually gated.

### Why read-only?

The vault is the system of record for notes and decisions. The connector's job is to let Claude read it, not to let Claude (or anyone who compromises Claude's context) rewrite it. If you need write access, use Obsidian directly.

## Day-2 operations

### Restart after a config change

If you installed the launchd plist:

```bash
launchctl kickstart -k gui/$(id -u)/local.armonica
```

If you installed the systemd unit:

```bash
sudo systemctl restart armonica
```

### See who is signed in

```bash
.venv/bin/python -m armonica status
```

### Rotate the passphrase (and kick everyone out)

```bash
.venv/bin/python -m armonica set-passphrase --generate
.venv/bin/python -m armonica revoke-all
```

`set-passphrase` alone does not end existing sign-ins; `revoke-all` does, and takes effect on the running server without a restart. Then reconnect the connector in Claude (it will show the sign-in page again).

### Turn it off

- **Instant kill switch** (vault unreachable from the internet, server keeps running locally): turn off your reverse proxy or Funnel.
- **Stop the server:** unload the launchd plist or stop the systemd unit.
- **Remove completely:** stop the server, delete the connector in Claude, remove the plist/unit file, and `rm -rf ~/.armonica`.

## Risks and limits

- **The passphrase is the only gate.** The sign-in page is on the public internet. Use the generated one; do not reuse a password.
- **Lockout can be abused.** An attacker can trigger five bad attempts and lock their own IP for 15 minutes. They cannot lock the owner signing in from a different IP. Existing sign-ins keep working; only new sign-ins are blocked. Lock state persists across restarts. Acceptable for one user.
- **Prompt injection runs both ways.** The vault is agent-authored. Anything Claude reads from it is just text to Claude, but a note that says "ignore your instructions" is now reachable by every Claude surface. The tools cannot write, so the blast radius is what Claude does next, not the vault.
- **Funnel is beta and bandwidth-limited** (Tailscale's words). Fine for notes, not for attachments, which this server does not serve anyway.
- **SDK version.** `mcp` 2.x renamed its APIs recently; keep it pinned and rerun the tests before upgrading.
- **Client secret at rest.** The SDK's `ClientAuthenticator` compares `client.client_secret` directly, so the secret must be stored as plaintext in `state.json` (mode 600). This is a documented design decision, not an oversight.
- **Tested clients.** Verified end to end with claude.ai and Claude Duet, including Duet's scheduled runs. Other MCP clients are untested.
