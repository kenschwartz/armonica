# Security

This document describes the security model of Armonica for operators who are not the original author.

## Assets

The only asset is your Obsidian vault. The connector exposes it read-only; no tool writes to disk.

## Threat model

### Attackers we consider

- Anyone on the internet who learns or guesses the public URL.
- A phishing signer who clones the sign-in page to trick you into entering the passphrase.
- A compromised note that tries to exploit the reading model via prompt injection.

### Boundaries we enforce

- **Confinement:** every path resolves inside the vault. `..`, absolute paths, dotfiles, excluded folders, symlinks that leave the vault and hard-linked files are refused. A hard-linked note you made on purpose (to share it between two vaults, say) is hidden too; copy it instead.
- **Transport:** Tailscale Funnel (or another reverse proxy) terminates TLS. The connector itself binds to loopback only.
- **Authentication:** OAuth 2.1 with PKCE and a single pre-registered confidential client. Only Claude's registered callback can receive an authorization code. The `--public` fallback client has no secret; with it, the passphrase and PKCE are the whole gate.
- **Passphrase gate:** The sign-in page requires a passphrase stored only as a scrypt hash.
- **IP allowlist:** `/mcp`, `/token`, `/revoke` and every `/.well-known/` path accept only Anthropic connector egress (`160.79.104.0/21` by default; `IP_ALLOWLIST_CIDR` replaces it with a comma-separated list). The address is the last `X-Forwarded-For` entry, so the proxy in front must append the real client address (Tailscale Funnel sets it); a proxy that forwards the client's own header unchanged defeats the check. Requests to those paths without the header are refused 403. `/authorize` and `/login` are not allowlisted, because your own browser completes the sign-in from wherever you are.

### What is NOT protected

- **CT-log hostname visibility.** If you use a public Funnel URL, the hostname appears in Certificate Transparency logs. This reveals that a service exists at that domain, though not its contents.
- **Lockout-abuse DoS.** Five wrong passphrase attempts from one IP lock that IP for 15 minutes. An attacker cannot lock the owner out from a different IP. Existing sessions continue to work; only new sign-ins are blocked.
- **Prompt injection from note content.** The vault is agent-authored. Anything Claude reads from it is plain text to the model. A note that says "ignore your instructions" is now reachable by every Claude surface. The tools are read-only, so the blast radius is what Claude does next, not the vault itself.

## Kill switches

- **Stop internet exposure instantly:** turn off your reverse proxy or Funnel. The server keeps running locally but is unreachable from the internet.
- **End every sign-in:** `python -m armonica revoke-all`. Takes effect on the running server; Claude must sign in again.

`IP_ALLOWLIST=0` is not a kill switch: it removes the network check and widens exposure. Use it only for loopback testing, never behind a public front.

## Reporting

If you discover a security issue, please open a private GitHub security advisory rather than a public issue. We will respond as quickly as we can.
