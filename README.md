# doorman

> Run your MCP server, guard it behind a password, and put it on the internet for
> Claude — in one binary. No Auth0, no Keycloak, no database.

Claude's custom-connector UI can only reach a remote MCP server through the
OAuth 2.1 flow — there's no field for a static token. **doorman** is the missing
piece: it runs your MCP server on localhost, speaks the exact OAuth dance Claude
expects, gates access behind a password you control, and reverse-proxies to the
upstream — injecting the upstream's own credential so **Claude never sees it**.

It runs on a Raspberry Pi. The only on-disk state is an auto-generated signing
key and a small registered-clients file.

> ⚠️ **Beta.** doorman guards real credentials — see [SECURITY.md](SECURITY.md).

## Quickstart

```sh
cargo install doorman          # or: brew install sebasv/tap/doorman

doorman init                   # asks what starts your MCP server, sets everything up
doorman doctor                 # end-to-end self-check
```

`init` walks you through it in about four answers:

1. **What command starts your MCP server?** doorman runs and supervises it on
   localhost — so there's no upstream token to configure.
2. **A public address.** If [Tailscale](https://tailscale.com) is set up, doorman
   derives your public URL and brings up a Funnel automatically; otherwise it
   guides you or takes a URL you already have.
3. **An owner password** (press Enter for a generated one) — the key that
   approves Claude.
4. **Run on boot?** doorman installs itself as a service (systemd / launchd /
   Windows task).

It finishes by printing the exact **URL**, **Client ID**, **Client Secret**, and
**owner password** to paste into Claude → *Settings → Connectors → Add custom
connector*. The URL ends in `/mcp`.

## Commands

```
doorman init [name]      Interactive setup for an instance
doorman run [name]       Run it (and supervise its upstream)
doorman restart [name]   Restart the service to pick up config changes
doorman doctor [name]    Diagnose upstream, funnel, discovery, token round-trip
doorman list             List instances with status + URL
doorman delete [name]    Stop & remove an instance (service, funnel, config)
doorman funnel-cmd [name]   Print the tunnel command to expose an instance
doorman install-service [name]   Register an instance to start on boot
```

Every command takes an optional instance **name** (default `default`), so one
machine can front several MCP servers — each gets its own port, Funnel port,
config, and service:

```sh
doorman init picnic
doorman init n8n
doorman list
```

## How it works

```
Claude (cloud) ──OAuth 2.1 + Bearer──▶  doorman  ──▶  your MCP server (localhost)
                                        │  runs & supervises the upstream
                                        │  AS: /authorize /token /register /jwks + discovery
                                        │  RS: validates the token, proxies /mcp (streaming)
                                        │  injects the upstream credential; Claude never sees it
```

- OAuth 2.1 **authorization_code + PKCE (S256)**, audience-bound RS256 access
  tokens, stateless refresh tokens.
- **Dynamic client registration** (RFC 7591) so Claude registers itself.
- Config resolves **env `DOORMAN_*` > `~/.config/doorman/<name>/config.toml` > defaults**.

## Install

| Path | Command |
|---|---|
| Homebrew | `brew install sebasv/tap/doorman` |
| Cargo | `cargo install doorman` |
| Installer | `curl --proto '=https' --tlsv1.2 -LsSf https://github.com/sebasv/doorman/releases/latest/download/doorman-installer.sh \| sh` |
| Raw binary | download the tarball for your platform from [Releases](https://github.com/sebasv/doorman/releases) |

Prebuilt for macOS (arm64/x64), Linux (arm64/x64, incl. the Pi), and Windows (x64).

## Docs

- [Getting started](docs/getting-started.md) — full walkthrough + config reference
- [Troubleshooting](docs/troubleshooting.md)
- [Security](SECURITY.md) — threat model, hardening, known limits, disclosure

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
