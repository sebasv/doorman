# Troubleshooting

Run `doorman doctor [name]` first — it checks the Funnel, the upstream, the
public discovery doc, the unauthenticated challenge, and a full OAuth + token
round-trip, and prints a targeted fix for whatever fails. It isolates *which*
layer is broken (your server vs. the tunnel vs. doorman). The cases below are
the ones seen in practice.

## "Authorized but no MCP server found" — the connector URL is missing `/mcp`

The connector URL must end in `/mcp` (`https://host/mcp`), not just the host.
Remove and re-add the connector with the full path.

## `doctor` says the upstream is unreachable

Your MCP server isn't answering on its local port. If doorman runs it
(`spawn_cmd`), check the command and port in the config; watch `doorman run`'s
logs for the upstream's own errors. This is independent of the Funnel and the
OAuth flow.

## `doctor` says the Funnel isn't serving

`tailscale funnel status` isn't showing this instance. Either it was never
brought up (`doorman funnel-cmd <name>` prints the command), or **Funnel isn't
enabled for your tailnet** — that's a Tailscale admin-console toggle (Access
controls → node attributes → `funnel`), without which `tailscale funnel`
silently refuses.

## Tailscale on macOS

Homebrew's `tailscale` runs a daemon that must be started (`sudo brew services
start tailscale`) and logged in (`sudo tailscale up`); Homebrew's warnings about
root-owned paths and "start at user login" are cosmetic. The GUI app from
tailscale.com/download is the no-terminal alternative. Funnel works fine in
Homebrew's userspace-networking mode.

## `redirect_uri not allowed`

The callback isn't registered for the client. With dynamic registration Claude
registers its own; a stale pre-registered client is the usual cause — let Claude
register fresh, or add the exact callback to `allowed_redirect_uris`. doorman
logs the rejected `redirect_uri` (not a secret) so you can copy it.

## Claude completes OAuth but never sends the token

A known **client-side** issue on some Claude surfaces: the flow finishes but
requests arrive without the `Authorization` header, so doorman correctly returns
401. `doorman doctor`'s round-trip proves the server side is fine — if it passes
but a surface still fails, it's the client; try another surface.

## Team / Enterprise accounts

Members often can't add custom connectors — an Owner must, or use a personal
Pro/Max account.

## `429 rate limited`

Too many requests to the auth endpoints from one IP (behind a Funnel that's
effectively global). Wait a minute or raise `rate_limit` (`0` disables). This
never affects an already-connected session — only new authorizations.

## Refresh stopped working

Refresh tokens expire after `refresh_ttl` (default 60 days); deleting the signing
key also invalidates every token. In both cases, remove and re-add the connector.

## Won't start: missing `owner_password` / `issuer_url`

Run `doorman init <name>` (or set the values in `config.toml`). The owner
password must be present; an empty value is allowed but means anyone reaching the
consent page can approve.
