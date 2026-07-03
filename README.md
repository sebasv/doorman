# doorman

> Front any MCP server (or any static-token / no-auth HTTP service) with the
> OAuth 2.1 flow Claude requires — in one binary. No Auth0, no Keycloak, no database.

Claude's custom-connector UI authenticates to remote MCP servers *only* via
OAuth 2.1 — there's no field for a static Bearer token. That blocks a large
class of self-hosted and static-token MCP servers. **doorman** is both the
authorization server (issues & signs tokens, minimal consent step) **and** the
resource server (validates tokens, reverse-proxies to your upstream, swapping in
the upstream's real credential so Claude never sees it). Single static binary,
runs on a Raspberry Pi.

> ⚠️ **Beta.** Guards real credentials — see [SECURITY.md](SECURITY.md). Not yet externally reviewed.

## Status

Early. See [DESIGN.md](DESIGN.md) for architecture, scope, and the build plan.

## Quickstart

_(coming with M2 — `doorman init` → `doorman run` → `doorman funnel-cmd`)_

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
