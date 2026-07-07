# doorman "web mode" — gating a human-facing service (design note)

Status: **pontification, for discussion.** No code. Answers the question: *what
changes if I want to share a web dashboard with a colleague who has the
password?*

## The scenario

You have a dashboard (Grafana, a Streamlit app, an internal admin UI — any HTTP
service) running on your machine. You want a colleague on the open internet to
reach it, gated by a password you Slacked them. They open it **in a browser**.

## Why the current flow doesn't fit

Everything doorman does today is shaped for **one specific programmatic client —
Claude — speaking OAuth 2.1**:

- the connector URL must end in **`/mcp`**, and only that one endpoint is proxied;
- **OAuth 2.1**: `/authorize` + `/token` + PKCE + audience-bound RS256 JWTs +
  `/register` (DCR) + `/.well-known/*` discovery + JWKS.

A human in a browser does none of that. They can't do PKCE, they won't hit
discovery docs, they don't have a client id/secret, and they want the *whole*
site (HTML, assets, sub-pages, XHR/APIs), not a single JSON-RPC endpoint. So the
OAuth machinery is dead weight, and the single-`/mcp`-endpoint proxy is wrong.

## What carries over unchanged

The genuinely reusable half — and it's most of the value:

- the **reverse proxy** (streaming, SSE-safe) and **upstream credential
  injection** (dashboard stays gated; the shared secret never leaves the box);
- the **owner password** (becomes the login password);
- **Tailscale Funnel** exposure, **multi-instance**, **service install**, `doctor`.

This is exactly why "doorman" was named generically rather than "mcpgate": a
human-login gate is on-brand.

## The delta (what a `web` mode changes)

| Aspect | MCP mode (today) | Web mode (proposed) |
|---|---|---|
| Who authenticates | Claude, via OAuth 2.1 | a human, via a login form |
| Credential | client id/secret + PKCE + owner-password consent | just the owner password |
| Session | audience-bound JWT per request | **signed session cookie** set after login |
| Routes proxied | only `/mcp` | **all paths** (full passthrough) |
| OAuth endpoints | served | **absent** (`/authorize`,`/token`,`/register`,discovery,JWKS) |
| Login UI | consent page inside Claude's OAuth redirect | a **login page** served on any unauthenticated request |
| Logout | n/a (token expiry) | a `logout` endpoint |
| WebSocket | not needed | **often needed** (dashboards use WS) — see gap |

### Concretely, web mode is a classic auth reverse proxy

```
Browser ──GET /anything──▶ doorman
   no/invalid cookie → 302 to login page (or serve it inline)
   POST password (constant-time check) → Set-Cookie: signed, HttpOnly, Secure,
                                          SameSite=Lax, ~30d expiry → 302 back
   valid cookie → reverse-proxy the FULL request (any path) to the upstream,
                  injecting the upstream credential as today
```

Points that need real thought:
- **Cookie**: signed + expiring. Reuse the existing RS256 key to sign a tiny
  session token, or add an HMAC secret. Flags: `HttpOnly`, `Secure`,
  `SameSite=Lax`. Sliding expiry (refresh on use) so the colleague isn't logged
  out mid-session.
- **CSRF**: `SameSite=Lax` covers the login POST for the common case; a token on
  the form is the belt-and-braces option.
- **Login brute-force**: reuse the existing per-IP rate limiter on the login
  endpoint (behind a funnel it's effectively global — acceptable for a shared
  password; a lockout/backoff is the upgrade).
- **WebSocket (the real gap)**: the current proxy is `reqwest`-based and handles
  HTTP + SSE, **not WS `Upgrade`**. Many dashboards (Grafana live, notebooks,
  anything with live reload) need it. Adding WS proxying is the biggest single
  lift here (hyper `on_upgrade` + bidirectional copy, or a WS-aware proxy layer).
- **Single shared password vs per-user**: the scenario is one Slacked password →
  keep it single/shared for v1. Per-user accounts / audit is a much bigger scope
  and arguably out of doorman's "no IdP" lane.

## Recommendation

Add a **`mode` config knob** (`mcp` default, `web`). It's a clean fork at the
router: web mode mounts `{login, logout, cookie-gate, full-path proxy}` and does
**not** mount the OAuth AS/discovery endpoints. Owner password, funnel, cred
injection, instances, and service install are shared verbatim. `init` grows one
question ("Is this an MCP server for Claude, or a web app for people?") that
picks the mode and skips the client-id/secret generation in web mode.

### Lazy MVP (if we build it)

Login page (reuse the consent HTML) → `POST /_doorman/login` (constant-time
password → signed cookie) → cookie-gated full passthrough proxy → `/_doorman/logout`.
Reuse the RS256 key for cookie signing. **Defer WebSocket** with a loud note in
`init`/README ("web mode proxies HTTP/SSE; WebSocket dashboards aren't supported
yet") until a real dashboard needs it — that keeps the MVP to roughly the size of
the current OAuth handlers.

## When *not* to build this

If the colleague can join your tailnet, **Tailscale Serve + a node share** (or
Funnel with Tailscale's own auth) gets them in with no password and no public
exposure at all — simpler and safer. doorman web mode earns its keep only when
the colleague is fully external and a shared password is the desired bar. (And
if you want full-featured human SSO, `oauth2-proxy` / Authelia / Caddy
`forward_auth` already exist — doorman's niche is the same one-binary, no-IdP,
funnel-native simplicity, not competing with those.)

## Verdict

Very doable and on-brand, but it's a **distinct mode**, not a tweak: different
auth (cookie vs OAuth), different routing (all paths vs `/mcp`), no OAuth
endpoints, plus the WebSocket question. Recommend shipping the MCP path to 1.0
first, then adding `mode = "web"` as a fast-follow with the MVP above.
