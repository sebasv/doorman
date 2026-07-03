# doorman — design

> Front any static-token or no-auth HTTP service with the OAuth 2.1 flow that
> Claude's custom-connector UI requires — in **one binary**. No Auth0, no
> Keycloak, no database.

This is the working design. The full brief lives in `mcpgate-handoff.md` (the
Claude-chat handoff); this document is the trimmed, decision-made version we
actually build against. Where they differ, this wins.

---

## 1. Name & scope

**`doorman`** — locked. Free on crates.io, Homebrew, Debian, and `github.com/sebasv/doorman`.

Chosen over `mcpgate` deliberately: doorman is a **generic OAuth-gate reverse
proxy**, and MCP-for-Claude is just its first target — not a hardcoded
assumption. Concretely that means:

- Naming, crate, binary, config keys are all MCP-free (`DOORMAN_*`, not `MCPGATE_*`).
- The one genuinely MCP-shaped thing — RFC 9728 protected-resource metadata
  advertising `resource_type: mcp-server` — stays, because that *is* the wedge
  that makes Claude connect. It's config-shaped, not load-bearing on the name.
- **We do not build a plugin system or "gate framework."** A second use case can
  earn its abstraction when it's real. Until then doorman is one proxy with one
  auth flow. (ponytail: no speculative generality.)

Non-goals (unchanged from handoff §11): not a multi-tenant IdP, not a policy
engine, not a fix for upstream-specific auth beyond a static token/header.

---

## 2. Architecture

```
Claude (cloud) ──OAuth 2.1 + Bearer──▶  doorman  ──static token──▶  upstream (HTTP, localhost)
                                        │  AS: /authorize /token /jwks + discovery docs
                                        │  RS: validates Bearer, proxies (streaming, SSE-safe)
                                        │  swaps Claude's token for the upstream's downstream credential
```

Single binary, single process, no external state store. The **only** on-disk
state is the RSA signing key (0600, auto-generated on first run). Everything
else — auth codes, rate-limit buckets — is in-memory and disposable. This is
correct for the single-owner / small-trusted-group scope; it is a deliberate
ceiling, not an oversight.

Two request planes:

- **Authorization server** (unauthenticated, discoverable): serves the three
  discovery docs + JWKS, runs `authorize_code + PKCE/S256` behind a single
  owner-password consent page, issues audience-bound RS256 access tokens +
  stateless signed refresh tokens.
- **Resource server / proxy** (token-gated): validates the Bearer (sig + `iss` +
  `aud` + `exp`), then reverse-proxies to the upstream, **streaming the
  response** (SSE-safe) and **injecting the upstream's static credential**
  downstream so Claude never sees it. Unauthenticated → 401 +
  `WWW-Authenticate: Bearer resource_metadata=…`.

---

## 3. The seed

`src/main.rs` is the working prototype, dropped in unmodified (still named
`picnic-oauth-proxy` internally — M0 de-picnicifies it). ~675 lines, axum +
jsonwebtoken + rsa + reqwest. It compiles and has been smoke-tested end-to-end
(happy path, wrong password, tampered PKCE, missing token). **Start here, extend
— do not rewrite.**

### Security review of the seed (what's already right)

- PKCE **S256 mandatory**; `plain` and missing challenge rejected in `validate_auth_req`.
- **Constant-time** compare (`subtle::ct_eq`) for owner password, client id, and client secret.
- **Exact-match** redirect allowlist — no substring/prefix matching, no open redirect.
- Access tokens **audience-bound** to `issuer + /mcp`; RS path validates `iss`, `aud`, `exp`, signature.
- Auth codes **single-use** (removed from map on redemption) and **≤120s** TTL.
- **Confused-deputy safe**: Claude's token is stripped, the configured downstream credential is injected — never forwarded.
- Signing key written **0600**; regenerated if absent (delete key ⇒ new keypair/JWKS = rotation).
- Response streamed via `Body::from_stream` — works for SSE / streamable HTTP.

### Gaps the milestones must close

| # | Gap | Severity | Fix |
|---|---|---|---|
| 1 | Auth-code map only pruned on redemption → unredeemed codes leak | low (mem/DoS) | prune-on-insert sweep (a few lines) — **M1** |
| 2 | **No rate limiting** on `/authorize` + `/token` → owner-password / client-secret brute force | **the one real hole** | per-IP token bucket, in-memory — **M1** |
| 3 | Request body fully buffered (`body: Bytes`), no size cap | low (authenticated only) | `DefaultBodyLimit` (e.g. 4 MiB) — **M1** |
| 4 | Stateless refresh tokens non-revocable until `exp` (60d) | accepted tradeoff | **document** in SECURITY.md; revisit only if DCR lands — **M5** |
| 5 | `audience` taken from client-supplied `resource` param | low (RS still checks `aud == cfg.resource`, so a mismatched token can't proxy) | pin audience to `cfg.resource` — **M0/M1** |
| 6 | Picnic naming: `kid = "picnic-oauth-1"`, consent copy, comments | cosmetic | **M0** |

None of these block the current happy path; #2 is the only one that must land
before we call it beta-secure.

---

## 4. v1 scope — the lazy cut

The handoff lists M0–M5. Here's what actually ships in v1 and what waits, with
the reasoning:

### In v1

- **M0 — Generalize.** De-picnicify (naming, `DOORMAN_*` env keys, `kid`, consent
  copy, comments). Add `DOORMAN_UPSTREAM_PATH` and configurable upstream auth
  header (`DOORMAN_UPSTREAM_HEADER`, support injecting both forms). Pin token
  audience to `cfg.resource`. `cargo fmt` + `clippy -D warnings` clean.
- **M1 — Correctness & trust.** Rate limiting (gap #2), auth-code GC (#1), body
  cap (#3), and the **test suite** (§6). This is the milestone that earns the
  "beta-secure" label.
- **M1b — DCR (RFC 7591), in v1.** `/register` endpoint (open registration, gated
  by the owner-password consent — see below), clients persisted to a small JSON
  (`$STATE/clients.json`) so they survive restart, `registration_endpoint`
  advertised in AS metadata. The pre-registered env client keeps working
  alongside. This is what makes setup zero-paste for others: Claude registers
  itself, the owner never touches Advanced settings.
- **M2 (trimmed) — Ergonomics that matter.** `init` (interactive: writes config,
  generates key + secrets, prints the exact Client ID / Client Secret / URL /
  owner-password to paste into Claude), `doctor` (upstream reachable → discovery
  docs served → public reachability → unauthenticated `/mcp` returns 401+challenge
  → full self-driven OAuth+token round-trip; emits targeted fixes), and
  `funnel-cmd` (prints the copy-paste `tailscale funnel --bg <port>` and a ready
  cloudflared `config.yml` — it's ~10 lines of string, no reason to defer).
- **M4 — Distribution.** `cargo-dist` → cross-compiled binaries (macOS arm64/x64,
  Linux arm64/x64 incl. the Pi) on GitHub Releases + a Homebrew tap + shell
  installer; publish to crates.io; `cargo-deb` → `.deb` on Releases. Four install
  paths: `brew`, `.deb`/`apt`, `cargo install`, raw binary.
- **M5 — Docs.** README, `docs/getting-started.md` (three deployment shapes:
  Tailscale Funnel [default], Cloudflare Tunnel, direct+TLS), `docs/troubleshooting.md`
  (seeded with the real failure modes from the handoff §8), SECURITY.md.

### Deferred (with the trigger to add them)

- **Built-in ACME TLS (`--tls-domain`).** Deferred, behind a cargo feature so the
  default binary stays lean. Tunnel/Funnel users get TLS for free; only
  direct-public-host deploys need it. Add when: someone actually wants to drop the
  tunnel.
- **`--spawn` (supervise upstream as child).** Deferred — process supervision is
  real complexity for a convenience. Add when: the two-process setup proves annoying.
- **`install-service` (systemd unit).** Deferred to a `doctor`-printed hint first;
  full unit-writing later. Add when: people are running it as a daemon and asking.

---

## 5. Configuration surface

Precedence: **flag > env > `doorman.toml` > default**. `init` writes the toml.
Keep the set tight — anything beyond this needs a strong justification.

| Key | Env | Default | Notes |
|---|---|---|---|
| issuer URL | `DOORMAN_ISSUER_URL` | — (required) | public base URL, no trailing slash |
| listen addr | `DOORMAN_BIND` | `127.0.0.1:8080` | |
| upstream URL | `DOORMAN_UPSTREAM_URL` | `http://127.0.0.1:3000` | |
| upstream path | `DOORMAN_UPSTREAM_PATH` | `/mcp` | for services exposing at a sub-path |
| upstream auth header | `DOORMAN_UPSTREAM_HEADER` | `Authorization` | e.g. `x-mcp-token`; `both` supported |
| upstream token | `DOORMAN_UPSTREAM_TOKEN` | — (optional) | omit for no-auth upstreams |
| client id / secret | `DOORMAN_CLIENT_ID` / `_SECRET` | — | pre-registered client |
| owner password | `DOORMAN_OWNER_PASSWORD` | — (presence required, empty allowed) | consent always prompts; there is **no** auto-approve bypass. Value may be length 0 (no complexity gate), but the var must be *present* — `run` refuses to start if it's entirely unset, so you never silently ship an empty gate. `init` suggests a generated strong password + an importance reminder. |
| allowed redirects | `DOORMAN_ALLOWED_REDIRECT_URIS` | Claude callback(s) | comma-sep exact allowlist |
| access / refresh TTL | `DOORMAN_ACCESS_TTL` / `_REFRESH_TTL` | 3600 / 60d | |
| signing key path | `DOORMAN_KEY_PATH` | `$STATE/signing_key.pem` | auto-gen if absent, 0600 |
| rate limit | `DOORMAN_RATE_LIMIT` | sane default | per-IP on auth endpoints |
| spawn upstream | `--spawn "<cmd>"` | off | *(deferred)* |
| TLS domain | `--tls-domain <host>` | off | *(deferred, cargo feature)* |

---

## 6. Testing

- **Security-critical unit/integration:** PKCE happy + tampered verifier;
  redirect allowlist enforced; token `aud`/`iss`/`exp`/signature validation;
  client auth (both `client_secret_post` and `client_secret_basic`) + bad secret;
  auth-code single-use + expiry; refresh grant + rejection of an access token used
  as a refresh token; owner-password path; rate-limit trips after N attempts.
- **End-to-end harness:** spin doorman against a stub upstream, drive
  discovery → authorize → token → authenticated proxy in-process, assert the stub
  received the **injected downstream header** and **not** Claude's token.
- **CI (GitHub Actions):** fmt, clippy (`-D warnings`), test, cross-build matrix;
  release job via cargo-dist on tags.

---

## 7. Security posture (non-negotiable checklist)

This guards real credentials. Label the project **beta** until externally
reviewed. Everything here is a hard requirement, not a "nice to have":

- PKCE S256 mandatory; reject `plain`. ✓ (seed)
- Exact-match redirect_uri allowlist; HTTPS-only except localhost for dev. ✓ (seed)
- Tokens bind `aud` to the resource, set `iss`, short access TTL, verify all on the RS path. ✓ (seed)
- Constant-time compare for owner password and client secret. ✓ (seed)
- Signing key 0600; document rotation. ✓ (seed) / doc in M5.
- **Rate-limit auth endpoints** (M1); cap auth-code TTL ≤120s + single-use. ✓/M1.
- Never log secrets, tokens, verifiers, or the owner password. — audit in M1.
- Never forward Claude's token upstream; always swap for the downstream credential. ✓ (seed)
- Request body size cap (M1).
- SECURITY.md with a disclosure contact (M5).

Log the incoming `redirect_uri` **on mismatch only** (not the successful one) so
the most common misconfig — a callback not in the allowlist — is trivial to
diagnose without leaking anything sensitive.

---

## 8. Decisions (resolved 2026-07-03)

1. **DCR — in v1.** No fallback-check gating; we build it (M1b).
2. **Built-in TLS — follow-up.** Deferred, cargo-feature-gated.
3. **Consent — always require the password step, no auto-approve.** No
   length/complexity gate (empty value permitted), but the var must be present.
   `init` suggests an autogenerated password and reminds the owner it's the only
   thing guarding the upstream credential.
4. **License — MIT/Apache-2.0 dual.** Confirmed.
5. **Public repo — after M1 is merged by Sebastiaan.** Repo starts **private**;
   build lands as stacked PRs that Sebastiaan merges; flip to public once M1 is in.
