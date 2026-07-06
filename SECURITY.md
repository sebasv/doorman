# Security

doorman issues and validates the OAuth tokens that gate access to your service,
and holds the upstream's real credential. Treat it accordingly. It is **beta**;
it has had an internal adversarial review but no external audit.

## Reporting a vulnerability

Report privately via GitHub's **[Security → Report a vulnerability](https://github.com/sebasv/doorman/security/advisories/new)**
(private advisory), not a public issue. I'll acknowledge and fix before any
public disclosure.

## Threat model

doorman is a **single-owner** gate. The owner password is the root of trust:
anyone who has it can approve a client to reach the upstream. Config (issuer,
upstream, spawn command, instance name) is owner-controlled, not
attacker-controlled. The relevant attacker is external — they can reach the
public endpoints but have neither the owner password nor local access.

## What's in place

- **PKCE S256 mandatory**; `plain` and empty challenges rejected.
- **RS256 pinned** on token validation — no `alg:none` / HS256 confusion; the
  JWKS public key can't be used to forge tokens.
- **Access tokens audience-bound** to doorman's own resource; `iss`, `aud`,
  `exp`, and signature verified on every proxied request. The audience is never
  taken from a client-supplied parameter.
- **Auth codes** are single-use, ≤120s, bound to the redirect and PKCE challenge.
- **Refresh tokens are bound to their client** — a client can't redeem another
  client's refresh token.
- **Exact-match redirect URIs** at `/authorize`; registered redirects must be
  HTTPS (localhost allowed for dev) and free of control characters.
- **Constant-time comparison** for the owner password and client secrets.
- **Confused-deputy safe** — Claude's `Authorization` is stripped and never
  forwarded; the upstream sees only doorman's configured credential.
- **Instance names are validated** (`[A-Za-z0-9_-]`, ≤64) — no path traversal or
  service/unit injection.
- **Secrets on disk are `0600`**, written atomically; secrets/tokens/PKCE
  verifiers/passwords are never logged.
- **Rate limiting** on `/authorize`, `/token`, `/register`; request body capped.
- The supervised upstream runs in its own process group and is terminated with
  it on shutdown.

## Known limitations

- **Auth-endpoint DoS.** Behind a Tailscale Funnel all traffic shares one source
  IP, so the per-IP rate limiter is effectively global: a sustained flood can
  keep `/authorize` / `/token` / `/register` returning 429, blocking *new*
  authorizations. It does **not** affect an already-connected session and leaks
  nothing.
- **Open dynamic registration** is capped (`MAX_CLIENTS`); a registration flood
  can fill the cap and block *new* DCR until `clients.json` is cleared. Existing
  clients keep working. Registration grants nothing on its own — the owner
  password still gates every token.
- **Refresh tokens are stateless and non-revocable** until they expire
  (`refresh_ttl`, default 60 days). To force re-authorization sooner, delete the
  signing key (invalidates all issued tokens) and restart.
- **An empty owner password is permitted** (must be explicitly set) — then anyone
  who reaches the consent page can approve. Don't, unless you mean to.

## Key rotation

Delete the signing key (default `~/.config/doorman/<name>/signing_key.pem`) and
restart. doorman generates a fresh RSA-2048 keypair and publishes new JWKS; all
previously issued tokens become invalid.
