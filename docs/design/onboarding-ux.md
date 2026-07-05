# Onboarding UX redesign — init, doctor, delete

Status: **proposal, for review.** No code yet.

The current `init` works but assumes you already know the jargon (issuer URL,
upstream, auth header) and that your MCP server is running and exposed. This
redesign targets a first-timer who just has *"an MCP server I want to use from
Claude"* and nothing set up.

## Goals

- **Beginner-first.** Explain each concept in one plain sentence before asking
  about it. Never ask for something we can figure out ourselves.
- **doorman owns the whole stack.** It runs your MCP server, gates it, and
  exposes it — one command, one thing to start.
- **Multiple services per machine.** Named instances, each independent.
- **Reversible.** A `delete` command that cleanly removes everything an instance
  created.

## Mental model (the three things doorman talks about)

| Term | One-line explanation shown to the user |
|---|---|
| **upstream** | "the MCP server you want Claude to use — the thing doorman guards" |
| **public address** | "a URL on the internet Claude can reach, because Claude runs in the cloud, not on your machine" |
| **owner password** | "the password you type to approve Claude — the key to your service" |

## The two insights that make it simple

1. **If doorman runs the upstream, there's no upstream auth to configure.** The
   upstream binds `127.0.0.1` and *only* doorman can reach it, so it doesn't need
   its own token — doorman is the gate. The entire "auth header / token" branch
   disappears for the common case. (We only ask about upstream auth when you
   point doorman at a service it does *not* run.)

2. **If Tailscale is present, doorman derives the public address itself.** It
   reads the tailnet name from `tailscale status --json` and sets up the Funnel,
   so the user never types or even sees an "issuer URL".

Net effect: the beginner path is *"what command starts your server?"* → *"pick a
password (or take the generated one)"* → done.

## Instances & on-disk layout

One machine can run several doormen (e.g. `picnic`, `n8n`). Each is a **named
instance** with its own config, keys, port, service, and funnel.

```
<root>/                     # ~/.config/doorman  (macOS/Linux) | %APPDATA%\doorman (Windows)
  picnic/
    config.toml             # 0600 — issuer, upstream, spawn cmd, secrets
    signing_key.pem         # 0600
    clients.json            # 0600 — DCR-registered clients
  n8n/
    config.toml
    ...
```

- Commands take an instance name: `doorman init [name]`, `run [name]`,
  `doctor [name]`, `delete [name]`, plus `doorman list`. Name defaults to
  `default` when omitted, so single-instance users never think about it.
- `DOORMAN_CONFIG` / env vars still override for Docker/advanced use.

### Ports & Funnel

Each instance gets its own local bind port and its own Tailscale Funnel port,
assigned at init to the next free slot:

| Instance | local bind | funnel port | issuer |
|---|---|---|---|
| 1st | 127.0.0.1:8080 | 443 | `https://host.tailXXXX.ts.net` |
| 2nd | 127.0.0.1:8081 | 8443 | `https://host.tailXXXX.ts.net:8443` |
| 3rd | 127.0.0.1:8082 | 10000 | `https://host.tailXXXX.ts.net:10000` |

Tailscale Funnel offers exactly these three ports per machine, so **3 funnelled
instances** is the built-in ceiling. Beyond that (or for a cleaner URL) is
path-based Funnel (`https://host/n8n`), which needs doorman to mount its routes
under a base path — deferred as a follow-up, noted here so the port scheme
doesn't box us in.

---

## `doorman init [name]` — flow

```
                       ┌─────────────────────────────────────────────┐
                       │ Welcome. Explain in 3 lines: doorman runs &  │
                       │ guards your MCP server and puts it on the    │
                       │ internet for Claude, behind a password.      │
                       │ You'll need: (a) your server, (b) Tailscale  │
                       │ for the public address (we'll help).         │
                       └───────────────────────┬─────────────────────┘
                                               │
        ┌──────────────────────────────────────▼─────────────────────────────┐
        │ STEP 1 — Your MCP server ("upstream": the service doorman guards")  │
        │ "Should doorman run it for you, or is it already running?"          │
        └───────────────┬───────────────────────────────────┬────────────────┘
             doorman runs it (recommended)          already running (advanced)
                         │                                   │
   ┌─────────────────────▼──────────────┐     ┌──────────────▼───────────────────┐
   │ "Command that starts your server?" │     │ "Upstream URL?" [127.0.0.1:3000]  │
   │   e.g. npx -y mcp-picnic ...        │     │ "MCP path?"      [/mcp]           │
   │ "Which port does it listen on?"[3000]     │ "Does it need an auth header/     │
   │ "MCP path?" [/mcp]                  │     │  token? Many don't." [n]          │
   │ → no token: only doorman can reach  │     │   if yes: header [Authorization], │
   │   it on localhost (explain)         │     │           token value            │
   └─────────────────────┬──────────────┘     └──────────────┬───────────────────┘
                         └─────────────────┬─────────────────┘
                                           │
        ┌───────────────────────────────────▼──────────────────────────────────┐
        │ STEP 2 — Public address. Explain: Claude is in the cloud, so it needs │
        │ a public HTTPS URL. Easiest is Tailscale Funnel (free, no port-       │
        │ forwarding). Check `tailscale`:                                       │
        └───────┬───────────────────────────┬───────────────────────┬──────────┘
         installed + up               not installed            installed, not up
                │                            │                        │
   ┌────────────▼───────────┐   ┌────────────▼─────────────┐   ┌──────▼───────────────┐
   │ read tailnet name via  │   │ "Install Tailscale now?" │   │ "Run `tailscale up`  │
   │ `tailscale status      │   │  Y → run install script  │   │  to log in, then      │
   │  --json`; pick funnel  │   │      (Linux) / print     │   │  re-run init."        │
   │  port; issuer derived  │   │      steps (mac/win),    │   │  (or fall to manual)  │
   │  automatically.        │   │      then `tailscale up` │   └──────────────────────┘
   │  "Expose at <URL>? [Y]"│   │  N → "Have your own      │
   └────────────┬───────────┘   │      public HTTPS addr?  │
                │               │      Enter it:" → issuer │
                │               └────────────┬─────────────┘
                └───────────────┬────────────┘
                                │
        ┌─────────────────────────▼───────────────────────────────────┐
        │ STEP 3 — Owner password. Explain it's the key to approve     │
        │ Claude. Offer a generated strong one (just press Enter).     │
        └─────────────────────────┬───────────────────────────────────┘
                                  │
        ┌─────────────────────────▼───────────────────────────────────┐
        │ WRITE: <root>/<name>/config.toml (0600), signing key, client │
        │ generate client id/secret.                                   │
        └─────────────────────────┬───────────────────────────────────┘
                                  │
        ┌─────────────────────────▼───────────────────────────────────┐
        │ STEP 4 — "Start on boot & keep running? [Y]" → install-service│
        │ (systemd --user / launchd / Windows task). This also starts  │
        │ doorman + the spawned upstream now.                          │
        └─────────────────────────┬───────────────────────────────────┘
                                  │
        ┌─────────────────────────▼───────────────────────────────────┐
        │ STEP 5 — If Tailscale path: bring the Funnel up now for the  │
        │ assigned port.                                               │
        └─────────────────────────┬───────────────────────────────────┘
                                  │
        ┌─────────────────────────▼───────────────────────────────────┐
        │ DONE. Print: connector URL (…/mcp), Client ID/Secret, owner  │
        │ password, and "verify with: doorman doctor <name>".          │
        └──────────────────────────────────────────────────────────────┘
```

Beginner happy path collapses to four answers: **run command → port → password
(Enter for generated) → yes to service.** Everything else is derived.

---

## `doorman doctor [name]` — flow

Same checks as today, but per-instance, with plain-language results and the
exact next command on any failure.

```
doorman doctor <name>
  │
  ├─ 1. Config for <name> exists?            ✗ → "run: doorman init <name>"
  ├─ 2. Service installed & active?          ✗ → "start it: doorman run <name>"
  │       (or child upstream process alive if spawned)
  ├─ 3. Upstream answering on its local port? ✗ → "your MCP server isn't up;
  │                                                check the run command"
  ├─ 4. Tailscale Funnel up for this port?   ✗ → "expose it: (funnel cmd)"
  ├─ 5. Discovery doc reachable at issuer?   ✗ → "public URL not reachable —
  │                                                tunnel/DNS? check issuer"
  ├─ 6. Unauthenticated /mcp → 401+challenge  ✗ → "URL must end in /mcp"
  ├─ 7. Full OAuth + token round-trip         ✗ → "check client/secret/password"
  │
  └─ SUMMARY: ✓/✗ per line; on all-green, print the connector URL to paste.
```

Isolation is the point: check 3 failing but 7 passing means "your server is
down, doorman is fine"; 5 failing means "the tunnel, not doorman."

---

## `doorman delete [name]` — flow

```
doorman delete <name>
  │
  ├─ Show what will be removed (service, funnel port, config dir) and CONFIRM.
  │     abort on anything but an explicit yes.
  │
  ├─ 1. Stop & remove the service
  │        systemd:  systemctl --user disable --now doorman-<name>
  │        launchd:  launchctl unload + rm the plist
  │        windows:  schtasks /delete /tn doorman-<name>
  │
  ├─ 2. Turn off ONLY this instance's funnel port
  │        tailscale funnel --https=<port> off      (never `funnel reset` —
  │        that would kill other instances' funnels)
  │
  ├─ 3. Remove <root>/<name>/  (config, signing key, clients.json)
  │
  └─ REPORT each removed item. Note: the connector still exists in Claude —
     remind the user to remove it there too.
```

`delete` never touches the spawned upstream's own install (e.g. it won't
`npm uninstall`), only what doorman created.

---

## `doorman list` (supporting)

```
doorman list
  NAME     STATUS    URL                                   UPSTREAM
  picnic   running   https://host.tailXXXX.ts.net/mcp      npx -y mcp-picnic … :3000
  n8n      stopped   https://host.tailXXXX.ts.net:8443/mcp http://127.0.0.1:5678
```

---

## What this changes in the code (impact)

- **`--spawn` becomes core**, not a deferred flag. `run` supervises the upstream
  child (restart on exit, terminate it on shutdown). Config gains `spawn_cmd`.
- **Config moves** from cwd `doorman.toml` to `<root>/<name>/config.toml`;
  commands gain an optional name arg; add `list` and `delete`. Env overrides stay.
- **Funnel/port assignment** logic (next free local port + funnel port), and
  reading the tailnet name from `tailscale status --json`.
- **install-service** (from PR #1) is reused, parameterized by instance name
  (`doorman-<name>` unit/label/task). PR #1's in-`init` Tailscale prompt gets
  folded into this richer Step 2.
- Discovery/token code is unchanged; only wiring and UX move.

## Open decisions (your call)

1. **Instance ceiling via Funnel ports (3) — acceptable for v1?** Recommend yes;
   path-based Funnel as a later follow-up if you want >3 or prettier URLs.
2. **Auto-install Tailscale** — run the official install script on Linux, but
   `tailscale up` needs interactive login you must do. OK to guide-then-wait,
   or should init stay hands-off and just link the docs?
3. **Config location** `~/.config/doorman/<name>/` — good, or prefer keeping a
   project-local `doorman.toml` option too?
4. **Default instance name `default`** when omitted — or require an explicit name
   to make multi-instance obvious from day one?
```
