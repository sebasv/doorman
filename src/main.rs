// doorman
// A single-binary OAuth 2.1 authorization server + resource-server reverse proxy.
//
// It sits in front of a static-token (or no-auth) HTTP service listening on 127.0.0.1
// and becomes the public OAuth face that claude.ai's custom-connector UI expects. It
// speaks the exact dance the connector requires (RFC 9728 protected-resource metadata,
// RFC 8414 AS metadata, PKCE/S256, audience-bound JWTs), and once a request carries a
// valid token it reverse-proxies to the upstream, injecting the upstream's own static
// credential itself so the upstream stays gated and Claude never sees it.
//
// Everything is driven by env vars — see Config::from_env below.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::{Body, Bytes},
    extract::{ConnectInfo, DefaultBodyLimit, Form, Query, Request, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{any, get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::RngCore;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Config {
    /// Public origin (e.g. the Funnel URL), no trailing slash, e.g. https://pi.tailXXXX.ts.net
    issuer: String,
    /// The canonical MCP resource URL = issuer + "/mcp". Tokens are audience-bound to this.
    resource: String,
    bind: String,
    /// Upstream base, e.g. http://127.0.0.1:3000
    upstream: String,
    /// Path on the upstream that the MCP endpoint is served at, e.g. "/mcp".
    upstream_path: String,
    /// Header the upstream expects its static credential in: "Authorization" (Bearer),
    /// a custom header name (raw value, e.g. "x-mcp-token"), or "both".
    upstream_header: String,
    /// Static credential the upstream expects; injected downstream. None ⇒ no-auth upstream.
    upstream_token: Option<String>,
    client_id: String,
    client_secret: String,
    owner_password: String,
    allowed_redirects: Vec<String>,
    key_path: String,
    /// Where DCR-registered clients are persisted (JSON, 0600) so they survive restart.
    clients_path: String,
    access_ttl: u64,
    refresh_ttl: u64,
    /// Lifetime of an authorization code in seconds (capped short; single-use anyway).
    code_ttl: u64,
    /// Max requests per IP per minute on /authorize and /token. 0 disables limiting.
    rate_limit: u32,
    /// Command doorman runs and supervises as the upstream (localhost). None ⇒ external upstream.
    spawn_cmd: Option<String>,
    /// Tailscale Funnel port this instance uses (443/8443/10000), if any — for doctor/delete.
    funnel_port: Option<u16>,
    /// Instance name (not stored in the toml; identifies paths, service, funnel).
    name: String,
}

impl Config {
    /// Resolve the named instance's config with precedence env > config.toml > default.
    fn load(name: &str) -> Config {
        let file = load_toml(name);
        let g = |k: &str| get_cfg(&file, k);
        let issuer = g("issuer_url")
            .unwrap_or_else(|| {
                panic!("issuer_url not set for instance '{name}'. Run: doorman init {name}")
            })
            .trim_end_matches('/')
            .to_string();
        let dir = instance_dir(name);
        let in_dir = |f: &str| dir.join(f).to_string_lossy().into_owned();
        Config {
            resource: format!("{issuer}/mcp"),
            bind: g("bind").unwrap_or_else(|| "127.0.0.1:8080".into()),
            upstream: g("upstream_url")
                .unwrap_or_else(|| "http://127.0.0.1:3000".into())
                .trim_end_matches('/')
                .to_string(),
            upstream_path: g("upstream_path").unwrap_or_else(|| "/mcp".into()),
            upstream_header: g("upstream_header").unwrap_or_else(|| "Authorization".into()),
            upstream_token: g("upstream_token"),
            client_id: g("client_id").unwrap_or_default(),
            client_secret: g("client_secret").unwrap_or_default(),
            // Presence required, empty value allowed (no complexity gate). An empty
            // password means anyone who reaches the consent page can approve — so we
            // refuse to start silently if it is not present at all.
            owner_password: get_cfg_present(&file, "owner_password").unwrap_or_else(|| {
                panic!("owner_password not set for '{name}'. Run: doorman init {name}")
            }),
            allowed_redirects: g("allowed_redirect_uris")
                .unwrap_or_else(|| "https://claude.ai/api/mcp/auth_callback".into())
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            key_path: g("key_path").unwrap_or_else(|| in_dir("signing_key.pem")),
            clients_path: g("clients_path").unwrap_or_else(|| in_dir("clients.json")),
            access_ttl: g("access_ttl").and_then(|v| v.parse().ok()).unwrap_or(3600),
            refresh_ttl: g("refresh_ttl")
                .and_then(|v| v.parse().ok())
                .unwrap_or(60 * 60 * 24 * 60),
            code_ttl: g("code_ttl")
                .and_then(|v| v.parse().ok())
                .unwrap_or(120)
                .min(120),
            rate_limit: g("rate_limit").and_then(|v| v.parse().ok()).unwrap_or(30),
            spawn_cmd: g("spawn_cmd"),
            funnel_port: g("funnel_port").and_then(|v| v.parse().ok()),
            issuer,
            name: name.to_string(),
        }
    }
}

/// Root config directory holding all instances.
fn root_dir() -> std::path::PathBuf {
    if cfg!(target_os = "windows") {
        let base = std::env::var("APPDATA").unwrap_or_else(|_| ".".into());
        std::path::Path::new(&base).join("doorman")
    } else {
        let base = std::env::var("XDG_CONFIG_HOME").unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            format!("{home}/.config")
        });
        std::path::Path::new(&base).join("doorman")
    }
}

fn instance_dir(name: &str) -> std::path::PathBuf {
    root_dir().join(name)
}

fn config_path(name: &str) -> std::path::PathBuf {
    instance_dir(name).join("config.toml")
}

fn load_toml(name: &str) -> toml::Table {
    let path = std::env::var("DOORMAN_CONFIG")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| config_path(name));
    match std::fs::read_to_string(&path) {
        Ok(s) => s
            .parse()
            .unwrap_or_else(|e| panic!("{} is present but not valid TOML: {e}", path.display())),
        Err(_) => toml::Table::new(),
    }
}

/// env DOORMAN_<UPPER> (non-empty) beats the toml key beats absent.
fn get_cfg(file: &toml::Table, key: &str) -> Option<String> {
    std::env::var(format!("DOORMAN_{}", key.to_uppercase()))
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| file.get(key).and_then(|v| v.as_str()).map(String::from))
}

/// Like get_cfg but treats an *empty* value as present (for owner_password).
fn get_cfg_present(file: &toml::Table, key: &str) -> Option<String> {
    std::env::var(format!("DOORMAN_{}", key.to_uppercase()))
        .ok()
        .or_else(|| file.get(key).and_then(|v| v.as_str()).map(String::from))
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

struct Inner {
    cfg: Config,
    enc: EncodingKey,
    dec: DecodingKey,
    jwk: serde_json::Value,
    codes: Mutex<HashMap<String, Code>>,
    /// Registered OAuth clients (DCR + the pre-registered env client), keyed by client_id.
    clients: Mutex<HashMap<String, Client>>,
    /// Per-IP fixed-window counters for the auth endpoints: ip -> (window_start, count).
    limits: Mutex<HashMap<IpAddr, (u64, u32)>>,
    http: reqwest::Client,
}
type AppState = Arc<Inner>;

/// Cap on stored clients — a backstop against a registration flood filling disk.
/// ponytail: fixed ceiling; rate-limiting already throttles /register.
const MAX_CLIENTS: usize = 1000;

#[derive(Clone, Serialize, Deserialize)]
struct Client {
    /// None ⇒ public client (PKCE-only, `token_endpoint_auth_method=none`).
    secret: Option<String>,
    redirect_uris: Vec<String>,
}

struct Code {
    challenge: String,
    redirect_uri: String,
    audience: String,
    exp: u64,
}

#[derive(Serialize, Deserialize)]
struct AccessClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: u64,
    iat: u64,
    scope: String,
    client_id: String,
}

#[derive(Serialize, Deserialize)]
struct RefreshClaims {
    iss: String,
    sub: String,
    aud: String, // = issuer, distinguishes refresh from access
    exp: u64,
    iat: u64,
    #[serde(rename = "use")]
    token_use: String,
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("");
    // Optional instance name is the 2nd positional arg; defaults to "default".
    let name = args
        .get(2)
        .map(String::as_str)
        .unwrap_or("default")
        .to_string();
    match cmd {
        "run" => run(&name).await,
        "init" => init(&name),
        "doctor" => doctor(&name).await,
        "delete" => delete(&name),
        "list" => list(),
        "funnel-cmd" => funnel_cmd(&name),
        "install-service" => install_service(&name),
        "--version" | "-V" => println!("doorman {}", env!("CARGO_PKG_VERSION")),
        "--help" | "-h" | "" => print_usage(),
        other => {
            eprintln!("doorman: unknown command '{other}'\n");
            print_usage();
            std::process::exit(2);
        }
    }
}

fn print_usage() {
    println!(
        "doorman {} — OAuth 2.1 gate + reverse proxy for MCP servers\n\n\
         USAGE:\n  doorman <command> [instance-name]      (instance defaults to \"default\")\n\n\
         COMMANDS:\n  \
         init [name]      Interactive setup for an instance; prints connector values\n  \
         run [name]       Start the instance (and supervise its upstream if configured)\n  \
         doctor [name]    Diagnose upstream, funnel, discovery, and a full token round-trip\n  \
         delete [name]    Stop & remove an instance (service, funnel, config)\n  \
         list             List configured instances and their status\n  \
         funnel-cmd [name]  Print the tunnel command to expose an instance\n  \
         install-service [name]  Register an instance to start on boot\n  \
         --version        Print version\n",
        env!("CARGO_PKG_VERSION")
    );
}

async fn run(name: &str) {
    let cfg = Config::load(name);
    // If configured, run the upstream as a supervised child on localhost.
    let _child = cfg.spawn_cmd.clone().map(spawn_supervised);

    let state = build_state(cfg);
    let listener = tokio::net::TcpListener::bind(&state.cfg.bind)
        .await
        .expect("bind");
    eprintln!(
        "doorman[{}]: issuer={} -> upstream={}{} listening on {}",
        state.cfg.name,
        state.cfg.issuer,
        state.cfg.upstream,
        state.cfg.upstream_path,
        state.cfg.bind
    );
    let app = build_app(state).into_make_service_with_connect_info::<SocketAddr>();
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("serve");
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

/// Handle for a supervised upstream child. Dropping it aborts the supervisor loop;
/// the running child is killed via `kill_on_drop`.
struct ChildGuard(tokio::task::JoinHandle<()>);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Spawn the upstream via the shell and keep it alive, restarting on exit.
/// ponytail: kill_on_drop kills the shell child on shutdown; under a service manager
/// (systemd/launchd) the whole process tree is reaped by the unit anyway. Process-group
/// kill is the upgrade path if orphaned grandchildren become a problem in foreground use.
fn spawn_supervised(cmd: String) -> ChildGuard {
    ChildGuard(tokio::spawn(async move {
        loop {
            let mut c = if cfg!(target_os = "windows") {
                let mut c = tokio::process::Command::new("cmd");
                c.arg("/C").arg(&cmd);
                c
            } else {
                let mut c = tokio::process::Command::new("sh");
                c.arg("-c").arg(&cmd);
                c
            };
            match c.kill_on_drop(true).spawn() {
                Ok(mut child) => {
                    eprintln!("doorman: started upstream: {cmd}");
                    let status = child.wait().await;
                    eprintln!("doorman: upstream exited ({status:?}); restarting in 2s");
                }
                Err(e) => {
                    eprintln!("doorman: could not start upstream `{cmd}`: {e}; retrying in 2s")
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    }))
}

// ---------------------------------------------------------------------------
// init — interactive setup
// ---------------------------------------------------------------------------

fn init(name: &str) {
    println!("doorman init — let's connect an MCP server to Claude (instance: {name})\n");
    println!("doorman runs your MCP server, guards it behind a password, and puts it on");
    println!("the internet so Claude can reach it. You'll need two things:");
    println!("  1. the MCP server you want to use ('upstream' — the service we gate)");
    println!(
        "  2. a public address (Claude runs in the cloud) — easiest via Tailscale, we'll help.\n"
    );

    if config_path(name).exists()
        && !ask_yes(
            &format!("Instance '{name}' already exists — overwrite it?"),
            false,
        )
    {
        println!("Aborted; '{name}' left unchanged.");
        return;
    }

    // --- Step 1: the upstream ---------------------------------------------------
    println!("\n── Your MCP server ──");
    let (bind_port, _f) = assign_ports(name);
    let mut cfg: Vec<(String, String)> = Vec::new();
    cfg.push(("bind".into(), format!("127.0.0.1:{bind_port}")));

    if ask_yes(
        "Should doorman run your MCP server for you? (recommended — you give the start command)",
        true,
    ) {
        let spawn_cmd = prompt(
            "  Command that starts your MCP server (e.g. npx -y mcp-picnic --enable-http --http-port 3000)",
            None,
        );
        let uport = prompt("  Which port does it listen on?", Some("3000"));
        let upath = prompt("  What path is the MCP endpoint on?", Some("/mcp"));
        println!("  → doorman will run it on localhost where only doorman can reach it, so no upstream token is needed.");
        cfg.push(("spawn_cmd".into(), spawn_cmd));
        cfg.push(("upstream_url".into(), format!("http://127.0.0.1:{uport}")));
        cfg.push(("upstream_path".into(), upath));
    } else {
        println!("  OK — point doorman at your already-running server.");
        let url = prompt("  Upstream URL", Some("http://127.0.0.1:3000"));
        let upath = prompt("  MCP path", Some("/mcp"));
        cfg.push(("upstream_url".into(), url));
        cfg.push(("upstream_path".into(), upath));
        if ask_yes(
            "  Does your upstream require an auth header/token to reach it? (many don't)",
            false,
        ) {
            let header = prompt(
                "    Header name — Authorization (Bearer) | both | <custom, e.g. x-mcp-token>",
                Some("Authorization"),
            );
            let token = prompt("    Token value", None);
            cfg.push(("upstream_header".into(), header));
            cfg.push(("upstream_token".into(), token));
        }
    }

    // --- Step 2: the public address --------------------------------------------
    println!("\n── Public address ──");
    println!("Claude is in the cloud, so it needs a public HTTPS URL for doorman.");
    let (issuer, funnel_port) = choose_public_address();
    cfg.push(("issuer_url".into(), issuer.clone()));
    if let Some(fp) = funnel_port {
        cfg.push(("funnel_port".into(), fp.to_string()));
    }

    // --- Step 3: owner password -------------------------------------------------
    println!("\n── Owner password ──");
    println!("This is the key to your service: anyone who has it can approve Claude's access.");
    let generated = random_token(18);
    let owner_password = prompt(
        &format!("Owner password [Enter to use generated: {generated}]"),
        Some(&generated),
    );

    // --- Write config -----------------------------------------------------------
    let client_id = random_token(16);
    let client_secret = random_token(32);
    cfg.push(("client_id".into(), client_id.clone()));
    cfg.push(("client_secret".into(), client_secret.clone()));
    cfg.push(("owner_password".into(), owner_password.clone()));
    write_config(name, &cfg);
    println!("\nWrote {} (0600).", config_path(name).display());

    println!("\nAdd a custom connector in Claude with:");
    println!("  URL:            {issuer}/mcp");
    println!("  Client ID:      {client_id}");
    println!("  Client Secret:  {client_secret}");
    println!("  Owner password: {owner_password}   (typed on the consent page)");

    // --- Step 4: run as a service ----------------------------------------------
    println!();
    let installed = ask_yes(
        "Keep doorman running in the background and start it on boot?",
        true,
    );
    if installed {
        install_service(name);
    }

    // --- Step 5: bring the funnel up -------------------------------------------
    if let Some(fp) = funnel_port {
        if ask_yes(
            &format!("Expose it now via Tailscale Funnel (port {fp})?"),
            true,
        ) {
            if run_cmd(
                "tailscale",
                &[
                    "funnel",
                    "--bg",
                    &format!("--https={fp}"),
                    &bind_port.to_string(),
                ],
            ) {
                println!("Funnel is up at {issuer}");
            } else {
                println!("Funnel didn't start — you may need to enable Funnel in the Tailscale admin console.");
            }
        }
    }

    if installed {
        println!(
            "\n✓ Done. doorman is running. Verify the whole path with:  doorman doctor {name}"
        );
    } else {
        println!("\n✓ Done. Start it with:  doorman run {name}");
    }
}

/// Decide the public HTTPS address: automate via Tailscale when possible, else ask.
/// Returns (issuer_url, funnel_port).
fn choose_public_address() -> (String, Option<u16>) {
    match tailscale_dnsname() {
        Some(dns) => {
            let fp = next_funnel_port();
            match fp {
                Some(fp) => {
                    let issuer = if fp == 443 {
                        format!("https://{dns}")
                    } else {
                        format!("https://{dns}:{fp}")
                    };
                    println!(
                        "Tailscale is set up. doorman will expose this instance at:\n  {issuer}"
                    );
                    (issuer, Some(fp))
                }
                None => {
                    println!("All 3 Tailscale Funnel ports are already in use by other instances.");
                    (ask_public_url(), None)
                }
            }
        }
        None if tailscale_present() => {
            println!("Tailscale is installed but not logged in. Run `tailscale up` to log in,");
            println!("then re-run `doorman init`. For now, enter your public address manually:");
            (ask_public_url(), None)
        }
        None => {
            println!("Tailscale isn't installed. It gives you a free public HTTPS address with no");
            println!("port-forwarding — the easiest option.");
            if ask_yes("Install Tailscale now?", true) {
                print_tailscale_install();
                println!("After installing and running `tailscale up`, re-run `doorman init`.");
            }
            println!("Or, if you already have a public HTTPS address for this machine:");
            (ask_public_url(), None)
        }
    }
}

fn ask_public_url() -> String {
    prompt(
        "  Public HTTPS URL for this machine (e.g. https://mcp.example.com)",
        None,
    )
    .trim_end_matches('/')
    .to_string()
}

fn print_tailscale_install() {
    if cfg!(target_os = "linux") {
        println!("  curl -fsSL https://tailscale.com/install.sh | sh && sudo tailscale up");
    } else if cfg!(target_os = "macos") {
        println!("  brew install tailscale && sudo tailscale up   (or install the Mac app)");
    } else {
        println!("  Install from https://tailscale.com/download, then run `tailscale up`.");
    }
}

/// Ask a yes/no question with a default; returns the boolean.
fn ask_yes(question: &str, default_yes: bool) -> bool {
    let hint = if default_yes { "[Y/n]" } else { "[y/N]" };
    let ans = prompt(
        &format!("{question} {hint}"),
        Some(if default_yes { "y" } else { "n" }),
    );
    ans.eq_ignore_ascii_case("y") || ans.eq_ignore_ascii_case("yes")
}

/// Write an instance's config.toml (0600), creating the instance dir.
fn write_config(name: &str, kv: &[(String, String)]) {
    let dir = instance_dir(name);
    std::fs::create_dir_all(&dir).expect("create instance dir");
    let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    let mut out = String::new();
    for (k, v) in kv {
        out.push_str(&format!("{k} = \"{}\"\n", esc(v)));
    }
    let path = config_path(name);
    std::fs::write(&path, out).expect("write config.toml");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
}

fn prompt(label: &str, default: Option<&str>) -> String {
    use std::io::Write;
    loop {
        print!("{label}: ");
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            std::process::exit(1);
        }
        let val = line.trim().to_string();
        if !val.is_empty() {
            return val;
        }
        match default {
            Some(d) => return d.to_string(),
            None => println!("  (required)"),
        }
    }
}

// ---------------------------------------------------------------------------
// doctor — end-to-end diagnostics
// ---------------------------------------------------------------------------

async fn doctor(name: &str) {
    if !config_path(name).exists() {
        eprintln!("No instance '{name}'. Run: doorman init {name}   (or `doorman list`)");
        std::process::exit(1);
    }
    let cfg = Config::load(name);
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("http client");
    let mut ok = true;
    println!("doorman doctor [{name}] — checking {}\n", cfg.issuer);

    // 0. Funnel: if this instance uses a Tailscale Funnel port, is it serving?
    if let Some(fp) = cfg.funnel_port {
        let funnel_ok = std::process::Command::new("tailscale")
            .args(["funnel", "status"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains(&fp.to_string()))
            .unwrap_or(false);
        if funnel_ok {
            report(true, &format!("Tailscale Funnel is serving port {fp}"), "");
        } else {
            ok = false;
            report(
                false,
                &format!("Tailscale Funnel not serving port {fp}"),
                &format!("bring it up: doorman funnel-cmd {name}"),
            );
        }
    }

    // 1. Upstream reachable (whether spawned by doorman or external).
    let upstream_url = format!("{}{}", cfg.upstream, cfg.upstream_path);
    match http.get(&upstream_url).send().await {
        Ok(_) => report(true, &format!("upstream reachable ({upstream_url})"), ""),
        Err(_) => {
            ok = false;
            let fix = if cfg.spawn_cmd.is_some() {
                "doorman couldn't reach the server it runs — check the spawn command and port in the config"
            } else {
                "start your MCP server, or fix upstream_url / upstream_path in the config"
            };
            report(
                false,
                &format!("upstream unreachable ({upstream_url})"),
                fix,
            );
        }
    }

    // 2. Discovery doc served over the public issuer URL.
    let prm_url = format!("{}/.well-known/oauth-protected-resource", cfg.issuer);
    let discovery_ok = match http.get(&prm_url).send().await {
        Ok(r) if r.status().is_success() => {
            let body: serde_json::Value = r.json().await.unwrap_or_default();
            body.get("resource").is_some()
        }
        _ => false,
    };
    if discovery_ok {
        report(
            true,
            "discovery document served + reachable over the public URL",
            "",
        );
    } else {
        ok = false;
        report(
            false,
            "discovery document not reachable at the public issuer URL",
            &format!(
                "is `doorman run {name}` up, and is the tunnel pointing at it? check issuer_url"
            ),
        );
    }

    // 3. Unauthenticated /mcp returns 401 + challenge.
    match http.get(format!("{}/mcp", cfg.issuer)).send().await {
        Ok(r) if r.status() == 401 && r.headers().contains_key("www-authenticate") => report(
            true,
            "unauthenticated /mcp returns 401 + WWW-Authenticate",
            "",
        ),
        Ok(r) => {
            ok = false;
            report(
                false,
                &format!(
                    "unauthenticated /mcp returned {} (expected 401)",
                    r.status()
                ),
                "the connector URL must end in /mcp; check the upstream isn't answering directly",
            );
        }
        Err(_) => {
            ok = false;
            report(
                false,
                "could not reach /mcp",
                "see the discovery check above",
            );
        }
    }

    // 4. Full self-driven OAuth + token round-trip (only if we have the client creds).
    if cfg.client_id.is_empty() {
        report(
            true,
            "skipping token round-trip (no pre-registered client_id configured)",
            "",
        );
    } else if roundtrip(&http, &cfg).await {
        report(true, "full OAuth + token round-trip succeeded", "");
    } else {
        ok = false;
        report(
            false,
            "OAuth + token round-trip failed",
            "check client_id/secret, owner_password, and allowed_redirect_uris",
        );
    }

    println!();
    if ok {
        println!("All checks passed.");
    } else {
        println!("Some checks failed — see the fixes above.");
        std::process::exit(1);
    }
}

fn report(ok: bool, msg: &str, fix: &str) {
    let mark = if ok { "\u{2713}" } else { "\u{2717}" };
    println!("  {mark} {msg}");
    if !ok && !fix.is_empty() {
        println!("      fix: {fix}");
    }
}

/// Drive authorize → token → authenticated /mcp against the live public URL.
async fn roundtrip(http: &reqwest::Client, cfg: &Config) -> bool {
    let redirect = match cfg.allowed_redirects.first() {
        Some(r) => r.clone(),
        None => return false,
    };
    let verifier = random_token(32);
    let challenge = sha256_b64url(verifier.as_bytes());

    let auth = http
        .post(format!("{}/authorize", cfg.issuer))
        .form(&[
            ("response_type", "code"),
            ("client_id", cfg.client_id.as_str()),
            ("redirect_uri", redirect.as_str()),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("password", cfg.owner_password.as_str()),
        ])
        .send()
        .await;
    let location = match auth {
        Ok(r) => r
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(String::from),
        Err(_) => None,
    };
    let code = match location.as_deref().and_then(|l| l.split_once('?')) {
        Some((_, q)) => q.split('&').find_map(|p| {
            let (k, v) = p.split_once('=')?;
            (k == "code").then(|| v.to_string())
        }),
        None => None,
    };
    let code = match code {
        Some(c) => c,
        None => return false,
    };

    let tok = http
        .post(format!("{}/token", cfg.issuer))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", redirect.as_str()),
            ("code_verifier", verifier.as_str()),
            ("client_id", cfg.client_id.as_str()),
            ("client_secret", cfg.client_secret.as_str()),
        ])
        .send()
        .await;
    let access = match tok {
        Ok(r) => {
            let body: serde_json::Value = r.json().await.unwrap_or_default();
            body.get("access_token")
                .and_then(|v| v.as_str())
                .map(String::from)
        }
        Err(_) => None,
    };
    let access = match access {
        Some(a) => a,
        None => return false,
    };

    matches!(
        http.post(format!("{}/mcp", cfg.issuer)).bearer_auth(&access).body("{}").send().await,
        Ok(r) if r.status() != 401
    )
}

// ---------------------------------------------------------------------------
// funnel-cmd — print the exact tunnel command
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// delete / list
// ---------------------------------------------------------------------------

fn delete(name: &str) {
    if !config_path(name).exists() {
        eprintln!("No instance '{name}'. `doorman list` shows configured instances.");
        std::process::exit(1);
    }
    // Read funnel_port tolerantly (don't require a complete config to delete).
    let funnel_port: Option<u16> = std::fs::read_to_string(config_path(name))
        .ok()
        .and_then(|s| s.parse::<toml::Table>().ok())
        .and_then(|t| {
            t.get("funnel_port")
                .and_then(|v| v.as_str())
                .and_then(|p| p.parse().ok())
        });

    if !ask_yes(
        &format!(
            "Delete '{name}' — stop its service, turn off its funnel, and remove {}? This can't be undone.",
            instance_dir(name).display()
        ),
        false,
    ) {
        println!("Aborted.");
        return;
    }

    remove_service(name);
    if let Some(fp) = funnel_port {
        run_cmd("tailscale", &["funnel", &format!("--https={fp}"), "off"]);
        println!("Turned off Tailscale Funnel port {fp}.");
    }
    match std::fs::remove_dir_all(instance_dir(name)) {
        Ok(_) => println!("Removed {}", instance_dir(name).display()),
        Err(e) => eprintln!("Could not remove {}: {e}", instance_dir(name).display()),
    }
    println!("\nDone. Remember to also remove the connector for '{name}' inside Claude.");
}

/// Stop and remove the instance's service, tolerating "not installed" quietly.
fn remove_service(name: &str) {
    use std::process::Stdio;
    // Best-effort: a not-installed service is fine, so swallow its complaints.
    let quiet = |cmd: &str, args: &[&str]| {
        let _ = std::process::Command::new(cmd)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    };
    let id = service_id(name);
    if cfg!(target_os = "linux") {
        let unit = format!("{id}.service");
        quiet("systemctl", &["--user", "disable", "--now", &unit]);
        if let Ok(home) = std::env::var("HOME") {
            let _ = std::fs::remove_file(format!("{home}/.config/systemd/user/{unit}"));
        }
        quiet("systemctl", &["--user", "daemon-reload"]);
    } else if cfg!(target_os = "macos") {
        if let Ok(home) = std::env::var("HOME") {
            let path = format!("{home}/Library/LaunchAgents/dev.{id}.plist");
            quiet("launchctl", &["unload", &path]);
            let _ = std::fs::remove_file(&path);
        }
    } else if cfg!(target_os = "windows") {
        quiet("schtasks", &["/delete", "/tn", &id, "/f"]);
    }
}

fn list() {
    use std::net::TcpStream;
    let names = instance_names();
    if names.is_empty() {
        println!("No instances yet. Create one with:  doorman init");
        return;
    }
    println!("{:<12} {:<9} {:<7} URL", "NAME", "STATUS", "FUNNEL");
    for n in &names {
        let t = std::fs::read_to_string(config_path(n))
            .ok()
            .and_then(|s| s.parse::<toml::Table>().ok())
            .unwrap_or_default();
        let get = |k: &str| t.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let issuer = get("issuer_url");
        let fp = t.get("funnel_port").and_then(|v| v.as_str()).unwrap_or("-");
        let status = get("bind")
            .parse::<SocketAddr>()
            .ok()
            .and_then(|a| {
                TcpStream::connect_timeout(&a, std::time::Duration::from_millis(200)).ok()
            })
            .map(|_| "running")
            .unwrap_or("stopped");
        println!("{n:<12} {status:<9} {fp:<7} {issuer}/mcp");
    }
}

fn funnel_cmd(name: &str) {
    let cfg = Config::load(name);
    let port = cfg.bind.rsplit(':').next().unwrap_or("8080");
    let fp = cfg.funnel_port.unwrap_or(443);
    println!(
        "Expose '{}' (listening on {}) publicly:\n",
        cfg.name, cfg.bind
    );
    println!("Tailscale Funnel (no DNS, no open ports):");
    println!("  tailscale funnel --bg --https={fp} {port}\n");
    println!("Cloudflare Tunnel — add to your config.yml ingress:");
    println!("  ingress:");
    println!("    - hostname: <your-hostname>");
    println!("      service: http://{}", cfg.bind);
    println!("    - service: http_status:404");
    println!("  then: cloudflared tunnel run <tunnel-name>");
}

// ---------------------------------------------------------------------------
// Instances, ports, Tailscale
// ---------------------------------------------------------------------------

/// Names of all configured instances (dirs under the root that contain a config.toml).
fn instance_names() -> Vec<String> {
    let mut names = Vec::new();
    if let Ok(rd) = std::fs::read_dir(root_dir()) {
        for e in rd.flatten() {
            if e.path().join("config.toml").exists() {
                names.push(e.file_name().to_string_lossy().into_owned());
            }
        }
    }
    names.sort();
    names
}

/// Bind ports and funnel ports already claimed by other instances.
fn used_ports(exclude: &str) -> (Vec<u16>, Vec<u16>) {
    let (mut binds, mut funnels) = (Vec::new(), Vec::new());
    for n in instance_names() {
        if n == exclude {
            continue;
        }
        if let Ok(s) = std::fs::read_to_string(config_path(&n)) {
            if let Ok(t) = s.parse::<toml::Table>() {
                if let Some(p) = t
                    .get("bind")
                    .and_then(|v| v.as_str())
                    .and_then(|b| b.rsplit(':').next())
                    .and_then(|p| p.parse().ok())
                {
                    binds.push(p);
                }
                if let Some(f) = t
                    .get("funnel_port")
                    .and_then(|v| v.as_str())
                    .and_then(|p| p.parse().ok())
                {
                    funnels.push(f);
                }
            }
        }
    }
    (binds, funnels)
}

/// Pick the next free local bind port (from 8080) and note funnel ports already taken.
fn assign_ports(name: &str) -> (u16, Vec<u16>) {
    let (binds, funnels) = used_ports(name);
    (next_free_bind(&binds), funnels)
}

fn next_free_bind(used: &[u16]) -> u16 {
    let mut port = 8080u16;
    while used.contains(&port) {
        port += 1;
    }
    port
}

/// The next free Tailscale Funnel port, in Tailscale's fixed set. None if all 3 are taken.
fn next_funnel_port() -> Option<u16> {
    let (_binds, funnels) = used_ports("");
    next_free_funnel(&funnels)
}

fn next_free_funnel(used: &[u16]) -> Option<u16> {
    [443u16, 8443, 10000]
        .into_iter()
        .find(|p| !used.contains(p))
}

/// The machine's tailnet DNS name, if Tailscale is up and logged in.
fn tailscale_dnsname() -> Option<String> {
    let out = std::process::Command::new("tailscale")
        .args(["status", "--json"])
        .output()
        .ok()?;
    out.status.success().then_some(())?;
    parse_tailscale_dnsname(&out.stdout)
}

/// Extract `Self.DNSName` (trailing dot stripped) from `tailscale status --json` output.
fn parse_tailscale_dnsname(stdout: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(stdout).ok()?;
    let dns = v
        .get("Self")?
        .get("DNSName")?
        .as_str()?
        .trim_end_matches('.');
    (!dns.is_empty()).then(|| dns.to_string())
}

/// Whether the `tailscale` binary is installed (regardless of login state).
fn tailscale_present() -> bool {
    use std::process::Stdio;
    std::process::Command::new("tailscale")
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// install-service — register doorman to start on boot, per platform
// ---------------------------------------------------------------------------

fn install_service(name: &str) {
    let exe = match std::env::current_exe() {
        Ok(p) => p.display().to_string(),
        Err(e) => {
            eprintln!("doorman: could not find own executable path: {e}");
            return;
        }
    };
    let workdir = instance_dir(name).display().to_string();

    if cfg!(target_os = "linux") {
        install_systemd(&exe, &workdir, name);
    } else if cfg!(target_os = "macos") {
        install_launchd(&exe, &workdir, name);
    } else if cfg!(target_os = "windows") {
        print_windows_service(&exe, &workdir, name);
    } else {
        println!("Automatic service install isn't supported on this OS. Run `doorman run {name}` under your process manager.");
    }
}

/// systemd/launchd/Windows identifier for an instance's service.
fn service_id(name: &str) -> String {
    format!("doorman-{name}")
}

fn install_systemd(exe: &str, workdir: &str, name: &str) {
    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => {
            eprintln!("doorman: HOME is not set; cannot place a user unit");
            return;
        }
    };
    let unit = format!("{}.service", service_id(name));
    let dir = format!("{home}/.config/systemd/user");
    let path = format!("{dir}/{unit}");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("doorman: could not create {dir}: {e}");
        return;
    }
    if let Err(e) = std::fs::write(&path, systemd_unit(exe, workdir, name)) {
        eprintln!("doorman: could not write {path}: {e}");
        return;
    }
    println!("Wrote {path}");
    run_cmd("systemctl", &["--user", "daemon-reload"]);
    run_cmd("systemctl", &["--user", "enable", "--now", &unit]);
    println!("Enabled the {unit} user service.");
    println!("To keep it running while you're logged out (e.g. a headless Pi), run once:");
    println!("  sudo loginctl enable-linger \"$USER\"");
}

fn install_launchd(exe: &str, workdir: &str, name: &str) {
    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => {
            eprintln!("doorman: HOME is not set; cannot place a LaunchAgent");
            return;
        }
    };
    let label = format!("dev.{}", service_id(name));
    let dir = format!("{home}/Library/LaunchAgents");
    let path = format!("{dir}/{label}.plist");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("doorman: could not create {dir}: {e}");
        return;
    }
    if let Err(e) = std::fs::write(&path, launchd_plist(exe, workdir, &label, name)) {
        eprintln!("doorman: could not write {path}: {e}");
        return;
    }
    println!("Wrote {path}");
    // Reload cleanly: unload if it was already loaded, then load.
    let _ = std::process::Command::new("launchctl")
        .args(["unload", &path])
        .status();
    run_cmd("launchctl", &["load", "-w", &path]);
    println!("Loaded the {label} LaunchAgent.");
}

fn print_windows_service(exe: &str, workdir: &str, name: &str) {
    let task = service_id(name);
    println!("On Windows, register a logon task (run in an elevated prompt):");
    println!("  schtasks /create /tn {task} /sc onlogon /rl highest \\");
    println!("    /tr \"cmd /c cd /d \\\"{workdir}\\\" && \\\"{exe}\\\" run {name}\"");
    println!("\nOr use a service wrapper (nssm / WinSW) pointing at:");
    println!("  \"{exe}\" run {name}   (working directory: {workdir})");
}

/// Run a command inheriting stdio; returns whether it succeeded.
fn run_cmd(cmd: &str, args: &[&str]) -> bool {
    match std::process::Command::new(cmd).args(args).status() {
        Ok(s) if s.success() => true,
        Ok(s) => {
            eprintln!("  `{cmd} {}` exited with {s}", args.join(" "));
            false
        }
        Err(e) => {
            eprintln!("  could not run `{cmd}`: {e}");
            false
        }
    }
}

fn systemd_unit(exe: &str, workdir: &str, name: &str) -> String {
    format!(
        "[Unit]\n\
         Description=doorman OAuth gate ({name})\n\
         After=network-online.target\n\
         Wants=network-online.target\n\n\
         [Service]\n\
         ExecStart={exe} run {name}\n\
         WorkingDirectory={workdir}\n\
         Restart=on-failure\n\
         RestartSec=2\n\n\
         [Install]\n\
         WantedBy=default.target\n"
    )
}

fn launchd_plist(exe: &str, workdir: &str, label: &str, name: &str) -> String {
    let x = |s: &str| {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{label}</string>
  <key>ProgramArguments</key>
  <array><string>{exe}</string><string>run</string><string>{name}</string></array>
  <key>WorkingDirectory</key><string>{workdir}</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
"#,
        exe = x(exe),
        workdir = x(workdir),
        name = x(name),
    )
}

fn build_state(cfg: Config) -> AppState {
    let (enc, dec, jwk) = load_or_make_key(&cfg.key_path);
    let mut clients = load_clients(&cfg.clients_path);
    // Seed the pre-registered env client so it works alongside DCR-registered ones.
    if !cfg.client_id.is_empty() {
        clients.insert(
            cfg.client_id.clone(),
            Client {
                secret: Some(cfg.client_secret.clone()),
                redirect_uris: cfg.allowed_redirects.clone(),
            },
        );
    }
    Arc::new(Inner {
        http: reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("http client"),
        enc,
        dec,
        jwk,
        codes: Mutex::new(HashMap::new()),
        clients: Mutex::new(clients),
        limits: Mutex::new(HashMap::new()),
        cfg,
    })
}

fn load_clients(path: &str) -> HashMap<String, Client> {
    match std::fs::read_to_string(path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_else(|e| {
            panic!("clients file {path} is present but unparseable: {e} — fix or remove it")
        }),
        Err(_) => HashMap::new(),
    }
}

/// Write-through persistence for the client registry. Best-effort: a failed write is
/// logged, not fatal — the in-memory registry is still authoritative for this run.
fn save_clients(path: &str, clients: &HashMap<String, Client>) {
    match serde_json::to_string_pretty(clients) {
        Ok(json) => {
            if let Err(e) = std::fs::write(path, json) {
                eprintln!("doorman: warning: could not persist clients to {path}: {e}");
                return;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            }
        }
        Err(e) => eprintln!("doorman: warning: could not serialize clients: {e}"),
    }
}

fn build_app(state: AppState) -> Router {
    // Rate limiting applies only to the brute-forceable auth endpoints.
    let limited = Router::new()
        .route("/authorize", get(authorize_get).post(authorize_post))
        .route("/token", post(token))
        .route("/register", post(register))
        .route_layer(middleware::from_fn_with_state(state.clone(), rate_limit));

    Router::new()
        .route("/.well-known/oauth-protected-resource", get(prm))
        .route("/.well-known/oauth-protected-resource/mcp", get(prm))
        .route("/.well-known/oauth-authorization-server", get(as_meta))
        .route("/.well-known/jwks.json", get(jwks))
        .merge(limited)
        .route("/health", get(|| async { "ok" }))
        .route("/mcp", any(proxy))
        .fallback(any(proxy))
        // Cap request bodies. MCP JSON-RPC is small; this bounds a token-holding client.
        .layer(DefaultBodyLimit::max(4 * 1024 * 1024))
        .with_state(state)
}

/// Per-IP fixed-window rate limit on the auth endpoints, keyed by the socket peer
/// address (not a spoofable forwarded header). Behind a tunnel this is effectively a
/// global limit on the tunnel's IP, which is the intended brute-force protection.
async fn rate_limit(
    State(s): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    if s.cfg.rate_limit > 0 {
        let ip = addr.ip();
        let now = now();
        let mut m = s.limits.lock().unwrap();
        m.retain(|_, (start, _)| now.saturating_sub(*start) < 60);
        let e = m.entry(ip).or_insert((now, 0));
        if now.saturating_sub(e.0) >= 60 {
            *e = (now, 0);
        }
        e.1 += 1;
        if e.1 > s.cfg.rate_limit {
            return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
        }
    }
    next.run(req).await
}

// ---------------------------------------------------------------------------
// Discovery documents
// ---------------------------------------------------------------------------

async fn prm(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({
        "resource": s.cfg.resource,
        "authorization_servers": [s.cfg.issuer],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["mcp"],
        "mcp_protocol_version": "2025-06-18",
        "resource_type": "mcp-server"
    }))
}

async fn as_meta(State(s): State<AppState>) -> Json<serde_json::Value> {
    let i = &s.cfg.issuer;
    Json(json!({
        "issuer": i,
        "authorization_endpoint": format!("{i}/authorize"),
        "token_endpoint": format!("{i}/token"),
        "registration_endpoint": format!("{i}/register"),
        "jwks_uri": format!("{i}/.well-known/jwks.json"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "scopes_supported": ["mcp"]
    }))
}

async fn jwks(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({ "keys": [ s.jwk.clone() ] }))
}

// ---------------------------------------------------------------------------
// Dynamic client registration (RFC 7591)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct RegisterReq {
    redirect_uris: Option<Vec<String>>,
    token_endpoint_auth_method: Option<String>,
}

/// Open registration. This is safe because registering a client grants nothing on its
/// own: the owner-password consent still gates every token, and redirect_uris are
/// validated exactly. Registration is rate-limited and capped (MAX_CLIENTS).
async fn register(State(s): State<AppState>, Json(r): Json<RegisterReq>) -> Response {
    let redirect_uris = match r.redirect_uris {
        Some(u) if !u.is_empty() => u,
        _ => return oauth_err(StatusCode::BAD_REQUEST, "invalid_redirect_uri"),
    };
    if !redirect_uris.iter().all(|u| is_valid_redirect(u)) {
        return oauth_err(StatusCode::BAD_REQUEST, "invalid_redirect_uri");
    }

    let public = r.token_endpoint_auth_method.as_deref() == Some("none");
    let client_id = random_token(24);
    let secret = (!public).then(|| random_token(32));

    {
        let mut clients = s.clients.lock().unwrap();
        if clients.len() >= MAX_CLIENTS {
            return oauth_err(StatusCode::TOO_MANY_REQUESTS, "too_many_registrations");
        }
        clients.insert(
            client_id.clone(),
            Client {
                secret: secret.clone(),
                redirect_uris: redirect_uris.clone(),
            },
        );
        save_clients(&s.cfg.clients_path, &clients);
    }

    let mut body = json!({
        "client_id": client_id,
        "client_id_issued_at": now(),
        "redirect_uris": redirect_uris,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": if public { "none" } else { "client_secret_basic" },
    });
    if let Some(sec) = secret {
        body["client_secret"] = json!(sec);
        body["client_secret_expires_at"] = json!(0); // never expires
    }
    (StatusCode::CREATED, Json(body)).into_response()
}

/// Registered redirect URIs must be HTTPS (or localhost for dev) — never a scheme like
/// javascript: or an arbitrary custom scheme.
fn is_valid_redirect(u: &str) -> bool {
    u.starts_with("https://")
        || u.starts_with("http://localhost")
        || u.starts_with("http://127.0.0.1")
}

// ---------------------------------------------------------------------------
// Authorization endpoint
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct AuthReq {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    state: Option<String>,
    #[allow(dead_code)]
    scope: Option<String>,
    resource: Option<String>,
}

async fn authorize_get(State(s): State<AppState>, Query(q): Query<AuthReq>) -> Response {
    if let Err(e) = validate_auth_req(&s, &q) {
        return (StatusCode::BAD_REQUEST, e).into_response();
    }
    let hidden = |name: &str, val: &Option<String>| -> String {
        match val {
            Some(v) => format!(
                r#"<input type="hidden" name="{}" value="{}">"#,
                name,
                html_escape(v)
            ),
            None => String::new(),
        }
    };
    let form = format!(
        r#"<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize access</title>
<style>body{{font-family:system-ui;max-width:22rem;margin:4rem auto;padding:0 1rem}}
input[type=password]{{width:100%;padding:.6rem;font-size:1rem;box-sizing:border-box}}
button{{margin-top:1rem;width:100%;padding:.6rem;font-size:1rem}}</style></head>
<body><h2>Authorize access</h2>
<p>An application is requesting access to your service through doorman.</p>
<form method="post" action="/authorize">
{rt}{cid}{ru}{cc}{ccm}{st}{res}
<label>Owner password<br><input type="password" name="password" autofocus></label>
<button type="submit">Approve</button>
</form></body></html>"#,
        rt = hidden("response_type", &q.response_type),
        cid = hidden("client_id", &q.client_id),
        ru = hidden("redirect_uri", &q.redirect_uri),
        cc = hidden("code_challenge", &q.code_challenge),
        ccm = hidden("code_challenge_method", &q.code_challenge_method),
        st = hidden("state", &q.state),
        res = hidden("resource", &q.resource),
    );
    Html(form).into_response()
}

#[derive(Deserialize)]
struct AuthPost {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    state: Option<String>,
    resource: Option<String>,
    password: Option<String>,
}

async fn authorize_post(State(s): State<AppState>, Form(f): Form<AuthPost>) -> Response {
    let q = AuthReq {
        response_type: f.response_type,
        client_id: f.client_id,
        redirect_uri: f.redirect_uri.clone(),
        code_challenge: f.code_challenge.clone(),
        code_challenge_method: f.code_challenge_method,
        state: f.state.clone(),
        scope: None,
        resource: f.resource.clone(),
    };
    if let Err(e) = validate_auth_req(&s, &q) {
        return (StatusCode::BAD_REQUEST, e).into_response();
    }
    // Owner gate: constant-time password check.
    let ok = f
        .password
        .as_deref()
        .map(|p| p.as_bytes().ct_eq(s.cfg.owner_password.as_bytes()).into())
        .unwrap_or(false);
    if !ok {
        return (StatusCode::UNAUTHORIZED, "bad password").into_response();
    }

    let redirect_uri = q.redirect_uri.unwrap();
    // Audience is pinned to our own resource — never taken from the client-supplied
    // `resource` param, so a token can only ever be minted for the endpoint we guard.
    let audience = s.cfg.resource.clone();
    let code = random_token(32);
    {
        let mut codes = s.codes.lock().unwrap();
        // Prune expired-but-never-redeemed codes so the map can't grow unbounded.
        let now = now();
        codes.retain(|_, c| c.exp >= now);
        codes.insert(
            code.clone(),
            Code {
                challenge: q.code_challenge.unwrap(),
                redirect_uri: redirect_uri.clone(),
                audience,
                exp: now + s.cfg.code_ttl,
            },
        );
    }

    let mut url = format!("{redirect_uri}?code={code}");
    if let Some(st) = q.state {
        url.push_str(&format!("&state={}", urlencode(&st)));
    }
    Redirect::to(&url).into_response()
}

fn validate_auth_req(s: &AppState, q: &AuthReq) -> Result<(), &'static str> {
    if q.response_type.as_deref() != Some("code") {
        return Err("unsupported response_type");
    }
    let client_id = q.client_id.as_deref().ok_or("unknown client_id")?;
    let clients = s.clients.lock().unwrap();
    let client = clients.get(client_id).ok_or("unknown client_id")?;
    if q.code_challenge_method.as_deref() != Some("S256") {
        return Err("code_challenge_method must be S256");
    }
    if q.code_challenge
        .as_deref()
        .map(|c| c.is_empty())
        .unwrap_or(true)
    {
        return Err("missing code_challenge");
    }
    match &q.redirect_uri {
        // redirect_uri must exactly match one the client registered.
        Some(ru) if client.redirect_uris.iter().any(|a| a == ru) => {}
        // Log the offending redirect_uri (it is not a secret) so the most common
        // misconfig — a callback the client never registered — is trivial to diagnose.
        Some(ru) => {
            eprintln!("doorman: rejected redirect_uri not registered for client: {ru}");
            return Err("redirect_uri not allowed");
        }
        None => return Err("missing redirect_uri"),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Token endpoint
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct TokenReq {
    grant_type: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    #[allow(dead_code)]
    resource: Option<String>,
}

async fn token(State(s): State<AppState>, headers: HeaderMap, Form(t): Form<TokenReq>) -> Response {
    // Client authentication: Basic header or POST body.
    let (cid, csec) = match basic_auth(&headers) {
        Some(pair) => pair,
        None => (
            t.client_id.clone().unwrap_or_default(),
            t.client_secret.clone().unwrap_or_default(),
        ),
    };
    let authed = {
        let clients = s.clients.lock().unwrap();
        match clients.get(&cid) {
            None => false,
            // Public client (PKCE-only): no secret to verify; the code grant's PKCE
            // check is the protection. Confidential client: constant-time secret compare.
            Some(c) => match &c.secret {
                None => true,
                Some(sec) => csec.as_bytes().ct_eq(sec.as_bytes()).into(),
            },
        }
    };
    if !authed {
        return oauth_err(StatusCode::UNAUTHORIZED, "invalid_client");
    }

    match t.grant_type.as_deref() {
        Some("authorization_code") => {
            let code = match t.code {
                Some(c) => c,
                None => return oauth_err(StatusCode::BAD_REQUEST, "invalid_request"),
            };
            let entry = s.codes.lock().unwrap().remove(&code);
            let entry = match entry {
                Some(e) if e.exp >= now() => e,
                _ => return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant"),
            };
            if t.redirect_uri.as_deref() != Some(entry.redirect_uri.as_str()) {
                return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant");
            }
            // PKCE: S256(verifier) must equal stored challenge.
            let verifier = t.code_verifier.unwrap_or_default();
            if sha256_b64url(verifier.as_bytes()) != entry.challenge {
                return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant");
            }
            issue_tokens(&s, &entry.audience, &cid)
        }
        Some("refresh_token") => {
            let rt = t.refresh_token.unwrap_or_default();
            let mut v = Validation::new(Algorithm::RS256);
            v.set_issuer(std::slice::from_ref(&s.cfg.issuer));
            v.set_audience(std::slice::from_ref(&s.cfg.issuer));
            match decode::<RefreshClaims>(&rt, &s.dec, &v) {
                Ok(data) if data.claims.token_use == "refresh" => {
                    issue_tokens(&s, &s.cfg.resource.clone(), &cid)
                }
                _ => oauth_err(StatusCode::BAD_REQUEST, "invalid_grant"),
            }
        }
        _ => oauth_err(StatusCode::BAD_REQUEST, "unsupported_grant_type"),
    }
}

fn issue_tokens(s: &AppState, audience: &str, client_id: &str) -> Response {
    let iat = now();
    let access = AccessClaims {
        iss: s.cfg.issuer.clone(),
        sub: "owner".into(),
        aud: audience.to_string(),
        exp: iat + s.cfg.access_ttl,
        iat,
        scope: "mcp".into(),
        client_id: client_id.to_string(),
    };
    let refresh = RefreshClaims {
        iss: s.cfg.issuer.clone(),
        sub: "owner".into(),
        aud: s.cfg.issuer.clone(),
        exp: iat + s.cfg.refresh_ttl,
        iat,
        token_use: "refresh".into(),
    };
    let hdr = Header::new(Algorithm::RS256);
    let access_token = encode(&hdr, &access, &s.enc).expect("sign access");
    let refresh_token = encode(&hdr, &refresh, &s.enc).expect("sign refresh");
    Json(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": s.cfg.access_ttl,
        "refresh_token": refresh_token,
        "scope": "mcp"
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// Protected reverse proxy
// ---------------------------------------------------------------------------

async fn proxy(
    State(s): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // 1. Require a valid, audience-bound access token.
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string());

    let token = match bearer {
        Some(t) => t,
        None => return unauthorized(&s),
    };
    let mut v = Validation::new(Algorithm::RS256);
    v.set_issuer(std::slice::from_ref(&s.cfg.issuer));
    v.set_audience(std::slice::from_ref(&s.cfg.resource));
    if decode::<AccessClaims>(&token, &s.dec, &v).is_err() {
        return unauthorized(&s);
    }

    // 2. Forward to the upstream, injecting the downstream credential.
    // ponytail: doorman fronts a single MCP endpoint, so every request is routed to
    // the configured upstream path (carrying the query string) rather than mirroring
    // arbitrary sub-paths. Fine for MCP-over-HTTP; revisit if a multi-route upstream shows up.
    let query = uri.query().map(|q| format!("?{q}")).unwrap_or_default();
    let url = format!("{}{}{}", s.cfg.upstream, s.cfg.upstream_path, query);

    let mut req = s.http.request(method, &url);
    // Copy client headers except hop-by-hop / auth / host / length.
    for (name, value) in headers.iter() {
        if is_skipped_request_header(name) {
            continue;
        }
        req = req.header(name.as_str(), value.as_bytes());
    }
    // The upstream never sees Claude's token, only its own configured credential.
    if let Some(tok) = &s.cfg.upstream_token {
        let h = s.cfg.upstream_header.as_str();
        if h.eq_ignore_ascii_case("both") {
            req = req.header("x-mcp-token", tok);
            req = req.header(header::AUTHORIZATION, format!("Bearer {tok}"));
        } else if h.eq_ignore_ascii_case("authorization") {
            req = req.header(header::AUTHORIZATION, format!("Bearer {tok}"));
        } else {
            req = req.header(h, tok);
        }
    }
    req = req.body(body);

    let upstream = match req.send().await {
        Ok(r) => r,
        Err(_) => {
            return (StatusCode::BAD_GATEWAY, "upstream unreachable").into_response();
        }
    };

    // 3. Stream the response back verbatim (works for SSE / streamable HTTP).
    let status = upstream.status();
    let mut out = Response::builder().status(status);
    for (name, value) in upstream.headers().iter() {
        if is_skipped_response_header(name) {
            continue;
        }
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(name.as_ref()),
            HeaderValue::from_bytes(value.as_bytes()),
        ) {
            out = out.header(n, v);
        }
    }
    out.body(Body::from_stream(upstream.bytes_stream()))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn unauthorized(s: &AppState) -> Response {
    let prm_url = format!("{}/.well-known/oauth-protected-resource", s.cfg.issuer);
    let mut resp = (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "invalid_token"})),
    )
        .into_response();
    resp.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_str(&format!(
            "Bearer resource_metadata=\"{prm_url}\", error=\"invalid_token\""
        ))
        .unwrap(),
    );
    resp
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

fn sha256_b64url(input: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(input);
    URL_SAFE_NO_PAD.encode(h.finalize())
}

fn basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let b64 = raw.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    let s = String::from_utf8(decoded).ok()?;
    let (u, p) = s.split_once(':')?;
    Some((urldecode(u), urldecode(p)))
}

fn oauth_err(status: StatusCode, code: &str) -> Response {
    (status, Json(json!({ "error": code }))).into_response()
}

fn is_skipped_request_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "authorization" | "host" | "content-length" | "connection" | "proxy-authorization"
    )
}

fn is_skipped_response_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "transfer-encoding" | "content-length" | "connection"
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

fn urldecode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(v);
                    i += 3;
                    continue;
                }
                out.push(bytes[i]);
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------------------
// Key management: load an RSA key from disk, or generate + persist one.
// ---------------------------------------------------------------------------

fn load_or_make_key(path: &str) -> (EncodingKey, DecodingKey, serde_json::Value) {
    let pem = match std::fs::read_to_string(path) {
        Ok(p) => p,
        Err(_) => {
            eprintln!("no signing key at {path}, generating a fresh RSA-2048 key");
            let mut rng = rand::thread_rng();
            let key = RsaPrivateKey::new(&mut rng, 2048).expect("generate key");
            let pem = key
                .to_pkcs8_pem(LineEnding::LF)
                .expect("encode key")
                .to_string();
            std::fs::write(path, &pem).expect("write key");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            }
            pem
        }
    };

    let priv_key = RsaPrivateKey::from_pkcs8_pem(&pem).expect("parse key");
    let pub_key = RsaPublicKey::from(&priv_key);
    let n = URL_SAFE_NO_PAD.encode(pub_key.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(pub_key.e().to_bytes_be());

    let enc = EncodingKey::from_rsa_pem(pem.as_bytes()).expect("encoding key");
    let dec = DecodingKey::from_rsa_components(&n, &e).expect("decoding key");
    let jwk = json!({
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": "doorman-1",
        "n": n,
        "e": e
    });
    (enc, dec, jwk)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const REDIRECT: &str = "https://claude.ai/api/mcp/auth_callback";

    fn test_cfg(upstream: &str) -> Config {
        let tag = random_token(8);
        let tmp = |ext: &str| {
            let mut p = std::env::temp_dir();
            p.push(format!("doorman-test-{tag}.{ext}"));
            p.to_string_lossy().into_owned()
        };
        Config {
            issuer: "https://test.doorman".into(),
            resource: "https://test.doorman/mcp".into(),
            bind: "127.0.0.1:0".into(),
            upstream: upstream.to_string(),
            upstream_path: "/mcp".into(),
            upstream_header: "both".into(),
            upstream_token: Some("upstream-secret".into()),
            client_id: "cid".into(),
            client_secret: "csec".into(),
            owner_password: "hunter2".into(),
            allowed_redirects: vec![REDIRECT.into()],
            key_path: tmp("pem"),
            clients_path: tmp("clients.json"),
            access_ttl: 3600,
            refresh_ttl: 3600,
            code_ttl: 120,
            rate_limit: 0,
            spawn_cmd: None,
            funnel_port: None,
            name: "test".into(),
        }
    }

    async fn spawn_doorman(cfg: Config) -> String {
        let state = build_state(cfg);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let app = build_app(state).into_make_service_with_connect_info::<SocketAddr>();
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    /// Stub upstream that records the headers of the last request it received.
    async fn spawn_stub() -> (String, Arc<Mutex<Option<HeaderMap>>>) {
        let cap: Arc<Mutex<Option<HeaderMap>>> = Arc::new(Mutex::new(None));
        let c2 = cap.clone();
        let app = Router::new().fallback(any(move |headers: HeaderMap, _b: Bytes| {
            let c = c2.clone();
            async move {
                *c.lock().unwrap() = Some(headers);
                "upstream-ok"
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}"), cap)
    }

    fn client() -> reqwest::Client {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
    }

    fn pkce() -> (String, String) {
        let verifier = random_token(32);
        let challenge = sha256_b64url(verifier.as_bytes());
        (verifier, challenge)
    }

    fn qp(url: &str, key: &str) -> Option<String> {
        let q = url.split_once('?')?.1;
        q.split('&').find_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            (k == key).then(|| v.to_string())
        })
    }

    /// Drive /authorize with the given password + challenge, return the auth code.
    async fn get_code(
        c: &reqwest::Client,
        base: &str,
        challenge: &str,
        password: &str,
    ) -> Response2 {
        let resp = c
            .post(format!("{base}/authorize"))
            .form(&[
                ("response_type", "code"),
                ("client_id", "cid"),
                ("redirect_uri", REDIRECT),
                ("code_challenge", challenge),
                ("code_challenge_method", "S256"),
                ("state", "xyz"),
                ("password", password),
            ])
            .send()
            .await
            .unwrap();
        let status = resp.status();
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        Response2 { status, location }
    }

    struct Response2 {
        status: reqwest::StatusCode,
        location: Option<String>,
    }

    /// Register a client via DCR; returns the parsed registration response.
    async fn dcr_register(
        c: &reqwest::Client,
        base: &str,
        auth_method: Option<&str>,
    ) -> serde_json::Value {
        let mut body = json!({ "redirect_uris": [REDIRECT] });
        if let Some(m) = auth_method {
            body["token_endpoint_auth_method"] = json!(m);
        }
        let resp = c
            .post(format!("{base}/register"))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201);
        resp.json().await.unwrap()
    }

    /// Drive /authorize for an arbitrary client_id, returning the auth code.
    async fn code_for(c: &reqwest::Client, base: &str, client_id: &str, challenge: &str) -> String {
        let resp = c
            .post(format!("{base}/authorize"))
            .form(&[
                ("response_type", "code"),
                ("client_id", client_id),
                ("redirect_uri", REDIRECT),
                ("code_challenge", challenge),
                ("code_challenge_method", "S256"),
                ("password", "hunter2"),
            ])
            .send()
            .await
            .unwrap();
        let loc = resp
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        qp(&loc, "code").unwrap()
    }

    #[tokio::test]
    async fn discovery_docs_advertise_endpoints() {
        let base = spawn_doorman(test_cfg("http://127.0.0.1:1")).await;
        let c = client();
        let prm: serde_json::Value = c
            .get(format!("{base}/.well-known/oauth-protected-resource"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(prm["resource"], "https://test.doorman/mcp");
        assert_eq!(prm["authorization_servers"][0], "https://test.doorman");

        let asm: serde_json::Value = c
            .get(format!("{base}/.well-known/oauth-authorization-server"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(asm["code_challenge_methods_supported"][0], "S256");
        assert_eq!(asm["token_endpoint"], "https://test.doorman/token");
    }

    #[tokio::test]
    async fn happy_path_injects_downstream_credential_and_hides_claude_token() {
        let (stub, cap) = spawn_stub().await;
        let base = spawn_doorman(test_cfg(&stub)).await;
        let c = client();
        let (verifier, challenge) = pkce();

        let code = get_code(&c, &base, &challenge, "hunter2").await;
        assert!(code.status.is_redirection());
        let code = qp(code.location.as_ref().unwrap(), "code").unwrap();

        let tok: serde_json::Value = c
            .post(format!("{base}/token"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", REDIRECT),
                ("code_verifier", &verifier),
                ("client_id", "cid"),
                ("client_secret", "csec"),
            ])
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let access = tok["access_token"].as_str().unwrap().to_string();
        assert_eq!(tok["token_type"], "Bearer");

        let resp = c
            .post(format!("{base}/mcp"))
            .bearer_auth(&access)
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        let seen = cap.lock().unwrap().clone().unwrap();
        // Upstream received the injected downstream credential (both header forms)...
        assert_eq!(seen.get("x-mcp-token").unwrap(), "upstream-secret");
        assert_eq!(seen.get("authorization").unwrap(), "Bearer upstream-secret");
        // ...and never Claude's access token.
        assert!(!seen
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap()
            .contains(&access));
    }

    #[tokio::test]
    async fn wrong_password_is_rejected() {
        let base = spawn_doorman(test_cfg("http://127.0.0.1:1")).await;
        let (_v, challenge) = pkce();
        let r = get_code(&client(), &base, &challenge, "wrong").await;
        assert_eq!(r.status, 401);
    }

    #[tokio::test]
    async fn tampered_pkce_verifier_is_rejected() {
        let base = spawn_doorman(test_cfg("http://127.0.0.1:1")).await;
        let c = client();
        let (_verifier, challenge) = pkce();
        let code = get_code(&c, &base, &challenge, "hunter2").await;
        let code = qp(code.location.as_ref().unwrap(), "code").unwrap();

        let resp = c
            .post(format!("{base}/token"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", REDIRECT),
                ("code_verifier", "not-the-verifier"),
                ("client_id", "cid"),
                ("client_secret", "csec"),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400);
    }

    #[tokio::test]
    async fn redirect_uri_not_in_allowlist_is_rejected() {
        let base = spawn_doorman(test_cfg("http://127.0.0.1:1")).await;
        let (_v, challenge) = pkce();
        let resp = client()
            .post(format!("{base}/authorize"))
            .form(&[
                ("response_type", "code"),
                ("client_id", "cid"),
                ("redirect_uri", "https://evil.example/callback"),
                ("code_challenge", &challenge),
                ("code_challenge_method", "S256"),
                ("password", "hunter2"),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400);
    }

    #[tokio::test]
    async fn plain_pkce_method_is_rejected() {
        let base = spawn_doorman(test_cfg("http://127.0.0.1:1")).await;
        let resp = client()
            .post(format!("{base}/authorize"))
            .form(&[
                ("response_type", "code"),
                ("client_id", "cid"),
                ("redirect_uri", REDIRECT),
                ("code_challenge", "abc"),
                ("code_challenge_method", "plain"),
                ("password", "hunter2"),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400);
    }

    #[tokio::test]
    async fn bad_client_secret_is_rejected() {
        let base = spawn_doorman(test_cfg("http://127.0.0.1:1")).await;
        let c = client();
        let (verifier, challenge) = pkce();
        let code = get_code(&c, &base, &challenge, "hunter2").await;
        let code = qp(code.location.as_ref().unwrap(), "code").unwrap();

        let resp = c
            .post(format!("{base}/token"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", REDIRECT),
                ("code_verifier", &verifier),
                ("client_id", "cid"),
                ("client_secret", "wrong"),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
    }

    #[tokio::test]
    async fn client_auth_via_basic_header_works() {
        let (stub, _cap) = spawn_stub().await;
        let base = spawn_doorman(test_cfg(&stub)).await;
        let c = client();
        let (verifier, challenge) = pkce();
        let code = get_code(&c, &base, &challenge, "hunter2").await;
        let code = qp(code.location.as_ref().unwrap(), "code").unwrap();

        let resp = c
            .post(format!("{base}/token"))
            .basic_auth("cid", Some("csec"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", REDIRECT),
                ("code_verifier", &verifier),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn authorization_code_is_single_use() {
        let (stub, _cap) = spawn_stub().await;
        let base = spawn_doorman(test_cfg(&stub)).await;
        let c = client();
        let (verifier, challenge) = pkce();
        let code = get_code(&c, &base, &challenge, "hunter2").await;
        let code = qp(code.location.as_ref().unwrap(), "code").unwrap();
        let form = [
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT),
            ("code_verifier", &verifier),
            ("client_id", "cid"),
            ("client_secret", "csec"),
        ];
        let first = c
            .post(format!("{base}/token"))
            .form(&form)
            .send()
            .await
            .unwrap();
        assert_eq!(first.status(), 200);
        let second = c
            .post(format!("{base}/token"))
            .form(&form)
            .send()
            .await
            .unwrap();
        assert_eq!(second.status(), 400);
    }

    #[tokio::test]
    async fn expired_authorization_code_is_rejected() {
        let mut cfg = test_cfg("http://127.0.0.1:1");
        cfg.code_ttl = 1;
        let base = spawn_doorman(cfg).await;
        let c = client();
        let (verifier, challenge) = pkce();
        let code = get_code(&c, &base, &challenge, "hunter2").await;
        let code = qp(code.location.as_ref().unwrap(), "code").unwrap();

        // TTL is 1s but now() has whole-second resolution and the check is `>=`, so wait
        // past 2s to guarantee the code's exp second is strictly behind the current second.
        tokio::time::sleep(std::time::Duration::from_millis(2100)).await;

        let resp = c
            .post(format!("{base}/token"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", REDIRECT),
                ("code_verifier", &verifier),
                ("client_id", "cid"),
                ("client_secret", "csec"),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400);
    }

    #[tokio::test]
    async fn refresh_grant_works_but_access_token_is_not_a_refresh_token() {
        let (stub, _cap) = spawn_stub().await;
        let base = spawn_doorman(test_cfg(&stub)).await;
        let c = client();
        let (verifier, challenge) = pkce();
        let code = get_code(&c, &base, &challenge, "hunter2").await;
        let code = qp(code.location.as_ref().unwrap(), "code").unwrap();
        let tok: serde_json::Value = c
            .post(format!("{base}/token"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", REDIRECT),
                ("code_verifier", &verifier),
                ("client_id", "cid"),
                ("client_secret", "csec"),
            ])
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let access = tok["access_token"].as_str().unwrap().to_string();
        let refresh = tok["refresh_token"].as_str().unwrap().to_string();

        // A real refresh succeeds.
        let ok = c
            .post(format!("{base}/token"))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh),
                ("client_id", "cid"),
                ("client_secret", "csec"),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(ok.status(), 200);

        // An access token presented as a refresh token is rejected.
        let bad = c
            .post(format!("{base}/token"))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &access),
                ("client_id", "cid"),
                ("client_secret", "csec"),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(bad.status(), 400);
    }

    #[tokio::test]
    async fn unauthenticated_proxy_returns_401_with_challenge() {
        let base = spawn_doorman(test_cfg("http://127.0.0.1:1")).await;
        let resp = client().get(format!("{base}/mcp")).send().await.unwrap();
        assert_eq!(resp.status(), 401);
        let wa = resp
            .headers()
            .get("www-authenticate")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(wa.contains("resource_metadata="));
    }

    #[tokio::test]
    async fn auth_endpoint_is_rate_limited() {
        let mut cfg = test_cfg("http://127.0.0.1:1");
        cfg.rate_limit = 3;
        let base = spawn_doorman(cfg).await;
        let c = client();
        // First 3 requests pass the limiter (they fail auth, but not with 429).
        for _ in 0..3 {
            let r = c
                .post(format!("{base}/token"))
                .form(&[("grant_type", "authorization_code"), ("client_id", "cid")])
                .send()
                .await
                .unwrap();
            assert_ne!(r.status(), 429);
        }
        // The 4th trips the limit.
        let r = c
            .post(format!("{base}/token"))
            .form(&[("grant_type", "authorization_code"), ("client_id", "cid")])
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 429);
    }

    #[tokio::test]
    async fn dcr_confidential_client_can_complete_the_flow() {
        let (stub, _cap) = spawn_stub().await;
        let base = spawn_doorman(test_cfg(&stub)).await;
        let c = client();
        let reg = dcr_register(&c, &base, None).await;
        let client_id = reg["client_id"].as_str().unwrap().to_string();
        let client_secret = reg["client_secret"].as_str().unwrap().to_string();

        let (verifier, challenge) = pkce();
        let code = code_for(&c, &base, &client_id, &challenge).await;
        let resp = c
            .post(format!("{base}/token"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", REDIRECT),
                ("code_verifier", &verifier),
                ("client_id", &client_id),
                ("client_secret", &client_secret),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn dcr_public_client_needs_no_secret() {
        let (stub, _cap) = spawn_stub().await;
        let base = spawn_doorman(test_cfg(&stub)).await;
        let c = client();
        let reg = dcr_register(&c, &base, Some("none")).await;
        assert!(reg.get("client_secret").is_none());
        let client_id = reg["client_id"].as_str().unwrap().to_string();

        let (verifier, challenge) = pkce();
        let code = code_for(&c, &base, &client_id, &challenge).await;
        let resp = c
            .post(format!("{base}/token"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", REDIRECT),
                ("code_verifier", &verifier),
                ("client_id", &client_id),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn dcr_rejects_non_https_redirect() {
        let base = spawn_doorman(test_cfg("http://127.0.0.1:1")).await;
        let resp = client()
            .post(format!("{base}/register"))
            .json(&json!({ "redirect_uris": ["http://evil.example/cb"] }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400);
    }

    #[tokio::test]
    async fn dcr_client_is_bound_to_its_registered_redirect() {
        let base = spawn_doorman(test_cfg("http://127.0.0.1:1")).await;
        let c = client();
        let reg = dcr_register(&c, &base, None).await;
        let client_id = reg["client_id"].as_str().unwrap().to_string();
        let (_v, challenge) = pkce();
        // Authorize with a redirect the client never registered.
        let resp = c
            .post(format!("{base}/authorize"))
            .form(&[
                ("response_type", "code"),
                ("client_id", client_id.as_str()),
                ("redirect_uri", "https://claude.ai/other/callback"),
                ("code_challenge", challenge.as_str()),
                ("code_challenge_method", "S256"),
                ("password", "hunter2"),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400);
    }

    #[tokio::test]
    async fn dcr_registered_client_survives_restart() {
        let cfg = test_cfg("http://127.0.0.1:1");
        let clients_path = cfg.clients_path.clone();
        let base = spawn_doorman(cfg.clone()).await;
        let reg = dcr_register(&client(), &base, None).await;
        let client_id = reg["client_id"].as_str().unwrap().to_string();

        // A fresh instance pointed at the same clients file must know the client.
        let base2 = spawn_doorman(cfg).await;
        assert!(std::path::Path::new(&clients_path).exists());
        let (_v, challenge) = pkce();
        let code = code_for(&client(), &base2, &client_id, &challenge).await;
        assert!(!code.is_empty());
    }

    #[tokio::test]
    async fn doctor_roundtrip_succeeds_against_live_server() {
        let (stub, _cap) = spawn_stub().await;
        let cfg = test_cfg(&stub);
        let mut dcfg = cfg.clone();
        let base = spawn_doorman(cfg).await;
        dcfg.issuer = base; // point the round-trip at the live ephemeral server
        assert!(roundtrip(&client(), &dcfg).await);
    }

    #[tokio::test]
    async fn doctor_roundtrip_fails_with_wrong_password() {
        let cfg = test_cfg("http://127.0.0.1:1");
        let mut dcfg = cfg.clone();
        let base = spawn_doorman(cfg).await;
        dcfg.issuer = base;
        dcfg.owner_password = "wrong".into();
        assert!(!roundtrip(&client(), &dcfg).await);
    }

    #[test]
    fn systemd_unit_runs_the_binary_from_the_workdir() {
        let u = systemd_unit("/usr/bin/doorman", "/var/lib/doorman", "picnic");
        assert!(u.contains("ExecStart=/usr/bin/doorman run picnic"));
        assert!(u.contains("WorkingDirectory=/var/lib/doorman"));
        assert!(u.contains("Restart=on-failure"));
        assert!(u.contains("[Install]"));
    }

    #[test]
    fn launchd_plist_is_well_formed_and_xml_escaped() {
        let p = launchd_plist(
            "/opt/doorman & co/doorman",
            "/home/me",
            "dev.doorman-n8n",
            "n8n",
        );
        assert!(p.contains("<key>Label</key><string>dev.doorman-n8n</string>"));
        assert!(p.contains("<string>run</string><string>n8n</string>"));
        assert!(p.contains("<key>RunAtLoad</key><true/>"));
        // the & in the path must be escaped for valid XML
        assert!(p.contains("/opt/doorman &amp; co/doorman"));
        assert!(!p.contains("doorman & co"));
    }

    #[test]
    fn bind_port_picks_the_next_free_slot() {
        assert_eq!(next_free_bind(&[]), 8080);
        assert_eq!(next_free_bind(&[8080]), 8081);
        assert_eq!(next_free_bind(&[8080, 8081, 8083]), 8082);
    }

    #[test]
    fn funnel_ports_follow_tailscales_fixed_set_and_run_out() {
        assert_eq!(next_free_funnel(&[]), Some(443));
        assert_eq!(next_free_funnel(&[443]), Some(8443));
        assert_eq!(next_free_funnel(&[443, 8443]), Some(10000));
        assert_eq!(next_free_funnel(&[443, 8443, 10000]), None);
    }

    #[test]
    fn parses_tailnet_name_and_strips_trailing_dot() {
        let json = br#"{"Self":{"DNSName":"pi.tailXXXX.ts.net."}}"#;
        assert_eq!(
            parse_tailscale_dnsname(json).as_deref(),
            Some("pi.tailXXXX.ts.net")
        );
        assert_eq!(parse_tailscale_dnsname(b"{}"), None);
        assert_eq!(parse_tailscale_dnsname(b"not json"), None);
    }
}
