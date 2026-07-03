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
}

impl Config {
    /// Resolve config with precedence env > doorman.toml > default.
    fn load() -> Config {
        let file = load_toml();
        let g = |k: &str| get_cfg(&file, k);
        let issuer = g("issuer_url")
            .expect("issuer URL required (DOORMAN_ISSUER_URL, or issuer_url in doorman.toml)")
            .trim_end_matches('/')
            .to_string();
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
            owner_password: get_cfg_present(&file, "owner_password").expect(
                "owner password required (DOORMAN_OWNER_PASSWORD, or owner_password in \
                 doorman.toml). An empty value is allowed, but it must be present.",
            ),
            allowed_redirects: g("allowed_redirect_uris")
                .unwrap_or_else(|| "https://claude.ai/api/mcp/auth_callback".into())
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            key_path: g("key_path").unwrap_or_else(|| "signing_key.pem".into()),
            clients_path: g("clients_path").unwrap_or_else(|| "clients.json".into()),
            access_ttl: g("access_ttl").and_then(|v| v.parse().ok()).unwrap_or(3600),
            refresh_ttl: g("refresh_ttl")
                .and_then(|v| v.parse().ok())
                .unwrap_or(60 * 60 * 24 * 60),
            code_ttl: g("code_ttl")
                .and_then(|v| v.parse().ok())
                .unwrap_or(120)
                .min(120),
            rate_limit: g("rate_limit").and_then(|v| v.parse().ok()).unwrap_or(30),
            issuer,
        }
    }
}

const CONFIG_FILE: &str = "doorman.toml";

fn load_toml() -> toml::Table {
    let path = std::env::var("DOORMAN_CONFIG").unwrap_or_else(|_| CONFIG_FILE.into());
    match std::fs::read_to_string(&path) {
        Ok(s) => s
            .parse()
            .unwrap_or_else(|e| panic!("{path} is present but not valid TOML: {e}")),
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
    let cmd = std::env::args().nth(1).unwrap_or_default();
    match cmd.as_str() {
        "run" => run().await,
        "init" => init(),
        "doctor" => doctor().await,
        "funnel-cmd" => funnel_cmd(),
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
         USAGE:\n  doorman <command>\n\n\
         COMMANDS:\n  \
         run          Start the gate (reads config from env / doorman.toml)\n  \
         init         Interactive setup: writes doorman.toml, prints connector values\n  \
         doctor       Diagnose upstream, discovery, reachability, and a full token round-trip\n  \
         funnel-cmd   Print the exact tunnel command to expose the gate\n  \
         --version    Print version\n",
        env!("CARGO_PKG_VERSION")
    );
}

async fn run() {
    let cfg = Config::load();
    let state = build_state(cfg);

    let listener = tokio::net::TcpListener::bind(&state.cfg.bind)
        .await
        .expect("bind");
    eprintln!(
        "doorman: issuer={} resource={} -> upstream={}{} listening on {}",
        state.cfg.issuer,
        state.cfg.resource,
        state.cfg.upstream,
        state.cfg.upstream_path,
        state.cfg.bind
    );
    let app = build_app(state).into_make_service_with_connect_info::<SocketAddr>();
    axum::serve(listener, app).await.expect("serve");
}

// ---------------------------------------------------------------------------
// init — interactive setup
// ---------------------------------------------------------------------------

fn init() {
    use std::io::Write;
    println!("doorman init — interactive setup\n");

    let issuer = prompt("Public issuer URL (e.g. https://pi.tailXXXX.ts.net)", None)
        .trim_end_matches('/')
        .to_string();
    let upstream = prompt("Upstream URL", Some("http://127.0.0.1:3000"));
    let upstream_path = prompt("Upstream MCP path", Some("/mcp"));
    let upstream_header = prompt(
        "Upstream auth header — Authorization | both | <custom name>",
        Some("Authorization"),
    );
    let upstream_token = prompt(
        "Upstream static token (blank if the upstream is open)",
        Some(""),
    );

    let generated = random_token(18);
    println!(
        "\n  The owner password gates every authorization. Anyone who has it can approve\n  \
         Claude's access to your upstream — treat it like the key to your house.\n"
    );
    let owner_password = prompt(
        &format!("Owner password [press Enter to use generated: {generated}]"),
        Some(&generated),
    );

    let client_id = random_token(16);
    let client_secret = random_token(32);

    let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    let mut toml = String::new();
    toml.push_str(&format!("issuer_url = \"{}\"\n", esc(&issuer)));
    toml.push_str(&format!("upstream_url = \"{}\"\n", esc(&upstream)));
    toml.push_str(&format!("upstream_path = \"{}\"\n", esc(&upstream_path)));
    toml.push_str(&format!(
        "upstream_header = \"{}\"\n",
        esc(&upstream_header)
    ));
    if !upstream_token.is_empty() {
        toml.push_str(&format!("upstream_token = \"{}\"\n", esc(&upstream_token)));
    }
    toml.push_str(&format!("client_id = \"{}\"\n", esc(&client_id)));
    toml.push_str(&format!("client_secret = \"{}\"\n", esc(&client_secret)));
    toml.push_str(&format!("owner_password = \"{}\"\n", esc(&owner_password)));

    if std::path::Path::new(CONFIG_FILE).exists() {
        let overwrite = prompt(
            &format!("{CONFIG_FILE} exists — overwrite? [y/N]"),
            Some("N"),
        );
        if !overwrite.eq_ignore_ascii_case("y") {
            println!("aborted; {CONFIG_FILE} left unchanged.");
            return;
        }
    }
    std::fs::write(CONFIG_FILE, &toml).expect("write doorman.toml");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Contains the owner password + client secret.
        let _ = std::fs::set_permissions(CONFIG_FILE, std::fs::Permissions::from_mode(0o600));
    }

    let _ = std::io::stdout().flush();
    println!("\nWrote {CONFIG_FILE} (0600).\n");
    println!("Add a custom connector in Claude with:");
    println!("  URL:            {issuer}/mcp");
    println!("  Client ID:      {client_id}");
    println!("  Client Secret:  {client_secret}");
    println!("\nWhen Claude sends you to the consent page, approve with the owner password:");
    println!("  {owner_password}");
    println!("\nNext:  doorman run     (then `doorman funnel-cmd` to expose it)");
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

async fn doctor() {
    let cfg = Config::load();
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("http client");
    let mut ok = true;
    println!("doorman doctor — checking {}\n", cfg.issuer);

    // 1. Upstream reachable.
    let upstream_url = format!("{}{}", cfg.upstream, cfg.upstream_path);
    match http.get(&upstream_url).send().await {
        Ok(_) => report(true, &format!("upstream reachable ({upstream_url})"), ""),
        Err(_) => {
            ok = false;
            report(
                false,
                &format!("upstream unreachable ({upstream_url})"),
                "start the upstream, or fix DOORMAN_UPSTREAM_URL / _PATH",
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
            "is `doorman run` up, and is the tunnel/DNS pointing at it? check DOORMAN_ISSUER_URL",
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

fn funnel_cmd() {
    let cfg = Config::load();
    let port = cfg.bind.rsplit(':').next().unwrap_or("8080");
    println!("Expose doorman (listening on {}) publicly:\n", cfg.bind);
    println!("Tailscale Funnel (no DNS, no open ports):");
    println!("  tailscale funnel --bg {port}\n");
    println!("Cloudflare Tunnel — add to your config.yml ingress:");
    println!("  ingress:");
    println!("    - hostname: <your-hostname>");
    println!("      service: http://{}", cfg.bind);
    println!("    - service: http_status:404");
    println!("  then: cloudflared tunnel run <tunnel-name>");
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
}
