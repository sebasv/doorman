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
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::{Body, Bytes},
    extract::{Form, Query, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri},
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
    access_ttl: u64,
    refresh_ttl: u64,
}

impl Config {
    fn from_env() -> Config {
        let issuer = env("DOORMAN_ISSUER_URL").trim_end_matches('/').to_string();
        Config {
            resource: format!("{issuer}/mcp"),
            bind: opt("DOORMAN_BIND").unwrap_or_else(|| "127.0.0.1:8080".into()),
            upstream: opt("DOORMAN_UPSTREAM_URL")
                .unwrap_or_else(|| "http://127.0.0.1:3000".into())
                .trim_end_matches('/')
                .to_string(),
            upstream_path: opt("DOORMAN_UPSTREAM_PATH").unwrap_or_else(|| "/mcp".into()),
            upstream_header: opt("DOORMAN_UPSTREAM_HEADER")
                .unwrap_or_else(|| "Authorization".into()),
            upstream_token: opt("DOORMAN_UPSTREAM_TOKEN"),
            client_id: env("DOORMAN_CLIENT_ID"),
            client_secret: env("DOORMAN_CLIENT_SECRET"),
            // Presence required, empty value allowed (no complexity gate). An empty
            // password means anyone who reaches the consent page can approve — the
            // missing-var panic below refuses to start silently in that state.
            owner_password: env_owner_password(),
            allowed_redirects: opt("DOORMAN_ALLOWED_REDIRECT_URIS")
                .unwrap_or_else(|| "https://claude.ai/api/mcp/auth_callback".into())
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            key_path: opt("DOORMAN_KEY_PATH").unwrap_or_else(|| "signing_key.pem".into()),
            access_ttl: envn("DOORMAN_ACCESS_TTL", 3600),
            refresh_ttl: envn("DOORMAN_REFRESH_TTL", 60 * 60 * 24 * 60),
            issuer,
        }
    }
}

fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| panic!("missing required env var {k}"))
}
fn opt(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.is_empty())
}
fn envn(k: &str, default: u64) -> u64 {
    std::env::var(k)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
fn env_owner_password() -> String {
    std::env::var("DOORMAN_OWNER_PASSWORD").unwrap_or_else(|_| {
        panic!(
            "missing required env var DOORMAN_OWNER_PASSWORD — set it to gate the consent page. \
             An empty value is allowed (DOORMAN_OWNER_PASSWORD=\"\") but then anyone who reaches \
             the authorize page can approve access, so only do that deliberately."
        )
    })
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
    http: reqwest::Client,
}
type AppState = Arc<Inner>;

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
    let cfg = Config::from_env();
    let (enc, dec, jwk) = load_or_make_key(&cfg.key_path);

    let state: AppState = Arc::new(Inner {
        http: reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("http client"),
        enc,
        dec,
        jwk,
        codes: Mutex::new(HashMap::new()),
        cfg,
    });

    let app = Router::new()
        .route("/.well-known/oauth-protected-resource", get(prm))
        .route("/.well-known/oauth-protected-resource/mcp", get(prm))
        .route("/.well-known/oauth-authorization-server", get(as_meta))
        .route("/.well-known/jwks.json", get(jwks))
        .route("/authorize", get(authorize_get).post(authorize_post))
        .route("/token", post(token))
        .route("/health", get(|| async { "ok" }))
        .route("/mcp", any(proxy))
        .fallback(any(proxy))
        .with_state(state.clone());

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
    axum::serve(listener, app).await.expect("serve");
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
    s.codes.lock().unwrap().insert(
        code.clone(),
        Code {
            challenge: q.code_challenge.unwrap(),
            redirect_uri: redirect_uri.clone(),
            audience,
            exp: now() + 120,
        },
    );

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
    if q.client_id.as_deref() != Some(s.cfg.client_id.as_str()) {
        return Err("unknown client_id");
    }
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
        Some(ru) if s.cfg.allowed_redirects.iter().any(|a| a == ru) => {}
        // Log the offending redirect_uri (it is not a secret) so the most common
        // misconfig — a callback not in the allowlist — is trivial to diagnose.
        Some(ru) => {
            eprintln!("doorman: rejected redirect_uri not in allowlist: {ru}");
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
    let client_ok: bool = cid.as_bytes().ct_eq(s.cfg.client_id.as_bytes()).into();
    let secret_ok: bool = csec.as_bytes().ct_eq(s.cfg.client_secret.as_bytes()).into();
    if !(client_ok && secret_ok) {
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
            issue_tokens(&s, &entry.audience)
        }
        Some("refresh_token") => {
            let rt = t.refresh_token.unwrap_or_default();
            let mut v = Validation::new(Algorithm::RS256);
            v.set_issuer(std::slice::from_ref(&s.cfg.issuer));
            v.set_audience(std::slice::from_ref(&s.cfg.issuer));
            match decode::<RefreshClaims>(&rt, &s.dec, &v) {
                Ok(data) if data.claims.token_use == "refresh" => {
                    issue_tokens(&s, &s.cfg.resource.clone())
                }
                _ => oauth_err(StatusCode::BAD_REQUEST, "invalid_grant"),
            }
        }
        _ => oauth_err(StatusCode::BAD_REQUEST, "unsupported_grant_type"),
    }
}

fn issue_tokens(s: &AppState, audience: &str) -> Response {
    let iat = now();
    let access = AccessClaims {
        iss: s.cfg.issuer.clone(),
        sub: "owner".into(),
        aud: audience.to_string(),
        exp: iat + s.cfg.access_ttl,
        iat,
        scope: "mcp".into(),
        client_id: s.cfg.client_id.clone(),
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
