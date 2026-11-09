//! The governed LLM lane — `kriya-gateway egress --llm-listen <addr>`: a plain-HTTP
//! OpenAI / Anthropic API pass-through that runs inside the egress process beside the CONNECT
//! proxy, scans every prompt and every reply for the closed secret/PII set
//! ([`crate::permissions::scan_secrets_pii_spans`]) and either rewrites matches to
//! `[REDACTED <type>]`, denies, or allows — before the body leaves the gateway in either
//! direction. Every request is receipted on the SAME signer/chain the egress proxy uses.
//!
//! ## How a client uses it
//! No TLS interception: the gateway is simply the client's configured API endpoint
//! (`OPENAI_BASE_URL=http://127.0.0.1:15081/v1`, `ANTHROPIC_BASE_URL=http://127.0.0.1:15081`).
//! Routing is by path: `/v1/messages*` → the `anthropic` upstream; every other `/v1/…` path → the
//! `openai` upstream. Request headers (`Authorization`, `x-api-key`, `anthropic-version`, …) pass
//! through to the provider; their values are never logged or receipted.
//!
//! ## Decision order (per request)
//! 1. provider enabled by `llm.providers`? else 403 + `kriya.io.llm.deny`;
//! 2. the provider host through the SAME [`EgressPolicy::evaluate`] the CONNECT lane uses — deny
//!    (or approval tier: no synchronous approval channel here) → 403 + the egress deny receipt
//!    (`kriya.io.egress.http.deny`, with `"lane": "llm"`);
//! 3. request body: canary tokens (`detection.canary_tokens`) are always-deny; then the detector
//!    per `llm.request` (`redact` rewrites the redactable text fields, `deny` refuses, `allow`
//!    forwards and records the match types). In `redact` mode a match OUTSIDE the redactable text
//!    fields is a deny (`match outside redactable text`) — fail closed, never forward it;
//! 4. forward over `ureq` (TLS for `https://` upstreams; redirects disabled so a 3xx can never
//!    walk the request to a host the egress tier did not evaluate);
//! 5. response body: the whole upstream response is buffered (streaming included), scanned per
//!    `llm.response`, and released verbatim (clean), rewritten (redacted), or replaced by a 403 in
//!    the provider's own error shape (denied) so SDKs raise a clean exception.
//!
//! ## Redactable text fields
//! Requests — OpenAI: `messages[].content` (string or parts' `.text`), `input` (string, or items
//! that are strings / carry `content` (string or parts' `.text`) / `.text`), plus `prompt` and
//! `instructions`; Anthropic: `system` (string or blocks' `.text`), `messages[].content` (string or
//! blocks' `.text`). Responses — OpenAI: `choices[].message.content`, `choices[].text`,
//! `output[].content[].text`, streaming `choices[].delta.content`; Anthropic: `content[].text`,
//! streaming `content_block_delta.delta.text`.
//!
//! ## Streaming
//! A `text/event-stream` response is buffered whole and its joined text scanned (a match split
//! across chunks is still caught). Clean → the buffered bytes are released verbatim (same status,
//! headers, SSE framing). Redacted → re-emitted as ONE synthetic chunk sequence in the provider's
//! own stream shape. A stream that needs redaction but carries non-text content (tool-call /
//! JSON / thinking deltas, or more than one choice) is denied rather than re-emitted lossy.
//! Buffering means the client sees the reply only once the upstream has finished.
//!
//! ## Honest ceiling
//! This lane governs ONLY clients pointed at the listener. A process that talks to the provider
//! directly bypasses it — pair it with the CONNECT lane's egress rules (deny the provider hosts
//! there) to close that path. The detector is a closed set of shapes, not a classifier.

use std::io::{BufReader, Read};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::audit::{now_ms, Actor, Receipt, Signer};
use crate::http1::{self, ParsedRequest};
use crate::permissions::{
    canary_match, scan_secrets_pii, scan_secrets_pii_spans, url_host, EgressDecision, EgressPolicy,
    LlmContentAction, LlmPolicy, LlmProvider,
};

use super::executor::{HashScheme, IoDecision, IoDirection, IoKind, IoRecord};

/// One receipt per governed LLM request (allow / redact / deny).
pub const LLM_REQUEST: &str = "kriya.io.llm.request";
/// The decision-point receipt for a request or response the lane refused.
pub const LLM_DENY: &str = "kriya.io.llm.deny";

/// Request headers never forwarded upstream beyond the hop-by-hop set `http1::forward` drops:
/// `accept-encoding` (the lane must read the reply to scan it — `ureq` negotiates + decodes gzip
/// itself), `expect` (the body is already read), and proxy/connection-scoped headers.
const SKIP_REQUEST_HEADERS: &[&str] = &[
    "accept-encoding",
    "expect",
    "keep-alive",
    "proxy-connection",
    "proxy-authorization",
    "te",
    "upgrade",
];

/// Base URLs of the two provider families. Defaults to the public APIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlmUpstreams {
    pub openai: String,
    pub anthropic: String,
}

impl Default for LlmUpstreams {
    fn default() -> Self {
        LlmUpstreams {
            openai: "https://api.openai.com".to_string(),
            anthropic: "https://api.anthropic.com".to_string(),
        }
    }
}

impl LlmUpstreams {
    pub fn base(&self, p: LlmProvider) -> &str {
        match p {
            LlmProvider::Openai => &self.openai,
            LlmProvider::Anthropic => &self.anthropic,
        }
    }

    /// Apply a `--llm-upstream` spec (`openai=<url>,anthropic=<url>`, either key optional) on top
    /// of the current values. The URL is a base WITHOUT the `/v1` suffix (the client's path,
    /// `/v1/...`, is appended verbatim).
    pub fn apply_spec(&mut self, spec: &str) -> Result<(), String> {
        for part in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let Some((k, v)) = part.split_once('=') else {
                return Err(format!("expected provider=url, got '{part}'"));
            };
            let v = v.trim().trim_end_matches('/').to_string();
            if !(v.starts_with("https://") || v.starts_with("http://")) {
                return Err(format!(
                    "upstream for '{k}' must be an http(s) URL, got '{v}'"
                ));
            }
            match k.trim() {
                "openai" => self.openai = v,
                "anthropic" => self.anthropic = v,
                other => {
                    return Err(format!(
                        "unknown provider '{other}' (expected openai|anthropic)"
                    ))
                }
            }
        }
        Ok(())
    }
}

/// Everything the lane enforces, taken from the one policy file the egress process loads.
#[derive(Debug, Clone)]
pub struct LlmGatewayConfig {
    pub upstreams: LlmUpstreams,
    /// The `llm:` section (or its default when absent).
    pub llm: LlmPolicy,
    /// The SAME egress tier the CONNECT lane evaluates.
    pub egress: EgressPolicy,
    /// `detection.canary_tokens` — always-deny in both directions.
    pub canary_tokens: Vec<String>,
}

/// A running governed LLM listener. Dropping it stops accepting; in-flight requests finish.
pub struct LlmGateway {
    port: u16,
    stop: Arc<AtomicBool>,
    accept_thread: Option<thread::JoinHandle<()>>,
}

struct Ctx {
    config: LlmGatewayConfig,
    signer: Arc<Signer>,
    actor: Option<Actor>,
    scope_token: String,
    agent: ureq::Agent,
}

impl LlmGateway {
    /// Bind `addr` (e.g. `"127.0.0.1:15081"`, or `"127.0.0.1:0"` for an ephemeral port) and start
    /// accepting — the same shape as [`super::ConnectProxy::spawn_on`]. Receipts are signed by
    /// `signer` (the egress chain), carry `actor`, and correlate to the run via `scope_token`.
    pub fn spawn_on(
        addr: &str,
        config: LlmGatewayConfig,
        signer: Arc<Signer>,
        actor: Option<Actor>,
        scope_token: String,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        let port = listener.local_addr()?.port();
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = stop.clone();
        let ctx = Arc::new(Ctx {
            config,
            signer,
            actor,
            scope_token,
            agent: ureq::AgentBuilder::new()
                .timeout_connect(Duration::from_secs(10))
                .timeout_read(Duration::from_secs(600))
                .timeout_write(Duration::from_secs(60))
                .redirects(0)
                .build(),
        });

        let accept_thread = thread::spawn(move || {
            while !stop_flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _addr)) => {
                        // Same BSD/macOS gotcha `ConnectProxy` documents: an accepted socket can
                        // inherit O_NONBLOCK from the non-blocking listener.
                        if stream.set_nonblocking(false).is_err() {
                            continue;
                        }
                        let ctx = ctx.clone();
                        thread::spawn(move || handle_connection(stream, &ctx));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(50));
                    }
                    Err(_) => thread::sleep(Duration::from_millis(50)),
                }
            }
        });

        Ok(Self {
            port,
            stop,
            accept_thread: Some(accept_thread),
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for LlmGateway {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.accept_thread.take() {
            let _ = h.join();
        }
    }
}

// ─── Connection handling ────────────────────────────────────────────────────────────────────────

fn handle_connection(stream: TcpStream, ctx: &Ctx) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(600)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(600)));
    let Ok(read_stream) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(read_stream);
    let mut writer = stream;
    match http1::read_request(&mut reader) {
        Ok(Some(req)) => handle_request(&mut writer, req, ctx),
        Ok(None) => {}
        Err(_) => {
            let _ = write_plain_error(&mut writer, 400, "invalid_request", "malformed request");
        }
    }
}

/// Which provider a request path routes to: `/v1/messages*` → Anthropic, other `/v1/…` → OpenAI.
pub(crate) fn route(path: &str) -> Option<LlmProvider> {
    if path.starts_with("/v1/messages") {
        Some(LlmProvider::Anthropic)
    } else if path.starts_with("/v1/") {
        Some(LlmProvider::Openai)
    } else {
        None
    }
}

/// The per-request receipt state, filled in as the request moves through the lane.
struct RequestRecord {
    provider: LlmProvider,
    path: String,
    model: Option<String>,
    stream: bool,
    decision: &'static str,
    request_matches: Vec<&'static str>,
    response_matches: Vec<&'static str>,
    request_sha256: String,
    status: u16,
    bytes_in: u64,
    bytes_out: u64,
}

fn handle_request(writer: &mut TcpStream, req: ParsedRequest, ctx: &Ctx) {
    let started = Instant::now();
    // Route + receipt on the path only — never the query string.
    let path = req.path.split(['?', '#']).next().unwrap_or("").to_string();
    let Some(provider) = route(&path) else {
        let _ = write_plain_error(
            writer,
            404,
            "not_found",
            "kriya llm lane: only /v1/... API paths are served",
        );
        return;
    };
    let req_json: Option<Value> = serde_json::from_slice(&req.body).ok();
    let mut rec = RequestRecord {
        provider,
        path,
        model: req_json
            .as_ref()
            .and_then(|v| v.get("model"))
            .and_then(Value::as_str)
            .map(str::to_string),
        stream: req_json
            .as_ref()
            .and_then(|v| v.get("stream"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        decision: "allow",
        request_matches: Vec::new(),
        response_matches: Vec::new(),
        request_sha256: sha256_hex(&req.body),
        status: 0,
        bytes_in: 0,
        bytes_out: 0,
    };

    // 1. Provider enabled by `llm.providers`.
    if !ctx.config.llm.allows_provider(provider) {
        deny(
            writer,
            ctx,
            &mut rec,
            "request",
            "provider not enabled by llm.providers",
            &[],
        );
        finish(ctx, &rec, started);
        return;
    }

    // 2. The provider host through the SAME egress tier the CONNECT lane uses.
    let base = ctx.config.upstreams.base(provider).to_string();
    let host = url_host(&base);
    let refused = match ctx.config.egress.evaluate(&host) {
        EgressDecision::Allow { .. } => None,
        EgressDecision::Deny { rule, reason } => Some((rule, reason)),
        EgressDecision::Approval { rule } => Some((
            rule,
            "approval-tier destination refused in the llm lane (no synchronous approval \
             channel)"
                .to_string(),
        )),
    };
    if let Some((rule, reason)) = refused {
        record_egress_deny(ctx, &host, &req.method, rule, reason);
        let _ = write_policy_error(
            writer,
            provider,
            &format!("egress to {host} denied by policy"),
        );
        rec.decision = "deny";
        rec.status = 403;
        finish(ctx, &rec, started);
        return;
    }

    // 3. Request content.
    let scanned = govern_body(
        provider,
        Dir::Request,
        &req.body,
        ctx.config.llm.request,
        &ctx.config.canary_tokens,
    );
    rec.request_matches = scanned.matches.clone();
    let fwd_body: Vec<u8> = match scanned.verdict {
        Verdict::Clean | Verdict::Allowed => req.body.clone(),
        Verdict::Redacted(b) => {
            rec.decision = "redact";
            b
        }
        Verdict::Denied(reason) => {
            let matches = rec.request_matches.clone();
            deny(writer, ctx, &mut rec, "request", &reason, &matches);
            finish(ctx, &rec, started);
            return;
        }
    };
    rec.request_sha256 = sha256_hex(&fwd_body);
    rec.bytes_out = fwd_body.len() as u64;

    // 4. Forward.
    let url = format!("{}{}", base.trim_end_matches('/'), req.path);
    let resp = match http1::forward(
        &ctx.agent,
        &req.method,
        &url,
        &req.headers,
        &fwd_body,
        SKIP_REQUEST_HEADERS,
    ) {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r,
        Err(_) => {
            let _ = write_plain_error(writer, 502, "upstream_error", "upstream unreachable");
            rec.status = 502;
            finish(ctx, &rec, started);
            return;
        }
    };
    let status = resp.status();
    let headers: Vec<(String, String)> = http1::collect_headers(&resp)
        .into_iter()
        .filter(|(k, _)| !k.eq_ignore_ascii_case("content-encoding"))
        .collect();
    let content_type = resp
        .header("content-type")
        .unwrap_or("")
        .to_ascii_lowercase();
    // `ureq` strips Content-Encoding when it decoded the body itself; anything still encoded is
    // unreadable here, so it can't be scanned — fail closed.
    let undecodable = resp
        .header("content-encoding")
        .map(|e| !e.trim().is_empty() && !e.trim().eq_ignore_ascii_case("identity"))
        .unwrap_or(false);
    let mut body = Vec::new();
    let read = resp
        .into_reader()
        .take(http1::MAX_BODY_BYTES as u64 + 1)
        .read_to_end(&mut body);
    rec.bytes_in = body.len() as u64;
    if read.is_err() || body.len() > http1::MAX_BODY_BYTES {
        let _ = write_plain_error(
            writer,
            502,
            "upstream_error",
            "upstream response unreadable",
        );
        rec.status = 502;
        finish(ctx, &rec, started);
        return;
    }
    if undecodable {
        deny(
            writer,
            ctx,
            &mut rec,
            "response",
            "response content-encoding cannot be scanned",
            &[],
        );
        finish(ctx, &rec, started);
        return;
    }

    // 5. Response content.
    let is_sse = content_type.contains("text/event-stream");
    let scanned = if is_sse {
        govern_sse(
            provider,
            &body,
            ctx.config.llm.response,
            &ctx.config.canary_tokens,
        )
    } else {
        govern_body(
            provider,
            Dir::Response,
            &body,
            ctx.config.llm.response,
            &ctx.config.canary_tokens,
        )
    };
    rec.response_matches = scanned.matches.clone();
    match scanned.verdict {
        Verdict::Clean | Verdict::Allowed => {
            let _ = http1::write_full_response(writer, status, &headers, &body);
            rec.status = status;
        }
        Verdict::Redacted(new_body) => {
            rec.decision = "redact";
            let _ = http1::write_full_response(writer, status, &headers, &new_body);
            rec.status = status;
        }
        Verdict::Denied(reason) => {
            let matches = rec.response_matches.clone();
            deny(writer, ctx, &mut rec, "response", &reason, &matches);
        }
    }
    finish(ctx, &rec, started);
}

/// Refuse with a provider-shaped 403 and sign the `kriya.io.llm.deny` decision receipt.
fn deny(
    writer: &mut TcpStream,
    ctx: &Ctx,
    rec: &mut RequestRecord,
    direction: &str,
    reason: &str,
    matches: &[&'static str],
) {
    let _ = write_policy_error(
        writer,
        rec.provider,
        &format!("kriya llm lane denied the {direction}: {reason}"),
    );
    rec.decision = "deny";
    rec.status = 403;
    ctx.signer.record(
        Receipt::new(
            uuid::Uuid::new_v4().to_string(),
            LLM_DENY.to_string(),
            json!({
                "lane": "llm",
                "corr": ctx.scope_token,
                "provider": rec.provider.as_str(),
                "path": rec.path,
                "model": rec.model,
                "direction": direction,
                "reason": reason,
                "matches": matches,
            }),
            false,
            now_ms(),
        )
        .with_actor(ctx.actor.clone()),
    );
}

/// Sign the one `kriya.io.llm.request` receipt for this request. Content-free by construction:
/// match TYPES, a hash of the forwarded body, sizes and timing — never text, never a header.
fn finish(ctx: &Ctx, rec: &RequestRecord, started: Instant) {
    ctx.signer.record(
        Receipt::new(
            uuid::Uuid::new_v4().to_string(),
            LLM_REQUEST.to_string(),
            json!({
                "lane": "llm",
                "corr": ctx.scope_token,
                "provider": rec.provider.as_str(),
                "path": rec.path,
                "model": rec.model,
                "stream": rec.stream,
                "decision": rec.decision,
                "request_matches": rec.request_matches,
                "response_matches": rec.response_matches,
                "request_sha256": rec.request_sha256,
                "status": rec.status,
                "bytes_in": rec.bytes_in,
                "bytes_out": rec.bytes_out,
                "latency_ms": started.elapsed().as_millis() as u64,
            }),
            rec.decision != "deny",
            now_ms(),
        )
        .with_actor(ctx.actor.clone()),
    );
}

/// The egress tier refused the provider host: the SAME receipt the CONNECT lane signs for a
/// denied destination (`kriya.io.egress.http.deny`, same params), tagged `"lane": "llm"`.
fn record_egress_deny(ctx: &Ctx, host: &str, method: &str, rule: Option<String>, reason: String) {
    let io = IoRecord {
        direction: IoDirection::Egress,
        dest_host: Some(host.to_string()),
        dest_kind: IoKind::Http,
        method: Some(method.to_string()),
        bytes_out: None,
        bytes_in: None,
        bytes_in_is_partial: false,
        content_sha256: None,
        hash_scheme: HashScheme::WireBytes,
        decision: IoDecision::Deny,
        policy_rule: rule,
        approved_by: None,
        reason: Some(reason),
        server: None,
        flags: Vec::new(),
    };
    let mut params = io.params(Some(&ctx.scope_token));
    if let Value::Object(m) = &mut params {
        m.insert("lane".into(), Value::String("llm".into()));
    }
    ctx.signer.record(
        Receipt::new(
            uuid::Uuid::new_v4().to_string(),
            io.action_id(),
            params,
            false,
            now_ms(),
        )
        .with_actor(ctx.actor.clone()),
    );
}

// ─── Response writers ───────────────────────────────────────────────────────────────────────────

/// The provider's own error-body shape for a policy refusal, so SDKs raise a clean exception.
pub(crate) fn policy_error_body(provider: LlmProvider, message: &str) -> Vec<u8> {
    let v = match provider {
        LlmProvider::Openai => json!({
            "error": { "type": "policy_denied", "code": "policy_denied", "message": message }
        }),
        LlmProvider::Anthropic => json!({
            "type": "error",
            "error": { "type": "permission_error", "message": message }
        }),
    };
    serde_json::to_vec(&v).unwrap_or_default()
}

fn write_policy_error(
    writer: &mut TcpStream,
    provider: LlmProvider,
    message: &str,
) -> std::io::Result<()> {
    http1::write_full_response(
        writer,
        403,
        &[("Content-Type".to_string(), "application/json".to_string())],
        &policy_error_body(provider, message),
    )
}

fn write_plain_error(
    writer: &mut TcpStream,
    status: u16,
    kind: &str,
    message: &str,
) -> std::io::Result<()> {
    let body = json!({ "error": { "type": kind, "message": message } }).to_string();
    http1::write_full_response(
        writer,
        status,
        &[("Content-Type".to_string(), "application/json".to_string())],
        body.as_bytes(),
    )
}

// ─── Content governance (pure, unit-tested) ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dir {
    Request,
    Response,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// No match anywhere: forward/release the original bytes.
    Clean,
    /// Matches found, `allow` mode: forward/release the original bytes, record the types.
    Allowed,
    /// Matches rewritten in place: forward/release these bytes instead.
    Redacted(Vec<u8>),
    /// Refuse, with a content-free reason.
    Denied(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Scanned {
    pub(crate) verdict: Verdict,
    /// Distinct match types, detector order — never values.
    pub(crate) matches: Vec<&'static str>,
}

const OUTSIDE_REASON: &str = "match outside redactable text";

fn push_unique(into: &mut Vec<&'static str>, items: impl IntoIterator<Item = &'static str>) {
    for t in items {
        if !into.contains(&t) {
            into.push(t);
        }
    }
}

/// Visit a value that is a string, or an array of strings / blocks carrying a `.text` string.
fn text_or_parts(v: &mut Value, f: &mut dyn FnMut(&mut String)) {
    match v {
        Value::String(s) => f(s),
        Value::Array(items) => {
            for item in items {
                match item {
                    Value::String(s) => f(s),
                    Value::Object(o) => {
                        if let Some(Value::String(s)) = o.get_mut("text") {
                            f(s);
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
}

fn for_each_in_array(v: Option<&mut Value>, mut each: impl FnMut(&mut Value)) {
    if let Some(Value::Array(items)) = v {
        for item in items {
            each(item);
        }
    }
}

/// Visit every redactable text field of a (non-streaming) body. See the module doc for the list.
pub(crate) fn for_each_text(
    v: &mut Value,
    provider: LlmProvider,
    dir: Dir,
    f: &mut dyn FnMut(&mut String),
) {
    let Value::Object(root) = v else {
        return;
    };
    match (provider, dir) {
        (LlmProvider::Openai, Dir::Request) => {
            for_each_in_array(root.get_mut("messages"), |m| {
                if let Some(c) = m.get_mut("content") {
                    text_or_parts(c, f);
                }
            });
            match root.get_mut("input") {
                Some(Value::String(s)) => f(s),
                Some(Value::Array(items)) => {
                    for item in items {
                        match item {
                            Value::String(s) => f(s),
                            Value::Object(o) => {
                                if let Some(c) = o.get_mut("content") {
                                    text_or_parts(c, f);
                                }
                                if let Some(Value::String(s)) = o.get_mut("text") {
                                    f(s);
                                }
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
            if let Some(p) = root.get_mut("prompt") {
                text_or_parts(p, f);
            }
            if let Some(Value::String(s)) = root.get_mut("instructions") {
                f(s);
            }
        }
        (LlmProvider::Anthropic, Dir::Request) => {
            if let Some(s) = root.get_mut("system") {
                text_or_parts(s, f);
            }
            for_each_in_array(root.get_mut("messages"), |m| {
                if let Some(c) = m.get_mut("content") {
                    text_or_parts(c, f);
                }
            });
        }
        (LlmProvider::Openai, Dir::Response) => {
            for_each_in_array(root.get_mut("choices"), |c| {
                if let Some(content) = c.get_mut("message").and_then(|m| m.get_mut("content")) {
                    text_or_parts(content, f);
                }
                if let Some(Value::String(s)) = c.get_mut("text") {
                    f(s);
                }
            });
            for_each_in_array(root.get_mut("output"), |o| {
                if let Some(c) = o.get_mut("content") {
                    text_or_parts(c, f);
                }
            });
        }
        (LlmProvider::Anthropic, Dir::Response) => {
            if let Some(c) = root.get_mut("content") {
                text_or_parts(c, f);
            }
        }
    }
}

/// Any canary token in any JSON string (catches a token the raw-body check would miss because the
/// client JSON-escaped part of it).
fn any_string_canary(v: &Value, tokens: &[String]) -> bool {
    match v {
        Value::String(s) => canary_match(s, tokens).is_some(),
        Value::Array(a) => a.iter().any(|x| any_string_canary(x, tokens)),
        Value::Object(o) => o
            .iter()
            .any(|(k, x)| canary_match(k, tokens).is_some() || any_string_canary(x, tokens)),
        _ => false,
    }
}

/// Rewrite every span in `text` to `[REDACTED <type>]`, merging overlaps (the merged range takes
/// the first span's type). Panic-free: a range not on a char boundary is widened to one.
pub(crate) fn redact_text(text: &str, spans: &[(std::ops::Range<usize>, &'static str)]) -> String {
    let mut sorted: Vec<(std::ops::Range<usize>, &'static str)> = spans.to_vec();
    sorted.sort_by_key(|(r, _)| (r.start, r.end));
    let mut merged: Vec<(std::ops::Range<usize>, &'static str)> = Vec::new();
    for (r, t) in sorted {
        let mut start = r.start.min(text.len());
        let mut end = r.end.min(text.len());
        while start > 0 && !text.is_char_boundary(start) {
            start -= 1;
        }
        while end < text.len() && !text.is_char_boundary(end) {
            end += 1;
        }
        match merged.last_mut() {
            Some((last, _)) if start < last.end => last.end = last.end.max(end),
            _ => merged.push((start..end, t)),
        }
    }
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    for (r, t) in merged {
        out.push_str(&text[at..r.start]);
        out.push_str("[REDACTED ");
        out.push_str(t);
        out.push(']');
        at = r.end;
    }
    out.push_str(&text[at..]);
    out
}

fn decide(
    action: LlmContentAction,
    dir: Dir,
    matches: Vec<&'static str>,
    outside: bool,
    redacted: impl FnOnce() -> Verdict,
) -> Scanned {
    let verdict = if matches.is_empty() {
        Verdict::Clean
    } else {
        match action {
            LlmContentAction::Allow => Verdict::Allowed,
            LlmContentAction::Deny => Verdict::Denied(format!(
                "secret/PII match in the {}",
                if dir == Dir::Request {
                    "request"
                } else {
                    "response"
                }
            )),
            LlmContentAction::Redact if outside => Verdict::Denied(OUTSIDE_REASON.to_string()),
            LlmContentAction::Redact => redacted(),
        }
    };
    Scanned { verdict, matches }
}

/// Govern one complete (non-streaming) body. Canary → deny; then the detector over the redactable
/// text fields and, separately, over everything else (the body with those fields blanked).
pub(crate) fn govern_body(
    provider: LlmProvider,
    dir: Dir,
    body: &[u8],
    action: LlmContentAction,
    canaries: &[String],
) -> Scanned {
    if body.is_empty() {
        return Scanned {
            verdict: Verdict::Clean,
            matches: Vec::new(),
        };
    }
    let raw = String::from_utf8_lossy(body);
    let canary_deny = || Scanned {
        verdict: Verdict::Denied("canary token matched".to_string()),
        matches: Vec::new(),
    };
    if canary_match(&raw, canaries).is_some() {
        return canary_deny();
    }
    let Ok(mut v) = serde_json::from_slice::<Value>(body) else {
        // Not JSON: nothing is a redactable field, so any match is "outside".
        let hits = scan_secrets_pii(&raw);
        return decide(action, dir, hits, true, || Verdict::Clean);
    };
    if any_string_canary(&v, canaries) {
        return canary_deny();
    }

    let mut blank = v.clone();
    for_each_text(&mut blank, provider, dir, &mut |s| s.clear());
    let outside = scan_secrets_pii(&serde_json::to_string(&blank).unwrap_or_default());

    let mut matches: Vec<&'static str> = Vec::new();
    let rewrite = action == LlmContentAction::Redact && outside.is_empty();
    for_each_text(&mut v, provider, dir, &mut |s| {
        let spans = scan_secrets_pii_spans(s);
        if spans.is_empty() {
            return;
        }
        push_unique(&mut matches, spans.iter().map(|(_, t)| *t));
        if rewrite {
            *s = redact_text(s, &spans);
        }
    });
    let outside_hit = !outside.is_empty();
    push_unique(&mut matches, outside);
    decide(action, dir, matches, outside_hit, || {
        let out = serde_json::to_vec(&v).unwrap_or_default();
        // Belt and braces: the rewritten body as a whole must now be clean.
        if scan_secrets_pii(&String::from_utf8_lossy(&out)).is_empty() {
            Verdict::Redacted(out)
        } else {
            Verdict::Denied(OUTSIDE_REASON.to_string())
        }
    })
}

/// Stream metadata kept for re-emitting a redacted stream in the provider's own shape.
#[derive(Default)]
struct StreamMeta {
    first: Option<Value>,
    finish_reason: Option<Value>,
    usage: Option<Value>,
    message_start: Option<Value>,
    message_delta: Option<Value>,
}

/// Pull the text deltas out of one SSE event (clearing them in place, so the remainder can be
/// scanned as "outside" text), flagging content the synthetic re-emit could not carry.
fn take_stream_text(
    provider: LlmProvider,
    ev: &mut Value,
    text: &mut String,
    mixed: &mut bool,
    meta: &mut StreamMeta,
) {
    match provider {
        LlmProvider::Openai => {
            if meta.first.is_none() {
                meta.first = Some(ev.clone());
            }
            if let Some(u) = ev.get("usage").filter(|u| !u.is_null()) {
                meta.usage = Some(u.clone());
            }
            for_each_in_array(ev.get_mut("choices"), |c| {
                if c.get("index").and_then(Value::as_u64).unwrap_or(0) != 0 {
                    *mixed = true;
                }
                if let Some(fr) = c.get("finish_reason").filter(|f| !f.is_null()) {
                    meta.finish_reason = Some(fr.clone());
                }
                if let Some(delta) = c.get_mut("delta") {
                    if delta.get("tool_calls").is_some_and(|t| !t.is_null())
                        || delta.get("function_call").is_some_and(|t| !t.is_null())
                    {
                        *mixed = true;
                    }
                    if let Some(Value::String(s)) = delta.get_mut("content") {
                        text.push_str(s);
                        s.clear();
                    }
                }
            });
        }
        LlmProvider::Anthropic => {
            let ty = ev
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            match ty.as_str() {
                "message_start" => meta.message_start = Some(ev.clone()),
                "message_delta" => meta.message_delta = Some(ev.clone()),
                "content_block_start" => {
                    let block = ev.get_mut("content_block");
                    match block {
                        Some(b) if b.get("type").and_then(Value::as_str) == Some("text") => {
                            if let Some(Value::String(s)) = b.get_mut("text") {
                                text.push_str(s);
                                s.clear();
                            }
                        }
                        _ => *mixed = true,
                    }
                }
                "content_block_delta" => match ev.get_mut("delta") {
                    Some(d) if d.get("type").and_then(Value::as_str) == Some("text_delta") => {
                        if let Some(Value::String(s)) = d.get_mut("text") {
                            text.push_str(s);
                            s.clear();
                        }
                    }
                    _ => *mixed = true,
                },
                _ => {}
            }
        }
    }
}

/// Govern a buffered `text/event-stream` response: scan the joined text (a match split across
/// chunks is still caught) and everything else separately; redaction re-emits one synthetic chunk
/// sequence in the provider's stream shape.
pub(crate) fn govern_sse(
    provider: LlmProvider,
    body: &[u8],
    action: LlmContentAction,
    canaries: &[String],
) -> Scanned {
    let raw = String::from_utf8_lossy(body);
    let canary_deny = || Scanned {
        verdict: Verdict::Denied("canary token matched".to_string()),
        matches: Vec::new(),
    };
    if canary_match(&raw, canaries).is_some() {
        return canary_deny();
    }
    let mut text = String::new();
    let mut mixed = false;
    let mut meta = StreamMeta::default();
    let mut outside: Vec<&'static str> = Vec::new();
    for line in raw.split('\n') {
        let line = line.trim_end_matches('\r');
        let Some(data) = line.strip_prefix("data:") else {
            // `event:` / `id:` / comment lines: not text, but never unscanned.
            push_unique(&mut outside, scan_secrets_pii(line));
            continue;
        };
        let data = data.strip_prefix(' ').unwrap_or(data);
        if data.trim() == "[DONE]" {
            continue;
        }
        match serde_json::from_str::<Value>(data) {
            Ok(mut ev) => {
                if any_string_canary(&ev, canaries) {
                    return canary_deny();
                }
                take_stream_text(provider, &mut ev, &mut text, &mut mixed, &mut meta);
                push_unique(
                    &mut outside,
                    scan_secrets_pii(&serde_json::to_string(&ev).unwrap_or_default()),
                );
            }
            Err(_) => push_unique(&mut outside, scan_secrets_pii(data)),
        }
    }
    if canary_match(&text, canaries).is_some() {
        return canary_deny();
    }
    let spans = scan_secrets_pii_spans(&text);
    let mut matches: Vec<&'static str> = Vec::new();
    push_unique(&mut matches, spans.iter().map(|(_, t)| *t));
    let outside_hit = !outside.is_empty();
    push_unique(&mut matches, outside);
    decide(action, Dir::Response, matches, outside_hit, || {
        if mixed {
            return Verdict::Denied(
                "redaction of a stream carrying non-text content is not supported".to_string(),
            );
        }
        let redacted = redact_text(&text, &spans);
        let out = synthesize_stream(provider, &redacted, &meta);
        if scan_secrets_pii(&String::from_utf8_lossy(&out)).is_empty() {
            Verdict::Redacted(out)
        } else {
            Verdict::Denied(OUTSIDE_REASON.to_string())
        }
    })
}

/// One synthetic stream carrying the full (redacted) text, in the provider's own SSE shape.
fn synthesize_stream(provider: LlmProvider, text: &str, meta: &StreamMeta) -> Vec<u8> {
    let mut out = String::new();
    match provider {
        LlmProvider::Openai => {
            let first = meta.first.clone().unwrap_or_else(|| json!({}));
            let id = first
                .get("id")
                .cloned()
                .unwrap_or_else(|| json!("chatcmpl-kriya"));
            let model = first.get("model").cloned().unwrap_or(Value::Null);
            let created = first
                .get("created")
                .cloned()
                .unwrap_or_else(|| json!((now_ms() / 1000) as u64));
            let content = json!({
                "id": id, "object": "chat.completion.chunk", "created": created, "model": model,
                "choices": [{ "index": 0,
                              "delta": { "role": "assistant", "content": text },
                              "finish_reason": null }]
            });
            let mut finish = json!({
                "id": id, "object": "chat.completion.chunk", "created": created, "model": model,
                "choices": [{ "index": 0, "delta": {},
                              "finish_reason": meta.finish_reason.clone().unwrap_or_else(|| json!("stop")) }]
            });
            if let (Some(u), Value::Object(m)) = (&meta.usage, &mut finish) {
                m.insert("usage".into(), u.clone());
            }
            out.push_str(&format!("data: {content}\n\n"));
            out.push_str(&format!("data: {finish}\n\n"));
            out.push_str("data: [DONE]\n\n");
        }
        LlmProvider::Anthropic => {
            let start = meta.message_start.clone().unwrap_or_else(|| {
                json!({ "type": "message_start", "message": {
                    "id": "msg_kriya", "type": "message", "role": "assistant", "content": [],
                    "model": null, "stop_reason": null, "stop_sequence": null,
                    "usage": { "input_tokens": 0, "output_tokens": 0 } } })
            });
            let delta_end = meta.message_delta.clone().unwrap_or_else(|| {
                json!({ "type": "message_delta",
                        "delta": { "stop_reason": "end_turn", "stop_sequence": null },
                        "usage": { "output_tokens": 0 } })
            });
            let events = [
                ("message_start", start),
                (
                    "content_block_start",
                    json!({ "type": "content_block_start", "index": 0,
                            "content_block": { "type": "text", "text": "" } }),
                ),
                (
                    "content_block_delta",
                    json!({ "type": "content_block_delta", "index": 0,
                            "delta": { "type": "text_delta", "text": text } }),
                ),
                (
                    "content_block_stop",
                    json!({ "type": "content_block_stop", "index": 0 }),
                ),
                ("message_delta", delta_end),
                ("message_stop", json!({ "type": "message_stop" })),
            ];
            for (name, data) in events {
                out.push_str(&format!("event: {name}\ndata: {data}\n\n"));
            }
        }
    }
    out.into_bytes()
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    const AADHAAR: &str = "2345 6789 0124";
    const CARD: &str = "4111 1111 1111 1111";
    const EMAIL: &str = "jane.doe@example.com";

    fn gov(provider: LlmProvider, dir: Dir, v: Value, action: LlmContentAction) -> Scanned {
        govern_body(provider, dir, &serde_json::to_vec(&v).unwrap(), action, &[])
    }

    fn redacted_json(s: &Scanned) -> Value {
        match &s.verdict {
            Verdict::Redacted(b) => serde_json::from_slice(b).unwrap(),
            other => panic!("expected Redacted, got {other:?}"),
        }
    }

    #[test]
    fn route_splits_anthropic_messages_from_openai() {
        assert_eq!(route("/v1/messages"), Some(LlmProvider::Anthropic));
        assert_eq!(
            route("/v1/messages/count_tokens"),
            Some(LlmProvider::Anthropic)
        );
        assert_eq!(route("/v1/chat/completions"), Some(LlmProvider::Openai));
        assert_eq!(route("/v1/responses"), Some(LlmProvider::Openai));
        assert_eq!(route("/v1/models"), Some(LlmProvider::Openai));
        assert_eq!(route("/healthz"), None);
    }

    #[test]
    fn upstream_spec_overrides_and_rejects_garbage() {
        let mut u = LlmUpstreams::default();
        u.apply_spec("openai=http://127.0.0.1:9/").unwrap();
        assert_eq!(u.openai, "http://127.0.0.1:9");
        assert_eq!(u.anthropic, "https://api.anthropic.com");
        u.apply_spec("anthropic=https://a.example,openai=https://o.example")
            .unwrap();
        assert_eq!(u.anthropic, "https://a.example");
        assert!(u.apply_spec("gemini=https://x").is_err());
        assert!(u.apply_spec("openai").is_err());
        assert!(u.apply_spec("openai=ftp://x").is_err());
    }

    #[test]
    fn openai_chat_string_content_is_rewritten() {
        let s = gov(
            LlmProvider::Openai,
            Dir::Request,
            json!({"model": "gpt-x", "messages": [
                {"role": "user", "content": format!("my id {AADHAAR} card {CARD} mail {EMAIL}")}
            ]}),
            LlmContentAction::Redact,
        );
        let v = redacted_json(&s);
        let c = v["messages"][0]["content"].as_str().unwrap();
        assert_eq!(
            c,
            "my id [REDACTED aadhaar] card [REDACTED credit_card] mail [REDACTED email]"
        );
        for t in ["aadhaar", "credit_card", "email"] {
            assert!(s.matches.contains(&t), "{t} in {:?}", s.matches);
        }
        assert_eq!(v["model"], "gpt-x");
    }

    #[test]
    fn openai_chat_parts_are_rewritten() {
        let s = gov(
            LlmProvider::Openai,
            Dir::Request,
            json!({"messages": [{"role": "user", "content": [
                {"type": "text", "text": format!("reach me at {EMAIL}")},
                {"type": "text", "text": "nothing here"}
            ]}]}),
            LlmContentAction::Redact,
        );
        let v = redacted_json(&s);
        assert_eq!(
            v["messages"][0]["content"][0]["text"],
            "reach me at [REDACTED email]"
        );
        assert_eq!(v["messages"][0]["content"][1]["text"], "nothing here");
    }

    #[test]
    fn openai_responses_input_string_and_items_are_rewritten() {
        let s = gov(
            LlmProvider::Openai,
            Dir::Request,
            json!({"input": format!("pan ABCPE1234F")}),
            LlmContentAction::Redact,
        );
        assert_eq!(redacted_json(&s)["input"], "pan [REDACTED pan_in]");
        let s = gov(
            LlmProvider::Openai,
            Dir::Request,
            json!({"input": [
                {"role": "user", "content": [{"type": "input_text", "text": format!("x {CARD}")}]},
                {"role": "user", "content": format!("y {EMAIL}")},
                {"type": "message", "text": "ssn 123-45-6789"}
            ]}),
            LlmContentAction::Redact,
        );
        let v = redacted_json(&s);
        assert_eq!(
            v["input"][0]["content"][0]["text"],
            "x [REDACTED credit_card]"
        );
        assert_eq!(v["input"][1]["content"], "y [REDACTED email]");
        assert_eq!(v["input"][2]["text"], "ssn [REDACTED ssn]");
    }

    #[test]
    fn anthropic_system_and_blocks_are_rewritten() {
        let s = gov(
            LlmProvider::Anthropic,
            Dir::Request,
            json!({
                "system": format!("operator email {EMAIL}"),
                "messages": [{"role": "user", "content": [{"type": "text", "text": format!("id {AADHAAR}")}]}]
            }),
            LlmContentAction::Redact,
        );
        let v = redacted_json(&s);
        assert_eq!(v["system"], "operator email [REDACTED email]");
        assert_eq!(
            v["messages"][0]["content"][0]["text"],
            "id [REDACTED aadhaar]"
        );

        let s = gov(
            LlmProvider::Anthropic,
            Dir::Request,
            json!({"system": [{"type": "text", "text": format!("{CARD}")}], "messages": []}),
            LlmContentAction::Redact,
        );
        assert_eq!(
            redacted_json(&s)["system"][0]["text"],
            "[REDACTED credit_card]"
        );
    }

    #[test]
    fn response_shapes_are_rewritten() {
        let s = gov(
            LlmProvider::Openai,
            Dir::Response,
            json!({"choices": [{"index": 0, "message": {"role": "assistant", "content": format!("it is {EMAIL}")}}]}),
            LlmContentAction::Redact,
        );
        assert_eq!(
            redacted_json(&s)["choices"][0]["message"]["content"],
            "it is [REDACTED email]"
        );
        let s = gov(
            LlmProvider::Openai,
            Dir::Response,
            json!({"output": [{"type": "message", "content": [{"type": "output_text", "text": format!("{CARD}")}]}]}),
            LlmContentAction::Redact,
        );
        assert_eq!(
            redacted_json(&s)["output"][0]["content"][0]["text"],
            "[REDACTED credit_card]"
        );
        let s = gov(
            LlmProvider::Anthropic,
            Dir::Response,
            json!({"type": "message", "content": [{"type": "text", "text": format!("{AADHAAR}")}]}),
            LlmContentAction::Redact,
        );
        assert_eq!(
            redacted_json(&s)["content"][0]["text"],
            "[REDACTED aadhaar]"
        );
    }

    #[test]
    fn match_outside_redactable_text_is_denied_in_redact_mode() {
        let s = gov(
            LlmProvider::Openai,
            Dir::Request,
            json!({"user": EMAIL, "messages": [{"role": "user", "content": "hello"}]}),
            LlmContentAction::Redact,
        );
        assert_eq!(s.verdict, Verdict::Denied(OUTSIDE_REASON.to_string()));
        assert_eq!(s.matches, vec!["email"]);
        // Tool-call arguments in a reply are not redactable text either.
        let s = gov(
            LlmProvider::Anthropic,
            Dir::Response,
            json!({"content": [{"type": "tool_use", "input": {"to": EMAIL}}]}),
            LlmContentAction::Redact,
        );
        assert_eq!(s.verdict, Verdict::Denied(OUTSIDE_REASON.to_string()));
    }

    #[test]
    fn deny_and_allow_modes() {
        let body = json!({"messages": [{"role": "user", "content": format!("{EMAIL}")}]});
        let s = gov(
            LlmProvider::Openai,
            Dir::Request,
            body.clone(),
            LlmContentAction::Deny,
        );
        assert!(matches!(s.verdict, Verdict::Denied(_)));
        let s = gov(
            LlmProvider::Openai,
            Dir::Request,
            body.clone(),
            LlmContentAction::Allow,
        );
        assert_eq!(s.verdict, Verdict::Allowed);
        assert_eq!(s.matches, vec!["email"]);
        let s = gov(
            LlmProvider::Openai,
            Dir::Request,
            json!({"messages": [{"role": "user", "content": "ordinary text, order 12"}]}),
            LlmContentAction::Deny,
        );
        assert_eq!(s.verdict, Verdict::Clean);
    }

    #[test]
    fn canary_is_always_denied_even_in_allow_mode() {
        let canaries = vec!["kriya-canary-7f3a".to_string()];
        let body = serde_json::to_vec(
            &json!({"messages": [{"role": "user", "content": "use kriya-canary-7f3a now"}]}),
        )
        .unwrap();
        for action in [
            LlmContentAction::Allow,
            LlmContentAction::Redact,
            LlmContentAction::Deny,
        ] {
            let s = govern_body(LlmProvider::Openai, Dir::Request, &body, action, &canaries);
            assert_eq!(s.verdict, Verdict::Denied("canary token matched".into()));
        }
        // A JSON-escaped canary is caught via the decoded strings.
        let escaped = br#"{"messages":[{"role":"user","content":"use kriya-canary-7f3a"}]}"#;
        let s = govern_body(
            LlmProvider::Openai,
            Dir::Request,
            escaped,
            LlmContentAction::Allow,
            &canaries,
        );
        assert!(matches!(s.verdict, Verdict::Denied(_)));
    }

    #[test]
    fn non_json_body_with_a_match_is_denied_in_redact_mode() {
        let s = govern_body(
            LlmProvider::Openai,
            Dir::Request,
            format!("plain {EMAIL}").as_bytes(),
            LlmContentAction::Redact,
            &[],
        );
        assert_eq!(s.verdict, Verdict::Denied(OUTSIDE_REASON.to_string()));
    }

    #[test]
    fn redact_text_merges_overlaps_and_is_boundary_safe() {
        let t = "héllo 4111111111111111 bye";
        let spans = scan_secrets_pii_spans(t);
        assert_eq!(redact_text(t, &spans), "héllo [REDACTED credit_card] bye");
        let merged = redact_text("abcdef", &[(1..3, "x"), (2..5, "y")]);
        assert_eq!(merged, "a[REDACTED x]f");
        // An off-boundary range is widened, never a panic.
        let _ = redact_text("é", &[(1..2, "x")]);
    }

    fn openai_sse(parts: &[&str]) -> Vec<u8> {
        let mut s = String::new();
        for p in parts {
            s.push_str(&format!(
                "data: {}\n\n",
                json!({"id": "c1", "object": "chat.completion.chunk", "created": 1, "model": "m",
                       "choices": [{"index": 0, "delta": {"content": p}, "finish_reason": null}]})
            ));
        }
        s.push_str(&format!(
            "data: {}\n\ndata: [DONE]\n\n",
            json!({"id": "c1", "object": "chat.completion.chunk", "created": 1, "model": "m",
                   "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]})
        ));
        s.into_bytes()
    }

    #[test]
    fn sse_clean_stream_is_released_and_split_match_is_caught() {
        let clean = openai_sse(&["hel", "lo"]);
        let s = govern_sse(LlmProvider::Openai, &clean, LlmContentAction::Redact, &[]);
        assert_eq!(s.verdict, Verdict::Clean);
        // The email is split across two chunks: only the joined text shows it.
        let split = openai_sse(&["write to jane.doe@exa", "mple.com today"]);
        let s = govern_sse(LlmProvider::Openai, &split, LlmContentAction::Redact, &[]);
        let Verdict::Redacted(out) = s.verdict else {
            panic!("expected redacted")
        };
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("write to [REDACTED email] today"));
        assert!(!out.contains("jane.doe"));
        assert!(out.ends_with("data: [DONE]\n\n"));
        assert_eq!(out.matches("data: ").count(), 3);
    }

    #[test]
    fn sse_anthropic_redacted_reemits_the_full_event_sequence() {
        let mut s = String::new();
        let evs = [
            json!({"type": "message_start", "message": {"id": "msg_1", "type": "message", "role": "assistant", "content": [], "model": "c", "usage": {"input_tokens": 3, "output_tokens": 0}}}),
            json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
            json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "id 2345 "}}),
            json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "6789 0124 ok"}}),
            json!({"type": "content_block_stop", "index": 0}),
            json!({"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": null}, "usage": {"output_tokens": 9}}),
            json!({"type": "message_stop"}),
        ];
        for e in &evs {
            s.push_str(&format!(
                "event: {}\ndata: {e}\n\n",
                e["type"].as_str().unwrap()
            ));
        }
        let r = govern_sse(
            LlmProvider::Anthropic,
            s.as_bytes(),
            LlmContentAction::Redact,
            &[],
        );
        assert_eq!(r.matches, vec!["aadhaar"]);
        let Verdict::Redacted(out) = r.verdict else {
            panic!("expected redacted")
        };
        let out = String::from_utf8(out).unwrap();
        let names: Vec<&str> = out
            .lines()
            .filter_map(|l| l.strip_prefix("event: "))
            .collect();
        assert_eq!(
            names,
            vec![
                "message_start",
                "content_block_start",
                "content_block_delta",
                "content_block_stop",
                "message_delta",
                "message_stop"
            ]
        );
        assert!(out.contains("id [REDACTED aadhaar] ok"));
        assert!(out.contains("msg_1"));
    }

    #[test]
    fn sse_redaction_with_tool_call_deltas_is_denied_not_reemitted_lossy() {
        let mut s = String::from_utf8(openai_sse(&[EMAIL])).unwrap();
        s.insert_str(
            0,
            &format!(
                "data: {}\n\n",
                json!({"id": "c1", "choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"arguments": "{}"}}]}}]})
            ),
        );
        let r = govern_sse(
            LlmProvider::Openai,
            s.as_bytes(),
            LlmContentAction::Redact,
            &[],
        );
        assert!(matches!(r.verdict, Verdict::Denied(ref m) if m.contains("non-text")));
    }

    #[test]
    fn policy_error_bodies_follow_provider_shapes() {
        let o: Value =
            serde_json::from_slice(&policy_error_body(LlmProvider::Openai, "no")).unwrap();
        assert_eq!(o["error"]["type"], "policy_denied");
        let a: Value =
            serde_json::from_slice(&policy_error_body(LlmProvider::Anthropic, "no")).unwrap();
        assert_eq!(a["type"], "error");
        assert_eq!(a["error"]["type"], "permission_error");
    }
}
