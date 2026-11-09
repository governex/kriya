//! The MCP **client** half — the one genuinely new subsystem Front 1 needs. kriya has only
//! ever been an MCP *server* (it exposes an app's actions as governed tools); the stdio
//! governance proxy must also *speak to* a downstream server it spawns as a child.
//!
//! [`McpClient`] spawns the downstream MCP server (`std::process::Command` with piped stdio —
//! the exact pattern already proven in [`super::executor::PersistentProcessExecutor`]), keeps a
//! request-id counter, and exchanges newline-delimited JSON-RPC over the child's stdin/stdout.
//! It reuses the `jsonrpc.rs` types unchanged — the same shapes serve both directions of MCP.
//!
//! The wire transport is split out into a private generic [`Transport`] over `BufRead + Write`
//! so the framing + id-correlation logic is unit-testable with in-memory pipes, no subprocess.
//!
//! std-only by design: no tokio, no async — a synchronous request → response client is all the
//! MVP proxy needs (see `proxy_server.rs`). EOF / broken pipe surfaces as `Err`, never a panic,
//! so a dead downstream degrades into a readable failure rather than taking down the session.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};

use serde_json::{json, Value};

use super::executor::IoRecord;
#[cfg(feature = "mcp-http")]
use super::executor::{HashScheme, IoDecision, IoDirection, IoKind};
use super::jsonrpc::{CallToolResult, InitializeResult, ListToolsResult, Tool, PROTOCOL_VERSION};

/// The proxy's *own* downstream request ids live in a disjoint range from the client ids it
/// passes through, so a downstream reply can never be confused with an echoed client id. The
/// MVP is strictly request→response (one outstanding request at a time), so a simple counter
/// from this base is enough; the range keeps the invariant explicit for the full-lifecycle
/// version (two reader threads correlating by id).
const PROXY_ID_BASE: u64 = 1;

/// B6 SSRF/rebinding guard, TRANSPORT-level enforcement (doc 24 §11 B6): resolves `netloc`
/// (`"host:port"`, ureq's resolver convention) and returns EXACTLY ONE address that is not a
/// forbidden target (loopback/RFC1918/link-local — which subsumes the 169.254.169.254 cloud-
/// metadata endpoint — /IPv6 unique-local), never the full resolved set. Returning only one matters:
/// on a failed connect ureq tries the NEXT address in whatever list the resolver returned, so handing
/// back every resolved address (forbidden ones included) would leave a fallback path straight to
/// whichever one this filter exists to remove — pinning to a single validated address is what closes
/// the gap between "checked" and "connected" that a DNS-rebinding attack targets. Only installed on
/// the agent when the caller opts in (see [`McpClient::connect_http`]'s `ssrf_guard` — a local dev
/// upstream on `127.0.0.1`/`localhost` is a legitimate target, so this is NOT unconditional).
#[cfg(feature = "mcp-http")]
fn ssrf_safe_resolver(netloc: &str) -> std::io::Result<Vec<std::net::SocketAddr>> {
    use std::net::ToSocketAddrs;
    match pick_safe_address(netloc.to_socket_addrs()?) {
        Some(addr) => Ok(vec![addr]),
        None => Err(std::io::Error::other(
            "SSRF guard: destination resolves only to a forbidden target \
             (loopback/private/link-local/metadata) — refusing to connect (B6)",
        )),
    }
}

/// The pure filter behind [`ssrf_safe_resolver`], split out so a synthetic multi-address "DNS
/// answer" (a rebinding fixture: some addresses forbidden, some not) can be tested directly without
/// a real resolver. Returns the first non-forbidden address in `addrs`, or `None` if every one is
/// forbidden.
#[cfg(feature = "mcp-http")]
fn pick_safe_address(
    mut addrs: impl Iterator<Item = std::net::SocketAddr>,
) -> Option<std::net::SocketAddr> {
    addrs.find(|addr| crate::permissions::ssrf_disallowed_reason(addr.ip()).is_none())
}

/// A downstream MCP server connection plus the JSON-RPC transport over its stdio. Single-threaded
/// MVP: one request out, one response in. Holds the [`Child`] (when spawned) so dropping the client
/// tears the subprocess down with it.
///
/// The transport streams are boxed trait objects so the *same* `McpClient` type drives either a real
/// subprocess (the product path) or in-memory pipes (tests, via [`McpClient::from_streams`]) — the
/// proxy and the binary depend on one concrete type, not a generic.
pub struct McpClient {
    /// `None` for an in-memory test client; `Some` for a spawned downstream (killed on drop).
    child: Option<Child>,
    backend: Backend,
}

/// Where an [`McpClient`]'s JSON-RPC actually flows. Stdio (a spawned or in-memory downstream, the
/// original Front-1 path) or HTTP (a REMOTE MCP server over Streamable HTTP + SSE — the broker's
/// W2-2 path). Both expose the same request/notify surface so [`McpProxyExecutor`] and the broker
/// are identical regardless of transport.
// The HTTP transport carries a `ureq::Agent` + per-request io capture, so it is chunkier than the
// stdio variant. One `Backend` lives per client for the session's lifetime — boxing it would trade a
// real indirection for a lint with no runtime benefit.
#[allow(clippy::large_enum_variant)]
enum Backend {
    Stdio(Transport<Box<dyn BufRead + Send>, Box<dyn Write + Send>>),
    #[cfg(feature = "mcp-http")]
    Http(HttpTransport),
}

impl McpClient {
    /// Spawn `program` with `args` as the downstream MCP server. stdin/stdout are piped (the
    /// JSON-RPC channel); stderr is inherited so the downstream's own diagnostics reach the
    /// operator's terminal without polluting the protocol stream — same posture as the executors.
    pub fn spawn(program: &str, args: &[String]) -> std::io::Result<Self> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        // A piped child always yields both handles; treat their absence as a spawn IO error
        // rather than panicking inside the proxy.
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("child stdin unavailable"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("child stdout unavailable"))?;
        let reader: Box<dyn BufRead + Send> = Box::new(BufReader::new(stdout));
        let writer: Box<dyn Write + Send> = Box::new(stdin);
        Ok(Self {
            child: Some(child),
            backend: Backend::Stdio(Transport::new(reader, writer)),
        })
    }

    /// Connect to a **remote** MCP server over Streamable HTTP (W2-2). `url` is the server's MCP
    /// endpoint; `headers` are extra request headers (e.g. `("Authorization", "Bearer …")`) sent on
    /// every call. No subprocess — the "child" is `None`. The MCP session id the server assigns on
    /// `initialize` is captured and echoed on later requests automatically. `ssrf_guard` installs the
    /// B6 resolver pin (doc 24 §11 B6) — gated, not unconditional: a local dev/test upstream on
    /// `127.0.0.1`/`localhost` is a legitimate `url:` target, so the guard only activates when the
    /// operator's policy turns it on (`detection.ssrf_guard.enabled`), same opt-in as every other
    /// detector in the pack. `secrets` installs credential brokering (doc 24 §11 B13) — `None` is
    /// byte-identical to pre-EG-B.
    #[cfg(feature = "mcp-http")]
    pub fn connect_http(
        url: &str,
        headers: Vec<(String, String)>,
        ssrf_guard: bool,
        secrets: Option<crate::secrets::SecretsPolicy>,
    ) -> std::io::Result<Self> {
        Ok(Self {
            child: None,
            backend: Backend::Http(HttpTransport::new(url, headers, ssrf_guard, secrets)),
        })
    }

    /// Build a client over arbitrary streams instead of a subprocess — used by the proxy's tests to
    /// drive the full client/transport with a scripted in-memory downstream (no real process).
    #[cfg(test)]
    pub(crate) fn from_streams<R, W>(reader: R, writer: W) -> Self
    where
        R: std::io::Read + Send + 'static,
        W: Write + Send + 'static,
    {
        let reader: Box<dyn BufRead + Send> = Box::new(BufReader::new(reader));
        let writer: Box<dyn Write + Send> = Box::new(writer);
        Self {
            child: None,
            backend: Backend::Stdio(Transport::new(reader, writer)),
        }
    }

    /// MCP handshake: send `initialize`, read the downstream's `InitializeResult`, then send the
    /// `notifications/initialized` notification the downstream expects before it will serve tools.
    pub fn initialize(&mut self) -> Result<InitializeResult, String> {
        let result = self.request("initialize", Some(initialize_params()))?;
        let init: InitializeResult = parse_init(&result)?;
        // A spec-compliant server waits for this notification before considering itself ready.
        self.notify("notifications/initialized", None)?;
        Ok(init)
    }

    /// `tools/list` against the downstream — the dynamic catalog the proxy caches and serves
    /// (policy-filtered) to its own client.
    pub fn list_tools(&mut self) -> Result<Vec<Tool>, String> {
        let result = self.request("tools/list", Some(json!({})))?;
        let list: ListToolsResult = parse_tools(&result)?;
        Ok(list.tools)
    }

    /// Forward a cleared `tools/call` to the downstream and return its `CallToolResult`. This is
    /// the last hop the [`super::proxy_executor::McpProxyExecutor`] makes on a governed call.
    pub fn call_tool(&mut self, name: &str, arguments: &Value) -> Result<CallToolResult, String> {
        let params = json!({ "name": name, "arguments": arguments });
        let result = self.request("tools/call", Some(params))?;
        Ok(parse_call_result(&result))
    }

    /// Generic request: send `method` with `params`, block for the matching response, return its
    /// `result`. Used for transparent passthrough of arbitrary methods (`resources/*`, `prompts/*`,
    /// `ping`, …) the proxy doesn't model. A JSON-RPC error reply becomes an `Err` string.
    pub fn request(&mut self, method: &str, params: Option<Value>) -> Result<Value, String> {
        match &mut self.backend {
            Backend::Stdio(t) => t.request(method, params),
            #[cfg(feature = "mcp-http")]
            Backend::Http(h) => h.request(method, params),
        }
    }

    /// Fire-and-forget notification (no id, no response) — forwarded verbatim from the client to
    /// the downstream (e.g. `notifications/initialized`, `notifications/cancelled`).
    pub fn notify(&mut self, method: &str, params: Option<Value>) -> Result<(), String> {
        match &mut self.backend {
            Backend::Stdio(t) => t.notify(method, params),
            #[cfg(feature = "mcp-http")]
            Backend::Http(h) => h.notify(method, params),
        }
    }

    /// Set (or clear) the cooperative origin chain sent as `X-Kriya-Chain` on subsequent HTTP
    /// requests. A stdio upstream has no header to carry it on, so this is a no-op there.
    pub fn set_call_chain(&mut self, chain: Option<String>) {
        match &mut self.backend {
            Backend::Stdio(_) => {
                let _ = chain;
            }
            #[cfg(feature = "mcp-http")]
            Backend::Http(h) => h.call_chain = chain,
        }
    }

    /// Take the governed-lane io observation captured on the most recent request, if the backend
    /// records one. The HTTP transport captures `{dest_host, observed payload bytes, content hash}`
    /// (doc 24 §4.1); the stdio backend records **nothing** — a stdio child's own outbound sockets
    /// are invisible to kriya, which sees only the frame that crossed its pipe (doc 24 §4.3). The
    /// [`super::proxy_executor::McpProxyExecutor`] calls this right after `call_tool` and attaches
    /// it to the `ActionOutcome` so the governor can emit a `kriya.io.*` receipt.
    pub fn take_last_io(&mut self) -> Option<IoRecord> {
        match &mut self.backend {
            Backend::Stdio(_) => None,
            #[cfg(feature = "mcp-http")]
            Backend::Http(h) => h.last_io.take(),
        }
    }
}

impl Drop for McpClient {
    fn drop(&mut self) {
        // Best-effort: don't leave a downstream server running after the proxy exits. Dropping
        // stdin already signals EOF to a read-to-end server; kill covers the rest. No-op for an
        // in-memory test client (no child).
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// The framing + id-correlation logic, generic over the streams so it is unit-testable with
/// in-memory pipes (`Vec<u8>` writer + `Cursor`/`&[u8]` reader) instead of a real subprocess.
struct Transport<R: BufRead, W: Write> {
    reader: R,
    writer: W,
    /// Monotonic counter for the proxy's own downstream requests (disjoint from client ids).
    next_id: u64,
}

impl<R: BufRead, W: Write> Transport<R, W> {
    fn new(reader: R, writer: W) -> Self {
        Self {
            reader,
            writer,
            next_id: PROXY_ID_BASE,
        }
    }

    /// Allocate the next downstream request id.
    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Send a request, read responses until the one carrying our id arrives, return its `result`.
    /// Responses with a different id (a stray downstream notification echoed as a response, say)
    /// are skipped rather than mistaken for our reply.
    fn request(&mut self, method: &str, params: Option<Value>) -> Result<Value, String> {
        let id = self.alloc_id();
        let mut msg = json!({ "jsonrpc": "2.0", "id": id, "method": method });
        if let Some(p) = params {
            msg["params"] = p;
        }
        self.write_line(&msg.to_string())?;

        loop {
            let line = self.read_line()?;
            if line.trim().is_empty() {
                continue;
            }
            // Parse as a raw JSON value, not the `Response` struct: `jsonrpc::Response` is a
            // server-side (Serialize-only) shape we reuse UNCHANGED, so we read replies by hand.
            // A non-JSON / non-object line (a downstream-initiated request/notification) is skipped —
            // the MVP doesn't service those — and we keep waiting for our reply.
            let msg: Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            // Match our id exactly; interleaved notifications (no id) and stray ids are skipped.
            if msg.get("id") != Some(&json!(id)) {
                continue;
            }
            if let Some(err) = msg.get("error") {
                let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
                let message = err
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown error");
                return Err(format!("downstream {method} error {code}: {message}"));
            }
            return Ok(msg.get("result").cloned().unwrap_or(Value::Null));
        }
    }

    /// Send a notification — no id, no response awaited.
    fn notify(&mut self, method: &str, params: Option<Value>) -> Result<(), String> {
        let mut msg = json!({ "jsonrpc": "2.0", "method": method });
        if let Some(p) = params {
            msg["params"] = p;
        }
        self.write_line(&msg.to_string())
    }

    fn write_line(&mut self, line: &str) -> Result<(), String> {
        writeln!(self.writer, "{line}").map_err(|e| format!("write to downstream failed: {e}"))?;
        self.writer
            .flush()
            .map_err(|e| format!("flush to downstream failed: {e}"))
    }

    /// Read one line; a zero-length read is EOF (downstream closed its output / died).
    fn read_line(&mut self) -> Result<String, String> {
        let mut line = String::new();
        let n = self
            .reader
            .read_line(&mut line)
            .map_err(|e| format!("read from downstream failed: {e}"))?;
        if n == 0 {
            return Err("downstream closed its output (EOF)".into());
        }
        Ok(line)
    }
}

/// A **remote** MCP transport over Streamable HTTP + SSE (W2-2) — the broker's path to hosted MCP
/// servers. Synchronous (`ureq`, no async), matching the stdio [`Transport`]'s request→response
/// contract: POST a JSON-RPC request, read the reply from either a single JSON body or an SSE
/// stream, correlate by id. Captures and echoes the server's `Mcp-Session-Id`, and sends any
/// operator-supplied headers (e.g. `Authorization: Bearer …`) on every call.
#[cfg(feature = "mcp-http")]
struct HttpTransport {
    url: String,
    /// The destination host parsed once from `url` — the governed-lane egress dest_host (doc 24
    /// §4.1). kriya is the TLS client here, so the request body is plaintext in hand.
    host: String,
    /// Extra headers sent on every request (auth, etc.).
    extra_headers: Vec<(String, String)>,
    /// The MCP session id the server assigns on `initialize`, echoed on later requests. `None`
    /// until the server sends one (servers that don't use sessions simply never set it).
    session_id: Option<String>,
    next_id: u64,
    agent: ureq::Agent,
    /// The io observation from the most recent request — taken by the proxy executor and attached
    /// to the `ActionOutcome` for the governor to receipt. Overwritten each request; only the value
    /// read immediately after a governed `tools/call` is consumed.
    last_io: Option<IoRecord>,
    /// Credential brokering (doc 24 §11 B13 / EG-B). `None` → byte-identical to pre-EG-B: no
    /// `{{kriya:*}}` placeholder is ever substituted. When present, [`Self::request`] substitutes
    /// AFTER `last_io.content_sha256` is computed over the placeholder form, and only for an alias
    /// scoped to this transport's own `host` — see `secrets::broker_body`.
    secrets: Option<crate::secrets::SecretsPolicy>,
    /// Cooperative origin chain (C3) for the current governed call, sent as `X-Kriya-Chain`.
    /// `None` (the default, and always outside an HTTP-served broker call) → header not sent.
    call_chain: Option<String>,
}

#[cfg(feature = "mcp-http")]
impl HttpTransport {
    fn new(
        url: &str,
        extra_headers: Vec<(String, String)>,
        ssrf_guard: bool,
        secrets: Option<crate::secrets::SecretsPolicy>,
    ) -> Self {
        let agent = if ssrf_guard {
            ureq::AgentBuilder::new()
                .resolver(ssrf_safe_resolver)
                .build()
        } else {
            ureq::agent()
        };
        Self {
            url: url.to_string(),
            host: crate::permissions::url_host(url),
            extra_headers,
            session_id: None,
            next_id: PROXY_ID_BASE,
            agent,
            last_io: None,
            secrets,
            call_chain: None,
        }
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Build a POST with the MCP + session + operator headers applied.
    fn post(&self) -> ureq::Request {
        let mut req = self
            .agent
            .post(&self.url)
            .set("Content-Type", "application/json")
            // MCP Streamable HTTP: the server may reply with a single JSON object OR an SSE stream.
            .set("Accept", "application/json, text/event-stream");
        if let Some(sid) = &self.session_id {
            req = req.set("Mcp-Session-Id", sid);
        }
        for (k, v) in &self.extra_headers {
            req = req.set(k, v);
        }
        if let Some(chain) = &self.call_chain {
            req = req.set("X-Kriya-Chain", chain);
        }
        req
    }

    /// Send `method` and return its `result`. Session recovery: when the upstream has restarted —
    /// the stored `Mcp-Session-Id` is rejected (HTTP 404 / "Session not found") or the connection is
    /// refused/reset — drop the session, re-run the `initialize` handshake (capturing the new
    /// session id), and retry the original request exactly ONCE. A second failure surfaces as-is.
    /// `initialize` itself is never retried this way (it IS the handshake).
    fn request(&mut self, method: &str, params: Option<Value>) -> Result<Value, String> {
        match self.attempt(method, params.clone()) {
            Ok(v) => Ok(v),
            Err(e) if e.recoverable && method != "initialize" => {
                self.session_id = None;
                if let Err(h) = self.rehandshake() {
                    return Err(format!(
                        "{} (session recovery re-initialize failed: {h})",
                        e.message
                    ));
                }
                eprintln!(
                    "[kriya] remote MCP upstream {}: session re-established after: {}",
                    self.host, e.message
                );
                self.attempt(method, params).map_err(|e| e.message)
            }
            Err(e) => Err(e.message),
        }
    }

    /// The `initialize` + `notifications/initialized` handshake on this transport, used to recover
    /// a lost session. The per-call `X-Kriya-Chain` is withheld from the handshake (it is protocol
    /// setup, not the governed call) and restored for the retried request.
    fn rehandshake(&mut self) -> Result<(), String> {
        let chain = self.call_chain.take();
        let result = self
            .attempt("initialize", Some(initialize_params()))
            .map_err(|e| e.message)
            .and_then(|r| parse_init(&r).map(|_| ()))
            .and_then(|_| self.notify("notifications/initialized", None));
        self.call_chain = chain;
        result
    }

    /// One HTTP attempt of `method`. Classifies failures as recoverable (see [`AttemptError`]).
    fn attempt(&mut self, method: &str, params: Option<Value>) -> Result<Value, AttemptError> {
        let had_session = self.session_id.is_some();
        let id = self.alloc_id();
        let mut msg = json!({ "jsonrpc": "2.0", "id": id, "method": method });
        if let Some(p) = params {
            msg["params"] = p;
        }
        // Capture the OUTBOUND observation from the exact request body BEFORE sending — the bytes
        // that will leave, hashed as exact wire strings (kriya is the TLS client, so this is the
        // plaintext body). These are *observed payload bytes*, never wire/TLS/header/keep-alive
        // bytes (doc 24 L2/L4). Set now so the bytes are recorded even if the reply later errors;
        // `bytes_in` is filled in after the response is read. `decision` is a placeholder the
        // governor overrides from its tier decision.
        let body = msg.to_string();
        self.last_io = Some(IoRecord {
            direction: IoDirection::Egress,
            dest_host: Some(self.host.clone()),
            dest_kind: IoKind::Mcp,
            method: Some(method.to_string()),
            bytes_out: Some(body.len() as u64),
            bytes_in: None,
            bytes_in_is_partial: false,
            content_sha256: Some(sha256_hex(body.as_bytes())),
            hash_scheme: HashScheme::WireBytes,
            decision: IoDecision::Allow,
            policy_rule: None,
            approved_by: None,
            reason: None,
            server: None,
            flags: Vec::new(),
        });

        // Credential brokering (doc 24 §11 B13 / EG-B) — substitute `{{kriya:<alias>}}` placeholders
        // with the real secret AFTER `last_io.content_sha256` above was computed over `body` (the
        // placeholder form), and only in THIS separate `send_body`, never touching `body` itself — so
        // the receipt, and anything derived from `body` after this point, never sees the real value.
        // The governor's OWN pre-check (`mcp::governor::egress_gate`) already verified every alias
        // here is configured and scoped to this host; this is the actual enforcement (defense in
        // depth, same dual-layer shape as the B6 SSRF guard) and fails closed independently of it.
        let send_body = match &self.secrets {
            Some(secrets) => crate::secrets::broker_body(&body, secrets, &self.host)
                .map_err(AttemptError::fatal)?,
            None => zeroize::Zeroizing::new(body.clone()),
        };

        let resp = match self.post().send_string(&send_body) {
            Ok(r) => r,
            Err(ureq::Error::Status(code, r)) => {
                let body = r.into_string().unwrap_or_default();
                // 404 on an established session = the server no longer knows our session id
                // (MCP streamable HTTP: the client MUST start a new session).
                let session_lost = had_session
                    && (code == 404 || body.contains("Session not found"));
                return Err(AttemptError {
                    message: format!(
                        "remote {method} HTTP {code}: {}",
                        body.trim().chars().take(300).collect::<String>()
                    ),
                    recoverable: session_lost,
                });
            }
            Err(ureq::Error::Transport(t)) => {
                return Err(AttemptError {
                    recoverable: is_reconnectable(&t),
                    message: format!("remote {method} request failed: {t}"),
                })
            }
        };

        // Capture the session id the server assigns (typically on the initialize reply).
        if let Some(sid) = resp.header("Mcp-Session-Id") {
            self.session_id = Some(sid.to_string());
        }

        if resp.content_type().contains("event-stream") {
            // SSE: count the bytes CONSUMED up to the correlated reply and flag the count partial —
            // an early-return stream is never fully drained, so `bytes_in` is a lower bound (L2).
            let (value, consumed) =
                sse_find_result_counted(BufReader::new(resp.into_reader()), id, method)
                    .map_err(|m| AttemptError {
                        recoverable: had_session && m.contains("Session not found"),
                        message: m,
                    })?;
            if let Some(io) = self.last_io.as_mut() {
                io.bytes_in = Some(consumed);
                io.bytes_in_is_partial = true;
            }
            Ok(value)
        } else {
            let body = resp
                .into_string()
                .map_err(|e| AttemptError::fatal(format!("remote {method}: reading body: {e}")))?;
            if let Some(io) = self.last_io.as_mut() {
                io.bytes_in = Some(body.len() as u64);
            }
            let v: Value = serde_json::from_str(&body).map_err(|e| {
                AttemptError::fatal(format!("remote {method}: reply is not JSON: {e}"))
            })?;
            extract_result(&v, id, method).map_err(|message| AttemptError {
                recoverable: had_session && is_session_not_found(&v),
                message,
            })
        }
    }

    fn notify(&mut self, method: &str, params: Option<Value>) -> Result<(), String> {
        let mut msg = json!({ "jsonrpc": "2.0", "method": method });
        if let Some(p) = params {
            msg["params"] = p;
        }
        match self.post().send_string(&msg.to_string()) {
            // The spec returns 202 Accepted (a 2xx, so ureq gives Ok) with no body — ignore it.
            Ok(_) => Ok(()),
            Err(ureq::Error::Status(code, _)) => Err(format!("remote notify {method} HTTP {code}")),
            Err(e) => Err(format!("remote notify {method} failed: {e}")),
        }
    }
}

/// The SSE event-loop, generic over the byte source so it is unit-testable with an in-memory
/// stream (no `ureq::Response`). Correlates the first `data:` event that parses to a JSON-RPC
/// message with the matching `id`, and returns the stream bytes CONSUMED to reach it. That count is
/// a lower bound — the stream is not drained after the correlated reply — so the caller flags
/// `bytes_in` partial (doc 24 L2).
#[cfg(feature = "mcp-http")]
fn sse_find_result_counted<R: BufRead>(
    reader: R,
    id: u64,
    method: &str,
) -> Result<(Value, u64), String> {
    let mut data = String::new();
    let mut consumed: u64 = 0;
    let check = |data: &str| -> Option<Result<Value, String>> {
        if data.is_empty() {
            return None;
        }
        match serde_json::from_str::<Value>(data) {
            Ok(v) if v.get("id") == Some(&json!(id)) => Some(extract_result(&v, id, method)),
            _ => None, // a notification, a different id, or a partial event — keep reading
        }
    };
    for line in reader.lines() {
        let line = line.map_err(|e| format!("remote {method}: SSE read: {e}"))?;
        consumed += line.len() as u64 + 1; // +1 approximates the newline the line iterator strips
        if let Some(rest) = line.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(rest.trim_start());
        } else if line.is_empty() {
            // Blank line ends one SSE event — try to correlate, then reset for the next event.
            if let Some(found) = check(&data) {
                return found.map(|v| (v, consumed));
            }
            data.clear();
        }
        // `event:` / `id:` / comment (`:`) lines carry no JSON-RPC payload — ignore.
    }
    // A stream that ended without a terminating blank line: try the trailing event.
    if let Some(found) = check(&data) {
        return found.map(|v| (v, consumed));
    }
    Err(format!(
        "remote {method}: SSE stream ended before a reply for id {id}"
    ))
}

/// Back-compat wrapper returning just the correlated value (the unit tests drive this directly).
#[cfg(all(test, feature = "mcp-http"))]
fn sse_find_result<R: BufRead>(reader: R, id: u64, method: &str) -> Result<Value, String> {
    sse_find_result_counted(reader, id, method).map(|(v, _)| v)
}

/// Lowercase-hex SHA-256 — the content commitment for a captured egress observation (over the exact
/// wire request body; `hash_scheme: wire-bytes`).
#[cfg(feature = "mcp-http")]
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// The `initialize` params this client sends — shared by [`McpClient::initialize`] and the HTTP
/// transport's session-recovery re-handshake.
fn initialize_params() -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        // The proxy is itself an MCP client to the downstream; advertise nothing we don't
        // proxy. Downstream-initiated sampling/elicitation is the full-lifecycle concern.
        "capabilities": {},
        "clientInfo": { "name": "kriya-gateway", "version": env!("CARGO_PKG_VERSION") },
    })
}

/// One failed HTTP attempt. `recoverable` marks the failures a restarted upstream produces — the
/// old `Mcp-Session-Id` rejected (HTTP 404, or a JSON-RPC "Session not found" error) or the
/// connection refused/reset (the pod's address changed) — which earn one re-handshake + one retry.
#[cfg(feature = "mcp-http")]
struct AttemptError {
    message: String,
    recoverable: bool,
}

#[cfg(feature = "mcp-http")]
impl AttemptError {
    fn fatal(message: String) -> Self {
        Self { message, recoverable: false }
    }
}

/// A transport failure that a restarted upstream causes: connection refused, or the (possibly
/// pooled) connection reset/aborted/closed under us. Timeouts are deliberately NOT included — a
/// timed-out `tools/call` may still be running server-side, and replaying it is not ours to decide.
#[cfg(feature = "mcp-http")]
fn is_reconnectable(t: &ureq::Transport) -> bool {
    use std::error::Error as _;
    match t.kind() {
        ureq::ErrorKind::ConnectionFailed => true,
        ureq::ErrorKind::Io => {
            let mut src = t.source();
            while let Some(e) = src {
                if let Some(io) = e.downcast_ref::<std::io::Error>() {
                    return matches!(
                        io.kind(),
                        std::io::ErrorKind::ConnectionRefused
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::BrokenPipe
                            | std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::NotConnected
                    );
                }
                src = e.source();
            }
            false
        }
        _ => false,
    }
}

/// Whether a JSON-RPC reply is the server saying our session id is unknown to it.
#[cfg(feature = "mcp-http")]
fn is_session_not_found(v: &Value) -> bool {
    v.get("error")
        .and_then(|e| e.get("message"))
        .and_then(Value::as_str)
        .is_some_and(|m| m.contains("Session not found"))
}

/// Pull `result` out of a JSON-RPC response value (or map a JSON-RPC error to `Err`). Shared by the
/// single-JSON and SSE HTTP reply paths; mirrors the stdio transport's error mapping.
#[cfg(feature = "mcp-http")]
fn extract_result(v: &Value, id: u64, method: &str) -> Result<Value, String> {
    if v.get("id") != Some(&json!(id)) {
        return Err(format!(
            "remote {method}: reply id mismatch (expected {id})"
        ));
    }
    if let Some(err) = v.get("error") {
        let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
        let message = err
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("unknown error");
        return Err(format!("remote {method} error {code}: {message}"));
    }
    Ok(v.get("result").cloned().unwrap_or(Value::Null))
}

/// Parse an `InitializeResult` from a raw `result` value (camelCase wire shape).
fn parse_init(result: &Value) -> Result<InitializeResult, String> {
    // `InitializeResult` only derives Serialize (it's a server-side shape), so reconstruct the
    // fields we actually need from the wire JSON rather than deserializing into it.
    let protocol_version = result
        .get("protocolVersion")
        .and_then(Value::as_str)
        .unwrap_or(PROTOCOL_VERSION);
    // We don't reuse the downstream's exact string for protocol_version (the field is &'static);
    // InitializeResult::new pins ours and we override server_info below. capabilities pass through.
    let _ = protocol_version;
    let name = result
        .get("serverInfo")
        .and_then(|s| s.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("downstream")
        .to_string();
    let version = result
        .get("serverInfo")
        .and_then(|s| s.get("version"))
        .and_then(Value::as_str)
        .unwrap_or("0.0.0")
        .to_string();
    let mut init = InitializeResult::new(name, version);
    if let Some(caps) = result.get("capabilities") {
        init.capabilities = caps.clone();
    }
    Ok(init)
}

/// Parse a `ListToolsResult` from a raw `result` value.
fn parse_tools(result: &Value) -> Result<ListToolsResult, String> {
    let arr = result
        .get("tools")
        .and_then(Value::as_array)
        .ok_or("downstream tools/list result has no `tools` array")?;
    let mut tools = Vec::with_capacity(arr.len());
    for t in arr {
        let name = t
            .get("name")
            .and_then(Value::as_str)
            .ok_or("a downstream tool entry has no `name`")?
            .to_string();
        let description = t
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let input_schema = t
            .get("inputSchema")
            .cloned()
            .unwrap_or_else(|| json!({ "type": "object" }));
        tools.push(Tool {
            name,
            description,
            input_schema,
        });
    }
    Ok(ListToolsResult { tools })
}

/// Build a `CallToolResult` from a raw downstream `result` value. `jsonrpc::CallToolResult` is a
/// server-side (Serialize-only) shape we reuse UNCHANGED, so we read the wire fields by hand:
/// `content` (default empty) and `isError` (MCP convention: tool failure is a *result* flag, not a
/// protocol error). A downstream that omits `content` on success still yields a well-formed result.
fn parse_call_result(result: &Value) -> CallToolResult {
    let content = result
        .get("content")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let is_error = result
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    CallToolResult { content, is_error }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Drive a `Transport` with a canned downstream reply and assert the request framing + id
    /// correlation — no subprocess. The proxy's first downstream id is `PROXY_ID_BASE` (1).
    #[test]
    fn request_writes_framed_json_and_correlates_the_reply() {
        let downstream = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n";
        let mut sent: Vec<u8> = Vec::new();
        {
            let mut t = Transport::new(Cursor::new(downstream), &mut sent);
            let result = t.request("tools/list", Some(json!({}))).unwrap();
            assert_eq!(result, json!({ "ok": true }));
        }
        // The request we wrote carries jsonrpc, the allocated id (1), method, and params.
        let line = String::from_utf8(sent).unwrap();
        let v: Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["id"], json!(1));
        assert_eq!(v["method"], "tools/list");
        assert!(v["params"].is_object());
    }

    #[test]
    fn request_ids_are_monotonic_and_disjoint_from_client_ids() {
        // Two replies, ids 1 then 2 — the proxy's own counter advances per request.
        let downstream = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":1}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":2}\n",
        );
        let mut sent: Vec<u8> = Vec::new();
        let mut t = Transport::new(Cursor::new(downstream), &mut sent);
        assert_eq!(t.request("a", None).unwrap(), json!(1));
        assert_eq!(t.request("b", None).unwrap(), json!(2));
    }

    #[test]
    fn request_skips_interleaved_notifications_and_mismatched_ids() {
        // A downstream notification (no id) and a stray response with a different id precede our
        // real reply (id 1). Both must be skipped, not mistaken for the answer.
        let downstream = concat!(
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":999,\"result\":\"stray\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"mine\"}\n",
        );
        let mut sent: Vec<u8> = Vec::new();
        let mut t = Transport::new(Cursor::new(downstream), &mut sent);
        assert_eq!(t.request("tools/call", None).unwrap(), json!("mine"));
    }

    #[test]
    fn request_surfaces_a_downstream_error_as_err() {
        let downstream =
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32601,\"message\":\"nope\"}}\n";
        let mut sent: Vec<u8> = Vec::new();
        let mut t = Transport::new(Cursor::new(downstream), &mut sent);
        let err = t.request("frobnicate", None).unwrap_err();
        assert!(err.contains("nope"), "got: {err}");
    }

    #[test]
    fn request_errors_on_eof_instead_of_panicking() {
        let mut sent: Vec<u8> = Vec::new();
        let mut t = Transport::new(Cursor::new(""), &mut sent); // immediate EOF
        let err = t.request("tools/list", None).unwrap_err();
        assert!(err.contains("EOF"), "got: {err}");
    }

    #[test]
    fn notify_writes_no_id_and_awaits_nothing() {
        let mut sent: Vec<u8> = Vec::new();
        {
            let mut t = Transport::new(Cursor::new(""), &mut sent);
            t.notify("notifications/initialized", None).unwrap();
        }
        let line = String::from_utf8(sent).unwrap();
        let v: Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(v["method"], "notifications/initialized");
        assert!(v.get("id").is_none(), "a notification must carry no id");
    }

    #[test]
    fn parse_tools_reads_camel_case_input_schema() {
        let result = json!({
            "tools": [
                { "name": "get_x", "description": "read x", "inputSchema": { "type": "object" } },
                { "name": "delete_x" } // description + schema default
            ]
        });
        let parsed = parse_tools(&result).unwrap();
        assert_eq!(parsed.tools.len(), 2);
        assert_eq!(parsed.tools[0].name, "get_x");
        assert_eq!(parsed.tools[0].input_schema, json!({ "type": "object" }));
        assert_eq!(parsed.tools[1].name, "delete_x");
        assert_eq!(parsed.tools[1].input_schema, json!({ "type": "object" }));
    }

    #[test]
    fn parse_init_keeps_downstream_capabilities_and_server_name() {
        let result = json!({
            "protocolVersion": "2025-06-18",
            "capabilities": { "tools": { "listChanged": true }, "resources": {} },
            "serverInfo": { "name": "actual-mcp", "version": "1.2.3" }
        });
        let init = parse_init(&result).unwrap();
        assert_eq!(init.server_info.name, "actual-mcp");
        assert_eq!(init.server_info.version, "1.2.3");
        assert_eq!(init.capabilities["resources"], json!({}));
    }

    // ── W2-2: remote HTTP transport SSE parsing ──────────────────────────────────────────────

    #[cfg(feature = "mcp-http")]
    #[test]
    fn sse_correlates_the_matching_event_and_skips_notifications() {
        // A progress notification (no id) precedes our real reply (id 1). Standard SSE framing:
        // `event:`/`data:` lines, events separated by a blank line.
        let stream = concat!(
            "event: message\n",
            "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n",
            "\n",
            "event: message\n",
            "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n",
            "\n",
        );
        let got = sse_find_result(Cursor::new(stream), 1, "tools/call").unwrap();
        assert_eq!(got, json!({ "ok": true }));
    }

    #[cfg(feature = "mcp-http")]
    #[test]
    fn sse_maps_a_jsonrpc_error_event_to_err() {
        let stream = "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32000,\"message\":\"boom\"}}\n\n";
        let err = sse_find_result(Cursor::new(stream), 1, "tools/call").unwrap_err();
        assert!(err.contains("boom"), "got: {err}");
    }

    #[cfg(feature = "mcp-http")]
    #[test]
    fn sse_without_a_matching_reply_is_an_error_not_a_hang() {
        // Only a mismatched id — the stream ends without our reply.
        let stream = "data: {\"jsonrpc\":\"2.0\",\"id\":99,\"result\":1}\n\n";
        let err = sse_find_result(Cursor::new(stream), 1, "tools/list").unwrap_err();
        assert!(err.contains("ended before a reply"), "got: {err}");
    }

    #[cfg(feature = "mcp-http")]
    #[test]
    fn sse_handles_a_trailing_event_without_a_final_blank_line() {
        let stream = "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"tail\"}";
        let got = sse_find_result(Cursor::new(stream), 1, "ping").unwrap();
        assert_eq!(got, json!("tail"));
    }

    /// L2: the SSE reader counts the bytes CONSUMED up to the correlated reply — the `bytes_in` the
    /// transport records is that count, flagged partial (the stream is never fully drained).
    #[cfg(feature = "mcp-http")]
    #[test]
    fn sse_counted_reports_bytes_consumed_up_to_the_reply() {
        let stream = concat!(
            "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n",
            "\n",
            "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n",
            "\n",
        );
        let (val, consumed) =
            sse_find_result_counted(Cursor::new(stream), 1, "tools/call").unwrap();
        assert_eq!(val, json!({ "ok": true }));
        assert!(
            consumed > 0 && consumed <= stream.len() as u64 + 4,
            "observed payload bytes are counted as a lower bound: {consumed}"
        );
    }

    // B6 SSRF/rebinding guard — transport-level resolver pin (doc 24 §11 B6).

    #[cfg(feature = "mcp-http")]
    #[test]
    fn b6_rebinding_fixture_pins_to_the_one_safe_address_never_the_forbidden_one() {
        // A synthetic DNS answer mixing a forbidden (rebound-to) address with a legitimate one —
        // the exact shape a DNS-rebinding attack produces. Forbidden listed FIRST specifically to
        // prove the filter, not list order, decides the outcome.
        let addrs = vec![
            "169.254.169.254:443".parse().unwrap(), // cloud metadata — forbidden
            "93.184.216.34:443".parse().unwrap(),   // ordinary public address — safe
        ];
        let picked = pick_safe_address(addrs.into_iter());
        assert_eq!(picked, Some("93.184.216.34:443".parse().unwrap()));
    }

    #[cfg(feature = "mcp-http")]
    #[test]
    fn b6_rebinding_fixture_denies_when_every_resolved_address_is_forbidden() {
        let addrs = vec![
            "127.0.0.1:443".parse().unwrap(),
            "169.254.169.254:443".parse().unwrap(),
        ];
        assert_eq!(pick_safe_address(addrs.into_iter()), None);
    }

    #[cfg(feature = "mcp-http")]
    #[test]
    fn b6_ordinary_single_address_host_resolves_normally() {
        let addrs = vec!["93.184.216.34:443".parse().unwrap()];
        assert_eq!(
            pick_safe_address(addrs.into_iter()),
            Some("93.184.216.34:443".parse().unwrap())
        );
    }
}
