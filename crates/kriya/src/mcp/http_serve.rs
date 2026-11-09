//! Streamable-HTTP **serve** mode for the broker (`kriya-gateway broker --listen <addr>`) — the
//! sidecar lane: the same [`RouterServer`] the stdio broker drives, reached over HTTP at `/mcp`
//! instead of over a parent's stdin/stdout.
//!
//! ## What it speaks (and what it doesn't)
//! The MCP Streamable-HTTP transport, the subset a request/response tool server needs:
//! - `POST /mcp` with one JSON-RPC message or a batch array → `200 application/json` carrying the
//!   response (an array for a batch). Notifications / client responses only → `202`, empty body.
//!   Malformed JSON → `400` with a JSON-RPC parse error. Bodies over 1 MiB → `413`.
//! - The `initialize` response carries a fresh `Mcp-Session-Id`; later requests may echo any value
//!   (or none) — the broker keeps no per-session state, so it never requires or checks it.
//! - `GET /mcp` → `405` (**no server-initiated SSE stream in this version**), `DELETE /mcp` → `200`
//!   (session end; nothing to tear down), `OPTIONS` → `204` (CORS only for `http://127.0.0.1[:port]`
//!   origins). Any other path → `404`. Every response is `Connection: close` (no keep-alive).
//! - It always answers JSON, never SSE — permitted by the spec even when the client's `Accept`
//!   lists `text/event-stream`, and what the official SDK clients accept.
//!
//! ## One governor, sequential
//! One [`RouterServer`] (one governor, one signed chain, one approval gate, one budget) sits behind a
//! `Mutex`; connections are accepted on a thread each, but requests are handled one at a time.
//!
//! ## Cooperative origin chain (C3)
//! An inbound `X-Kriya-Chain: a,b` header (validated by [`parse_chain_header`]; invalid ⇒ ignored)
//! plus this hop's actor label becomes the per-request chain `[a, b, <actor>]`: every receipt the
//! governor signs for that request carries it as the `chain` param, and an HTTP upstream's
//! `tools/call` carries it onward as `X-Kriya-Chain: a,b,<actor>`. It is *cooperative*: a caller can
//! claim any upstream hops it likes — the chain records what was asserted, not what was proven.
//!
//! Std-only (one `TcpListener`, thread per connection) — the same hand-rolled idiom as
//! [`super::contain`] and the LLM proxy; no HTTP-server crate.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde_json::{json, Value};

use super::jsonrpc::{error_code, Request, Response};
use super::router::RouterServer;

/// The one path the transport is served on.
pub const MCP_PATH: &str = "/mcp";
/// Request body cap (bytes). Larger → `413`.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;
/// How much of an oversized body is drained (read and discarded) before answering `413`, so the
/// client sees the status instead of a connection reset. Beyond this the connection is just closed.
const MAX_DRAIN_BYTES: usize = 16 * 1024 * 1024;
/// Header-section cap, so a client can't stream an unbounded header block.
const MAX_HEADER_BYTES: usize = 64 * 1024;
/// The cooperative origin-chain header (C3).
pub const CHAIN_HEADER: &str = "X-Kriya-Chain";
/// Chain limits: at most this many inbound entries, each at most this many bytes.
pub const MAX_CHAIN_ENTRIES: usize = 16;
pub const MAX_CHAIN_ENTRY_BYTES: usize = 64;

/// Bind `listen`, serve the broker over streamable HTTP, and block forever (until the accept loop
/// fails). Prints nothing — the caller owns the startup line (see [`spawn`] for the bound address).
pub fn serve_http(listen: &str, server: RouterServer, chain_actor: &str) -> std::io::Result<()> {
    let (_addr, handle) = spawn(listen, server, chain_actor)?;
    handle
        .join()
        .map_err(|_| std::io::Error::other("http serve accept loop panicked"))
}

/// Bind `listen` (e.g. `127.0.0.1:0` for an OS-assigned port) and run the accept loop on a
/// background thread. Returns the **bound** address (so a caller binding port 0 learns the real
/// port) and the accept thread's handle. `chain_actor` is this hop's entry appended to every
/// request's origin chain (sanitized to the chain alphabet).
pub fn spawn(
    listen: &str,
    server: RouterServer,
    chain_actor: &str,
) -> std::io::Result<(SocketAddr, JoinHandle<()>)> {
    let listener = TcpListener::bind(listen)?;
    let addr = listener.local_addr()?;
    let server = Arc::new(Mutex::new(server));
    let actor = Arc::new(sanitize_chain_entry(chain_actor));
    let handle = thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let server = server.clone();
            let actor = actor.clone();
            thread::spawn(move || handle_connection(stream, &server, &actor));
        }
    });
    Ok((addr, handle))
}

/// Validate an inbound `X-Kriya-Chain` value: comma-separated tokens of `[A-Za-z0-9._:/-]`, at most
/// [`MAX_CHAIN_ENTRIES`] entries, each 1..=[`MAX_CHAIN_ENTRY_BYTES`] bytes (surrounding whitespace
/// trimmed). Anything else ⇒ `None` — an invalid chain is ignored wholesale, never partially kept.
pub fn parse_chain_header(value: &str) -> Option<Vec<String>> {
    let entries: Vec<String> = value.split(',').map(|e| e.trim().to_string()).collect();
    if entries.is_empty() || entries.len() > MAX_CHAIN_ENTRIES {
        return None;
    }
    if entries.iter().all(|e| valid_chain_entry(e)) {
        Some(entries)
    } else {
        None
    }
}

fn valid_chain_entry(e: &str) -> bool {
    !e.is_empty() && e.len() <= MAX_CHAIN_ENTRY_BYTES && e.bytes().all(chain_byte_ok)
}

fn chain_byte_ok(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'/' | b'-')
}

/// Map an operator-supplied actor label into the chain alphabet (other bytes → `_`, truncated to
/// [`MAX_CHAIN_ENTRY_BYTES`]; empty → `broker`) so this hop's own entry is always a valid token.
fn sanitize_chain_entry(label: &str) -> String {
    let s: String = label
        .chars()
        .map(|c| if c.is_ascii() && chain_byte_ok(c as u8) { c } else { '_' })
        .take(MAX_CHAIN_ENTRY_BYTES)
        .collect();
    if s.is_empty() {
        "broker".to_string()
    } else {
        s
    }
}

// ─── HTTP plumbing ──────────────────────────────────────────────────────────────────────────────

struct HttpRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
}

impl HttpRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

enum Body {
    Ok(Vec<u8>),
    TooLarge,
}

fn read_head(reader: &mut impl BufRead) -> std::io::Result<Option<HttpRequest>> {
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(None);
    }
    let trimmed = request_line.trim_end_matches(['\r', '\n']);
    let mut parts = trimmed.splitn(3, ' ');
    let (Some(method), Some(target), Some(_version)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "malformed request line",
        ));
    };
    // The path without any query string.
    let path = target.split('?').next().unwrap_or("").to_string();
    let mut headers = Vec::new();
    let mut total = 0usize;
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break;
        }
        total += n;
        if total > MAX_HEADER_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "header section too large",
            ));
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Ok(Some(HttpRequest {
        method: method.to_string(),
        path,
        headers,
    }))
}

/// Read the request body (Content-Length or chunked), capped at [`MAX_BODY_BYTES`]. An oversized
/// body is drained up to [`MAX_DRAIN_BYTES`] so the `413` reaches the client cleanly.
fn read_body(reader: &mut impl BufRead, req: &HttpRequest) -> std::io::Result<Body> {
    let chunked = req
        .header("transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    if chunked {
        return read_chunked(reader);
    }
    let Some(len) = req
        .header("content-length")
        .and_then(|v| v.parse::<usize>().ok())
    else {
        return Ok(Body::Ok(Vec::new()));
    };
    if len > MAX_BODY_BYTES {
        if len <= MAX_DRAIN_BYTES {
            let _ = std::io::copy(&mut reader.take(len as u64), &mut std::io::sink());
        }
        return Ok(Body::TooLarge);
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(Body::Ok(buf))
}

fn read_chunked(reader: &mut impl BufRead) -> std::io::Result<Body> {
    let mut out = Vec::new();
    let mut seen = 0usize;
    let mut too_large = false;
    loop {
        let mut size_line = String::new();
        if reader.read_line(&mut size_line)? == 0 {
            break;
        }
        let size_str = size_line.trim().split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_str, 16).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed chunk size")
        })?;
        if size == 0 {
            loop {
                let mut trailer = String::new();
                if reader.read_line(&mut trailer)? == 0 || trailer.trim().is_empty() {
                    break;
                }
            }
            break;
        }
        seen = seen.saturating_add(size);
        if seen > MAX_DRAIN_BYTES {
            return Ok(Body::TooLarge);
        }
        if seen > MAX_BODY_BYTES {
            too_large = true;
            out = Vec::new();
            std::io::copy(&mut reader.take(size as u64), &mut std::io::sink())?;
        } else {
            let mut chunk = vec![0u8; size];
            reader.read_exact(&mut chunk)?;
            out.extend_from_slice(&chunk);
        }
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf)?;
    }
    Ok(if too_large { Body::TooLarge } else { Body::Ok(out) })
}

fn status_text(status: u16) -> &'static str {
    match status {
        200 => "OK",
        202 => "Accepted",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        _ => "Unknown",
    }
}

fn write_response(
    w: &mut impl Write,
    status: u16,
    headers: &[(&str, String)],
    body: Option<&str>,
) -> std::io::Result<()> {
    let mut head = format!("HTTP/1.1 {status} {}\r\n", status_text(status));
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    let body = body.unwrap_or("");
    if !body.is_empty() {
        head.push_str("Content-Type: application/json\r\n");
    }
    head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    head.push_str("Connection: close\r\n\r\n");
    w.write_all(head.as_bytes())?;
    w.write_all(body.as_bytes())?;
    w.flush()
}

/// `Origin` values allowed CORS access: `http://127.0.0.1` with an optional port only.
fn loopback_origin(origin: Option<&str>) -> Option<String> {
    let o = origin?;
    let rest = o.strip_prefix("http://127.0.0.1")?;
    let ok = rest.is_empty()
        || rest
            .strip_prefix(':')
            .is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    ok.then(|| o.to_string())
}

fn cors_headers(origin: &str) -> Vec<(&'static str, String)> {
    vec![
        ("Access-Control-Allow-Origin", origin.to_string()),
        ("Vary", "Origin".to_string()),
        ("Access-Control-Expose-Headers", "Mcp-Session-Id".to_string()),
    ]
}

fn handle_connection(stream: TcpStream, server: &Mutex<RouterServer>, actor: &str) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
    let Ok(read_half) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(read_half);
    let mut writer = stream;

    let req = match read_head(&mut reader) {
        Ok(Some(r)) => r,
        Ok(None) => return,
        Err(_) => {
            let _ = write_response(&mut writer, 400, &[], None);
            return;
        }
    };
    let cors = loopback_origin(req.header("origin"));
    let mut headers: Vec<(&str, String)> = cors.as_deref().map(cors_headers).unwrap_or_default();

    if req.path != MCP_PATH {
        let _ = write_response(&mut writer, 404, &headers, None);
        return;
    }
    match req.method.as_str() {
        "POST" => {}
        "DELETE" => {
            // Session end: the broker keeps no per-session state, so there is nothing to tear down.
            let _ = write_response(&mut writer, 200, &headers, None);
            return;
        }
        "OPTIONS" => {
            if cors.is_some() {
                headers.push(("Access-Control-Allow-Methods", "POST, DELETE, OPTIONS".into()));
                headers.push((
                    "Access-Control-Allow-Headers",
                    "Content-Type, Accept, Mcp-Session-Id, MCP-Protocol-Version, X-Kriya-Chain"
                        .into(),
                ));
            }
            let _ = write_response(&mut writer, 204, &headers, None);
            return;
        }
        _ => {
            // GET (a server-initiated SSE stream) is not offered in this version.
            headers.push(("Allow", "POST, DELETE".into()));
            let _ = write_response(&mut writer, 405, &headers, None);
            return;
        }
    }

    let body = match read_body(&mut reader, &req) {
        Ok(Body::Ok(b)) => b,
        Ok(Body::TooLarge) => {
            let err = Response::error(
                Value::Null,
                error_code::INVALID_REQUEST,
                format!("request body exceeds {MAX_BODY_BYTES} bytes"),
            );
            let _ = write_response(&mut writer, 413, &headers, Some(&err.to_line()));
            return;
        }
        Err(_) => {
            let _ = write_response(&mut writer, 400, &headers, None);
            return;
        }
    };

    let chain = {
        let mut c = req
            .header(CHAIN_HEADER)
            .and_then(parse_chain_header)
            .unwrap_or_default();
        c.push(actor.to_string());
        c
    };

    let (status, extra, out) = dispatch_body(&body, server, chain);
    headers.extend(extra);
    let _ = write_response(&mut writer, status, &headers, out.as_deref());
}

/// Parse + route one POST body. Returns `(status, extra headers, response body)`.
fn dispatch_body(
    body: &[u8],
    server: &Mutex<RouterServer>,
    chain: Vec<String>,
) -> (u16, Vec<(&'static str, String)>, Option<String>) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            let err = Response::error(
                Value::Null,
                error_code::PARSE_ERROR,
                format!("parse error: {e}"),
            );
            return (400, Vec::new(), Some(err.to_line()));
        }
    };
    let (messages, batch) = match parsed {
        Value::Array(items) if items.is_empty() => {
            let err = Response::error(Value::Null, error_code::INVALID_REQUEST, "empty batch");
            return (400, Vec::new(), Some(err.to_line()));
        }
        Value::Array(items) => (items, true),
        other => (vec![other], false),
    };

    let mut responses: Vec<Value> = Vec::new();
    let mut initialized = false;
    {
        let mut guard = match server.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.set_call_chain(Some(chain));
        for msg in messages {
            // A JSON-RPC *response* from the client (to a server request we never send) or any
            // other method-less object: accepted, nothing to answer.
            if msg.get("method").is_none()
                && (msg.get("result").is_some() || msg.get("error").is_some())
            {
                continue;
            }
            let resp = match serde_json::from_value::<Request>(msg) {
                Ok(req) => {
                    if req.method == "initialize" && !req.is_notification() {
                        initialized = true;
                    }
                    guard.handle(req)
                }
                Err(e) => Some(Response::error(
                    Value::Null,
                    error_code::INVALID_REQUEST,
                    format!("invalid request: {e}"),
                )),
            };
            if let Some(r) = resp {
                responses.push(serde_json::to_value(&r).unwrap_or_else(|_| {
                    json!({"jsonrpc":"2.0","id":null,"error":{"code":error_code::INTERNAL_ERROR,"message":"failed to serialize response"}})
                }));
            }
        }
        guard.set_call_chain(None);
    }

    let mut extra = Vec::new();
    if initialized {
        extra.push(("Mcp-Session-Id", uuid::Uuid::new_v4().to_string()));
    }
    if responses.is_empty() {
        return (202, extra, None);
    }
    let out = if batch {
        Value::Array(responses).to_string()
    } else {
        responses.remove(0).to_string()
    };
    (200, extra, Some(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_header_accepts_valid_tokens() {
        assert_eq!(
            parse_chain_header("fieldwatch, coordinator"),
            Some(vec!["fieldwatch".into(), "coordinator".into()])
        );
        assert_eq!(
            parse_chain_header("spiffe://a.b/c-d_e:1"),
            Some(vec!["spiffe://a.b/c-d_e:1".into()])
        );
    }

    #[test]
    fn chain_header_rejects_invalid_wholesale() {
        assert_eq!(parse_chain_header(""), None);
        assert_eq!(parse_chain_header("a,,b"), None);
        assert_eq!(parse_chain_header("a,b c"), None);
        assert_eq!(parse_chain_header("a,\"b\""), None);
        assert_eq!(parse_chain_header(&"x".repeat(65)), None);
        assert!(parse_chain_header(&"x".repeat(64)).is_some());
        let sixteen = vec!["a"; 16].join(",");
        assert!(parse_chain_header(&sixteen).is_some());
        let seventeen = vec!["a"; 17].join(",");
        assert_eq!(parse_chain_header(&seventeen), None);
    }

    #[test]
    fn actor_label_is_sanitized_into_the_chain_alphabet() {
        assert_eq!(sanitize_chain_entry("broker-actor"), "broker-actor");
        assert_eq!(sanitize_chain_entry("my agent,1"), "my_agent_1");
        assert_eq!(sanitize_chain_entry(""), "broker");
        assert_eq!(sanitize_chain_entry(&"y".repeat(100)).len(), 64);
    }

    #[test]
    fn cors_only_for_loopback_ip_origins() {
        assert!(loopback_origin(Some("http://127.0.0.1")).is_some());
        assert!(loopback_origin(Some("http://127.0.0.1:5173")).is_some());
        assert!(loopback_origin(Some("http://127.0.0.1.evil.com")).is_none());
        assert!(loopback_origin(Some("http://127.0.0.1:80@evil.com")).is_none());
        assert!(loopback_origin(Some("https://example.com")).is_none());
        assert!(loopback_origin(None).is_none());
    }
}
