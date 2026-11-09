//! Containment (doc 24 §11 B14 / EG-C): force a **launched** agent's network egress through the
//! governed lane so the allowlist, byte budgets, and detection pack (EG-2/EG-P) actually *enforce*
//! instead of merely observing — closing the `curl`/subprocess bypass every governed-lane receipt
//! honestly discloses. This is WATCHER-ROADMAP W4 (macOS launch-under), pulled forward as the
//! parity answer to a competitor's OS-level traffic forcing.
//!
//! ## The spike (doc 24 §11.3, run live before this module was written)
//! `log stream --style ndjson` fidelity for child-subtree exec/file events was measured on real
//! hardware: a marker planted in a child process's argv/environment produced **zero** matching
//! log lines (macOS unified logging does not expose `execve` argv without EndpointSecurity or
//! dtrace-level instrumentation, neither of which this module uses). Per the pre-registered
//! fallback, **containment narrows to egress-only** — this module claims NOTHING about file or
//! process visibility inside the sandbox, only network egress.
//!
//! ## What this actually does
//! 1. [`seatbelt_profile`] generates a Seatbelt (`sandbox-exec`) profile that denies all outbound
//!    network except a loopback connection to this process's own [`ConnectProxy`] port — verified
//!    working on real hardware (loopback:port succeeds, an external host is refused with
//!    "Operation not permitted").
//! 2. [`ConnectProxy`] is a plain HTTP CONNECT tunnel: it evaluates the requested host against the
//!    installed [`EgressPolicy`], either tunnels the bytes **unmodified** (no TLS termination — the
//!    agent's TLS session is end-to-end intact) or refuses the CONNECT, and emits a signed
//!    `kriya.io.egress.http.{allow,deny}` receipt either way, at the decision point (L10).
//!    The same listener also forwards **plain HTTP** sent in absolute-form
//!    (`POST http://svc:9000/mcp HTTP/1.1`, what an `HTTP_PROXY`-honouring client emits for an
//!    `http://` URL): same policy evaluation, same receipts (plus `scheme`/`method`/`path`/`chain`
//!    params), one request per connection, re-sent upstream in origin-form with hop-by-hop headers
//!    stripped and the cooperative `X-Kriya-Chain` origin-chain header appended.
//! 3. The `kriya-gateway run -- <cmd>` subcommand (in the binary) bookends a session with
//!    [`RUN_START`]/[`RUN_EXIT`] receipts carrying a `scope_token` — the governed subtree.
//!
//! ## The honest ceiling (say this everywhere this module is described)
//! Covers **only** the process `run --` launches and its children (the `scope_token` subtree).
//! It is a **network-only** profile: file/process/mach access inside the sandbox is unrestricted
//! (`(allow default)` plus the network carve-out) — this is deliberate (the spike above), not an
//! oversight; claiming file/exec coverage here would be exactly the overclaim doc 24 exists to
//! prevent. A raw TCP connection that ignores `HTTP_PROXY`/`HTTPS_PROXY` is *blocked by the
//! profile* (Seatbelt denies `network-outbound` at the kernel/MACF layer, independent of whether
//! the process cooperates) — this is real containment, not a request the agent can politely
//! ignore. What is NOT covered: a determined escape of a fiddly/overly-permissive profile is
//! possible in principle (Seatbelt is deprecated-but-present; the durable seam is rung-3 NetExt,
//! demand-pulled per WATCHER-ROADMAP); and Linux has NO containment path in this module
//! (`kriya-gateway run` is macOS-only in this release — Linux containment rides the W3 Tetragon
//! watcher (`kriyawatch`) when it ships, per doc 24 §11.3's documented v1 choice).
//!
//! **Header visibility differs by lane.** A CONNECT tunnel is **opaque**: after the `CONNECT`
//! line the proxy relays TLS bytes it cannot read, so it can record only host + byte counts and
//! can NOT inject or inspect any header (no `X-Kriya-Chain` on HTTPS hops — doing so would need
//! the TLS interception this module rules out). Plain-HTTP forward is **header-visible**: the
//! proxy parses the request head, which is what lets it strip hop-by-hop headers and append the
//! chain header. The receipt still records only `method`, the `path` (query string dropped — it
//! routinely carries secrets), `scheme`, the chain and byte counts — never header values and
//! never the body. `X-Kriya-Chain` is **cooperative**, not an identity proof: any hop can forge or
//! drop it; it is lineage metadata for honest workloads, receipted as observed. Plain-HTTP
//! forward is one exchange per connection (`Connection: close` on both legs; no keep-alive, no
//! `Upgrade`/WebSocket), with a bounded head (64 KiB) and body (64 MiB), and a 330 s idle
//! timeout on both of its sockets so a call held in a downstream approval (≤ 300 s) is not cut off.
//! NEVER claim host-wide coverage — only "agents kriya launches."

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::audit::{now_ms, Actor, Receipt, Signer};
use crate::permissions::{url_host, EgressDecision, EgressPolicy};

use super::executor::{HashScheme, IoDecision, IoDirection, IoKind, IoRecord};

/// Reserved `action_id` for the session-start bookend (doc 24 §9 EG-C item 1d). Not a `kriya.io.*`
/// egress/ingress record — a session marker carrying the `scope_token` that defines the governed
/// subtree, the Seatbelt profile's sha256 (so an auditor can confirm exactly what was enforced),
/// and the local proxy port.
pub const RUN_START: &str = "kriya.io.run.start";
/// Reserved `action_id` for the session-end bookend: exit code + duration, correlated to
/// [`RUN_START`] by the same `scope_token`.
pub const RUN_EXIT: &str = "kriya.io.run.exit";

/// Generate a Seatbelt profile denying all outbound network EXCEPT a loopback connection to
/// `proxy_port` — the mechanism that forces a launched agent's HTTP(S) traffic through
/// [`ConnectProxy`]. Deliberately narrow (network-only; see the module doc's honest ceiling).
/// Verified against real `sandbox-exec` on this exact grammar: loopback:port succeeds, any other
/// outbound host is refused at the kernel layer ("Operation not permitted").
pub fn seatbelt_profile(proxy_port: u16) -> String {
    format!(
        "(version 1)\n\
         (allow default)\n\
         (deny network-outbound)\n\
         (allow network-outbound (remote ip \"localhost:{proxy_port}\"))\n"
    )
}

/// SHA-256 hex of the profile text — recorded in [`RUN_START`] so the receipt names exactly what
/// was enforced, and an auditor (or a hostile assessor) can re-derive it from the profile on disk.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// A running recording CONNECT proxy: binds a loopback port, accepts `CONNECT host:port` requests
/// from the sandboxed child, evaluates each destination against the installed [`EgressPolicy`],
/// and either tunnels the TLS-opaque bytes (no termination) or refuses — signing a `kriya.io.*`
/// receipt either way. Dropping the handle stops accepting new connections; in-flight tunnels
/// finish naturally when their sockets close.
pub struct ConnectProxy {
    port: u16,
    stop: Arc<AtomicBool>,
    accept_thread: Option<thread::JoinHandle<()>>,
}

impl ConnectProxy {
    /// Bind to an OS-assigned loopback port and start accepting. `policy` is evaluated per
    /// CONNECT; `signer`/`actor` sign every emitted `kriya.io.*` receipt; `scope_token` correlates
    /// every egress receipt from this session back to its [`RUN_START`]/[`RUN_EXIT`] bookends.
    pub fn spawn(
        policy: EgressPolicy,
        signer: Arc<Signer>,
        actor: Option<Actor>,
        scope_token: String,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        Self::from_listener(
            listener,
            policy,
            signer,
            actor,
            scope_token,
            FORWARD_IDLE_TIMEOUT,
        )
    }

    /// [`Self::spawn`], but bound on an operator-chosen address (for example a fixed loopback
    /// port inside a pod, where the containers share one network namespace and the governed
    /// process points `HTTP(S)_PROXY` at it) instead of an OS-assigned port. Same proxy, same
    /// policy evaluation, same receipts — only the bind differs.
    pub fn spawn_on(
        addr: &str,
        policy: EgressPolicy,
        signer: Arc<Signer>,
        actor: Option<Actor>,
        scope_token: String,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        Self::from_listener(
            listener,
            policy,
            signer,
            actor,
            scope_token,
            FORWARD_IDLE_TIMEOUT,
        )
    }

    /// [`Self::spawn`] with the plain-HTTP forward lane's idle timeout overridden, so tests can
    /// exercise the cut-off without waiting out [`FORWARD_IDLE_TIMEOUT`].
    #[cfg(test)]
    pub(crate) fn spawn_with_forward_idle_timeout(
        policy: EgressPolicy,
        signer: Arc<Signer>,
        actor: Option<Actor>,
        scope_token: String,
        forward_idle: Duration,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        Self::from_listener(listener, policy, signer, actor, scope_token, forward_idle)
    }

    fn from_listener(
        listener: TcpListener,
        policy: EgressPolicy,
        signer: Arc<Signer>,
        actor: Option<Actor>,
        scope_token: String,
        forward_idle: Duration,
    ) -> std::io::Result<Self> {
        let port = listener.local_addr()?.port();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = stop.clone();
        // A short accept-loop timeout so the thread notices `stop` promptly rather than blocking
        // forever in `accept()` after the caller asked to shut down.
        listener.set_nonblocking(true)?;

        let policy = Arc::new(policy);
        let accept_thread = thread::spawn(move || {
            while !stop_flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _addr)) => {
                        // BSD/macOS gotcha: a socket `accept()`-ed from a non-blocking listener
                        // can inherit O_NONBLOCK (needed on the LISTENER so this loop can poll
                        // `stop`). Without resetting it here, every `read()` downstream races the
                        // client's next write and fails immediately with WouldBlock instead of
                        // blocking for it — which is exactly the zero-byte "tunnel established
                        // but nothing forwarded" failure this comment replaces a debugging
                        // session for. Each accepted connection's own blocking mode is
                        // independent of the listener's, so this doesn't affect the accept loop.
                        if let Err(e) = stream.set_nonblocking(false) {
                            eprintln!(
                                "[kriya-gateway] contain: failed to set accepted stream to \
                                 blocking mode, dropping connection: {e}"
                            );
                            continue;
                        }
                        let policy = policy.clone();
                        let signer = signer.clone();
                        let actor = actor.clone();
                        let scope_token = scope_token.clone();
                        thread::spawn(move || {
                            handle_connect(
                                stream,
                                &policy,
                                &signer,
                                &actor,
                                &scope_token,
                                forward_idle,
                            );
                        });
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

    /// The loopback port a caller must point `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` at.
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for ConnectProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.accept_thread.take() {
            let _ = h.join();
        }
    }
}

/// Idle timeout for reading a request head and for the CONNECT lane's sockets, and the TCP
/// connect timeout on both lanes: a stalled peer frees its handler thread instead of pinning it.
const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// Read/write idle timeout on BOTH sockets of the plain-HTTP forward lane once a request is being
/// forwarded: a governed upstream call can legitimately sit silent through a downstream human-
/// approval hold of up to 300 s (the runtime's deny-on-timeout), plus 30 s of slack.
const FORWARD_IDLE_TIMEOUT: Duration = Duration::from_secs(330);
/// Upper bound on a request head (request line + headers, CONNECT or forward). Larger → 413.
const MAX_HEAD_BYTES: usize = 64 * 1024;
/// Upper bound on a forwarded plain-HTTP request body (decoded). Larger → 413.
const MAX_BODY_BYTES: u64 = 64 * 1024 * 1024;
/// The cooperative origin-chain header (see the module doc: lineage metadata, not identity proof).
const CHAIN_HEADER: &str = "X-Kriya-Chain";
/// Max entries in a forwarded chain (inbound entries + this hop's actor).
const MAX_CHAIN_ENTRIES: usize = 16;
/// Max bytes per chain entry.
const MAX_CHAIN_ENTRY_BYTES: usize = 64;

/// Why reading a request head stopped short of a usable head.
#[derive(Debug, PartialEq, Eq)]
enum HeadError {
    /// The peer closed (or timed out) before a complete head — nothing to answer.
    Closed,
    /// The head exceeded [`MAX_HEAD_BYTES`] → 413.
    TooLarge,
}

/// Read one request head (up to the blank line), bounded by `limit` bytes in total. Returns the
/// lines without their line terminators; the first is the request line. Bytes after the head stay
/// buffered in `r` (the body, for the forward lane).
fn read_head<R: BufRead>(r: &mut R, limit: usize) -> Result<Vec<Vec<u8>>, HeadError> {
    let mut lines: Vec<Vec<u8>> = Vec::new();
    let mut total = 0usize;
    loop {
        let mut line = Vec::new();
        let budget = (limit - total) as u64 + 1;
        let n = r
            .by_ref()
            .take(budget)
            .read_until(b'\n', &mut line)
            .map_err(|_| HeadError::Closed)?;
        if n == 0 {
            return Err(HeadError::Closed);
        }
        total += n;
        if total > limit {
            return Err(HeadError::TooLarge);
        }
        if line.last() != Some(&b'\n') {
            // EOF mid-line.
            return Err(HeadError::Closed);
        }
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.is_empty() {
            if lines.is_empty() {
                // RFC 9112 §2.2: a server SHOULD ignore empty lines before the request line.
                continue;
            }
            return Ok(lines);
        }
        lines.push(line);
    }
}

/// Answer a client-side error and close without a receipt (nothing egressed). The client may still
/// be mid-send (an oversized head, an unread body); closing a socket with unread input makes the
/// kernel send RST, which can destroy the response before the client reads it — so half-close and
/// drain a bounded amount first.
fn reject(mut s: TcpStream, status: &str) {
    let _ = write!(
        s,
        "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let _ = s.flush();
    let _ = s.shutdown(std::net::Shutdown::Write);
    let _ = s.set_read_timeout(Some(Duration::from_millis(500)));
    let _ = std::io::copy(&mut (&s).take(1024 * 1024), &mut std::io::sink());
}

/// Handle one accepted connection. Reads the request head (bounded), then dispatches:
/// `CONNECT host:port` → evaluate, receipt, tunnel opaque bytes ([`connect_lane`]);
/// absolute-form `http://…` → evaluate, receipt, forward one request ([`forward_lane`]);
/// absolute-form `https://…` → 400 (an HTTPS client must use CONNECT); anything else (origin-form)
/// → 405, as before.
fn handle_connect(
    stream: TcpStream,
    policy: &EgressPolicy,
    signer: &Signer,
    actor: &Option<Actor>,
    scope_token: &str,
    forward_idle: Duration,
) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let lines = match read_head(&mut reader, MAX_HEAD_BYTES) {
        Ok(l) => l,
        Err(HeadError::Closed) => return,
        Err(HeadError::TooLarge) => {
            drop(reader);
            reject(stream, "413 Payload Too Large");
            return;
        }
    };
    let request_line =
        String::from_utf8_lossy(lines.first().map(Vec::as_slice).unwrap_or(&[])).into_owned();
    let mut parts = request_line.splitn(3, ' ');
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        drop(reader);
        reject(stream, "400 Bad Request");
        return;
    };

    if method.eq_ignore_ascii_case("CONNECT") {
        connect_lane(reader, target, policy, signer, actor, scope_token);
    } else if has_scheme(target, "http://") {
        let headers = match parse_headers(lines.get(1..).unwrap_or(&[])) {
            Some(h) => h,
            None => {
                drop(reader);
                reject(stream, "400 Bad Request");
                return;
            }
        };
        let req = ForwardRequest {
            method,
            target,
            version,
            headers,
        };
        forward_lane(
            reader,
            stream,
            req,
            policy,
            signer,
            actor,
            scope_token,
            forward_idle,
        );
    } else if has_scheme(target, "https://") {
        // An HTTPS URL must arrive as CONNECT (the proxy never terminates TLS) — a client sending
        // `GET https://…` in the clear is misconfigured; refuse rather than downgrade it to HTTP.
        drop(reader);
        reject(stream, "400 Bad Request");
    } else {
        // Origin-form (no scheme) is not a proxy request — refuse cleanly, as v1 always has.
        let mut s = reader.into_inner();
        let _ = s.write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n");
    }
}

fn has_scheme(target: &str, scheme: &str) -> bool {
    target
        .get(..scheme.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(scheme))
}

/// The CONNECT lane: evaluate the target host, decide, receipt, and (on allow) tunnel bytes
/// unmodified in both directions until either side closes. Never terminates TLS — the agent's
/// session is end-to-end intact through the tunnel.
fn connect_lane(
    reader: BufReader<TcpStream>,
    target: &str,
    policy: &EgressPolicy,
    signer: &Signer,
    actor: &Option<Actor>,
    scope_token: &str,
) {
    let host = url_host(target);
    let decision = policy.evaluate(&host);
    let mut s = reader.into_inner();
    let rec = |decision, rule, reason, bytes_out, bytes_in| {
        record_io(
            signer,
            actor,
            scope_token,
            &host,
            "CONNECT",
            decision,
            rule,
            reason,
            bytes_out,
            bytes_in,
            None,
        )
    };

    match decision {
        EgressDecision::Deny { rule, reason } => {
            let _ = s.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n");
            rec(IoDecision::Deny, rule, Some(reason), None, None);
        }
        // No synchronous approval channel exists across a raw TCP CONNECT tunnel in v1 — an
        // approval-tier destination is refused here, honestly, rather than silently allowed or
        // hung indefinitely. Route approval-tier destinations through the interactive proxy/broker
        // lanes instead (doc 24 §9 EG-C, deliberate v1 scope).
        EgressDecision::Approval { rule } => {
            let _ = s.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n");
            rec(
                IoDecision::Deny,
                rule,
                Some(
                    "approval-tier destination refused in the contained lane (no synchronous \
                     approval channel over a raw CONNECT tunnel in v1)"
                        .to_string(),
                ),
                None,
                None,
            );
        }
        EgressDecision::Allow { rule } => {
            let Ok(dest) = TcpStream::connect(target) else {
                let _ = s.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
                rec(
                    IoDecision::Deny,
                    rule,
                    Some("upstream connect failed".to_string()),
                    None,
                    None,
                );
                return;
            };
            if s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .is_err()
            {
                return;
            }
            let (bytes_out, bytes_in) = tunnel(s, dest);
            rec(
                IoDecision::Allow,
                rule,
                None,
                Some(bytes_out),
                Some(bytes_in),
            );
        }
    }
}

/// A parsed absolute-form request head, borrowed from the request line.
struct ForwardRequest<'a> {
    method: &'a str,
    target: &'a str,
    version: &'a str,
    /// `(name, raw value)` in arrival order; the value is OWS-trimmed.
    headers: Vec<(String, Vec<u8>)>,
}

/// Parse header lines into `(name, value)`. `None` on anything a request-smuggling defence must
/// refuse: obsolete line folding, an empty or non-token name, whitespace before the colon.
fn parse_headers(lines: &[Vec<u8>]) -> Option<Vec<(String, Vec<u8>)>> {
    let mut out = Vec::with_capacity(lines.len());
    for line in lines {
        if matches!(line.first(), Some(b' ' | b'\t')) {
            return None; // obs-fold
        }
        let colon = line.iter().position(|&b| b == b':')?;
        let name = line.get(..colon)?;
        if name.is_empty() || !name.iter().all(|&b| is_tchar(b)) {
            return None;
        }
        let value = trim_ows(line.get(colon + 1..)?);
        if value.iter().any(|&b| b == b'\r' || b == b'\n' || b == 0) {
            return None;
        }
        out.push((String::from_utf8_lossy(name).into_owned(), value.to_vec()));
    }
    Some(out)
}

fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

fn trim_ows(mut v: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = v {
        v = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = v {
        v = rest;
    }
    v
}

/// The pieces of an `http://` absolute-form target the forward lane needs.
#[derive(Debug, PartialEq, Eq)]
struct HttpTarget {
    /// Lowercased host (IPv6 literal without brackets) — what the policy evaluates.
    host: String,
    port: u16,
    /// The authority as sent (host + optional `:port`) — becomes the upstream `Host` header.
    authority: String,
    /// The origin-form request-target sent upstream (`/path?query`, `/` when empty).
    origin_form: String,
    /// The path component only (no query) — the receipt's `path` param.
    path: String,
}

/// Parse `http://host[:port][/path][?query][#frag]`. `None` for anything malformed, including
/// userinfo (`user@host` — deprecated in `http` URIs and a classic host-confusion vector).
fn parse_http_target(target: &str) -> Option<HttpTarget> {
    let rest = target.get("http://".len()..)?;
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = rest.get(..auth_end)?;
    let tail = rest.get(auth_end..)?;
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let (host, port_str) = if let Some(after) = authority.strip_prefix('[') {
        let (h, after_bracket) = after.split_once(']')?;
        if h.is_empty()
            || !h
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
        {
            return None;
        }
        let port = match after_bracket {
            "" => None,
            p => Some(p.strip_prefix(':')?),
        };
        (h, port)
    } else {
        let (h, p) = match authority.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        };
        if h.is_empty()
            || !h
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
        {
            return None;
        }
        (h, p)
    };
    let port = match port_str {
        None | Some("") => 80,
        Some(p) if p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()) => {
            match p.parse::<u16>() {
                Ok(0) | Err(_) => return None,
                Ok(n) => n,
            }
        }
        Some(_) => return None,
    };
    let tail = tail.split('#').next().unwrap_or("");
    if tail.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return None;
    }
    let origin_form = if tail.starts_with('/') {
        tail.to_string()
    } else {
        format!("/{tail}")
    };
    let path = origin_form.split('?').next().unwrap_or("/").to_string();
    Some(HttpTarget {
        host: host.to_ascii_lowercase(),
        port,
        authority: authority.to_string(),
        origin_form,
        path,
    })
}

/// Build the forwarded `X-Kriya-Chain` list from the inbound header value(s) plus this hop's
/// actor. Returns `(chain, dropped)`: an inbound value that fails validation (a token outside
/// `[A-Za-z0-9._:/-]`, an empty entry, an entry over 64 bytes, or a chain that would exceed 16
/// entries once this hop is appended) is discarded and a fresh chain started, with `dropped` set
/// so the receipt says so.
fn build_chain(inbound: &[&[u8]], actor: &Option<Actor>) -> (Vec<String>, bool) {
    let me = chain_token_for(actor);
    if inbound.iter().all(|v| trim_ows(v).is_empty()) {
        return (vec![me], false);
    }
    let joined: Vec<u8> = inbound.join(&b","[..]);
    let entries: Vec<&[u8]> = joined.split(|&b| b == b',').map(trim_ows).collect();
    let valid = entries.len() < MAX_CHAIN_ENTRIES
        && entries.iter().all(|e| {
            !e.is_empty() && e.len() <= MAX_CHAIN_ENTRY_BYTES && e.iter().all(|&b| is_chain_byte(b))
        });
    if !valid {
        return (vec![me], true);
    }
    let mut chain: Vec<String> = entries
        .iter()
        .map(|e| String::from_utf8_lossy(e).into_owned())
        .collect();
    chain.push(me);
    (chain, false)
}

fn is_chain_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"._:/-".contains(&b)
}

/// This hop's chain entry: `actor.agent` coerced into the chain alphabet (any other byte → `_`,
/// truncated to 64 bytes), or `egress` when there is no actor / nothing usable is left.
fn chain_token_for(actor: &Option<Actor>) -> String {
    let token: String = actor
        .as_ref()
        .map(|a| a.agent.as_str())
        .unwrap_or("")
        .chars()
        .map(|c| {
            if c.is_ascii() && is_chain_byte(c as u8) {
                c
            } else {
                '_'
            }
        })
        .take(MAX_CHAIN_ENTRY_BYTES)
        .collect();
    if token.is_empty() || token.bytes().all(|b| b == b'_') {
        "egress".to_string()
    } else {
        token
    }
}

/// Headers the proxy never forwards verbatim: hop-by-hop (RFC 9110 §7.6.1) plus the ones it
/// regenerates itself (`Host` from the target, `Content-Length` from the decoded body, the chain
/// header, and `Expect`, which it answers locally).
const DROPPED_HEADERS: &[&str] = &[
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authorization",
    "proxy-authenticate",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
    "expect",
    "x-kriya-chain",
];

/// How the request body is framed.
enum BodyFraming {
    None,
    Length(u64),
    Chunked,
}

/// Decide body framing from the headers. `Err(status)` for framing this proxy refuses: a
/// transfer-coding other than exactly `chunked`, conflicting/invalid `Content-Length`s, or a
/// declared length over [`MAX_BODY_BYTES`]. `Transfer-Encoding` wins over `Content-Length`
/// (RFC 9112 §6.3); the stale length is dropped, never forwarded.
fn body_framing(headers: &[(String, Vec<u8>)]) -> Result<BodyFraming, &'static str> {
    let te: Vec<String> = headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("transfer-encoding"))
        .flat_map(|(_, v)| {
            String::from_utf8_lossy(v)
                .split(',')
                .map(|t| t.trim().to_ascii_lowercase())
                .collect::<Vec<_>>()
        })
        .filter(|t| !t.is_empty())
        .collect();
    if headers
        .iter()
        .any(|(n, _)| n.eq_ignore_ascii_case("transfer-encoding"))
    {
        return if te == ["chunked"] {
            Ok(BodyFraming::Chunked)
        } else {
            Err("501 Not Implemented")
        };
    }
    let mut len: Option<u64> = None;
    for (_, v) in headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("content-length"))
    {
        for part in String::from_utf8_lossy(v).split(',') {
            let part = part.trim();
            if part.is_empty() || part.len() > 19 || !part.bytes().all(|b| b.is_ascii_digit()) {
                return Err("400 Bad Request");
            }
            let n: u64 = part.parse().map_err(|_| "400 Bad Request")?;
            if len.is_some_and(|l| l != n) {
                return Err("400 Bad Request");
            }
            len = Some(n);
        }
    }
    match len {
        Some(n) if n > MAX_BODY_BYTES => Err("413 Payload Too Large"),
        Some(n) => Ok(BodyFraming::Length(n)),
        None => Ok(BodyFraming::None),
    }
}

/// Read the full request body per `framing`, decoding chunked transfer-coding (trailers are read,
/// bounded, and dropped). `Err(status)` on malformed framing, a short body, or over-size.
fn read_body<R: BufRead>(r: &mut R, framing: &BodyFraming) -> Result<Vec<u8>, &'static str> {
    match framing {
        BodyFraming::None => Ok(Vec::new()),
        BodyFraming::Length(n) => {
            let mut body = Vec::new();
            let got = r
                .by_ref()
                .take(*n)
                .read_to_end(&mut body)
                .map_err(|_| "400 Bad Request")?;
            if got as u64 != *n {
                return Err("400 Bad Request");
            }
            Ok(body)
        }
        BodyFraming::Chunked => {
            let mut body = Vec::new();
            loop {
                let mut size_line = Vec::new();
                r.by_ref()
                    .take(1024)
                    .read_until(b'\n', &mut size_line)
                    .map_err(|_| "400 Bad Request")?;
                if size_line.last() != Some(&b'\n') {
                    return Err("400 Bad Request");
                }
                let size_str = String::from_utf8_lossy(&size_line);
                let size_hex = size_str.split(';').next().unwrap_or("").trim();
                if size_hex.is_empty()
                    || size_hex.len() > 16
                    || !size_hex.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    return Err("400 Bad Request");
                }
                let size = u64::from_str_radix(size_hex, 16).map_err(|_| "400 Bad Request")?;
                if size == 0 {
                    // Trailer section up to the final empty line — bounded like a head, dropped.
                    let mut total = 0usize;
                    loop {
                        let mut line = Vec::new();
                        let n = r
                            .by_ref()
                            .take((MAX_HEAD_BYTES - total) as u64 + 1)
                            .read_until(b'\n', &mut line)
                            .map_err(|_| "400 Bad Request")?;
                        total += n;
                        if total > MAX_HEAD_BYTES {
                            return Err("413 Payload Too Large");
                        }
                        if line.last() != Some(&b'\n') {
                            return Err("400 Bad Request");
                        }
                        if line == b"\r\n" || line == b"\n" {
                            return Ok(body);
                        }
                    }
                }
                if body.len() as u64 + size > MAX_BODY_BYTES {
                    return Err("413 Payload Too Large");
                }
                let before = body.len();
                r.by_ref()
                    .take(size)
                    .read_to_end(&mut body)
                    .map_err(|_| "400 Bad Request")?;
                if (body.len() - before) as u64 != size {
                    return Err("400 Bad Request");
                }
                let mut crlf = [0u8; 2];
                r.read_exact(&mut crlf).map_err(|_| "400 Bad Request")?;
                if &crlf != b"\r\n" {
                    return Err("400 Bad Request");
                }
            }
        }
    }
}

/// The plain-HTTP forward lane: evaluate the absolute-form target's host with the same
/// [`EgressPolicy`] as CONNECT, receipt at the decision point, and on allow re-send ONE request
/// upstream in origin-form (hop-by-hop headers stripped, body re-framed with `Content-Length`,
/// `Connection: close`, `X-Kriya-Chain` appended), then relay the response until the destination
/// closes.
#[allow(clippy::too_many_arguments)]
fn forward_lane(
    mut reader: BufReader<TcpStream>,
    client: TcpStream,
    req: ForwardRequest<'_>,
    policy: &EgressPolicy,
    signer: &Signer,
    actor: &Option<Actor>,
    scope_token: &str,
    forward_idle: Duration,
) {
    // From here on the client may wait out a long upstream call (and may be slow to send its
    // body) — switch it from the head-read timeout to the forward lane's idle timeout.
    let _ = client.set_read_timeout(Some(forward_idle));
    let _ = client.set_write_timeout(Some(forward_idle));
    let valid_line = !req.method.is_empty()
        && req.method.bytes().all(is_tchar)
        && (req.version == "HTTP/1.1" || req.version == "HTTP/1.0");
    let Some(t) = parse_http_target(req.target).filter(|_| valid_line) else {
        drop(reader);
        reject(client, "400 Bad Request");
        return;
    };

    let inbound: Vec<&[u8]> = req
        .headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case(CHAIN_HEADER))
        .map(|(_, v)| v.as_slice())
        .collect();
    let (chain, chain_dropped) = build_chain(&inbound, actor);
    let mut extra = serde_json::Map::new();
    extra.insert("scheme".into(), "http".into());
    extra.insert("path".into(), t.path.clone().into());
    extra.insert("chain".into(), chain.clone().into());
    if chain_dropped {
        extra.insert("chain_dropped".into(), true.into());
    }
    let rec = |decision, rule, reason, bytes_out, bytes_in| {
        record_io(
            signer,
            actor,
            scope_token,
            &t.host,
            req.method,
            decision,
            rule,
            reason,
            bytes_out,
            bytes_in,
            Some(&extra),
        )
    };

    let rule = match policy.evaluate(&t.host) {
        EgressDecision::Deny { rule, reason } => {
            rec(IoDecision::Deny, rule, Some(reason), None, None);
            drop(reader);
            reject(client, "403 Forbidden");
            return;
        }
        // Same as the CONNECT lane: no synchronous approval channel here in v1 — refuse honestly.
        EgressDecision::Approval { rule } => {
            rec(
                IoDecision::Deny,
                rule,
                Some(
                    "approval-tier destination refused in the contained lane (no synchronous \
                     approval channel in the plain-HTTP forward lane in v1)"
                        .to_string(),
                ),
                None,
                None,
            );
            drop(reader);
            reject(client, "403 Forbidden");
            return;
        }
        EgressDecision::Allow { rule } => rule,
    };

    // Client-side framing errors egress nothing, so they answer without a receipt (like 405/400).
    let framing = match body_framing(&req.headers) {
        Ok(f) => f,
        Err(status) => {
            drop(reader);
            reject(client, status);
            return;
        }
    };
    let expects_continue = req
        .headers
        .iter()
        .any(|(n, v)| n.eq_ignore_ascii_case("expect") && v.eq_ignore_ascii_case(b"100-continue"));
    if expects_continue
        && req.version == "HTTP/1.1"
        && !matches!(framing, BodyFraming::None)
        && (&client)
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .is_err()
    {
        return;
    }
    let body = match read_body(&mut reader, &framing) {
        Ok(b) => b,
        Err(status) => {
            drop(reader);
            reject(client, status);
            return;
        }
    };
    drop(reader);

    let Some(dest) = connect_upstream(&t.host, t.port, forward_idle) else {
        rec(
            IoDecision::Deny,
            rule,
            Some("upstream connect failed".to_string()),
            None,
            None,
        );
        reject(client, "502 Bad Gateway");
        return;
    };

    let connection_tokens: Vec<String> = req
        .headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, v)| {
            String::from_utf8_lossy(v)
                .split(',')
                .map(|t| t.trim().to_ascii_lowercase())
                .collect::<Vec<_>>()
        })
        .collect();
    let mut head = Vec::with_capacity(1024);
    head.extend_from_slice(
        format!("{} {} {}\r\n", req.method, t.origin_form, req.version).as_bytes(),
    );
    head.extend_from_slice(format!("Host: {}\r\n", t.authority).as_bytes());
    for (name, value) in &req.headers {
        let lower = name.to_ascii_lowercase();
        if DROPPED_HEADERS.contains(&lower.as_str()) || connection_tokens.contains(&lower) {
            continue;
        }
        head.extend_from_slice(name.as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value);
        head.extend_from_slice(b"\r\n");
    }
    if !matches!(framing, BodyFraming::None) {
        head.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }
    head.extend_from_slice(b"Connection: close\r\n");
    head.extend_from_slice(format!("{CHAIN_HEADER}: {}\r\n\r\n", chain.join(",")).as_bytes());

    let sent = (&dest)
        .write_all(&head)
        .and_then(|()| (&dest).write_all(&body))
        .and_then(|()| (&dest).flush());
    if sent.is_err() {
        rec(
            IoDecision::Deny,
            rule,
            Some("upstream write failed".to_string()),
            None,
            None,
        );
        reject(client, "502 Bad Gateway");
        return;
    }

    let relay = relay_response(&dest, &client);
    let bytes_in = relay.payload;
    let reason = match (relay.total, relay.end) {
        (0, RelayEnd::IdleTimeout) => {
            let _ = (&client).write_all(
                b"HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
            Some("upstream idle timeout before a response".to_string())
        }
        (0, _) => {
            let _ = (&client).write_all(
                b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
            Some("upstream closed without a response".to_string())
        }
        (_, RelayEnd::IdleTimeout) => Some("upstream idle timeout mid-response".to_string()),
        (_, RelayEnd::Error) => Some("response relay aborted".to_string()),
        (_, RelayEnd::Closed) => None,
    };
    let _ = client.shutdown(std::net::Shutdown::Write);
    let _ = dest.shutdown(std::net::Shutdown::Both);
    rec(
        IoDecision::Allow,
        rule,
        reason,
        Some(body.len() as u64),
        Some(bytes_in),
    );
}

/// Resolve and connect to `host:port`, trying each resolved address with [`IO_TIMEOUT`] for the
/// TCP connect itself; the established socket then gets the forward lane's `idle` timeout.
fn connect_upstream(host: &str, port: u16, idle: Duration) -> Option<TcpStream> {
    use std::net::ToSocketAddrs;
    for addr in (host, port).to_socket_addrs().ok()? {
        if let Ok(s) = TcpStream::connect_timeout(&addr, IO_TIMEOUT) {
            let _ = s.set_read_timeout(Some(idle));
            let _ = s.set_write_timeout(Some(idle));
            return Some(s);
        }
    }
    None
}

/// Why the response relay stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayEnd {
    /// The destination closed its side — the normal end of a `Connection: close` exchange.
    Closed,
    /// No byte from the destination (or no progress writing to the client) for a whole idle
    /// timeout. A slow-but-alive upstream never lands here as long as it is inside the window.
    IdleTimeout,
    /// Any other socket error (reset, client gone).
    Error,
}

/// What [`relay_response`] observed.
struct Relay {
    /// Every byte relayed, head included.
    total: u64,
    /// Bytes after the response head's terminating CRLFCRLF — the receipt's `bytes_in` (payload,
    /// never header bytes, matching the ledger's byte-count definition).
    payload: u64,
    end: RelayEnd,
}

/// Relay the destination's response to the client byte-for-byte until the destination closes
/// or stays silent past the socket's idle timeout. Waiting is not an error: a read that blocks
/// is just the upstream still working, and only a full idle window with no bytes ends the relay.
fn relay_response(dest: &TcpStream, client: &TcpStream) -> Relay {
    const TERMINATOR: &[u8; 4] = b"\r\n\r\n";
    let mut buf = [0u8; 16 * 1024];
    let (mut total, mut payload) = (0u64, 0u64);
    let mut matched = 0usize;
    let mut in_body = false;
    let end = loop {
        let n = match (&*dest).read(&mut buf) {
            Ok(0) => break RelayEnd::Closed,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) if is_timeout(&e) => break RelayEnd::IdleTimeout,
            Err(_) => break RelayEnd::Error,
        };
        let chunk = buf.get(..n).unwrap_or(&[]);
        if let Err(e) = (&*client).write_all(chunk) {
            break if is_timeout(&e) {
                RelayEnd::IdleTimeout
            } else {
                RelayEnd::Error
            };
        }
        total += n as u64;
        if in_body {
            payload += n as u64;
            continue;
        }
        for (i, &b) in chunk.iter().enumerate() {
            matched = if TERMINATOR.get(matched) == Some(&b) {
                matched + 1
            } else if b == b'\r' {
                1
            } else {
                0
            };
            if matched == TERMINATOR.len() {
                in_body = true;
                payload += (n - i - 1) as u64;
                break;
            }
        }
    };
    Relay {
        total,
        payload,
        end,
    }
}

/// A socket timeout surfaces as `WouldBlock` on Unix and `TimedOut` on Windows.
fn is_timeout(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

/// Forward bytes unmodified in both directions between the sandboxed client and the real
/// destination until either side closes — no TLS termination, no content inspection. Returns
/// observed payload bytes `(client_to_dest, dest_to_client)`.
fn tunnel(client: TcpStream, dest: TcpStream) -> (u64, u64) {
    let out_count = Arc::new(AtomicU64::new(0));
    let in_count = Arc::new(AtomicU64::new(0));

    let c2d = {
        let mut client_r = match client.try_clone() {
            Ok(c) => c,
            Err(_) => return (0, 0),
        };
        let mut dest_w = match dest.try_clone() {
            Ok(d) => d,
            Err(_) => return (0, 0),
        };
        let count = out_count.clone();
        thread::spawn(move || {
            let n = copy_counted(&mut client_r, &mut dest_w);
            count.fetch_add(n, Ordering::Relaxed);
            let _ = dest_w.shutdown(std::net::Shutdown::Write);
        })
    };
    let d2c = {
        let mut dest_r = dest;
        let mut client_w = client;
        let count = in_count.clone();
        thread::spawn(move || {
            let n = copy_counted(&mut dest_r, &mut client_w);
            count.fetch_add(n, Ordering::Relaxed);
            let _ = client_w.shutdown(std::net::Shutdown::Write);
        })
    };
    let _ = c2d.join();
    let _ = d2c.join();
    (
        out_count.load(Ordering::Relaxed),
        in_count.load(Ordering::Relaxed),
    )
}

fn copy_counted(r: &mut impl Read, w: &mut impl Write) -> u64 {
    let mut buf = [0u8; 16 * 1024];
    let mut total = 0u64;
    loop {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if w.write_all(&buf[..n]).is_err() {
                    break;
                }
                total += n as u64;
            }
            Err(_) => break,
        }
    }
    total
}

/// Sign the `kriya.io.egress.http.{allow,deny}` receipt for one egress decision (CONNECT or
/// plain-HTTP forward), correlated to the session via `scope_token` (carried as `corr` — this lane
/// has no MCP action receipt to correlate to, so the run session itself is the correlation unit).
/// `method` is `CONNECT` for the tunnel lane and the request verb for the forward lane; `extra`
/// carries the forward lane's `scheme`/`path`/`chain`(/`chain_dropped`) params. No
/// `content_sha256`: a raw TCP tunnel with no TLS termination never sees plaintext content to hash
/// — recording a hash there would be either fabricated or require the exact interception this
/// module's honest ceiling rules out (doc 24 L7's "commitment to OBSERVED content" — there is none
/// to observe past the CONNECT line); the forward lane deliberately commits to nothing about the
/// body either (it records metadata only). Byte counts: the tunnel counts every relayed byte (it
/// cannot tell header from payload inside TLS); the forward lane counts the decoded request body
/// out and the response bytes after its head in.
#[allow(clippy::too_many_arguments)]
fn record_io(
    signer: &Signer,
    actor: &Option<Actor>,
    scope_token: &str,
    host: &str,
    method: &str,
    decision: IoDecision,
    policy_rule: Option<String>,
    reason: Option<String>,
    bytes_out: Option<u64>,
    bytes_in: Option<u64>,
    extra: Option<&serde_json::Map<String, serde_json::Value>>,
) {
    let io = IoRecord {
        direction: IoDirection::Egress,
        dest_host: Some(host.to_string()),
        dest_kind: IoKind::Http,
        method: Some(method.to_string()),
        bytes_out,
        bytes_in,
        bytes_in_is_partial: false,
        content_sha256: None,
        hash_scheme: HashScheme::WireBytes,
        decision,
        policy_rule,
        approved_by: None,
        reason,
        server: None,
        flags: Vec::new(),
    };
    let mut params = io.params(Some(scope_token));
    if let (Some(extra), Some(obj)) = (extra, params.as_object_mut()) {
        for (k, v) in extra {
            obj.insert(k.clone(), v.clone());
        }
    }
    signer.record(
        Receipt::new(
            uuid::Uuid::new_v4().to_string(),
            io.action_id(),
            params,
            !matches!(decision, IoDecision::Deny),
            now_ms(),
        )
        .with_actor(actor.clone()),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_signer() -> Signer {
        Signer::with_log_path(
            std::env::temp_dir().join(format!("kriya-contain-test-{}.jsonl", uuid::Uuid::new_v4())),
        )
    }

    #[test]
    fn profile_denies_network_except_the_given_loopback_port() {
        let p = seatbelt_profile(9999);
        assert!(p.contains("(deny network-outbound)"));
        assert!(p.contains("localhost:9999"));
        assert!(p.contains("(allow default)"));
    }

    #[test]
    fn profile_sha256_is_stable_for_the_same_port() {
        let a = sha256_hex(seatbelt_profile(4321).as_bytes());
        let b = sha256_hex(seatbelt_profile(4321).as_bytes());
        assert_eq!(a, b);
        let c = sha256_hex(seatbelt_profile(1234).as_bytes());
        assert_ne!(a, c, "different ports must hash differently");
    }

    /// A tiny local "destination" the proxy is allowed to reach — stands in for a real upstream so
    /// the tunnel test doesn't touch the network. Echoes whatever it receives once, then closes.
    fn spawn_echo_server() -> (u16, thread::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let h = thread::spawn(move || {
            if let Ok((mut conn, _)) = listener.accept() {
                let mut buf = [0u8; 256];
                if let Ok(n) = conn.read(&mut buf) {
                    let _ = conn.write_all(&buf[..n]);
                }
            }
        });
        (port, h)
    }

    fn policy_allow_only(host: &str) -> EgressPolicy {
        let yaml = format!("rules:\n  - host: \"{host}\"\n    tier: allow\nunlisted: deny\n");
        serde_yaml::from_str(&yaml).expect("test policy parses")
    }

    #[test]
    fn allowed_host_tunnels_and_emits_an_allow_receipt() {
        let (echo_port, echo_handle) = spawn_echo_server();
        let host = "127.0.0.1";
        let policy = policy_allow_only(host);
        let log = std::env::temp_dir().join(format!(
            "kriya-contain-allow-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let signer = Arc::new(Signer::with_log_path(log.clone()));
        let proxy = ConnectProxy::spawn(
            policy,
            signer.clone(),
            Some(Actor::new("test-agent", "tester")),
            "scope-allow".to_string(),
        )
        .unwrap();

        // Speak raw CONNECT to the proxy, then push bytes through the tunnel.
        let mut client = TcpStream::connect(("127.0.0.1", proxy.port())).unwrap();
        write!(
            client,
            "CONNECT {host}:{echo_port} HTTP/1.1\r\nHost: {host}:{echo_port}\r\n\r\n"
        )
        .unwrap();
        let mut resp = [0u8; 64];
        let n = client.read(&mut resp).unwrap();
        let resp_text = String::from_utf8_lossy(&resp[..n]);
        assert!(resp_text.starts_with("HTTP/1.1 200"), "got: {resp_text}");

        client.write_all(b"hello-through-tunnel").unwrap();
        let mut echoed = [0u8; 64];
        let n = client.read(&mut echoed).unwrap();
        assert_eq!(
            &echoed[..n],
            b"hello-through-tunnel",
            "TLS-opaque bytes must pass unmodified"
        );

        drop(client);
        echo_handle.join().unwrap();
        drop(proxy);

        let text = std::fs::read_to_string(&log).unwrap();
        assert!(
            text.contains("kriya.io.egress.http.allow"),
            "expected an allow receipt, got: {text}"
        );
        assert!(
            text.contains("scope-allow"),
            "corr must carry the scope_token"
        );
        let _ = std::fs::remove_file(&log);
    }

    #[test]
    fn denied_host_is_refused_and_emits_a_deny_receipt_no_tunnel() {
        let (echo_port, _echo_handle) = spawn_echo_server(); // never connected to — denial happens first
        let policy = policy_allow_only("only-this-host-is-allowed.invalid");
        let log =
            std::env::temp_dir().join(format!("kriya-contain-deny-{}.jsonl", uuid::Uuid::new_v4()));
        let signer = Arc::new(Signer::with_log_path(log.clone()));
        let proxy =
            ConnectProxy::spawn(policy, signer.clone(), None, "scope-deny".to_string()).unwrap();

        let mut client = TcpStream::connect(("127.0.0.1", proxy.port())).unwrap();
        write!(
            client,
            "CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\nHost: 127.0.0.1:{echo_port}\r\n\r\n"
        )
        .unwrap();
        let mut resp = [0u8; 64];
        let n = client.read(&mut resp).unwrap();
        let resp_text = String::from_utf8_lossy(&resp[..n]);
        assert!(resp_text.starts_with("HTTP/1.1 403"), "got: {resp_text}");

        drop(client);
        drop(proxy);

        let text = std::fs::read_to_string(&log).unwrap();
        assert!(
            text.contains("kriya.io.egress.http.deny"),
            "expected a deny receipt, got: {text}"
        );
        let _ = std::fs::remove_file(&log);
    }

    #[test]
    fn an_origin_form_request_is_refused_cleanly() {
        let policy = EgressPolicy::default();
        let signer = Arc::new(test_signer());
        let proxy =
            ConnectProxy::spawn(policy, signer, None, "scope-badmethod".to_string()).unwrap();
        let mut client = TcpStream::connect(("127.0.0.1", proxy.port())).unwrap();
        write!(client, "GET /foo HTTP/1.1\r\nHost: example.com\r\n\r\n").unwrap();
        let mut resp = [0u8; 64];
        let n = client.read(&mut resp).unwrap();
        let resp_text = String::from_utf8_lossy(&resp[..n]);
        assert!(
            resp_text.starts_with("HTTP/1.1 405"),
            "an origin-form (non-proxy) request must be refused, got: {resp_text}"
        );
    }

    #[test]
    fn parses_absolute_form_http_targets() {
        let t = parse_http_target("http://svc.ns.svc.cluster.local:9000/mcp?x=1#f").unwrap();
        assert_eq!(t.host, "svc.ns.svc.cluster.local");
        assert_eq!(t.port, 9000);
        assert_eq!(t.authority, "svc.ns.svc.cluster.local:9000");
        assert_eq!(t.origin_form, "/mcp?x=1");
        assert_eq!(t.path, "/mcp");
        let t = parse_http_target("http://Example.COM").unwrap();
        assert_eq!(
            (t.host.as_str(), t.port, t.origin_form.as_str()),
            ("example.com", 80, "/")
        );
        let t = parse_http_target("http://[::1]:8080?q").unwrap();
        assert_eq!(
            (t.host.as_str(), t.port, t.origin_form.as_str()),
            ("::1", 8080, "/?q")
        );
        for bad in [
            "http://",
            "http://user@host/",
            "http://host:0/",
            "http://host:99999/",
            "http://host:8a/",
            "http://ho st/",
            "http://[zz]/",
            "http://a:b:c/",
            "http://host/\x01",
        ] {
            assert!(parse_http_target(bad).is_none(), "{bad} must be rejected");
        }
    }

    #[test]
    fn chain_extends_valid_inbound_and_drops_invalid() {
        let me = Some(Actor::new("agent-x", "u"));
        assert_eq!(build_chain(&[], &me), (vec!["agent-x".to_string()], false));
        assert_eq!(
            build_chain(&[b"a, b"], &me),
            (vec!["a".into(), "b".into(), "agent-x".into()], false)
        );
        assert_eq!(
            build_chain(&[b"a", b"b"], &None).0,
            vec!["a", "b", "egress"]
        );
        for bad in [&b"a,,b"[..], b"a b", b"a,\xff", b"a;b"] {
            assert_eq!(
                build_chain(&[bad], &me),
                (vec!["agent-x".to_string()], true)
            );
        }
        let long = vec![b'x'; 65];
        assert!(build_chain(&[&long], &me).1);
        let fifteen = vec!["h"; 15].join(",");
        assert_eq!(build_chain(&[fifteen.as_bytes()], &me).0.len(), 16);
        let sixteen = vec!["h"; 16].join(",");
        assert!(build_chain(&[sixteen.as_bytes()], &me).1);
        // An actor name outside the chain alphabet is coerced, never forwarded raw.
        assert_eq!(
            chain_token_for(&Some(Actor::new("my agent\r\n", "u"))),
            "my_agent__"
        );
        assert_eq!(chain_token_for(&Some(Actor::new("  ", "u"))), "egress");
    }

    #[test]
    fn head_reader_is_bounded_and_tolerates_leading_blank_lines() {
        let mut r = std::io::Cursor::new(b"\r\nGET / HTTP/1.1\r\nA: b\r\n\r\nBODY".to_vec());
        let lines = read_head(&mut r, MAX_HEAD_BYTES).unwrap();
        assert_eq!(lines, vec![b"GET / HTTP/1.1".to_vec(), b"A: b".to_vec()]);
        let mut rest = String::new();
        r.read_to_string(&mut rest).unwrap();
        assert_eq!(rest, "BODY");
        let mut big = b"GET / HTTP/1.1\r\n".to_vec();
        big.extend(std::iter::repeat(b'a').take(100));
        assert_eq!(
            read_head(&mut std::io::Cursor::new(big), 64),
            Err(HeadError::TooLarge)
        );
        let mut trunc = std::io::Cursor::new(b"GET / HTTP/1.1\r\nA: b".to_vec());
        assert_eq!(read_head(&mut trunc, 1024), Err(HeadError::Closed));
    }

    #[test]
    fn chunked_bodies_decode_and_bad_framing_is_refused() {
        let mut r =
            std::io::Cursor::new(b"4;ext=1\r\nWiki\r\n5\r\npedia\r\n0\r\nT: v\r\n\r\n".to_vec());
        assert_eq!(
            read_body(&mut r, &BodyFraming::Chunked).unwrap(),
            b"Wikipedia"
        );
        let mut bad = std::io::Cursor::new(b"zz\r\n".to_vec());
        assert!(read_body(&mut bad, &BodyFraming::Chunked).is_err());
        let mut short = std::io::Cursor::new(b"abc".to_vec());
        assert!(read_body(&mut short, &BodyFraming::Length(10)).is_err());
        let h = |pairs: &[(&str, &str)]| {
            pairs
                .iter()
                .map(|(n, v)| (n.to_string(), v.as_bytes().to_vec()))
                .collect::<Vec<_>>()
        };
        assert!(matches!(
            body_framing(&h(&[("Content-Length", "5")])),
            Ok(BodyFraming::Length(5))
        ));
        assert!(body_framing(&h(&[("Content-Length", "5"), ("content-length", "6")])).is_err());
        assert!(body_framing(&h(&[("Content-Length", "-1")])).is_err());
        assert_eq!(
            body_framing(&h(&[("Content-Length", "99999999999")])).err(),
            Some("413 Payload Too Large")
        );
        assert!(matches!(
            body_framing(&h(&[
                ("Transfer-Encoding", "chunked"),
                ("Content-Length", "3")
            ])),
            Ok(BodyFraming::Chunked)
        ));
        assert!(body_framing(&h(&[("Transfer-Encoding", "gzip, chunked")])).is_err());
    }

    /// A destination that accepts one request, waits `delay`, then answers a fixed body.
    fn spawn_slow_destination(delay: Duration) -> u16 {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((conn, _)) = listener.accept() {
                let mut r = BufReader::new(conn.try_clone().unwrap());
                let _ = read_head(&mut r, MAX_HEAD_BYTES);
                thread::sleep(delay);
                let _ = (&conn).write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nslow-but-ok",
                );
            }
        });
        port
    }

    fn forward_through(forward_idle: Duration, delay: Duration) -> (String, String) {
        let dport = spawn_slow_destination(delay);
        let log =
            std::env::temp_dir().join(format!("kriya-contain-slow-{}.jsonl", uuid::Uuid::new_v4()));
        let signer = Arc::new(Signer::with_log_path(log.clone()));
        let proxy = ConnectProxy::spawn_with_forward_idle_timeout(
            policy_allow_only("127.0.0.1"),
            signer,
            None,
            "scope-slow".to_string(),
            forward_idle,
        )
        .unwrap();
        let mut client = TcpStream::connect(("127.0.0.1", proxy.port())).unwrap();
        write!(
            client,
            "GET http://127.0.0.1:{dport}/slow HTTP/1.1\r\nHost: x\r\n\r\n"
        )
        .unwrap();
        let mut out = String::new();
        let _ = client.read_to_string(&mut out);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let receipt = loop {
            let text = std::fs::read_to_string(&log).unwrap_or_default();
            if !text.trim().is_empty() || std::time::Instant::now() > deadline {
                break text;
            }
            thread::sleep(Duration::from_millis(20));
        };
        drop(proxy);
        let _ = std::fs::remove_file(&log);
        (out, receipt)
    }

    #[test]
    fn forward_lane_waits_out_a_slow_but_alive_upstream() {
        // The upstream is silent for 1 s — longer than nothing, well inside a 3 s idle window.
        let (resp, receipt) = forward_through(Duration::from_secs(3), Duration::from_secs(1));
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
        assert!(
            resp.ends_with("slow-but-ok"),
            "full response delivered: {resp}"
        );
        assert!(receipt.contains("kriya.io.egress.http.allow"), "{receipt}");
        assert!(!receipt.contains("idle timeout"), "{receipt}");
    }

    #[test]
    fn forward_lane_cuts_off_an_upstream_silent_past_the_idle_window() {
        let (resp, receipt) = forward_through(Duration::from_millis(500), Duration::from_secs(1));
        assert!(resp.starts_with("HTTP/1.1 504"), "got: {resp}");
        assert!(
            receipt.contains("upstream idle timeout before a response"),
            "{receipt}"
        );
    }

    #[test]
    fn forward_idle_timeout_covers_the_approval_window() {
        assert!(FORWARD_IDLE_TIMEOUT >= Duration::from_secs(300));
        assert_eq!(IO_TIMEOUT, Duration::from_secs(10));
    }
}
