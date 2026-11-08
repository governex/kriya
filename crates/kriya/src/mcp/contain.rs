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
//! demand-pulled per WATCHER-ROADMAP); plain (non-TLS) HTTP through the proxy is out of scope for
//! v1 (CONNECT-only — most agent/API traffic is HTTPS); and Linux has NO containment path in this
//! module (`kriya-gateway run` is macOS-only in this release — Linux containment rides the W3
//! Tetragon watcher (`kriyawatch`) when it ships, per doc 24 §11.3's documented v1 choice).
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
        Self::from_listener(listener, policy, signer, actor, scope_token)
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
        Self::from_listener(listener, policy, signer, actor, scope_token)
    }

    fn from_listener(
        listener: TcpListener,
        policy: EgressPolicy,
        signer: Arc<Signer>,
        actor: Option<Actor>,
        scope_token: String,
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
                            handle_connect(stream, &policy, &signer, &actor, &scope_token);
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

/// Handle one accepted connection: read the CONNECT request line, evaluate the target host,
/// decide, receipt, and (on allow) tunnel bytes unmodified in both directions until either side
/// closes. Never terminates TLS — the agent's session is end-to-end intact through the tunnel.
fn handle_connect(
    stream: TcpStream,
    policy: &EgressPolicy,
    signer: &Signer,
    actor: &Option<Actor>,
    scope_token: &str,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
        return;
    }
    // Drain the rest of the CONNECT request's headers (up to the blank line) without acting on
    // them — a CONNECT tunnel doesn't need them, and we must not treat a plain (non-CONNECT) HTTP
    // request as a tunnel target (out of scope for v1; see the module doc).
    let mut target = None;
    let mut parts = request_line.trim_end().splitn(3, ' ');
    if let (Some(method), Some(t), Some(_httpver)) = (parts.next(), parts.next(), parts.next()) {
        if method.eq_ignore_ascii_case("CONNECT") {
            target = Some(t.to_string());
        }
    }
    loop {
        let mut header_line = String::new();
        match reader.read_line(&mut header_line) {
            Ok(0) => break,
            Ok(_) if header_line.trim().is_empty() => break,
            Ok(_) => continue,
            Err(_) => return,
        }
    }
    let Some(target) = target else {
        // Not a CONNECT — refuse cleanly (v1 is CONNECT-only; see module doc "honest ceiling").
        let mut s = reader.into_inner();
        let _ = s.write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n");
        return;
    };

    let host = url_host(&target);
    let decision = policy.evaluate(&host);
    let mut s = reader.into_inner();

    match decision {
        EgressDecision::Deny { rule, reason } => {
            let _ = s.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n");
            record_io(
                signer,
                actor,
                scope_token,
                &host,
                IoDecision::Deny,
                rule,
                Some(reason),
                None,
                None,
            );
        }
        // No synchronous approval channel exists across a raw TCP CONNECT tunnel in v1 — an
        // approval-tier destination is refused here, honestly, rather than silently allowed or
        // hung indefinitely. Route approval-tier destinations through the interactive proxy/broker
        // lanes instead (doc 24 §9 EG-C, deliberate v1 scope).
        EgressDecision::Approval { rule } => {
            let _ = s.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n");
            record_io(
                signer,
                actor,
                scope_token,
                &host,
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
            let Ok(dest) = TcpStream::connect(&target) else {
                let _ = s.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
                record_io(
                    signer,
                    actor,
                    scope_token,
                    &host,
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
            record_io(
                signer,
                actor,
                scope_token,
                &host,
                IoDecision::Allow,
                rule,
                None,
                Some(bytes_out),
                Some(bytes_in),
            );
        }
    }
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

/// Sign the `kriya.io.egress.http.{allow,deny}` receipt for one CONNECT decision, correlated to
/// the session via `scope_token` (carried as `corr` — this lane has no MCP action receipt to
/// correlate to, so the run session itself is the correlation unit). No `content_sha256`: a raw
/// TCP tunnel with no TLS termination never sees plaintext content to hash — recording a hash here
/// would be either fabricated or require the exact interception this module's honest ceiling rules
/// out (doc 24 L7's "commitment to OBSERVED content" — there is none to observe past the CONNECT
/// line).
#[allow(clippy::too_many_arguments)]
fn record_io(
    signer: &Signer,
    actor: &Option<Actor>,
    scope_token: &str,
    host: &str,
    decision: IoDecision,
    policy_rule: Option<String>,
    reason: Option<String>,
    bytes_out: Option<u64>,
    bytes_in: Option<u64>,
) {
    let io = IoRecord {
        direction: IoDirection::Egress,
        dest_host: Some(host.to_string()),
        dest_kind: IoKind::Http,
        method: Some("CONNECT".to_string()),
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
    signer.record(
        Receipt::new(
            uuid::Uuid::new_v4().to_string(),
            io.action_id(),
            io.params(Some(scope_token)),
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
    fn a_non_connect_request_is_refused_cleanly() {
        let policy = EgressPolicy::default();
        let signer = Arc::new(test_signer());
        let proxy =
            ConnectProxy::spawn(policy, signer, None, "scope-badmethod".to_string()).unwrap();
        let mut client = TcpStream::connect(("127.0.0.1", proxy.port())).unwrap();
        write!(
            client,
            "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"
        )
        .unwrap();
        let mut resp = [0u8; 64];
        let n = client.read(&mut resp).unwrap();
        let resp_text = String::from_utf8_lossy(&resp[..n]);
        assert!(
            resp_text.starts_with("HTTP/1.1 405"),
            "plain HTTP (non-CONNECT) must be refused in v1, got: {resp_text}"
        );
    }
}
