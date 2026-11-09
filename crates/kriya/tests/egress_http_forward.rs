//! Plain-HTTP forward proxying through the contained egress proxy (`ConnectProxy`): an
//! `HTTP_PROXY`-honouring client sends `POST http://host:port/path HTTP/1.1` (absolute-form); the
//! proxy evaluates the host with the same `EgressPolicy` as CONNECT, re-sends the request upstream
//! in origin-form with hop-by-hop headers stripped, `Connection: close` and the cooperative
//! `X-Kriya-Chain` header appended, relays the response, and signs a `kriya.io.egress.http.*`
//! receipt carrying `scheme`/`method`/`path`/`chain` + byte counts — never header values or body.
//! Every receipt is Ed25519-verified and the hash chain checked, as in `egress_ledger.rs`.
#![cfg(feature = "contain")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use kriya::audit::{Actor, Signer};
use kriya::mcp::ConnectProxy;
use kriya::permissions::EgressPolicy;
use serde_json::Value;

const CANNED: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#;

/// What the fake destination saw on one connection.
#[derive(Debug)]
struct Seen {
    request_line: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    fn count(&self, name: &str) -> usize {
        self.headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .count()
    }
}

/// A fake HTTP destination on `127.0.0.1:0`: records the request line, headers and body
/// (`Content-Length`-framed — the proxy always re-frames that way) of each connection and answers
/// a canned JSON with `Connection: close`. Each connection's record is sent on the channel.
fn spawn_destination() -> (u16, mpsc::Receiver<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut stream) = conn else { return };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            let mut headers = Vec::new();
            loop {
                let mut h = String::new();
                reader.read_line(&mut h).unwrap();
                let h = h.trim_end_matches(['\r', '\n']).to_string();
                if h.is_empty() {
                    break;
                }
                let (n, v) = h.split_once(':').unwrap();
                headers.push((n.to_string(), v.trim().to_string()));
            }
            let len: usize = headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
                .map(|(_, v)| v.parse().unwrap())
                .unwrap_or(0);
            let mut body = vec![0u8; len];
            reader.read_exact(&mut body).unwrap();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{CANNED}",
                CANNED.len()
            );
            stream.write_all(resp.as_bytes()).unwrap();
            let _ = tx.send(Seen {
                request_line: request_line.trim_end().to_string(),
                headers,
                body,
            });
        }
    });
    (port, rx)
}

fn policy(yaml: &str) -> EgressPolicy {
    serde_yaml::from_str(yaml).expect("test policy parses")
}

fn allow_loopback() -> EgressPolicy {
    policy("rules:\n  - host: \"127.0.0.1\"\n    tier: allow\nunlisted: deny\n")
}

fn fresh_log(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "kriya-egress-fwd-{tag}-{}-{}.jsonl",
        std::process::id(),
        uuid::Uuid::new_v4()
    ))
}

fn proxy(policy: EgressPolicy, log: &Path, actor: Option<Actor>) -> ConnectProxy {
    ConnectProxy::spawn(
        policy,
        std::sync::Arc::new(Signer::with_log_path(log.to_path_buf())),
        actor,
        "scope-fwd".to_string(),
    )
    .unwrap()
}

/// Send raw bytes to the proxy and read the whole response until the proxy closes.
fn exchange(port: u16, request: &[u8]) -> String {
    let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    c.write_all(request).unwrap();
    let mut out = Vec::new();
    let _ = c.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

/// The receipt is signed after the response relay finishes, so it can land just after the client
/// sees EOF — poll for `n` non-empty lines.
fn wait_for_receipts(log: &Path, n: usize) -> Vec<Value> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let lines = std::fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count();
        if lines >= n {
            return verify_log(log);
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {n} receipt(s)"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Verify every line's Ed25519 signature and `prev_hash` chain (same checks as `egress_ledger.rs`).
fn verify_log(log: &Path) -> Vec<Value> {
    let text = std::fs::read_to_string(log).unwrap();
    let mut prev: Option<String> = None;
    let mut parsed = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let v: Value = serde_json::from_str(line).unwrap();
        let pk: [u8; 32] = hex::decode(v["public_key"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let sig: [u8; 64] = hex::decode(v["signature"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        assert!(
            VerifyingKey::from_bytes(&pk)
                .unwrap()
                .verify(&signed_bytes(&v), &Signature::from_bytes(&sig))
                .is_ok(),
            "signature must verify for {}",
            v["action_id"]
        );
        let declared = v
            .get("prev_hash")
            .and_then(Value::as_str)
            .map(str::to_string);
        assert_eq!(declared, prev, "chain must be contiguous");
        prev = Some(sha256_hex(line.as_bytes()));
        parsed.push(v);
    }
    parsed
}

fn signed_bytes(v: &Value) -> Vec<u8> {
    let mut s = String::from("{");
    s.push_str(&format!("\"step_id\":{}", v["step_id"]));
    s.push_str(&format!(",\"action_id\":{}", v["action_id"]));
    s.push_str(&format!(
        ",\"params\":{}",
        serde_json::to_string(&canonical(&v["params"])).unwrap()
    ));
    s.push_str(&format!(",\"success\":{}", v["success"]));
    s.push_str(&format!(",\"ts_ms\":{}", v["ts_ms"]));
    if let Some(a) = v.get("actor").filter(|a| !a.is_null()) {
        s.push_str(&format!(
            ",\"actor\":{}",
            serde_json::to_string(&canonical(a)).unwrap()
        ));
    }
    if let Some(ph) = v.get("prev_hash").filter(|p| !p.is_null()) {
        s.push_str(&format!(",\"prev_hash\":{ph}"));
    }
    s.push('}');
    s.into_bytes()
}

fn canonical(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for k in keys {
                out.insert(k.clone(), canonical(&map[k]));
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(canonical).collect()),
        other => other.clone(),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

const BODY: &str =
    r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"secret":"BODY-SENTINEL"}}"#;

/// Common assertions for an allowed forward: origin-form upstream, body intact, hop-by-hop gone,
/// `Connection: close`, the expected chain, the full response at the client, and an allow receipt
/// with metadata only.
fn assert_forwarded(seen: &Seen, resp: &str, log: &Path, expect_chain: &[&str]) {
    assert_eq!(seen.request_line, "POST /mcp?token=QUERY-SENTINEL HTTP/1.1");
    assert_eq!(seen.body, BODY.as_bytes(), "body must arrive intact");
    assert_eq!(seen.header("Connection"), Some("close"));
    assert_eq!(seen.count("Connection"), 1);
    assert_eq!(
        seen.header("Content-Length"),
        Some(BODY.len().to_string().as_str())
    );
    for hop in [
        "Proxy-Connection",
        "Proxy-Authorization",
        "Keep-Alive",
        "TE",
        "Transfer-Encoding",
    ] {
        assert!(
            seen.header(hop).is_none(),
            "{hop} is hop-by-hop and must not be forwarded"
        );
    }
    assert_eq!(
        seen.header("X-Custom"),
        Some("HEADER-SENTINEL"),
        "end-to-end headers pass"
    );
    assert_eq!(seen.count("X-Kriya-Chain"), 1);
    assert_eq!(
        seen.header("X-Kriya-Chain"),
        Some(expect_chain.join(",").as_str())
    );

    assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
    assert!(
        resp.ends_with(CANNED),
        "client must get the full response: {resp}"
    );

    let receipts = wait_for_receipts(log, 1);
    assert_eq!(receipts.len(), 1);
    let r = &receipts[0];
    assert_eq!(r["action_id"], "kriya.io.egress.http.allow");
    let p = &r["params"];
    assert_eq!(p["scheme"], "http");
    assert_eq!(p["method"], "POST");
    assert_eq!(p["path"], "/mcp");
    assert_eq!(p["dest_host"], "127.0.0.1");
    assert_eq!(p["dest_kind"], "http");
    assert_eq!(p["policy_rule"], "127.0.0.1");
    assert_eq!(p["corr"], "scope-fwd");
    assert_eq!(p["decision"], "allow");
    assert_eq!(p["chain"], serde_json::json!(expect_chain));
    assert!(p.get("chain_dropped").is_none());
    assert_eq!(p["bytes_out"], BODY.len() as u64);
    assert_eq!(p["bytes_in"], CANNED.len() as u64);
    let raw = std::fs::read_to_string(log).unwrap();
    for sentinel in [
        "BODY-SENTINEL",
        "HEADER-SENTINEL",
        "QUERY-SENTINEL",
        "proxy-secret",
    ] {
        assert!(
            !raw.contains(sentinel),
            "receipt must not carry {sentinel}: {raw}"
        );
    }
}

fn post_head(port: u16, extra: &str, framing: &str) -> String {
    format!(
        "POST http://127.0.0.1:{port}/mcp?token=QUERY-SENTINEL HTTP/1.1\r\n\
         Host: 127.0.0.1:{port}\r\n\
         Content-Type: application/json\r\n\
         X-Custom: HEADER-SENTINEL\r\n\
         Proxy-Connection: keep-alive\r\n\
         Proxy-Authorization: Basic proxy-secret\r\n\
         Keep-Alive: timeout=5\r\n\
         TE: trailers\r\n\
         Connection: keep-alive, TE\r\n\
         {extra}{framing}\r\n"
    )
}

#[test]
fn content_length_post_is_forwarded_in_origin_form_with_a_fresh_chain() {
    let (dport, seen_rx) = spawn_destination();
    let log = fresh_log("cl");
    let p = proxy(
        allow_loopback(),
        &log,
        Some(Actor::new("agent-a", "tester")),
    );

    let mut req = post_head(dport, "", &format!("Content-Length: {}\r\n", BODY.len())).into_bytes();
    req.extend_from_slice(BODY.as_bytes());
    let resp = exchange(p.port(), &req);

    let seen = seen_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_forwarded(&seen, &resp, &log, &["agent-a"]);
    drop(p);
    let _ = std::fs::remove_file(&log);
}

#[test]
fn chunked_post_is_reframed_and_an_inbound_chain_is_extended() {
    let (dport, seen_rx) = spawn_destination();
    let log = fresh_log("chunked");
    let p = proxy(
        allow_loopback(),
        &log,
        Some(Actor::new("agent-c", "tester")),
    );

    let (a, b) = BODY.split_at(17);
    let mut req = post_head(
        dport,
        "X-Kriya-Chain: a,b\r\n",
        "Transfer-Encoding: chunked\r\n",
    )
    .into_bytes();
    req.extend_from_slice(
        format!(
            "{:x}\r\n{a}\r\n{:x};ext=1\r\n{b}\r\n0\r\n\r\n",
            a.len(),
            b.len()
        )
        .as_bytes(),
    );
    let resp = exchange(p.port(), &req);

    let seen = seen_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_forwarded(&seen, &resp, &log, &["a", "b", "agent-c"]);
    drop(p);
    let _ = std::fs::remove_file(&log);
}

#[test]
fn an_invalid_inbound_chain_is_dropped_and_receipted() {
    let (dport, seen_rx) = spawn_destination();
    let log = fresh_log("badchain");
    let p = proxy(allow_loopback(), &log, None);

    let req = format!(
        "GET http://127.0.0.1:{dport}/health HTTP/1.1\r\nHost: x\r\nX-Kriya-Chain: a, b c\r\n\r\n"
    );
    let resp = exchange(p.port(), req.as_bytes());
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");

    let seen = seen_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(seen.request_line, "GET /health HTTP/1.1");
    assert_eq!(
        seen.header("Host"),
        Some(format!("127.0.0.1:{dport}").as_str()),
        "Host is regenerated from the request-target"
    );
    assert_eq!(seen.header("X-Kriya-Chain"), Some("egress"));
    let receipts = wait_for_receipts(&log, 1);
    assert_eq!(
        receipts[0]["params"]["chain"],
        serde_json::json!(["egress"])
    );
    assert_eq!(receipts[0]["params"]["chain_dropped"], true);
    assert_eq!(receipts[0]["params"]["method"], "GET");
    assert_eq!(receipts[0]["params"]["bytes_out"], 0);
    drop(p);
    let _ = std::fs::remove_file(&log);
}

#[test]
fn a_denied_host_gets_403_and_a_deny_receipt_and_nothing_connects() {
    let (dport, seen_rx) = spawn_destination();
    let log = fresh_log("deny");
    let p = proxy(
        policy("rules:\n  - host: \"only-this.invalid\"\n    tier: allow\nunlisted: deny\n"),
        &log,
        Some(Actor::new("agent-d", "tester")),
    );

    let mut req = post_head(dport, "", &format!("Content-Length: {}\r\n", BODY.len())).into_bytes();
    req.extend_from_slice(BODY.as_bytes());
    let resp = exchange(p.port(), &req);
    assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");

    let receipts = wait_for_receipts(&log, 1);
    assert_eq!(receipts.len(), 1);
    let r = &receipts[0];
    assert_eq!(r["action_id"], "kriya.io.egress.http.deny");
    assert_eq!(r["success"], false);
    assert_eq!(r["params"]["scheme"], "http");
    assert_eq!(r["params"]["method"], "POST");
    assert_eq!(r["params"]["path"], "/mcp");
    assert_eq!(r["params"]["chain"], serde_json::json!(["agent-d"]));
    assert!(r["params"].get("bytes_out").is_none());
    assert!(
        seen_rx.recv_timeout(Duration::from_millis(300)).is_err(),
        "a denied request must never reach the destination"
    );
    drop(p);
    let _ = std::fs::remove_file(&log);
}

#[test]
fn an_approval_tier_host_is_refused_like_connect() {
    let (dport, seen_rx) = spawn_destination();
    let log = fresh_log("approval");
    let p = proxy(
        policy("rules:\n  - host: \"127.0.0.1\"\n    tier: approval\nunlisted: deny\n"),
        &log,
        None,
    );
    let req = format!("GET http://127.0.0.1:{dport}/ HTTP/1.1\r\nHost: x\r\n\r\n");
    let resp = exchange(p.port(), req.as_bytes());
    assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");
    let receipts = wait_for_receipts(&log, 1);
    assert_eq!(receipts[0]["action_id"], "kriya.io.egress.http.deny");
    assert_eq!(receipts[0]["params"]["policy_rule"], "127.0.0.1");
    assert!(seen_rx.recv_timeout(Duration::from_millis(300)).is_err());
    drop(p);
    let _ = std::fs::remove_file(&log);
}

#[test]
fn origin_form_is_405_https_absolute_form_is_400_and_neither_is_receipted() {
    let log = fresh_log("refuse");
    let p = proxy(allow_loopback(), &log, None);
    let resp = exchange(p.port(), b"GET /foo HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 405"), "got: {resp}");
    let resp = exchange(
        p.port(),
        b"GET https://127.0.0.1/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    );
    assert!(resp.starts_with("HTTP/1.1 400"), "got: {resp}");
    std::thread::sleep(Duration::from_millis(200));
    assert!(std::fs::read_to_string(&log)
        .unwrap_or_default()
        .trim()
        .is_empty());
    drop(p);
    let _ = std::fs::remove_file(&log);
}

#[test]
fn an_oversized_header_block_is_413() {
    let (dport, seen_rx) = spawn_destination();
    let log = fresh_log("big");
    let p = proxy(allow_loopback(), &log, None);
    let mut req = format!("GET http://127.0.0.1:{dport}/ HTTP/1.1\r\nHost: x\r\n");
    for i in 0..1200 {
        req.push_str(&format!("X-Pad-{i}: {}\r\n", "p".repeat(60)));
    }
    req.push_str("\r\n");
    assert!(req.len() > 64 * 1024);
    let resp = exchange(p.port(), req.as_bytes());
    assert!(resp.starts_with("HTTP/1.1 413"), "got: {resp}");
    assert!(seen_rx.recv_timeout(Duration::from_millis(300)).is_err());
    drop(p);
    let _ = std::fs::remove_file(&log);
}

#[test]
fn malformed_framing_is_refused_without_reaching_the_destination() {
    let (dport, seen_rx) = spawn_destination();
    let log = fresh_log("framing");
    let p = proxy(allow_loopback(), &log, None);
    for (framing, want) in [
        ("Content-Length: 5\r\nContent-Length: 6\r\n", "HTTP/1.1 400"),
        ("Transfer-Encoding: gzip\r\n", "HTTP/1.1 501"),
        ("Content-Length: 999999999999\r\n", "HTTP/1.1 413"),
    ] {
        let req =
            format!("POST http://127.0.0.1:{dport}/ HTTP/1.1\r\nHost: x\r\n{framing}\r\nhello");
        let resp = exchange(p.port(), req.as_bytes());
        assert!(resp.starts_with(want), "{framing:?}: got {resp}");
    }
    let resp = exchange(
        p.port(),
        b"POST http://127.0.0.1:1/ HTTP/1.1\r\nBad Header: x\r\n\r\n",
    );
    assert!(resp.starts_with("HTTP/1.1 400"), "got: {resp}");
    assert!(seen_rx.recv_timeout(Duration::from_millis(300)).is_err());
    drop(p);
    let _ = std::fs::remove_file(&log);
}
