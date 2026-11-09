//! End-to-end tests for the governed LLM lane (`kriya-gateway egress --llm-listen`): the real
//! [`LlmGateway`] runs in-process on `127.0.0.1:0` in front of a std-only fake provider (also on
//! `127.0.0.1:0`) that records exactly what it received and returns canned OpenAI / Anthropic
//! replies (JSON or SSE). Asserts on what crossed the wire upstream, what the client got back, and
//! what the signed receipt chain holds.

#![cfg(all(feature = "contain", feature = "mcp-http"))]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

use kriya::audit::Signer;
use kriya::mcp::{LlmGateway, LlmGatewayConfig, LlmUpstreams};
use kriya::permissions::Policy;
use serde_json::{json, Value};

const AADHAAR: &str = "2345 6789 0124";
const CARD: &str = "4111 1111 1111 1111";
const EMAIL: &str = "jane.doe@example.com";
const CANARY: &str = "kriya-canary-5e1d9b";
const API_KEY: &str = "sk-test-DO-NOT-LOG-9f8e7d";

/// What the fake provider received: (path, headers lowercased, body).
type Seen = Arc<Mutex<Vec<(String, Vec<(String, String)>, String)>>>;

/// A fake provider. The reply is chosen by the `x-fake-reply` request header (`clean` | `pii`)
/// and the request's `"stream"` flag; `/v1/messages` answers in Anthropic shapes, everything else
/// in OpenAI shapes.
fn spawn_fake_provider() -> (u16, Seen) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let seen2 = seen.clone();
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(conn) = conn else { continue };
            let seen = seen2.clone();
            thread::spawn(move || serve_one(conn, &seen));
        }
    });
    (port, seen)
}

fn serve_one(conn: TcpStream, seen: &Seen) {
    let mut reader = BufReader::new(conn.try_clone().unwrap());
    let mut line = String::new();
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return;
    }
    let path = line.split(' ').nth(1).unwrap_or("").to_string();
    let mut headers = Vec::new();
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h).unwrap_or(0) == 0 {
            break;
        }
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    let len: usize = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).unwrap();
    let body = String::from_utf8_lossy(&body).to_string();
    let reply_kind = headers
        .iter()
        .find(|(k, _)| k == "x-fake-reply")
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| "clean".into());
    let stream = serde_json::from_str::<Value>(&body)
        .ok()
        .and_then(|v| v.get("stream").and_then(Value::as_bool))
        .unwrap_or(false);
    seen.lock().unwrap().push((path.clone(), headers, body));

    let text = if reply_kind == "pii" {
        format!("Sure — the address is {EMAIL}, done.")
    } else {
        "Hello from the model.".to_string()
    };
    let anthropic = path.starts_with("/v1/messages");
    let (ctype, out) = match (anthropic, stream) {
        (false, false) => ("application/json", openai_json(&text)),
        (false, true) => ("text/event-stream", openai_sse(&text)),
        (true, false) => ("application/json", anthropic_json(&text)),
        (true, true) => ("text/event-stream", anthropic_sse(&text)),
    };
    let mut w = conn;
    let _ = write!(
        w,
        "HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nx-request-id: fake-1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        out.len()
    );
    let _ = w.write_all(out.as_bytes());
}

fn openai_json(text: &str) -> String {
    json!({"id": "chatcmpl-1", "object": "chat.completion", "created": 1700000000, "model": "gpt-test",
           "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
           "usage": {"prompt_tokens": 5, "completion_tokens": 7, "total_tokens": 12}})
    .to_string()
}

/// Split the text across several chunks (so a match spans chunk boundaries).
fn openai_sse(text: &str) -> String {
    let mut out = String::new();
    let chars: Vec<char> = text.chars().collect();
    for piece in chars.chunks(9) {
        let p: String = piece.iter().collect();
        out.push_str(&format!(
            "data: {}\n\n",
            json!({"id": "chatcmpl-1", "object": "chat.completion.chunk", "created": 1700000000, "model": "gpt-test",
                   "choices": [{"index": 0, "delta": {"content": p}, "finish_reason": null}]})
        ));
    }
    out.push_str(&format!(
        "data: {}\n\ndata: [DONE]\n\n",
        json!({"id": "chatcmpl-1", "object": "chat.completion.chunk", "created": 1700000000, "model": "gpt-test",
               "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]})
    ));
    out
}

fn anthropic_json(text: &str) -> String {
    json!({"id": "msg_1", "type": "message", "role": "assistant", "model": "claude-test",
           "content": [{"type": "text", "text": text}], "stop_reason": "end_turn", "stop_sequence": null,
           "usage": {"input_tokens": 5, "output_tokens": 7}})
    .to_string()
}

fn anthropic_sse(text: &str) -> String {
    let (a, b) = text.split_at(text.len() / 2);
    let evs = [
        json!({"type": "message_start", "message": {"id": "msg_1", "type": "message", "role": "assistant", "content": [], "model": "claude-test", "stop_reason": null, "stop_sequence": null, "usage": {"input_tokens": 5, "output_tokens": 1}}}),
        json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
        json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": a}}),
        json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": b}}),
        json!({"type": "content_block_stop", "index": 0}),
        json!({"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": null}, "usage": {"output_tokens": 7}}),
        json!({"type": "message_stop"}),
    ];
    evs.iter()
        .map(|e| format!("event: {}\ndata: {e}\n\n", e["type"].as_str().unwrap()))
        .collect()
}

struct Harness {
    gw: LlmGateway,
    log: PathBuf,
    seen: Seen,
}

fn harness_with(llm_yaml: &str, openai_base: Option<String>) -> Harness {
    let (port, seen) = spawn_fake_provider();
    let yaml = format!(
        "rules: [{{action: \"*\", allow: true}}]\n\
         egress:\n  rules:\n    - host: \"127.0.0.1\"\n      tier: allow\n  unlisted: deny\n\
         detection:\n  canary_tokens: [\"{CANARY}\"]\n{llm_yaml}"
    );
    let policy: Policy = serde_yaml::from_str(&yaml).expect("test policy parses");
    let mut upstreams = LlmUpstreams::default();
    let openai = openai_base.unwrap_or_else(|| format!("http://127.0.0.1:{port}"));
    upstreams
        .apply_spec(&format!(
            "openai={openai},anthropic=http://127.0.0.1:{port}"
        ))
        .unwrap();
    let config = LlmGatewayConfig {
        upstreams,
        llm: policy.llm().cloned().unwrap_or_default(),
        egress: policy.egress().cloned().unwrap(),
        canary_tokens: policy.detection().unwrap().canary_tokens.clone(),
    };
    let log = std::env::temp_dir().join(format!("kriya-llm-gw-{}.jsonl", uuid::Uuid::new_v4()));
    let signer = Arc::new(Signer::with_log_path(log.clone()));
    let gw = LlmGateway::spawn_on("127.0.0.1:0", config, signer, None, "scope-test".into())
        .expect("gateway binds");
    Harness { gw, log, seen }
}

fn harness() -> Harness {
    harness_with("", None)
}

/// Send one HTTP/1.1 request; return (status, headers, body).
fn send(
    port: u16,
    path: &str,
    extra_headers: &[(&str, &str)],
    body: &Value,
) -> (u16, String, Vec<u8>) {
    let body = serde_json::to_vec(body).unwrap();
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut req = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (k, v) in extra_headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).unwrap();
    s.write_all(&body).unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response has a head");
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let status: u16 = head.split(' ').nth(1).unwrap().parse().unwrap();
    (status, head, raw[split + 4..].to_vec())
}

fn receipts(log: &PathBuf) -> Vec<Value> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn by_action<'a>(rs: &'a [Value], action: &str) -> Vec<&'a Value> {
    rs.iter().filter(|r| r["action_id"] == action).collect()
}

fn chat(content: &str, stream: bool) -> Value {
    json!({"model": "gpt-test", "stream": stream,
           "messages": [{"role": "user", "content": content}]})
}

#[test]
fn request_pii_is_rewritten_before_it_leaves_and_receipted_content_free() {
    let h = harness();
    let prompt = format!("My Aadhaar is {AADHAAR}, card {CARD}, email {EMAIL}. Summarise.");
    let auth = format!("Bearer {API_KEY}");
    let (status, _, body) = send(
        h.gw.port(),
        "/v1/chat/completions",
        &[("Authorization", &auth)],
        &chat(&prompt, false),
    );
    assert_eq!(status, 200);
    let reply: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        reply["choices"][0]["message"]["content"],
        "Hello from the model."
    );

    let seen = h.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    let (path, headers, upstream_body) = &seen[0];
    assert_eq!(path, "/v1/chat/completions");
    for t in [
        "[REDACTED aadhaar]",
        "[REDACTED credit_card]",
        "[REDACTED email]",
    ] {
        assert!(upstream_body.contains(t), "upstream got {upstream_body}");
    }
    for original in [AADHAAR, CARD, EMAIL, "234567890124", "4111111111111111"] {
        assert!(
            !upstream_body.contains(original),
            "original {original} leaked upstream"
        );
    }
    assert!(
        headers
            .iter()
            .any(|(k, v)| k == "authorization" && v == &auth),
        "Authorization passes through to the provider"
    );

    let rs = receipts(&h.log);
    let reqs = by_action(&rs, "kriya.io.llm.request");
    assert_eq!(reqs.len(), 1);
    let p = &reqs[0]["params"];
    assert_eq!(p["decision"], "redact");
    assert_eq!(p["provider"], "openai");
    assert_eq!(p["path"], "/v1/chat/completions");
    assert_eq!(p["model"], "gpt-test");
    assert_eq!(p["stream"], false);
    assert_eq!(p["status"], 200);
    let m: Vec<&str> = p["request_matches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    for t in ["aadhaar", "credit_card", "email"] {
        assert!(m.contains(&t), "request_matches {m:?} lacks {t}");
    }
    assert_eq!(p["response_matches"], json!([]));
    assert_eq!(p["request_sha256"].as_str().unwrap().len(), 64);
    assert!(p["bytes_out"].as_u64().unwrap() > 0 && p["bytes_in"].as_u64().unwrap() > 0);
    assert!(p["latency_ms"].is_u64());

    // Nothing in the whole chain carries the originals, the key, or the prompt.
    let chain = std::fs::read_to_string(&h.log).unwrap();
    for leak in [AADHAAR, "234567890124", "4111", EMAIL, API_KEY, "Summarise"] {
        assert!(!chain.contains(leak), "receipt chain leaked {leak}");
    }
}

#[test]
fn canary_in_a_prompt_is_denied_and_never_forwarded() {
    let h = harness_with("llm:\n  request: allow\n", None);
    let (status, _, body) = send(
        h.gw.port(),
        "/v1/chat/completions",
        &[],
        &chat(&format!("use {CANARY} please"), false),
    );
    assert_eq!(status, 403);
    let err: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(err["error"]["type"], "policy_denied");
    assert!(
        h.seen.lock().unwrap().is_empty(),
        "nothing reached the provider"
    );
    let rs = receipts(&h.log);
    let denies = by_action(&rs, "kriya.io.llm.deny");
    assert_eq!(denies.len(), 1);
    assert_eq!(denies[0]["params"]["reason"], "canary token matched");
    assert_eq!(denies[0]["params"]["direction"], "request");
    assert_eq!(
        by_action(&rs, "kriya.io.llm.request")[0]["params"]["decision"],
        "deny"
    );
}

#[test]
fn provider_host_not_allowed_by_egress_is_403_with_the_egress_deny_receipt() {
    let h = harness_with("", Some("https://blocked.invalid".into()));
    let (status, _, body) = send(h.gw.port(), "/v1/chat/completions", &[], &chat("hi", false));
    assert_eq!(status, 403);
    let err: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(err["error"]["type"], "policy_denied");
    let rs = receipts(&h.log);
    let eg = by_action(&rs, "kriya.io.egress.http.deny");
    assert_eq!(eg.len(), 1, "the CONNECT lane's deny receipt shape");
    assert_eq!(eg[0]["params"]["dest_host"], "blocked.invalid");
    assert_eq!(eg[0]["params"]["lane"], "llm");
    assert_eq!(eg[0]["params"]["corr"], "scope-test");
    assert_eq!(
        by_action(&rs, "kriya.io.llm.request")[0]["params"]["decision"],
        "deny"
    );
    assert!(h.seen.lock().unwrap().is_empty());
}

#[test]
fn request_deny_mode_refuses_with_403() {
    let h = harness_with("llm:\n  request: deny\n", None);
    let (status, _, _) = send(
        h.gw.port(),
        "/v1/chat/completions",
        &[],
        &chat(&format!("email {EMAIL}"), false),
    );
    assert_eq!(status, 403);
    assert!(h.seen.lock().unwrap().is_empty());
    let rs = receipts(&h.log);
    assert_eq!(by_action(&rs, "kriya.io.llm.deny").len(), 1);
    let p = &by_action(&rs, "kriya.io.llm.request")[0]["params"];
    assert_eq!(p["decision"], "deny");
    assert_eq!(p["request_matches"], json!(["email"]));
}

#[test]
fn provider_not_enabled_is_403_in_the_anthropic_error_shape() {
    let h = harness_with("llm:\n  providers: [openai]\n", None);
    let (status, _, body) = send(
        h.gw.port(),
        "/v1/messages",
        &[("x-api-key", API_KEY), ("anthropic-version", "2023-06-01")],
        &json!({"model": "claude-test", "max_tokens": 10, "messages": [{"role": "user", "content": "hi"}]}),
    );
    assert_eq!(status, 403);
    let err: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(err["type"], "error");
    assert_eq!(err["error"]["type"], "permission_error");
    assert!(h.seen.lock().unwrap().is_empty());
    let rs = receipts(&h.log);
    assert_eq!(by_action(&rs, "kriya.io.llm.deny").len(), 1);
}

#[test]
fn clean_stream_is_released_verbatim() {
    let h = harness();
    let (status, head, body) = send(
        h.gw.port(),
        "/v1/chat/completions",
        &[("x-fake-reply", "clean")],
        &chat("say hello", true),
    );
    assert_eq!(status, 200);
    assert!(head
        .to_ascii_lowercase()
        .contains("content-type: text/event-stream"));
    assert!(
        head.contains("x-request-id: fake-1"),
        "upstream headers pass through"
    );
    assert_eq!(
        String::from_utf8(body).unwrap(),
        openai_sse("Hello from the model.")
    );
    let rs = receipts(&h.log);
    let p = &by_action(&rs, "kriya.io.llm.request")[0]["params"];
    assert_eq!(p["decision"], "allow");
    assert_eq!(p["stream"], true);
}

#[test]
fn redacted_stream_is_reemitted_as_one_chunk() {
    let h = harness();
    let (status, _, body) = send(
        h.gw.port(),
        "/v1/chat/completions",
        &[("x-fake-reply", "pii")],
        &chat("what is the address?", true),
    );
    assert_eq!(status, 200);
    let body = String::from_utf8(body).unwrap();
    assert!(!body.contains(EMAIL));
    let data: Vec<&str> = body
        .lines()
        .filter_map(|l| l.strip_prefix("data: "))
        .collect();
    assert_eq!(
        data.len(),
        3,
        "one content chunk, one finish chunk, [DONE]: {body}"
    );
    let first: Value = serde_json::from_str(data[0]).unwrap();
    assert_eq!(first["object"], "chat.completion.chunk");
    assert_eq!(
        first["choices"][0]["delta"]["content"],
        "Sure — the address is [REDACTED email], done."
    );
    let fin: Value = serde_json::from_str(data[1]).unwrap();
    assert_eq!(fin["choices"][0]["finish_reason"], "stop");
    assert_eq!(data[2], "[DONE]");
    let rs = receipts(&h.log);
    let p = &by_action(&rs, "kriya.io.llm.request")[0]["params"];
    assert_eq!(p["decision"], "redact");
    assert_eq!(p["response_matches"], json!(["email"]));
}

#[test]
fn anthropic_reply_is_redacted_json_and_stream() {
    let h = harness();
    let req = |stream: bool| {
        json!({"model": "claude-test", "max_tokens": 50, "stream": stream,
               "system": "be brief", "messages": [{"role": "user", "content": "address?"}]})
    };
    let (status, _, body) = send(
        h.gw.port(),
        "/v1/messages",
        &[("x-api-key", API_KEY), ("x-fake-reply", "pii")],
        &req(false),
    );
    assert_eq!(status, 200);
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        v["content"][0]["text"],
        "Sure — the address is [REDACTED email], done."
    );

    let (status, _, body) = send(
        h.gw.port(),
        "/v1/messages",
        &[("x-api-key", API_KEY), ("x-fake-reply", "pii")],
        &req(true),
    );
    assert_eq!(status, 200);
    let body = String::from_utf8(body).unwrap();
    assert!(!body.contains(EMAIL));
    assert_eq!(body.matches("event: content_block_delta").count(), 1);
    assert!(body.contains("[REDACTED email]"));
    assert!(body.contains("event: message_stop"));
    let seen = h.seen.lock().unwrap();
    assert!(seen
        .iter()
        .all(|(_, hs, _)| hs.iter().any(|(k, v)| k == "x-api-key" && v == API_KEY)));
    let chain = std::fs::read_to_string(&h.log).unwrap();
    assert!(!chain.contains(API_KEY) && !chain.contains(EMAIL));
}

#[test]
fn response_deny_mode_returns_provider_shaped_403() {
    let h = harness_with("llm:\n  response: deny\n", None);
    let (status, _, body) = send(
        h.gw.port(),
        "/v1/chat/completions",
        &[("x-fake-reply", "pii")],
        &chat("address?", true),
    );
    assert_eq!(status, 403);
    let err: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(err["error"]["type"], "policy_denied");
    let rs = receipts(&h.log);
    let d = by_action(&rs, "kriya.io.llm.deny");
    assert_eq!(d[0]["params"]["direction"], "response");
    assert_eq!(d[0]["params"]["matches"], json!(["email"]));
}
