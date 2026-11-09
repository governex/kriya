//! The `kriya-llm-proxy` HTTP reverse proxy itself (F1, doc 28 §F1): a hand-rolled std
//! `TcpListener` server — same idiom as [`crate::mcp::contain::ConnectProxy`] (thread-per-connection,
//! no async runtime, no HTTP-server crate) — in front of a local OpenAI-compatible / Ollama-native
//! inference server. Streaming passthrough for SSE/chunked responses is real: bytes are relayed to
//! the client as they arrive from upstream; only a running hash + a small rolling "last line" tail
//! (for best-effort usage-token extraction) are kept in memory, never the full body.
//!
//! **Bypass honesty**: this proxy governs ONLY clients pointed at it — see `llm/mod.rs`'s module doc.

use std::collections::{HashMap, HashSet};
use std::io::{BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::audit::{now_ms, Actor, Receipt, Signer};
use crate::permissions::ModelPolicy;

use super::{manifest, receipts};
use crate::http1::{
    self, collect_headers, read_request, status_text, write_response_head, ParsedRequest,
};

/// Governed endpoints: OpenAI-compatible chat/completions/embeddings + Ollama-native chat/generate.
/// Every other path/method is relayed transparently (no receipts) — a client that speaks to, say,
/// `/api/tags` or `/v1/models` through this proxy still works, it's just not a completion to gate.
const GOVERNED_PATHS: &[&str] = &[
    "/v1/chat/completions",
    "/v1/completions",
    "/v1/embeddings",
    "/api/chat",
    "/api/generate",
];

/// Known sampler-parameter keys worth carrying into the `kriya.model.serve` receipt — present-only,
/// values only, never the prompt/output text next to them. Covers both the OpenAI top-level shape
/// and Ollama's `options: {...}` nesting (see [`extract_sampler`]).
const SAMPLER_KEYS: &[&str] = &[
    "temperature",
    "top_p",
    "top_k",
    "seed",
    "max_tokens",
    "num_predict",
    "presence_penalty",
    "frequency_penalty",
    "repeat_penalty",
    "stop",
];

/// Where `kriya-llm-proxy` resolves model identities from — see [`manifest`].
pub struct ProxyOptions {
    pub models_dir: PathBuf,
    pub cache_path: PathBuf,
    /// Operator-supplied `model name -> local file path` mapping, for the file-hash-cache
    /// resolution path (llama.cpp-style servers with no Ollama manifest).
    pub model_paths: HashMap<String, PathBuf>,
}

impl Default for ProxyOptions {
    fn default() -> Self {
        Self {
            models_dir: manifest::ollama_models_dir(),
            cache_path: manifest::default_cache_path(),
            model_paths: HashMap::new(),
        }
    }
}

struct RuntimeInfoCache(Mutex<Option<(Option<String>, Option<String>)>>);

impl RuntimeInfoCache {
    fn get_or_fetch(
        &self,
        agent: &ureq::Agent,
        upstream: &str,
    ) -> (Option<String>, Option<String>) {
        let mut guard = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(v) = &*guard {
            return v.clone();
        }
        let result = fetch_ollama_version(agent, upstream);
        *guard = Some(result.clone());
        result
    }
}

/// Best-effort `/api/version` probe (Ollama-native; OpenAI-compat servers generally don't expose
/// one). Failure is silent and cached — the identity receipt honestly omits `runtime`/
/// `runtime_version` rather than retrying every request.
fn fetch_ollama_version(agent: &ureq::Agent, upstream: &str) -> (Option<String>, Option<String>) {
    let url = format!("{}/api/version", upstream.trim_end_matches('/'));
    match agent.get(&url).call() {
        Ok(resp) => match resp.into_json::<Value>() {
            Ok(v) => {
                let version = v.get("version").and_then(Value::as_str).map(str::to_string);
                (Some("ollama".to_string()), version)
            }
            Err(_) => (None, None),
        },
        Err(_) => (None, None),
    }
}

struct ConnCtx {
    upstream: String,
    options: ProxyOptions,
    signer: Arc<Signer>,
    actor: Option<Actor>,
    policy: Arc<ModelPolicy>,
    agent: ureq::Agent,
    /// First-sight tracking for `kriya.model.identity`, keyed by `"<model>\0<digest>"` — seeded at
    /// startup from the signer's own log so a restart doesn't re-emit identity receipts for models
    /// this device has already seen.
    seen: Mutex<HashSet<String>>,
    runtime_cache: RuntimeInfoCache,
}

/// A running `kriya-llm-proxy` instance. Dropping it stops accepting new connections; in-flight
/// requests finish naturally.
pub struct LlmProxy {
    port: u16,
    stop: Arc<AtomicBool>,
    accept_thread: Option<thread::JoinHandle<()>>,
}

impl LlmProxy {
    /// Bind `bind_addr` (e.g. `"127.0.0.1:11435"`) and start accepting. `upstream` is the base URL
    /// of the real inference server (e.g. `"http://localhost:11434"`); `policy` is evaluated on
    /// every governed request's resolved digest; every emitted receipt is signed via `signer` and
    /// carries `actor`.
    pub fn spawn(
        bind_addr: &str,
        upstream: String,
        options: ProxyOptions,
        signer: Arc<Signer>,
        actor: Option<Actor>,
        policy: Arc<ModelPolicy>,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind(bind_addr)?;
        let port = listener.local_addr()?.port();
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = stop.clone();

        let seen = Mutex::new(seed_seen_from_log(signer.log_path()));
        let ctx = Arc::new(ConnCtx {
            upstream,
            options,
            signer,
            actor,
            policy,
            agent: ureq::AgentBuilder::new()
                .timeout_connect(Duration::from_secs(10))
                .timeout_read(Duration::from_secs(600))
                .timeout_write(Duration::from_secs(60))
                .build(),
            seen,
            runtime_cache: RuntimeInfoCache(Mutex::new(None)),
        });

        let accept_thread = thread::spawn(move || {
            while !stop_flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _addr)) => {
                        // Same BSD/macOS gotcha `mcp::contain::ConnectProxy` documents: an accepted
                        // socket can inherit O_NONBLOCK from a non-blocking listener.
                        if let Err(e) = stream.set_nonblocking(false) {
                            eprintln!(
                                "[kriya-llm-proxy] failed to set accepted stream to blocking mode, \
                                 dropping connection: {e}"
                            );
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

impl Drop for LlmProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.accept_thread.take() {
            let _ = h.join();
        }
    }
}

fn seed_seen_from_log(log_path: &std::path::Path) -> HashSet<String> {
    let mut set = HashSet::new();
    if let Ok(text) = std::fs::read_to_string(log_path) {
        for line in text.lines() {
            let Ok(v) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            if v.get("action_id").and_then(Value::as_str) != Some(receipts::MODEL_IDENTITY) {
                continue;
            }
            let Some(params) = v.get("params") else {
                continue;
            };
            let model = params
                .get("gen_ai.request.model")
                .and_then(Value::as_str)
                .unwrap_or("");
            let digest = params.get("digest").and_then(Value::as_str).unwrap_or("");
            set.insert(seen_key(model, digest));
        }
    }
    set
}

fn seen_key(model: &str, digest: &str) -> String {
    format!("{model}\u{0}{digest}")
}

// ─── HTTP parsing (request side) ────────────────────────────────────────────────────────────────

// `ParsedRequest` / `read_request` / chunked decoding live in `crate::http1` (shared with the
// governed LLM lane of `kriya-gateway egress`).

// ─── Connection handling ────────────────────────────────────────────────────────────────────────

fn handle_connection(stream: TcpStream, ctx: &ConnCtx) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(600)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(600)));
    let read_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut reader = BufReader::new(read_stream);
    let mut writer = stream;

    let request = match read_request(&mut reader) {
        Ok(Some(r)) => r,
        Ok(None) => return,
        Err(_) => {
            let _ = write_error(&mut writer, 400, "malformed request");
            return;
        }
    };

    handle_request(&mut writer, request, ctx);
}

fn handle_request(writer: &mut TcpStream, req: ParsedRequest, ctx: &ConnCtx) {
    let started = Instant::now();
    let path = req
        .path
        .split(['?', '#'])
        .next()
        .unwrap_or(&req.path)
        .to_string();
    let is_governed =
        req.method.eq_ignore_ascii_case("POST") && GOVERNED_PATHS.contains(&path.as_str());

    let body_json: Option<Value> = if is_governed {
        serde_json::from_slice(&req.body).ok()
    } else {
        None
    };
    let model_name = body_json
        .as_ref()
        .and_then(|v| v.get("model"))
        .and_then(Value::as_str)
        .map(str::to_string);

    let Some(model) = model_name.filter(|_| is_governed) else {
        // Ungoverned: unmatched path, GET, or a governed-path POST with no resolvable model name.
        // No receipts — nothing to gate or identify honestly.
        transparent_relay(writer, &req, ctx);
        return;
    };

    let resolved = manifest::resolve_model(
        &ctx.options.models_dir,
        &ctx.options.cache_path,
        &ctx.options.model_paths,
        &model,
    );
    let digest = resolved.digest.clone();

    let first_sight = {
        let mut seen = ctx.seen.lock().unwrap_or_else(|e| e.into_inner());
        seen.insert(seen_key(&model, digest.as_deref().unwrap_or("")))
    };
    if first_sight {
        let (runtime, runtime_version) = ctx.runtime_cache.get_or_fetch(&ctx.agent, &ctx.upstream);
        let params = receipts::IdentityParams {
            model: &model,
            digest: digest.as_deref(),
            digest_source: resolved.source.as_str(),
            runtime: runtime.as_deref(),
            runtime_version: runtime_version.as_deref(),
        }
        .to_value();
        ctx.signer.record(
            Receipt::new(
                uuid::Uuid::new_v4().to_string(),
                receipts::MODEL_IDENTITY.to_string(),
                params,
                true,
                now_ms(),
            )
            .with_actor(ctx.actor.clone()),
        );
    }

    // The policy verdict — evaluated + receipted on EVERY governed completion (fail-OPEN default:
    // the common case is an explicit `warn`, never silence).
    let decision = ctx.policy.evaluate(digest.as_deref());
    let gate_reason = decision.reason();
    let gate_params = receipts::GateParams {
        model: &model,
        digest: digest.as_deref(),
        decision: decision.facet(),
        matched_rule: decision.matched_rule(),
        reason: &gate_reason,
    }
    .to_value();
    ctx.signer.record(
        Receipt::new(
            uuid::Uuid::new_v4().to_string(),
            receipts::MODEL_GATE.to_string(),
            gate_params,
            !decision.blocks(),
            now_ms(),
        )
        .with_actor(ctx.actor.clone()),
    );

    if decision.blocks() {
        let _ = write_error(writer, 403, &gate_reason);
        return;
    }

    let prompt_hash = extract_prompt_hash(body_json.as_ref());
    let sampler = extract_sampler(body_json.as_ref());
    let streaming = body_json
        .as_ref()
        .and_then(|v| v.get("stream"))
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let resp = match forward_upstream(&ctx.agent, &ctx.upstream, &req) {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r,
        Err(e) => {
            let _ = write_error(writer, 502, &format!("upstream unreachable: {e}"));
            return;
        }
    };
    let status = resp.status();
    let headers = collect_headers(&resp);
    let mut body_reader = resp.into_reader();
    if write_response_head(writer, status, &headers).is_err() {
        return;
    }
    let Ok((_bytes, output_hash, last_json_line)) =
        relay_response_and_hash(&mut body_reader, writer)
    else {
        return;
    };

    let (input_tokens, output_tokens) = extract_usage(&last_json_line);
    let duration_ms = started.elapsed().as_millis() as u64;
    let serve_params = receipts::ServeParams {
        model: &model,
        digest: digest.as_deref(),
        input_tokens,
        output_tokens,
        sampler,
        prompt_hash: prompt_hash.as_deref(),
        output_hash: Some(&output_hash),
        streaming,
        duration_ms,
        upstream_path: &path,
    }
    .to_value();
    ctx.signer.record(
        Receipt::new(
            uuid::Uuid::new_v4().to_string(),
            receipts::MODEL_SERVE.to_string(),
            serve_params,
            status < 400,
            now_ms(),
        )
        .with_actor(ctx.actor.clone()),
    );
}

/// Relay a non-governed (or unidentifiable) request/response pair verbatim — still through the same
/// hashing relay function (cheap), but with NO receipts: nothing here is a completion to gate.
fn transparent_relay(writer: &mut TcpStream, req: &ParsedRequest, ctx: &ConnCtx) {
    let resp = match forward_upstream(&ctx.agent, &ctx.upstream, req) {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r,
        Err(e) => {
            let _ = write_error(writer, 502, &format!("upstream unreachable: {e}"));
            return;
        }
    };
    let status = resp.status();
    let headers = collect_headers(&resp);
    let mut body_reader = resp.into_reader();
    if write_response_head(writer, status, &headers).is_err() {
        return;
    }
    let _ = relay_response_and_hash(&mut body_reader, writer);
}

// See `crate::http1::forward` for why the large `Err` is intentional.
#[allow(clippy::result_large_err)]
fn forward_upstream(
    agent: &ureq::Agent,
    upstream: &str,
    req: &ParsedRequest,
) -> Result<ureq::Response, ureq::Error> {
    let url = format!("{}{}", upstream.trim_end_matches('/'), req.path);
    http1::forward(agent, &req.method, &url, &req.headers, &req.body, &[])
}

fn write_error(writer: &mut impl Write, status: u16, message: &str) -> std::io::Result<()> {
    let body = serde_json::json!({ "error": { "message": message, "source": "kriya-llm-proxy" } })
        .to_string();
    write!(writer, "HTTP/1.1 {status} {}\r\n", status_text(status))?;
    write!(writer, "Content-Type: application/json\r\n")?;
    write!(writer, "Content-Length: {}\r\n", body.len())?;
    write!(writer, "Connection: close\r\n\r\n")?;
    writer.write_all(body.as_bytes())?;
    Ok(())
}

/// Relay `upstream` to `client` byte-for-byte as HTTP chunked framing, hashing as it goes (never
/// buffering the full body) while tracking a small rolling "last complete line" — the mechanism
/// [`extract_usage`] reads, since both OpenAI SSE (`stream_options.include_usage`) and Ollama's
/// NDJSON streaming shape carry their usage stats on the FINAL line. Returns `(bytes relayed,
/// sha256 hex of those bytes, the last JSON-parseable line seen, if any)`.
fn relay_response_and_hash(
    upstream: &mut dyn Read,
    client: &mut dyn Write,
) -> std::io::Result<(u64, String, Option<String>)> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let mut total: u64 = 0;
    let mut current_line: Vec<u8> = Vec::new();
    let mut last_json_line: Option<String> = None;
    let mut buf = [0u8; 16 * 1024];

    loop {
        let n = upstream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let chunk = &buf[..n];
        hasher.update(chunk);
        total += n as u64;
        write!(client, "{n:x}\r\n")?;
        client.write_all(chunk)?;
        client.write_all(b"\r\n")?;

        for &b in chunk {
            if b == b'\n' {
                consider_line(&current_line, &mut last_json_line);
                current_line.clear();
            } else {
                current_line.push(b);
                // Bound the tail buffer — a pathological upstream that never sends a newline must
                // not grow this unboundedly; drop tracking rather than accumulate forever.
                if current_line.len() > 1_048_576 {
                    current_line.clear();
                }
            }
        }
    }
    consider_line(&current_line, &mut last_json_line); // a trailing partial line with no final \n
    client.write_all(b"0\r\n\r\n")?;

    Ok((total, hex::encode(hasher.finalize()), last_json_line))
}

fn consider_line(line: &[u8], last_json_line: &mut Option<String>) {
    let s = String::from_utf8_lossy(line);
    let s = s.trim_end_matches('\r').trim();
    if s.is_empty() {
        return;
    }
    let stripped = s.strip_prefix("data:").map(str::trim).unwrap_or(s);
    if stripped == "[DONE]" {
        return;
    }
    if serde_json::from_str::<Value>(stripped).is_ok() {
        *last_json_line = Some(stripped.to_string());
    }
}

/// Best-effort token-usage extraction from the response's final line — OpenAI's `usage` object
/// (present on non-streaming responses, and streaming ones with `include_usage` set) or Ollama's
/// `prompt_eval_count`/`eval_count` (present on every streaming/non-streaming final line). `None`
/// when the shape isn't recognized — never fabricated.
fn extract_usage(last_json_line: &Option<String>) -> (Option<u64>, Option<u64>) {
    let Some(s) = last_json_line else {
        return (None, None);
    };
    let Ok(v) = serde_json::from_str::<Value>(s) else {
        return (None, None);
    };
    if let Some(usage) = v.get("usage") {
        let inp = usage.get("prompt_tokens").and_then(Value::as_u64);
        let out = usage.get("completion_tokens").and_then(Value::as_u64);
        if inp.is_some() || out.is_some() {
            return (inp, out);
        }
    }
    let inp = v.get("prompt_eval_count").and_then(Value::as_u64);
    let out = v.get("eval_count").and_then(Value::as_u64);
    (inp, out)
}

/// sha256 hex of the canonicalized (recursively key-sorted) prompt/messages/input field — never the
/// text itself. Tries the OpenAI chat shape (`messages`), then the completions/Ollama shape
/// (`prompt`), then the embeddings shape (`input`); `None` when the body has none of these.
fn extract_prompt_hash(body: Option<&Value>) -> Option<String> {
    let body = body?;
    let material = if let Some(v) = body.get("messages") {
        v
    } else if let Some(v) = body.get("prompt") {
        v
    } else {
        body.get("input")?
    };
    Some(sha256_hex(canonical_json_string(material).as_bytes()))
}

/// Present-only sampler params, values only — never adjacent to the prompt/output. Reads both the
/// OpenAI top-level shape and Ollama's `options: {...}` nesting (top-level wins if both are set).
fn extract_sampler(body: Option<&Value>) -> Value {
    let mut out = serde_json::Map::new();
    if let Some(obj) = body.and_then(Value::as_object) {
        if let Some(options) = obj.get("options").and_then(Value::as_object) {
            for key in SAMPLER_KEYS {
                if let Some(v) = options.get(*key) {
                    out.insert((*key).to_string(), v.clone());
                }
            }
        }
        for key in SAMPLER_KEYS {
            if let Some(v) = obj.get(*key) {
                out.insert((*key).to_string(), v.clone());
            }
        }
    }
    Value::Object(out)
}

fn canonical_value(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for k in keys {
                out.insert(k.clone(), canonical_value(&map[k]));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonical_value).collect()),
        other => other.clone(),
    }
}

fn canonical_json_string(v: &Value) -> String {
    serde_json::to_string(&canonical_value(v)).unwrap_or_default()
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
    use crate::permissions::UnknownModelAction;
    use std::io::{BufRead, Cursor};

    // ── pure-function tests ──────────────────────────────────────────────────────────────────

    #[test]
    fn extract_prompt_hash_hashes_messages_never_leaking_the_text() {
        let body = serde_json::json!({
            "model": "llama3.1",
            "messages": [{"role": "user", "content": "the secret prompt text"}],
        });
        let hash = extract_prompt_hash(Some(&body)).expect("messages present");
        assert_eq!(hash.len(), 64);
        assert!(!hash.contains("secret"));
        // Deterministic under key reordering (canonicalization).
        let body2 = serde_json::json!({
            "messages": [{"content": "the secret prompt text", "role": "user"}],
            "model": "llama3.1",
        });
        assert_eq!(extract_prompt_hash(Some(&body2)).unwrap(), hash);
    }

    #[test]
    fn extract_prompt_hash_falls_back_to_prompt_then_input() {
        let generate = serde_json::json!({"model": "m", "prompt": "hi"});
        assert!(extract_prompt_hash(Some(&generate)).is_some());
        let embeddings = serde_json::json!({"model": "m", "input": ["a", "b"]});
        assert!(extract_prompt_hash(Some(&embeddings)).is_some());
        let nothing = serde_json::json!({"model": "m"});
        assert!(extract_prompt_hash(Some(&nothing)).is_none());
    }

    #[test]
    fn extract_sampler_pulls_known_keys_from_top_level_and_ollama_options() {
        let openai =
            serde_json::json!({"model": "m", "temperature": 0.7, "seed": 42, "unrelated": "x"});
        let s = extract_sampler(Some(&openai));
        assert_eq!(s["temperature"], serde_json::json!(0.7));
        assert_eq!(s["seed"], serde_json::json!(42));
        assert!(s.get("unrelated").is_none());

        let ollama =
            serde_json::json!({"model": "m", "options": {"temperature": 0.2, "num_predict": 128}});
        let s2 = extract_sampler(Some(&ollama));
        assert_eq!(s2["temperature"], serde_json::json!(0.2));
        assert_eq!(s2["num_predict"], serde_json::json!(128));
    }

    #[test]
    fn extract_usage_reads_openai_and_ollama_shapes() {
        let openai = Some(
            serde_json::json!({"usage": {"prompt_tokens": 10, "completion_tokens": 20}})
                .to_string(),
        );
        assert_eq!(extract_usage(&openai), (Some(10), Some(20)));

        let ollama = Some(
            serde_json::json!({"done": true, "prompt_eval_count": 5, "eval_count": 15}).to_string(),
        );
        assert_eq!(extract_usage(&ollama), (Some(5), Some(15)));

        assert_eq!(extract_usage(&None), (None, None));
        assert_eq!(extract_usage(&Some("not json".to_string())), (None, None));
    }

    #[test]
    fn consider_line_handles_sse_prefix_and_done_sentinel() {
        let mut last = None;
        consider_line(b"data: {\"a\":1}", &mut last);
        assert_eq!(last.as_deref(), Some("{\"a\":1}"));
        consider_line(b"data: [DONE]", &mut last);
        assert_eq!(
            last.as_deref(),
            Some("{\"a\":1}"),
            "[DONE] must not clobber the last real line"
        );
        consider_line(b"", &mut last);
        assert_eq!(
            last.as_deref(),
            Some("{\"a\":1}"),
            "blank lines are ignored"
        );
    }

    #[test]
    fn relay_response_and_hash_streams_chunked_and_captures_the_last_json_line() {
        let body = b"{\"response\":\"partial\",\"done\":false}\n{\"response\":\"\",\"done\":true,\"prompt_eval_count\":3,\"eval_count\":7}\n";
        let mut upstream = Cursor::new(body.to_vec());
        let mut out: Vec<u8> = Vec::new();
        let (bytes, hash, last) = relay_response_and_hash(&mut upstream, &mut out).unwrap();
        assert_eq!(bytes, body.len() as u64);
        assert_eq!(hash.len(), 64);
        assert!(last.unwrap().contains("\"eval_count\":7"));
        // Chunked-framed: ends with the terminating zero-length chunk.
        assert!(out.ends_with(b"0\r\n\r\n"));
        // The body bytes appear intact between chunk-size markers.
        let out_str = String::from_utf8_lossy(&out);
        assert!(out_str.contains("\"done\":true"));
    }

    #[test]
    fn read_request_parses_a_content_length_json_post() {
        let raw = b"POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"model\":\"m\"}";
        let mut reader = BufReader::new(Cursor::new(raw.to_vec()));
        let req = read_request(&mut reader).unwrap().unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/v1/chat/completions");
        assert_eq!(req.body, b"{\"model\":\"m\"}");
    }

    #[test]
    fn read_request_decodes_a_chunked_body() {
        let raw = b"POST /v1/chat/completions HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n";
        let mut reader = BufReader::new(Cursor::new(raw.to_vec()));
        let req = read_request(&mut reader).unwrap().unwrap();
        assert_eq!(req.body, b"test");
    }

    #[test]
    fn read_request_returns_none_on_immediate_eof() {
        let mut reader = BufReader::new(Cursor::new(Vec::<u8>::new()));
        assert!(read_request(&mut reader).unwrap().is_none());
    }

    // ── integration test: a real TcpListener stand-in for "Ollama", a real LlmProxy in front ────

    fn spawn_fake_ollama(
        responses: &'static [(&'static str, &'static str, &'static str)],
    ) -> (u16, thread::JoinHandle<()>) {
        // `responses`: (path, content_type, body) — served once, in order, one connection each.
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            for _ in 0..responses.len() {
                let Ok((stream, _)) = listener.accept() else {
                    break;
                };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut writer = stream;
                // Drain the request (we don't need to inspect it here).
                let mut line = String::new();
                let _ = reader.read_line(&mut line);
                let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
                loop {
                    let mut h = String::new();
                    if reader.read_line(&mut h).unwrap_or(0) == 0 || h.trim().is_empty() {
                        break;
                    }
                }
                let entry = responses
                    .iter()
                    .find(|(p, _, _)| *p == path)
                    .unwrap_or(&responses[0]);
                let body = entry.2.as_bytes();
                let _ = write!(
                    writer,
                    "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\n\r\n",
                    entry.1,
                    body.len()
                );
                let _ = writer.write_all(body);
            }
        });
        (port, handle)
    }

    fn test_signer() -> (Arc<Signer>, std::path::PathBuf) {
        let log = std::env::temp_dir().join(format!(
            "kriya-llm-proxy-test-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        (Arc::new(Signer::with_log_path(log.clone())), log)
    }

    #[test]
    fn end_to_end_governed_completion_emits_identity_gate_and_serve_receipts() {
        let (upstream_port, _h) = spawn_fake_ollama(&[
            // The first-sight identity lookup probes /api/version before the real completion.
            ("/api/version", "application/json", "{\"version\":\"0.5.1\"}"),
            (
                "/api/chat",
                "application/json",
                "{\"model\":\"llama3.1\",\"message\":{\"role\":\"assistant\",\"content\":\"hi\"},\"done\":true,\"prompt_eval_count\":3,\"eval_count\":2}",
            ),
        ]);
        let (signer, log_path) = test_signer();
        let policy = Arc::new(ModelPolicy::default()); // default unknown_model: warn

        let proxy = LlmProxy::spawn(
            "127.0.0.1:0",
            format!("http://127.0.0.1:{upstream_port}"),
            ProxyOptions {
                models_dir: std::env::temp_dir().join("kriya-llm-proxy-test-no-ollama-dir"),
                cache_path: std::env::temp_dir().join(format!(
                    "kriya-llm-proxy-test-cache-{}.json",
                    uuid::Uuid::new_v4()
                )),
                model_paths: HashMap::new(),
            },
            signer.clone(),
            Some(Actor::new("test-client", "tester")),
            policy,
        )
        .unwrap();

        let mut client = TcpStream::connect(("127.0.0.1", proxy.port())).unwrap();
        let body = "{\"model\":\"llama3.1\",\"messages\":[{\"role\":\"user\",\"content\":\"hello there\"}],\"stream\":false}";
        write!(
            client,
            "POST /api/chat HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
        let mut resp = String::new();
        std::io::Read::read_to_string(&mut client, &mut resp).unwrap();
        assert!(resp.starts_with("HTTP/1.1 200"), "got: {resp}");
        assert!(
            resp.contains("\"eval_count\":2"),
            "response body relayed through: {resp}"
        );

        drop(client);
        drop(proxy);

        let text = std::fs::read_to_string(&log_path).unwrap();
        assert!(
            text.contains(receipts::MODEL_IDENTITY),
            "expected an identity receipt: {text}"
        );
        assert!(
            text.contains(receipts::MODEL_GATE),
            "expected a gate receipt: {text}"
        );
        assert!(
            text.contains(receipts::MODEL_SERVE),
            "expected a serve receipt: {text}"
        );
        assert!(
            text.contains("\"decision\":\"warn\""),
            "default unknown_model is warn: {text}"
        );
        assert!(
            !text.contains("hello there"),
            "prompt text must never appear in a receipt: {text}"
        );
        assert!(
            !text.contains("\"content\":\"hi\""),
            "output text must never appear in a receipt: {text}"
        );
        let _ = std::fs::remove_file(&log_path);
    }

    #[test]
    fn deny_tier_model_is_refused_with_no_serve_receipt() {
        let (upstream_port, _h) =
            spawn_fake_ollama(&[("/api/chat", "application/json", "{\"done\":true}")]);
        let (signer, log_path) = test_signer();
        let policy = Arc::new(ModelPolicy {
            approved: vec![],
            unknown_model: UnknownModelAction::Deny,
        });

        let proxy = LlmProxy::spawn(
            "127.0.0.1:0",
            format!("http://127.0.0.1:{upstream_port}"),
            ProxyOptions {
                models_dir: std::env::temp_dir().join("kriya-llm-proxy-test-no-ollama-dir-2"),
                cache_path: std::env::temp_dir().join(format!(
                    "kriya-llm-proxy-test-cache-{}.json",
                    uuid::Uuid::new_v4()
                )),
                model_paths: HashMap::new(),
            },
            signer,
            None,
            policy,
        )
        .unwrap();

        let mut client = TcpStream::connect(("127.0.0.1", proxy.port())).unwrap();
        let body =
            "{\"model\":\"unapproved-model\",\"messages\":[{\"role\":\"user\",\"content\":\"x\"}]}";
        write!(
            client,
            "POST /api/chat HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
        let mut resp = String::new();
        std::io::Read::read_to_string(&mut client, &mut resp).unwrap();
        assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp}");

        drop(client);
        drop(proxy);
        let text = std::fs::read_to_string(&log_path).unwrap();
        assert!(text.contains("\"decision\":\"deny\""));
        assert!(
            !text.contains(receipts::MODEL_SERVE),
            "a denied request must never emit a serve receipt"
        );
        let _ = std::fs::remove_file(&log_path);
    }

    #[test]
    fn ungoverned_path_is_relayed_with_no_receipts() {
        let (upstream_port, _h) =
            spawn_fake_ollama(&[("/api/tags", "application/json", "{\"models\":[]}")]);
        let (signer, log_path) = test_signer();
        let proxy = LlmProxy::spawn(
            "127.0.0.1:0",
            format!("http://127.0.0.1:{upstream_port}"),
            ProxyOptions {
                models_dir: std::env::temp_dir().join("kriya-llm-proxy-test-no-ollama-dir-3"),
                cache_path: std::env::temp_dir().join(format!(
                    "kriya-llm-proxy-test-cache-{}.json",
                    uuid::Uuid::new_v4()
                )),
                model_paths: HashMap::new(),
            },
            signer,
            None,
            Arc::new(ModelPolicy::default()),
        )
        .unwrap();

        let mut client = TcpStream::connect(("127.0.0.1", proxy.port())).unwrap();
        write!(client, "GET /api/tags HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let mut resp = String::new();
        std::io::Read::read_to_string(&mut client, &mut resp).unwrap();
        assert!(resp.starts_with("HTTP/1.1 200"));
        assert!(resp.contains("\"models\":[]"));

        drop(client);
        drop(proxy);
        // The log file may not even exist yet (never written to) — either way, no model receipts.
        if let Ok(text) = std::fs::read_to_string(&log_path) {
            assert!(!text.contains(receipts::MODEL_IDENTITY));
            assert!(!text.contains(receipts::MODEL_GATE));
        }
        let _ = std::fs::remove_file(&log_path);
    }
}
