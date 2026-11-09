//! Remote broker upstream end-to-end (W2-2): the broker governs a REMOTE MCP server over the
//! Streamable-HTTP transport (`McpClient::connect_http`), not a spawned process. A minimal std-only
//! HTTP MCP server (one `TcpListener`, no extra deps) stands in for a hosted server; the broker
//! connects to it, and the same composition as the stdio path (proxy executor → Front →
//! RouterServer under `default_broker_policy`) routes + signs every call. Also proves the MCP
//! session id is captured on `initialize` and echoed on later requests (the server rejects a
//! tools/call that lacks it).
#![cfg(feature = "mcp-http")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use kriya::audit::{Actor, Signer};
use kriya::mcp::{AutoApprove, Front, McpClient, McpProxyExecutor, RouterServer};
use kriya::permissions::default_broker_policy;
use serde_json::{json, Value};

const SESSION_ID: &str = "sess-w2-2";

/// Serve exactly `n_requests` MCP HTTP requests on a fresh ephemeral port, then stop. Returns the
/// bound `http://127.0.0.1:PORT/` URL and the join handle. Each request is one connection
/// (`Connection: close`), which keeps the parser trivial and matches how ureq drives it here.
fn spawn_http_mcp_server(n_requests: usize) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let handle = std::thread::spawn(move || {
        for _ in 0..n_requests {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut reader = BufReader::new(stream.try_clone().unwrap());

            // Parse request line + headers (we only need Content-Length + Mcp-Session-Id).
            let mut content_length = 0usize;
            let mut session_hdr: Option<String> = None;
            let mut line = String::new();
            reader.read_line(&mut line).unwrap(); // request line, ignored
            loop {
                let mut h = String::new();
                reader.read_line(&mut h).unwrap();
                if h == "\r\n" || h.is_empty() {
                    break;
                }
                let lower = h.to_ascii_lowercase();
                if let Some(v) = lower.strip_prefix("content-length:") {
                    content_length = v.trim().parse().unwrap_or(0);
                } else if lower.starts_with("mcp-session-id:") {
                    session_hdr = Some(h.splitn(2, ':').nth(1).unwrap().trim().to_string());
                }
            }
            let mut body = vec![0u8; content_length];
            reader.read_exact(&mut body).unwrap();
            let req: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let id = req.get("id").cloned();
            let method = req.get("method").and_then(Value::as_str).unwrap_or("");

            // A notification (no id) — e.g. notifications/initialized — gets 202 with no body.
            if id.is_none() {
                write_http(&mut stream, "202 Accepted", None, None);
                continue;
            }
            let id = id.unwrap();

            let (result, set_session): (Value, bool) = match method {
                "initialize" => (
                    json!({
                        "protocolVersion": "2025-06-18",
                        "capabilities": { "tools": {} },
                        "serverInfo": { "name": "remote-widgets", "version": "9.9.9" }
                    }),
                    true, // assign the session id on initialize
                ),
                "tools/list" => (
                    json!({ "tools": [
                        { "name": "list_widgets", "description": "read", "inputSchema": {"type":"object"} },
                        { "name": "delete_widget", "description": "destroy", "inputSchema": {"type":"object"} },
                    ]}),
                    false,
                ),
                "tools/call" => {
                    // Prove the client captured + echoed the session id: reject if absent/wrong.
                    if session_hdr.as_deref() != Some(SESSION_ID) {
                        let err = json!({
                            "jsonrpc": "2.0", "id": id,
                            "error": { "code": -32000, "message": "missing/invalid Mcp-Session-Id" }
                        });
                        write_http(&mut stream, "200 OK", Some(&err.to_string()), None);
                        continue;
                    }
                    let tool = req["params"]["name"].as_str().unwrap_or("");
                    (
                        json!({ "content": [{ "type": "text", "text": format!("ran {tool}") }], "isError": false }),
                        false,
                    )
                }
                _ => (Value::Null, false),
            };

            let resp = json!({ "jsonrpc": "2.0", "id": id, "result": result });
            let session = if set_session { Some(SESSION_ID) } else { None };
            write_http(&mut stream, "200 OK", Some(&resp.to_string()), session);
        }
    });
    (url, handle)
}

fn write_http(
    stream: &mut std::net::TcpStream,
    status: &str,
    body: Option<&str>,
    session: Option<&str>,
) {
    let mut head = format!("HTTP/1.1 {status}\r\nConnection: close\r\n");
    if let Some(s) = session {
        head.push_str(&format!("Mcp-Session-Id: {s}\r\n"));
    }
    match body {
        Some(b) => {
            head.push_str(&format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                b.len()
            ));
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(b.as_bytes());
        }
        None => {
            head.push_str("Content-Length: 0\r\n\r\n");
            let _ = stream.write_all(head.as_bytes());
        }
    }
    let _ = stream.flush();
}

fn call(server: &mut RouterServer, name: &str, arguments: Value) -> Value {
    let req = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": name, "arguments": arguments },
    });
    let mut out = Vec::new();
    server
        .serve(std::io::Cursor::new(format!("{req}\n")), &mut out)
        .expect("serve one call");
    serde_json::from_slice(&out).expect("one JSON-RPC response line")
}

#[test]
fn broker_governs_a_remote_http_upstream_and_signs_it() {
    // Requests the broker makes to the remote server, in order: initialize, notifications/initialized,
    // tools/list, tools/call (read), tools/call (delete) = 5. The denied create never leaves the
    // broker, so it is NOT one of them.
    let (url, handle) = spawn_http_mcp_server(5);

    let namespaces = vec!["widgets".to_string()];
    let policy = Arc::new(default_broker_policy(&namespaces));
    let dir = std::env::temp_dir().join(format!("kriya-broker-http-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("broker.jsonl");
    let signer = Arc::new(Signer::with_log_path(log.clone()));

    // Connect the REMOTE upstream over HTTP and wrap it exactly as the broker binary does.
    let client = Arc::new(Mutex::new(
        McpClient::connect_http(&url, vec![], false, None).expect("connect http upstream"),
    ));
    let tools = {
        let mut g = client.lock().unwrap();
        g.initialize().expect("initialize remote"); // captures the session id
        g.list_tools().expect("list remote tools")
    };
    assert_eq!(tools.len(), 2, "remote tools cached");
    let front = Front::new("widgets", tools, Box::new(McpProxyExecutor::new(client)));

    let mut server = RouterServer::from_parts(
        "kriya-broker-http-test",
        vec![front],
        policy,
        signer,
        Box::new(AutoApprove),
        Some(Actor::new("claude-desktop", "tester")),
    );

    // Read is allowed and routed to the remote server.
    let read = call(&mut server, "widgets__list_widgets", json!({}));
    assert!(
        read["result"].get("isError").is_none(),
        "allowed remote read: {read}"
    );
    assert!(read["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("ran list_widgets"));

    // Destructive is approval-gated (AutoApprove clears it), routed to the remote, and the remote
    // ONLY answered because the session id captured on initialize was echoed on this call.
    let del = call(&mut server, "widgets__delete_widget", json!({ "id": "w1" }));
    assert!(
        del["result"].get("isError").is_none(),
        "approved remote delete (session echoed): {del}"
    );
    assert!(del["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("ran delete_widget"));

    // The one broker chain holds exactly the two executed remote calls, both verifying.
    let text = std::fs::read_to_string(&log).unwrap();
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 2, "two executed remote calls signed: {text}");
    for l in &lines {
        let v: Value = serde_json::from_str(l).unwrap();
        assert!(v["action_id"].as_str().unwrap().starts_with("widgets__"));
    }

    handle.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

// ─── Serve mode: `kriya-gateway broker --listen` (streamable-HTTP MCP at /mcp) ─────────────────

/// One HTTP/1.1 exchange over a plain `TcpStream` (the server closes after each response).
/// Returns `(status, headers, body)`; header names are lowercased.
fn http(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> (u16, Vec<(String, String)>, String) {
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect broker");
    s.set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .unwrap();
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    s.write_all(head.as_bytes()).unwrap();
    // A large body may be cut short by an early response — ignore write errors and read anyway.
    let _ = s.write_all(body);
    let _ = s.flush();
    let mut raw = Vec::new();
    let _ = s.read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").expect("an HTTP response head");
    let mut lines = head.lines();
    let status: u16 = lines
        .next()
        .unwrap()
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let hdrs = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    (status, hdrs, body.to_string())
}

fn hdr<'a>(h: &'a [(String, String)], name: &str) -> Option<&'a str> {
    h.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

const JSON_ACCEPT: (&str, &str) = ("Accept", "application/json, text/event-stream");
const JSON_CT: (&str, &str) = ("Content-Type", "application/json");

fn post(port: u16, extra: &[(&str, &str)], body: &Value) -> (u16, Vec<(String, String)>, String) {
    let mut h = vec![JSON_CT, JSON_ACCEPT];
    h.extend_from_slice(extra);
    http(port, "POST", "/mcp", &h, body.to_string().as_bytes())
}

fn node_available() -> bool {
    std::process::Command::new("node")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Kills the broker process when the test ends (pass or panic).
struct KillOnDrop(std::process::Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The signed action receipts for `action_id` in the broker's log, in order.
fn action_receipts(log: &std::path::Path, action_id: &str) -> Vec<Value> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .filter(|v| v["action_id"] == action_id)
        .collect()
}

#[test]
fn broker_listen_serves_streamable_http_mcp_with_chain_receipts() {
    if !node_available() {
        eprintln!("skipping broker --listen e2e: node not available");
        return;
    }
    let dir = std::env::temp_dir().join(format!("kriya-broker-listen-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mock = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/gateway-proxy-demo/mock-mcp-server.js");
    let config = dir.join("broker.yaml");
    std::fs::write(
        &config,
        format!(
            "upstreams:\n  - name: notes\n    command: node\n    args: [{:?}]\n",
            mock.to_string_lossy()
        ),
    )
    .unwrap();
    let policy = dir.join("policy.yaml");
    std::fs::write(&policy, "rules:\n  - action: \"*\"\n    allow: true\n").unwrap();
    let log = dir.join("broker.jsonl");

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_kriya-gateway"))
        .args(["broker", "--config"])
        .arg(&config)
        .arg("--policy")
        .arg(&policy)
        .args(["--actor", "broker-actor", "--approval", "deny", "--audit-log"])
        .arg(&log)
        .args(["--listen", "127.0.0.1:0"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn kriya-gateway broker --listen");
    let stderr = child.stderr.take().unwrap();
    let _guard = KillOnDrop(child);

    // Read the startup line for the OS-assigned port; keep draining stderr afterwards.
    let (tx, rx) = std::sync::mpsc::channel::<u16>();
    std::thread::spawn(move || {
        let mut tx = Some(tx);
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if let Some(rest) = line.split("listening on http://127.0.0.1:").nth(1) {
                let port: u16 = rest.trim_end_matches("/mcp").parse().expect("port");
                if let Some(t) = tx.take() {
                    let _ = t.send(port);
                }
            }
        }
    });
    let port = rx
        .recv_timeout(std::time::Duration::from_secs(60))
        .expect("broker printed its listening address");

    // initialize → 200 JSON with an Mcp-Session-Id.
    let (st, h, body) = post(
        port,
        &[],
        &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-06-18","capabilities":{},
            "clientInfo":{"name":"test","version":"0"}}}),
    );
    assert_eq!(st, 200, "initialize: {body}");
    assert!(hdr(&h, "content-type").unwrap().starts_with("application/json"));
    assert_eq!(hdr(&h, "connection"), Some("close"));
    let sid = hdr(&h, "mcp-session-id").expect("Mcp-Session-Id on initialize");
    assert_eq!(sid.len(), 36, "uuid session id: {sid}");
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["id"], 1);
    assert!(v["result"]["serverInfo"]["name"].is_string());
    let sid = sid.to_string();

    // notifications/initialized → 202, empty body.
    let (st, _, body) = post(
        port,
        &[("Mcp-Session-Id", &sid)],
        &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    );
    assert_eq!(st, 202);
    assert!(body.is_empty());

    // tools/list → the namespaced upstream tools.
    let (st, _, body) = post(
        port,
        &[("Mcp-Session-Id", &sid)],
        &json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
    );
    assert_eq!(st, 200);
    let v: Value = serde_json::from_str(&body).unwrap();
    let names: Vec<&str> = v["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"notes__list_notes"), "{names:?}");
    assert!(names.contains(&"notes__create_note"), "{names:?}");

    // tools/call → the upstream result + a signed receipt with chain [actor].
    let call = json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
        "params":{"name":"notes__list_notes","arguments":{}}});
    let (st, _, body) = post(port, &[], &call); // no session id: never required
    assert_eq!(st, 200, "{body}");
    let v: Value = serde_json::from_str(&body).unwrap();
    assert!(v["result"].get("isError").is_none(), "{v}");
    assert!(v["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("Groceries"));
    let r = action_receipts(&log, "notes__list_notes");
    assert_eq!(r.len(), 1);
    assert_eq!(r[0]["params"]["chain"], json!(["broker-actor"]));
    assert!(r[0]["signature"].is_string() && r[0]["public_key"].is_string());

    // Same call with an inbound chain → [inbound..., actor].
    let (st, _, _) = post(port, &[("X-Kriya-Chain", "fieldwatch,coordinator")], &call);
    assert_eq!(st, 200);
    let r = action_receipts(&log, "notes__list_notes");
    assert_eq!(r.len(), 2);
    assert_eq!(
        r[1]["params"]["chain"],
        json!(["fieldwatch", "coordinator", "broker-actor"])
    );

    // An invalid chain header is ignored wholesale.
    let (st, _, _) = post(port, &[("X-Kriya-Chain", "ok,not valid!")], &call);
    assert_eq!(st, 200);
    let r = action_receipts(&log, "notes__list_notes");
    assert_eq!(r[2]["params"]["chain"], json!(["broker-actor"]));

    // Every line of the broker log verifies as one hash chain.
    let lines: Vec<String> = std::fs::read_to_string(&log)
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(String::from)
        .collect();
    let verdict = kriya::audit::verify_chain(&lines);
    assert!(verdict.verified, "chain verifies: {:?}", verdict.first_break);

    // Batch of two requests → a two-element array.
    let (st, _, body) = post(
        port,
        &[],
        &json!([
            {"jsonrpc":"2.0","id":10,"method":"tools/list"},
            {"jsonrpc":"2.0","id":11,"method":"tools/call",
             "params":{"name":"notes__get_note","arguments":{"id":"note-1"}}},
        ]),
    );
    assert_eq!(st, 200, "{body}");
    let v: Value = serde_json::from_str(&body).unwrap();
    let arr = v.as_array().expect("batch reply is an array");
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["id"], 10);
    assert_eq!(arr[1]["id"], 11);

    // GET → 405 with Allow; DELETE → 200; other path → 404; bad JSON → 400 parse error.
    let (st, h, _) = http(port, "GET", "/mcp", &[JSON_ACCEPT], b"");
    assert_eq!(st, 405);
    assert_eq!(hdr(&h, "allow"), Some("POST, DELETE"));
    let (st, _, _) = http(port, "DELETE", "/mcp", &[("Mcp-Session-Id", &sid)], b"");
    assert_eq!(st, 200);
    let (st, _, _) = http(port, "POST", "/other", &[JSON_CT], b"{}");
    assert_eq!(st, 404);
    let (st, _, body) = http(port, "POST", "/mcp", &[JSON_CT], b"{not json");
    assert_eq!(st, 400);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["error"]["code"], -32700);

    // OPTIONS: CORS only for a 127.0.0.1 origin.
    let (st, h, _) = http(port, "OPTIONS", "/mcp", &[("Origin", "http://127.0.0.1:5173")], b"");
    assert_eq!(st, 204);
    assert_eq!(
        hdr(&h, "access-control-allow-origin"),
        Some("http://127.0.0.1:5173")
    );
    let (st, h, _) = http(port, "OPTIONS", "/mcp", &[("Origin", "https://evil.example")], b"");
    assert_eq!(st, 204);
    assert!(hdr(&h, "access-control-allow-origin").is_none());

    // A 2 MiB body → 413.
    let big = vec![b' '; 2 * 1024 * 1024];
    let (st, _, _) = http(port, "POST", "/mcp", &[JSON_CT], &big);
    assert_eq!(st, 413);

    // Still serving after all of the above.
    let (st, _, _) = post(port, &[], &call);
    assert_eq!(st, 200);

    drop(_guard);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A remote upstream that records the `X-Kriya-Chain` header of every `tools/call` it receives.
fn spawn_chain_recording_upstream(
    seen: Arc<Mutex<Vec<Option<String>>>>,
) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}/", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let mut content_length = 0usize;
            let mut chain: Option<String> = None;
            loop {
                let mut h = String::new();
                reader.read_line(&mut h).unwrap();
                if h == "\r\n" || h.is_empty() {
                    break;
                }
                if let Some((k, v)) = h.split_once(':') {
                    if k.eq_ignore_ascii_case("content-length") {
                        content_length = v.trim().parse().unwrap_or(0);
                    } else if k.eq_ignore_ascii_case("x-kriya-chain") {
                        chain = Some(v.trim().to_string());
                    }
                }
            }
            let mut body = vec![0u8; content_length];
            reader.read_exact(&mut body).unwrap();
            let req: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let Some(id) = req.get("id").cloned() else {
                write_http(&mut stream, "202 Accepted", None, None);
                continue;
            };
            let result = match req["method"].as_str().unwrap_or("") {
                "initialize" => json!({"protocolVersion":"2025-06-18","capabilities":{"tools":{}},
                    "serverInfo":{"name":"chain-rec","version":"1"}}),
                "tools/list" => json!({"tools":[{"name":"list_items","description":"read",
                    "inputSchema":{"type":"object"}}]}),
                "tools/call" => {
                    seen.lock().unwrap().push(chain);
                    json!({"content":[{"type":"text","text":"pong"}]})
                }
                _ => Value::Null,
            };
            let resp = json!({"jsonrpc":"2.0","id":id,"result":result});
            write_http(&mut stream, "200 OK", Some(&resp.to_string()), None);
        }
    });
    url
}

#[test]
fn http_served_broker_forwards_the_chain_to_an_http_upstream() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let url = spawn_chain_recording_upstream(seen.clone());

    let dir = std::env::temp_dir().join(format!("kriya-broker-chain-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("broker.jsonl");
    let signer = Arc::new(Signer::with_log_path(log.clone()));
    let policy = Arc::new(default_broker_policy(&["rec".to_string()]));

    let client = Arc::new(Mutex::new(
        McpClient::connect_http(&url, vec![], false, None).expect("connect"),
    ));
    let tools = {
        let mut g = client.lock().unwrap();
        g.initialize().expect("initialize");
        g.list_tools().expect("list")
    };
    let front = Front::new("rec", tools, Box::new(McpProxyExecutor::new(client)));
    let server = RouterServer::from_parts(
        "chain-test",
        vec![front],
        policy,
        signer,
        Box::new(AutoApprove),
        Some(Actor::new("broker-actor", "tester")),
    );
    let (addr, _h) =
        kriya::mcp::http_serve::spawn("127.0.0.1:0", server, "broker-actor").expect("listen");
    let port = addr.port();

    let call = json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
        "params":{"name":"rec__list_items","arguments":{}}});
    let (st, _, body) = post(port, &[("X-Kriya-Chain", "fieldwatch,coordinator")], &call);
    assert_eq!(st, 200, "{body}");
    let (st, _, _) = post(port, &[], &call);
    assert_eq!(st, 200);

    let seen = seen.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec![
            Some("fieldwatch,coordinator,broker-actor".to_string()),
            Some("broker-actor".to_string()),
        ]
    );
    let r = action_receipts(&log, "rec__list_items");
    assert_eq!(r.len(), 2);
    assert_eq!(
        r[0]["params"]["chain"],
        json!(["fieldwatch", "coordinator", "broker-actor"])
    );
    assert_eq!(r[1]["params"]["chain"], json!(["broker-actor"]));
    // Every receipt the governor signed for the chained request carries the chain — the action
    // receipt above and, when the egress tier is configured, its `kriya.io.*` companions. Here no
    // egress policy is set, so the action receipts are the whole log.
    let all = std::fs::read_to_string(&log).unwrap();
    assert!(all
        .lines()
        .filter(|l| !l.trim().is_empty())
        .all(|l| serde_json::from_str::<Value>(l).unwrap()["params"]["chain"].is_array()));
    let _ = std::fs::remove_dir_all(&dir);
}

// ─── Session recovery: a restarted remote upstream (new process, old Mcp-Session-Id unknown) ─────

/// How the fake upstream rejects a `tools/call` carrying a session id it doesn't know.
#[derive(Clone, Copy, PartialEq)]
enum Reject {
    /// HTTP 404 with a JSON-RPC "Session not found" body (what the MCP SDK servers send).
    Http404,
    /// HTTP 200 whose body is a JSON-RPC "Session not found" error.
    RpcError,
    /// Every `tools/call` is rejected with 404, even on a fresh session (retry must fail once).
    Always404,
    /// The first `tools/call` connection is dropped without an HTTP reply (reset), then normal.
    DropOnce,
}

/// One request the fake upstream saw: (method, Mcp-Session-Id, X-Kriya-Chain).
type Seen = Arc<Mutex<Vec<(String, Option<String>, Option<String>)>>>;

/// A fake HTTP MCP upstream whose live session id changes on every `initialize` (`s1`, `s2`, …).
/// After `restart` is set, the server "forgets" all earlier sessions — exactly what a restarted pod
/// does — and rejects them per `mode`.
fn spawn_restartable_upstream(
    mode: Reject,
    restart: Arc<std::sync::atomic::AtomicBool>,
    seen: Seen,
) -> String {
    use std::sync::atomic::Ordering;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}/mcp", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        let mut inits = 0u32;
        let mut current: Option<String> = None;
        let mut dropped = false;
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                continue;
            }
            let (mut len, mut sid, mut chain) = (0usize, None, None);
            loop {
                let mut h = String::new();
                if reader.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" {
                    break;
                }
                if let Some((k, v)) = h.split_once(':') {
                    let v = v.trim().to_string();
                    match k.to_ascii_lowercase().as_str() {
                        "content-length" => len = v.parse().unwrap_or(0),
                        "mcp-session-id" => sid = Some(v),
                        "x-kriya-chain" => chain = Some(v),
                        _ => {}
                    }
                }
            }
            if mode == Reject::DropOnce
                && restart.load(Ordering::SeqCst)
                && !dropped
                && len > 0
            {
                // Drop the first post-restart connection outright, body unread — the client sees
                // the connection reset/closed with no HTTP reply, as when a pod goes away.
                dropped = true;
                seen.lock().unwrap().push(("<dropped>".into(), sid, chain));
                drop(reader);
                drop(stream);
                continue;
            }
            let mut body = vec![0u8; len];
            let _ = reader.read_exact(&mut body);
            let req: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let method = req["method"].as_str().unwrap_or("").to_string();
            seen.lock()
                .unwrap()
                .push((method.clone(), sid.clone(), chain.clone()));
            let Some(id) = req.get("id").cloned() else {
                write_http(&mut stream, "202 Accepted", None, None);
                continue;
            };
            if method == "initialize" {
                inits += 1;
                let s = format!("s{inits}");
                current = Some(s.clone());
                let resp = json!({"jsonrpc":"2.0","id":id,"result":{
                    "protocolVersion":"2025-06-18","capabilities":{"tools":{}},
                    "serverInfo":{"name":"restartable","version":"1"}}});
                write_http(&mut stream, "200 OK", Some(&resp.to_string()), Some(&s));
                continue;
            }
            // After a restart the server only knows sessions minted since (s2+).
            let known = sid.is_some()
                && sid == current
                && !(restart.load(Ordering::SeqCst) && sid.as_deref() == Some("s1"));
            let not_found = json!({"jsonrpc":"2.0","id":"server-error",
                "error":{"code":-32600,"message":"Session not found"}})
            .to_string();
            if method == "tools/call" && (mode == Reject::Always404 && restart.load(Ordering::SeqCst)) {
                write_http(&mut stream, "404 Not Found", Some(&not_found), None);
                continue;
            }
            if !known {
                match mode {
                    Reject::RpcError => {
                        let e = json!({"jsonrpc":"2.0","id":id,
                            "error":{"code":-32600,"message":"Session not found"}});
                        write_http(&mut stream, "200 OK", Some(&e.to_string()), None);
                    }
                    _ => write_http(&mut stream, "404 Not Found", Some(&not_found), None),
                }
                continue;
            }
            let result = match method.as_str() {
                "tools/list" => json!({"tools":[{"name":"list_items","description":"read",
                    "inputSchema":{"type":"object"}}]}),
                _ => json!({"content":[{"type":"text","text":format!("ok via {}", sid.unwrap())}]}),
            };
            let resp = json!({"jsonrpc":"2.0","id":id,"result":result});
            write_http(&mut stream, "200 OK", Some(&resp.to_string()), None);
        }
    });
    url
}

/// Connect + handshake (session `s1`), "restart" the upstream, then make one chained call.
fn call_across_restart(mode: Reject) -> (Result<String, String>, Vec<(String, Option<String>, Option<String>)>) {
    let restart = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let url = spawn_restartable_upstream(mode, restart.clone(), seen.clone());
    let mut client = McpClient::connect_http(&url, vec![], false, None).expect("connect");
    client.initialize().expect("initialize");
    assert_eq!(client.list_tools().expect("list").len(), 1);
    restart.store(true, std::sync::atomic::Ordering::SeqCst);
    seen.lock().unwrap().clear();
    client.set_call_chain(Some("fieldwatch,broker-actor".into()));
    let out = client
        .call_tool("list_items", &json!({}))
        .map(|r| r.content[0]["text"].as_str().unwrap_or("").to_string());
    let log = seen.lock().unwrap().clone();
    (out, log)
}

fn methods(log: &[(String, Option<String>, Option<String>)]) -> Vec<&str> {
    log.iter().map(|(m, _, _)| m.as_str()).collect()
}

#[test]
fn http_client_recovers_a_lost_session_on_404_and_retries_once_with_the_chain() {
    let (out, log) = call_across_restart(Reject::Http404);
    assert_eq!(out.as_deref(), Ok("ok via s2"), "{log:?}");
    assert_eq!(
        methods(&log),
        ["tools/call", "initialize", "notifications/initialized", "tools/call"]
    );
    assert_eq!(log[0].1.as_deref(), Some("s1"), "first try on the stale session");
    assert_eq!(log[1].1, None, "re-initialize drops the stale session id");
    assert_eq!(log[1].2, None, "handshake carries no X-Kriya-Chain");
    assert_eq!(log[2].1.as_deref(), Some("s2"));
    assert_eq!(log[3].1.as_deref(), Some("s2"), "retry uses the new session");
    assert_eq!(log[3].2.as_deref(), Some("fieldwatch,broker-actor"), "chain kept on retry");
}

#[test]
fn http_client_recovers_a_lost_session_on_a_jsonrpc_session_not_found_error() {
    let (out, log) = call_across_restart(Reject::RpcError);
    assert_eq!(out.as_deref(), Ok("ok via s2"), "{log:?}");
    assert_eq!(
        methods(&log),
        ["tools/call", "initialize", "notifications/initialized", "tools/call"]
    );
}

#[test]
fn http_client_recovers_after_a_dropped_connection() {
    let (out, log) = call_across_restart(Reject::DropOnce);
    assert_eq!(out.as_deref(), Ok("ok via s2"), "{log:?}");
    assert_eq!(
        methods(&log),
        ["<dropped>", "initialize", "notifications/initialized", "tools/call"]
    );
    assert_eq!(log[3].2.as_deref(), Some("fieldwatch,broker-actor"));
}

#[test]
fn http_client_surfaces_the_error_when_the_single_retry_also_fails() {
    let (out, log) = call_across_restart(Reject::Always404);
    let err = out.expect_err("retry fails too");
    assert!(err.contains("HTTP 404") && err.contains("Session not found"), "{err}");
    assert_eq!(
        methods(&log),
        ["tools/call", "initialize", "notifications/initialized", "tools/call"],
        "exactly one re-handshake and one retry"
    );
}
