//! How a governed `tools/call` actually runs the action, once the gates have cleared.
//!
//! The MCP server doesn't know *how* an app executes an action — a Tauri app dispatches it
//! in the webview, a sidecar (roadmap R3) forwards it to the app's main process, a CLI app
//! shells out. So execution is a trait. The governor owns the policy/approval/budget/audit
//! decision; the executor owns only the mechanics of running the cleared action and
//! reporting back what happened.

use serde_json::Value;

/// What running an action produced. `data` is whatever the handler returned (typically the
/// refreshed app state) and is surfaced to the calling agent; `error` is set on failure.
///
/// `io` carries a **governed-lane I/O observation** (doc 24 §4.1) when the executor is one that
/// actually crossed a network/connector lane — the HTTP upstream transport captures the
/// destination + observed payload bytes + a content hash and hands it up here. It is crate-internal
/// (NOT the wire receipt schema): the [`super::governor::Governor`] turns a present `io` into a
/// standalone signed receipt in the reserved `kriya.io.*` vocabulary. `None` on every executor that
/// isn't an egress lane — so nothing about the existing non-egress fronts changes.
#[derive(Debug, Clone)]
pub struct ActionOutcome {
    pub success: bool,
    pub data: Value,
    pub error: Option<String>,
    pub io: Option<IoRecord>,
}

impl ActionOutcome {
    pub fn ok(data: Value) -> Self {
        Self {
            success: true,
            data,
            error: None,
            io: None,
        }
    }

    pub fn failed(error: impl Into<String>) -> Self {
        Self {
            success: false,
            data: Value::Null,
            error: Some(error.into()),
            io: None,
        }
    }

    /// Attach a governed-lane I/O observation. Chainable on top of [`ActionOutcome::ok`]/`failed`;
    /// the governor reads it to emit the `kriya.io.*` receipt.
    pub fn with_io(mut self, io: Option<IoRecord>) -> Self {
        self.io = io;
        self
    }
}

/// One governed I/O event captured alongside an action — the raw material for a `kriya.io.*`
/// receipt (doc 24 §4.1/§4.2). **Crate-internal**, never the wire schema: the receipt itself rides
/// the frozen `SignedReceipt` shape with a reserved `action_id` and these fields as its `params`.
///
/// The honest ceiling is baked into the field docs: bytes are *observed payload bytes* (never
/// wire/TLS/header bytes — doc 24 L2/L4), `content_sha256` is a *commitment to observed content
/// under the named scheme* and is deliberately **not** recomputable from these fields (L7), and a
/// `deny` record is written at the decision point, before/instead of execution (L10).
#[derive(Debug, Clone)]
pub struct IoRecord {
    /// `egress` (agent → outside) or `ingress` (outside → agent) — one of the two closed values.
    pub direction: IoDirection,
    /// The destination host on a lane where "destination" is a host (the gateway HTTP upstream, a
    /// WebFetch URL). `None` where it is not (a stdio child's argv, an `mcp` server whose endpoint
    /// isn't claimable — doc 24 §4.3): kriya sees only what crossed its own pipe.
    pub dest_host: Option<String>,
    /// The closed four-value kind — never a fifth (doc 24 §4.2 rule 5 / §6-H6).
    pub dest_kind: IoKind,
    /// The MCP method / HTTP verb when meaningful (`tools/call`, `GET`), else `None`.
    pub method: Option<String>,
    /// Observed *payload* bytes sent — request-body length, never wire/TLS/header bytes (L2/L4).
    pub bytes_out: Option<u64>,
    /// Observed *payload* bytes received. On an SSE stream this is the bytes consumed up to the
    /// correlated reply, with [`Self::bytes_in_is_partial`] set (L2).
    pub bytes_in: Option<u64>,
    /// `true` when `bytes_in` is a lower bound (SSE early-return; chunked with no trustworthy
    /// length). The receipt label is always "observed payload bytes"; this flag says how partial.
    pub bytes_in_is_partial: bool,
    /// Hex SHA-256 / HMAC committing to the observed content under [`Self::hash_scheme`]. A
    /// commitment to observed content, NOT recomputable from these fields (L7).
    pub content_sha256: Option<String>,
    /// Which bytes `content_sha256` commits to — required on every emitted receipt (L6 / §4.2 r6).
    pub hash_scheme: HashScheme,
    /// The policy decision that produced this record (L10 for `deny`).
    pub decision: IoDecision,
    /// The operator-authored policy pattern the destination matched (`*.vendor.com`), when a rule
    /// matched — carried as the receipt's `policy_rule` param so the destination is echoed only as a
    /// string the operator already authored.
    pub policy_rule: Option<String>,
    /// The operator identity that approved an `approve`-tier egress → the receipt's `approved_by`.
    pub approved_by: Option<String>,
    /// A short, human-readable reason on a `deny` (allowlist, byte budget, fail-closed).
    pub reason: Option<String>,
    /// The server NAME for an `mcp` dest_kind whose endpoint is not claimable (the hook lane) —
    /// carried in a *separate* param, never conflated with a host (doc 24 §6-H6).
    pub server: Option<String>,
    /// Additive detection-pack signals (doc 24 §11 / EG-P) that rode ALONG with this record rather
    /// than deciding it — e.g. an `AlertOrDeny::Alert` DNS-exfil match on an otherwise-allowed
    /// egress. Each entry is a short self-describing tag (`"b5-dns-exfil:entropy=4.32"`); never a
    /// raw matched value (B7's redact-or-deny keeps secret/PII values out of every flag string, by
    /// construction — type+hash only, same rule as the rest of the receipt). Empty on the common
    /// path; a `deny` decision never needs a flag because [`Self::reason`] already says why.
    pub flags: Vec<String>,
}

/// Egress (agent → outside) or ingress (outside → agent). The first facet of a `kriya.io.*` id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoDirection {
    Egress,
    Ingress,
}

impl IoDirection {
    pub fn facet(self) -> &'static str {
        match self {
            IoDirection::Egress => "egress",
            IoDirection::Ingress => "ingress",
        }
    }
}

/// The closed four-value destination kind — the second facet of a `kriya.io.*` id. Pinning it to
/// exactly these four (never a fifth like "mcp-connector") is what keeps redaction structural and
/// policy prefix-globs total (doc 24 §4.2 rule 5 / §6-H6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoKind {
    Mcp,
    Http,
    Model,
    File,
}

impl IoKind {
    pub fn facet(self) -> &'static str {
        match self {
            IoKind::Mcp => "mcp",
            IoKind::Http => "http",
            IoKind::Model => "model",
            IoKind::File => "file",
        }
    }
}

/// What `content_sha256` commits to. The gateway lane hashes exact wire strings; the hook lane
/// hashes the canonical key-sorted serialization — two different definitions under one field, so
/// the receipt must say which (doc 24 §4.2 rule 6 / L6), or the IPE guarantee reverses under
/// sampling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashScheme {
    WireBytes,
    CanonicalJson,
}

impl HashScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            HashScheme::WireBytes => "wire-bytes",
            HashScheme::CanonicalJson => "canonical-json",
        }
    }
}

/// The decision facet of a `kriya.io.*` id: `allow` (no gate), `approve` (approval-gated + granted),
/// `deny` (blocked: allowlist / byte budget / fail-closed / refused approval).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoDecision {
    Allow,
    Deny,
    Approve,
}

impl IoDecision {
    pub fn facet(self) -> &'static str {
        match self {
            IoDecision::Allow => "allow",
            IoDecision::Deny => "deny",
            IoDecision::Approve => "approve",
        }
    }
}

impl IoRecord {
    /// The reserved `action_id` this record signs under: `kriya.io.<direction>.<kind>.<decision>`
    /// — one of the 24 enumerated ids (2 × 4 × 3). The closed facets are what make the id
    /// prefix-globbable by policy and structurally redactable by the console minimizer.
    pub fn action_id(&self) -> String {
        format!(
            "kriya.io.{}.{}.{}",
            self.direction.facet(),
            self.dest_kind.facet(),
            self.decision.facet()
        )
    }

    /// Build the receipt `params` for this record: `corr` (the correlated action `step_id`, absent
    /// on a decision-point deny that never produced an action receipt) plus every present io field.
    /// Correlation is by `corr`, never adjacency (doc 24 L5).
    pub fn params(&self, corr: Option<&str>) -> Value {
        let mut m = serde_json::Map::new();
        if let Some(c) = corr {
            m.insert("corr".into(), Value::String(c.to_string()));
        }
        if let Some(h) = &self.dest_host {
            m.insert("dest_host".into(), Value::String(h.clone()));
        }
        m.insert(
            "dest_kind".into(),
            Value::String(self.dest_kind.facet().to_string()),
        );
        if let Some(s) = &self.server {
            m.insert("server".into(), Value::String(s.clone()));
        }
        if let Some(meth) = &self.method {
            m.insert("method".into(), Value::String(meth.clone()));
        }
        if let Some(b) = self.bytes_out {
            m.insert("bytes_out".into(), Value::from(b));
        }
        if let Some(b) = self.bytes_in {
            m.insert("bytes_in".into(), Value::from(b));
            if self.bytes_in_is_partial {
                m.insert("bytes_in_is_partial".into(), Value::Bool(true));
            }
        }
        if let Some(h) = &self.content_sha256 {
            m.insert("content_sha256".into(), Value::String(h.clone()));
        }
        m.insert(
            "hash_scheme".into(),
            Value::String(self.hash_scheme.as_str().to_string()),
        );
        if let Some(r) = &self.policy_rule {
            m.insert("policy_rule".into(), Value::String(r.clone()));
        }
        if let Some(a) = &self.approved_by {
            m.insert("approved_by".into(), Value::String(a.clone()));
        }
        if let Some(r) = &self.reason {
            m.insert("reason".into(), Value::String(r.clone()));
        }
        if !self.flags.is_empty() {
            m.insert(
                "flags".into(),
                Value::Array(self.flags.iter().cloned().map(Value::String).collect()),
            );
        }
        m.insert(
            "decision".into(),
            Value::String(self.decision.facet().to_string()),
        );
        Value::Object(m)
    }
}

/// Runs an action that has already passed every governance gate. Implementations must not
/// re-check policy — that decision was already made and audited by the [`super::governor`].
pub trait ActionExecutor: Send {
    fn execute(&mut self, action_id: &str, params: &Value) -> ActionOutcome;

    /// Set (or clear, with `None`) the cooperative origin chain for the calls that follow — the
    /// comma-joined `X-Kriya-Chain` value an HTTP-transport executor forwards on its upstream
    /// request. Set by the governor for exactly one dispatch and cleared after it. Default: no-op
    /// (an in-process or stdio executor has no header to carry it on).
    fn set_call_chain(&mut self, _chain: Option<&str>) {}
}

/// Adapts a closure into an [`ActionExecutor`]. Handy for tests and for embedders that
/// already hold a dispatch function.
pub struct FnExecutor<F>(pub F);

impl<F> ActionExecutor for FnExecutor<F>
where
    F: FnMut(&str, &Value) -> ActionOutcome + Send,
{
    fn execute(&mut self, action_id: &str, params: &Value) -> ActionOutcome {
        (self.0)(action_id, params)
    }
}

/// Runs each cleared action by shelling out to an external command — the simplest way to
/// bolt governed MCP onto an app that isn't Tauri. For every call the executor spawns the
/// command, writes one line of `{"action","params"}` JSON to its stdin, and reads one line
/// of `{"success","data","error"}` JSON back from its stdout. The app supplies that handler.
///
/// Per-call spawn keeps this dependency-free and stateless — fine for cheap, stateless
/// handlers. For a handler that holds an expensive connection, use
/// [`PersistentProcessExecutor`], which keeps it alive across calls (same line contract).
pub struct ProcessExecutor {
    program: String,
    args: Vec<String>,
}

impl ProcessExecutor {
    /// Build from a shell-style command string, e.g. `"node handle-action.js"`. Split on
    /// whitespace — the first token is the program, the rest are fixed leading arguments.
    pub fn new(command: &str) -> Self {
        let mut parts = command.split_whitespace().map(String::from);
        let program = parts.next().unwrap_or_default();
        let args = parts.collect();
        Self { program, args }
    }

    fn run(&self, action_id: &str, params: &Value) -> Result<ActionOutcome, String> {
        use std::io::{BufRead, BufReader, Write};
        use std::process::{Command, Stdio};

        let mut child = Command::new(&self.program)
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("failed to spawn '{}': {e}", self.program))?;

        {
            let stdin = child.stdin.as_mut().ok_or("child stdin unavailable")?;
            writeln!(stdin, "{}", request_line(action_id, params))
                .map_err(|e| format!("write to child failed: {e}"))?;
        } // drop stdin → EOF, so handlers that read-to-end terminate.

        let stdout = child.stdout.take().ok_or("child stdout unavailable")?;
        let mut last_line = String::new();
        for line in BufReader::new(stdout).lines() {
            let line = line.map_err(|e| format!("read from child failed: {e}"))?;
            if !line.trim().is_empty() {
                last_line = line;
            }
        }
        let _ = child.wait();

        if last_line.trim().is_empty() {
            return Err("handler produced no JSON response line".into());
        }
        parse_reply(&last_line)
    }
}

impl ActionExecutor for ProcessExecutor {
    fn execute(&mut self, action_id: &str, params: &Value) -> ActionOutcome {
        // Any plumbing failure becomes a failed outcome the agent can read — never a panic
        // that would take down the whole MCP session.
        self.run(action_id, params)
            .unwrap_or_else(ActionOutcome::failed)
    }
}

/// The handler-reply contract, shared by every process executor: one line of
/// `{ success: bool, data?: any, error?: string }`.
fn request_line(action_id: &str, params: &Value) -> String {
    serde_json::json!({ "action": action_id, "params": params }).to_string()
}

fn parse_reply(line: &str) -> Result<ActionOutcome, String> {
    let reply: Value =
        serde_json::from_str(line).map_err(|e| format!("handler response was not JSON: {e}"))?;
    let success = reply
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if success {
        Ok(ActionOutcome::ok(
            reply.get("data").cloned().unwrap_or(Value::Null),
        ))
    } else {
        let err = reply
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("handler reported failure")
            .to_string();
        Ok(ActionOutcome::failed(err))
    }
}

/// Like [`ProcessExecutor`], but keeps the handler process **alive across calls** — spawned
/// once, then one request line and one response line per action over its stdio. This is what a
/// real bolt-on needs: a handler that holds an expensive in-process connection (e.g. Actual
/// Budget's `@actual-app/api`, which loads a local SQLite budget on `init()`) pays that cost
/// once, not on every `tools/call`. Same line contract as `ProcessExecutor`, so the same
/// handler script works in either mode.
///
/// The child is spawned lazily on the first call and reused thereafter; if it dies, the next
/// call surfaces the failure as a failed `ActionOutcome` (never a panic).
pub struct PersistentProcessExecutor {
    program: String,
    args: Vec<String>,
    proc: Option<Handles>,
}

struct Handles {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    stdout: std::io::BufReader<std::process::ChildStdout>,
}

impl PersistentProcessExecutor {
    pub fn new(command: &str) -> Self {
        let mut parts = command.split_whitespace().map(String::from);
        let program = parts.next().unwrap_or_default();
        let args = parts.collect();
        Self {
            program,
            args,
            proc: None,
        }
    }

    fn ensure(&mut self) -> Result<&mut Handles, String> {
        if self.proc.is_none() {
            use std::process::{Command, Stdio};
            let mut child = Command::new(&self.program)
                .args(&self.args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .map_err(|e| format!("failed to spawn '{}': {e}", self.program))?;
            let stdin = child.stdin.take().ok_or("child stdin unavailable")?;
            let stdout = child.stdout.take().ok_or("child stdout unavailable")?;
            self.proc = Some(Handles {
                child,
                stdin,
                stdout: std::io::BufReader::new(stdout),
            });
        }
        Ok(self.proc.as_mut().expect("just set"))
    }

    fn run(&mut self, action_id: &str, params: &Value) -> Result<ActionOutcome, String> {
        let h = self.ensure()?;
        match exchange(&mut h.stdin, &mut h.stdout, action_id, params) {
            Ok(outcome) => Ok(outcome),
            Err(e) => {
                // A broken pipe / dead handler means this child is unusable — drop it so the
                // next call respawns a fresh one.
                let _ = h.child.kill();
                self.proc = None;
                Err(e)
            }
        }
    }
}

/// One persistent-handler round-trip: write a request line, read exactly one non-blank
/// response line. Generic over the streams so the protocol is unit-testable without a real
/// process.
fn exchange<W: std::io::Write, R: std::io::BufRead>(
    stdin: &mut W,
    stdout: &mut R,
    action_id: &str,
    params: &Value,
) -> Result<ActionOutcome, String> {
    writeln!(stdin, "{}", request_line(action_id, params))
        .map_err(|e| format!("write to handler failed: {e}"))?;
    stdin
        .flush()
        .map_err(|e| format!("flush to handler failed: {e}"))?;

    let mut line = String::new();
    loop {
        line.clear();
        let n = stdout
            .read_line(&mut line)
            .map_err(|e| format!("read from handler failed: {e}"))?;
        if n == 0 {
            return Err("handler closed its output before replying".into());
        }
        if !line.trim().is_empty() {
            return parse_reply(line.trim());
        }
    }
}

impl ActionExecutor for PersistentProcessExecutor {
    fn execute(&mut self, action_id: &str, params: &Value) -> ActionOutcome {
        self.run(action_id, params)
            .unwrap_or_else(ActionOutcome::failed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_reply_maps_success_and_failure() {
        let ok = parse_reply(r#"{"success":true,"data":{"id":1}}"#).unwrap();
        assert!(ok.success);
        assert_eq!(ok.data, json!({"id": 1}));

        let bad = parse_reply(r#"{"success":false,"error":"nope"}"#).unwrap();
        assert!(!bad.success);
        assert_eq!(bad.error.as_deref(), Some("nope"));

        assert!(parse_reply("not json").is_err());
    }

    #[test]
    fn exchange_writes_request_and_reads_one_reply() {
        let mut sent: Vec<u8> = Vec::new();
        // Handler "output": a blank line (must be skipped) then the real reply.
        let mut out = std::io::Cursor::new("\n{\"success\":true,\"data\":42}\n");

        let outcome = exchange(&mut sent, &mut out, "categorize_txn", &json!({"id": 7})).unwrap();
        assert!(outcome.success);
        assert_eq!(outcome.data, json!(42));

        // The request line we wrote carries the action + params.
        let request = String::from_utf8(sent).unwrap();
        let v: serde_json::Value = serde_json::from_str(request.trim()).unwrap();
        assert_eq!(v["action"], "categorize_txn");
        assert_eq!(v["params"]["id"], 7);
    }

    #[test]
    fn exchange_errors_when_handler_closes_without_replying() {
        let mut sent: Vec<u8> = Vec::new();
        let mut out = std::io::Cursor::new(""); // immediate EOF
        let err = exchange(&mut sent, &mut out, "a", &json!({})).unwrap_err();
        assert!(err.contains("closed"), "got: {err}");
    }
}
