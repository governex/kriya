//! `kriya-hook` — govern **the whole Claude Code lane** via its hooks seam (R30): native tools
//! (Bash, Edit, Write, …) **and every MCP server attached to Claude Code** (`mcp__<server>__<tool>`
//! calls). Servers added straight to Claude Code never pass a gateway — hooks are the one seam
//! that sees them all, with zero per-server config (the snippet below sets **no `matcher`**, and
//! per the hooks contract an absent matcher fires for *every* tool — verified 2026-07-03 against
//! the hooks reference). The gateway remains the seam for *other* MCP clients (Claude Desktop,
//! Cursor, …). One paste into `~/.claude/settings.json`:
//!
//! ```jsonc
//! { "hooks": {
//!     "PreToolUse":  [{ "hooks": [{ "type": "command", "command": "kriya-hook pre" }] }],
//!     "PostToolUse": [{ "hooks": [{ "type": "command", "command": "kriya-hook post" }] }]
//! } }
//! ```
//!
//! Claude Code pipes a JSON payload on stdin (`hook_event_name`, `tool_name`, `tool_input`,
//! and on PostToolUse `tool_response` — see the hooks reference:
//! <https://docs.anthropic.com/en/docs/claude-code/hooks>). Mapping: every tool call becomes the
//! governed action `claude-code__<tool_name lowercased>` with `params = tool_input`; MCP tools
//! keep their full name, so `mcp__github__create_issue` becomes
//! `claude-code__mcp__github__create_issue` — which makes **per-server policy** a prefix glob
//! (`claude-code__mcp__github__*`).
//!
//! ## Division of labor (why two hooks)
//! - **`pre` is the GATE.** Policy check (+ optional human approval). A blocked call exits **2**
//!   with the reason on stderr (the documented blocking contract — Claude sees why and adapts)
//!   and signs a `success:false` receipt so **attempts are evidence too**. An allowed call exits
//!   0 and signs nothing — the outcome isn't known yet.
//! - **`post` is the RECORD.** Signs the Ed25519, hash-chained receipt of what actually ran
//!   (success derived from `tool_response`). Install BOTH: `pre` alone gates but records only
//!   blocks; `post` alone records but never gates.
//!
//! Receipts append to the standard on-device audit dir (`~/.kriya/audit/claude-code.jsonl`) under
//! a **persistent** signing identity (`~/.kriya/keys/claude-code-hook.key`, 0600, auto-created) —
//! the Console auto-discovers the log (R27) and `kriya-audit` / the 5-language verifiers re-prove
//! it offline. The hash chain seeds from the log tail, so the chain spans hook invocations even
//! though each is a fresh process.
//!
//! ## Flags (both subcommands)
//! ```text
//! kriya-hook pre|post [--policy <p.yaml>] [--approval deny|tty|gui|auto|file]
//!                     [--audit-log <path>] [--signing-key <path>]
//!                     [--actor <agent>] [--user <user>]
//! ```
//! Default policy is **record-only** (`action: "*"` → allow): evidence first, zero broken
//! sessions; enforce by passing a policy (first match wins, no match = deny), e.g.
//! ```yaml
//! rules:
//!   - { action: "claude-code__read",  allow: true }
//!   - { action: "claude-code__glob",  allow: true }
//!   - { action: "claude-code__grep",  allow: true }
//!   - { action: "claude-code__bash",  allow: true, require_approval: true }
//!   # MCP servers attached to Claude Code, gated per server:
//!   - { action: "claude-code__mcp__github__*",  allow: true, require_approval: true }
//!   - { action: "claude-code__mcp__*",          allow: false }
//!   - { action: "claude-code__*",     allow: true }
//! ```
//!
//! ## Honest boundaries (documented, not hidden)
//! - **Fail-closed:** a malformed `pre` payload or unreadable policy blocks the call (exit 2) —
//!   governance that fails open is theater. `post` is best-effort (loud stderr, exit 0): the tool
//!   already ran; blocking after the fact only breaks the session.
//! - Hooks are a **cooperative seam**: whoever controls `settings.json` controls the hook (use
//!   managed settings org-wide; the *absence* of expected receipts is itself visible in the
//!   Console's coverage view).
//! - Per-minute **budget caps don't apply here**: each hook call is a fresh process, so there is
//!   no in-process rate state. Budgets live in the long-running gateway; the hook's `post`
//!   receipts still make volume visible after the fact.
//! - Approval modes: `deny` (default — a `require_approval` rule blocks unless changed), `tty`
//!   (prompt on /dev/tty — terminal sessions only), `gui` (macOS dialog), `auto` (approve all —
//!   demos only), `file` (route to an out-of-band decider such as K-Apter via the JSONL mailbox —
//!   for a standalone headless device; self-bounds at 300s → deny, same as tty/gui).
//!   **Claude Code's own hook timeout (600s default for command hooks) fails OPEN on
//!   expiry** — a killed/timed-out hook is treated as no decision, and the tool proceeds. This is
//!   the opposite of an earlier version of this comment, which incorrectly claimed timeouts fail
//!   closed; verified against the current hooks reference. `tty`/`gui` mitigate this the only way
//!   this binary can: both self-bound an unanswered prompt at 300s (well under Claude Code's own
//!   ceiling) and deny on their own timeout, so the decision is made here, not by an external kill.
//!   We deliberately do **not** use Claude Code's native `permissionDecision:"ask"` for the
//!   approval tier — it has documented, reproducible reliability gaps (doesn't always fire in
//!   headless `claude -p` mode, can race with tool execution there, and has been observed silently
//!   overridden by a broad `permissions.allow` rule elsewhere in settings, letting the tool run
//!   with no prompt at all) — `tty`/`gui` are the more reliable mechanism this binary controls
//!   end-to-end.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use kriya::audit::{default_audit_dir, now_ms, Actor, Receipt, Signer};
use kriya::corr::{self, Correlation};
use kriya::memwrite;
use kriya::pay;
#[cfg(target_os = "macos")]
use kriya::mcp::GuiApproval;
use kriya::mcp::{
    ApprovalGate, AutoApprove, DenyApproval, FileApproval, HashScheme, IoDecision, IoDirection,
    IoKind, IoRecord, TtyApproval,
};
use kriya::permissions::{
    url_host, BudgetCtx, BudgetGateDecision, BudgetGateRecord, CondRecord, Decision, GateDecision,
    GateRecord, OnUnavailable, Policy, TemporalDecision, Tier,
};
use kriya::shift_guard;
use kriya::secrets::{
    find_placeholder_aliases, json_escape_inner, read_keychain_secret, redact_broker_values,
    substitute_placeholders,
};
use kriya::session_cond;
use kriya::duration;
use kriya::spend_state::{state_dir_for_audit_log, SpendState};
use serde::Deserialize;
use serde_json::Value;

/// Record-only default: sign everything, block nothing, until the operator authors a policy.
/// (The in-process host's deny-by-default is right for app actions; silently bricking a user's
/// coding agent on install is not — evidence first, enforcement by explicit choice.)
const DEFAULT_POLICY_YAML: &str = "rules:\n  - { action: \"*\", allow: true }\n";

/// The slice of the Claude Code hook payload we consume. Unknown fields are ignored on purpose —
/// the payload grows over time and the adapter must not break when it does.
#[derive(Debug, Deserialize)]
struct HookPayload {
    #[serde(default)]
    tool_name: Option<String>,
    #[serde(default)]
    tool_input: Option<Value>,
    #[serde(default)]
    tool_response: Option<Value>,
    /// Run correlation (S3): the Claude Code session id — stable across every tool call in one
    /// session, including a spawned subagent's calls — so it is the run scope for `kriya.corr.run_id`.
    #[serde(default)]
    session_id: Option<String>,
    /// Run correlation (S3): the per-agent id. Claude Code stamps a DIFFERENT `agent_id` on a spawned
    /// subagent's tool calls than on the main agent's, with no parent-step pointer anywhere in the
    /// payload (verified 2026-07-22 against the hooks reference) — so it is the honest sub-agent
    /// discriminator for `kriya.corr.agent_id` (nests `run → subagent → actions`), and the hook never
    /// fabricates a `parent_step_id` it cannot see. Absent on payloads/versions that omit it.
    #[serde(default)]
    agent_id: Option<String>,
}

struct Args {
    mode: String,
    policy: Option<PathBuf>,
    approval: String,
    audit_log: Option<PathBuf>,
    signing_key: Option<PathBuf>,
    actor: String,
    user: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut argv = std::env::args().skip(1);
    let mode = match argv.next() {
        Some(m) if m == "pre" || m == "post" => m,
        Some(other) => return Err(format!("unknown subcommand '{other}' (expected pre|post)")),
        None => return Err("usage: kriya-hook pre|post [--policy p.yaml] …".into()),
    };
    let mut args = Args {
        mode,
        policy: None,
        approval: "deny".into(),
        audit_log: None,
        signing_key: None,
        actor: "claude-code".into(),
        user: None,
    };
    while let Some(flag) = argv.next() {
        let mut val = |name: &str| argv.next().ok_or_else(|| format!("{name} needs a value"));
        match flag.as_str() {
            "--policy" => args.policy = Some(PathBuf::from(val("--policy")?)),
            "--approval" => args.approval = val("--approval")?,
            "--audit-log" => args.audit_log = Some(PathBuf::from(val("--audit-log")?)),
            "--signing-key" => args.signing_key = Some(PathBuf::from(val("--signing-key")?)),
            "--actor" => args.actor = val("--actor")?,
            "--user" => args.user = Some(val("--user")?),
            other => return Err(format!("unknown flag '{other}'")),
        }
    }
    Ok(args)
}

/// Map a Claude Code tool name onto the governed action id namespace.
fn action_id_for(tool_name: &str) -> String {
    format!("claude-code__{}", tool_name.to_lowercase())
}

/// Success of a completed call, derived from `tool_response`: an explicit `success` bool wins;
/// an `error`/`is_error`/`isError` marker means failure; otherwise the tool ran and returned →
/// success. `isError` (camelCase) is the MCP `CallToolResult` convention — without it every failed
/// `mcp__*` call would sign as a success, which is wrong evidence.
fn outcome_success(tool_response: Option<&Value>) -> bool {
    match tool_response {
        None => true,
        Some(v) => {
            if let Some(b) = v.get("success").and_then(Value::as_bool) {
                return b;
            }
            if v.get("error").is_some() {
                return false;
            }
            for key in ["is_error", "isError"] {
                if let Some(b) = v.get(key).and_then(Value::as_bool) {
                    return !b;
                }
            }
            true
        }
    }
}

fn load_policy(path: Option<&PathBuf>) -> Result<Policy, String> {
    match path {
        None => serde_yaml::from_str(DEFAULT_POLICY_YAML)
            .map_err(|e| format!("built-in default policy failed to parse: {e}")),
        Some(p) => {
            let text = std::fs::read_to_string(p)
                .map_err(|e| format!("cannot read policy {}: {e}", p.display()))?;
            serde_yaml::from_str(&text)
                .map_err(|e| format!("policy {} is not valid YAML: {e}", p.display()))
        }
    }
}

fn approval_gate(mode: &str) -> Result<Box<dyn ApprovalGate>, String> {
    match mode {
        "deny" => Ok(Box::new(DenyApproval)),
        "tty" => Ok(Box::new(TtyApproval)),
        "auto" => Ok(Box::new(AutoApprove)),
        // file: route to an out-of-band decider (K-Apter) via the JSONL mailbox — for a standalone
        // device with no tty and no window server. Deny-default on timeout/IO error.
        "file" => Ok(Box::new(FileApproval::with_default_dir())),
        #[cfg(target_os = "macos")]
        "gui" => Ok(Box::new(GuiApproval)),
        other => Err(format!("unknown --approval mode '{other}'")),
    }
}

/// `<audit-dir>/claude-code.jsonl` (default) or the operator's `--audit-log` override — computed
/// once here so both [`signer_for`] and the C2 budget-gate consult (which derives the state dir as
/// `<audit-dir>/../state`, F-C1) agree on exactly the same path, no new flag involved.
fn resolved_audit_log_path(args: &Args) -> PathBuf {
    match &args.audit_log {
        Some(p) => p.clone(),
        None => default_audit_dir().join("claude-code.jsonl"),
    }
}

/// The stable per-front audit log + persisted signing identity (defaults; flags override).
fn signer_for(args: &Args) -> Result<Signer, String> {
    let log_path = resolved_audit_log_path(args);
    if let Some(dir) = log_path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    }
    let key_path = match &args.signing_key {
        Some(p) => p.clone(),
        None => {
            let keys = default_audit_dir()
                .parent()
                .map(|p| p.join("keys"))
                .unwrap_or_else(|| PathBuf::from(".kriya-keys"));
            std::fs::create_dir_all(&keys)
                .map_err(|e| format!("cannot create {}: {e}", keys.display()))?;
            keys.join("claude-code-hook.key")
        }
    };
    let signer = Signer::with_identity(&key_path, log_path)?;
    Ok(maybe_attach_pq(signer, &key_path))
}

/// A5 (design D3, `pq-crypto` feature only): attach a PQ (ML-DSA-87) identity beside the
/// persisted Ed25519 one, at a seed file colocated with `key_path`
/// (`<dir>/pq-signing.seed`). Checkpoint-only mode (`dual_sign_enabled = false` — design D1
/// default). Fail-open on any PQ-key error (logs to stderr, continues without the PQ lane) —
/// mirrors `kriya-gateway`'s `maybe_attach_pq` exactly; a broken PQ seed file must never block a
/// hook invocation (each one IS the process — there is no "start up without the feature" retry).
#[cfg(feature = "pq-crypto")]
fn maybe_attach_pq(signer: Signer, key_path: &Path) -> Signer {
    let pq_seed_path = key_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("pq-signing.seed");
    match signer.with_pq(&pq_seed_path, false) {
        Ok(s) => s,
        Err((s, e)) => {
            eprintln!("[kriya-hook] PQ (ML-DSA-87) identity unavailable, continuing without it: {e}");
            s
        }
    }
}
#[cfg(not(feature = "pq-crypto"))]
fn maybe_attach_pq(signer: Signer, _key_path: &Path) -> Signer {
    signer
}

/// Build the `kriya.spend.gate.*` receipt `params` (D4) — count/cost/hash/id/timestamp only, never
/// transcript content. The runtime never prices: `observed_usd`/`pricing_sheet`/`pricing_sheet_hash`
/// are copied straight through from the Console-written state file the [`BudgetGateRecord`] carries.
fn budget_gate_params(r: &BudgetGateRecord) -> Value {
    serde_json::json!({
        "v": 1,
        "budget_id": r.budget_id,
        "scope": r.scope.as_str(),
        "scope_key": r.scope_key,
        "threshold_usd": r.threshold_usd,
        "observed_usd": r.observed_usd,
        "action": r.action.as_str(),
        "state_source": r.state_source,
        "state_as_of_ms": r.state_as_of_ms,
        "state_stale": r.state_stale,
        "on_missing_state": r.on_missing_state.map(|s| s.as_str()),
        "pricing_sheet": r.pricing_sheet,
        "pricing_sheet_hash": r.pricing_sheet_hash,
    })
}

/// B4 (doc 27 §4 / docs/design/b4-temporal-conditions.md D4) — the `kriya.policy.cond.*` receipt
/// `params`. `CondRecord` derives `Serialize` with field names that already match the D4 shape
/// (`rule_id`/`action_id`/`subject_selector`/`tier`/`conditions`/`now_ms`/`index_as_of_ms`/
/// `index_source`) — this only adds the schema-version marker every field-set here is
/// ids/patterns/counts/bools/timestamps, NEVER the agent's command content (D4's privacy audit).
fn cond_params(r: &CondRecord) -> Value {
    let mut v = serde_json::to_value(r).unwrap_or(Value::Null);
    if let Value::Object(ref mut map) = v {
        map.insert("v".to_string(), serde_json::json!(1));
    }
    v
}

/// B4: `params.command` when present (the Bash lane) — `None` for every other tool. The C2
/// `egress_target_for`/`budget_gate_params` sibling.
fn command_of(params: &Value) -> Option<&str> {
    params.get("command").and_then(Value::as_str)
}

/// F-2: the `kriya.gate.<class>.*` receipt params — [`GateRecord`]'s serde shape (ids, class,
/// tier, matcher kind, recipient CLASS; never command content — design §5) + the schema-version
/// marker + `corr_step` pointing at the blocked attempt's own action receipt when one was written.
fn gate_params(rec: &GateRecord, corr_step: Option<&str>) -> Value {
    let mut v = serde_json::to_value(rec).unwrap_or(Value::Null);
    if let Value::Object(ref mut map) = v {
        map.insert("v".to_string(), serde_json::json!(1));
        if let Some(step) = corr_step {
            map.insert("corr_step".to_string(), serde_json::json!(step));
        }
    }
    v
}

/// F-4 Inc 3 (kriya-console doc 31 §3.6 / doc 33 §4-A): the payment lane. When a governed call
/// matches a `payment`-class action gate, the hook emits the purchase-receipt CHAIN alongside the
/// `kriya.gate.payment.*` receipt — `kriya.pay.intent` (what the agent asked, best-effort amount) →
/// `kriya.pay.decision` (the gate result). The `pay_id` is derived deterministically from the call
/// (see [`pay::pay_id_for`]) so the *post* hook's `kriya.pay.outcome` chains on without any marker
/// file. This writes the OPEN half of the chain (intent + decision); the outcome is written by the
/// deny arm (below, synchronously) or by the post hook (for calls that actually run). Returns the
/// shared `pay_id`. Merchant is a processor/host string only (custody stays in EG-B — no PAN here).
fn emit_pay_open(
    signer: &Signer,
    actor: &Actor,
    corr: &Correlation,
    session_id: Option<&str>,
    tool_name: &str,
    action_id: &str,
    params: &Value,
    rec: &GateRecord,
    decision: &str,
    approver: Option<&str>,
) -> String {
    let pay_id = pay::pay_id_for(session_id, tool_name, &canonical_json_string(params));
    let merchant = egress_target_for(tool_name, params).and_then(|(_, host, server)| host.or(server));
    record(
        signer,
        actor,
        pay::PAY_INTENT,
        pay::intent_params(&pay_id, merchant.as_deref(), tool_name, action_id, params),
        true,
        corr,
    );
    // A held/denied decision is not a success (mirrors the gate held/denied receipts' `success:false`);
    // an approved one is. The Console folds by `pay_id`, reading `decision`/`success` for the chip.
    record(
        signer,
        actor,
        pay::PAY_DECISION,
        pay::decision_params(&pay_id, decision, &rec.rule_id, approver),
        decision == "approved",
        corr,
    );
    pay_id
}

/// Sign the action receipt and return its `step_id` so a correlated `kriya.io.*` receipt can carry
/// it as `corr` (doc 24 §4.2 — correlation by `corr`, never adjacency, L5).
///
/// Run correlation (S3): `corr` stamps `kriya.corr` (run_id + agent_id) into `params` via the shared,
/// seam-authoritative [`kriya::corr::attach`] — one placement, reused by every emitter. Empty
/// correlation leaves `params` byte-identical to the pre-S3 receipt.
fn record(
    signer: &Signer,
    actor: &Actor,
    action_id: &str,
    params: Value,
    success: bool,
    corr: &Correlation,
) -> String {
    let step_id = uuid::Uuid::new_v4().to_string();
    signer.record(
        Receipt::new(
            step_id.clone(),
            action_id.to_string(),
            corr::attach(params, corr),
            success,
            now_ms(),
        )
        .with_actor(Some(actor.clone())),
    );
    step_id
}

/// Resolve the governed-lane egress destination for a Claude Code tool, if one is knowable.
/// Returns `(kind, dest_host, server)`:
/// - `mcp__<server>__<tool>` → an `mcp` destination carrying the server NAME (its endpoint is not
///   claimable, so no host — doc 24 §6-H6).
/// - a tool whose `tool_input` has a `url` (WebFetch) → an `http` destination with the parsed host.
/// - **Bash → `None`**: a shell command has no single extractable destination — never invent one
///   (doc 24 §4.1). Edit/Write/Read and a URL-less WebSearch likewise → `None`.
fn egress_target_for(
    tool_name: &str,
    tool_input: &Value,
) -> Option<(IoKind, Option<String>, Option<String>)> {
    if let Some(rest) = tool_name.strip_prefix("mcp__") {
        let server = rest.split("__").next().unwrap_or(rest).to_string();
        return Some((IoKind::Mcp, None, Some(server)));
    }
    if tool_name.eq_ignore_ascii_case("bash") {
        return None; // never extract a URL from a shell command (doc 24 §4.1)
    }
    if let Some(url) = tool_input.get("url").and_then(Value::as_str) {
        return Some((IoKind::Http, Some(url_host(url)), None));
    }
    None
}

/// Emit a `kriya.io.egress.<kind>.<decision>` receipt for a hook-lane tool call. Records
/// **payload bytes** (the serialized `tool_input` size) — NEVER network bytes — and a content hash
/// over the CANONICAL key-sorted serialization (`hash_scheme: canonical-json`), a different
/// definition than the gateway lane's wire bytes and labeled as such (doc 24 §4.2 rule 6 / L6).
/// Hash + size only, never content (L9). `tool_input` here MUST already be safe to hash/record — see
/// `redact_broker_values` at every hook-lane call site where `policy.secrets()` is configured (doc 24
/// §11 B13): this function itself does no redaction, it trusts its caller.
#[allow(clippy::too_many_arguments)]
fn emit_io_egress(
    signer: &Signer,
    actor: &Actor,
    kind: IoKind,
    dest_host: Option<String>,
    server: Option<String>,
    tool_input: &Value,
    decision: IoDecision,
    reason: Option<String>,
    corr: &str,
    flags: Vec<String>,
) {
    let canon = canonical_json_string(tool_input);
    let io = IoRecord {
        direction: IoDirection::Egress,
        dest_host,
        dest_kind: kind,
        method: None,
        bytes_out: Some(canon.len() as u64),
        bytes_in: None,
        bytes_in_is_partial: false,
        content_sha256: Some(sha256_hex(canon.as_bytes())),
        hash_scheme: HashScheme::CanonicalJson,
        decision,
        policy_rule: None,
        approved_by: None,
        reason,
        server,
        flags,
    };
    signer.record(
        Receipt::new(
            uuid::Uuid::new_v4().to_string(),
            io.action_id(),
            io.params(Some(corr)),
            decision != IoDecision::Deny,
            now_ms(),
        )
        .with_actor(Some(actor.clone())),
    );
}

/// Emit a `kriya.io.ingress.<kind>.allow` receipt: a **KEYED** hash + size of the tool response
/// (doc 24 §6-P3). The hash is HMAC-SHA256 under a device-local salt over the canonical
/// serialization, so a receipt-holder without the salt cannot dictionary-attack guessable content —
/// an unsalted hash of guessable content is content disclosure. Hash + size only, never content (L9).
fn emit_io_ingress(
    signer: &Signer,
    actor: &Actor,
    kind: IoKind,
    server: Option<String>,
    tool_response: &Value,
    salt: &[u8],
    corr: &str,
) {
    let canon = canonical_json_string(tool_response);
    let io = IoRecord {
        direction: IoDirection::Ingress,
        dest_host: None,
        dest_kind: kind,
        method: None,
        bytes_out: None,
        bytes_in: Some(canon.len() as u64),
        bytes_in_is_partial: false,
        content_sha256: Some(hmac_sha256_hex(salt, canon.as_bytes())),
        hash_scheme: HashScheme::CanonicalJson,
        decision: IoDecision::Allow,
        policy_rule: None,
        approved_by: None,
        reason: None,
        server,
        flags: Vec::new(),
    };
    signer.record(
        Receipt::new(
            uuid::Uuid::new_v4().to_string(),
            io.action_id(),
            io.params(Some(corr)),
            true,
            now_ms(),
        )
        .with_actor(Some(actor.clone())),
    );
}

/// Lowercase-hex SHA-256.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// HMAC-SHA256 (lowercase hex) — RFC 2104, built on `sha2` so the hook adds no HMAC dependency. The
/// keyed ingress hash (doc 24 §6-P3).
fn hmac_sha256_hex(key: &[u8], msg: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let d = Sha256::digest(key);
        k[..d.len()].copy_from_slice(&d);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let inner = {
        let mut h = Sha256::new();
        h.update(ipad);
        h.update(msg);
        h.finalize()
    };
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    hex::encode(outer.finalize())
}

/// Canonical key-sorted JSON serialization — the commitment `content_sha256` is taken over on the
/// hook lane. Matches `kriya::audit`'s param canonicalization so the definition is consistent.
fn canonical_json_string(v: &Value) -> String {
    serde_json::to_string(&canonical_value(v)).unwrap_or_default()
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

/// Load (or create + persist, 0600) the device-local HMAC salt for keyed ingress hashing. Co-located
/// with the hook's signing key. Best-effort: an unwritable location returns an in-memory salt so
/// ingress recording still functions within the run.
fn load_or_create_ingress_salt(args: &Args) -> [u8; 32] {
    let path = match &args.signing_key {
        Some(p) => p.with_file_name("ingress-hmac.salt"),
        None => default_audit_dir()
            .parent()
            .map(|p| p.join("keys"))
            .unwrap_or_else(|| PathBuf::from(".kriya-keys"))
            .join("ingress-hmac.salt"),
    };
    if let Ok(text) = std::fs::read_to_string(&path) {
        if let Ok(bytes) = hex::decode(text.trim()) {
            if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                return arr;
            }
        }
    }
    let salt: [u8; 32] = rand::random();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if std::fs::write(&path, hex::encode(salt)).is_ok() {
        restrict_salt_perms(&path);
    }
    salt
}

#[cfg(unix)]
fn restrict_salt_perms(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn restrict_salt_perms(_path: &Path) {}

/// Emit a `kriya.io.egress.*.deny` receipt for a blocked hook-lane tool call, when the destination
/// is knowable and the policy carries an egress tier (doc 24 L10 — the deny is receipted at the
/// decision point). No-op otherwise.
fn maybe_record_io_deny(
    signer: &Signer,
    actor: &Actor,
    policy: &Policy,
    tool_name: &str,
    tool_input: &Value,
    reason: &str,
    corr: &str,
) {
    if policy.egress().is_none() {
        return;
    }
    if let Some((kind, host, server)) = egress_target_for(tool_name, tool_input) {
        emit_io_egress(
            signer,
            actor,
            kind,
            host,
            server,
            tool_input,
            IoDecision::Deny,
            Some(reason.to_string()),
            corr,
            Vec::new(),
        );
    }
}

/// Sign a `kriya.io.egress.<kind>.deny` receipt for a credential-brokering refusal (doc 24 §11 B13):
/// an unconfigured or misrouted alias on a tool whose destination IS knowable. Fires whenever
/// `secrets:` is configured, independent of whether `egress:` is ALSO configured — brokering is its
/// own policy section with its own gate, unlike [`maybe_record_io_deny`] above which rides the
/// egress tier's own switch. No-op when the destination isn't knowable at all (Bash, matching
/// `egress_target_for`'s own "never invent one" rule) — that case is still evidenced by the plain
/// action receipt every `pre` caller already writes; there's no host/server to attribute an io
/// receipt to.
fn record_brokering_deny(
    signer: &Signer,
    actor: &Actor,
    tool_name: &str,
    tool_input: &Value,
    reason: &str,
    corr: &str,
) {
    if let Some((kind, host, server)) = egress_target_for(tool_name, tool_input) {
        emit_io_egress(
            signer,
            actor,
            kind,
            host,
            server,
            tool_input,
            IoDecision::Deny,
            Some(reason.to_string()),
            corr,
            Vec::new(),
        );
    }
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("kriya-hook: {e}");
            return ExitCode::from(2); // fail closed — a misconfigured gate must not wave calls through
        }
    };

    let mut stdin = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut stdin) {
        eprintln!("kriya-hook: cannot read hook payload: {e}");
        return fail_mode_exit(&args.mode);
    }
    let payload: HookPayload = match serde_json::from_str(&stdin) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("kriya-hook: hook payload is not the expected JSON: {e}");
            return fail_mode_exit(&args.mode);
        }
    };
    let tool_name = match payload.tool_name.as_deref() {
        Some(t) if !t.is_empty() => t,
        _ => {
            eprintln!("kriya-hook: payload has no tool_name");
            return fail_mode_exit(&args.mode);
        }
    };
    let action_id = action_id_for(tool_name);
    let params = payload.tool_input.clone().unwrap_or(Value::Null);

    let user = args
        .user
        .clone()
        .or_else(|| std::env::var("USER").ok())
        .unwrap_or_else(|| "unknown".into());
    let actor = Actor::new(args.actor.clone(), user);

    // Run correlation (S3): stamp the session as `run_id` and the sub-agent id (when present) so the
    // Console can build the `run → subagent → actions` tree from verified receipts. `parent_step_id`
    // is deliberately NOT set — the Claude Code payload carries no parent pointer (W0-3), and guessing
    // lineage the seam can't see is dishonest (doc 24 locus discipline). Empty ⇒ params byte-identical.
    let corr = Correlation {
        run_id: payload.session_id.clone().filter(|s| !s.is_empty()),
        parent_step_id: None,
        agent_id: payload.agent_id.clone().filter(|s| !s.is_empty()),
    };

    let signer = match signer_for(&args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("kriya-hook: signer unavailable: {e}");
            return fail_mode_exit(&args.mode);
        }
    };

    // Both modes need the policy: `pre` for the decision, `post` for whether to record io receipts.
    let policy = match load_policy(args.policy.as_ref()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "kriya-hook: {e} — {}",
                if args.mode == "pre" {
                    "blocking (fail closed)"
                } else {
                    "skipping io (fail open)"
                }
            );
            return fail_mode_exit(&args.mode);
        }
    };

    match args.mode.as_str() {
        "pre" => {
            // O-3 (kriya-console doc 32 §4 O-3 / doc 33 §5.5): capture this call's START instant +
            // its identity correlation key up front. The marker is written ONLY on the allow paths
            // below (a denied call, which post never follows, leaves none); the *post* invocation
            // reads+deletes it to stamp `kriya.dur.ms`. Key = session+tool+canonical(`params`) — the
            // same derivation `pay_id` uses, and the same `params` (raw tool_input, pre-brokering)
            // that post re-derives from its placeholder-redacted `safe_params` (they canonicalize
            // identically — see the post-hook pay_id note). All best-effort: a marker failure NEVER
            // affects the decision (the session_cond "cache is never the source of truth" law).
            let dur_t_start = now_ms() as u64;
            let dur_log_path = resolved_audit_log_path(&args);
            let dur_state_dir = state_dir_for_audit_log(&dur_log_path);
            let dur_key = duration::call_key(
                payload.session_id.as_deref(),
                tool_name,
                &canonical_json_string(&params),
            );
            // Opportunistic, bounded sweep of markers whose post never arrived (session ended, key
            // collision) — runs on pre so a marker written later this run is never its own victim.
            duration::sweep_stale(&dur_state_dir, dur_t_start, duration::MAX_MARKER_AGE_MS);

            match policy.check(&action_id) {
                Decision::Allow => {} // the post hook records the outcome
                Decision::RequiresApproval => {
                    let gate = match approval_gate(&args.approval) {
                        Ok(g) => g,
                        Err(e) => {
                            eprintln!("kriya-hook: {e} — blocking (fail closed)");
                            return ExitCode::from(2);
                        }
                    };
                    if !gate.request(&action_id, &params) {
                        let step_id =
                            record(&signer, &actor, &action_id, params.clone(), false, &corr);
                        maybe_record_io_deny(
                            &signer,
                            &actor,
                            &policy,
                            tool_name,
                            &params,
                            "requires human approval; not granted",
                            &step_id,
                        );
                        eprintln!(
                            "kriya-hook: '{action_id}' requires human approval and was not approved \
                             (kriya policy; approval mode: {}). A signed receipt of the blocked \
                             attempt was recorded.",
                            args.approval
                        );
                        return ExitCode::from(2);
                    }
                }
                Decision::Deny => {
                    let step_id = record(&signer, &actor, &action_id, params.clone(), false, &corr);
                    maybe_record_io_deny(
                        &signer,
                        &actor,
                        &policy,
                        tool_name,
                        &params,
                        "denied by kriya policy",
                        &step_id,
                    );
                    eprintln!(
                        "kriya-hook: '{action_id}' is denied by kriya policy. A signed receipt of \
                         the blocked attempt was recorded."
                    );
                    return ExitCode::from(2);
                }
            }

            // F-2 (kriya-console doc 31 §3.3 / the F2-gates design doc (kriya-console)) — action gates.
            // Placed FIRST among the escalation dimensions (before B4 temporal and the C2 budget
            // gate): gates are pure in-process pattern matching — no session fold, no external
            // state — so a gate-denied action is blocked before any state producer runs at all.
            // Tighten-only, exactly like B4: a gate can only ESCALATE the already-resolved
            // Allow/granted-approval above to approval/deny; the deny/ungranted-approval outcomes
            // already returned. Receipt vocabulary: kriya.gate.<class>.{evaluated,held,approved,
            // denied}. On a block, the ACTION receipt (success:false, params = tool_input — exactly
            // what the action-tier deny path records) is written first and the gate receipt points
            // at it via `corr_step`, so the Console shows the exact command without the gate
            // receipt itself carrying command content (design §5 privacy discipline).
            if let Some(gates) = policy.gates() {
                match gates.evaluate(tool_name, &params, &action_id) {
                    GateDecision::Pass => {}
                    GateDecision::Receipt(rec) => {
                        record(
                            &signer,
                            &actor,
                            &format!("kriya.gate.{}.evaluated", rec.class),
                            gate_params(&rec, None),
                            true,
                            &corr,
                        );
                        // F-4 Inc 3: a receipt-tier payment gate lets the call proceed — open the
                        // purchase chain as approved; the post hook writes the outcome.
                        if rec.class == "payment" {
                            emit_pay_open(
                                &signer, &actor, &corr, payload.session_id.as_deref(),
                                tool_name, &action_id, &params, &rec, "approved", None,
                            );
                        }
                    }
                    GateDecision::Approval(rec) => {
                        let gate = match approval_gate(&args.approval) {
                            Ok(g) => g,
                            Err(e) => {
                                eprintln!("kriya-hook: {e} — blocking (fail closed)");
                                return ExitCode::from(2);
                            }
                        };
                        if gate.request(&action_id, &params) {
                            record(
                                &signer,
                                &actor,
                                &format!("kriya.gate.{}.approved", rec.class),
                                gate_params(&rec, None),
                                true,
                                &corr,
                            );
                            // F-4 Inc 3: a human granted the approve-tier payment gate — open the
                            // chain as approved with the operator as approver; post writes outcome.
                            if rec.class == "payment" {
                                emit_pay_open(
                                    &signer, &actor, &corr, payload.session_id.as_deref(),
                                    tool_name, &action_id, &params, &rec, "approved",
                                    Some(actor.user.as_str()),
                                );
                            }
                        } else {
                            let step_id =
                                record(&signer, &actor, &action_id, params.clone(), false, &corr);
                            record(
                                &signer,
                                &actor,
                                &format!("kriya.gate.{}.held", rec.class),
                                gate_params(&rec, Some(&step_id)),
                                false,
                                &corr,
                            );
                            // F-4 Inc 3: a held payment is the honest 2/3 chain shape — intent +
                            // decision(held), NO outcome (it neither executed nor failed; it awaits
                            // a human). The Console renders "2/3 steps · held".
                            if rec.class == "payment" {
                                emit_pay_open(
                                    &signer, &actor, &corr, payload.session_id.as_deref(),
                                    tool_name, &action_id, &params, &rec, "held", None,
                                );
                            }
                            eprintln!(
                                "kriya-hook: the {} gate requires human approval for '{action_id}' \
                                 and it was not granted (rule: {}; approval mode: {}). A signed \
                                 receipt of the held attempt was recorded.",
                                rec.class, rec.rule_id, args.approval
                            );
                            return ExitCode::from(2);
                        }
                    }
                    GateDecision::Deny(rec) => {
                        let step_id =
                            record(&signer, &actor, &action_id, params.clone(), false, &corr);
                        record(
                            &signer,
                            &actor,
                            &format!("kriya.gate.{}.denied", rec.class),
                            gate_params(&rec, Some(&step_id)),
                            false,
                            &corr,
                        );
                        // F-4 Inc 3: a denied payment never runs, so the outcome is known NOW —
                        // the full chain closes synchronously (intent → decision(denied) →
                        // outcome(denied)); there is no post hook for a blocked call.
                        if rec.class == "payment" {
                            let pay_id = emit_pay_open(
                                &signer, &actor, &corr, payload.session_id.as_deref(),
                                tool_name, &action_id, &params, &rec, "denied", None,
                            );
                            record(
                                &signer,
                                &actor,
                                pay::PAY_OUTCOME,
                                pay::outcome_params(&pay_id, "denied", None),
                                false,
                                &corr,
                            );
                        }
                        eprintln!(
                            "kriya-hook: the {} gate denied '{action_id}' (rule: {}). A signed \
                             receipt of the blocked attempt was recorded.",
                            rec.class, rec.rule_id
                        );
                        return ExitCode::from(2);
                    }
                }
            }

            // B4 (doc 27 §4 / docs/design/b4-temporal-conditions.md D3) — temporal policy
            // conditions. Placed HERE, immediately after the F-2 gates block above (temporal is a
            // *workflow-ordering* precondition — cheaper than the C2 budget gate below, no
            // external state producer — so a workflow-illegal action is blocked before any
            // spend/keychain work runs at all).
            // Tighten-only (axiom 5): a temporal rule can only ESCALATE this already-resolved
            // Allow/granted-approval to approval/deny; it can never loosen the deny/ungranted-
            // approval outcomes above, which already returned.
            if let Some(temporal) = policy.temporal() {
                let log_path = resolved_audit_log_path(&args);
                let state_dir = state_dir_for_audit_log(&log_path);
                let run_id = payload.session_id.clone().unwrap_or_default();
                let command = command_of(&params);

                let decision = match session_cond::load_or_build(&state_dir, &run_id, &log_path) {
                    Ok(fold) => {
                        let mut decision =
                            temporal.evaluate(&fold.events, &action_id, command, now_ms() as u64);
                        if let TemporalDecision::Approval(ref mut rec) | TemporalDecision::Deny(ref mut rec) =
                            decision
                        {
                            rec.index_source = fold.source;
                        }
                        decision
                    }
                    Err(_unavailable) => match temporal.first_matching_rule(&action_id, command) {
                        None => TemporalDecision::Pass, // no rule even concerns this action
                        Some(rule) => {
                            let unavailable_record = CondRecord {
                                rule_id: rule.id.clone(),
                                action_id: action_id.clone(),
                                subject_selector: rule.selector.clone(),
                                tier: rule.tier,
                                conditions: Vec::new(),
                                now_ms: now_ms() as u64,
                                index_as_of_ms: now_ms() as u64,
                                index_source: "unavailable",
                            };
                            match rule.on_unavailable_posture() {
                                OnUnavailable::FailOpen => TemporalDecision::Pass,
                                OnUnavailable::RequireApproval => {
                                    TemporalDecision::Approval(unavailable_record)
                                }
                                OnUnavailable::FailClosed => {
                                    TemporalDecision::Deny(unavailable_record)
                                }
                            }
                        }
                    },
                };

                match decision {
                    TemporalDecision::Pass => {}
                    TemporalDecision::Approval(rec) => {
                        let gate = match approval_gate(&args.approval) {
                            Ok(g) => g,
                            Err(e) => {
                                eprintln!("kriya-hook: {e} — blocking (fail closed)");
                                return ExitCode::from(2);
                            }
                        };
                        if !gate.request(&action_id, &params) {
                            record(&signer, &actor, "kriya.policy.cond.approval", cond_params(&rec), false, &corr);
                            eprintln!(
                                "kriya-hook: temporal rule '{}' requires human approval and was not \
                                 approved (approval mode: {}). A signed receipt of the blocked \
                                 attempt was recorded.",
                                rec.rule_id, args.approval
                            );
                            return ExitCode::from(2);
                        }
                    }
                    TemporalDecision::Deny(rec) => {
                        record(&signer, &actor, "kriya.policy.cond.deny", cond_params(&rec), false, &corr);
                        eprintln!(
                            "kriya-hook: temporal rule '{}' denied '{action_id}' — a signed receipt \
                             of the blocked attempt was recorded.",
                            rec.rule_id
                        );
                        return ExitCode::from(2);
                    }
                }
            }

            // F-6 (doc 31 §9 / doc 33 §4-C; design ../kriya-console/docs/ideas/design/F6-shift.md) —
            // the shift-armed fail-closed clamp. Placed HERE in the same tighten-only slot as the
            // temporal (B4) lane above and the budget (C2) lane below: it can only ESCALATE the
            // already-resolved Allow/granted-approval to approval|deny, never loosen the deny/
            // ungranted-approval outcomes that already returned. Reads the Console-written armed
            // state (~/.kriya/state/shift.json) + the freshest heartbeat; state absent/unparseable ⇒
            // NO clamp (the session_cond "cache is never the source of truth" law — availability is
            // never held hostage to the state file; the enforcement fail-closed IS the clamp, applied
            // only when the state is readable and says a beat was actually missed inside the window).
            {
                let log_path = resolved_audit_log_path(&args);
                let state_dir = state_dir_for_audit_log(&log_path);
                if let Some(guard) = shift_guard::load(&state_dir) {
                    let last_beat = shift_guard::last_heartbeat_ms(&log_path);
                    if let Some(tier) = guard.clamp(now_ms() as u64, last_beat) {
                        let age_ms = last_beat.map(|b| (now_ms() as u64).saturating_sub(b));
                        let clamp_params = serde_json::json!({
                            "reason": "missed-heartbeat",
                            "tier": if tier == Tier::Deny { "deny" } else { "approval" },
                            "shift_start_ms": guard.start_ms,
                            "shift_end_ms": guard.end_ms,
                            "cadence_ms": guard.cadence_ms,
                            "last_heartbeat_age_ms": age_ms,
                            "last_heartbeat_seen": last_beat.is_some(),
                        });
                        match tier {
                            Tier::Approval => {
                                let gate = match approval_gate(&args.approval) {
                                    Ok(g) => g,
                                    Err(e) => {
                                        eprintln!("kriya-hook: {e} — blocking (fail closed)");
                                        return ExitCode::from(2);
                                    }
                                };
                                if !gate.request(&action_id, &params) {
                                    record(&signer, &actor, "kriya.shift.clamp", clamp_params, false, &corr);
                                    eprintln!(
                                        "kriya-hook: unattended shift armed and a heartbeat was missed \
                                         — '{action_id}' held for approval (fail-closed tier) and was \
                                         not granted (approval mode: {}). A signed receipt of the \
                                         blocked attempt was recorded.",
                                        args.approval
                                    );
                                    return ExitCode::from(2);
                                }
                            }
                            Tier::Deny => {
                                record(&signer, &actor, "kriya.shift.clamp", clamp_params, false, &corr);
                                eprintln!(
                                    "kriya-hook: unattended shift armed and a heartbeat was missed — \
                                     '{action_id}' denied (fail-closed tier). A signed receipt of the \
                                     blocked attempt was recorded."
                                );
                                return ExitCode::from(2);
                            }
                            Tier::Allow => {} // shift_guard::fail_tier never yields Allow (axiom 5)
                        }
                    }
                }
            }

            // C2 (doc 27 §4 / docs/design/c2-budget-gate.md D6/F-B1) — the endpoint budget gate.
            // Placed HERE, immediately after the action-tier `Decision::Allow` / granted-approval
            // resolution above and BEFORE the credential-brokering block below (`if let Some(secrets)
            // = policy.secrets()`) — never after it. The brokering block returns early on a
            // successful `{{kriya:*}}` substitution, so a consult placed after it would never run
            // for a credential-brokered call, silently failing the `deny` tier open on exactly the
            // highest-privilege (secret-injecting) calls (the B0 fix, F-B1). A budget can only ever
            // ESCALATE this already-resolved Allow/granted-approval to approval/deny — it can never
            // loosen the deny/ungranted-approval outcomes above, which already returned.
            if let Some(budgets) = policy.budgets() {
                let log_path = resolved_audit_log_path(&args);
                let state_dir = state_dir_for_audit_log(&log_path);
                let state = SpendState::load(&state_dir);
                let ctx = BudgetCtx { session_id: payload.session_id.as_deref(), os_user: &actor.user };
                match budgets.check(&state, &ctx, now_ms() as u64) {
                    BudgetGateDecision::Pass => {}
                    BudgetGateDecision::Warn(r) => {
                        record(
                            &signer,
                            &actor,
                            "kriya.spend.gate.warn",
                            budget_gate_params(&r),
                            true,
                            &corr,
                        );
                    }
                    BudgetGateDecision::Approval(r) => {
                        let gate = match approval_gate(&args.approval) {
                            Ok(g) => g,
                            Err(e) => {
                                eprintln!("kriya-hook: {e} — blocking (fail closed)");
                                return ExitCode::from(2);
                            }
                        };
                        if !gate.request(&action_id, &params) {
                            record(
                                &signer,
                                &actor,
                                "kriya.spend.gate.approval",
                                budget_gate_params(&r),
                                false,
                                &corr,
                            );
                            eprintln!(
                                "kriya-hook: budget '{}' requires human approval and was not \
                                 approved (observed ${:.2} >= threshold ${:.2}; approval mode: {}). \
                                 A signed receipt of the blocked attempt was recorded.",
                                r.budget_id, r.observed_usd, r.threshold_usd, args.approval
                            );
                            return ExitCode::from(2);
                        }
                    }
                    BudgetGateDecision::Deny(r) => {
                        record(
                            &signer,
                            &actor,
                            "kriya.spend.gate.deny",
                            budget_gate_params(&r),
                            false,
                            &corr,
                        );
                        eprintln!(
                            "kriya-hook: budget '{}' is denied — observed ${:.2} {} threshold \
                             ${:.2} (trailing-state, gated on state as of {}; source: {}). A signed \
                             receipt of the blocked attempt was recorded.",
                            r.budget_id,
                            r.observed_usd,
                            if r.state_stale { "vs (stale/missing)" } else { ">=" },
                            r.threshold_usd,
                            r.state_as_of_ms,
                            r.state_source
                        );
                        return ExitCode::from(2);
                    }
                }
            }

            // Credential brokering (doc 24 §11 B13 / EG-B) — only when the policy configures
            // `secrets:` AND this call's tool_input actually names a `{{kriya:<alias>}}`
            // placeholder; zero behavior change for every other call, which is the overwhelming
            // majority. The agent never sees a real credential: it composed the placeholder, and
            // ONLY the real value (never the placeholder text) is handed to Claude Code via
            // `updatedInput`, injected right here, as late as possible.
            if let Some(secrets) = policy.secrets() {
                let canon = canonical_json_string(&params);
                let aliases = find_placeholder_aliases(&canon);
                if !aliases.is_empty() {
                    let scope = egress_target_for(tool_name, &params)
                        .and_then(|(_, host, server)| host.or(server));
                    let deny_reason = match &scope {
                        None => Some(format!(
                            "credential brokering: '{tool_name}' has no resolvable destination to \
                             scope the placeholder against (B13, fail-closed on ambiguity)"
                        )),
                        Some(dest) => aliases.iter().find_map(|alias| match secrets.find(alias) {
                            None => {
                                Some(format!("credential brokering: alias '{alias}' is not configured (B13)"))
                            }
                            Some(entry) if !entry.allows_host(dest) => Some(format!(
                                "credential brokering: alias '{alias}' is not allowed for destination \
                                 '{dest}' (B13)"
                            )),
                            Some(_) => None,
                        }),
                    };
                    if let Some(reason) = deny_reason {
                        let step_id =
                            record(&signer, &actor, &action_id, params.clone(), false, &corr);
                        record_brokering_deny(
                            &signer, &actor, tool_name, &params, &reason, &step_id,
                        );
                        eprintln!(
                            "kriya-hook: {reason}. A signed receipt of the blocked attempt was recorded."
                        );
                        return ExitCode::from(2);
                    }

                    // Cleared: substitute and hand the real values to Claude Code via updatedInput —
                    // never through this process's own receipt-writing (pre signs nothing further on
                    // allow, matching the existing convention; the io.egress.allow receipt with its
                    // `b13-brokered` flag is POST's job, from the safe placeholder-redacted form).
                    match substitute_placeholders(&canon, |alias| {
                        let entry = secrets.find(alias)?; // already validated above; cheap re-check
                        let raw =
                            read_keychain_secret(&entry.keychain_service, &entry.keychain_account)
                                .ok()?;
                        Some(zeroize::Zeroizing::new(json_escape_inner(&raw)))
                    }) {
                        Ok(Some(substituted)) => {
                            match serde_json::from_str::<Value>(&substituted) {
                                Ok(updated_input) => {
                                    let out = serde_json::json!({
                                        "hookSpecificOutput": {
                                            "hookEventName": "PreToolUse",
                                            "permissionDecision": "allow",
                                            "updatedInput": updated_input,
                                        }
                                    });
                                    // O-3: the brokered call proceeds → stamp its start marker for post.
                                    duration::write_start(&dur_state_dir, &dur_key, dur_t_start);
                                    println!("{out}");
                                    return ExitCode::SUCCESS;
                                }
                                Err(e) => {
                                    eprintln!(
                                    "kriya-hook: credential brokering produced invalid JSON ({e}) — \
                                     blocking (fail closed)"
                                );
                                    return ExitCode::from(2);
                                }
                            }
                        }
                        Ok(None) => {} // unreachable (aliases was non-empty) — fall through to plain allow
                        Err(alias) => {
                            eprintln!(
                                "kriya-hook: credential brokering: alias '{alias}' could not be read \
                                 from Keychain — blocking (fail closed)"
                            );
                            return ExitCode::from(2);
                        }
                    }
                }
            }

            // O-3: a plain (non-brokered) allow proceeds → stamp its start marker for post.
            duration::write_start(&dur_state_dir, &dur_key, dur_t_start);
            ExitCode::SUCCESS
        }
        "post" => {
            // A4 (doc 27 / docs/design/a4-fips-lane.md D2): the hook has no persistent-process
            // "startup" — each invocation IS the process. Fired only from `post` (which always
            // records at least the action receipt below) rather than unconditionally after
            // `signer_for`, so it never disturbs `pre`'s deliberate "signs nothing on a cleared
            // allow" no-write property (a real security invariant — see `brokering.rs`'s
            // `pre signs nothing on a cleared allow` — a pre-hook call that writes NOTHING has no
            // receipt file for a secret to ever leak into). Additive, new `action_id`; never
            // affects the chain a verifier without A4 awareness already accepts.
            signer.attest_crypto_module("kriya-hook", Some(actor.clone()));
            // A5 (doc 27 / docs/design/a5-pq-dual-sig.md §4.2): same "fired only from `post`"
            // reasoning as the A4 attestation above. No-op when this signer has no PQ key loaded.
            #[cfg(feature = "pq-crypto")]
            if let Err(e) = signer.attest_pq_key("kriya-hook", Some(actor.clone())) {
                eprintln!("kriya-hook: skipping PQ key attestation: {e}");
            }

            // Credential brokering safety net (doc 24 §11 B13 / EG-B): it is NOT documented whether
            // Claude Code's PostToolUse payload reflects the ORIGINAL (placeholder) tool_input or the
            // MUTATED one a PreToolUse `updatedInput` substituted — so this never trusts either
            // possibility. When secrets are configured, every configured alias's REAL value is
            // redacted back to `{{kriya:<alias>}}` in `safe_params` BEFORE anything downstream (the
            // action receipt, the io receipt) hashes or records it. If the real value was never
            // present here, every redaction is a harmless no-op; if it WAS, it's gone before it can
            // leak — regardless of which of the two possibilities is actually true.
            let safe_params = match policy.secrets() {
                Some(secrets) => redact_broker_values(&params, secrets),
                None => params.clone(),
            };
            let success = outcome_success(payload.tool_response.as_ref());
            // O-3 (doc 33 §5.5): stamp the measured duration onto THIS action receipt when the pre
            // hook left a start marker for this exact call. The key is derived from `safe_params`
            // (post's placeholder-redacted form), which canonicalizes identically to pre's raw
            // `params` for both plain and brokered calls — the same property that lets `pay_id`
            // chain across the two processes. Absent marker ⇒ params stay byte-identical (honest
            // absence, never an estimate); a negative interval (a collided key) is likewise dropped.
            // Read+delete is best-effort and only ever ADDS optional params — it never blocks.
            let mut action_params = safe_params.clone();
            {
                let dur_state_dir = state_dir_for_audit_log(&resolved_audit_log_path(&args));
                let dur_key = duration::call_key(
                    payload.session_id.as_deref(),
                    tool_name,
                    &canonical_json_string(&safe_params),
                );
                if let Some(t_start) = duration::take_end(&dur_state_dir, &dur_key) {
                    if let Some(dur_ms) = duration::compute_dur_ms(t_start, now_ms() as u64) {
                        duration::annotate_duration(&mut action_params, dur_ms, duration::BASIS_HOOK_PRE_POST);
                    }
                }
            }
            let step_id = record(
                &signer,
                &actor,
                &action_id,
                action_params,
                success,
                &corr,
            );
            // F-4 Inc 3 (kriya-console doc 31 §3.6 / doc 33 §4-A): close the purchase chain for a
            // payment-class call that actually RAN. The pre hook wrote intent + decision(approved);
            // this writes `kriya.pay.outcome`, chained by the SAME deterministic `pay_id` (derived
            // from session + tool + tool_input — identical in both invocations, so no marker file
            // is needed). `result` = executed | denied from the real `tool_response`; `status` is
            // best-effort from that response (absent ⇒ omitted, never invented). We only reach post
            // when pre let the call through, so a payment gate that returns Receipt/Approval here
            // was the approved/receipt tier (deny/held short-circuit pre with exit 2). Derived from
            // `safe_params` so a credential-brokered call's placeholder form matches pre's `pay_id`.
            if let Some(gates) = policy.gates() {
                let is_payment = matches!(
                    gates.evaluate(tool_name, &safe_params, &action_id),
                    GateDecision::Receipt(rec) | GateDecision::Approval(rec) if rec.class == "payment"
                );
                if is_payment {
                    let pay_id = pay::pay_id_for(
                        payload.session_id.as_deref(),
                        tool_name,
                        &canonical_json_string(&safe_params),
                    );
                    let result = if success { "executed" } else { "denied" };
                    let status = pay::status_of(payload.tool_response.as_ref());
                    record(
                        &signer,
                        &actor,
                        pay::PAY_OUTCOME,
                        pay::outcome_params(&pay_id, result, status.as_deref()),
                        success,
                        &corr,
                    );
                }
            }
            // D1 (doc 27 §4 / docs/design/d1-memory-receipts.md D-4): classify + emit a
            // `kriya.memory.*` receipt for a write to a governed persistent-memory surface —
            // unconditional (no policy opt-in), mirroring the base action receipt's own always-on
            // posture; hash-only, never content (§D-3/acceptance #2). No-op for anything not
            // write-shaped or whose path matches none of the four confirmed classes (§D-1).
            if let Some(surface) = memwrite::memory_surface_for(tool_name, &safe_params) {
                let salt = load_or_create_ingress_salt(&args);
                let (mut verb, mut basis) = memwrite::base_verb_for(tool_name);
                if verb == memwrite::MemoryVerb::Write {
                    if let (Some(run_id), Some(path)) = (corr.run_id.as_deref(), surface.path.as_deref()) {
                        let path_hmac = memwrite::path_hmac_hex(&salt, path);
                        // F4: bounded tail scan (500 lines) — never an unbounded log walk; the
                        // fallback (basis stays tool-write) is itself honest, not a loosening.
                        if memwrite::prior_write_seen(&resolved_audit_log_path(&args), run_id, &path_hmac, 500) {
                            verb = memwrite::MemoryVerb::Update;
                            basis = memwrite::VerbBasis::PriorWriteSeen;
                        }
                    }
                }
                let content = memwrite::file_write_content(&safe_params);
                memwrite::emit_memory_receipt(
                    &signer,
                    Some(&actor),
                    verb,
                    basis,
                    &surface,
                    &content,
                    success,
                    &corr,
                    &salt,
                );
            }
            // kriya.io.* receipts (doc 24 §7.3): recorded only when the policy opts in via an
            // `egress:` section, and only for a tool whose destination is knowable (WebFetch host,
            // mcp server) — Bash and file tools produce none (doc 24 §4.1).
            if let Some(egress) = policy.egress() {
                if let Some((kind, host, server)) = egress_target_for(tool_name, &safe_params) {
                    // Only ever flag an alias that's actually configured — a stray literal
                    // `{{kriya:...}}`-shaped string that isn't one PRE would ever have brokered
                    // must not be mislabeled as a brokering event.
                    let flags: Vec<String> =
                        find_placeholder_aliases(&canonical_json_string(&safe_params))
                            .into_iter()
                            .filter(|a| policy.secrets().is_some_and(|s| s.find(a).is_some()))
                            .map(|alias| format!("b13-brokered:{alias}"))
                            .collect();
                    emit_io_egress(
                        &signer,
                        &actor,
                        kind,
                        host,
                        server.clone(),
                        &safe_params,
                        IoDecision::Allow,
                        None,
                        &step_id,
                        flags,
                    );
                    // Ingress digests ride their OWN switch, default OFF (doc 24 §6-P3): a keyed
                    // (HMAC) hash + size of the response, never its content.
                    if egress.record_ingress() {
                        if let Some(resp) = payload.tool_response.as_ref() {
                            let salt = load_or_create_ingress_salt(&args);
                            emit_io_ingress(&signer, &actor, kind, server, resp, &salt, &step_id);
                        }
                    }
                }
            }
            ExitCode::SUCCESS
        }
        _ => unreachable!("parse_args validated the mode"),
    }
}

/// `pre` fails CLOSED (exit 2 blocks the call); `post` fails OPEN-but-loud (exit 0 — the tool
/// already ran; blocking after the fact only breaks the session, so surface the evidence gap on
/// stderr instead).
fn fail_mode_exit(mode: &str) -> ExitCode {
    if mode == "pre" {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// S3 run correlation: the hook builds `Correlation { run_id = session_id, agent_id }` from the
    /// payload and NEVER a `parent_step_id` (the Claude Code payload has no parent pointer). The
    /// `record()` helper stamps `kriya.corr` into params while leaving the tool args intact; a
    /// payload without a session id leaves params byte-identical.
    #[test]
    fn hook_stamps_run_correlation_from_the_payload_and_never_a_parent() {
        let dir = std::env::temp_dir().join(format!("kriya-hook-corr-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("claude-code.jsonl");
        let actor = Actor::new("claude-code", "tester");
        let s = Signer::with_identity(&dir.join("k.key"), log.clone()).unwrap();

        // A subagent's tool call: session_id (run) + a distinct agent_id, no parent pointer.
        let corr = Correlation {
            run_id: Some("sess-42".into()),
            parent_step_id: None,
            agent_id: Some("subagent-7".into()),
        };
        record(
            &s,
            &actor,
            "claude-code__bash",
            json!({"command":"ls"}),
            true,
            &corr,
        );

        // No correlation at all → params byte-identical to the raw tool input.
        record(
            &s,
            &actor,
            "claude-code__read",
            json!({"file_path":"a.txt"}),
            true,
            &Correlation::default(),
        );

        let lines: Vec<String> = std::fs::read_to_string(&log)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        let v0: Value = serde_json::from_str(&lines[0]).unwrap();
        let v1: Value = serde_json::from_str(&lines[1]).unwrap();

        // The correlated receipt: reserved key present, tool arg intact, NO parent_step_id.
        assert_eq!(v0["params"]["kriya.corr"]["run_id"], json!("sess-42"));
        assert_eq!(v0["params"]["kriya.corr"]["agent_id"], json!("subagent-7"));
        assert!(v0["params"]["kriya.corr"].get("parent_step_id").is_none());
        assert_eq!(v0["params"]["command"], json!("ls"));

        // The uncorrelated receipt: NO reserved key — params is exactly the raw tool input.
        assert_eq!(v1["params"], json!({"file_path":"a.txt"}));
        assert!(v1["params"].get("kriya.corr").is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn maps_tool_names_into_the_governed_namespace() {
        assert_eq!(action_id_for("Bash"), "claude-code__bash");
        assert_eq!(action_id_for("WebFetch"), "claude-code__webfetch");
        // MCP tools keep their full name under the same namespace — the whole Claude Code lane,
        // native + attached MCP servers, one action-id scheme.
        assert_eq!(
            action_id_for("mcp__github__create_issue"),
            "claude-code__mcp__github__create_issue"
        );
    }

    // ─── EG-2: hook-lane io destinations + keyed ingress (doc 24 §4.1 / §6-P3) ───────────────────

    #[test]
    fn egress_target_extraction_by_tool() {
        // WebFetch → an http destination with the parsed host.
        let (kind, host, server) =
            egress_target_for("WebFetch", &json!({"url": "https://api.vendor.com/v1"})).unwrap();
        assert_eq!(kind, IoKind::Http);
        assert_eq!(host.as_deref(), Some("api.vendor.com"));
        assert!(server.is_none());

        // mcp__<server>__<tool> → an mcp destination carrying the SERVER NAME, no host.
        let (kind, host, server) =
            egress_target_for("mcp__github__create_issue", &json!({})).unwrap();
        assert_eq!(kind, IoKind::Mcp);
        assert!(host.is_none(), "an mcp endpoint is not a claimable host");
        assert_eq!(server.as_deref(), Some("github"));

        // Bash → NEVER extract a URL, even if the command contains one.
        assert!(
            egress_target_for("Bash", &json!({"command": "curl https://evil.example"})).is_none(),
            "Bash must never yield an egress destination"
        );
        // Edit/Write and a url-less WebSearch → no destination.
        assert!(egress_target_for("Edit", &json!({"file_path": "/x"})).is_none());
        assert!(egress_target_for("WebSearch", &json!({"query": "kriya"})).is_none());
    }

    #[test]
    fn ingress_hash_is_keyed_so_it_is_not_a_content_disclosure() {
        // The SAME content under two different device salts must hash differently — a receipt-holder
        // without the salt cannot dictionary-attack guessable content (doc 24 §6-P3).
        let content = b"did this agent read salary.xlsx?";
        let a = hmac_sha256_hex(&[7u8; 32], content);
        let b = hmac_sha256_hex(&[9u8; 32], content);
        assert_ne!(a, b, "different salts → different keyed hashes");
        assert_eq!(a.len(), 64, "sha256 hex");
        // Deterministic under a fixed salt.
        assert_eq!(a, hmac_sha256_hex(&[7u8; 32], content));
        // Differs from a plain (unkeyed) SHA-256 of the same content.
        assert_ne!(a, sha256_hex(content));
    }

    #[test]
    fn ingress_receipt_serializes_only_a_keyed_digest_and_size_never_the_content() {
        // L9 sentinel: build an ingress receipt exactly as `emit_io_ingress` does and prove the
        // sensitive content NEVER appears in the receipt params — only the keyed HMAC digest + size.
        let sensitive = json!({ "secret": "AKIAIOSFODNN7EXAMPLE", "path": "salary.xlsx" });
        let canon = canonical_json_string(&sensitive);
        let io = IoRecord {
            direction: IoDirection::Ingress,
            dest_host: None,
            dest_kind: IoKind::Http,
            method: None,
            bytes_out: None,
            bytes_in: Some(canon.len() as u64),
            bytes_in_is_partial: false,
            content_sha256: Some(hmac_sha256_hex(&[3u8; 32], canon.as_bytes())),
            hash_scheme: HashScheme::CanonicalJson,
            decision: IoDecision::Allow,
            policy_rule: None,
            approved_by: None,
            reason: None,
            server: None,
            flags: Vec::new(),
        };
        let params = io.params(Some("corr-x")).to_string();
        assert!(
            !params.contains("AKIAIOSFODNN7EXAMPLE"),
            "the secret must never serialize: {params}"
        );
        assert!(
            !params.contains("salary.xlsx"),
            "content must never serialize: {params}"
        );
        assert!(
            params.contains("content_sha256"),
            "only the keyed digest is present"
        );
        assert!(
            params.contains(&format!("\"bytes_in\":{}", canon.len())),
            "size is present"
        );
    }

    #[test]
    fn canonical_json_is_key_sorted_and_stable() {
        let a = canonical_json_string(&json!({"z": 1, "a": {"y": 2, "b": 3}}));
        let b = canonical_json_string(&json!({"a": {"b": 3, "y": 2}, "z": 1}));
        assert_eq!(a, b, "key order must not change the commitment");
        assert_eq!(a, r#"{"a":{"b":3,"y":2},"z":1}"#);
    }

    #[test]
    fn outcome_success_derivation() {
        assert!(outcome_success(None), "no response info → ran → success");
        assert!(outcome_success(Some(&json!({"success": true}))));
        assert!(!outcome_success(Some(&json!({"success": false}))));
        assert!(!outcome_success(Some(&json!({"error": "boom"}))));
        assert!(!outcome_success(Some(&json!({"is_error": true}))));
        assert!(outcome_success(Some(&json!({"stdout": "ok"}))));
        // MCP CallToolResult convention (camelCase) — a failed MCP call must not sign as success.
        assert!(!outcome_success(Some(&json!({"isError": true}))));
        assert!(outcome_success(Some(
            &json!({"isError": false, "content": []})
        )));
    }

    /// Per-server MCP gating is just a prefix glob over the mapped action id — no new policy
    /// machinery. This is Rung 0a of the PATH→WATCHER ladder: the hook is the whole-Claude-Code
    /// lane, and servers attached directly to Claude Code are governable per server.
    #[test]
    fn an_enforcing_policy_gates_mcp_servers_individually() {
        let p: Policy = serde_yaml::from_str(
            "rules:\n  - { action: \"claude-code__mcp__github__*\", allow: true, require_approval: true }\n  - { action: \"claude-code__mcp__*\", allow: false }\n  - { action: \"claude-code__*\", allow: true }\n",
        )
        .unwrap();
        assert_eq!(
            p.check(&action_id_for("mcp__github__create_issue")),
            Decision::RequiresApproval,
            "named server is approval-gated"
        );
        assert_eq!(
            p.check(&action_id_for("mcp__shady_exfil__send")),
            Decision::Deny,
            "unlisted MCP servers are denied"
        );
        assert_eq!(
            p.check(&action_id_for("Bash")),
            Decision::Allow,
            "native tools ride the trailing namespace rule"
        );
    }

    #[test]
    fn default_policy_records_everything_blocks_nothing() {
        let p: Policy = serde_yaml::from_str(DEFAULT_POLICY_YAML).unwrap();
        assert_eq!(p.check("claude-code__bash"), Decision::Allow);
        assert_eq!(p.check("claude-code__write"), Decision::Allow);
    }

    #[test]
    fn an_enforcing_policy_gates_the_namespace() {
        let p: Policy = serde_yaml::from_str(
            "rules:\n  - { action: \"claude-code__read\", allow: true }\n  - { action: \"claude-code__bash\", allow: true, require_approval: true }\n  - { action: \"*\", allow: false }\n",
        )
        .unwrap();
        assert_eq!(p.check("claude-code__read"), Decision::Allow);
        assert_eq!(p.check("claude-code__bash"), Decision::RequiresApproval);
        assert_eq!(p.check("claude-code__write"), Decision::Deny);
    }

    /// Two separate Signer instances over the SAME log (≈ two hook invocations, fresh process
    /// each) must extend one hash chain under one persisted identity, and deleting a line must
    /// be visible in the chain — the properties that make per-call hook receipts evidence.
    /// (Full signature re-verification is exercised end-to-end by the external verifiers —
    /// `tools/verify-receipts` and the released `kriya-audit` — against a real hook-written log.)
    #[test]
    fn receipts_chain_across_invocations_and_deletion_is_visible() {
        use sha2::{Digest, Sha256};
        let sha256_hex = |b: &[u8]| {
            let mut h = Sha256::new();
            h.update(b);
            hex::encode(h.finalize())
        };

        let dir = std::env::temp_dir().join(format!("kriya-hook-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = dir.join("hook.key");
        let log = dir.join("claude-code.jsonl");
        let actor = Actor::new("claude-code", "tester");

        let s1 = Signer::with_identity(&key, log.clone()).unwrap();
        record(
            &s1,
            &actor,
            "claude-code__bash",
            json!({"command":"ls"}),
            true,
            &Correlation::default(),
        );
        drop(s1); // ≈ the pre/post process exits
        let s2 = Signer::with_identity(&key, log.clone()).unwrap();
        record(
            &s2,
            &actor,
            "claude-code__edit",
            json!({"file":"a.rs"}),
            false,
            &Correlation::default(),
        );

        let text = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        let v1: Value = serde_json::from_str(lines[0]).unwrap();
        let v2: Value = serde_json::from_str(lines[1]).unwrap();

        assert_eq!(
            v1["public_key"], v2["public_key"],
            "one persisted identity across invocations"
        );
        assert_eq!(v1["prev_hash"], Value::Null, "genesis receipt is unchained");
        assert_eq!(
            v2["prev_hash"].as_str().unwrap(),
            sha256_hex(lines[0].as_bytes()),
            "receipt 2 chains to the exact bytes of receipt 1 — across process boundaries"
        );
        assert_eq!(
            v2["success"],
            json!(false),
            "blocked/failed attempts are receipts too"
        );

        // Delete the first line: the survivor still claims a predecessor whose bytes are gone —
        // any chain verifier flags it (prev_hash matches nothing before it).
        assert_ne!(
            v2["prev_hash"],
            Value::Null,
            "after deleting line 1, line 2's dangling prev_hash exposes the deletion"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
