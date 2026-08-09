//! `kriya-govern` — a framework-agnostic **per-call govern + sign** service over stdio.
//!
//! The sibling of `kriya-hook` (Claude Code's hook) and `kriya-mcp` (an MCP server), but with
//! **no protocol wrapper and no agent loop**: it reads one small JSON request per line on stdin and
//! writes one JSON response per line on stdout, so an in-process SDK middleware (LangGraph, CrewAI,
//! the OpenAI/Claude Agent SDKs, …) can route each of its own tool calls through kriya's action
//! gates and get a signed receipt **without an MCP hop and without inverting control** — the
//! framework keeps driving its loop; kriya just governs + signs each call.
//!
//! **The one-Signer law (design law 3).** This binary reimplements NONE of the trust primitives: it
//! reuses the runtime's `Policy` (action gate), `BudgetTracker` (rate cap), `ApprovalGate`, and
//! `Signer` (Ed25519 + hash chain) exactly as the in-process host and `kriya-mcp` do. There is no
//! crypto, no chain writer, and no policy engine here — only orchestration.
//!
//! **Protocol** (one JSON object per line, both directions):
//!   → `{"op":"check","action_id":"create_note","params":{…}}`
//!   ← `{"op":"check","decision":"allow"}`  (or `"denied"` | `"not_approved"` | `"budget_exceeded"`,
//!      the last two/one carrying a `"reason"`). Matches the in-process governor: an action-tier
//!      deny signs NO receipt (only egress denies do, and this lane sees no egress) — the decision
//!      is the record. The middleware surfaces a non-`allow` decision as the framework's own error.
//!   → `{"op":"record","action_id":"create_note","params":{…},"success":true}`
//!   ← `{"op":"record","receipt":{…signed…}}`  the Ed25519-signed, hash-chained receipt appended to
//!      the audit log (byte-identical to every other kriya receipt — the Console re-verifies it).
//!
//! **The split is deliberate.** The tool runs IN the framework's process, so the middleware calls
//! `check` first (policy → approval → budget), runs the real tool only on `allow`, then calls
//! `record` with the outcome — the budget is consumed at `check`, so an allowed-but-unrun call still
//! costs its slot (conservative, never under-counts). One process = one govern session, so the
//! budget cap spans the whole run exactly like a single in-process agent.
//!
//! **Honest ceiling (stated in the SDK READMEs too).** In-process governance is **cooperative**: a
//! hostile agent process can simply not call this. That is what launch-under containment (B14) is
//! for. And because the tool executes in the framework — not here — this lane governs the
//! **action tier** (policy / approval / budget) and signs the receipt; it does NOT see the tool's
//! own outbound network calls, so egress-tier / detection-pack governance is out of scope for it
//! (use the gateway/containment lanes for that).
//!
//! Usage:
//!   kriya-govern [--policy <policy.yaml>] [--approval deny|tty|gui|auto|file]
//!                [--actor <agent>] [--user <user>] [--audit-log <path>]
//!
//!   --policy     YAML permission policy (default: the safe built-in default).
//!   --approval   how `require_approval` actions are decided: deny (default), tty, gui (macOS), auto, file (JSONL mailbox → K-Apter).
//!   --actor      agent identity stamped into every signed receipt's `actor` (R8).
//!   --user       operator identity (default: $USER). Only used with --actor.
//!   --audit-log  signed-receipt JSONL path. Point it at ~/.kriya/audit/<name>.jsonl for the Console
//!                to tail + re-verify it (default: $TMPDIR/kriya-audit.jsonl).

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::process::exit;
use std::sync::Arc;

use kriya::audit::{Actor, Receipt, Signer};
use kriya::budget::BudgetTracker;
use kriya::corr::{self, Correlation};
#[cfg(target_os = "macos")]
use kriya::mcp::GuiApproval;
use kriya::mcp::{ApprovalGate, AutoApprove, DenyApproval, FileApproval, TtyApproval};
use kriya::permissions::{Decision, Policy};
use serde_json::{json, Value};

struct Args {
    policy: Option<PathBuf>,
    approval: String,
    actor: Option<String>,
    user: Option<String>,
    audit_log: Option<PathBuf>,
}

fn usage_and_exit(msg: &str) -> ! {
    eprintln!("kriya-govern: {msg}");
    eprintln!(
        "usage: kriya-govern [--policy <policy.yaml>] [--approval deny|tty|gui|auto|file] \
         [--actor <agent>] [--user <user>] [--audit-log <path>]"
    );
    exit(2);
}

fn parse_args() -> Args {
    let mut policy: Option<PathBuf> = None;
    let mut approval = "deny".to_string();
    let mut actor: Option<String> = None;
    let mut user: Option<String> = None;
    let mut audit_log: Option<PathBuf> = None;

    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut take = |label: &str| -> String {
            it.next()
                .unwrap_or_else(|| usage_and_exit(&format!("{label} needs a value")))
        };
        match flag.as_str() {
            "--policy" => policy = Some(PathBuf::from(take("--policy"))),
            "--approval" => approval = take("--approval"),
            "--actor" => actor = Some(take("--actor")),
            "--user" => user = Some(take("--user")),
            "--audit-log" => audit_log = Some(PathBuf::from(take("--audit-log"))),
            "-h" | "--help" => usage_and_exit("help"),
            other => usage_and_exit(&format!("unknown argument: {other}")),
        }
    }
    Args {
        policy,
        approval,
        actor,
        user,
        audit_log,
    }
}

/// Mirrors `kriya-mcp`'s approval-gate construction so the two governed lanes decide identically.
fn build_approval(mode: &str) -> Box<dyn ApprovalGate> {
    match mode {
        "deny" => Box::new(DenyApproval),
        "auto" => Box::new(AutoApprove),
        "tty" => Box::new(TtyApproval),
        // file: route to an out-of-band decider (K-Apter) via the JSONL mailbox — for a standalone
        // device with no tty and no window server. Deny-default on timeout/IO error.
        "file" => Box::new(FileApproval::with_default_dir()),
        #[cfg(target_os = "macos")]
        "gui" => Box::new(GuiApproval),
        #[cfg(not(target_os = "macos"))]
        "gui" => usage_and_exit("--approval gui is only available on macOS"),
        other => usage_and_exit(&format!(
            "--approval must be deny|tty|gui|auto|file, got '{other}'"
        )),
    }
}

/// Build the receipt actor (R8) from the identity flags — `None` leaves receipts unattributed.
fn build_actor(agent: Option<String>, user: Option<String>) -> Option<Actor> {
    agent.map(|a| {
        let u = user
            .or_else(|| std::env::var("USER").ok())
            .unwrap_or_else(|| "local".to_string());
        Actor::new(a, u)
    })
}

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// The govern session state — one per process, so the budget cap spans the whole run.
struct Session {
    policy: Arc<Policy>,
    signer: Arc<Signer>,
    budget: BudgetTracker,
    approval: Box<dyn ApprovalGate>,
    actor: Option<Actor>,
}

impl Session {
    /// Handle one request line, returning the response line (without the trailing newline). Kept
    /// pure w.r.t. I/O (no stdin/stdout here) so the govern logic is unit-testable directly.
    fn handle(&mut self, line: &str) -> String {
        let req: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => return err_line(&format!("invalid JSON request: {e}")),
        };
        let op = req.get("op").and_then(Value::as_str).unwrap_or("");
        let action_id = req.get("action_id").and_then(Value::as_str).unwrap_or("");
        if action_id.is_empty() {
            return err_line("missing action_id");
        }
        let params = req.get("params").cloned().unwrap_or_else(|| json!({}));

        match op {
            "check" => self.check(action_id, &params),
            "record" => {
                let success = req.get("success").and_then(Value::as_bool).unwrap_or(false);
                // Run correlation (S3): the middleware may attach `{"corr":{"run_id","parent_step_id"}}`
                // per framework invocation / nested call. The reserved-key placement is centralized
                // HERE (the one Signer path) so the TS + Python wrappers never re-implement it.
                let corr = corr::from_json(req.get("corr"));
                self.record(action_id, params, success, &corr)
            }
            other => err_line(&format!("unknown op '{other}' (expected check|record)")),
        }
    }

    /// Action gate → approval (if required) → budget. Signs nothing (parity with the in-process
    /// governor: action-tier denials are not receipts; only executed calls are, via `record`).
    fn check(&mut self, action_id: &str, params: &Value) -> String {
        match self.policy.check(action_id) {
            Decision::Deny => return decision_line("denied", None),
            Decision::RequiresApproval => {
                if !self.approval.request(action_id, params) {
                    return decision_line("not_approved", None);
                }
            }
            Decision::Allow => {}
        }
        // Budget last — a call the human just approved must still respect the rate cap (a runaway
        // that a lax approver keeps clearing is exactly what the cap is for).
        if let Err(reason) = self.budget.check_and_record(now_ms()) {
            return decision_line("budget_exceeded", Some(&reason));
        }
        decision_line("allow", None)
    }

    /// Sign + append the action receipt for a call the middleware executed. Reuses `Signer::record`
    /// — same Ed25519 key, same hash chain, same canonicalization the Console re-verifies. Run
    /// correlation (S3) rides `corr` → the shared, seam-authoritative `kriya.corr` params key; an
    /// empty `corr` leaves `params` byte-identical to the pre-S3 receipt.
    fn record(
        &mut self,
        action_id: &str,
        params: Value,
        success: bool,
        corr: &Correlation,
    ) -> String {
        let step_id = uuid::Uuid::new_v4().to_string();
        let signed = self.signer.record(
            Receipt::new(
                step_id,
                action_id.to_string(),
                corr::attach(params, corr),
                success,
                now_ms(),
            )
            .with_actor(self.actor.clone()),
        );
        match serde_json::to_value(&signed) {
            Ok(receipt) => json!({ "op": "record", "receipt": receipt }).to_string(),
            Err(e) => err_line(&format!("could not serialize receipt: {e}")),
        }
    }
}

fn decision_line(decision: &str, reason: Option<&str>) -> String {
    let mut obj = json!({ "op": "check", "decision": decision });
    if let Some(r) = reason {
        obj["reason"] = json!(r);
    }
    obj.to_string()
}

fn err_line(message: &str) -> String {
    json!({ "op": "error", "error": message }).to_string()
}

fn main() -> std::io::Result<()> {
    let args = parse_args();

    let policy = match &args.policy {
        Some(p) => Policy::load_or_default(p),
        None => Policy::default(),
    };
    let signer = Arc::new(match &args.audit_log {
        Some(p) => Signer::with_log_path(p.clone()),
        None => Signer::new(),
    });
    let budget = BudgetTracker::new(policy.max_actions_per_minute());
    let approval = build_approval(&args.approval);
    let actor = build_actor(args.actor.clone(), args.user.clone());
    // A4 (doc 27 / docs/design/a4-fips-lane.md D2): NOT wired here — `kriya-ci` invokes
    // `kriya-govern` once PER GOVERNED ACTION (see `kriya_ci_smoke.rs`), so a per-invocation
    // attestation would double every action-count assertion in that suite for a low-priority,
    // "optional (consistency)" binary per the design. The crypto lane is still fully migrated to
    // the facade here (`crypto::verify`/`SigningKey` via `Signer`); only the self-attestation
    // RECEIPT is intentionally not emitted by this particular binary.

    let actor_desc = match &actor {
        Some(a) => format!("{}/{}", a.agent, a.user),
        None => "<unattributed>".to_string(),
    };
    eprintln!(
        "[kriya-govern] per-call govern+sign · approval={} · actor={} · audit log={}",
        args.approval,
        actor_desc,
        signer.log_path().display()
    );

    let mut session = Session {
        policy: Arc::new(policy),
        signer,
        budget,
        approval,
        actor,
    };

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let response = session.handle(&line);
        writeln!(out, "{response}")?;
        out.flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session_with(policy_yaml: &str, approval: Box<dyn ApprovalGate>) -> Session {
        let policy: Policy = serde_yaml::from_str(policy_yaml).expect("test policy parses");
        let log = std::env::temp_dir().join(format!(
            "kriya-govern-test-{}-{:?}.jsonl",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_file(&log);
        let signer = Arc::new(Signer::with_log_path(log));
        let budget = BudgetTracker::new(policy.max_actions_per_minute());
        Session {
            policy: Arc::new(policy),
            signer,
            budget,
            approval,
            actor: Some(Actor::new("langgraph", "ci")),
        }
    }

    fn decision(line: &str) -> String {
        let v: Value = serde_json::from_str(line).unwrap();
        v["decision"].as_str().unwrap_or("").to_string()
    }

    #[test]
    fn allow_then_record_produces_a_signed_verifiable_receipt() {
        let mut s = session_with(
            "rules:\n  - { action: \"create_note\", allow: true }\nbudget:\n  max_actions_per_minute: 60\n",
            Box::new(DenyApproval),
        );
        assert_eq!(
            decision(&s.handle(r#"{"op":"check","action_id":"create_note","params":{"t":"x"}}"#)),
            "allow"
        );
        let rec_line = s.handle(
            r#"{"op":"record","action_id":"create_note","params":{"t":"x"},"success":true}"#,
        );
        let v: Value = serde_json::from_str(&rec_line).unwrap();
        assert_eq!(v["op"], "record");
        let receipt = &v["receipt"];
        assert_eq!(receipt["action_id"], "create_note");
        assert_eq!(receipt["success"], true);
        assert_eq!(receipt["actor"]["agent"], "langgraph");
        // The receipt carries a real Ed25519 signature + public key (the one-Signer path).
        assert!(receipt["signature"].as_str().is_some_and(|s| s.len() >= 64));
        assert!(receipt["public_key"]
            .as_str()
            .is_some_and(|s| s.len() == 64));
    }

    #[test]
    fn deny_returns_a_decision_and_signs_no_receipt() {
        let mut s = session_with(
            "rules:\n  - { action: \"*\", allow: false }\n",
            Box::new(DenyApproval),
        );
        assert_eq!(
            decision(&s.handle(r#"{"op":"check","action_id":"delete_everything","params":{}}"#)),
            "denied"
        );
        // Nothing was appended to the log — an action-tier deny is the decision, not a receipt.
        assert!(
            !s.signer.log_path().exists()
                || std::fs::read_to_string(s.signer.log_path())
                    .unwrap()
                    .trim()
                    .is_empty()
        );
    }

    #[test]
    fn require_approval_denied_surfaces_not_approved() {
        let mut s = session_with(
            "rules:\n  - { action: \"send_email\", allow: true, require_approval: true }\n",
            Box::new(DenyApproval), // headless: the runtime's fail-closed default
        );
        assert_eq!(
            decision(&s.handle(r#"{"op":"check","action_id":"send_email","params":{}}"#)),
            "not_approved"
        );
    }

    #[test]
    fn require_approval_auto_approves_then_allows() {
        let mut s = session_with(
            "rules:\n  - { action: \"send_email\", allow: true, require_approval: true }\nbudget:\n  max_actions_per_minute: 60\n",
            Box::new(AutoApprove),
        );
        assert_eq!(
            decision(&s.handle(r#"{"op":"check","action_id":"send_email","params":{}}"#)),
            "allow"
        );
    }

    #[test]
    fn budget_exhaustion_denies_further_calls() {
        let mut s = session_with(
            "rules:\n  - { action: \"tick\", allow: true }\nbudget:\n  max_actions_per_minute: 2\n",
            Box::new(DenyApproval),
        );
        assert_eq!(
            decision(&s.handle(r#"{"op":"check","action_id":"tick","params":{}}"#)),
            "allow"
        );
        assert_eq!(
            decision(&s.handle(r#"{"op":"check","action_id":"tick","params":{}}"#)),
            "allow"
        );
        // The third call in the same minute is over the cap.
        assert_eq!(
            decision(&s.handle(r#"{"op":"check","action_id":"tick","params":{}}"#)),
            "budget_exceeded"
        );
    }

    #[test]
    fn record_stamps_run_correlation_when_the_middleware_supplies_it() {
        let mut s = session_with(
            "rules:\n  - { action: \"web_search\", allow: true }\nbudget:\n  max_actions_per_minute: 60\n",
            Box::new(DenyApproval),
        );
        // The middleware attaches run_id (per invocation) + parent_step_id (per nested call).
        let rec = s.handle(
            r#"{"op":"record","action_id":"web_search","params":{"q":"kriya"},"success":true,"corr":{"run_id":"run-9","parent_step_id":"step-parent"}}"#,
        );
        let v: Value = serde_json::from_str(&rec).unwrap();
        let params = &v["receipt"]["params"];
        assert_eq!(params["kriya.corr"]["run_id"], "run-9");
        assert_eq!(params["kriya.corr"]["parent_step_id"], "step-parent");
        assert_eq!(params["q"], "kriya", "the tool's own params are preserved");
        // The receipt still carries a real signature (correlation rides the one-Signer path).
        assert!(v["receipt"]["signature"]
            .as_str()
            .is_some_and(|s| s.len() >= 64));

        // No corr supplied → params is byte-clean (no reserved key), byte-identical to pre-S3.
        let rec2 = s.handle(
            r#"{"op":"record","action_id":"web_search","params":{"q":"x"},"success":true}"#,
        );
        let v2: Value = serde_json::from_str(&rec2).unwrap();
        assert!(
            v2["receipt"]["params"].get("kriya.corr").is_none(),
            "no correlation means no reserved key"
        );
    }

    #[test]
    fn malformed_and_unknown_requests_are_errors_not_panics() {
        let mut s = session_with(
            "rules:\n  - { action: \"*\", allow: true }\n",
            Box::new(DenyApproval),
        );
        let v: Value = serde_json::from_str(&s.handle("{not json")).unwrap();
        assert_eq!(v["op"], "error");
        let v: Value =
            serde_json::from_str(&s.handle(r#"{"op":"frobnicate","action_id":"x"}"#)).unwrap();
        assert_eq!(v["op"], "error");
        let v: Value = serde_json::from_str(&s.handle(r#"{"op":"check","params":{}}"#)).unwrap();
        assert_eq!(v["op"], "error", "missing action_id is an error");
    }
}
