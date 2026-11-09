//! The governed dispatch core — what makes this an *agent-governance* MCP server and not a
//! vanilla one. Every `tools/call` an external agent makes passes through the exact same
//! gate sequence the in-process host enforces (see `agent::host`):
//!
//! 1. **Policy** — deny-by-default; the host decides, the agent cannot bypass it.
//! 2. **Approval** — actions the policy guards wait for a human (deny by default in MCP mode).
//! 3. **Budget** — a runaway agent is rate-limited before it acts.
//! 4. **Execute** — only now does the cleared action run, via a pluggable executor.
//! 5. **Audit** — every *executed* action gets an Ed25519-signed receipt the agent can't forge.
//!
//! Blocked actions (denied / unapproved / over budget) are *not* signed — receipts attest
//! to what actually ran, matching the in-process host's audit semantics. The block itself is
//! reported back to the agent so it can reason about the refusal.
//!
//! ## The governed-lane I/O ledger (`kriya.io.*`, doc 24 §7.3)
//!
//! When an [`EgressControl`] is installed, a governed call whose destination the resolver names is
//! checked against the egress tier (allow / approval / deny by host + per-destination byte budgets)
//! and produces a standalone `kriya.io.<direction>.<kind>.<decision>` receipt, correlated to its
//! action receipt by a `corr` param (never adjacency). A denied egress is receipted at the decision
//! point, before/instead of execute. This is a governed-lane control, and its honest ceiling is
//! fixed:
//!
//! > *When a stdio MCP server routed through kriya calls an external API, kriya sees — and signs —
//! > only the tool call and result that crossed its stdio pipe; the server's own outbound network
//! > traffic (which hosts it contacted, what it sent) is invisible to kriya and appears in no
//! > receipt. Host-level observation of that traffic is E2.*

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::Value;

use crate::audit::{now_ms, Actor, Receipt, SignedReceipt, Signer};
use crate::budget::BudgetTracker;
use crate::permissions::{
    canary_match, evaluate_operation_rails, max_subdomain_entropy, scan_secrets_pii,
    ssrf_disallowed_reason, AlertOrDeny, Decision, EgressDecision, McpResponsePolicy, Policy,
    RailOutcome, RedactOrDeny, TrustClass,
};
use crate::secrets::find_placeholder_aliases;

use super::approval::ApprovalGate;
use super::executor::{
    ActionExecutor, ActionOutcome, HashScheme, IoDecision, IoDirection, IoKind, IoRecord,
};

/// The result of routing one `tools/call` through the gates.
// `Executed` carries a full `SignedReceipt` (R20 hash-chain + R8 actor pushed it past the lint's
// size threshold). Boxing it would ripple to every `DispatchOutcome` match site repo-wide for no
// real gain — the value is short-lived, one per call.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum DispatchOutcome {
    /// Policy denied the action outright. Never executed, never signed.
    Denied,
    /// Policy required approval and the human declined (or no operator was reachable).
    NotApproved,
    /// The per-minute action budget was exhausted. Carries the human-readable reason.
    BudgetExceeded(String),
    /// The **egress tier** blocked the destination (allowlist deny, byte budget, or a fail-closed
    /// receipt-precondition write failure) — decided at the gate, before/instead of execute. A
    /// signed `kriya.io.*.deny` receipt is written at the decision point (doc 24 §7.3 / L10), EXCEPT
    /// when the block itself is that no receipt could be written (fail-closed on an unwritable log).
    /// Carries the reason.
    EgressDenied(String),
    /// The action cleared every gate and ran. Carries the handler outcome and the signed
    /// receipt appended to the audit log.
    Executed {
        outcome: ActionOutcome,
        receipt: SignedReceipt,
    },
}

/// The destination an action egresses to, resolved from `(action_id, params)` **before** execution
/// so the egress tier can decide — and a `deny` receipt can be written — at the decision point
/// (doc 24 L10). The broker supplies a resolver over its upstream→host map; the hook lane parses a
/// WebFetch URL.
pub struct EgressTarget {
    pub host: String,
    pub kind: IoKind,
    /// The MCP server NAME when the destination is an `mcp` kind whose endpoint isn't a claimable
    /// host (carried as a separate param, never conflated with a host — doc 24 §6-H6).
    pub server: Option<String>,
}

/// Egress governance wired onto a [`Governor`] (doc 24 §7.3). The `resolver` maps an action to its
/// destination; the [`crate::permissions::EgressPolicy`] holds the tier + byte budgets. Absent on a
/// Governor → egress is ungoverned and dispatch is byte-identical to pre-EG-2. Present → each action
/// whose destination the resolver names is checked against the tier + byte budgets, approval-gated
/// at the ApprovalGate for the approve/defer tier, and produces a `kriya.io.*` receipt.
pub struct EgressControl {
    policy: crate::permissions::EgressPolicy,
    #[allow(clippy::type_complexity)]
    resolver: Box<dyn Fn(&str, &Value) -> Option<EgressTarget> + Send>,
    /// Sliding per-destination byte windows keyed by the budget's pattern (B2).
    budgets: Mutex<HashMap<String, Vec<(u128, u64)>>>,
}

impl EgressControl {
    pub fn new(
        policy: crate::permissions::EgressPolicy,
        resolver: impl Fn(&str, &Value) -> Option<EgressTarget> + Send + 'static,
    ) -> Self {
        Self {
            policy,
            resolver: Box::new(resolver),
            budgets: Mutex::new(HashMap::new()),
        }
    }

    /// Charge `bytes` against the destination's byte budget in a trailing window; `Err(reason)` if
    /// this call would breach it (anti slow-drip exfil, B2). No budget for the host → always Ok.
    /// `bytes` is the *estimated* outbound payload (the serialized request), so the budget is a true
    /// pre-emptive gate — the receipt still records the transport-observed bytes.
    fn charge_budget(&self, host: &str, bytes: u64, now: u128) -> Result<(), String> {
        let Some((pattern, budget)) = self.policy.budget_for(host) else {
            return Ok(());
        };
        let mut map = self.budgets.lock().unwrap_or_else(|e| e.into_inner());
        let window_ms = (budget.window_secs.saturating_mul(1000)) as u128;
        let entries = map.entry(pattern.clone()).or_default();
        entries.retain(|(ts, _)| now.saturating_sub(*ts) < window_ms);
        let used: u64 = entries.iter().map(|(_, b)| *b).sum();
        if used.saturating_add(bytes) > budget.max_bytes {
            return Err(format!(
                "egress byte budget for '{pattern}' exhausted ({used}+{bytes} > {} bytes / {}s)",
                budget.max_bytes, budget.window_secs
            ));
        }
        entries.push((now, bytes));
        Ok(())
    }
}

/// Ingress governance (doc 24 §11 B12) wired onto a [`Governor`]. `policy` holds the per-server
/// trust classes; `resolver` maps an action id to the server name whose RESPONSE it carries. The
/// broker supplies `<namespace>__<tool>` splitting; `Governor` itself stays agnostic of that naming
/// convention, exactly like [`EgressControl`]'s resolver keeps host-resolution out of `Governor`.
/// Absent on a `Governor` → byte-identical to pre-EG-P.
pub struct IngressControl {
    policy: McpResponsePolicy,
    #[allow(clippy::type_complexity)]
    resolver: Box<dyn Fn(&str) -> Option<String> + Send>,
}

impl IngressControl {
    pub fn new(
        policy: McpResponsePolicy,
        resolver: impl Fn(&str) -> Option<String> + Send + 'static,
    ) -> Self {
        Self {
            policy,
            resolver: Box::new(resolver),
        }
    }
}

/// B12 core: resolve the response's server via `ingress.resolver`, classify it, and decide what
/// happens to `outcome`. `None` if the resolver can't name a server for this action (an action id
/// outside the lane ingress governance was installed for) or the policy is disabled — ingress
/// governance is opt-in and silent-absent otherwise. `Block` replaces `outcome`'s content with a
/// synthetic denial IN PLACE, before the action receipt captures it — but preserves `outcome.io` (the
/// OUTBOUND capture egress emission still needs) rather than wiping it. Returns
/// `Some((server, decision, flags))` for the receipt [`Governor::emit_io_ingress`] emits right after.
fn apply_ingress(
    ingress: &IngressControl,
    action_id: &str,
    outcome: &mut ActionOutcome,
) -> Option<(String, IoDecision, Vec<String>)> {
    if !ingress.policy.enabled {
        return None;
    }
    let server = (ingress.resolver)(action_id)?;
    match ingress.policy.class_for(&server) {
        TrustClass::Trusted => Some((server, IoDecision::Allow, Vec::new())),
        TrustClass::Scan => {
            let body = serde_json::to_string(&outcome.data).unwrap_or_default();
            let hits = scan_secrets_pii(&body);
            let flags = if hits.is_empty() {
                Vec::new()
            } else {
                vec![format!("b7-secret-pii:{}", hits.join(","))]
            };
            Some((server, IoDecision::Allow, flags))
        }
        TrustClass::Block => {
            let preserved_io = outcome.io.take();
            *outcome = ActionOutcome::failed(
                "response blocked: server trust class is 'block' (B12)".to_string(),
            )
            .with_io(preserved_io);
            Some((server, IoDecision::Deny, Vec::new()))
        }
    }
}

/// B6 governor-level pre-check: resolve `host` and reject if EVERY resolved address is a forbidden
/// SSRF/rebinding target (loopback/RFC1918/link-local — which subsumes the 169.254.169.254 cloud-
/// metadata endpoint — /IPv6 unique-local). `None` (proceed) on a resolution failure: that's not
/// itself an SSRF signal, just a host that will fail naturally at the transport layer. `None` is also
/// returned if ANY resolved address is ordinary and routable — a genuine rebinding attack (a
/// forbidden address swapped in between THIS check and the actual connect) is not this function's
/// job to close; that TOCTOU-proof enforcement is the transport-level resolver pin in
/// `mcp::client::HttpTransport`, which validates the exact IP it connects to. This is a best-effort,
/// receipt-quality check on top of that, not a replacement for it.
fn check_ssrf_target(host: &str) -> Option<String> {
    use std::net::ToSocketAddrs;
    let addrs: Vec<_> = (host, 0u16).to_socket_addrs().ok()?.collect();
    if addrs.is_empty() {
        return None;
    }
    let mut reasons = Vec::new();
    for addr in &addrs {
        match ssrf_disallowed_reason(addr.ip()) {
            Some(reason) => reasons.push(format!("{} ({reason})", addr.ip())),
            None => return None,
        }
    }
    Some(format!(
        "SSRF/rebinding guard: '{host}' resolves only to forbidden target(s): {} (B6)",
        reasons.join(", ")
    ))
}

/// The egress gate's decision for one dispatch.
enum EgressGate {
    /// No egress governance applies (no control installed, or the action resolves to no
    /// destination) — proceed exactly as pre-EG-2.
    Ungoverned,
    /// Governed egress cleared; carries what the post-execute emission needs.
    Cleared(Box<EgressCtx>),
    /// Blocked at the decision point (allowlist deny / byte budget / fail-closed write failure). The
    /// `kriya.io.*.deny` receipt is already written.
    Denied(String),
    /// Approval-tier egress not granted (the parked/refused attempt is already receipted).
    NotApproved,
}

/// What a cleared egress gate carries forward to emit the `kriya.io.*` allow/approve receipt after
/// execution.
struct EgressCtx {
    target: EgressTarget,
    decision: IoDecision, // Allow or Approve
    policy_rule: Option<String>,
    approved_by: Option<String>,
    /// True when the io receipt was ALREADY signed pre-execute (fail-closed mode) — don't emit a
    /// second one post-execute.
    pre_signed: bool,
    /// Additive detection-pack signals (doc 24 §11 / EG-P) from an `AlertOrDeny::Alert`/
    /// `RedactOrDeny::Redact` detector match that didn't block this call — carried into the emitted
    /// `kriya.io.*` receipt's `flags` param. Empty on the common (no detector configured, or nothing
    /// matched) path.
    flags: Vec<String>,
}

/// Wires the gates around a pluggable [`ActionExecutor`] + [`ApprovalGate`]. Holds the
/// budget tracker (stateful across calls) so the rate limit spans the whole MCP session,
/// exactly like a single agent run in the in-process host.
pub struct Governor {
    policy: Arc<Policy>,
    signer: Arc<Signer>,
    budget: BudgetTracker,
    approval: Box<dyn ApprovalGate>,
    executor: Box<dyn ActionExecutor>,
    /// Who the external agent is (R8). Set by the binary from the MCP client identity;
    /// stamped into every signed receipt so cross-app audit attributes each call.
    actor: Option<Actor>,
    /// Optional egress governance (doc 24 §7.3). `None` → byte-identical to pre-EG-2.
    egress: Option<EgressControl>,
    /// Optional ingress governance (doc 24 §11 B12). `None` → byte-identical to pre-EG-P.
    ingress: Option<IngressControl>,
    /// Optional run correlation (S3): a per-gateway-process `run_id` stamped into every action
    /// receipt's `kriya.corr`, so the Console groups one gateway *session*'s tool calls into a run.
    /// The gateway is spawned as ONE client's stdio subprocess and lives for that session, so one
    /// Governor = one connection = one run — a real scope, not a fabricated one. `None` (the router /
    /// in-process server / tests) → byte-identical to pre-S3. No `parent_step_id`/`agent_id`: the
    /// proxy lane sees no sub-agent lineage, and guessing one would be dishonest.
    run_id: Option<String>,
    /// Cooperative origin chain (C3) for the call being dispatched — set per request by the
    /// HTTP-served broker (`X-Kriya-Chain` + this hop's actor) and stamped as the `chain` param on
    /// every receipt this governor signs while it is set. `None` (stdio, in-process, tests) →
    /// receipts byte-identical to before.
    chain: Option<Vec<String>>,
}

impl Governor {
    pub fn new(
        policy: Arc<Policy>,
        signer: Arc<Signer>,
        approval: Box<dyn ApprovalGate>,
        executor: Box<dyn ActionExecutor>,
    ) -> Self {
        let budget = BudgetTracker::new(policy.max_actions_per_minute());
        Self {
            policy,
            signer,
            budget,
            approval,
            executor,
            actor: None,
            egress: None,
            ingress: None,
            run_id: None,
            chain: None,
        }
    }

    /// Set (or clear, with `None`) the cooperative origin chain (C3) for the following dispatch(es):
    /// stamped as the `chain` param on every receipt this governor signs, and handed to the executor
    /// (comma-joined) so an HTTP upstream receives it as `X-Kriya-Chain`. The caller clears it after
    /// the request it belongs to.
    pub fn set_call_chain(&mut self, chain: Option<Vec<String>>) {
        let joined = chain.as_ref().map(|c| c.join(","));
        self.executor.set_call_chain(joined.as_deref());
        self.chain = chain;
    }

    /// Add the `chain` param to a receipt's params when a chain is set. A no-op without one (and on
    /// non-object params, defensively), so the ungoverned-chain path stays byte-identical.
    fn stamp_chain(&self, mut params: Value) -> Value {
        if let (Some(chain), Some(obj)) = (&self.chain, params.as_object_mut()) {
            obj.insert(
                "chain".to_string(),
                Value::Array(chain.iter().cloned().map(Value::String).collect()),
            );
        }
        params
    }

    /// Attribute every receipt this governor signs to `actor` (R8). Chainable on `new`.
    pub fn with_actor(mut self, actor: Option<Actor>) -> Self {
        self.actor = actor;
        self
    }

    /// Stamp a per-session `run_id` (S3 run correlation) into every action receipt. Set once per
    /// gateway process (one Governor = one client session = one run). An empty/absent id is a no-op,
    /// leaving receipts byte-identical to pre-S3. Chainable.
    pub fn with_run_correlation(mut self, run_id: Option<String>) -> Self {
        self.run_id = run_id.filter(|s| !s.is_empty());
        self
    }

    /// Install egress governance (doc 24 §7.3). Chainable on `new`/`with_actor`.
    pub fn with_egress(mut self, egress: EgressControl) -> Self {
        self.egress = Some(egress);
        self
    }

    /// Install ingress governance (doc 24 §11 B12). Chainable on `new`/`with_actor`/`with_egress`.
    pub fn with_ingress(mut self, ingress: IngressControl) -> Self {
        self.ingress = Some(ingress);
        self
    }

    /// Run one action through policy → egress tier → budget → execute → audit (+ `kriya.io.*`).
    pub fn dispatch(&mut self, action_id: &str, params: &Value) -> DispatchOutcome {
        // 1. Action policy gate — the host decides, not the agent.
        match self.policy.check(action_id) {
            Decision::Allow => {}
            Decision::RequiresApproval => {
                // Approval gate — held for a human; default-deny in MCP mode.
                if !self.approval.request(action_id, params) {
                    return DispatchOutcome::NotApproved;
                }
            }
            Decision::Deny => return DispatchOutcome::Denied,
        }

        // 2. Budget gate — stop a runaway/looping agent before it acts. Runs BEFORE the egress gate
        //    so a budget-blocked call never signs a fail-closed egress precondition receipt (which
        //    would record — and durably persist — an egress that then never happens).
        if let Err(reason) = self.budget.check_and_record(now_ms()) {
            return DispatchOutcome::BudgetExceeded(reason);
        }

        // The action receipt's step_id, generated up front so the `kriya.io.*` receipt can carry it
        // as `corr` — including in fail-closed mode where the io receipt is signed BEFORE execute.
        let action_step_id = uuid::Uuid::new_v4().to_string();

        // 3. Egress tier gate (doc 24 §7.3) — only when configured AND the action resolves to a
        //    destination. Deny is decided here, at the decision point, so a `kriya.io.*.deny`
        //    receipt exists before/instead of execute (L10).
        let egress_ctx = match self.egress_gate(action_id, params, &action_step_id) {
            EgressGate::Ungoverned => None,
            EgressGate::Cleared(ctx) => Some(ctx),
            EgressGate::Denied(reason) => return DispatchOutcome::EgressDenied(reason),
            EgressGate::NotApproved => return DispatchOutcome::NotApproved,
        };

        // 4. Execute the cleared action. Time it in-process (O-3, doc 33 §5.5 — the `in-process`
        //    duration lane). Unlike the hook's fresh-process pre→post marker (`duration.rs`), the
        //    proxy governor brackets the real tool execution within ONE process, so the interval is
        //    a direct measurement — always present, never a cross-process marker round-trip. It is
        //    stamped below as the SAME two additive params the hook lane emits (`kriya.dur.ms` +
        //    `kriya.dur.basis`), with basis `in-process`.
        let exec_start = std::time::Instant::now();
        let mut outcome = self.executor.execute(action_id, params);
        let exec_dur_ms = exec_start.elapsed().as_millis() as u64;

        // 4b. Ingress trust-class enforcement (doc 24 §11 B12) — the RESPONSE side of a governed
        //     MCP call, independent of egress (applies to stdio upstreams too, which have no host
        //     to egress-govern at all). `Block` replaces `outcome`'s content in place, BEFORE the
        //     action receipt below captures it — so a fully-untrusted server's content never
        //     reaches the action receipt or the caller.
        let ingress_result = self
            .ingress
            .as_ref()
            .and_then(|ig| apply_ingress(ig, action_id, &mut outcome));

        // 5. Sign + append the action receipt (frozen schema), success or failure. The signing key
        //    never leaves the host, so the agent can propose and run an action but cannot forge its
        //    receipt. The receipt carries who acted (R8) when the binary supplied an identity.
        // Run correlation (S3): stamp the per-session run_id (proxy lane has no parent/subagent
        // lineage — never fabricated). Empty run scope ⇒ params byte-identical to pre-S3.
        let mut corr_params = crate::corr::attach(
            params.clone(),
            &crate::corr::Correlation {
                run_id: self.run_id.clone(),
                parent_step_id: None,
                agent_id: None,
            },
        );
        // Additive, optional in-process duration params (O-3). No-op when `params` is not an object
        // (defensive); every real tool-call params is an object, so the receipt carries the measured
        // interval alongside the tool's own fields — a verifier with no duration awareness accepts it
        // byte-for-byte as before (no new action_id, no envelope change).
        crate::duration::annotate_duration(
            &mut corr_params,
            exec_dur_ms,
            crate::duration::BASIS_IN_PROCESS,
        );
        let receipt = self.signer.record(
            Receipt::new(
                action_step_id.clone(),
                action_id.to_string(),
                self.stamp_chain(corr_params),
                outcome.success,
                now_ms(),
            )
            .with_actor(self.actor.clone()),
        );

        // 6. The `kriya.io.*` allow/approve receipt — a standalone signed receipt correlated by
        //    `corr` (never adjacency, L5). In fail-closed mode it was already written pre-execute.
        if let Some(ctx) = egress_ctx {
            if !ctx.pre_signed {
                self.emit_io_allow(&ctx, outcome.io.as_ref(), &action_step_id);
            }
        }

        // 7. The `kriya.io.ingress.mcp.*` receipt (B12), correlated the same way. Unlike an egress
        //    deny, an ingress deny still has an action receipt (the call DID execute — that's how a
        //    response existed to classify), so it always carries `corr`.
        if let Some((server, decision, flags)) = ingress_result {
            self.emit_io_ingress(&server, decision, &flags, &action_step_id);
        }

        // 8. D1 (doc 27 §4 / docs/design/d1-memory-receipts.md D-4): a REGISTERED memory tool
        //    (§D-1's honest default — never a bare name-looks-like heuristic) gets an additional
        //    `kriya.memory.<verb>` receipt, correlated the same way, hashing the registry-named
        //    content field (or the full request arguments when unnamed) — the REQUEST, because a
        //    memory write's content is in `arguments`, which the broker sees in full, unlike the
        //    response (`emit_io_ingress` above never hashes response content, §D-4). `success`
        //    mirrors the action's own outcome, exactly like the base receipt above.
        if let Some((server, tool)) = action_id.split_once("__") {
            if let Some(entry) = self.policy.memory_registered_for(server, tool) {
                let content = crate::memwrite::mcp_memory_content(params, entry.content_field.as_deref());
                // The MCP lane's verb is OPERATOR-DECLARED (the registry's `op`), never inferred
                // from tool shape or an in-run scan — there is no ambiguity for `prior_write_seen`
                // to resolve here. Reusing `ToolEdit`/`ToolWrite` (never `PriorWriteSeen`, which
                // would falsely claim a scan happened) is the closest honest fit within the
                // existing three-value `verb_basis` enum: it marks "not a scanned upgrade",
                // exactly what's true, keyed off the registry's own update-vs-not distinction.
                let basis = if entry.op == crate::memwrite::MemoryOp::Update {
                    crate::memwrite::VerbBasis::ToolEdit
                } else {
                    crate::memwrite::VerbBasis::ToolWrite
                };
                crate::memwrite::emit_memory_receipt_chained(
                    &self.signer,
                    self.actor.as_ref(),
                    entry.op.verb(),
                    basis,
                    &crate::memwrite::mcp_surface(server, tool, entry.op),
                    &content,
                    outcome.success,
                    &crate::corr::Correlation {
                        run_id: self.run_id.clone(),
                        parent_step_id: None,
                        agent_id: None,
                    },
                    &[],
                    self.chain.as_deref(),
                );
            }
        }

        DispatchOutcome::Executed { outcome, receipt }
    }

    /// Evaluate the egress tier for an action's destination. Signs a `kriya.io.*.deny` receipt at
    /// the decision point on any block (L10). In fail-closed mode signs the allow receipt as a
    /// precondition (B3) and denies if it can't be persisted.
    ///
    /// Detection-pack order (doc 24 §11 / EG-P), and why: B9 canary tokens run FIRST and
    /// unconditionally — a planted honeytoken is a compromise signal independent of where it's
    /// headed, so it pre-empts even the destination-tier decision. Everything else (B6 SSRF/
    /// rebinding, B5 DNS-exfil entropy, B8 operation rails, B7 secret/PII) runs AFTER the tier
    /// clears (Allow, or Approval granted) — these are refinements on an otherwise-permitted call
    /// (e.g. B5 exists specifically to catch abuse of an *already-allowed* wildcard host), not a
    /// second independent allowlist, and running them post-tier avoids double-prompting when a
    /// destination is already at the Approval tier.
    fn egress_gate(&self, action_id: &str, params: &Value, action_step_id: &str) -> EgressGate {
        let Some(control) = self.egress.as_ref() else {
            return EgressGate::Ungoverned;
        };
        let Some(target) = (control.resolver)(action_id, params) else {
            return EgressGate::Ungoverned;
        };

        let detection = self.policy.detection();
        let payload = serde_json::to_string(params).unwrap_or_default();

        // B9 canary tokens — always-deny, checked before the tier decision (doc comment above).
        if let Some(det) = detection {
            if let Some(token) = canary_match(&payload, &det.canary_tokens) {
                let reason = format!(
                    "canary token match ({}…): outbound payload contains a planted honeytoken — \
                     treated as compromise, deny (B9)",
                    &token.chars().take(8).collect::<String>()
                );
                self.sign_io_deny(&target, None, reason.clone());
                return EgressGate::Denied(reason);
            }
        }

        // Tier decision by destination host.
        let (decision, policy_rule) = match control.policy.evaluate(&target.host) {
            EgressDecision::Allow { rule } => (IoDecision::Allow, rule),
            EgressDecision::Approval { rule } => {
                // Egress approval rides the existing ApprovalGate (approve/defer tier, B4). The
                // prompt shown is the io action id so the operator sees it is an egress decision.
                let io_prompt = format!(
                    "kriya.io.{}.{}.approve",
                    IoDirection::Egress.facet(),
                    target.kind.facet()
                );
                if !self.approval.request(&io_prompt, params) {
                    self.sign_io_deny(&target, rule, "egress approval not granted".to_string());
                    return EgressGate::NotApproved;
                }
                (IoDecision::Approve, rule)
            }
            EgressDecision::Deny { rule, reason } => {
                self.sign_io_deny(&target, rule, reason.clone());
                return EgressGate::Denied(reason);
            }
        };

        // B6 SSRF/rebinding guard — governor-level pre-check for a clean, attributed deny receipt.
        // The TOCTOU-proof enforcement is the transport-level resolver pin in
        // `mcp::client::HttpTransport`, gated by the SAME flag (see `SsrfGuardPolicy`'s doc comment
        // — a local dev/test upstream on loopback is a legitimate target, so neither layer defaults
        // on).
        if detection
            .and_then(|d| d.ssrf_guard)
            .is_some_and(|g| g.enabled)
        {
            if let Some(reason) = check_ssrf_target(&target.host) {
                self.sign_io_deny(&target, policy_rule.clone(), reason.clone());
                return EgressGate::Denied(reason);
            }
        }

        let mut flags: Vec<String> = Vec::new();

        // B5 DNS-exfil / subdomain-entropy heuristic — catches abuse of an already-allowed wildcard
        // host (e.g. `*.vendor.com`) via a high-entropy encoded subdomain label.
        if let Some(dns) = detection
            .and_then(|d| d.dns_exfil.as_ref())
            .filter(|d| d.enabled)
        {
            if let Some(entropy) = max_subdomain_entropy(&target.host) {
                if entropy >= dns.entropy_threshold {
                    match dns.action {
                        AlertOrDeny::Alert => {
                            flags.push(format!("b5-dns-exfil:entropy={entropy:.2}"))
                        }
                        AlertOrDeny::Deny => {
                            let reason = format!(
                                "DNS-exfil heuristic: subdomain entropy {entropy:.2} >= threshold \
                                 {:.2} on '{}' (B5)",
                                dns.entropy_threshold, target.host
                            );
                            self.sign_io_deny(&target, policy_rule.clone(), reason.clone());
                            return EgressGate::Denied(reason);
                        }
                    }
                }
            }
        }

        // B8 operation rails — a per-destination allowlist fence narrower than the host tier.
        if let Some(det) = detection {
            if !det.operation_rails.is_empty() {
                match evaluate_operation_rails(&det.operation_rails, &target.host, params) {
                    RailOutcome::NoRailApplies | RailOutcome::Allowed => {}
                    RailOutcome::RequiresApproval => {
                        let io_prompt = format!(
                            "kriya.io.{}.{}.approve",
                            IoDirection::Egress.facet(),
                            target.kind.facet()
                        );
                        if !self.approval.request(&io_prompt, params) {
                            self.sign_io_deny(
                                &target,
                                policy_rule.clone(),
                                "operation rail approval not granted".to_string(),
                            );
                            return EgressGate::NotApproved;
                        }
                    }
                    RailOutcome::Denied(reason) => {
                        self.sign_io_deny(&target, policy_rule.clone(), reason.clone());
                        return EgressGate::Denied(reason);
                    }
                    RailOutcome::ParseFailed => {
                        let reason = format!(
                            "operation rail configured for '{}' but the call's verb+path/mutation \
                             could not be parsed — fail-closed (B8)",
                            target.host
                        );
                        self.sign_io_deny(&target, policy_rule.clone(), reason.clone());
                        return EgressGate::Denied(reason);
                    }
                }
            }
        }

        // B7 secret/PII scan on the outbound payload.
        if let Some(sp) = detection
            .and_then(|d| d.secret_pii.as_ref())
            .filter(|d| d.enabled)
        {
            let hits = scan_secrets_pii(&payload);
            if !hits.is_empty() {
                match sp.action {
                    RedactOrDeny::Redact => flags.push(format!("b7-secret-pii:{}", hits.join(","))),
                    RedactOrDeny::Deny => {
                        let reason = format!(
                            "secret/PII scan matched outbound payload: {} (B7)",
                            hits.join(",")
                        );
                        self.sign_io_deny(&target, policy_rule.clone(), reason.clone());
                        return EgressGate::Denied(reason);
                    }
                }
            }
        }

        // B13 credential brokering (doc 24 §11 B13 / EG-B) — scope PRE-CHECK only: this never reads
        // a secret VALUE, only asks "which aliases are named here, and is each one configured and
        // allowed for this destination." A misrouted or unconfigured alias gets a clean, attributed
        // deny receipt here rather than a generic transport failure — the actual substitution (the
        // real enforcement) happens later, at the transport, right before the wire send; this is the
        // SAME dual-layer shape as the B6 SSRF guard (a governor-level belt to the transport's
        // suspenders). A cleared alias is recorded as an ADDITIVE flag — never the value — on the
        // eventual allow/approve receipt, exactly like every other detector's flag.
        if let Some(secrets) = self.policy.secrets() {
            for alias in find_placeholder_aliases(&payload) {
                match secrets.find(&alias) {
                    None => {
                        let reason = format!(
                            "credential brokering: alias '{alias}' is not configured (B13)"
                        );
                        self.sign_io_deny(&target, policy_rule.clone(), reason.clone());
                        return EgressGate::Denied(reason);
                    }
                    Some(entry) if !entry.allows_host(&target.host) => {
                        let reason = format!(
                            "credential brokering: alias '{alias}' is not allowed for destination '{}' (B13)",
                            target.host
                        );
                        self.sign_io_deny(&target, policy_rule.clone(), reason.clone());
                        return EgressGate::Denied(reason);
                    }
                    Some(_) => flags.push(format!("b13-brokered:{alias}")),
                }
            }
        }

        // Byte budget (B2) — estimate outbound payload from the serialized request arguments. Note:
        // when B13 brokering fires, this estimate is taken over the PLACEHOLDER form (the governor
        // never reads the real secret, so it can't know the substituted length) — a minor, honest
        // undercount when brokering is active, consistent with this ledger never claiming byte-exact
        // wire accounting (L2/L4).
        let est = payload.len() as u64;
        if let Err(reason) = control.charge_budget(&target.host, est, now_ms()) {
            self.sign_io_deny(&target, policy_rule, reason.clone());
            return EgressGate::Denied(reason);
        }

        let approved_by = if decision == IoDecision::Approve {
            self.actor.as_ref().map(|a| a.user.clone())
        } else {
            None
        };

        // Fail-closed receipt-precondition (B3): sign the io allow receipt BEFORE execute; if it
        // cannot be persisted, deny the egress — "no receipt, no egress." The honest cost is that
        // the pre-execute record commits to the serialized-request estimate (canonical-json), not
        // the transport-observed wire bytes, so its `hash_scheme` says `canonical-json`.
        let pre_signed = if control.policy.fail_closed() {
            let io = self.io_allow_record(
                &target,
                decision,
                &policy_rule,
                &approved_by,
                None,
                est,
                &flags,
            );
            let receipt = Receipt::new(
                uuid::Uuid::new_v4().to_string(),
                io.action_id(),
                self.stamp_chain(io.params(Some(action_step_id))),
                true,
                now_ms(),
            )
            .with_actor(self.actor.clone());
            if self.signer.record_persisted(receipt).is_err() {
                return EgressGate::Denied(
                    "egress blocked: kriya.io receipt could not be written (fail-closed)"
                        .to_string(),
                );
            }
            true
        } else {
            false
        };

        EgressGate::Cleared(Box::new(EgressCtx {
            target,
            decision,
            policy_rule,
            approved_by,
            pre_signed,
            flags,
        }))
    }

    /// Emit the `kriya.io.*` allow/approve receipt after a governed egress executed, preferring the
    /// transport-observed io (accurate wire bytes) when present.
    fn emit_io_allow(&self, ctx: &EgressCtx, transport_io: Option<&IoRecord>, corr: &str) {
        let est = 0; // unused when transport io is present
        let io = self.io_allow_record(
            &ctx.target,
            ctx.decision,
            &ctx.policy_rule,
            &ctx.approved_by,
            transport_io,
            est,
            &ctx.flags,
        );
        let receipt = Receipt::new(
            uuid::Uuid::new_v4().to_string(),
            io.action_id(),
            self.stamp_chain(io.params(Some(corr))),
            true,
            now_ms(),
        )
        .with_actor(self.actor.clone());
        self.signer.record(receipt);
    }

    /// Emit the `kriya.io.ingress.mcp.*` receipt for a governed MCP response (doc 24 §11 B12),
    /// correlated to the action receipt by `corr` — unlike an egress deny, an ingress deny still has
    /// a corresponding action receipt (the call executed; that's how a response existed to
    /// classify), so `corr` is always present here, allow or deny.
    fn emit_io_ingress(&self, server: &str, decision: IoDecision, flags: &[String], corr: &str) {
        let io = IoRecord {
            direction: IoDirection::Ingress,
            dest_host: None,
            dest_kind: IoKind::Mcp,
            method: None,
            bytes_out: None,
            bytes_in: None,
            bytes_in_is_partial: false,
            content_sha256: None,
            hash_scheme: HashScheme::WireBytes,
            decision,
            policy_rule: None,
            approved_by: None,
            reason: (decision == IoDecision::Deny)
                .then(|| "server trust class is 'block' (B12)".to_string()),
            server: Some(server.to_string()),
            flags: flags.to_vec(),
        };
        let receipt = Receipt::new(
            uuid::Uuid::new_v4().to_string(),
            io.action_id(),
            self.stamp_chain(io.params(Some(corr))),
            decision != IoDecision::Deny,
            now_ms(),
        )
        .with_actor(self.actor.clone());
        self.signer.record(receipt);
    }

    /// Build the io record for an allowed/approved egress. With `transport_io` (fail-open,
    /// post-execute) it carries the observed wire bytes + `wire-bytes` scheme; without it
    /// (fail-closed, pre-execute) it commits to the serialized-request estimate + `canonical-json`.
    // `flags` (EG-P) pushed this to 8 args over clippy's default 7. Both call sites already build
    // every argument from an `EgressCtx`/local scope, so a bundling struct would be a pass-through
    // wrapper with no real invariant of its own — not worth it for one private helper.
    #[allow(clippy::too_many_arguments)]
    fn io_allow_record(
        &self,
        target: &EgressTarget,
        decision: IoDecision,
        policy_rule: &Option<String>,
        approved_by: &Option<String>,
        transport_io: Option<&IoRecord>,
        est_bytes: u64,
        flags: &[String],
    ) -> IoRecord {
        match transport_io {
            Some(t) => IoRecord {
                direction: IoDirection::Egress,
                dest_host: t.dest_host.clone().or_else(|| Some(target.host.clone())),
                dest_kind: target.kind,
                method: t.method.clone(),
                bytes_out: t.bytes_out,
                bytes_in: t.bytes_in,
                bytes_in_is_partial: t.bytes_in_is_partial,
                content_sha256: t.content_sha256.clone(),
                hash_scheme: t.hash_scheme,
                decision,
                policy_rule: policy_rule.clone(),
                approved_by: approved_by.clone(),
                reason: None,
                server: target.server.clone(),
                flags: flags.to_vec(),
            },
            None => IoRecord {
                direction: IoDirection::Egress,
                dest_host: Some(target.host.clone()),
                dest_kind: target.kind,
                method: Some("tools/call".to_string()),
                bytes_out: Some(est_bytes),
                bytes_in: None,
                bytes_in_is_partial: false,
                content_sha256: None,
                hash_scheme: HashScheme::CanonicalJson,
                decision,
                policy_rule: policy_rule.clone(),
                approved_by: approved_by.clone(),
                reason: None,
                server: target.server.clone(),
                flags: flags.to_vec(),
            },
        }
    }

    /// Sign a `kriya.io.*.deny` receipt at the decision point — a denied egress never executes, so
    /// without this the `deny` rows would never exist (L10). No `corr`: there is no action receipt.
    /// No `flags`: a deny's [`IoRecord::reason`] already says why, so there is nothing a flag would
    /// add (unlike an alert-mode match, which needs a flag precisely because it did NOT get a
    /// `reason` — the call proceeded).
    fn sign_io_deny(&self, target: &EgressTarget, policy_rule: Option<String>, reason: String) {
        let io = IoRecord {
            direction: IoDirection::Egress,
            dest_host: Some(target.host.clone()),
            dest_kind: target.kind,
            method: None,
            bytes_out: None,
            bytes_in: None,
            bytes_in_is_partial: false,
            content_sha256: None,
            hash_scheme: HashScheme::WireBytes,
            decision: IoDecision::Deny,
            policy_rule,
            approved_by: None,
            reason: Some(reason),
            server: target.server.clone(),
            flags: Vec::new(),
        };
        let receipt = Receipt::new(
            uuid::Uuid::new_v4().to_string(),
            io.action_id(),
            self.stamp_chain(io.params(None)),
            false,
            now_ms(),
        )
        .with_actor(self.actor.clone());
        self.signer.record(receipt);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::approval::{AutoApprove, DenyApproval};
    use crate::mcp::executor::FnExecutor;
    use serde_json::{json, Value};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn signer() -> Arc<Signer> {
        Arc::new(Signer::new())
    }

    /// Counts how many times the executor actually ran — proves blocked actions never reach it.
    fn counting_executor(counter: Arc<AtomicUsize>) -> Box<dyn ActionExecutor> {
        Box::new(FnExecutor(move |_id: &str, _p: &Value| {
            counter.fetch_add(1, Ordering::SeqCst);
            ActionOutcome::ok(json!({"ran": true}))
        }))
    }

    #[test]
    fn allowed_action_executes_and_is_signed() {
        let ran = Arc::new(AtomicUsize::new(0));
        let mut g = Governor::new(
            Arc::new(Policy::default()),
            signer(),
            Box::new(DenyApproval),
            counting_executor(ran.clone()),
        );
        match g.dispatch("create_note", &json!({"title": "hi"})) {
            DispatchOutcome::Executed { outcome, receipt } => {
                assert!(outcome.success);
                assert_eq!(receipt.receipt.action_id, "create_note");
                assert!(!receipt.signature.is_empty());
            }
            other => panic!("expected Executed, got {other:?}"),
        }
        assert_eq!(ran.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn dispatch_stamps_per_session_run_correlation_when_set_and_is_byte_clean_otherwise() {
        // With a per-session run_id: the action receipt carries kriya.corr.run_id, no parent/agent
        // (the proxy lane has no sub-agent lineage), and the tool's own params survive.
        let ran = Arc::new(AtomicUsize::new(0));
        let mut g = Governor::new(
            Arc::new(Policy::default()),
            signer(),
            Box::new(DenyApproval),
            counting_executor(ran.clone()),
        )
        .with_run_correlation(Some("gw-session-1".into()));
        match g.dispatch("create_note", &json!({"title": "hi"})) {
            DispatchOutcome::Executed { receipt, .. } => {
                let p = &receipt.receipt.params;
                assert_eq!(p["kriya.corr"]["run_id"], json!("gw-session-1"));
                assert!(p["kriya.corr"].get("parent_step_id").is_none());
                assert!(p["kriya.corr"].get("agent_id").is_none());
                assert_eq!(p["title"], json!("hi"), "tool params preserved");
            }
            other => panic!("expected Executed, got {other:?}"),
        }

        // Without run correlation (the router / in-process lanes): no `kriya.corr` key, and the tool's
        // own params survive verbatim. The only ADDITIVE keys are the O-3 in-process duration params
        // (`kriya.dur.*`, basis "in-process") — the proxy governor times the execute in-process, so an
        // action receipt on this lane always carries a real (possibly sub-ms 0) measured interval.
        let mut g2 = Governor::new(
            Arc::new(Policy::default()),
            signer(),
            Box::new(DenyApproval),
            counting_executor(ran.clone()),
        );
        match g2.dispatch("create_note", &json!({"title": "hi"})) {
            DispatchOutcome::Executed { receipt, .. } => {
                let p = &receipt.receipt.params;
                assert_eq!(p["title"], json!("hi"), "tool params survive verbatim");
                assert!(p.get("kriya.corr").is_none(), "no run correlation on this lane");
                assert_eq!(
                    p["kriya.dur.basis"],
                    json!("in-process"),
                    "the proxy governor measures duration in-process"
                );
                assert!(
                    p["kriya.dur.ms"].as_u64().is_some(),
                    "a measured (non-negative) interval, never absent on the in-process lane"
                );
                // Exactly the tool param + the two additive duration params — nothing else leaked.
                assert_eq!(
                    p.as_object().unwrap().len(),
                    3,
                    "title + kriya.dur.ms + kriya.dur.basis"
                );
            }
            other => panic!("expected Executed, got {other:?}"),
        }
    }

    #[test]
    fn denied_action_never_runs_and_is_not_signed() {
        let ran = Arc::new(AtomicUsize::new(0));
        let mut g = Governor::new(
            Arc::new(Policy::default()),
            signer(),
            Box::new(AutoApprove),
            counting_executor(ran.clone()),
        );
        // `wire_money` matches no allow rule → deny by default.
        assert!(matches!(
            g.dispatch("wire_money", &json!({})),
            DispatchOutcome::Denied
        ));
        assert_eq!(
            ran.load(Ordering::SeqCst),
            0,
            "denied action must not execute"
        );
    }

    #[test]
    fn guarded_action_blocked_when_approval_denied() {
        let ran = Arc::new(AtomicUsize::new(0));
        let mut g = Governor::new(
            Arc::new(Policy::default()),
            signer(),
            Box::new(DenyApproval),
            counting_executor(ran.clone()),
        );
        // delete_* requires approval; DenyApproval refuses it.
        assert!(matches!(
            g.dispatch("delete_note", &json!({"id": 1})),
            DispatchOutcome::NotApproved
        ));
        assert_eq!(
            ran.load(Ordering::SeqCst),
            0,
            "unapproved action must not execute"
        );
    }

    #[test]
    fn guarded_action_runs_when_approved() {
        let ran = Arc::new(AtomicUsize::new(0));
        let mut g = Governor::new(
            Arc::new(Policy::default()),
            signer(),
            Box::new(AutoApprove),
            counting_executor(ran.clone()),
        );
        assert!(matches!(
            g.dispatch("delete_note", &json!({"id": 1})),
            DispatchOutcome::Executed { .. }
        ));
        assert_eq!(ran.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn budget_blocks_after_cap_and_does_not_execute() {
        let policy: Policy = serde_yaml::from_str(
            r#"
rules:
  - action: "create_*"
    allow: true
  - action: "*"
    allow: false
budget:
  max_actions_per_minute: 2
"#,
        )
        .unwrap();
        let ran = Arc::new(AtomicUsize::new(0));
        let mut g = Governor::new(
            Arc::new(policy),
            signer(),
            Box::new(DenyApproval),
            counting_executor(ran.clone()),
        );
        assert!(matches!(
            g.dispatch("create_note", &json!({})),
            DispatchOutcome::Executed { .. }
        ));
        assert!(matches!(
            g.dispatch("create_note", &json!({})),
            DispatchOutcome::Executed { .. }
        ));
        // third within the minute trips the budget — and must not reach the executor.
        assert!(matches!(
            g.dispatch("create_note", &json!({})),
            DispatchOutcome::BudgetExceeded(_)
        ));
        assert_eq!(ran.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn receipt_carries_actor_when_set() {
        let ran = Arc::new(AtomicUsize::new(0));
        let mut g = Governor::new(
            Arc::new(Policy::default()),
            signer(),
            Box::new(DenyApproval),
            counting_executor(ran.clone()),
        )
        .with_actor(Some(crate::audit::Actor::new("claude-desktop", "alice")));
        match g.dispatch("create_note", &json!({"title": "hi"})) {
            DispatchOutcome::Executed { receipt, .. } => {
                assert_eq!(
                    receipt.receipt.actor,
                    Some(crate::audit::Actor::new("claude-desktop", "alice"))
                );
            }
            other => panic!("expected Executed, got {other:?}"),
        }
    }

    #[test]
    fn receipt_has_no_actor_by_default() {
        let ran = Arc::new(AtomicUsize::new(0));
        let mut g = Governor::new(
            Arc::new(Policy::default()),
            signer(),
            Box::new(DenyApproval),
            counting_executor(ran.clone()),
        );
        match g.dispatch("create_note", &json!({})) {
            DispatchOutcome::Executed { receipt, .. } => assert!(receipt.receipt.actor.is_none()),
            other => panic!("expected Executed, got {other:?}"),
        }
    }

    #[test]
    fn failed_execution_is_still_signed() {
        let mut g = Governor::new(
            Arc::new(Policy::default()),
            signer(),
            Box::new(DenyApproval),
            Box::new(FnExecutor(|_id: &str, _p: &Value| {
                ActionOutcome::failed("boom")
            })),
        );
        match g.dispatch("create_note", &json!({})) {
            DispatchOutcome::Executed { outcome, receipt } => {
                assert!(!outcome.success);
                assert!(!receipt.receipt.success);
                assert!(!receipt.signature.is_empty(), "failures are audited too");
            }
            other => panic!("expected Executed, got {other:?}"),
        }
    }

    // ─── EG-2: the egress tier + kriya.io.* receipts (doc 24 §7.3) ───────────────────────────────

    use crate::permissions::EgressPolicy;
    use std::path::PathBuf;

    /// A signer over a UNIQUE temp log so a test can read back the receipts it wrote.
    fn signer_with_log() -> (Arc<Signer>, PathBuf) {
        let log = std::env::temp_dir().join(format!("kriya-eg2-{}.jsonl", uuid::Uuid::new_v4()));
        (Arc::new(Signer::with_log_path(log.clone())), log)
    }

    /// An action policy that clears everything so the egress gate is what decides.
    fn allow_all() -> Arc<Policy> {
        Arc::new(serde_yaml::from_str("rules:\n  - action: \"*\"\n    allow: true\nbudget:\n  max_actions_per_minute: 1000\n").unwrap())
    }

    /// A governor whose egress control resolves every action to `host` (kind mcp) under `egress_yaml`.
    fn egress_governor(
        signer: Arc<Signer>,
        egress_yaml: &str,
        host: &str,
        ran: Arc<AtomicUsize>,
        approval: Box<dyn ApprovalGate>,
    ) -> Governor {
        let ep: EgressPolicy = serde_yaml::from_str(egress_yaml).unwrap();
        let host = host.to_string();
        let control = EgressControl::new(ep, move |_a: &str, _p: &Value| {
            Some(EgressTarget {
                host: host.clone(),
                kind: IoKind::Mcp,
                server: Some("test-upstream".into()),
            })
        });
        Governor::new(allow_all(), signer, approval, counting_executor(ran)).with_egress(control)
    }

    /// Like [`egress_governor`], but the ACTION policy (not just the egress control) is parsed from
    /// `policy_yaml` — for the detection-pack tests (doc 24 §11 / EG-P), which need a `detection:`
    /// block wired onto the `Policy` the `Governor` actually consults.
    fn egress_governor_with_detection(
        signer: Arc<Signer>,
        policy_yaml: &str,
        egress_yaml: &str,
        host: &str,
        ran: Arc<AtomicUsize>,
        approval: Box<dyn ApprovalGate>,
    ) -> Governor {
        let policy: Arc<Policy> = Arc::new(serde_yaml::from_str(policy_yaml).unwrap());
        let ep: EgressPolicy = serde_yaml::from_str(egress_yaml).unwrap();
        let host = host.to_string();
        let control = EgressControl::new(ep, move |_a: &str, _p: &Value| {
            Some(EgressTarget {
                host: host.clone(),
                kind: IoKind::Mcp,
                server: Some("test-upstream".into()),
            })
        });
        Governor::new(policy, signer, approval, counting_executor(ran)).with_egress(control)
    }

    fn read_receipts(log: &std::path::Path) -> Vec<Value> {
        std::fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn io_lines(log: &std::path::Path) -> Vec<Value> {
        read_receipts(log)
            .into_iter()
            .filter(|v| {
                v["action_id"]
                    .as_str()
                    .map(|a| a.starts_with("kriya.io."))
                    .unwrap_or(false)
            })
            .collect()
    }

    #[test]
    fn call_chain_is_stamped_on_every_receipt_and_cleared_after() {
        let (s, log) = signer_with_log();
        let ran = Arc::new(AtomicUsize::new(0));
        let mut g = egress_governor(
            s,
            "rules:\n  - host: \"*.vendor.com\"\n    tier: allow\nunlisted: deny\n",
            "api.vendor.com",
            ran.clone(),
            Box::new(DenyApproval),
        );
        g.set_call_chain(Some(vec!["a".into(), "broker".into()]));
        assert!(matches!(
            g.dispatch("widgets__list", &json!({"q": 1})),
            DispatchOutcome::Executed { .. }
        ));
        g.set_call_chain(None);
        assert!(matches!(
            g.dispatch("widgets__list", &json!({"q": 2})),
            DispatchOutcome::Executed { .. }
        ));
        let all = read_receipts(&log);
        assert_eq!(all.len(), 4, "action + io per call: {all:?}");
        for r in &all[..2] {
            assert_eq!(r["params"]["chain"], json!(["a", "broker"]), "{r}");
        }
        for r in &all[2..] {
            assert!(r["params"].get("chain").is_none(), "cleared: {r}");
        }
    }

    #[test]
    fn egress_allow_executes_and_emits_an_io_allow_receipt() {
        let (s, log) = signer_with_log();
        let ran = Arc::new(AtomicUsize::new(0));
        let mut g = egress_governor(
            s,
            "rules:\n  - host: \"*.vendor.com\"\n    tier: allow\nunlisted: deny\n",
            "api.vendor.com",
            ran.clone(),
            Box::new(DenyApproval),
        );
        assert!(matches!(
            g.dispatch("widgets__list", &json!({"q": 1})),
            DispatchOutcome::Executed { .. }
        ));
        assert_eq!(ran.load(Ordering::SeqCst), 1, "allowed egress runs");
        let io = io_lines(&log);
        assert_eq!(io.len(), 1, "one io receipt: {io:?}");
        assert_eq!(io[0]["action_id"], "kriya.io.egress.mcp.allow");
        assert_eq!(io[0]["params"]["dest_host"], "api.vendor.com");
        assert_eq!(io[0]["params"]["policy_rule"], "*.vendor.com");
        // corr joins the io receipt to the action receipt (never adjacency, L5).
        let action = read_receipts(&log)
            .into_iter()
            .find(|v| v["action_id"] == "widgets__list")
            .unwrap();
        assert_eq!(io[0]["params"]["corr"], action["step_id"]);
    }

    #[test]
    fn egress_deny_blocks_at_the_decision_point_and_emits_a_deny_receipt() {
        let (s, log) = signer_with_log();
        let ran = Arc::new(AtomicUsize::new(0));
        // Deny-by-default; the destination is not listed → deny before execute (L10).
        let mut g = egress_governor(
            s,
            "unlisted: deny\nrules: []\n",
            "evil.example",
            ran.clone(),
            Box::new(AutoApprove),
        );
        assert!(matches!(
            g.dispatch("widgets__list", &json!({})),
            DispatchOutcome::EgressDenied(_)
        ));
        assert_eq!(
            ran.load(Ordering::SeqCst),
            0,
            "denied egress must NOT execute"
        );
        let io = io_lines(&log);
        assert_eq!(io.len(), 1);
        assert_eq!(io[0]["action_id"], "kriya.io.egress.mcp.deny");
        assert_eq!(io[0]["params"]["decision"], "deny");
        // A decision-point deny has no action receipt, so no corr — the deny row stands alone.
        assert!(io[0]["params"].get("corr").is_none());
        // No action receipt was written for the blocked call.
        assert!(read_receipts(&log)
            .iter()
            .all(|v| v["action_id"] != "widgets__list"));
    }

    #[test]
    fn egress_approval_tier_rides_the_approval_gate() {
        // Granted → executes + an `approve`-facet io receipt.
        let (s, log) = signer_with_log();
        let ran = Arc::new(AtomicUsize::new(0));
        let mut g = egress_governor(
            s,
            "rules:\n  - host: \"api.partner.com\"\n    tier: approval\nunlisted: deny\n",
            "api.partner.com",
            ran.clone(),
            Box::new(AutoApprove),
        );
        assert!(matches!(
            g.dispatch("widgets__list", &json!({})),
            DispatchOutcome::Executed { .. }
        ));
        assert_eq!(ran.load(Ordering::SeqCst), 1);
        assert_eq!(
            io_lines(&log)[0]["action_id"],
            "kriya.io.egress.mcp.approve"
        );

        // Refused → NotApproved, not executed, and a deny receipt records the parked attempt.
        let (s2, log2) = signer_with_log();
        let ran2 = Arc::new(AtomicUsize::new(0));
        let mut g2 = egress_governor(
            s2,
            "rules:\n  - host: \"api.partner.com\"\n    tier: approval\nunlisted: deny\n",
            "api.partner.com",
            ran2.clone(),
            Box::new(DenyApproval),
        );
        assert!(matches!(
            g2.dispatch("widgets__list", &json!({})),
            DispatchOutcome::NotApproved
        ));
        assert_eq!(ran2.load(Ordering::SeqCst), 0);
        assert_eq!(io_lines(&log2)[0]["action_id"], "kriya.io.egress.mcp.deny");
    }

    #[test]
    fn egress_byte_budget_breach_denies_with_a_receipt() {
        let (s, log) = signer_with_log();
        let ran = Arc::new(AtomicUsize::new(0));
        // A tiny budget: each call's serialized args (~a few bytes) accumulate; the call that would
        // breach is denied (anti slow-drip exfil, B2).
        let mut g = egress_governor(
            s,
            "rules:\n  - host: \"*.vendor.com\"\n    tier: allow\n    budget: { window_secs: 60, max_bytes: 40 }\n",
            "api.vendor.com",
            ran.clone(),
            Box::new(DenyApproval),
        );
        // Args serialize to ~15 bytes each; the third call crosses 40 bytes → deny.
        let mut denied = false;
        for i in 0..5 {
            match g.dispatch("widgets__list", &json!({"n": i, "pad": "xxxx"})) {
                DispatchOutcome::EgressDenied(reason) => {
                    assert!(reason.contains("byte budget"), "reason: {reason}");
                    denied = true;
                    break;
                }
                DispatchOutcome::Executed { .. } => {}
                other => panic!("unexpected: {other:?}"),
            }
        }
        assert!(denied, "the cumulative byte budget must eventually deny");
        let deny = io_lines(&log)
            .into_iter()
            .find(|v| v["action_id"] == "kriya.io.egress.mcp.deny")
            .expect("a byte-budget deny receipt");
        assert!(deny["params"]["reason"]
            .as_str()
            .unwrap()
            .contains("byte budget"));
    }

    #[test]
    fn fail_closed_denies_egress_when_the_receipt_cannot_be_written() {
        // Fault injection: the signer's log path is a DIRECTORY, so no receipt can be persisted.
        // In fail-closed mode the io receipt is a precondition — the egress is denied and the
        // executor never runs ("no receipt, no egress", B3).
        let dir = std::env::temp_dir().join(format!("kriya-eg2-fc-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let signer = Arc::new(Signer::with_log_path(dir.clone())); // path is a directory → unwritable
        let ran = Arc::new(AtomicUsize::new(0));
        let mut g = egress_governor(
            signer,
            "fail_closed: true\nrules:\n  - host: \"*.vendor.com\"\n    tier: allow\n",
            "api.vendor.com",
            ran.clone(),
            Box::new(DenyApproval),
        );
        match g.dispatch("widgets__list", &json!({})) {
            DispatchOutcome::EgressDenied(reason) => {
                assert!(reason.contains("fail-closed"), "reason: {reason}")
            }
            other => panic!("fail-closed must deny, got {other:?}"),
        }
        assert_eq!(
            ran.load(Ordering::SeqCst),
            0,
            "no receipt, no egress: the executor must not run"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn budget_block_does_not_leak_a_fail_closed_io_receipt() {
        // Regression: the action budget must be checked BEFORE the egress gate, or a budget-blocked
        // call in fail-closed mode would still persist a `kriya.io.*.allow` precondition receipt —
        // recording an egress that never happened, with a dangling corr.
        let (s, log) = signer_with_log();
        let ran = Arc::new(AtomicUsize::new(0));
        let policy = Arc::new(
            serde_yaml::from_str::<Policy>(
                "rules:\n  - action: \"*\"\n    allow: true\nbudget:\n  max_actions_per_minute: 1\n",
            )
            .unwrap(),
        );
        let ep: EgressPolicy = serde_yaml::from_str(
            "fail_closed: true\nrules:\n  - host: \"*.vendor.com\"\n    tier: allow\n",
        )
        .unwrap();
        let control = EgressControl::new(ep, move |_a: &str, _p: &Value| {
            Some(EgressTarget {
                host: "api.vendor.com".into(),
                kind: IoKind::Mcp,
                server: None,
            })
        });
        let mut g = Governor::new(
            policy,
            s,
            Box::new(DenyApproval),
            counting_executor(ran.clone()),
        )
        .with_egress(control);
        assert!(matches!(
            g.dispatch("widgets__list", &json!({})),
            DispatchOutcome::Executed { .. }
        ));
        // The second call trips the per-minute budget — BEFORE the egress precondition is signed.
        assert!(matches!(
            g.dispatch("widgets__list", &json!({})),
            DispatchOutcome::BudgetExceeded(_)
        ));
        assert_eq!(ran.load(Ordering::SeqCst), 1);
        let io = io_lines(&log);
        assert_eq!(
            io.len(),
            1,
            "the budget-blocked call must leak no io receipt: {io:?}"
        );
        // The one io receipt's corr resolves to the one action receipt (no dangling corr).
        let actions: Vec<Value> = read_receipts(&log)
            .into_iter()
            .filter(|v| v["action_id"] == "widgets__list")
            .collect();
        assert_eq!(actions.len(), 1);
        assert_eq!(io[0]["params"]["corr"], actions[0]["step_id"]);
    }

    #[test]
    fn corr_joins_action_and_io_across_interleaved_dispatches() {
        // Two governors share ONE signer + log; alternating dispatches interleave their receipts.
        // Every io receipt must still join its action receipt by `corr`, never by adjacency (L5).
        let (s, log) = signer_with_log();
        let ep = "rules:\n  - host: \"*.vendor.com\"\n    tier: allow\n";
        let mk = |ran: Arc<AtomicUsize>| {
            let control = EgressControl::new(
                serde_yaml::from_str::<EgressPolicy>(ep).unwrap(),
                move |_a: &str, _p: &Value| {
                    Some(EgressTarget {
                        host: "api.vendor.com".into(),
                        kind: IoKind::Mcp,
                        server: None,
                    })
                },
            );
            Governor::new(
                allow_all(),
                s.clone(),
                Box::new(DenyApproval),
                counting_executor(ran),
            )
            .with_egress(control)
        };
        let mut g1 = mk(Arc::new(AtomicUsize::new(0)));
        let mut g2 = mk(Arc::new(AtomicUsize::new(0)));
        for i in 0..3 {
            g1.dispatch("a__list", &json!({"g": 1, "i": i}));
            g2.dispatch("b__list", &json!({"g": 2, "i": i}));
        }
        let receipts = read_receipts(&log);
        let action_ids: std::collections::HashSet<String> = receipts
            .iter()
            .filter(|v| !v["action_id"].as_str().unwrap().starts_with("kriya.io."))
            .map(|v| v["step_id"].as_str().unwrap().to_string())
            .collect();
        let io: Vec<&Value> = receipts
            .iter()
            .filter(|v| v["action_id"].as_str().unwrap().starts_with("kriya.io."))
            .collect();
        assert_eq!(io.len(), 6, "one io receipt per dispatch");
        for r in io {
            let corr = r["params"]["corr"]
                .as_str()
                .expect("io receipt carries corr");
            assert!(
                action_ids.contains(corr),
                "every io receipt's corr must resolve to an action receipt's step_id, even interleaved"
            );
        }
    }

    // ---- Detection pack (doc 24 §11 / EG-P) ----------------------------------------------------

    const ALLOW_VENDOR_WILDCARD: &str =
        "rules:\n  - host: \"*.vendor.com\"\n    tier: allow\nunlisted: deny\n";

    fn detection_policy_yaml(detection_block: &str) -> String {
        format!(
            "rules:\n  - action: \"*\"\n    allow: true\nbudget:\n  max_actions_per_minute: 1000\ndetection:\n{detection_block}"
        )
    }

    // B5: DNS-exfil / subdomain-entropy heuristic.

    #[test]
    fn b5_dns_exfil_alert_mode_executes_and_flags_the_receipt() {
        let (s, log) = signer_with_log();
        let ran = Arc::new(AtomicUsize::new(0));
        // Same fixture proven >= 4.0 bits/char in permissions::tests.
        let exfil = "khbwy4dxovss4z3jf5xweidwmn2gk4dsn5wg65lsmvzq";
        let mut g = egress_governor_with_detection(
            s,
            &detection_policy_yaml("  dns_exfil:\n    action: alert\n"),
            ALLOW_VENDOR_WILDCARD,
            &format!("{exfil}.vendor.com"),
            ran.clone(),
            Box::new(DenyApproval),
        );
        assert!(matches!(
            g.dispatch("widgets__list", &json!({"q": 1})),
            DispatchOutcome::Executed { .. }
        ));
        assert_eq!(
            ran.load(Ordering::SeqCst),
            1,
            "alert mode never blocks the call"
        );
        let io = io_lines(&log);
        assert_eq!(io.len(), 1);
        assert_eq!(io[0]["action_id"], "kriya.io.egress.mcp.allow");
        let flags = io[0]["params"]["flags"]
            .as_array()
            .expect("flags array present");
        assert!(
            flags
                .iter()
                .any(|f| f.as_str().unwrap().starts_with("b5-dns-exfil:")),
            "flags: {flags:?}"
        );
    }

    #[test]
    fn b5_dns_exfil_deny_mode_blocks_at_the_decision_point() {
        let (s, log) = signer_with_log();
        let ran = Arc::new(AtomicUsize::new(0));
        let exfil = "khbwy4dxovss4z3jf5xweidwmn2gk4dsn5wg65lsmvzq";
        let mut g = egress_governor_with_detection(
            s,
            &detection_policy_yaml("  dns_exfil:\n    action: deny\n"),
            ALLOW_VENDOR_WILDCARD,
            &format!("{exfil}.vendor.com"),
            ran.clone(),
            Box::new(DenyApproval),
        );
        assert!(matches!(
            g.dispatch("widgets__list", &json!({"q": 1})),
            DispatchOutcome::EgressDenied(_)
        ));
        assert_eq!(
            ran.load(Ordering::SeqCst),
            0,
            "denied egress must NOT execute"
        );
        let io = io_lines(&log);
        assert_eq!(io.len(), 1);
        assert_eq!(io[0]["action_id"], "kriya.io.egress.mcp.deny");
        assert!(
            io[0]["params"]["reason"].as_str().unwrap().contains("B5"),
            "reason: {:?}",
            io[0]["params"]["reason"]
        );
    }

    #[test]
    fn b5_dns_exfil_false_positive_safety_ordinary_host_is_unaffected() {
        let (s, log) = signer_with_log();
        let ran = Arc::new(AtomicUsize::new(0));
        // Strictest setting (deny) on an ORDINARY host — must still execute untouched.
        let mut g = egress_governor_with_detection(
            s,
            &detection_policy_yaml("  dns_exfil:\n    action: deny\n"),
            ALLOW_VENDOR_WILDCARD,
            "api.vendor.com",
            ran.clone(),
            Box::new(DenyApproval),
        );
        assert!(matches!(
            g.dispatch("widgets__list", &json!({"q": 1})),
            DispatchOutcome::Executed { .. }
        ));
        assert_eq!(ran.load(Ordering::SeqCst), 1);
        let io = io_lines(&log);
        assert_eq!(io[0]["action_id"], "kriya.io.egress.mcp.allow");
        assert!(
            io[0]["params"].get("flags").is_none(),
            "no flag on an ordinary host"
        );
    }

    // B6: SSRF / private-IP / cloud-metadata / DNS-rebinding guard.

    #[test]
    fn b6_ssrf_guard_false_positive_safety_ordinary_public_address_is_unaffected() {
        let (s, log) = signer_with_log();
        let ran = Arc::new(AtomicUsize::new(0));
        let mut g = egress_governor_with_detection(
            s,
            &detection_policy_yaml("  ssrf_guard:\n    enabled: true\n"),
            "unlisted: allow\nrules: []\n",
            "93.184.216.34", // ordinary public address (example.com)
            ran.clone(),
            Box::new(DenyApproval),
        );
        assert!(matches!(
            g.dispatch("widgets__list", &json!({"q": 1})),
            DispatchOutcome::Executed { .. }
        ));
        assert_eq!(ran.load(Ordering::SeqCst), 1);
        assert_eq!(io_lines(&log)[0]["action_id"], "kriya.io.egress.mcp.allow");
    }

    #[test]
    fn b6_ssrf_guard_denies_loopback_target_at_the_decision_point() {
        let (s, log) = signer_with_log();
        let ran = Arc::new(AtomicUsize::new(0));
        let mut g = egress_governor_with_detection(
            s,
            &detection_policy_yaml("  ssrf_guard:\n    enabled: true\n"),
            "unlisted: allow\nrules: []\n",
            "127.0.0.1",
            ran.clone(),
            Box::new(DenyApproval),
        );
        assert!(matches!(
            g.dispatch("widgets__list", &json!({"q": 1})),
            DispatchOutcome::EgressDenied(_)
        ));
        assert_eq!(ran.load(Ordering::SeqCst), 0);
        let io = io_lines(&log);
        assert_eq!(io[0]["action_id"], "kriya.io.egress.mcp.deny");
        assert!(io[0]["params"]["reason"].as_str().unwrap().contains("B6"));
    }

    #[test]
    fn b6_ssrf_guard_denies_cloud_metadata_target() {
        let (s, log) = signer_with_log();
        let ran = Arc::new(AtomicUsize::new(0));
        let mut g = egress_governor_with_detection(
            s,
            &detection_policy_yaml("  ssrf_guard:\n    enabled: true\n"),
            "unlisted: allow\nrules: []\n",
            "169.254.169.254",
            ran.clone(),
            Box::new(DenyApproval),
        );
        assert!(matches!(
            g.dispatch("widgets__list", &json!({"q": 1})),
            DispatchOutcome::EgressDenied(_)
        ));
        assert_eq!(ran.load(Ordering::SeqCst), 0);
        assert!(io_lines(&log)[0]["params"]["reason"]
            .as_str()
            .unwrap()
            .contains("metadata"));
    }

    // B7: secret + PII scan/redact on outbound bodies.

    #[test]
    fn b7_secret_pii_redact_mode_executes_and_flags_the_type_only() {
        let (s, log) = signer_with_log();
        let ran = Arc::new(AtomicUsize::new(0));
        let mut g = egress_governor_with_detection(
            s,
            &detection_policy_yaml("  secret_pii:\n    action: redact\n"),
            ALLOW_VENDOR_WILDCARD,
            "api.vendor.com",
            ran.clone(),
            Box::new(DenyApproval),
        );
        assert!(matches!(
            g.dispatch(
                "widgets__list",
                &json!({"body": "Authorization: AKIAIOSFODNN7EXAMPLE"})
            ),
            DispatchOutcome::Executed { .. }
        ));
        assert_eq!(
            ran.load(Ordering::SeqCst),
            1,
            "redact mode never blocks the call"
        );
        let io = io_lines(&log);
        let flags = io[0]["params"]["flags"].as_array().expect("flags present");
        assert!(flags
            .iter()
            .any(|f| f.as_str().unwrap().contains("aws_access_key")));
        assert!(!io[0].to_string().contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn b7_secret_pii_deny_mode_blocks_at_the_decision_point() {
        let (s, log) = signer_with_log();
        let ran = Arc::new(AtomicUsize::new(0));
        let mut g = egress_governor_with_detection(
            s,
            &detection_policy_yaml("  secret_pii:\n    action: deny\n"),
            ALLOW_VENDOR_WILDCARD,
            "api.vendor.com",
            ran.clone(),
            Box::new(DenyApproval),
        );
        assert!(matches!(
            g.dispatch(
                "widgets__list",
                &json!({"body": "Authorization: AKIAIOSFODNN7EXAMPLE"})
            ),
            DispatchOutcome::EgressDenied(_)
        ));
        assert_eq!(ran.load(Ordering::SeqCst), 0);
        let io = io_lines(&log);
        assert_eq!(io[0]["action_id"], "kriya.io.egress.mcp.deny");
        assert!(io[0]["params"]["reason"].as_str().unwrap().contains("B7"));
        assert!(!io[0].to_string().contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn b7_secret_pii_false_positive_safety_ordinary_payload_is_unaffected() {
        let (s, log) = signer_with_log();
        let ran = Arc::new(AtomicUsize::new(0));
        // Strictest setting (deny) on an ordinary payload with none of the seven shapes.
        let mut g = egress_governor_with_detection(
            s,
            &detection_policy_yaml("  secret_pii:\n    action: deny\n"),
            ALLOW_VENDOR_WILDCARD,
            "api.vendor.com",
            ran.clone(),
            Box::new(DenyApproval),
        );
        assert!(matches!(
            g.dispatch(
                "widgets__list",
                &json!({"q": "list widgets in warehouse 12"})
            ),
            DispatchOutcome::Executed { .. }
        ));
        assert_eq!(ran.load(Ordering::SeqCst), 1);
        assert!(io_lines(&log)[0]["params"].get("flags").is_none());
    }

    #[test]
    fn b7_secret_pii_sentinel_the_matched_value_never_appears_in_the_io_receipt() {
        // The underlying ACTION receipt still mirrors `params` verbatim (the frozen receipt
        // schema's own contract, unrelated to B7 — redacting THAT for display/export is the
        // Console minimizer's job). This sentinel scopes its assertion to the io receipt, which is
        // what B7 actually writes, and proves the value never reaches it — type name only.
        let (s, log) = signer_with_log();
        let ran = Arc::new(AtomicUsize::new(0));
        let secret = "AKIAIOSFODNN7EXAMPLE";
        let mut g = egress_governor_with_detection(
            s,
            &detection_policy_yaml("  secret_pii:\n    action: redact\n"),
            ALLOW_VENDOR_WILDCARD,
            "api.vendor.com",
            ran.clone(),
            Box::new(DenyApproval),
        );
        assert!(matches!(
            g.dispatch(
                "widgets__list",
                &json!({"body": format!("Authorization: {secret}")})
            ),
            DispatchOutcome::Executed { .. }
        ));
        let io = io_lines(&log);
        let io_raw = io[0].to_string();
        assert!(
            !io_raw.contains(secret),
            "the secret must never appear in the io receipt: {io_raw}"
        );
        let flags = io[0]["params"]["flags"].as_array().expect("flags present");
        assert!(
            flags
                .iter()
                .any(|f| f.as_str().unwrap().contains("aws_access_key")),
            "flags: {flags:?}"
        );
    }

    // B8: operation rails (HTTP verb+path glob, GraphQL mutation name).

    #[test]
    fn b8_operation_rail_allow_permits_a_matching_operation() {
        let (s, log) = signer_with_log();
        let ran = Arc::new(AtomicUsize::new(0));
        let mut g = egress_governor_with_detection(
            s,
            &detection_policy_yaml(
                "  operation_rails:\n    - host: \"*.vendor.com\"\n      method: GET\n      path: \"/v1/*\"\n      tier: allow\n",
            ),
            ALLOW_VENDOR_WILDCARD,
            "api.vendor.com",
            ran.clone(),
            Box::new(DenyApproval),
        );
        assert!(matches!(
            g.dispatch(
                "widgets__list",
                &json!({"method": "GET", "path": "/v1/users"})
            ),
            DispatchOutcome::Executed { .. }
        ));
        assert_eq!(ran.load(Ordering::SeqCst), 1);
        assert_eq!(io_lines(&log)[0]["action_id"], "kriya.io.egress.mcp.allow");
    }

    #[test]
    fn b8_operation_rail_denies_an_operation_no_rail_permits() {
        let (s, log) = signer_with_log();
        let ran = Arc::new(AtomicUsize::new(0));
        let mut g = egress_governor_with_detection(
            s,
            &detection_policy_yaml(
                "  operation_rails:\n    - host: \"*.vendor.com\"\n      method: GET\n      path: \"/v1/*\"\n      tier: allow\n",
            ),
            ALLOW_VENDOR_WILDCARD,
            "api.vendor.com",
            ran.clone(),
            Box::new(DenyApproval),
        );
        // DELETE isn't on the rail — an allowlist fence denies anything not explicitly permitted.
        assert!(matches!(
            g.dispatch(
                "widgets__delete",
                &json!({"method": "DELETE", "path": "/v1/users/1"})
            ),
            DispatchOutcome::EgressDenied(_)
        ));
        assert_eq!(ran.load(Ordering::SeqCst), 0);
        let io = io_lines(&log);
        assert_eq!(io[0]["action_id"], "kriya.io.egress.mcp.deny");
        assert!(io[0]["params"]["reason"].as_str().unwrap().contains("B8"));
    }

    #[test]
    fn b8_operation_rail_false_positive_safety_unrailed_host_is_unaffected() {
        let (s, log) = signer_with_log();
        let ran = Arc::new(AtomicUsize::new(0));
        // The one configured rail scopes to a DIFFERENT host — api.vendor.com has no rail at all.
        let mut g = egress_governor_with_detection(
            s,
            &detection_policy_yaml(
                "  operation_rails:\n    - host: \"other.example.com\"\n      tier: allow\n",
            ),
            ALLOW_VENDOR_WILDCARD,
            "api.vendor.com",
            ran.clone(),
            Box::new(DenyApproval),
        );
        // Params carry none of the rail's expected shape — would parse-fail if a rail applied here.
        assert!(matches!(
            g.dispatch("widgets__list", &json!({"q": 1})),
            DispatchOutcome::Executed { .. }
        ));
        assert_eq!(
            ran.load(Ordering::SeqCst),
            1,
            "an unrailed host must be completely unaffected"
        );
        assert_eq!(io_lines(&log)[0]["action_id"], "kriya.io.egress.mcp.allow");
    }

    #[test]
    fn b8_operation_rail_parse_failure_denies_fail_closed() {
        let (s, log) = signer_with_log();
        let ran = Arc::new(AtomicUsize::new(0));
        let mut g = egress_governor_with_detection(
            s,
            &detection_policy_yaml(
                "  operation_rails:\n    - host: \"*.vendor.com\"\n      method: GET\n      path: \"/v1/*\"\n      tier: allow\n",
            ),
            ALLOW_VENDOR_WILDCARD,
            "api.vendor.com",
            ran.clone(),
            Box::new(DenyApproval),
        );
        // No method/path/url/query anywhere in params — the rail can't classify this call at all.
        assert!(matches!(
            g.dispatch("widgets__list", &json!({"q": 1})),
            DispatchOutcome::EgressDenied(_)
        ));
        assert_eq!(ran.load(Ordering::SeqCst), 0);
        let io = io_lines(&log);
        let reason = io[0]["params"]["reason"].as_str().unwrap();
        assert!(
            reason.contains("B8") && reason.contains("parsed"),
            "reason: {reason}"
        );
    }

    // B9: canary tokens.

    #[test]
    fn b9_canary_token_match_denies_regardless_of_any_soft_mode() {
        let (s, log) = signer_with_log();
        let ran = Arc::new(AtomicUsize::new(0));
        let mut g = egress_governor_with_detection(
            s,
            &detection_policy_yaml("  canary_tokens:\n    - \"canary-token-xyz123\"\n"),
            ALLOW_VENDOR_WILDCARD,
            "api.vendor.com",
            ran.clone(),
            Box::new(DenyApproval),
        );
        assert!(matches!(
            g.dispatch(
                "widgets__list",
                &json!({"note": "leaked canary-token-xyz123 here"})
            ),
            DispatchOutcome::EgressDenied(_)
        ));
        assert_eq!(ran.load(Ordering::SeqCst), 0);
        let io = io_lines(&log);
        assert_eq!(io[0]["action_id"], "kriya.io.egress.mcp.deny");
        assert!(io[0]["params"]["reason"].as_str().unwrap().contains("B9"));
    }

    #[test]
    fn b9_canary_false_positive_safety_ordinary_payload_is_unaffected() {
        let (s, log) = signer_with_log();
        let ran = Arc::new(AtomicUsize::new(0));
        let mut g = egress_governor_with_detection(
            s,
            &detection_policy_yaml("  canary_tokens:\n    - \"canary-token-xyz123\"\n"),
            ALLOW_VENDOR_WILDCARD,
            "api.vendor.com",
            ran.clone(),
            Box::new(DenyApproval),
        );
        assert!(matches!(
            g.dispatch("widgets__list", &json!({"note": "nothing suspicious here"})),
            DispatchOutcome::Executed { .. }
        ));
        assert_eq!(ran.load(Ordering::SeqCst), 1);
        assert_eq!(io_lines(&log)[0]["action_id"], "kriya.io.egress.mcp.allow");
    }

    #[test]
    fn b9_canary_check_runs_before_the_destination_tier_so_an_allowed_host_is_still_denied() {
        // Proves B9 pre-empts the tier decision rather than riding it: the destination is on the
        // ALLOW tier (would otherwise clear cleanly), yet a canary match still blocks it.
        let (s, log) = signer_with_log();
        let ran = Arc::new(AtomicUsize::new(0));
        let mut g = egress_governor_with_detection(
            s,
            &detection_policy_yaml("  canary_tokens:\n    - \"canary-token-xyz123\"\n"),
            ALLOW_VENDOR_WILDCARD,
            "api.vendor.com", // matches the allow-tier wildcard
            ran.clone(),
            Box::new(DenyApproval),
        );
        assert!(matches!(
            g.dispatch("widgets__list", &json!({"note": "canary-token-xyz123"})),
            DispatchOutcome::EgressDenied(_)
        ));
        assert_eq!(ran.load(Ordering::SeqCst), 0);
        // No `policy_rule` on the deny — it never reached the tier's rule-matching at all.
        assert!(io_lines(&log)[0]["params"].get("policy_rule").is_none());
    }

    // B12: MCP response enforcement (per-server trust classes).

    /// An executor returning fixed `data` for every call — for testing what B12 does with a
    /// response's content, independent of what the underlying action itself does.
    fn executor_returning(data: Value) -> Box<dyn ActionExecutor> {
        Box::new(FnExecutor(move |_id: &str, _p: &Value| {
            ActionOutcome::ok(data.clone())
        }))
    }

    /// A governor with ONLY ingress governance installed (no egress) — resolves `<namespace>__<tool>`
    /// action ids back to `namespace`, exactly like the broker's real resolver.
    fn ingress_governor(
        signer: Arc<Signer>,
        mcp_response_yaml: &str,
        executor: Box<dyn ActionExecutor>,
    ) -> Governor {
        let policy: McpResponsePolicy = serde_yaml::from_str(mcp_response_yaml).unwrap();
        let ingress = IngressControl::new(policy, |action_id: &str| {
            action_id.split_once("__").map(|(ns, _)| ns.to_string())
        });
        Governor::new(allow_all(), signer, Box::new(DenyApproval), executor).with_ingress(ingress)
    }

    #[test]
    fn b12_trusted_class_never_scans_even_a_secret_shaped_response() {
        let (s, log) = signer_with_log();
        let mut g = ingress_governor(
            s,
            "per_server:\n  widgets: trusted\n",
            executor_returning(json!({"body": "Authorization: AKIAIOSFODNN7EXAMPLE"})),
        );
        assert!(matches!(
            g.dispatch("widgets__list", &json!({})),
            DispatchOutcome::Executed { .. }
        ));
        let io = io_lines(&log);
        assert_eq!(io.len(), 1);
        assert_eq!(io[0]["action_id"], "kriya.io.ingress.mcp.allow");
        assert!(
            io[0]["params"].get("flags").is_none(),
            "trusted never scans, so never flags"
        );
    }

    #[test]
    fn b12_scan_class_flags_a_secret_shaped_response_without_blocking() {
        let (s, log) = signer_with_log();
        let mut g = ingress_governor(
            s,
            "per_server:\n  widgets: scan\n",
            executor_returning(json!({"body": "Authorization: AKIAIOSFODNN7EXAMPLE"})),
        );
        assert!(matches!(
            g.dispatch("widgets__list", &json!({})),
            DispatchOutcome::Executed { .. }
        ));
        let io = io_lines(&log);
        assert_eq!(
            io[0]["action_id"], "kriya.io.ingress.mcp.allow",
            "scan never blocks on content"
        );
        let flags = io[0]["params"]["flags"].as_array().expect("flags present");
        assert!(flags
            .iter()
            .any(|f| f.as_str().unwrap().contains("aws_access_key")));
        assert!(
            !io[0].to_string().contains("AKIAIOSFODNN7EXAMPLE"),
            "type only, never the value"
        );
        // corr always present on an ingress receipt — the call DID execute.
        let action = read_receipts(&log)
            .into_iter()
            .find(|v| v["action_id"] == "widgets__list")
            .unwrap();
        assert_eq!(io[0]["params"]["corr"], action["step_id"]);
    }

    #[test]
    fn b12_scan_class_false_positive_safety_ordinary_response_is_unaffected() {
        let (s, log) = signer_with_log();
        let mut g = ingress_governor(
            s,
            "per_server:\n  widgets: scan\n",
            executor_returning(json!({"items": ["widget-1", "widget-2"]})),
        );
        assert!(matches!(
            g.dispatch("widgets__list", &json!({})),
            DispatchOutcome::Executed { .. }
        ));
        let io = io_lines(&log);
        assert_eq!(io[0]["action_id"], "kriya.io.ingress.mcp.allow");
        assert!(io[0]["params"].get("flags").is_none());
    }

    #[test]
    fn b12_block_class_replaces_the_response_and_denies_at_the_ingress_receipt() {
        let (s, log) = signer_with_log();
        let mut g = ingress_governor(
            s,
            "per_server:\n  widgets: block\n",
            executor_returning(json!({"items": ["real", "data"]})),
        );
        match g.dispatch("widgets__list", &json!({})) {
            DispatchOutcome::Executed { outcome, .. } => {
                assert!(
                    !outcome.success,
                    "a blocked response must not report as a success"
                );
                assert!(
                    outcome.data.is_null(),
                    "the real content must not reach the caller"
                );
            }
            other => panic!("expected Executed (with a blocked outcome), got {other:?}"),
        }
        let io = io_lines(&log);
        assert_eq!(io[0]["action_id"], "kriya.io.ingress.mcp.deny");
        assert!(io[0]["params"]["reason"].as_str().unwrap().contains("B12"));
        // corr still present — unlike an egress deny, the action DID execute.
        assert!(io[0]["params"].get("corr").is_some());
    }

    #[test]
    fn b12_absent_ingress_control_is_byte_identical_to_pre_eg_p() {
        let ran = Arc::new(AtomicUsize::new(0));
        let (s, log) = signer_with_log();
        let mut g = Governor::new(
            allow_all(),
            s,
            Box::new(DenyApproval),
            counting_executor(ran),
        );
        assert!(matches!(
            g.dispatch("widgets__list", &json!({})),
            DispatchOutcome::Executed { .. }
        ));
        assert!(
            io_lines(&log).is_empty(),
            "no ingress control installed → no kriya.io.ingress.* at all"
        );
    }

    // ---- B13: credential brokering — governor pre-check (doc 24 §11 B13 / EG-B) --------------
    // These test the SCOPE pre-check only (alias configured + allowed for the destination): the
    // governor never reads a secret value, so it can't assert what got sent — that's `secrets.rs`'s
    // `broker_body` unit tests plus the real-transport integration test in `tests/brokering.rs`.

    fn secrets_policy_yaml(secrets_block: &str) -> String {
        format!(
            "rules:\n  - action: \"*\"\n    allow: true\nbudget:\n  max_actions_per_minute: 1000\nsecrets:\n{secrets_block}"
        )
    }

    #[test]
    fn b13_brokering_clears_a_configured_and_scoped_alias_and_flags_the_receipt() {
        let (s, log) = signer_with_log();
        let ran = Arc::new(AtomicUsize::new(0));
        let mut g = egress_governor_with_detection(
            s,
            &secrets_policy_yaml(
                "  aliases:\n    - alias: \"github_pat\"\n      keychain_service: \"kriya\"\n      keychain_account: \"github_pat\"\n      allowed_hosts:\n        - \"*.vendor.com\"\n",
            ),
            ALLOW_VENDOR_WILDCARD,
            "api.vendor.com",
            ran.clone(),
            Box::new(DenyApproval),
        );
        assert!(matches!(
            g.dispatch("widgets__list", &json!({"token": "{{kriya:github_pat}}"})),
            DispatchOutcome::Executed { .. }
        ));
        assert_eq!(
            ran.load(Ordering::SeqCst),
            1,
            "a cleared alias never blocks the call"
        );
        let io = io_lines(&log);
        assert_eq!(io[0]["action_id"], "kriya.io.egress.mcp.allow");
        let flags = io[0]["params"]["flags"].as_array().expect("flags present");
        assert!(flags
            .iter()
            .any(|f| f.as_str().unwrap() == "b13-brokered:github_pat"));
        // The placeholder text itself is a fine thing to see in the receipt (it's not the secret) —
        // but the point of the feature is that nothing BEYOND the placeholder ever appears here.
        assert!(!io[0].to_string().to_lowercase().contains("real_secret"));
    }

    #[test]
    fn b13_brokering_denies_an_unconfigured_alias() {
        let (s, log) = signer_with_log();
        let ran = Arc::new(AtomicUsize::new(0));
        let mut g = egress_governor_with_detection(
            s,
            &secrets_policy_yaml("  aliases: []\n"),
            ALLOW_VENDOR_WILDCARD,
            "api.vendor.com",
            ran.clone(),
            Box::new(DenyApproval),
        );
        assert!(matches!(
            g.dispatch("widgets__list", &json!({"token": "{{kriya:nope}}"})),
            DispatchOutcome::EgressDenied(_)
        ));
        assert_eq!(
            ran.load(Ordering::SeqCst),
            0,
            "an unconfigured alias must never execute"
        );
        let io = io_lines(&log);
        assert_eq!(io[0]["action_id"], "kriya.io.egress.mcp.deny");
        let reason = io[0]["params"]["reason"].as_str().unwrap();
        assert!(
            reason.contains("B13") && reason.contains("not configured"),
            "reason: {reason}"
        );
    }

    #[test]
    fn b13_brokering_denies_a_misrouted_alias_without_leaking_anything() {
        // The alias IS configured, but its allowed_hosts doesn't cover THIS destination — the exact
        // "misrouted call must not leak the secret to an unlisted host" acceptance criterion.
        let (s, log) = signer_with_log();
        let ran = Arc::new(AtomicUsize::new(0));
        let mut g = egress_governor_with_detection(
            s,
            &secrets_policy_yaml(
                "  aliases:\n    - alias: \"github_pat\"\n      keychain_service: \"kriya\"\n      keychain_account: \"github_pat\"\n      allowed_hosts:\n        - \"api.github.com\"\n",
            ),
            ALLOW_VENDOR_WILDCARD,
            "api.vendor.com", // allowed by the EGRESS tier, but NOT by the alias's own scope
            ran.clone(),
            Box::new(DenyApproval),
        );
        assert!(matches!(
            g.dispatch("widgets__list", &json!({"token": "{{kriya:github_pat}}"})),
            DispatchOutcome::EgressDenied(_)
        ));
        assert_eq!(
            ran.load(Ordering::SeqCst),
            0,
            "a misrouted alias must never execute"
        );
        let io = io_lines(&log);
        assert_eq!(io[0]["action_id"], "kriya.io.egress.mcp.deny");
        let reason = io[0]["params"]["reason"].as_str().unwrap();
        assert!(
            reason.contains("B13") && reason.contains("api.vendor.com"),
            "reason: {reason}"
        );
        let full = io[0].to_string();
        assert!(
            !full.to_lowercase().contains("secret"),
            "no value or hint of one, only the alias name"
        );
    }

    #[test]
    fn b13_brokering_false_positive_safety_a_payload_with_no_placeholder_is_unaffected() {
        let (s, log) = signer_with_log();
        let ran = Arc::new(AtomicUsize::new(0));
        let mut g = egress_governor_with_detection(
            s,
            &secrets_policy_yaml(
                "  aliases:\n    - alias: \"github_pat\"\n      keychain_service: \"kriya\"\n      keychain_account: \"github_pat\"\n      allowed_hosts:\n        - \"api.github.com\"\n",
            ),
            ALLOW_VENDOR_WILDCARD,
            "api.vendor.com",
            ran.clone(),
            Box::new(DenyApproval),
        );
        assert!(matches!(
            g.dispatch("widgets__list", &json!({"q": "list widgets"})),
            DispatchOutcome::Executed { .. }
        ));
        assert_eq!(ran.load(Ordering::SeqCst), 1);
        assert!(
            io_lines(&log)[0]["params"].get("flags").is_none(),
            "no placeholder → no flag at all"
        );
    }

    #[test]
    fn b13_brokering_one_bad_alias_denies_the_whole_call_even_with_a_good_one_present() {
        // Fail-safe: a call naming TWO aliases where only one passes its scope check must be denied
        // outright, never partially cleared.
        let (s, log) = signer_with_log();
        let ran = Arc::new(AtomicUsize::new(0));
        let mut g = egress_governor_with_detection(
            s,
            &secrets_policy_yaml(
                "  aliases:\n    - alias: \"good\"\n      keychain_service: \"kriya\"\n      keychain_account: \"good\"\n      allowed_hosts:\n        - \"*.vendor.com\"\n    - alias: \"bad\"\n      keychain_service: \"kriya\"\n      keychain_account: \"bad\"\n      allowed_hosts:\n        - \"somewhere-else.example\"\n",
            ),
            ALLOW_VENDOR_WILDCARD,
            "api.vendor.com",
            ran.clone(),
            Box::new(DenyApproval),
        );
        assert!(matches!(
            g.dispatch(
                "widgets__list",
                &json!({"a": "{{kriya:good}}", "b": "{{kriya:bad}}"})
            ),
            DispatchOutcome::EgressDenied(_)
        ));
        assert_eq!(
            ran.load(Ordering::SeqCst),
            0,
            "one bad alias must deny the WHOLE call"
        );
        let io = io_lines(&log);
        assert!(io[0]["params"]["reason"].as_str().unwrap().contains("bad"));
    }

    #[test]
    fn b13_absent_secrets_policy_never_scans_for_placeholders_at_all() {
        // No `secrets:` section at all → a literal-looking placeholder in a payload is just text.
        let (s, log) = signer_with_log();
        let ran = Arc::new(AtomicUsize::new(0));
        let mut g = egress_governor_with_detection(
            s,
            "rules:\n  - action: \"*\"\n    allow: true\nbudget:\n  max_actions_per_minute: 1000\n",
            ALLOW_VENDOR_WILDCARD,
            "api.vendor.com",
            ran.clone(),
            Box::new(DenyApproval),
        );
        assert!(matches!(
            g.dispatch("widgets__list", &json!({"note": "{{kriya:whatever}}"})),
            DispatchOutcome::Executed { .. }
        ));
        assert_eq!(ran.load(Ordering::SeqCst), 1);
        assert!(io_lines(&log)[0]["params"].get("flags").is_none());
    }

    // ── D1 (doc 27 §4 / docs/design/d1-memory-receipts.md D-4): broker memory-tool registry ──────

    fn memory_lines(log: &std::path::Path) -> Vec<Value> {
        read_receipts(log)
            .into_iter()
            .filter(|v| v["action_id"].as_str().map(|a| a.starts_with("kriya.memory.")).unwrap_or(false))
            .collect()
    }

    /// A policy that allows `notes__*` and registers `notes/create_entities` as a memory tool
    /// (`op: create`, `content_field: entity`) — the §5 test-plan fixture (d).
    fn policy_with_registered_memory_tool() -> Arc<Policy> {
        Arc::new(
            serde_yaml::from_str(
                "rules:\n  - action: \"notes__*\"\n    allow: true\nmemory:\n  - server: notes\n    tool: create_entities\n    op: create\n    content_field: entity\n",
            )
            .unwrap(),
        )
    }

    #[test]
    fn registered_memory_tool_call_emits_a_kriya_memory_write_receipt_hash_only() {
        let (s, log) = signer_with_log();
        let ran = Arc::new(AtomicUsize::new(0));
        let mut g = Governor::new(
            policy_with_registered_memory_tool(),
            s,
            Box::new(DenyApproval),
            counting_executor(ran.clone()),
        )
        .with_run_correlation(Some("run-mem-1".into()));

        let sentinel = "the actual memory content, never on the wire";
        match g.dispatch("notes__create_entities", &json!({ "entity": sentinel, "kind": "person" })) {
            DispatchOutcome::Executed { .. } => {}
            other => panic!("expected Executed, got {other:?}"),
        }
        assert_eq!(ran.load(Ordering::SeqCst), 1);

        let mem = memory_lines(&log);
        assert_eq!(mem.len(), 1, "exactly one kriya.memory.* receipt for the registered call");
        let r = &mem[0];
        assert_eq!(r["action_id"], json!("kriya.memory.write"), "op create -> verb write (§D-1)");
        assert_eq!(r["success"], json!(true));
        let m = &r["params"]["kriya.memory"];
        assert_eq!(m["class"], json!("mcp-registered"));
        assert_eq!(m["surface"], json!("mcp-tool"));
        assert_eq!(m["tool_ref"]["server"], json!("notes"));
        assert_eq!(m["tool_ref"]["tool"], json!("create_entities"));
        assert_eq!(m["tool_ref"]["op"], json!("create"));
        assert_eq!(
            m["content_sha256"].as_str().unwrap(),
            &{
                use sha2::{Digest, Sha256};
                hex::encode(Sha256::digest(sentinel.as_bytes()))
            }
        );
        assert_eq!(m["content_bytes"], json!(sentinel.len() as u64));
        assert_eq!(r["params"]["kriya.corr"]["run_id"], json!("run-mem-1"));

        // Hash-not-content (acceptance #2): the sentinel never appears in the `kriya.memory.*`
        // receipt itself (the base action receipt is a SEPARATE, pre-existing, disclosed lane
        // that already records full `arguments` verbatim — §D-7 — unchanged and out of scope
        // here; D1's OWN receipt is the thing under test).
        let mem_wire = serde_json::to_string(r).unwrap();
        assert!(!mem_wire.contains(sentinel), "the memory content leaked into D1's own receipt");
    }

    #[test]
    fn unregistered_memory_looking_tool_emits_no_kriya_memory_receipt_heuristic_honesty() {
        // A tool NAMED like memory (`__save`) but never registered in `memory:` — §D-1's honest
        // default: a bare name-looks-like-memory heuristic never mints a signed receipt.
        let (s, log) = signer_with_log();
        let ran = Arc::new(AtomicUsize::new(0));
        let policy: Arc<Policy> = Arc::new(
            serde_yaml::from_str("rules:\n  - action: \"memory__*\"\n    allow: true\n").unwrap(),
        );
        let mut g = Governor::new(policy, s, Box::new(DenyApproval), counting_executor(ran.clone()));

        match g.dispatch("memory__save", &json!({ "text": "looks like memory but isn't registered" })) {
            DispatchOutcome::Executed { .. } => {}
            other => panic!("expected Executed, got {other:?}"),
        }
        assert_eq!(ran.load(Ordering::SeqCst), 1);
        assert!(memory_lines(&log).is_empty(), "an unregistered tool must never mint kriya.memory.*");
    }

    #[test]
    fn absent_memory_section_round_trips_to_no_receipts_ever() {
        // BC-3: a policy that never authored `memory:` at all.
        let (s, log) = signer_with_log();
        let ran = Arc::new(AtomicUsize::new(0));
        let mut g = Governor::new(allow_all(), s, Box::new(DenyApproval), counting_executor(ran));
        match g.dispatch("create_note", &json!({"title": "hi"})) {
            DispatchOutcome::Executed { .. } => {}
            other => panic!("expected Executed, got {other:?}"),
        }
        assert!(memory_lines(&log).is_empty());
    }
}
