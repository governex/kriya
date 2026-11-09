//! Minimal but real permission layer. Every agent action is checked against a policy
//! before the host asks the app to run it. Default is deny-unknown; deletes require
//! human approval (no approval queue exists yet in Phase 0, so they are held/denied).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::agent::inference::retry::RetryPolicy;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    Allow,
    RequiresApproval,
    Deny,
}

#[derive(Debug, Clone, Deserialize)]
struct Rule {
    /// Exact action id, a `prefix_*` glob, or `*` for all.
    action: String,
    #[serde(default)]
    allow: bool,
    #[serde(default)]
    require_approval: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Budget {
    /// Max actions the agent may take in any trailing 60-second window. `None` = no cap.
    #[serde(default)]
    pub max_actions_per_minute: Option<u32>,
    /// Max inference/API calls the agent may make in any trailing 60-minute window. `None` = no
    /// cap. Independent of the per-minute action cap: this bounds model *cost* (each agent step is
    /// one backend call, possibly paid/remote), not action bursts against the app.
    #[serde(default)]
    pub max_api_calls_per_hour: Option<u32>,
}

/// Tunes how a *transient* inference-backend error is retried before the host gives up on a
/// step (R10). Optional in policy: when absent the host uses [`RetryPolicy::default`]. Lets an
/// operator dial reliability (e.g. a flaky local model vs. an expensive rate-limited cloud model)
/// without code changes. Has no effect on deterministic/scripted backends — they never error.
#[derive(Debug, Clone, Deserialize)]
pub struct RetryConfig {
    /// Retries after the first attempt. `0` = fail-fast (one attempt). Total attempts = this + 1.
    #[serde(default)]
    pub max_retries: Option<u32>,
    /// Backoff in milliseconds before the first retry; doubles each retry (capped by `max_backoff_ms`).
    #[serde(default)]
    pub initial_backoff_ms: Option<u64>,
    /// Upper bound on a single backoff wait, in milliseconds.
    #[serde(default)]
    pub max_backoff_ms: Option<u64>,
}

impl RetryConfig {
    /// Fold this config onto [`RetryPolicy::default`], overriding only the fields that are set.
    fn to_policy(&self) -> RetryPolicy {
        let mut p = RetryPolicy::default();
        if let Some(n) = self.max_retries {
            p.max_retries = n;
        }
        if let Some(ms) = self.initial_backoff_ms {
            p.initial_backoff = Duration::from_millis(ms);
        }
        if let Some(ms) = self.max_backoff_ms {
            p.max_backoff = Duration::from_millis(ms);
        }
        p
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Policy {
    rules: Vec<Rule>,
    #[serde(default)]
    budget: Budget,
    /// Optional retry/backoff tuning for transient inference failures (R10).
    #[serde(default)]
    retry: Option<RetryConfig>,
    /// On-device guarantee (R13). When `true`, the in-process host refuses to run with an
    /// inference backend that egresses to a remote service, and signs an attestation that the
    /// run was sealed — the "nothing leaves the device" posture regulated apps need. Default
    /// `false` (off, fully backward compatible).
    #[serde(default)]
    on_device: bool,
    /// Optional **egress destination tier** (doc 24 §7.3 / EG-2). When present, governed-lane
    /// egress (the gateway/broker HTTP upstreams, the hook's WebFetch lane) is checked against
    /// operator-authored host patterns → `allow | approval | deny`, with per-destination byte
    /// budgets. Absent by default → egress governance OFF, byte-identical to pre-EG-2 behaviour.
    /// This is a governed-lane control, not a host-level network control: a spawned subprocess
    /// bypasses it (see the module doc + TRUST.md).
    #[serde(default)]
    egress: Option<EgressPolicy>,
    /// Optional **retention design** (doc 24 §6-P2): the max-age classes that a retention pruner
    /// honours before sealing the pruned prefix behind a signed epoch-checkpoint receipt. Absent
    /// by default → receipts are retained indefinitely (the pre-EG-2 behaviour).
    #[serde(default)]
    retention: Option<Retention>,
    /// Optional **detection pack** (doc 24 §11 B5–B12 / EG-P): DNS-exfil heuristics, the SSRF/
    /// rebinding guard, secret+PII scanning, operation rails, canary tokens, the connector
    /// registry, read-only presets, and MCP response trust classes — each independently absent by
    /// default, so opting into the pack as a whole never silently enables a specific detector.
    #[serde(default)]
    detection: Option<DetectionPolicy>,
    /// Optional **credential brokering** (doc 24 §11 B13 / EG-B): alias → OS Keychain reference
    /// mappings, each scoped to its own destination allowlist. Absent by default → no `{{kriya:*}}`
    /// placeholder is ever substituted, byte-identical to pre-EG-B behaviour. A NEW trust posture
    /// when present — kriya briefly holds a real secret in process memory to inject it — see
    /// `crate::secrets`'s module doc and `docs/THREAT-MODEL-brokering.md`.
    #[serde(default)]
    secrets: Option<crate::secrets::SecretsPolicy>,
    /// Optional **A2A (agent-to-agent) governance seam** (doc 24 §11 B18 / EG-F). ROADMAP-DEPTH: no
    /// agent-to-agent transport exists in this codebase yet, so nothing calls
    /// [`Policy::evaluate_a2a_target`] today — this only defines the policy shape + decision
    /// function a future A2A broker lane will call once real inter-agent RPC exists, so that lane
    /// reuses the SAME allowlist engine as the egress tier instead of inventing a second allowlist
    /// DSL. Absent by default → byte-identical to pre-EG-F behaviour.
    #[serde(default)]
    a2a: Option<A2aPolicy>,
    /// Optional **model-identity gate** (F1, doc 28 §F1): `kriya-llm-proxy`'s policy dimension —
    /// approved local-inference model digests per tier + the default action for an unrecognized
    /// model. Absent by default → `kriya-llm-proxy` still runs with [`ModelPolicy::default`]
    /// (`unknown_model: warn`), so an agent-policy.yaml that never authored `model:` behaves
    /// identically whether the key is present-but-empty or absent (same BC discipline `egress`/
    /// `detection`/`secrets` already established).
    #[serde(default)]
    model: Option<ModelPolicy>,
    /// Optional **endpoint budget gate** (C2, doc 27 §4 / `docs/design/c2-budget-gate.md`): USD
    /// spend budgets (session / rolling-day / user scope) the hook `pre` lane enforces
    /// pre-execution against C1's trailing spend state. Absent by default → byte-identical to
    /// pre-C2 behaviour (the same BC discipline `egress`/`detection`/`secrets`/`model` already
    /// established).
    #[serde(default)]
    budgets: Option<BudgetPolicy>,
    /// Optional **deterministic-execution lane routing** (F4-wasm, doc 28 §F4): when a tool has a
    /// registered WASM variant AND `prefer_deterministic_lane` is on, governed calls to it route
    /// through `kriya-run-wasm`'s engine instead of the tool's normal executor — see
    /// [`ExecPolicy`]. Absent by default → byte-identical to pre-F4-wasm behaviour (the same BC
    /// discipline `egress`/`detection`/`secrets`/`model`/`budgets` already established).
    #[serde(default)]
    exec: Option<ExecPolicy>,
    /// D1 (doc 27 §4 / `docs/design/d1-memory-receipts.md` §D-1/§D-6): the broker's memory-tool
    /// registry — a `kriya.memory.*` receipt is minted for a REGISTERED tool only, never a bare
    /// name-looks-like-memory heuristic (the honest default). Absent `memory:` ⇒ no broker call
    /// is ever treated as memory, byte-identical to pre-D1 behaviour (the same BC discipline
    /// `egress`/`detection`/`secrets`/`model`/`budgets`/`exec` already established).
    #[serde(default)]
    memory: Option<Vec<MemoryRegistryEntry>>,
    /// B4 (doc 27 §4 / `docs/design/b4-temporal-conditions.md`): a small, closed set of
    /// session-scoped, cross-event preconditions layered on top of the action tier ("deny X unless
    /// Y happened/succeeded earlier this session"). Absent `temporal:` ⇒ the hook `pre` lane performs
    /// no temporal consult at all, byte-identical to pre-B4 behaviour (the same BC discipline
    /// `egress`/`detection`/`secrets`/`model`/`budgets`/`exec`/`memory` already established).
    #[serde(default)]
    temporal: Option<TemporalPolicy>,
    /// F-2 (kriya-console doc 31 §3.3 / the F2-gates design doc (kriya-console)): **action gates** — the
    /// Console-compiled high-stakes-class matcher rules (deploy, destructive-git, publish, prod-DB,
    /// infra, outbound-send, self-modification). Evaluated by the hook `pre` lane as a
    /// TIGHTEN-ONLY escalation over the action tier (the exact B4 idiom), with the receipt
    /// vocabulary `kriya.gate.<class>.{evaluated,held,approved,denied}`. Absent `gates:` ⇒ no gate
    /// behavior at all, byte-identical to pre-F2 (the same BC discipline every optional section
    /// above established). The Console's authoring state rides the same YAML under `gates.classes`,
    /// which this struct deliberately does NOT model — serde ignores unknown fields; the compiled
    /// `gates.rules` list is the enforcement truth.
    #[serde(default)]
    gates: Option<GatePolicy>,
    /// Optional **governed LLM lane** policy (`kriya-gateway egress --llm-listen`): what the
    /// plain-HTTP LLM pass-through does on a secret/PII match in a prompt or a reply
    /// (`redact | deny | allow`) and which providers it may forward to. Absent ⇒ the lane runs
    /// with [`LlmPolicy::default`] (redact both directions, both providers) and nothing else in the
    /// engine changes — the same BC discipline every optional section above established.
    #[serde(default)]
    llm: Option<LlmPolicy>,
}

impl Default for Policy {
    fn default() -> Self {
        // Allow writes/creates/edits; deletes need approval; everything else denied.
        Policy {
            rules: vec![
                Rule {
                    action: "create_*".into(),
                    allow: true,
                    require_approval: false,
                },
                Rule {
                    action: "edit_*".into(),
                    allow: true,
                    require_approval: false,
                },
                Rule {
                    action: "delete_*".into(),
                    allow: true,
                    require_approval: true,
                },
                Rule {
                    action: "*".into(),
                    allow: false,
                    require_approval: false,
                },
            ],
            budget: Budget::default(),
            retry: None,
            on_device: false,
            egress: None,
            retention: None,
            detection: None,
            secrets: None,
            a2a: None,
            model: None,
            budgets: None,
            exec: None,
            memory: None,
            temporal: None,
            gates: None,
            llm: None,
        }
    }
}

/// D1: one registered MCP memory tool ({server, tool, op, content_field?}, §D-6 item 5). Mirrors
/// [`crate::memwrite::MemoryOp`]'s `create`/`update`/`delete` vocabulary exactly.
#[derive(Debug, Clone, Deserialize)]
pub struct MemoryRegistryEntry {
    /// The broker namespace (upstream name) this tool is served under.
    pub server: String,
    /// The un-namespaced tool name.
    pub tool: String,
    /// §D-1: `create→write, update→update, delete→delete` (`MemoryOp::verb`).
    pub op: crate::memwrite::MemoryOp,
    /// The argument name carrying the memory content, hashed at emission (§D-3). `None` ⇒ hash
    /// the full canonical `arguments` instead — still content-free either way.
    #[serde(default)]
    pub content_field: Option<String>,
}

impl Policy {
    /// Load from a YAML file, falling back to the safe default if absent/invalid.
    pub fn load_or_default(path: &std::path::Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(text) => serde_yaml::from_str(&text).unwrap_or_else(|_| Policy::default()),
            Err(_) => Policy::default(),
        }
    }

    /// The configured per-minute action cap, if any.
    pub fn max_actions_per_minute(&self) -> Option<u32> {
        self.budget.max_actions_per_minute
    }

    /// The configured per-hour inference/API-call cap, if any.
    pub fn max_api_calls_per_hour(&self) -> Option<u32> {
        self.budget.max_api_calls_per_hour
    }

    /// The retry/backoff policy for transient inference failures (R10). Uses the sane default
    /// when no `retry:` section is configured.
    pub fn retry_policy(&self) -> RetryPolicy {
        self.retry
            .as_ref()
            .map(RetryConfig::to_policy)
            .unwrap_or_default()
    }

    /// Whether the on-device guarantee (R13) is in force for this policy.
    pub fn on_device(&self) -> bool {
        self.on_device
    }

    /// The egress destination tier (doc 24 §7.3), if the policy configures one. `None` → egress
    /// governance is off for this policy and every governed call proceeds unchecked (the io ledger
    /// is likewise silent), byte-identical to pre-EG-2.
    pub fn egress(&self) -> Option<&EgressPolicy> {
        self.egress.as_ref()
    }

    /// The retention design (doc 24 §6-P2), if configured.
    pub fn retention(&self) -> Option<&Retention> {
        self.retention.as_ref()
    }

    /// The detection pack (doc 24 §11 B5–B12 / EG-P), if configured.
    pub fn detection(&self) -> Option<&DetectionPolicy> {
        self.detection.as_ref()
    }

    /// The credential-brokering policy (doc 24 §11 B13 / EG-B), if configured.
    pub fn secrets(&self) -> Option<&crate::secrets::SecretsPolicy> {
        self.secrets.as_ref()
    }

    /// The A2A governance seam (doc 24 §11 B18 / EG-F), if configured. See [`A2aPolicy`]'s doc
    /// comment for why this is a seam, not a wired enforcement point, today.
    pub fn a2a(&self) -> Option<&A2aPolicy> {
        self.a2a.as_ref()
    }

    /// Decide what to do with an RPC call to `target_agent_id` under the A2A seam — `None` when
    /// `a2a:` isn't configured (no opinion, matches every other detector's "absent = off" idiom).
    /// Convenience wrapper so a future call site doesn't need to unwrap `a2a()` itself.
    pub fn evaluate_a2a_target(&self, target_agent_id: &str) -> Option<EgressDecision> {
        self.a2a.as_ref().map(|a| a.evaluate(target_agent_id))
    }

    /// The model-identity gate (F1, doc 28 §F1), if configured. `None` → `kriya-llm-proxy` runs
    /// with [`ModelPolicy::default`] (`unknown_model: warn`) rather than any stricter posture.
    pub fn model(&self) -> Option<&ModelPolicy> {
        self.model.as_ref()
    }

    /// The governed LLM lane policy (`kriya-gateway egress --llm-listen`), if configured. `None` →
    /// the lane applies [`LlmPolicy::default`].
    pub fn llm(&self) -> Option<&LlmPolicy> {
        self.llm.as_ref()
    }

    /// The endpoint budget gate (C2, doc 27 §4), if configured. `None` → the hook `pre` lane
    /// performs no budget consult at all, byte-identical to pre-C2 behaviour.
    pub fn budgets(&self) -> Option<&BudgetPolicy> {
        self.budgets.as_ref()
    }

    /// D1: the registered memory-tool list (doc 27 §4), if configured. `None` → the broker treats
    /// no MCP call as a memory write, byte-identical to pre-D1 behaviour.
    pub fn memory(&self) -> Option<&[MemoryRegistryEntry]> {
        self.memory.as_deref()
    }

    /// D1: look up whether `(server, tool)` is a REGISTERED memory tool (§D-1's honest default —
    /// never a bare name heuristic). `None` when `memory:` is absent or the pair isn't listed.
    pub fn memory_registered_for(&self, server: &str, tool: &str) -> Option<&MemoryRegistryEntry> {
        self.memory.as_ref()?.iter().find(|e| e.server == server && e.tool == tool)
    }

    /// The deterministic-execution lane routing policy (F4-wasm, doc 28 §F4), if configured.
    /// `None` → no action is ever routed to the WASM lane, byte-identical to pre-F4-wasm.
    pub fn exec(&self) -> Option<&ExecPolicy> {
        self.exec.as_ref()
    }

    /// The WASI-p2 component path registered for `action_id`'s deterministic-execution variant,
    /// IF `prefer_deterministic_lane` is on AND a variant is registered — `None` in every other
    /// case (no `exec:` section, the lane is off, or this action has no registered variant), which
    /// is exactly "route to it when a WASM variant is registered; receipted either way" (doc 28
    /// §F4 build spec item 4): whichever path a caller takes, the existing action receipt (or, on
    /// the WASM lane, the `kriya.exec.deterministic` receipt alongside it) still gets emitted —
    /// this method only decides WHICH executor runs, never whether a receipt is signed.
    pub fn resolve_wasm_variant(&self, action_id: &str) -> Option<&str> {
        let exec = self.exec.as_ref()?;
        if !exec.prefer_deterministic_lane {
            return None;
        }
        exec.wasm_variants.get(action_id).map(String::as_str)
    }

    /// B4 (doc 27 §4): the temporal-conditions policy, if configured. `None` → the hook `pre` lane
    /// performs no temporal consult at all, byte-identical to pre-B4 behaviour.
    pub fn temporal(&self) -> Option<&TemporalPolicy> {
        self.temporal.as_ref()
    }

    /// F-2: the action-gate rules, if configured. `None` → the hook `pre` lane performs no gate
    /// consult at all, byte-identical to pre-F2 behaviour.
    pub fn gates(&self) -> Option<&GatePolicy> {
        self.gates.as_ref()
    }

    pub fn check(&self, action_id: &str) -> Decision {
        // B11 (doc 24 §11): a read-only-preset connector's known-mutating tools are denied
        // BEFORE the explicit rules are even consulted — a hard override the operator's own
        // (possibly broad) allow rules can never widen back open. This is the "rides the existing
        // per-action tier" preset: it denies exactly where an explicit rule would, just pre-empted.
        if self
            .detection
            .as_ref()
            .is_some_and(|d| d.read_only_denies(action_id))
        {
            return Decision::Deny;
        }
        for rule in &self.rules {
            if matches(&rule.action, action_id) {
                if !rule.allow {
                    return Decision::Deny;
                }
                return if rule.require_approval {
                    Decision::RequiresApproval
                } else {
                    Decision::Allow
                };
            }
        }
        Decision::Deny
    }

    /// Lint the policy and return any concerns. Surfaced as warn-level logs at run
    /// start so developers notice obviously dangerous configurations early. Empty
    /// vec = clean policy.
    pub fn warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut delete_named_without_approval = Vec::new();

        for (i, rule) in self.rules.iter().enumerate() {
            // Destructive-named patterns that are allowed without human approval.
            if rule.allow && !rule.require_approval && is_destructive_name(&rule.action) {
                delete_named_without_approval.push(format!(
                    "rule #{}: \"{}\" is allowed without human approval — destructive-sounding actions usually want require_approval: true",
                    i + 1,
                    rule.action
                ));
            }

            // Catch-all wildcard that ALLOWS everything is almost always a mistake.
            if rule.action == "*" && rule.allow && !rule.require_approval {
                out.push(format!(
                    "rule #{}: catch-all \"*\" allows every action without approval — this defeats the deny-by-default model",
                    i + 1
                ));
            }
        }

        out.extend(delete_named_without_approval);

        // No catch-all at all → the host already falls through to Deny, but the
        // explicit `- action: "*"` rule documents intent. Recommend it.
        if !self.rules.iter().any(|r| r.action == "*") {
            out.push(
                "policy has no explicit catch-all \"*\" rule — relying on implicit deny. Add an explicit `- action: \"*\"` with `allow: false` so the intent is obvious.".to_string(),
            );
        }

        if self.budget.max_actions_per_minute.is_none() {
            out.push(
                "no budget.max_actions_per_minute is set — an LLM stuck in a loop can hammer your app indefinitely. Recommend a cap (e.g. 60).".to_string(),
            );
        }

        out
    }
}

fn is_destructive_name(pattern: &str) -> bool {
    let p = pattern.to_lowercase();
    const KEYWORDS: &[&str] = &["delete", "remove", "destroy", "drop", "purge", "wipe"];
    KEYWORDS.iter().any(|k| p.contains(k))
}

/// Read-like action-name prefixes the zero-config gateway policy allows outright. Verb-first
/// naming is the MCP convention (`get_account`, `list_transactions`), so a prefix match captures
/// the realistic cases.
pub const READ_PREFIXES: &[&str] = &[
    "get_",
    "list_",
    "read_",
    "fetch_",
    "search_",
    "query_",
    "show_",
    "describe_",
];

/// Destructive / side-effecting action-name prefixes the zero-config gateway policy gates behind
/// human approval. Spend/transfer verbs are here too — a cleared agent can read freely but must be
/// approved before it moves money, sends, or destroys.
pub const DESTRUCTIVE_PREFIXES: &[&str] = &[
    "delete", "remove", "destroy", "drop", "purge", "wipe", "close", "transfer", "send", "pay",
    "archive",
];

/// The zero-config **default deny-by-default policy for the broker** (W2): the same read-allow /
/// destructive-approve / else-deny posture as [`default_proxy_policy`], but the rules are minted
/// **per upstream namespace** — the broker serves tools as `<upstream>__<tool>`, so the flat
/// `get_*` prefixes would never match and would silently deny everything. For each namespace `ns`
/// this emits `ns__get_*`-style allows, `ns__delete*`-style approval gates, then the final
/// catch-all deny. An upstream not in `namespaces` (impossible via the broker, which builds this
/// from its own upstream list) falls to deny — the safe direction.
pub fn default_broker_policy(namespaces: &[String]) -> Policy {
    let mut rules = Vec::new();
    for ns in namespaces {
        for p in READ_PREFIXES {
            rules.push(Rule {
                action: format!("{ns}__{p}*"),
                allow: true,
                require_approval: false,
            });
        }
        for p in DESTRUCTIVE_PREFIXES {
            rules.push(Rule {
                action: format!("{ns}__{p}*"),
                allow: true,
                require_approval: true,
            });
        }
    }
    rules.push(Rule {
        action: "*".into(),
        allow: false,
        require_approval: false,
    });
    Policy {
        rules,
        // One budget spans the whole broker session — all upstreams together, same cap as proxy.
        budget: Budget {
            max_actions_per_minute: Some(60),
            max_api_calls_per_hour: None,
        },
        retry: None,
        on_device: false,
        egress: None,
        retention: None,
        detection: None,
        secrets: None,
        a2a: None,
        model: None,
        budgets: None,
        exec: None,
        memory: None,
        temporal: None,
        gates: None,
        llm: None,
    }
}

/// The zero-config **default deny-by-default policy** the `kriya-gateway proxy` uses when no
/// `--policy` file is given (D-016 / service-architecture §7): read-like names allow, destructive /
/// spend names require human approval, everything else is denied — with a sane per-minute budget so
/// a runaway agent is capped by the proxy. Built from the in-crate [`Rule`]/[`Budget`] structs so it
/// reuses the exact [`Policy::check`] matching the in-process host enforces.
///
/// Matching note: rules are tried in order and use the existing `prefix*` glob, not substring — so
/// `delete_transaction` is gated but a downstream that named the same capability `transaction_delete`
/// would fall through to deny (the safe direction). Operators wanting substring rules pass `--policy`.
pub fn default_proxy_policy() -> Policy {
    let mut rules = Vec::new();
    // Reads first (most permissive, but only for read-shaped names).
    for p in READ_PREFIXES {
        rules.push(Rule {
            action: format!("{p}*"),
            allow: true,
            require_approval: false,
        });
    }
    // Destructive / spend names: allowed only after explicit human approval.
    for p in DESTRUCTIVE_PREFIXES {
        rules.push(Rule {
            action: format!("{p}*"),
            allow: true,
            require_approval: true,
        });
    }
    // Everything else: deny by default (defense in depth — `check` also denies on no match).
    rules.push(Rule {
        action: "*".into(),
        allow: false,
        require_approval: false,
    });

    Policy {
        rules,
        // Cap a runaway agent: the proxy IS the handler from the budget's view, so this spans the
        // whole session's downstream calls.
        budget: Budget {
            max_actions_per_minute: Some(60),
            max_api_calls_per_hour: None,
        },
        retry: None,
        on_device: false,
        egress: None,
        retention: None,
        detection: None,
        secrets: None,
        a2a: None,
        model: None,
        budgets: None,
        exec: None,
        memory: None,
        temporal: None,
        gates: None,
        llm: None,
    }
}

fn matches(pattern: &str, action_id: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return action_id.starts_with(prefix);
    }
    pattern == action_id
}

// ─── Egress destination tier (doc 24 §7.3 / EG-2) ────────────────────────────────────────────────
//
// Operators author **human-readable host patterns** in the policy YAML (decided in doc 24 §7.3 — do
// not revisit):
//
// ```yaml
// egress:
//   unlisted: deny            # deny-by-default (default: allow — the permissive posture §7.3)
//   fail_closed: true         # "no receipt, no egress" (B3); default false
//   rules:
//     - host: "*.vendor.com"
//       tier: allow
//       budget: { window_secs: 60, max_bytes: 1048576 }
//     - host: "api.partner.com"
//       tier: approval
//     - host: "*"
//       tier: deny
// ```
//
// **Landmine L1 (permissions.rs `matches()` is PREFIX-only):** a host wildcard is a *leading* `*.`
// (a suffix match on the domain), so feeding `*.notion.com` to the action matcher would strip the
// trailing char (there is none to strip) and fall through to an exact compare — silently never
// matching. Egress matching therefore uses [`host_matches`], a dedicated suffix matcher; the
// reversed-host encoding named in doc 24 §7.3/L1 is one valid way to reuse `matches()`, a direct
// suffix matcher is another — either way the L1 silent-fail case is proven impossible by the test
// matrix below. Operators never see or write reversed hosts.

/// One egress destination rule as authored in the policy YAML.
#[derive(Debug, Clone, Deserialize)]
struct EgressRule {
    /// A human-readable host pattern: `*` (any), `*.vendor.com` (the vendor.com domain — its
    /// subdomains and the apex), or an exact host `api.vendor.com`.
    host: String,
    /// What to do with a call to this destination. Default `allow` (listing a host without a tier
    /// means "allow it").
    #[serde(default = "default_tier")]
    tier: EgressTier,
    /// Optional per-destination byte budget (B2 — anti slow-drip exfil). Observed *payload* bytes
    /// (L2), never wire/TLS bytes.
    #[serde(default)]
    budget: Option<ByteBudget>,
}

fn default_tier() -> EgressTier {
    EgressTier::Allow
}

/// The three egress tiers — the same three the action policy already has, applied by destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EgressTier {
    Allow,
    Approval,
    Deny,
}

/// A per-destination byte budget: no more than `max_bytes` of observed outbound payload in any
/// trailing `window_secs` window. Exceeding it denies the call that would breach — a signed
/// `kriya.io.*.deny` receipt, not a silent drop (B2).
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct ByteBudget {
    pub window_secs: u64,
    pub max_bytes: u64,
}

/// What happens to a host no rule matches. `deny` is deny-by-default (the safe allowlist posture,
/// which also arms the broker's startup allowlist check); `allow` is the permissive default §7.3
/// documents as a "documented deviation" printed in every export; `defer` parks the unlisted call
/// at the approval gate instead of hard-denying it (B4 defer semantics).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UnlistedPosture {
    #[default]
    Allow,
    Deny,
    Defer,
}

/// The compiled egress tier for a policy. Deserialized from the policy YAML's `egress:` section.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct EgressPolicy {
    #[serde(default)]
    rules: Vec<EgressRule>,
    /// The posture for a host no rule matches. Default `allow` (§7.3 — the tier ships OFF/permissive
    /// and every export prints the mode); set `deny` for deny-by-default.
    #[serde(default)]
    unlisted: UnlistedPosture,
    /// Fail-closed receipt-precondition mode (B3): if the `kriya.io.*` receipt cannot be written,
    /// the egress is DENIED. Default `false` (fail-open — the honest documented default).
    #[serde(default)]
    fail_closed: bool,
    /// Whether to record **ingress** digests (a keyed hash + size of tool responses / inbound
    /// content). Its OWN switch, **default OFF even when egress is ON** (doc 24 §6-P3): computing a
    /// hash reads every content byte, which is a processing activity in its own right, and an
    /// unsalted hash of guessable content is content disclosure — so ingress hashing is keyed
    /// (HMAC) and off unless the operator opts in.
    #[serde(default)]
    record_ingress: bool,
}

/// The outcome of evaluating one destination against the egress tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressDecision {
    /// Proceed. `rule` is the operator-authored pattern that matched (for the `policy_rule` param),
    /// `None` for the permissive-unlisted case.
    Allow { rule: Option<String> },
    /// Route through the approval gate (an `approval`-tier host, or `defer` on an unlisted host).
    Approval { rule: Option<String> },
    /// Block at the decision point. `reason` is human-readable for the receipt + the agent.
    Deny {
        rule: Option<String>,
        reason: String,
    },
}

impl EgressPolicy {
    /// Decide what to do with a call to `host` (already lowercased/trimmed is fine — the matcher
    /// normalizes). First matching rule wins; an unmatched host falls to the `unlisted` posture.
    pub fn evaluate(&self, host: &str) -> EgressDecision {
        for r in &self.rules {
            if host_matches(&r.host, host) {
                return match r.tier {
                    EgressTier::Allow => EgressDecision::Allow {
                        rule: Some(r.host.clone()),
                    },
                    EgressTier::Approval => EgressDecision::Approval {
                        rule: Some(r.host.clone()),
                    },
                    EgressTier::Deny => EgressDecision::Deny {
                        rule: Some(r.host.clone()),
                        reason: format!("egress to {host} denied by rule '{}'", r.host),
                    },
                };
            }
        }
        match self.unlisted {
            UnlistedPosture::Allow => EgressDecision::Allow { rule: None },
            UnlistedPosture::Deny => EgressDecision::Deny {
                rule: None,
                reason: format!("egress to {host} is not on the allowlist (deny-by-default)"),
            },
            UnlistedPosture::Defer => EgressDecision::Approval { rule: None },
        }
    }

    /// The byte budget in force for `host`, plus the pattern that carries it (the budget-counter
    /// key). The first matching rule that declares a `budget:` wins.
    pub fn budget_for(&self, host: &str) -> Option<(String, ByteBudget)> {
        self.rules
            .iter()
            .find(|r| host_matches(&r.host, host) && r.budget.is_some())
            .map(|r| (r.host.clone(), r.budget.expect("is_some checked")))
    }

    /// Whether fail-closed receipt-precondition mode (B3) is on.
    pub fn fail_closed(&self) -> bool {
        self.fail_closed
    }

    /// Whether ingress digest recording is on (its own switch, default OFF — doc 24 §6-P3).
    pub fn record_ingress(&self) -> bool {
        self.record_ingress
    }

    /// A short, export-safe label for the posture — printed in every egress-bearing export so an
    /// assessor's first question ("was the ledger permissive during the window?") is answered
    /// before it is asked (§6-H10).
    pub fn mode_label(&self) -> &'static str {
        match self.unlisted {
            UnlistedPosture::Allow => "allow-unlisted",
            UnlistedPosture::Deny => "deny-by-default",
            UnlistedPosture::Defer => "defer-unlisted",
        }
    }

    /// Whether the tier is deny-by-default (arms the broker startup allowlist check).
    pub fn is_deny_by_default(&self) -> bool {
        self.unlisted == UnlistedPosture::Deny
    }
}

// ─── A2A (agent-to-agent) governance seam (doc 24 §11 B18 / EG-F) ─────────────────────────────────
//
// ROADMAP-DEPTH: thin until real agent-to-agent traffic exists. There is no A2A transport in this
// codebase today (the broker in `kriya-gateway` aggregates MCP upstreams, not other agents; the
// `agent/` module drives one app, not a peer agent) — so nothing calls `A2aPolicy::evaluate` yet.
// This exists so that WHEN an A2A lane is built, it reuses the exact allowlist/tier engine
// `EgressPolicy` already has (rules -> tier, unlisted posture) instead of inventing a second
// allowlist DSL, and so it emits the SAME `kriya.io.*` receipt vocabulary (no new action_id shape)
// once it exists — "apply the same allowlist/receipt path" per doc 24 §11's build item.

/// The A2A destination allowlist, keyed by target agent id instead of network host. `#[serde(flatten)]`
/// so `a2a:` in the policy YAML has the IDENTICAL shape as `egress:` (`rules: [{host, tier, budget?}]`,
/// `unlisted`, `fail_closed`, `record_ingress`) — `host` is read as an agent-id pattern here, reusing
/// `EgressPolicy`'s exact matcher (`*`, `*.suffix`, exact) rather than a bespoke agent-id grammar.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct A2aPolicy {
    #[serde(flatten)]
    allowlist: EgressPolicy,
}

impl A2aPolicy {
    /// Decide what to do with an RPC call to `target_agent_id` — identical decision shape to
    /// [`EgressPolicy::evaluate`], just evaluated over an agent id instead of a host.
    pub fn evaluate(&self, target_agent_id: &str) -> EgressDecision {
        self.allowlist.evaluate(target_agent_id)
    }
}

// ─── Model-identity gate (F1, doc 28 §F1 / FRONTIER-EXECUTE-PROMPT.md §2 · §3 F1) ─────────────────
//
// `kriya-llm-proxy`'s policy dimension: gate a served completion on the RESOLVED digest of the
// model that served it (never the model's self-reported name alone — a name is not an identity).
// Deliberately NOT `EgressPolicy` reused wholesale, because the default posture differs on purpose:
// egress is deny-by-default-capable: an operator-authored destination allowlist; this is
// **observation-first** (doc 24 §11.5 — "enforcement verbs only where enforcement is real"): an
// unrecognized LOCAL model never blocks by default, it only WARNS — via an explicit, signed
// `kriya.model.gate` warn receipt, not silence — until the operator opts into `require-approval` or
// `deny`. The per-digest `approved` allowlist DOES reuse [`EgressTier`] (the same allow/approval/deny
// space an operator already knows from `egress:`), so authoring a specific digest's tier is the
// familiar idiom; only the *default-for-everything-else* posture (`unknown_model`) is a new type.

/// One approved model-identity rule: a resolved digest → tier. Mirrors an [`EgressRule`]'s shape
/// (`host` → `digest`), reusing [`EgressTier`]'s allow/approval/deny space.
#[derive(Debug, Clone, Deserialize)]
pub struct ApprovedModelRule {
    /// The resolved model digest (sha256 hex, no `sha256:` prefix) this rule matches exactly.
    pub digest: String,
    #[serde(default = "default_model_tier")]
    pub tier: EgressTier,
    /// Cosmetic-only human label (e.g. `"llama3.1:8b (verified 2026-07-24)"`) — never read by
    /// [`ModelPolicy::evaluate`], carried only for the Console's display.
    #[serde(default)]
    pub label: Option<String>,
}

fn default_model_tier() -> EgressTier {
    EgressTier::Allow
}

/// What happens to a served completion whose model digest matches no [`ApprovedModelRule`] —
/// covering BOTH a resolved-but-unlisted digest and a digest the `llm-proxy` feature's manifest
/// resolver couldn't resolve at all. Default `warn`: the fail-OPEN posture the F1 build spec
/// requires — an unrecognized model is disclosed, never silently blocked, unless the operator
/// explicitly opts into stricter enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnknownModelAction {
    #[default]
    Warn,
    RequireApproval,
    Deny,
}

/// The compiled model-identity policy for `kriya-llm-proxy`. Deserialized from the SAME
/// `agent-policy.yaml` every other governed binary loads, under an optional `model:` key —
/// `#[serde(default)]`'d on [`Policy`] so an agent-policy.yaml that never authored one round-trips
/// unchanged (the same BC discipline `egress`/`detection`/`secrets` already established).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ModelPolicy {
    #[serde(default)]
    pub approved: Vec<ApprovedModelRule>,
    #[serde(default)]
    pub unknown_model: UnknownModelAction,
}

/// The outcome of gating one served completion by model identity. Distinct from [`EgressDecision`]
/// because an unmatched digest WARNS by default rather than denies — see the module note above.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelGateDecision {
    /// Proceed, no further comment. `rule` is the approved digest that matched (`None` only when
    /// [`ModelPolicy::evaluate`] is called directly with an empty policy — practically unreachable
    /// since an empty policy's `unknown_model` default is `Warn`, never `Allow`).
    Allow { rule: Option<String> },
    /// Proceed, but disclose: the observation-first default for an unrecognized model.
    Warn { reason: String },
    /// No synchronous approval channel exists in the v1 proxy (same honest limitation as
    /// `mcp::contain`'s CONNECT tunnel) — refused, never silently allowed nor hung.
    Approval { reason: String },
    /// Block. `rule` is the specific approved-list digest that matched a `deny` tier (`None` for
    /// the `unknown_model: deny` default path).
    Deny {
        rule: Option<String>,
        reason: String,
    },
}

impl ModelGateDecision {
    /// The `decision` facet carried into the `kriya.model.gate` receipt — one of the four closed
    /// values (never a fifth, same discipline as [`IoDecision::facet`](crate::mcp::executor::IoDecision)).
    pub fn facet(&self) -> &'static str {
        match self {
            ModelGateDecision::Allow { .. } => "allow",
            ModelGateDecision::Warn { .. } => "warn",
            ModelGateDecision::Approval { .. } => "approval_required",
            ModelGateDecision::Deny { .. } => "deny",
        }
    }

    /// The approved-list digest that matched, if any (for the receipt's `matched_rule`).
    pub fn matched_rule(&self) -> Option<&str> {
        match self {
            ModelGateDecision::Allow { rule } | ModelGateDecision::Deny { rule, .. } => {
                rule.as_deref()
            }
            ModelGateDecision::Warn { .. } | ModelGateDecision::Approval { .. } => None,
        }
    }

    /// The human-readable reason (for the receipt's `reason` and the proxy's error body on refusal).
    pub fn reason(&self) -> String {
        match self {
            ModelGateDecision::Allow { rule: Some(r) } => {
                format!("model digest {r} is on the approved allowlist")
            }
            ModelGateDecision::Allow { rule: None } => "no model policy configured".to_string(),
            ModelGateDecision::Warn { reason }
            | ModelGateDecision::Approval { reason }
            | ModelGateDecision::Deny { reason, .. } => reason.clone(),
        }
    }

    /// Whether this decision blocks the request. Only `Approval` (no sync approval channel in v1 —
    /// refused honestly rather than hung or silently allowed) and `Deny` block; `Allow`/`Warn` never
    /// do — the fail-OPEN default the F1 spec requires.
    pub fn blocks(&self) -> bool {
        matches!(
            self,
            ModelGateDecision::Approval { .. } | ModelGateDecision::Deny { .. }
        )
    }
}

impl ModelPolicy {
    /// Decide what to do with a completion served by the model whose resolved digest is `digest`
    /// (`None` when [`crate::llm::manifest`] couldn't resolve one — treated exactly like a
    /// resolved-but-unlisted digest: the `unknown_model` default applies).
    pub fn evaluate(&self, digest: Option<&str>) -> ModelGateDecision {
        if let Some(d) = digest {
            if let Some(rule) = self.approved.iter().find(|r| r.digest == d) {
                return match rule.tier {
                    EgressTier::Allow => ModelGateDecision::Allow {
                        rule: Some(rule.digest.clone()),
                    },
                    EgressTier::Approval => ModelGateDecision::Approval {
                        reason: format!("model digest {d} is approval-tier by policy"),
                    },
                    EgressTier::Deny => ModelGateDecision::Deny {
                        rule: Some(rule.digest.clone()),
                        reason: format!("model digest {d} is denied by policy"),
                    },
                };
            }
        }
        match self.unknown_model {
            UnknownModelAction::Warn => ModelGateDecision::Warn {
                reason: "model digest is not on the approved allowlist (observation-only default \
                         — set unknown_model: require-approval or deny to enforce)"
                    .to_string(),
            },
            UnknownModelAction::RequireApproval => ModelGateDecision::Approval {
                reason: "unapproved model requires approval by policy".to_string(),
            },
            UnknownModelAction::Deny => ModelGateDecision::Deny {
                rule: None,
                reason: "unapproved model denied by policy".to_string(),
            },
        }
    }
}

// ─── F4-wasm (doc 28 §F4): deterministic-execution lane routing ──────────────────────────────
//
// Deliberately the SIMPLEST policy shape in this file: no tiers, no allow/approval/deny space —
// this is a ROUTING decision (which executor runs a cleared action), not a NEW gate. The action
// still goes through `Policy::check` exactly as before; a registered WASM variant only changes
// HOW an already-allowed action executes, and either path signs a receipt (the normal action
// receipt, or that PLUS `kriya.exec.deterministic` on the WASM lane) — see
// `Policy::resolve_wasm_variant`.

/// The deterministic-execution lane routing policy (F4-wasm). Deserialized from the SAME
/// `agent-policy.yaml` every other governed binary loads, under an optional `exec:` key.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ExecPolicy {
    /// The tier switch (doc 28 §F4 build spec item 4: "a tier option 'prefer deterministic
    /// lane'"). `false` (default) → `wasm_variants` is inert even if populated, so authoring the
    /// registry ahead of flipping this on is safe (no surprise routing change from an
    /// otherwise-unrelated edit).
    #[serde(default)]
    pub prefer_deterministic_lane: bool,
    /// `action_id` → path to a WASI-p2 component implementing the SAME action, built for
    /// `kriya-run-wasm`. An action with no entry here never routes to the WASM lane regardless of
    /// `prefer_deterministic_lane`.
    #[serde(default)]
    pub wasm_variants: std::collections::BTreeMap<String, String>,
}

/// Match an operator-authored **host pattern** against a concrete host — the internal compile
/// detail that maps human-readable patterns onto matching without the L1 prefix-only trap.
///
/// - `*` → any host
/// - `*.vendor.com` → the vendor.com domain: any subdomain (`a.vendor.com`, `a.b.vendor.com`) and the apex (`vendor.com`)
/// - `api.vendor.com` → exact match only
///
/// Case-insensitive; leading/trailing whitespace ignored. Unlike the action [`matches`] (prefix
/// glob only), a leading `*.` is a genuine suffix match — the exact case L1 warns silently fails
/// under the action matcher.
pub(crate) fn host_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim().to_ascii_lowercase();
    let host = host.trim().to_ascii_lowercase();
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // The vendor.com domain: subdomains AND the apex. An empty suffix ("*.") is malformed → no
        // match rather than matching everything.
        return !suffix.is_empty() && (host == suffix || host.ends_with(&format!(".{suffix}")));
    }
    pattern == host
}

/// Extract the host from an upstream/tool URL without pulling in a URL-parsing dependency. Shared
/// by the HTTP transport (the captured `dest_host`), the broker's egress resolver, and the hook's
/// WebFetch lane, so the ledger and the allowlist agree on the destination string. Lives here (an
/// always-compiled module) so the hook — built without `mcp-client` — can reach it too.
/// `https://user@api.vendor.com:443/mcp` → `api.vendor.com`.
pub fn url_host(url: &str) -> String {
    let after_scheme = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    let host_port = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    // Strip the port. IPv6 literals (`[::1]:port`) keep their brackets' contents; the common
    // hostname/IPv4 case splits on the first colon.
    if let Some(stripped) = host_port.strip_prefix('[') {
        return stripped.split(']').next().unwrap_or(stripped).to_string();
    }
    host_port
        .split(':')
        .next()
        .unwrap_or(host_port)
        .to_ascii_lowercase()
}

/// The **retention design** (doc 24 §6-P2): the max-age classes a retention pruner honours before
/// sealing the pruned prefix behind a signed epoch-checkpoint receipt (see
/// [`crate::audit::RETENTION_CHECKPOINT`]). `kriya.io.*` receipts get a **shorter** default class
/// than policy/approval receipts — I/O metadata is the most privacy-sensitive and least
/// evidence-durable class (§4.5). Both fields optional; absent → that class is retained
/// indefinitely.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Retention {
    /// Max age in days for `kriya.io.*` receipts. Shorter than [`Self::default_days`] by design.
    #[serde(default)]
    pub io_days: Option<u32>,
    /// Max age in days for policy/approval/action receipts.
    #[serde(default)]
    pub default_days: Option<u32>,
}

// ─── Detection pack (doc 24 §11 B5–B12 / EG-P) ───────────────────────────────────────────────────
//
// Every sub-detector is independently `Option`-gated and absent by default, so opting a policy into
// `detection:` at all never silently turns on a specific check — each one is a deliberate, separate
// operator choice (never auto-block silently by default). All detectors run on GOVERNED LANES only
// (the same seams the egress tier already gates); a spawned subprocess bypasses them exactly as it
// bypasses the egress tier itself — this is not a host boundary. Detection findings are additive
// receipt params on the SAME `kriya.io.*` vocabulary (never a new action_id shape): an "alert" is a
// call that still executes but whose io receipt carries an extra flag field; a "deny" is a real
// decision-point block with `decision: "deny"` and a `reason` naming the detector, mirroring the
// egress tier's own L10 discipline.

fn default_true() -> bool {
    true
}

/// What a detector does on a match: proceed but flag it (never blocks a legitimate call on its
/// own), or block outright. Default `Alert` — the house rule for every heuristic that can
/// false-positive (doc 24 §11's "never auto-block silently by default").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertOrDeny {
    #[default]
    Alert,
    Deny,
}

/// What a content-match detector (secret/PII) does: keep the call fidelity intact but strip the
/// matched value from what's hashed/recorded (default — safe, non-breaking), or block outright.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RedactOrDeny {
    #[default]
    Redact,
    Deny,
}

/// The detection pack. Every field is independently optional; only configured detectors run.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct DetectionPolicy {
    /// B5: DNS-exfil / anomalous-destination / subdomain-entropy heuristic.
    #[serde(default)]
    pub dns_exfil: Option<DnsExfilPolicy>,
    /// B6: SSRF / private-IP / cloud-metadata / DNS-rebinding guard.
    #[serde(default)]
    pub ssrf_guard: Option<SsrfGuardPolicy>,
    /// B7: secret + PII scan/redact on outbound governed bodies.
    #[serde(default)]
    pub secret_pii: Option<SecretPiiPolicy>,
    /// B8: operation rails — allow/deny specific outbound API operations, not just hosts.
    #[serde(default)]
    pub operation_rails: Vec<OperationRail>,
    /// B9: canary tokens — an exact-match string whose appearance in an outbound body is always an
    /// immediate deny, never policy-tunable (that is the entire point of a canary).
    #[serde(default)]
    pub canary_tokens: Vec<String>,
    /// B10: the connector registry — new/drifted MCP tools default disabled-until-approved.
    #[serde(default)]
    pub connector_registry: Option<ConnectorRegistryPolicy>,
    /// B11: per-connector/per-tool read-only presets — host/namespace patterns (egress
    /// [`host_matches`] syntax) whose known-mutating tools are denied.
    #[serde(default)]
    pub read_only: Vec<String>,
    /// B12: MCP response enforcement — per-server trust classes on governed-lane ingress.
    #[serde(default)]
    pub mcp_response: Option<McpResponsePolicy>,
}

/// B5: flag destinations whose leftmost subdomain label has unusually high character entropy (the
/// classic DNS-exfiltration shape: stolen data base32/hex/base64-encoded into a subdomain of an
/// otherwise-allowed domain). This is a HEURISTIC on top of the egress tier's own allow/deny — it
/// exists to catch abuse of an *already-allowed* wildcard domain, not to replace the allowlist.
#[derive(Debug, Clone, Deserialize)]
pub struct DnsExfilPolicy {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Shannon-entropy threshold in bits/char above which a subdomain label is flagged. Ordinary
    /// hostnames score roughly 2.5–3.5; base32/hex-encoded exfil payloads commonly score 3.8+.
    /// Default chosen conservatively high to minimize false positives on legitimate CDN/hash-named
    /// subdomains (see the false-positive-safety test).
    #[serde(default = "default_entropy_threshold")]
    pub entropy_threshold: f64,
    #[serde(default)]
    pub action: AlertOrDeny,
}

fn default_entropy_threshold() -> f64 {
    4.0
}

/// Shannon entropy in bits/character of `s`, over its raw bytes. A hostname label is ASCII (or
/// punycode-encoded at the wire level for IDN, which is itself a high-entropy string and correctly
/// flagged), so byte-level entropy is the right granularity. Strings under 2 bytes score 0.0 — too
/// short for a meaningful character distribution either way.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.len() < 2 {
        return 0.0;
    }
    let mut counts: std::collections::HashMap<u8, u32> = std::collections::HashMap::new();
    for b in s.bytes() {
        *counts.entry(b).or_insert(0) += 1;
    }
    let len = s.len() as f64;
    -counts
        .values()
        .map(|&c| {
            let p = c as f64 / len;
            p * p.log2()
        })
        .sum::<f64>()
}

/// The highest per-label Shannon entropy among `host`'s SUBDOMAIN labels — every label except the
/// trailing two (assumed to be the registrable apex domain + TLD, e.g. `vendor`/`com`), since that
/// pair is the operator-allowlisted destination itself, not an attacker-controlled position.
/// Exfiltration tools commonly chunk encoded data across multiple labels (DNS's 63-byte label
/// limit), so this checks ALL of them and returns the max, not just the leftmost. `None` for a host
/// with fewer than 3 labels — an apex or single-label host has no subdomain to inspect at all.
pub fn max_subdomain_entropy(host: &str) -> Option<f64> {
    let labels: Vec<&str> = host.trim().trim_end_matches('.').split('.').collect();
    if labels.len() < 3 {
        return None;
    }
    labels[..labels.len() - 2]
        .iter()
        .map(|l| shannon_entropy(l))
        .fold(None, |acc: Option<f64>, e| {
            Some(acc.map_or(e, |a| a.max(e)))
        })
}

/// B6: reject private/link-local/cloud-metadata destinations and pin the resolved IP for the
/// connection so a rebind between the check and the connect can't swap in a different address. This
/// is a real security control, not a tunable heuristic — the only dial is whether it's on.
///
/// That one dial governs BOTH layers together: the GOVERNOR-level pre-check (a forbidden destination
/// gets a clean, policy-attributed pre-execute `kriya.io.*.deny` receipt) AND the HTTP transport's IP
/// pin (`mcp::client::HttpTransport`, the actually TOCTOU-proof enforcement). Gated, not
/// unconditional: a local dev/test upstream on `127.0.0.1`/`localhost` is a legitimate `url:`
/// target — this is real, not hypothetical, an existing broker integration test connects to one — so
/// pinning away from loopback by default would have real legitimate-traffic cost, unlike (say)
/// refusing the cloud metadata endpoint. Same house rule as every other detector in the pack (doc 24
/// §11's "never auto-block silently by default"): absent `detection.ssrf_guard`, both layers are off.
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct SsrfGuardPolicy {
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// B6 core validator: why `ip` is a forbidden SSRF/rebinding target, or `None` if it's an ordinary
/// routable address. Covers loopback, RFC1918 private ranges, link-local (which subsumes the cloud
/// metadata endpoint `169.254.169.254` — it lives inside `169.254.0.0/16`), unspecified, broadcast,
/// IPv6 unique-local (`fc00::/7`) and link-local (`fe80::/10`), and IPv4-mapped IPv6 addresses
/// (checked against the same IPv4 rules after unwrapping). Used both by the governor's pre-check
/// (clean receipts) and the transport's resolver pin (actual enforcement) so the two layers can
/// never disagree about what's forbidden.
pub fn ssrf_disallowed_reason(ip: std::net::IpAddr) -> Option<&'static str> {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                Some("loopback (127.0.0.0/8)")
            } else if v4.is_private() {
                Some("RFC1918 private range")
            } else if v4.is_link_local() {
                Some("link-local (169.254.0.0/16, includes the cloud metadata endpoint)")
            } else if v4.is_unspecified() {
                Some("unspecified (0.0.0.0)")
            } else if v4.is_broadcast() {
                Some("broadcast (255.255.255.255)")
            } else {
                None
            }
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return ssrf_disallowed_reason(IpAddr::V4(v4));
            }
            let seg0 = v6.segments()[0];
            if v6.is_loopback() {
                Some("loopback (::1)")
            } else if v6.is_unspecified() {
                Some("unspecified (::)")
            } else if seg0 & 0xfe00 == 0xfc00 {
                Some("unique-local (fc00::/7)")
            } else if seg0 & 0xffc0 == 0xfe80 {
                Some("link-local (fe80::/10)")
            } else {
                None
            }
        }
    }
}

/// B7: scan outbound governed bodies for a closed set of secret/PII shapes. On a match, either
/// redact (record the match TYPE + a content hash only, never the value) or deny.
#[derive(Debug, Clone, Deserialize)]
pub struct SecretPiiPolicy {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub action: RedactOrDeny,
}

/// What the governed LLM lane does when the secret/PII detector matches a prompt (`request`) or a
/// model reply (`response`). Unlike the tool lane's [`RedactOrDeny`] — where `redact` is
/// receipt-side only — `redact` here REWRITES the matched text to `[REDACTED <type>]` before the
/// body leaves the gateway. `allow` forwards unchanged and only records the match types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LlmContentAction {
    #[default]
    Redact,
    Deny,
    Allow,
}

impl LlmContentAction {
    pub fn as_str(self) -> &'static str {
        match self {
            LlmContentAction::Redact => "redact",
            LlmContentAction::Deny => "deny",
            LlmContentAction::Allow => "allow",
        }
    }
}

/// An upstream LLM API family the governed LLM lane can forward to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LlmProvider {
    Openai,
    Anthropic,
}

impl LlmProvider {
    pub fn as_str(self) -> &'static str {
        match self {
            LlmProvider::Openai => "openai",
            LlmProvider::Anthropic => "anthropic",
        }
    }
}

fn default_llm_providers() -> Vec<LlmProvider> {
    vec![LlmProvider::Openai, LlmProvider::Anthropic]
}

/// The optional `llm:` policy section for `kriya-gateway egress --llm-listen`. Every key is
/// optional; an unknown key or value is a parse error (a typo in a redaction posture must never
/// silently fall back). `detection.canary_tokens` are always-deny in both directions regardless of
/// this section.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LlmPolicy {
    #[serde(default)]
    pub request: LlmContentAction,
    #[serde(default)]
    pub response: LlmContentAction,
    #[serde(default = "default_llm_providers")]
    pub providers: Vec<LlmProvider>,
}

impl Default for LlmPolicy {
    fn default() -> Self {
        LlmPolicy {
            request: LlmContentAction::default(),
            response: LlmContentAction::default(),
            providers: default_llm_providers(),
        }
    }
}

impl LlmPolicy {
    pub fn allows_provider(&self, p: LlmProvider) -> bool {
        self.providers.contains(&p)
    }
}

/// B7 scan: which secret/PII shapes matched `payload` (the canonical-JSON outbound body), by TYPE
/// name only. Byte-level scanning throughout (never a `&str` slice at an arbitrary offset) so this
/// can never panic on attacker-controlled UTF-8 — every helper below only ever compares/indexes
/// `&[u8]`. The matched substring itself is never extracted or returned: a caller has structurally
/// nothing to leak into a flag or a "redact" — the value never leaves this function (doc 24 L9's
/// hash-only rule, applied here as *no value at all*, not even hashed).
pub fn scan_secrets_pii(payload: &str) -> Vec<&'static str> {
    let b = payload.as_bytes();
    DETECTORS
        .iter()
        .filter(|(_, spans)| !spans(b).is_empty())
        .map(|(name, _)| *name)
        .collect()
}

/// B7 scan, span-reporting form: every secret/PII match in `payload` as `(byte range, type)`,
/// sorted by start offset. Same matchers as [`scan_secrets_pii`] (that function is exactly "the
/// distinct types this returns, in detector order"). Ranges always start on an ASCII byte and end
/// just after one, so they are valid `str` char boundaries; ranges of different types may overlap
/// (a caller rewriting text should merge them). Used by the governed LLM lane to rewrite matched
/// text to `[REDACTED <type>]` before a body leaves — the one place a range is ever needed; the
/// matched value itself is still never copied out of the caller's buffer here.
pub fn scan_secrets_pii_spans(payload: &str) -> Vec<(std::ops::Range<usize>, &'static str)> {
    let b = payload.as_bytes();
    let mut out: Vec<(std::ops::Range<usize>, &'static str)> = DETECTORS
        .iter()
        .flat_map(|(name, spans)| spans(b).into_iter().map(move |r| (r, *name)))
        .collect();
    out.sort_by_key(|(r, _)| (r.start, r.end));
    out
}

type SpanFn = fn(&[u8]) -> Vec<std::ops::Range<usize>>;

/// The closed detector set, in reporting order. Each entry reports byte ranges; the boolean
/// [`scan_secrets_pii`] is "any range at all".
const DETECTORS: &[(&str, SpanFn)] = &[
    ("aws_access_key", |b| {
        fixed_prefix_token_spans(b, b"AKIA", 16, is_upper_alnum)
    }),
    ("github_pat", |b| fixed_prefix_token_spans(b, b"ghp_", 36, is_alnum)),
    ("jwt", jwt_spans),
    ("private_key", private_key_spans),
    ("email", email_spans),
    ("credit_card", card_spans),
    ("ssn", ssn_spans),
    ("aadhaar", aadhaar_spans),
    ("pan_in", pan_in_spans),
];

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    find_from(hay, needle, 0).is_some()
}

/// First index `>= from` where `needle` occurs in `hay`.
fn find_from(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from >= hay.len() || hay.len() - from < needle.len() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

fn is_upper_alnum(c: u8) -> bool {
    c.is_ascii_uppercase() || c.is_ascii_digit()
}

fn is_alnum(c: u8) -> bool {
    c.is_ascii_alphanumeric()
}

/// Every place `prefix` appears in `b` followed immediately by at least `tail_len` bytes all
/// satisfying `tail_ok` (e.g. an AWS key: `AKIA` + 16 upper-alnum chars). The match condition is
/// "exactly `tail_len` qualifying bytes follow"; the reported range extends over any further
/// qualifying bytes so a rewrite never leaves a tail of the token behind.
fn fixed_prefix_token_spans(
    b: &[u8],
    prefix: &[u8],
    tail_len: usize,
    tail_ok: fn(u8) -> bool,
) -> Vec<std::ops::Range<usize>> {
    let plen = prefix.len();
    let mut out = Vec::new();
    if b.len() < plen + tail_len {
        return out;
    }
    let mut i = 0;
    while i + plen + tail_len <= b.len() {
        if &b[i..i + plen] == prefix
            && b[i + plen..i + plen + tail_len]
                .iter()
                .copied()
                .all(tail_ok)
        {
            let end = walk_while(b, i + plen + tail_len, tail_ok);
            out.push(i..end);
            i = end;
        } else {
            i += 1;
        }
    }
    out
}

fn is_b64url(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'-'
}

/// A JWT: three dot-separated base64url segments, the first starting `eyJ` (base64 for `{"`) — a
/// strong anchor that keeps this from firing on an ordinary dotted token or version string. Minimum
/// segment lengths are conservative (a real header/payload/signature are all comfortably longer).
fn jwt_spans(b: &[u8]) -> Vec<std::ops::Range<usize>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 3 <= b.len() {
        if &b[i..i + 3] == b"eyJ" {
            let seg1_end = walk_while(b, i, is_b64url);
            if seg1_end >= i + 10 && b.get(seg1_end) == Some(&b'.') {
                let seg2_start = seg1_end + 1;
                let seg2_end = walk_while(b, seg2_start, is_b64url);
                if seg2_end >= seg2_start + 10 && b.get(seg2_end) == Some(&b'.') {
                    let seg3_start = seg2_end + 1;
                    let seg3_end = walk_while(b, seg3_start, is_b64url);
                    if seg3_end >= seg3_start + 5 {
                        out.push(i..seg3_end);
                        i = seg3_end;
                        continue;
                    }
                }
            }
        }
        i += 1;
    }
    out
}

/// A PEM private key: the payload carries both `-----BEGIN` and `PRIVATE KEY` (the original
/// boolean rule). Each `-----BEGIN` block is reported from its marker through the closing
/// `-----END …-----` line, or to the end of the payload when the block is unterminated.
fn private_key_spans(b: &[u8]) -> Vec<std::ops::Range<usize>> {
    let mut out = Vec::new();
    if !(contains(b, b"-----BEGIN") && contains(b, b"PRIVATE KEY")) {
        return out;
    }
    let mut from = 0;
    while let Some(start) = find_from(b, b"-----BEGIN", from) {
        let end = match find_from(b, b"-----END", start + 10) {
            Some(e) => match find_from(b, b"-----", e + 8) {
                Some(close) => close + 5,
                None => b.len(),
            },
            None => b.len(),
        };
        out.push(start..end);
        from = end;
    }
    out
}

fn walk_while(b: &[u8], mut i: usize, pred: fn(u8) -> bool) -> usize {
    while i < b.len() && pred(b[i]) {
        i += 1;
    }
    i
}

fn is_email_local(c: u8) -> bool {
    matches!(c, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'+' | b'-' | b'_')
}

/// A conservative `local@domain.tld` shape: at least one local-part char, a domain of word chars and
/// dots, a final label of 2+ letters. Trailing `.`/`-` after the domain is treated as punctuation.
fn email_spans(b: &[u8]) -> Vec<std::ops::Range<usize>> {
    let mut out = Vec::new();
    for (idx, &c) in b.iter().enumerate() {
        if c != b'@' {
            continue;
        }
        let local_ok = idx > 0 && is_email_local(b[idx - 1]);
        if !local_ok {
            continue;
        }
        let dom_start = idx + 1;
        let mut dom_end = walk_while(b, dom_start, |c| {
            c.is_ascii_alphanumeric() || c == b'.' || c == b'-'
        });
        // A sentence-final `.` (or a stray trailing `-`) is punctuation, not part of the domain:
        // `mail jane@example.com.` must still match.
        while dom_end > dom_start && matches!(b[dom_end - 1], b'.' | b'-') {
            dom_end -= 1;
        }
        let domain = &b[dom_start..dom_end];
        if domain.len() < 4 {
            continue;
        }
        if let Some(dot) = domain.iter().rposition(|&c| c == b'.') {
            let tld = &domain[dot + 1..];
            if tld.len() >= 2 && tld.iter().all(u8::is_ascii_alphabetic) {
                let mut local_start = idx;
                while local_start > 0 && is_email_local(b[local_start - 1]) {
                    local_start -= 1;
                }
                // Never start a span inside a previous one (`a@b.co@c.org`-style runs).
                if out
                    .last()
                    .map_or(true, |r: &std::ops::Range<usize>| local_start >= r.end)
                {
                    out.push(local_start..dom_end);
                }
            }
        }
    }
    out
}

/// A maximal run of digit groups joined by single spaces/dashes (`4111 1111 1111 1111`,
/// `2345-6789-0124`, or one bare group). `groups` are the byte ranges of the digit groups.
struct DigitRun {
    groups: Vec<std::ops::Range<usize>>,
}

impl DigitRun {
    fn span(&self) -> std::ops::Range<usize> {
        self.groups[0].start..self.groups[self.groups.len() - 1].end
    }
    fn digits(&self, b: &[u8]) -> Vec<u8> {
        self.groups
            .iter()
            .flat_map(|g| b[g.clone()].iter().copied())
            .collect()
    }
    fn digit_count(&self) -> usize {
        self.groups.iter().map(|g| g.end - g.start).sum()
    }
}

fn digit_runs(b: &[u8]) -> Vec<DigitRun> {
    let mut runs = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if !b[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let mut groups = Vec::new();
        let mut start = i;
        loop {
            let end = walk_while(b, start, |c| c.is_ascii_digit());
            groups.push(start..end);
            if end + 1 < b.len()
                && (b[end] == b' ' || b[end] == b'-')
                && b[end + 1].is_ascii_digit()
            {
                start = end + 1;
            } else {
                i = end;
                break;
            }
        }
        runs.push(DigitRun { groups });
    }
    runs
}

/// A card number: a 13–19 digit run passing the Luhn checksum (the standard card-number DLP
/// heuristic — Luhn's own ~1-in-10 accept rate on random digits is an inherent property of the
/// checksum, not a flaw here; it is what every mainstream DLP tool uses for exactly this shape).
/// Either one unbroken digit run (the original rule, unchanged) or a whole run of digit groups
/// joined by single spaces/dashes (`4111 1111 1111 1111`, `4111-1111-1111-1111`).
fn card_spans(b: &[u8]) -> Vec<std::ops::Range<usize>> {
    let mut out = Vec::new();
    for run in digit_runs(b) {
        if run.groups.len() >= 2
            && (13..=19).contains(&run.digit_count())
            && luhn_valid(&run.digits(b))
        {
            out.push(run.span());
            continue;
        }
        for g in &run.groups {
            if (13..=19).contains(&(g.end - g.start)) && luhn_valid(&b[g.clone()]) {
                out.push(g.clone());
            }
        }
    }
    out
}

fn luhn_valid(digits: &[u8]) -> bool {
    let mut sum = 0u32;
    let mut double = false;
    for &d in digits.iter().rev() {
        let mut v = (d - b'0') as u32;
        if double {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
        double = !double;
    }
    sum % 10 == 0
}

/// An Aadhaar number (India's 12-digit resident ID): a whole digit run that is either 12 bare
/// digits or three 4-digit groups joined by single spaces/dashes, first digit 2–9 (UIDAI never
/// issues 0/1-leading numbers), passing the Verhoeff checksum, and not touching a letter or digit
/// on either side (so a 12-digit slice of a longer identifier never fires).
fn aadhaar_spans(b: &[u8]) -> Vec<std::ops::Range<usize>> {
    let mut out = Vec::new();
    for run in digit_runs(b) {
        let shape_ok = match run.groups.len() {
            1 => run.digit_count() == 12,
            3 => run.groups.iter().all(|g| g.end - g.start == 4),
            _ => false,
        };
        if !shape_ok {
            continue;
        }
        let span = run.span();
        let bounded = (span.start == 0 || !b[span.start - 1].is_ascii_alphanumeric())
            && (span.end >= b.len() || !b[span.end].is_ascii_alphanumeric());
        let digits = run.digits(b);
        if bounded && (b'2'..=b'9').contains(&digits[0]) && verhoeff_valid(&digits) {
            out.push(span);
        }
    }
    out
}

/// The Verhoeff checksum (dihedral group D5) — valid iff the running check over the reversed digit
/// string ends at 0. Catches every single-digit error and every adjacent transposition.
fn verhoeff_valid(digits: &[u8]) -> bool {
    const D: [[u8; 10]; 10] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
        [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
        [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
    ];
    const P: [[u8; 10]; 8] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
        [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
        [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
    ];
    let mut c = 0u8;
    for (i, &d) in digits.iter().rev().enumerate() {
        if !d.is_ascii_digit() {
            return false;
        }
        c = D[c as usize][P[i % 8][(d - b'0') as usize] as usize];
    }
    c == 0
}

/// An Indian PAN (Permanent Account Number): `[A-Z]{5}[0-9]{4}[A-Z]` whose 4th letter is a valid
/// holder-type code (`P C H F A T B L J G`), bounded by non-alphanumerics on both sides.
fn pan_in_spans(b: &[u8]) -> Vec<std::ops::Range<usize>> {
    const HOLDER: &[u8] = b"PCHFATBLJG";
    let mut out = Vec::new();
    if b.len() < 10 {
        return out;
    }
    for i in 0..=b.len() - 10 {
        let w = &b[i..i + 10];
        if w[..5].iter().all(u8::is_ascii_uppercase)
            && HOLDER.contains(&w[3])
            && w[5..9].iter().all(u8::is_ascii_digit)
            && w[9].is_ascii_uppercase()
            && (i == 0 || !b[i - 1].is_ascii_alphanumeric())
            && (i + 10 >= b.len() || !b[i + 10].is_ascii_alphanumeric())
        {
            out.push(i..i + 10);
        }
    }
    out
}

/// `\d{3}-\d{2}-\d{4}` not immediately bordered by another digit (so it doesn't fire inside a longer
/// dash-delimited digit run, e.g. a tracking or account number).
fn ssn_spans(b: &[u8]) -> Vec<std::ops::Range<usize>> {
    let mut out = Vec::new();
    if b.len() < 11 {
        return out;
    }
    for i in 0..=b.len() - 11 {
        if b[i..i + 3].iter().all(u8::is_ascii_digit)
            && b[i + 3] == b'-'
            && b[i + 4..i + 6].iter().all(u8::is_ascii_digit)
            && b[i + 6] == b'-'
            && b[i + 7..i + 11].iter().all(u8::is_ascii_digit)
            && (i == 0 || !b[i - 1].is_ascii_digit())
            && (i + 11 >= b.len() || !b[i + 11].is_ascii_digit())
        {
            out.push(i..i + 11);
        }
    }
    out
}

/// B9: the first configured canary token that appears verbatim in `payload`, if any. Canary tokens
/// are operator-planted honeytoken strings (bait credentials that should never legitimately appear
/// in real traffic) — ANY match is always-deny regardless of `AlertOrDeny`/`RedactOrDeny` (doc 24
/// §11 B9 is the one detector with no soft mode: there is no legitimate reason for a canary to ever
/// cross a governed lane, so there is nothing an "alert" mode would be hedging against).
pub fn canary_match<'a>(payload: &str, tokens: &'a [String]) -> Option<&'a str> {
    tokens
        .iter()
        .find(|t| !t.is_empty() && payload.contains(t.as_str()))
        .map(String::as_str)
}

/// B8: one operation rail — allow/deny/approve a specific outbound API operation, narrower than a
/// host-level egress rule. `host` uses the same pattern syntax as egress rules (`*` / `*.domain` /
/// exact); `method` is an HTTP verb or `*`; `path` is an optional `prefix_*` glob or exact match;
/// `graphql_mutation` optionally matches a GraphQL mutation NAME inside a JSON body. Rails are
/// evaluated top-to-bottom, first match wins; a body the rail must parse to decide (a `path`/
/// `graphql_mutation` rail against a non-JSON or malformed body) that fails to parse is a DENY
/// (fail-closed for the rail — an uninspectable body can't be cleared).
#[derive(Debug, Clone, Deserialize)]
pub struct OperationRail {
    #[serde(default = "default_star")]
    pub host: String,
    #[serde(default = "default_star")]
    pub method: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub graphql_mutation: Option<String>,
    pub tier: EgressTier,
}

fn default_star() -> String {
    "*".to_string()
}

/// B8 evaluation outcome for one call against the configured `operation_rails`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RailOutcome {
    /// No configured rail's `host` pattern matches this destination — rails are opt-in per
    /// destination, so an unrailed host is completely unaffected (false-positive safety).
    NoRailApplies,
    Allowed,
    RequiresApproval,
    Denied(String),
    /// A rail applies to this destination but the operation (verb+path or GraphQL mutation name)
    /// could not be extracted from `params` — fail-closed (doc 24 §11 B8).
    ParseFailed,
}

/// Best-effort `(METHOD, path)` from an action's params: an explicit `method`/`path` pair, or a
/// `method` + the path component of a `url` field (defaulting method to `GET`, matching a plain
/// WebFetch's implicit-GET shape).
fn extract_operation(params: &Value) -> Option<(String, String)> {
    let method = params
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("GET")
        .to_ascii_uppercase();
    if let Some(path) = params.get("path").and_then(Value::as_str) {
        return Some((method, path.to_string()));
    }
    let url = params.get("url").and_then(Value::as_str)?;
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let path = after_scheme
        .find('/')
        .map(|i| &after_scheme[i..])
        .unwrap_or("/");
    Some((method, path.to_string()))
}

/// A GraphQL mutation NAME out of a `query`/`body` string field: text after the first `mutation`
/// keyword, up to the first non-identifier character. `None` for an anonymous mutation (`mutation {
/// ... }`) or no mutation keyword at all — anonymous mutations can't be named-matched by a rail.
fn extract_graphql_mutation(params: &Value) -> Option<String> {
    let query = params
        .get("query")
        .and_then(Value::as_str)
        .or_else(|| params.get("body").and_then(Value::as_str))?;
    let idx = query.find("mutation")?;
    let rest = query[idx + "mutation".len()..].trim_start();
    let name: String = rest
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// B8: evaluate `params` against the operation rails that apply to `host`. Rails are an ALLOWLIST
/// FENCE (the "rail" in the name) — an operation that doesn't match any applicable rail is denied,
/// not silently passed through, consistent with the rest of kriya's deny-by-default posture. Rails
/// are evaluated top-to-bottom; first match wins.
pub fn evaluate_operation_rails(
    rails: &[OperationRail],
    host: &str,
    params: &Value,
) -> RailOutcome {
    let applicable: Vec<&OperationRail> = rails
        .iter()
        .filter(|r| r.host == "*" || host_matches(&r.host, host))
        .collect();
    if applicable.is_empty() {
        return RailOutcome::NoRailApplies;
    }

    let op = extract_operation(params);
    let mutation = extract_graphql_mutation(params);
    if op.is_none() && mutation.is_none() {
        return RailOutcome::ParseFailed;
    }

    for rail in applicable {
        let matched = if let Some(want) = &rail.graphql_mutation {
            mutation.as_deref() == Some(want.as_str())
        } else if let Some((method, path)) = &op {
            let method_ok = rail.method == "*" || rail.method.eq_ignore_ascii_case(method);
            let path_ok = rail
                .path
                .as_deref()
                .map_or(true, |pattern| matches(pattern, path));
            method_ok && path_ok
        } else {
            false
        };
        if matched {
            return match rail.tier {
                EgressTier::Allow => RailOutcome::Allowed,
                EgressTier::Approval => RailOutcome::RequiresApproval,
                EgressTier::Deny => RailOutcome::Denied(format!(
                    "operation rail explicitly denies {} on '{host}' (B8)",
                    op.as_ref()
                        .map(|(m, p)| format!("{m} {p}"))
                        .unwrap_or_else(|| format!(
                            "mutation {}",
                            mutation.as_deref().unwrap_or("?")
                        )),
                )),
            };
        }
    }
    RailOutcome::Denied(format!(
        "no operation rail on '{host}' permits {} (B8, fail-closed)",
        op.as_ref()
            .map(|(m, p)| format!("{m} {p}"))
            .unwrap_or_else(|| format!("mutation {}", mutation.as_deref().unwrap_or("?"))),
    ))
}

/// B10: the connector registry. A discovered MCP tool `(upstream, tool)` is disabled-until-approved
/// unless it appears here with a matching `description_hash`; a hash MISMATCH against an approved
/// entry (the tool's description/schema changed since approval) is drift — the tool-poisoning
/// signal — and disables it again until re-approved. Approval is authored in policy (via the
/// Console), never a runtime-mutable file, so it travels with the signed fleet PolicyBundle exactly
/// like every other policy dial.
#[derive(Debug, Clone, Deserialize)]
pub struct ConnectorRegistryPolicy {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub approved: Vec<ApprovedConnectorTool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApprovedConnectorTool {
    /// The broker upstream namespace (the slugified `name:` from `broker.yaml`, e.g. `"widgets"`).
    pub upstream: String,
    /// The inner (un-namespaced) tool name as the upstream reports it.
    pub tool: String,
    /// SHA-256 hex of the canonical tool description at approval time — see
    /// `connector_tool_hash` in `bin/kriya-gateway.rs`, the only place a full `Tool` (with its
    /// description) is in hand at discovery time. A live mismatch is drift.
    pub description_hash: String,
}

/// B12: per-server trust class for governed MCP ingress (responses). `Trusted` passes through
/// unchanged; `Scan` runs the B7 secret/PII pass over the response too; `Block` denies the response
/// outright. Default class is `Scan`, never `Block` — the house rule against silently auto-blocking
/// a server the operator hasn't explicitly classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustClass {
    Trusted,
    #[default]
    Scan,
    Block,
}

#[derive(Debug, Clone, Deserialize)]
pub struct McpResponsePolicy {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// The class an unlisted server gets. Default `Scan` (never `Block`).
    #[serde(default)]
    pub default_class: TrustClass,
    #[serde(default)]
    pub per_server: std::collections::BTreeMap<String, TrustClass>,
}

impl McpResponsePolicy {
    /// The effective trust class for `server` (the broker upstream namespace).
    pub fn class_for(&self, server: &str) -> TrustClass {
        self.per_server
            .get(server)
            .copied()
            .unwrap_or(self.default_class)
    }
}

impl DetectionPolicy {
    /// B11: whether `action_id` is a known-mutating tool on a connector the operator marked
    /// read-only — a hard override the explicit action `rules` can never widen back open (checked
    /// before them in [`Policy::check`]). `read_only` entries are connector NAMESPACE patterns using
    /// the action policy's own prefix-glob syntax (`"widgets"`/`"widgets__*"`/`"widgets__delete_*"`
    /// — a bare namespace like `"widgets"` is normalized to `"widgets__*"`), never a host: the
    /// namespace is what a "connector" means in the broker's `<namespace>__<tool>` scheme, and
    /// resolving a namespace to a destination host isn't information `Policy` has.
    pub fn read_only_denies(&self, action_id: &str) -> bool {
        if !is_destructive_name(action_id) {
            return false;
        }
        self.read_only.iter().any(|pattern| {
            let pattern = if pattern.contains('*') {
                pattern.clone()
            } else {
                format!("{pattern}__*")
            };
            matches(&pattern, action_id)
        })
    }
}

// ─── Endpoint budget gate (C2, doc 27 §4 / `docs/design/c2-budget-gate.md`) ────────────────────────
//
// A "trailing-state budget gate" — NEVER a hard cap (Red-team a / the naming-check test): it blocks
// or routes-to-approval the NEXT gated action once C1's Console-written spend state (read-only,
// [`crate::spend_state::SpendState`]) crosses an operator-authored USD threshold. This crate never
// prices anything — every `observed_usd` figure here was already priced by the Console and copied
// through a state file.
//
// Composition (D3, the tier-surprise guard, axiom 4): on the `kriya-hook pre` lane the action tier
// (`Policy::check`) is the ONLY pre-execution tier that precedes this gate. A budget can escalate an
// Allowed action to approval/deny; it can NEVER loosen an earlier Deny/ungranted-approval back to
// allow — [`Policy::check`]'s own early returns already guarantee that (this gate is only ever
// consulted once `check` resolved `Allow` or a GRANTED `RequiresApproval`).

/// Which observed-spend key a budget rule is scoped against (D3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BudgetScope {
    /// The current governed session (`session_id`/`run_id` from the hook payload).
    Session,
    /// The current UTC day's total across every session (F-MB: each session's whole priced total
    /// attributes to the UTC day of its `window_end_ms` — a coarse, honest, never-split boundary;
    /// see `docs/TRUST.md`).
    RollingDay,
    /// The OS user's cross-session total (this device's single local operator).
    User,
}

impl BudgetScope {
    pub fn as_str(self) -> &'static str {
        match self {
            BudgetScope::Session => "session",
            BudgetScope::RollingDay => "rolling-day",
            BudgetScope::User => "user",
        }
    }
}

/// What a breaching budget rule does (D3). Strictest-wins across rules: `deny` > `require-approval`
/// > `warn`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BudgetBreachAction {
    Deny,
    RequireApproval,
    Warn,
}

impl BudgetBreachAction {
    fn kind(self) -> BreachKind {
        match self {
            BudgetBreachAction::Deny => BreachKind::Deny,
            BudgetBreachAction::RequireApproval => BreachKind::Approval,
            BudgetBreachAction::Warn => BreachKind::Warn,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            BudgetBreachAction::Deny => "deny",
            BudgetBreachAction::RequireApproval => "require-approval",
            BudgetBreachAction::Warn => "warn",
        }
    }
}

/// What happens when the state needed to evaluate a rule is missing or stale (D2). Each rule's
/// EFFECTIVE posture, when this is omitted, defaults per-tier from [`BudgetBreachAction`] — see
/// [`default_on_missing`] — so every tier's fail-closed-by-default posture is exactly its own tier's
/// natural behavior; an operator opting a `deny` rule INTO `fail-open` is an explicit, receipted
/// loosening (never the default).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OnMissingState {
    FailClosed,
    FailOpen,
    RequireApproval,
}

impl OnMissingState {
    fn kind(self) -> BreachKind {
        match self {
            OnMissingState::FailClosed => BreachKind::Deny,
            OnMissingState::RequireApproval => BreachKind::Approval,
            OnMissingState::FailOpen => BreachKind::Warn,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            OnMissingState::FailClosed => "fail-closed",
            OnMissingState::FailOpen => "fail-open",
            OnMissingState::RequireApproval => "require-approval",
        }
    }
}

/// The per-tier default `on_missing_state` posture (D2's table): `deny`'s default IS fail-closed,
/// `require-approval`'s default IS route-to-approval, `warn`'s default IS fail-open — i.e. every
/// tier's own natural behavior is ALSO its missing-state default. This is what makes B0's fail-closed
/// matrix an EXTENSION rather than a new, separate posture to reason about.
fn default_on_missing(action: BudgetBreachAction) -> OnMissingState {
    match action {
        BudgetBreachAction::Deny => OnMissingState::FailClosed,
        BudgetBreachAction::RequireApproval => OnMissingState::RequireApproval,
        BudgetBreachAction::Warn => OnMissingState::FailOpen,
    }
}

/// One authored budget rule (D3 YAML shape).
#[derive(Debug, Clone, Deserialize)]
pub struct BudgetRule {
    /// A stable id, surfaced on the receipt + the Console's UI.
    pub id: String,
    pub scope: BudgetScope,
    pub threshold_usd: f64,
    pub action: BudgetBreachAction,
    /// Overrides the per-tier missing/stale-state default (D2). `None` = use [`default_on_missing`].
    #[serde(default)]
    pub on_missing_state: Option<OnMissingState>,
}

fn default_max_staleness_secs() -> u64 {
    900
}

/// The budget gate's policy section (D3). Additive nullable — mirrors `egress`/`detection`/
/// `secrets`/`model`'s `Option<...>` BC discipline exactly.
#[derive(Debug, Clone, Deserialize)]
pub struct BudgetPolicy {
    /// State older than this (seconds) is "stale" — treated exactly like missing state (D2).
    #[serde(default = "default_max_staleness_secs")]
    pub max_staleness_secs: u64,
    #[serde(default)]
    pub rules: Vec<BudgetRule>,
}

impl Default for BudgetPolicy {
    fn default() -> Self {
        BudgetPolicy { max_staleness_secs: default_max_staleness_secs(), rules: Vec::new() }
    }
}

/// The evaluation context a budget check needs beyond the spend state itself — the scope keys
/// [`BudgetScope::Session`]/[`BudgetScope::User`] resolve against.
#[derive(Debug, Clone, Copy)]
pub struct BudgetCtx<'a> {
    pub session_id: Option<&'a str>,
    pub os_user: &'a str,
}

/// The three receipt-shaped breach kinds — `deny` > `approval` > `warn` (strictest-wins, D3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BreachKind {
    Deny,
    Approval,
    Warn,
}
impl BreachKind {
    fn rank(self) -> u8 {
        match self {
            BreachKind::Deny => 2,
            BreachKind::Approval => 1,
            BreachKind::Warn => 0,
        }
    }
}

/// The full, privacy-audited param set for a `kriya.spend.gate.*` receipt (D4) — count/cost/hash/
/// id/timestamp only, NEVER transcript content. `scope_key` is always a hash or a non-sensitive
/// label, never a raw session id / OS username string.
#[derive(Debug, Clone, PartialEq)]
pub struct BudgetGateRecord {
    pub budget_id: String,
    pub scope: BudgetScope,
    pub scope_key: String,
    pub threshold_usd: f64,
    pub observed_usd: f64,
    pub action: BudgetBreachAction,
    pub state_source: &'static str, // "live-tick" | "statusline" | "none"
    pub state_as_of_ms: u64,
    pub state_stale: bool,
    /// Set only when missing/stale state (rather than a fresh over-threshold reading) produced this
    /// record (D2) — `None` on a native over-threshold breach.
    pub on_missing_state: Option<OnMissingState>,
    pub pricing_sheet: Option<String>,
    pub pricing_sheet_hash: Option<String>,
}

/// The gate's decision for one `kriya-hook pre` call, over EVERY matching rule (strictest wins).
#[derive(Debug, Clone, PartialEq)]
pub enum BudgetGateDecision {
    /// No rule breached at all (every rule is either absent, or resolved fresh-and-under-threshold).
    /// The action proceeds with no gate receipt — the common case, byte-identical to no `budgets:`
    /// section at all.
    Pass,
    /// A `warn`-shaped breach (fresh-and-over-threshold `warn` rule, or an explicit/default
    /// fail-open posture on missing/stale state) — observe-only, never blocks.
    Warn(BudgetGateRecord),
    /// A `require-approval`-shaped breach — the caller must route through the SAME approval gate the
    /// action tier uses; granted -> proceed, not granted -> block (D4).
    Approval(BudgetGateRecord),
    /// A `deny`-shaped breach — the caller must block immediately (exit 2 on the hook lane).
    Deny(BudgetGateRecord),
}

fn utc_day_string(ms: u64) -> String {
    let days = (ms / 86_400_000) as i64;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = y + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02}")
}

impl BudgetPolicy {
    /// Evaluate EVERY matching rule against `state`, returning the single strictest-wins decision
    /// (D3). Pure — no filesystem/signing here; the caller (the hook's `pre` lane) decides what to
    /// DO with the decision (sign a receipt, exit 2, route through the approval gate).
    pub fn check(
        &self,
        state: &crate::spend_state::SpendState,
        ctx: &BudgetCtx,
        now_ms: u64,
    ) -> BudgetGateDecision {
        let mut winner: Option<(BreachKind, BudgetGateRecord)> = None;

        for rule in &self.rules {
            let reading = state.resolve(rule.scope, ctx.session_id);
            let (kind, record) = match reading {
                None => {
                    // Missing state — includes an unresolvable scope key (e.g. no session_id for a
                    // session-scope rule), never silently skipped (Red-team b).
                    // Missing state, on a `warn`-tier rule with no explicit override, still emits a
                    // receipted warn (D2: "the chosen on_missing_state is written into the gate
                    // receipt so the posture is auditable") — never a silent no-op.
                    let posture = rule.on_missing_state.unwrap_or_else(|| default_on_missing(rule.action));
                    let kind = posture.kind();
                    let record = BudgetGateRecord {
                        budget_id: rule.id.clone(),
                        scope: rule.scope,
                        scope_key: scope_key_for(rule.scope, ctx),
                        threshold_usd: rule.threshold_usd,
                        observed_usd: 0.0,
                        action: rule.action,
                        state_source: "none",
                        state_as_of_ms: 0,
                        state_stale: true,
                        on_missing_state: Some(posture),
                        pricing_sheet: None,
                        pricing_sheet_hash: None,
                    };
                    (kind, record)
                }
                Some(r) => {
                    let age_secs = now_ms.saturating_sub(r.as_of_ms) / 1000;
                    let stale = age_secs > self.max_staleness_secs;
                    if stale {
                        let posture =
                            rule.on_missing_state.unwrap_or_else(|| default_on_missing(rule.action));
                        let record = BudgetGateRecord {
                            budget_id: rule.id.clone(),
                            scope: rule.scope,
                            scope_key: scope_key_for(rule.scope, ctx),
                            threshold_usd: rule.threshold_usd,
                            observed_usd: r.observed_usd,
                            action: rule.action,
                            state_source: r.source.as_str(),
                            state_as_of_ms: r.as_of_ms,
                            state_stale: true,
                            on_missing_state: Some(posture),
                            pricing_sheet: r.pricing_sheet.clone(),
                            pricing_sheet_hash: r.pricing_sheet_hash.clone(),
                        };
                        (posture.kind(), record)
                    } else if r.observed_usd >= rule.threshold_usd {
                        let record = BudgetGateRecord {
                            budget_id: rule.id.clone(),
                            scope: rule.scope,
                            scope_key: scope_key_for(rule.scope, ctx),
                            threshold_usd: rule.threshold_usd,
                            observed_usd: r.observed_usd,
                            action: rule.action,
                            state_source: r.source.as_str(),
                            state_as_of_ms: r.as_of_ms,
                            state_stale: false,
                            on_missing_state: None,
                            pricing_sheet: r.pricing_sheet.clone(),
                            pricing_sheet_hash: r.pricing_sheet_hash.clone(),
                        };
                        (rule.action.kind(), record)
                    } else {
                        continue; // fresh + under threshold — this rule does not fire
                    }
                }
            };

            let better = match &winner {
                None => true,
                Some((wk, _)) => kind.rank() > wk.rank(),
            };
            if better {
                winner = Some((kind, record));
            }
        }

        match winner {
            None => BudgetGateDecision::Pass,
            Some((BreachKind::Deny, r)) => BudgetGateDecision::Deny(r),
            Some((BreachKind::Approval, r)) => BudgetGateDecision::Approval(r),
            Some((BreachKind::Warn, r)) => BudgetGateDecision::Warn(r),
        }
    }
}

/// Lowercase-hex SHA-256 — a private copy of `audit.rs`'s helper (not itself `pub`) so `scope_key`
/// never carries a raw session id / OS username, only a commitment to it (D4).
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// The receipt's `scope_key` (D4): never a raw session id / OS username — always a hash (session,
/// user) or a non-sensitive label (rolling-day: a UTC date string, not sensitive on its own).
fn scope_key_for(scope: BudgetScope, ctx: &BudgetCtx) -> String {
    match scope {
        BudgetScope::Session => match ctx.session_id {
            Some(sid) => sha256_hex(sid.as_bytes()),
            None => "unresolved-session".to_string(),
        },
        BudgetScope::User => sha256_hex(ctx.os_user.as_bytes()),
        BudgetScope::RollingDay => utc_day_string(now_for_day_label()),
    }
}

/// The wall-clock "now", used ONLY to LABEL the rolling-day scope_key with today's UTC date — never
/// to compute `observed_usd` (that number always comes straight from the state reading).
fn now_for_day_label() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ─── B4 — Temporal policy conditions (doc 27 §4 / docs/design/b4-temporal-conditions.md) ─────────
//
// A small, CLOSED set of session-scoped, cross-event preconditions layered on top of the action
// tier: "deny X unless Y happened/succeeded earlier this session" (axiom 5 — TIGHTEN-ONLY: a
// temporal rule can only escalate the `Decision` `Policy::check` already resolved above, never
// re-open a Deny/ungranted-approval; `Policy::check`, `Rule`, and every existing `Rule {…}` literal
// are UNTOUCHED by this section). Evidence is a fold over THIS SESSION's own verified, GOVERNED
// receipts (axiom 3) — never an unbounded or cross-session scan. [`crate::session_cond::SessionEvent`]
// (the fold's OUTPUT type) is defined in that sibling module, not here — exactly like
// `BudgetPolicy::check` takes a `&crate::spend_state::SpendState` it does not itself define; this
// module owns only the pure schema + evaluator (D1/D3), `session_cond` owns the fold/cache/
// governance-filter/verification half.

use crate::session_cond::SessionEvent;

/// A case-sensitive literal SUBSTRING match on a Bash-lane `command` (D1, Red-team b) — never
/// glob/regex, and never argv parsing (env-assignments/pipes/`&&`/quoting make that non-
/// deterministic, a worse ambiguity than substring). `contains: "test"` also matches `latest`; the
/// documented mitigation is operator precision, surfaced by the Console's authoring lint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommandMatch {
    pub contains: String,
}

/// Filters a selector's match SET by the prior receipt's `success` bool (D1). Meaningless for the
/// rule's own subject selector (matching the CURRENT, not-yet-executed action, which has no
/// `success` yet — axiom 2) — only ever consulted for a condition's selector over prior events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Any,
    Success,
    Failure,
}

impl Default for Outcome {
    fn default() -> Self {
        Outcome::Any
    }
}

/// The closed, two-dimension selector (D1) — always operator-authored, never agent free-text.
/// `action` reuses the SAME glob semantics as a policy `Rule.action` ([`matches`], this module).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Selector {
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<CommandMatch>,
    #[serde(default)]
    pub outcome: Outcome,
}

impl Selector {
    /// D1: does `event` (a folded prior receipt) match this selector?
    fn matches_event(&self, event: &SessionEvent) -> bool {
        if !matches(&self.action, &event.action_id) {
            return false;
        }
        if let Some(cm) = &self.command {
            match &event.command {
                Some(c) if c.contains(&cm.contains) => {}
                _ => return false,
            }
        }
        match self.outcome {
            Outcome::Any => true,
            Outcome::Success => event.success,
            Outcome::Failure => !event.success,
        }
    }

    /// Does this selector match the CURRENT gated action (not a folded session event)? There is no
    /// `success`/`ts_ms` for an in-flight action (axiom 2), so `outcome` never applies here — only
    /// `action`/`command` are meaningful for a rule's subject selector.
    fn matches_current(&self, action_id: &str, command: Option<&str>) -> bool {
        if !matches(&self.action, action_id) {
            return false;
        }
        if let Some(cm) = &self.command {
            match command {
                Some(c) if c.contains(&cm.contains) => {}
                _ => return false,
            }
        }
        true
    }
}

/// D1: does `event` match `selector`? A free function (not just the `Selector` method) so a fixture
/// test can call the fold-agnostic matcher directly, matching this module's exported shape.
pub fn matches_selector(event: &SessionEvent, selector: &Selector) -> bool {
    selector.matches_event(event)
}

/// happened | succeeded | count | since_minutes (D1) — one shared primitive (a fold + match set),
/// four names. `succeeded(S)` is the sugar `happened(S, outcome=success)`: it reads the match set
/// under `S` with `outcome` FORCED to `success` regardless of what the operator's own selector says
/// (see [`effective_selector_for`]) — the receipt trace echoes that effective selector (D4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Predicate {
    Happened,
    Succeeded,
    Count,
    SinceMinutes,
}

/// satisfied (default) | unsatisfied — the closed-set stand-in for a NOT operator (D1). A rule's
/// `when:` is a conjunction: it matches only when EVERY condition's `observed` boolean equals its
/// own `expect`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Expect {
    Satisfied,
    Unsatisfied,
}

impl Default for Expect {
    fn default() -> Self {
        Expect::Satisfied
    }
}

/// `>=` | `<=` | `==` — meaningful only for `count`/`since_minutes` (D1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Cmp {
    #[serde(rename = ">=")]
    Ge,
    #[serde(rename = "<=")]
    Le,
    #[serde(rename = "==")]
    Eq,
}

/// One condition inside a rule's `when:` (D1/D3). `cmp`/`n` are `count`'s own fields; `cmp`/`t`
/// (minutes) are `since_minutes`'s — both are `Option` since only one predicate ever reads them
/// (unused-for-this-predicate fields are simply ignored, never a parse error).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Condition {
    pub predicate: Predicate,
    pub selector: Selector,
    #[serde(default)]
    pub expect: Expect,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmp: Option<Cmp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub t: Option<i64>,
}

/// fail-closed | fail-open | require-approval — the posture when the session fold itself is
/// UNAVAILABLE (D2: the log is unreadable — an I/O error, never merely "empty"). `None` on a rule
/// defaults per-tier via [`default_on_unavailable`], mirroring `OnMissingState`'s per-tier default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OnUnavailable {
    FailClosed,
    FailOpen,
    RequireApproval,
}

/// Per-tier default `on_unavailable` posture (D2), mirroring `default_on_missing`: a `deny` rule
/// defaults fail-closed, `approval` defaults to routing through approval. `allow` is unreachable in
/// practice (a `tier: allow` temporal rule is a rejected no-op at authoring time, D3) but still
/// needs a total mapping; fail-open is the honest answer (there is nothing to tighten either way).
pub fn default_on_unavailable(tier: Tier) -> OnUnavailable {
    match tier {
        Tier::Deny => OnUnavailable::FailClosed,
        Tier::Approval => OnUnavailable::RequireApproval,
        Tier::Allow => OnUnavailable::FailOpen,
    }
}

/// allow | approval | deny (D3) — reuses the SAME tier space a `Rule`'s decision resolves to; a
/// matched temporal rule may only ESCALATE the already-resolved action-tier decision, never loosen
/// it (axiom 5). `Tier::Allow` is retained here for schema completeness (an authored rule can name
/// it) but [`TemporalPolicy::evaluate`] treats a matched `allow`-tier rule as a no-op `Pass` —
/// defense in depth alongside the Console authoring lint that rejects it up front.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Allow,
    Approval,
    Deny,
}

/// One temporal rule (D1/D3): a subject `selector` matching the CURRENT action, a `tier` to
/// escalate to when every `when:` condition holds, and the posture when the session fold can't be
/// computed.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct TemporalRule {
    pub id: String,
    pub selector: Selector,
    pub tier: Tier,
    #[serde(default)]
    pub when: Vec<Condition>,
    #[serde(default)]
    pub on_unavailable: Option<OnUnavailable>,
}

impl TemporalRule {
    /// The EFFECTIVE `on_unavailable` posture: the authored override, or this rule's per-tier
    /// default (D2).
    pub fn on_unavailable_posture(&self) -> OnUnavailable {
        self.on_unavailable.unwrap_or_else(|| default_on_unavailable(self.tier))
    }
}

/// The `temporal:` policy section (D3) — additive nullable, exactly like `budgets`/`memory` before
/// it (BC-3: no `temporal:` key when unauthored — a pre-B4 policy round-trips byte-identically).
/// First-match-wins over `rules`, same discipline as the action tier.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct TemporalPolicy {
    #[serde(default)]
    pub rules: Vec<TemporalRule>,
}

impl TemporalPolicy {
    /// The FIRST rule (first-match-wins order) whose subject selector matches the current gated
    /// action, if any — used both by `evaluate` below and by the hook's `on_unavailable` handling
    /// when the session fold itself could not be computed (so there is no `events` to evaluate
    /// `when:` against, but the CURRENT-action match is still knowable without it).
    pub fn first_matching_rule(&self, action_id: &str, command: Option<&str>) -> Option<&TemporalRule> {
        self.rules.iter().find(|r| r.selector.matches_current(action_id, command))
    }
}

/// One evaluated condition's full trace — the privacy-audited param set for a `kriya.policy.cond.*`
/// receipt (D4): ids/patterns/counts/bools/timestamps only, NEVER the agent's command content.
/// `selector` here is the EFFECTIVE selector actually evaluated (for `succeeded`, `outcome` forced
/// to `success` — see [`effective_selector_for`]), so the receipt shows exactly what was checked.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ConditionRecord {
    pub predicate: Predicate,
    pub selector: Selector,
    pub expect: Expect,
    /// The predicate's raw boolean (before comparing against `expect`).
    pub observed: bool,
    /// Size of the match set the predicate read (metadata, never content).
    pub match_count: u64,
    /// The most-recent matching event's `ts_ms`, if any (`since_minutes` support).
    pub last_match_ms: Option<u64>,
    /// `observed == (expect == Satisfied)` — whether this condition contributed to the rule match.
    pub result: bool,
}

/// The full `kriya.policy.cond.*` receipt trace for one matched temporal rule (D4). `index_as_of_ms`
/// / `index_source` describe the FOLD's freshness (honesty, like C2's `state_as_of_ms`) — set here
/// to a live-gate-appropriate default (`now_ms` / `"cache"`) and patched by the caller when it knows
/// better (e.g. `"rebuilt"` after a cold-cache full refold, or `"unavailable"` on a fold failure).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CondRecord {
    pub rule_id: String,
    pub action_id: String,
    pub subject_selector: Selector,
    pub tier: Tier,
    pub conditions: Vec<ConditionRecord>,
    pub now_ms: u64,
    pub index_as_of_ms: u64,
    pub index_source: &'static str, // "cache" | "rebuilt" | "unavailable"
}

/// The temporal gate's decision for one `kriya-hook pre` call (D3/D4) — mirrors the shape of
/// `BudgetGateDecision`. **No `Warn` variant (M-1):** the observe-only path is a reserved v2 lever;
/// `kriya.policy.cond.warn` is reserved-not-emitted and this enum has no arm to construct it in v1.
#[derive(Debug, Clone, PartialEq)]
pub enum TemporalDecision {
    /// No rule matched (or the one matched rule was `tier: allow`, D3's no-op case) — the action
    /// proceeds; no receipt is signed for a temporal `Pass` (mirrors the budget gate's `Pass`).
    Pass,
    /// A `tier: approval` rule matched — the caller must route through the SAME approval gate the
    /// action tier / C2 budget gate use.
    Approval(CondRecord),
    /// A `tier: deny` rule matched — the caller must block immediately (exit 2 on the hook lane).
    Deny(CondRecord),
}

/// The selector actually evaluated for `condition` — `succeeded` FORCES `outcome: success`
/// regardless of what the operator's own selector says (D1: "succeeded(S) is the sugar
/// happened(S, outcome=success)"); every other predicate uses the selector exactly as authored.
fn effective_selector_for(condition: &Condition) -> Selector {
    if condition.predicate == Predicate::Succeeded {
        Selector { outcome: Outcome::Success, ..condition.selector.clone() }
    } else {
        condition.selector.clone()
    }
}

/// D1: evaluate one `Condition`'s boolean over `events` as of `now_ms` — the fold-agnostic
/// evaluator a fixture test can call directly. `now_ms` is the ONLY clock this whole feature reads,
/// and only for `since_minutes`, and only via this explicit parameter (D2's determinism seam: same
/// `events` + same `now_ms` ⇒ same verdict, on any platform, at any time the replay is run).
pub fn evaluate_condition(events: &[SessionEvent], condition: &Condition, now_ms: u64) -> bool {
    trace_condition(events, condition, now_ms).0
}

/// Same evaluation as [`evaluate_condition`], but also returns the full trace a `ConditionRecord`
/// needs: `(observed, match_count, last_match_ms, effective_selector)`. One implementation, two
/// callers — the bare boolean above, and [`TemporalPolicy::evaluate`] below.
fn trace_condition(events: &[SessionEvent], condition: &Condition, now_ms: u64) -> (bool, u64, Option<u64>, Selector) {
    let effective = effective_selector_for(condition);
    let match_events: Vec<&SessionEvent> = events.iter().filter(|e| matches_selector(e, &effective)).collect();
    let match_count = match_events.len() as u64;
    let last_match_ms = match_events.iter().map(|e| e.ts_ms).max();

    let observed = match condition.predicate {
        // `succeeded` shares `happened`'s ">= 1 match" shape — the only difference is that its
        // `effective` selector above already forced `outcome: success` onto the match set.
        Predicate::Happened | Predicate::Succeeded => match_count >= 1,
        Predicate::Count => {
            let n = condition.n.unwrap_or(0);
            let count = match_count as i64;
            match condition.cmp.unwrap_or(Cmp::Ge) {
                Cmp::Ge => count >= n,
                Cmp::Le => count <= n,
                Cmp::Eq => count == n,
            }
        }
        Predicate::SinceMinutes => {
            // No match ⇒ age = +∞ (D1) — an absent precondition is "infinitely long ago," never
            // "just happened," so `since_minutes(S) <= t` correctly reads false with no match.
            let age_minutes: i64 = match last_match_ms {
                Some(ts) => ((now_ms.saturating_sub(ts)) / 60_000) as i64,
                None => i64::MAX,
            };
            let t = condition.t.unwrap_or(0);
            match condition.cmp.unwrap_or(Cmp::Le) {
                Cmp::Ge => age_minutes >= t,
                Cmp::Le => age_minutes <= t,
                Cmp::Eq => age_minutes == t,
            }
        }
    };
    (observed, match_count, last_match_ms, effective)
}

impl TemporalPolicy {
    /// D1/D3: evaluate this session's temporal rules against the CURRENT gated action
    /// (`action_id`/`command`), over `events` (this session's already-folded, verified, governed
    /// PRIOR receipts — axiom 3 / [`crate::session_cond`]), as of `now_ms`. Pure: no I/O, no clock
    /// read except via the explicit `now_ms` parameter (D2). First-match-wins over `rules`, the
    /// same discipline [`Policy::check`] uses for the action tier.
    pub fn evaluate(
        &self,
        events: &[SessionEvent],
        action_id: &str,
        command: Option<&str>,
        now_ms: u64,
    ) -> TemporalDecision {
        for rule in &self.rules {
            if !rule.selector.matches_current(action_id, command) {
                continue;
            }
            let mut conditions = Vec::with_capacity(rule.when.len());
            let mut all_hold = true;
            for cond in &rule.when {
                let (observed, match_count, last_match_ms, effective_selector) =
                    trace_condition(events, cond, now_ms);
                let result = observed == (cond.expect == Expect::Satisfied);
                if !result {
                    all_hold = false;
                }
                conditions.push(ConditionRecord {
                    predicate: cond.predicate,
                    selector: effective_selector,
                    expect: cond.expect,
                    observed,
                    match_count,
                    last_match_ms,
                    result,
                });
            }
            if !all_hold {
                continue; // this rule's `when:` did not fully hold — not a match, try the next rule
            }
            // Matched. Tighten-only (axiom 5, D3): the authoring-time lint is what actually keeps a
            // `tier: allow` rule from being authored in the first place; treating a matched
            // `allow`-tier rule as a no-op `Pass` here is defense in depth, never a behavior an
            // operator can rely on to loosen anything (there is nothing to loosen — `evaluate` is
            // only ever consulted after `Policy::check` already resolved Allow/granted-approval).
            if rule.tier == Tier::Allow {
                return TemporalDecision::Pass;
            }
            let record = CondRecord {
                rule_id: rule.id.clone(),
                action_id: action_id.to_string(),
                subject_selector: rule.selector.clone(),
                tier: rule.tier,
                conditions,
                now_ms,
                index_as_of_ms: now_ms,
                index_source: "cache",
            };
            return match rule.tier {
                Tier::Allow => unreachable!("handled above"),
                Tier::Approval => TemporalDecision::Approval(record),
                Tier::Deny => TemporalDecision::Deny(record),
            };
        }
        TemporalDecision::Pass
    }
}

#[cfg(test)]
mod temporal_tests {
    use super::*;

    fn ev(action_id: &str, success: bool, ts_ms: u64, command: Option<&str>) -> SessionEvent {
        SessionEvent { action_id: action_id.to_string(), success, ts_ms, command: command.map(str::to_string) }
    }

    fn sel(action: &str, command_contains: Option<&str>) -> Selector {
        Selector {
            action: action.to_string(),
            command: command_contains.map(|c| CommandMatch { contains: c.to_string() }),
            outcome: Outcome::Any,
        }
    }

    fn cond(predicate: Predicate, selector: Selector, expect: Expect) -> Condition {
        Condition { predicate, selector, expect, cmp: None, n: None, t: None }
    }

    // ── happened / succeeded ──────────────────────────────────────────────────────────────────
    #[test]
    fn happened_true_iff_at_least_one_prior_match() {
        let events = vec![ev("claude-code__bash", false, 100, Some("npm test"))];
        let c = cond(Predicate::Happened, sel("claude-code__bash", Some("npm test")), Expect::Satisfied);
        assert!(evaluate_condition(&events, &c, 200));

        let c2 = cond(Predicate::Happened, sel("claude-code__bash", Some("npm lint")), Expect::Satisfied);
        assert!(!evaluate_condition(&events, &c2, 200));
    }

    #[test]
    fn succeeded_requires_success_even_when_a_matching_failure_exists() {
        let events = vec![
            ev("claude-code__bash", false, 100, Some("npm test")), // matches but FAILED
        ];
        let c = cond(Predicate::Succeeded, sel("claude-code__bash", Some("npm test")), Expect::Satisfied);
        assert!(!evaluate_condition(&events, &c, 200), "a failed matching event must not satisfy succeeded()");

        let events2 = vec![
            ev("claude-code__bash", false, 100, Some("npm test")),
            ev("claude-code__bash", true, 150, Some("npm test")),
        ];
        assert!(evaluate_condition(&events2, &c, 200), "a later successful match must satisfy succeeded()");
    }

    #[test]
    fn succeeded_ignores_an_authored_outcome_failure_by_forcing_success() {
        // succeeded(S) is the sugar happened(S, outcome=success) regardless of what the operator's
        // own selector.outcome says (D1) — an authored outcome:failure never makes succeeded() see
        // a successful event as satisfying it via some OR-of-filters confusion.
        let mut s = sel("claude-code__bash", Some("npm test"));
        s.outcome = Outcome::Failure;
        let events = vec![ev("claude-code__bash", true, 100, Some("npm test"))];
        let c = cond(Predicate::Succeeded, s, Expect::Satisfied);
        assert!(evaluate_condition(&events, &c, 200));
    }

    // ── count ──────────────────────────────────────────────────────────────────────────────────
    #[test]
    fn count_ge_le_eq_comparators() {
        let events = vec![
            ev("claude-code__bash", true, 100, Some("npm test")),
            ev("claude-code__bash", true, 200, Some("npm test")),
            ev("claude-code__bash", false, 300, Some("npm test")),
        ];
        let mut c = cond(Predicate::Count, sel("claude-code__bash", Some("npm test")), Expect::Satisfied);
        c.cmp = Some(Cmp::Ge);
        c.n = Some(3);
        assert!(evaluate_condition(&events, &c, 400));

        c.cmp = Some(Cmp::Le);
        c.n = Some(2);
        assert!(!evaluate_condition(&events, &c, 400));

        c.cmp = Some(Cmp::Eq);
        c.n = Some(3);
        assert!(evaluate_condition(&events, &c, 400));
    }

    #[test]
    fn count_reads_every_match_not_just_successes() {
        // count(S) is |match(S)| — attempts, not successes (D1); narrow with outcome: success.
        let events = vec![
            ev("claude-code__bash", false, 100, Some("npm test")),
            ev("claude-code__bash", false, 200, Some("npm test")),
        ];
        let mut c = cond(Predicate::Count, sel("claude-code__bash", Some("npm test")), Expect::Satisfied);
        c.cmp = Some(Cmp::Ge);
        c.n = Some(2);
        assert!(evaluate_condition(&events, &c, 300));
    }

    // ── since_minutes ──────────────────────────────────────────────────────────────────────────
    #[test]
    fn since_minutes_no_match_is_plus_infinity() {
        let events: Vec<SessionEvent> = vec![];
        let mut c = cond(Predicate::SinceMinutes, sel("claude-code__bash", Some("npm test")), Expect::Satisfied);
        c.cmp = Some(Cmp::Le);
        c.t = Some(30);
        assert!(!evaluate_condition(&events, &c, 1_000_000), "no match ever satisfies a <= age bound");
    }

    #[test]
    fn since_minutes_reads_the_most_recent_match() {
        let events = vec![
            ev("claude-code__bash", true, 0, Some("npm test")),
            ev("claude-code__bash", true, 10 * 60_000, Some("npm test")), // 10 min after epoch
        ];
        let mut c = cond(Predicate::SinceMinutes, sel("claude-code__bash", Some("npm test")), Expect::Satisfied);
        c.cmp = Some(Cmp::Le);
        c.t = Some(15);
        // now = 20 minutes after epoch -> most recent match (10 min) is 10 minutes ago -> <= 15 holds
        assert!(evaluate_condition(&events, &c, 20 * 60_000));
        c.t = Some(5);
        assert!(!evaluate_condition(&events, &c, 20 * 60_000));
    }

    // ── the canonical demo: deny git push unless npm test succeeded ───────────────────────────────
    fn canonical_policy() -> TemporalPolicy {
        TemporalPolicy {
            rules: vec![TemporalRule {
                id: "deny-push-without-tests".to_string(),
                selector: sel("claude-code__bash", Some("git push")),
                tier: Tier::Deny,
                when: vec![Condition {
                    predicate: Predicate::Succeeded,
                    selector: sel("claude-code__bash", Some("npm test")),
                    expect: Expect::Unsatisfied,
                    cmp: None,
                    n: None,
                    t: None,
                }],
                on_unavailable: None,
            }],
        }
    }

    #[test]
    fn canonical_demo_denies_push_with_no_prior_successful_test() {
        let policy = canonical_policy();
        let events: Vec<SessionEvent> = vec![];
        let decision = policy.evaluate(&events, "claude-code__bash", Some("git push origin main"), 1000);
        match decision {
            TemporalDecision::Deny(rec) => {
                assert_eq!(rec.rule_id, "deny-push-without-tests");
                assert_eq!(rec.conditions.len(), 1);
                assert!(!rec.conditions[0].observed);
                assert_eq!(rec.conditions[0].match_count, 0);
                assert!(rec.conditions[0].result, "unsatisfied expected + observed=false -> result true -> rule matches");
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn canonical_demo_allows_push_after_a_successful_test_this_session() {
        let policy = canonical_policy();
        let events = vec![ev("claude-code__bash", true, 500, Some("npm test"))];
        let decision = policy.evaluate(&events, "claude-code__bash", Some("git push origin main"), 1000);
        assert_eq!(decision, TemporalDecision::Pass);
    }

    #[test]
    fn a_non_matching_action_never_triggers_the_rule() {
        let policy = canonical_policy();
        let decision = policy.evaluate(&[], "claude-code__write", None, 1000);
        assert_eq!(decision, TemporalDecision::Pass);
    }

    #[test]
    fn command_matching_is_case_sensitive_substring_not_glob() {
        let s = sel("claude-code__bash", Some("npm test"));
        assert!(s.matches_current("claude-code__bash", Some("cd repo && npm test -- --watch")));
        assert!(!s.matches_current("claude-code__bash", Some("NPM TEST")), "case-sensitive");
        assert!(!s.matches_current("claude-code__bash", Some("npm run test")), "literal substring, not token-aware");
    }

    // ── conjunction: every `when:` condition must hold ────────────────────────────────────────────
    #[test]
    fn when_is_a_conjunction_of_every_condition() {
        let mut policy = canonical_policy();
        // Add a second condition that can never be satisfied.
        policy.rules[0].when.push(Condition {
            predicate: Predicate::Happened,
            selector: sel("claude-code__bash", Some("impossible-command-xyz")),
            expect: Expect::Satisfied,
            cmp: None,
            n: None,
            t: None,
        });
        let events = vec![ev("claude-code__bash", true, 500, Some("npm test"))];
        // First condition (succeeded npm test, expect unsatisfied) is now FALSE (test did succeed).
        // Second condition (happened impossible-command, expect satisfied) is also FALSE.
        // Neither condition holds its `expect` -> rule does not match -> Pass either way here,
        // but flip to a scenario where the FIRST holds and the SECOND does not:
        let decision = policy.evaluate(&events, "claude-code__bash", Some("git push"), 1000);
        assert_eq!(decision, TemporalDecision::Pass, "the impossible second condition can never hold, so the AND never matches");
    }

    // ── tighten-only (axiom 5) ─────────────────────────────────────────────────────────────────────
    #[test]
    fn a_matched_allow_tier_rule_is_always_a_no_op_pass() {
        let policy = TemporalPolicy {
            rules: vec![TemporalRule {
                id: "loosen-attempt".to_string(),
                selector: sel("claude-code__bash", None),
                tier: Tier::Allow,
                when: vec![],
                on_unavailable: None,
            }],
        };
        // No `when:` conditions at all -> trivially "matches" -> still must be Pass, never anything
        // that could be read as re-opening a base Deny.
        let decision = policy.evaluate(&[], "claude-code__bash", Some("anything"), 1000);
        assert_eq!(decision, TemporalDecision::Pass);
    }

    #[test]
    fn first_match_wins_across_multiple_rules() {
        let policy = TemporalPolicy {
            rules: vec![
                TemporalRule {
                    id: "first".to_string(),
                    selector: sel("claude-code__bash", Some("git push")),
                    tier: Tier::Deny,
                    when: vec![],
                    on_unavailable: None,
                },
                TemporalRule {
                    id: "second".to_string(),
                    selector: sel("claude-code__bash", Some("git push")),
                    tier: Tier::Approval,
                    when: vec![],
                    on_unavailable: None,
                },
            ],
        };
        let decision = policy.evaluate(&[], "claude-code__bash", Some("git push"), 1000);
        match decision {
            TemporalDecision::Deny(rec) => assert_eq!(rec.rule_id, "first"),
            other => panic!("expected the FIRST rule to win, got {other:?}"),
        }
    }

    // ── on_unavailable defaults (D2) ───────────────────────────────────────────────────────────────
    #[test]
    fn on_unavailable_defaults_per_tier() {
        assert_eq!(default_on_unavailable(Tier::Deny), OnUnavailable::FailClosed);
        assert_eq!(default_on_unavailable(Tier::Approval), OnUnavailable::RequireApproval);
        assert_eq!(default_on_unavailable(Tier::Allow), OnUnavailable::FailOpen);
    }

    #[test]
    fn on_unavailable_posture_uses_authored_override_when_present() {
        let rule = TemporalRule {
            id: "x".to_string(),
            selector: sel("claude-code__bash", Some("git push")),
            tier: Tier::Deny,
            when: vec![],
            on_unavailable: Some(OnUnavailable::FailOpen),
        };
        assert_eq!(rule.on_unavailable_posture(), OnUnavailable::FailOpen);
    }

    #[test]
    fn first_matching_rule_finds_the_first_rule_whose_subject_matches_the_current_action() {
        let policy = canonical_policy();
        assert!(policy.first_matching_rule("claude-code__bash", Some("git push origin main")).is_some());
        assert!(policy.first_matching_rule("claude-code__write", None).is_none());
    }

    // ── the receipt trace is content-free (D4) ────────────────────────────────────────────────────
    #[test]
    fn cond_record_never_carries_the_agents_command_text_as_a_bare_field() {
        let policy = canonical_policy();
        let decision = policy.evaluate(&[], "claude-code__bash", Some("git push origin main --force"), 1000);
        let TemporalDecision::Deny(rec) = decision else { panic!("expected Deny") };
        let json = serde_json::to_value(&rec).unwrap();
        let text = json.to_string();
        // The subject selector and condition selectors are operator-authored PATTERNS ("git push",
        // "npm test") — those are expected. The agent's actual command ("--force") must not appear.
        assert!(!text.contains("--force"), "the agent's own command text leaked into the receipt: {text}");
    }
}

// ─── F-2 — Action gates (kriya-console doc 31 §3.3 / the F2-gates design doc (kriya-console)) ─────────────
// The Console-compiled matcher rules for the high-stakes action classes. The engine is policy
// authoring + receipt vocabulary over the EXISTING enforcement path — evaluated by the hook `pre`
// lane in the exact tighten-only slot/idiom of the B4 temporal block: a gate can escalate an
// already-resolved Allow/granted-approval to approval/deny, never loosen a Deny.
//
// Matching is over regex patterns (the `regex-lite` crate: zero transitive deps, ASCII semantics
// shared with the Console's JS `RegExp` evaluation of the SAME table — see the design's §2 dialect
// note and the cross-repo `gate-matcher-vectors.json` parity test). This is a deliberate,
// documented departure from B4's substring-only `CommandMatch`: B4 selectors are OPERATOR-authored
// free text (worst-case ambiguity — substring is the honest ceiling there); gate rules are
// PRODUCT-defined vocabulary compiled from one audited table and parity-locked across both
// implementations.

/// Gate tier — `allow | receipt | approve | deny`, mapping onto the existing decision semantics:
/// `approve` ≡ [`Decision::RequiresApproval`] (same approval gate flow), `deny` ≡
/// [`Decision::Deny`] (same exit-2 block), `receipt` ≡ Allow + a `kriya.gate.<class>.evaluated`
/// receipt, `allow` ≡ Allow with no gate receipt (the action receipt itself always exists).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GateTier {
    Allow,
    Receipt,
    Approve,
    Deny,
}

/// One tool-name matcher: `tool` regex (+ optional `server` regex — a rule with `server` never
/// matches a call that has no server component).
#[derive(Debug, Clone, Deserialize)]
pub struct GateToolMatcher {
    pub tool: String,
    #[serde(default)]
    pub server: Option<String>,
}

/// The outbound-send class's recipient split (design §4): when `internal_domains` is configured
/// and EVERY recipient domain found in the tool input is internal, the rule's `internal_tier`
/// applies instead of its primary tier. Receipts record only `internal|external|unknown` + a
/// count — never an address.
#[derive(Debug, Clone, Deserialize)]
pub struct SendGateConfig {
    #[serde(default)]
    pub internal_domains: Vec<String>,
    #[serde(default = "default_internal_tier")]
    pub internal_tier: GateTier,
}

fn default_internal_tier() -> GateTier {
    GateTier::Receipt
}

/// One compiled gate rule. Exactly one matcher kind is populated (`command_any` / `path_any` /
/// `tool_any`); the Console compiler guarantees this, and a rule with none never matches.
/// Rules are evaluated IN ORDER; the first match wins (the house `rules` idiom — prod/non-prod
/// and protected/unprotected splits are two ordered rules of the same class).
#[derive(Debug, Clone, Deserialize)]
pub struct GateRule {
    pub class: String,
    pub rule_id: String,
    pub tier: GateTier,
    /// ≥1 must match the Bash `command` string.
    #[serde(default)]
    pub command_any: Vec<String>,
    /// ALL must match (same command).
    #[serde(default)]
    pub command_all: Vec<String>,
    /// NONE may match (same command).
    #[serde(default)]
    pub command_not: Vec<String>,
    /// ≥1 must match the `file_path` param — or any whitespace token of a Bash command
    /// (`cat .env`, `echo x > ~/.claude/settings.json`).
    #[serde(default)]
    pub path_any: Vec<String>,
    /// ≥1 must match the (tool, server) pair.
    #[serde(default)]
    pub tool_any: Vec<GateToolMatcher>,
    /// Outbound-send recipient split (send-class rules only).
    #[serde(default)]
    pub send: Option<SendGateConfig>,
}

/// The `gates:` policy section. The Console's `classes` authoring key rides the same YAML but is
/// deliberately not modeled here (serde ignores unknown fields) — `rules` is the enforcement truth.
#[derive(Debug, Clone, Deserialize)]
pub struct GatePolicy {
    #[serde(default)]
    pub rules: Vec<GateRule>,
}

/// The privacy-audited receipt payload for `kriya.gate.<class>.*` (design §5): ids, class, tier,
/// matcher kind, the action id, recipient CLASS — never command content (the blocked attempt's own
/// action receipt carries the params; the gate receipt points at it via `corr_step`, added by the
/// hook at record time).
#[derive(Debug, Clone, Serialize)]
pub struct GateRecord {
    pub class: String,
    pub rule_id: String,
    pub tier: GateTier,
    /// `command` | `path` | `tool`.
    pub matcher_kind: &'static str,
    pub action_id: String,
    /// Send-class rules only: `internal` | `external` | `unknown`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipients_class: Option<&'static str>,
    /// Send-class rules only: how many recipient strings were found.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipients_count: Option<usize>,
}

/// The gate's tighten-only decision for one pre-exec evaluation.
#[derive(Debug, Clone)]
pub enum GateDecision {
    /// No rule matched, or the matched tier is `allow`.
    Pass,
    /// `receipt` tier: record `kriya.gate.<class>.evaluated` and proceed.
    Receipt(GateRecord),
    /// `approve` tier: run the existing approval gate; `approved`/`held` receipts follow.
    Approval(GateRecord),
    /// `deny` tier: block (exit 2) with a `denied` receipt.
    Deny(GateRecord),
}

/// Compile a pattern, tolerating an invalid one as never-matching. An invalid pattern is a
/// Console-compiler bug, not an operator error — failing closed here would brick every action on
/// a typo'd custom pattern, a worse failure than one silent matcher (the parity vectors test is
/// the guard against silent drift).
fn gate_re(pattern: &str) -> Option<regex_lite::Regex> {
    regex_lite::Regex::new(pattern).ok()
}

fn any_match(patterns: &[String], text: &str) -> bool {
    patterns
        .iter()
        .any(|p| gate_re(p).is_some_and(|re| re.is_match(text)))
}

fn all_match(patterns: &[String], text: &str) -> bool {
    patterns
        .iter()
        .all(|p| gate_re(p).is_some_and(|re| re.is_match(text)))
}

/// Recipient field names scanned for the send split — the common MCP send-tool shapes.
const RECIPIENT_FIELDS: [&str; 6] = ["to", "cc", "bcc", "recipient", "recipients", "email"];

/// Collect recipient-ish strings from the tool input (string or array-of-string fields).
fn recipient_strings(tool_input: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let Some(map) = tool_input.as_object() else {
        return out;
    };
    for field in RECIPIENT_FIELDS {
        match map.get(field) {
            Some(Value::String(s)) => out.push(s.clone()),
            Some(Value::Array(items)) => {
                out.extend(items.iter().filter_map(Value::as_str).map(str::to_string));
            }
            _ => {}
        }
    }
    out
}

/// The domain after the last `@`, lowercased, trailing punctuation trimmed. `None` when the
/// string is not address-shaped.
fn domain_of(recipient: &str) -> Option<String> {
    let at = recipient.rfind('@')?;
    let domain: String = recipient[at + 1..]
        .trim_end_matches(['>', ')', '"', '\'', ',', ';'])
        .to_ascii_lowercase();
    if domain.is_empty() {
        None
    } else {
        Some(domain)
    }
}

impl GatePolicy {
    /// Evaluate the ordered rules against one pre-exec tool call. `tool_name` is the raw hook
    /// payload tool name (`Bash`, `Edit`, `mcp__server__tool`, …); extraction mirrors the
    /// Console's `severity.ts` exactly (the parity vectors lock this).
    pub fn evaluate(&self, tool_name: &str, tool_input: &Value, action_id: &str) -> GateDecision {
        let command = if tool_name.eq_ignore_ascii_case("bash") {
            tool_input.get("command").and_then(Value::as_str)
        } else {
            None
        };
        let file_path = tool_input.get("file_path").and_then(Value::as_str);
        // `mcp__<server>__<tool>` → (server, tool); a bare non-builtin name is a gateway tool.
        let (server, mcp_tool) = if let Some(rest) = tool_name.strip_prefix("mcp__") {
            match rest.split_once("__") {
                Some((s, t)) => (Some(s), Some(t)),
                None => (Some(rest), Some(rest)),
            }
        } else {
            (None, Some(tool_name))
        };

        for rule in &self.rules {
            let (matched_kind, mut tier) = if !rule.command_any.is_empty() {
                let Some(cmd) = command else { continue };
                if !any_match(&rule.command_any, cmd)
                    || !all_match(&rule.command_all, cmd)
                    || rule.command_not.iter().any(|p| gate_re(p).is_some_and(|re| re.is_match(cmd)))
                {
                    continue;
                }
                ("command", rule.tier)
            } else if !rule.path_any.is_empty() {
                // The file_path lane gates WRITE-shaped tools only (Edit/Write/NotebookEdit — the
                // self-mod class is "agent WRITES its own config"); a Read of the same path is the
                // view layer's business, never a block. The Bash token lane stays strict both ways:
                // shell read-vs-write is not parseable (the B4 ambiguity), so a command touching a
                // gated path is gated regardless.
                let read_like = tool_name.eq_ignore_ascii_case("read")
                    || tool_name.eq_ignore_ascii_case("grep")
                    || tool_name.eq_ignore_ascii_case("glob");
                let path_hit =
                    !read_like && file_path.is_some_and(|p| any_match(&rule.path_any, p));
                let token_hit = !path_hit
                    && command.is_some_and(|cmd| {
                        cmd.split_ascii_whitespace().any(|tok| any_match(&rule.path_any, tok))
                    });
                if !path_hit && !token_hit {
                    continue;
                }
                ("path", rule.tier)
            } else if !rule.tool_any.is_empty() {
                let Some(tool) = mcp_tool else { continue };
                // Builtin file/shell tools are never MCP-shaped — a tool rule must not match
                // `Bash`/`Edit` themselves (their governance is the command/path lanes above).
                if tool_name.eq_ignore_ascii_case("bash")
                    || tool_name.eq_ignore_ascii_case("edit")
                    || tool_name.eq_ignore_ascii_case("write")
                    || tool_name.eq_ignore_ascii_case("read")
                {
                    continue;
                }
                let hit = rule.tool_any.iter().any(|m| {
                    let tool_ok = gate_re(&m.tool).is_some_and(|re| re.is_match(tool));
                    match &m.server {
                        Some(srv_pat) => {
                            server.is_some_and(|s| gate_re(srv_pat).is_some_and(|re| re.is_match(s)))
                                && tool_ok
                        }
                        None => tool_ok,
                    }
                });
                if !hit {
                    continue;
                }
                ("tool", rule.tier)
            } else {
                continue; // a rule with no matcher never matches
            };

            // Outbound-send split: all-internal recipients demote to the internal tier;
            // unknown (no recipient field found) stays at the rule's primary tier — fail-visible.
            let mut recipients_class = None;
            let mut recipients_count = None;
            if let Some(send) = &rule.send {
                let recipients = recipient_strings(tool_input);
                recipients_count = Some(recipients.len());
                if recipients.is_empty() {
                    recipients_class = Some("unknown");
                } else {
                    let domains: Vec<String> =
                        recipients.iter().filter_map(|r| domain_of(r)).collect();
                    let all_internal = !domains.is_empty()
                        && domains.iter().all(|d| {
                            send.internal_domains.iter().any(|i| i.eq_ignore_ascii_case(d))
                        });
                    if all_internal {
                        recipients_class = Some("internal");
                        tier = send.internal_tier;
                    } else {
                        recipients_class = Some("external");
                    }
                }
            }

            let record = GateRecord {
                class: rule.class.clone(),
                rule_id: rule.rule_id.clone(),
                tier,
                matcher_kind: matched_kind,
                action_id: action_id.to_string(),
                recipients_class,
                recipients_count,
            };
            return match tier {
                GateTier::Allow => GateDecision::Pass,
                GateTier::Receipt => GateDecision::Receipt(record),
                GateTier::Approve => GateDecision::Approval(record),
                GateTier::Deny => GateDecision::Deny(record),
            };
        }
        GateDecision::Pass
    }
}

#[cfg(test)]
mod gate_tests {
    use super::*;
    use serde_json::json;

    fn gates_yaml(yaml: &str) -> GatePolicy {
        let p: Policy = serde_yaml::from_str(yaml).expect("policy parses");
        p.gates.expect("gates section present")
    }

    /// A minimal hand-authored gates section covering every matcher kind + the doc-30 incident
    /// shapes. The Console-compiled default set is exercised by `tests/gate_vectors.rs` over the
    /// committed `default-gates.yaml` + `gate-matcher-vectors.json` (the cross-repo parity lock).
    fn sample() -> GatePolicy {
        gates_yaml(
            r#"
rules: [{action: "*", allow: true}]
gates:
  rules:
    - class: destructive-git
      rule_id: git-force-push--protected
      tier: deny
      command_any: ["\\bgit\\s+push\\b[^|;&]*(\\s--force(-with-lease)?\\b|\\s-f\\b)"]
      command_all: ["(?:\\bmain\\b|\\brelease/)"]
    - class: destructive-git
      rule_id: git-force-push
      tier: receipt
      command_any: ["\\bgit\\s+push\\b[^|;&]*(\\s--force(-with-lease)?\\b|\\s-f\\b)"]
    - class: publish
      rule_id: npm-publish
      tier: approve
      command_any: ["\\b(npm|pnpm|yarn)\\s+publish\\b"]
    - class: prod-db
      rule_id: prisma-migrate-deploy
      tier: approve
      command_any: ["\\bprisma\\s+migrate\\s+deploy\\b"]
      command_not: ["(?i)\\b(localhost|127\\.0\\.0\\.1|preview|branch|staging|dev|test)\\b"]
    - class: self-mod
      rule_id: self-config-path
      tier: deny
      path_any: ["(?i)(^|/)\\.claude/settings[^/]*$|(^|/)\\.claude/hooks(/|$)|(^|/)\\.?mcp\\.json$"]
    - class: send
      rule_id: send-tool
      tier: approve
      tool_any: [{tool: "(?i)(^|_|\\b)(send|post)_(email|mail|message|dm|sms)\\b|^send_|_send$"}]
      send: {internal_domains: ["acme.com"], internal_tier: receipt}
"#,
        )
    }

    #[test]
    fn force_push_to_protected_ref_denies_and_elsewhere_receipts() {
        let g = sample();
        let d = g.evaluate("Bash", &json!({"command": "git push --force origin main"}), "claude-code__bash");
        assert!(matches!(d, GateDecision::Deny(ref r) if r.rule_id == "git-force-push--protected"));
        let d = g.evaluate("Bash", &json!({"command": "git push -f origin feat/x"}), "claude-code__bash");
        assert!(matches!(d, GateDecision::Receipt(ref r) if r.rule_id == "git-force-push"));
    }

    #[test]
    fn npm_publish_routes_to_approval_and_plain_push_passes() {
        let g = sample();
        assert!(matches!(
            g.evaluate("Bash", &json!({"command": "npm publish --access public"}), "claude-code__bash"),
            GateDecision::Approval(ref r) if r.class == "publish"
        ));
        assert!(matches!(
            g.evaluate("Bash", &json!({"command": "git push origin feat/x"}), "claude-code__bash"),
            GateDecision::Pass
        ));
    }

    #[test]
    fn prisma_migrate_deploy_gated_on_prod_but_not_on_branch_urls() {
        let g = sample();
        assert!(matches!(
            g.evaluate("Bash", &json!({"command": "DATABASE_URL=postgres://prod-db/main prisma migrate deploy"}), "claude-code__bash"),
            GateDecision::Approval(_)
        ));
        assert!(matches!(
            g.evaluate("Bash", &json!({"command": "DATABASE_URL=postgres://localhost/dev prisma migrate deploy"}), "claude-code__bash"),
            GateDecision::Pass
        ));
    }

    #[test]
    fn hooks_file_edit_denies_via_path_and_via_command_token() {
        let g = sample();
        assert!(matches!(
            g.evaluate("Edit", &json!({"file_path": "/Users/x/.claude/settings.json"}), "claude-code__edit"),
            GateDecision::Deny(ref r) if r.class == "self-mod" && r.matcher_kind == "path"
        ));
        assert!(matches!(
            g.evaluate("Bash", &json!({"command": "echo '{}' > /Users/x/.claude/settings.json"}), "claude-code__bash"),
            GateDecision::Deny(ref r) if r.matcher_kind == "path"
        ));
    }

    #[test]
    fn send_split_internal_receipts_external_approves_unknown_stays_strict() {
        let g = sample();
        let d = g.evaluate("mcp__gmail__send_email", &json!({"to": "a@acme.com"}), "claude-code__mcp__gmail__send_email");
        assert!(matches!(d, GateDecision::Receipt(ref r) if r.recipients_class == Some("internal")));
        let d = g.evaluate("mcp__gmail__send_email", &json!({"to": ["a@acme.com", "b@other.io"]}), "claude-code__mcp__gmail__send_email");
        assert!(matches!(d, GateDecision::Approval(ref r) if r.recipients_class == Some("external")));
        let d = g.evaluate("mcp__gmail__send_email", &json!({"subject": "hi"}), "claude-code__mcp__gmail__send_email");
        assert!(matches!(d, GateDecision::Approval(ref r) if r.recipients_class == Some("unknown")));
    }

    #[test]
    fn absent_gates_section_means_no_consult_and_receipts_never_leak_command_content() {
        let p: Policy = serde_yaml::from_str(r#"rules: [{action: "*", allow: true}]"#).unwrap();
        assert!(p.gates().is_none());
        let g = sample();
        let GateDecision::Deny(rec) =
            g.evaluate("Bash", &json!({"command": "git push --force origin main --secret-token abc123"}), "claude-code__bash")
        else {
            panic!("expected deny");
        };
        let text = serde_json::to_value(&rec).unwrap().to_string();
        assert!(!text.contains("abc123"), "command content leaked into the gate receipt: {text}");
        assert!(!text.contains("--force"), "command content leaked into the gate receipt: {text}");
    }

    #[test]
    fn tool_rules_never_match_builtin_bash_or_edit() {
        let g = gates_yaml(
            r#"
rules: [{action: "*", allow: true}]
gates:
  rules:
    - class: send
      rule_id: catchall-tool
      tier: deny
      tool_any: [{tool: ".*"}]
"#,
        );
        assert!(matches!(
            g.evaluate("Bash", &json!({"command": "ls"}), "claude-code__bash"),
            GateDecision::Pass
        ));
        assert!(matches!(
            g.evaluate("mcp__gmail__send_email", &json!({}), "claude-code__mcp__gmail__send_email"),
            GateDecision::Deny(_)
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spend_state::SpendState;

    #[test]
    fn default_policy_decisions() {
        let p = Policy::default();
        assert_eq!(p.check("create_note"), Decision::Allow);
        assert_eq!(p.check("edit_note"), Decision::Allow);
        assert_eq!(p.check("delete_note"), Decision::RequiresApproval);
        assert_eq!(p.check("wire_money"), Decision::Deny);
    }

    fn policy_from(yaml: &str) -> Policy {
        serde_yaml::from_str(yaml).unwrap()
    }

    #[test]
    fn warn_on_wildcard_allow() {
        let p = policy_from(
            r#"
rules:
  - action: "*"
    allow: true
budget:
  max_actions_per_minute: 60
"#,
        );
        let warns = p.warnings();
        assert!(
            warns
                .iter()
                .any(|w| w.contains("catch-all") && w.contains("defeats")),
            "got: {warns:?}"
        );
    }

    #[test]
    fn warn_on_destructive_named_action_without_approval() {
        let p = policy_from(
            r#"
rules:
  - action: "delete_note"
    allow: true
    require_approval: false
  - action: "purge_db"
    allow: true
    require_approval: false
  - action: "*"
    allow: false
budget:
  max_actions_per_minute: 60
"#,
        );
        let warns = p.warnings();
        assert_eq!(
            warns
                .iter()
                .filter(|w| w.contains("destructive-sounding"))
                .count(),
            2
        );
    }

    #[test]
    fn warn_on_missing_budget_and_missing_wildcard() {
        let p = policy_from(
            r#"
rules:
  - action: "create_*"
    allow: true
"#,
        );
        let warns = p.warnings();
        assert!(
            warns.iter().any(|w| w.contains("no explicit catch-all")),
            "got: {warns:?}"
        );
        assert!(
            warns
                .iter()
                .any(|w| w.contains("budget.max_actions_per_minute")),
            "got: {warns:?}"
        );
    }

    #[test]
    fn on_device_flag_parses_and_defaults_off() {
        // Absent → off (backward compatible).
        let off = policy_from(
            r#"
rules:
  - action: "*"
    allow: false
"#,
        );
        assert!(!off.on_device());
        // Explicitly sealed.
        let on = policy_from(
            r#"
rules:
  - action: "*"
    allow: false
on_device: true
"#,
        );
        assert!(on.on_device());
    }

    #[test]
    fn budget_caps_parse_and_default_to_none() {
        // Absent → no caps (backward compatible).
        let none = policy_from(
            r#"
rules:
  - action: "*"
    allow: false
"#,
        );
        assert_eq!(none.max_actions_per_minute(), None);
        assert_eq!(none.max_api_calls_per_hour(), None);
        // Both caps set, independently.
        let set = policy_from(
            r#"
rules:
  - action: "*"
    allow: false
budget:
  max_actions_per_minute: 60
  max_api_calls_per_hour: 500
"#,
        );
        assert_eq!(set.max_actions_per_minute(), Some(60));
        assert_eq!(set.max_api_calls_per_hour(), Some(500));
    }

    #[test]
    fn retry_config_parses_and_defaults_sanely() {
        // Absent → the host's default retry policy (3 retries, 250ms→5s).
        let none = policy_from(
            r#"
rules:
  - action: "*"
    allow: false
"#,
        );
        let def = none.retry_policy();
        assert_eq!(def.max_retries, 3);
        assert_eq!(def.initial_backoff, Duration::from_millis(250));
        assert_eq!(def.max_backoff, Duration::from_secs(5));

        // A partial override leaves the unspecified fields at their defaults.
        let tuned = policy_from(
            r#"
rules:
  - action: "*"
    allow: false
retry:
  max_retries: 5
  initial_backoff_ms: 100
"#,
        );
        let rp = tuned.retry_policy();
        assert_eq!(rp.max_retries, 5);
        assert_eq!(rp.initial_backoff, Duration::from_millis(100));
        assert_eq!(
            rp.max_backoff,
            Duration::from_secs(5),
            "unspecified field keeps the default"
        );

        // Fail-fast: explicit zero retries.
        let off = policy_from(
            r#"
rules:
  - action: "*"
    allow: false
retry:
  max_retries: 0
"#,
        );
        assert_eq!(off.retry_policy().max_retries, 0);
    }

    #[test]
    fn default_proxy_policy_reads_allow_destructive_approve_else_deny() {
        let p = default_proxy_policy();
        // Read-like names allow outright.
        assert_eq!(p.check("get_account"), Decision::Allow);
        assert_eq!(p.check("list_transactions"), Decision::Allow);
        assert_eq!(p.check("search_notes"), Decision::Allow);
        // Destructive / spend names require human approval.
        assert_eq!(p.check("delete_transaction"), Decision::RequiresApproval);
        assert_eq!(p.check("transfer_funds"), Decision::RequiresApproval);
        assert_eq!(p.check("send_payment"), Decision::RequiresApproval);
        assert_eq!(p.check("archive_account"), Decision::RequiresApproval);
        // Anything unrecognized is denied (deny-by-default).
        assert_eq!(p.check("frobnicate"), Decision::Deny);
        assert_eq!(
            p.check("create_note"),
            Decision::Deny,
            "even writes deny unless read-shaped"
        );
        // A budget cap is in force so a runaway agent is bounded.
        assert_eq!(p.max_actions_per_minute(), Some(60));
    }

    #[test]
    fn default_broker_policy_gates_per_upstream_namespace() {
        let p = default_broker_policy(&["github".into(), "linear".into()]);
        // The same read/destructive posture as the proxy default, per namespace.
        assert_eq!(p.check("github__get_issue"), Decision::Allow);
        assert_eq!(p.check("linear__list_projects"), Decision::Allow);
        assert_eq!(p.check("github__delete_repo"), Decision::RequiresApproval);
        assert_eq!(p.check("linear__send_invite"), Decision::RequiresApproval);
        // Non-read, non-destructive names deny — same safe fall-through as the proxy default.
        assert_eq!(p.check("github__create_issue"), Decision::Deny);
        // A namespace the broker didn't declare denies outright.
        assert_eq!(p.check("ghost__get_anything"), Decision::Deny);
        // The flat (un-namespaced) name never matches a broker rule.
        assert_eq!(p.check("get_issue"), Decision::Deny);
        assert_eq!(p.max_actions_per_minute(), Some(60));
    }

    #[test]
    fn clean_policy_emits_no_warnings() {
        let p = policy_from(
            r#"
rules:
  - action: "create_*"
    allow: true
  - action: "delete_*"
    allow: true
    require_approval: true
  - action: "*"
    allow: false
budget:
  max_actions_per_minute: 60
"#,
        );
        let warns = p.warnings();
        assert!(warns.is_empty(), "expected clean, got: {warns:?}");
    }

    // ─── Egress tier (doc 24 §7.3 / EG-2) ────────────────────────────────────────────────────────

    /// **Landmine L1, the mandatory matrix.** A leading-wildcard host pattern (`*.notion.com`) must
    /// match subdomains and the apex — the exact case that silently fails when fed to the PREFIX-only
    /// action matcher. This test both proves `host_matches` is correct AND documents *why* egress
    /// could not simply reuse `matches()`.
    #[test]
    fn l1_host_matcher_handles_leading_wildcards_that_prefix_matching_silently_drops() {
        // The landmine, made explicit: the action matcher strips a TRAILING `*`; a host wildcard is
        // LEADING, so `matches` finds no trailing `*`, falls to exact compare, and never matches.
        assert!(
            !matches("*.notion.com", "api.notion.com"),
            "documents L1: the action prefix matcher silently never matches a leading-wildcard host"
        );

        // The correct suffix matcher: subdomains AND the apex match; look-alikes do NOT.
        assert!(host_matches("*.notion.com", "api.notion.com"));
        assert!(host_matches("*.notion.com", "a.b.notion.com"));
        assert!(host_matches("*.notion.com", "notion.com"), "apex matches");
        assert!(
            !host_matches("*.notion.com", "evilnotion.com"),
            "a look-alike registrable domain must NOT match"
        );
        assert!(
            !host_matches("*.notion.com", "notion.com.evil.com"),
            "a suffix-injection host must NOT match"
        );

        // `*` matches anything; exact matches exactly; matching is case-insensitive.
        assert!(host_matches("*", "anything.example"));
        assert!(host_matches("api.vendor.com", "API.Vendor.COM"));
        assert!(!host_matches("api.vendor.com", "www.vendor.com"));
        // A malformed bare `*.` matches nothing (never an accidental match-all).
        assert!(!host_matches("*.", "vendor.com"));
    }

    fn egress_from(yaml: &str) -> EgressPolicy {
        policy_from(yaml)
            .egress()
            .expect("egress section present")
            .clone()
    }

    #[test]
    fn egress_tiers_allow_approval_deny_by_destination() {
        let e = egress_from(
            r#"
rules:
  - action: "*"
    allow: true
egress:
  unlisted: deny
  rules:
    - host: "*.vendor.com"
      tier: allow
    - host: "api.partner.com"
      tier: approval
    - host: "blocked.example"
      tier: deny
"#,
        );
        assert_eq!(
            e.evaluate("api.vendor.com"),
            EgressDecision::Allow {
                rule: Some("*.vendor.com".into())
            }
        );
        assert_eq!(
            e.evaluate("api.partner.com"),
            EgressDecision::Approval {
                rule: Some("api.partner.com".into())
            }
        );
        assert!(matches!(
            e.evaluate("blocked.example"),
            EgressDecision::Deny { .. }
        ));
        // Unlisted under deny-by-default → Deny (arms the broker startup allowlist check).
        assert!(matches!(
            e.evaluate("random.host"),
            EgressDecision::Deny { .. }
        ));
        assert!(e.is_deny_by_default());
        assert_eq!(e.mode_label(), "deny-by-default");
    }

    #[test]
    fn egress_unlisted_posture_defaults_to_allow_and_supports_defer() {
        // No `unlisted:` → permissive (§7.3: the tier ships OFF/allow, mode printed in the export).
        let permissive = egress_from(
            r#"
rules: [{action: "*", allow: true}]
egress:
  rules:
    - host: "blocked.example"
      tier: deny
"#,
        );
        assert_eq!(
            permissive.evaluate("anything.else"),
            EgressDecision::Allow { rule: None }
        );
        assert_eq!(permissive.mode_label(), "allow-unlisted");

        // `defer` parks an unlisted call at the approval gate instead of hard-denying (B4).
        let defer = egress_from(
            r#"
rules: [{action: "*", allow: true}]
egress:
  unlisted: defer
"#,
        );
        assert_eq!(
            defer.evaluate("new.host"),
            EgressDecision::Approval { rule: None }
        );
        assert_eq!(defer.mode_label(), "defer-unlisted");
    }

    #[test]
    fn egress_byte_budget_is_looked_up_by_matching_pattern() {
        let e = egress_from(
            r#"
rules: [{action: "*", allow: true}]
egress:
  rules:
    - host: "*.vendor.com"
      tier: allow
      budget: { window_secs: 60, max_bytes: 1048576 }
    - host: "nobudget.example"
      tier: allow
"#,
        );
        let (pattern, budget) = e.budget_for("api.vendor.com").expect("budget matched");
        assert_eq!(pattern, "*.vendor.com");
        assert_eq!(budget.window_secs, 60);
        assert_eq!(budget.max_bytes, 1_048_576);
        assert!(e.budget_for("nobudget.example").is_none());
        assert!(e.budget_for("unmatched.host").is_none());
    }

    #[test]
    fn egress_fail_closed_flag_parses_and_defaults_off() {
        let off = egress_from(
            r#"
rules: [{action: "*", allow: true}]
egress:
  rules: []
"#,
        );
        assert!(!off.fail_closed(), "fail-open is the documented default");
        // Ingress recording is its own switch, default OFF even when egress is configured (§6-P3).
        assert!(!off.record_ingress(), "ingress digests are default OFF");
        let on = egress_from(
            r#"
rules: [{action: "*", allow: true}]
egress:
  fail_closed: true
  record_ingress: true
"#,
        );
        assert!(on.fail_closed());
        assert!(on.record_ingress());
    }

    #[test]
    fn egress_absent_by_default_is_backward_compatible() {
        // A policy with no egress section → no egress governance, unchanged behaviour.
        let p = policy_from(r#"rules: [{action: "*", allow: false}]"#);
        assert!(p.egress().is_none());
    }

    // ─── A2A seam (doc 24 §11 B18 / EG-F) ──────────────────────────────────────────────────────────

    #[test]
    fn a2a_absent_by_default_is_backward_compatible() {
        let p = policy_from(r#"rules: [{action: "*", allow: false}]"#);
        assert!(p.a2a().is_none());
        assert!(p.evaluate_a2a_target("any-agent").is_none());
    }

    #[test]
    fn a2a_reuses_the_egress_allowlist_engine_keyed_by_agent_id() {
        let p = policy_from(
            r#"
rules: [{action: "*", allow: true}]
a2a:
  unlisted: deny
  rules:
    - host: "*.trusted-fleet"
      tier: allow
    - host: "quarantined-agent"
      tier: deny
"#,
        );
        assert_eq!(
            p.evaluate_a2a_target("worker.trusted-fleet"),
            Some(EgressDecision::Allow {
                rule: Some("*.trusted-fleet".into())
            })
        );
        assert!(matches!(
            p.evaluate_a2a_target("quarantined-agent"),
            Some(EgressDecision::Deny { .. })
        ));
        // Unlisted under deny-by-default → Deny, same posture semantics as the egress tier.
        assert!(matches!(
            p.evaluate_a2a_target("never-seen-agent"),
            Some(EgressDecision::Deny { .. })
        ));
    }

    /// The EG-F acceptance proof: a YAML shaped EXACTLY like kriya-console's
    /// `control_plane::policy::policy_yaml_from_bundle` produces (top-level `rules`/`egress`/
    /// `detection`, plus `budgets` merged in under a `budget:` key) round-trips through this crate's
    /// own `Policy` and actually enforces — "a bundle with an egress policy converges on a device
    /// and enforces" (doc 24 §11 / EG-F).
    #[test]
    fn a_policy_bundle_shaped_yaml_converges_and_enforces() {
        let p = policy_from(
            r#"
rules:
  - action: "*"
    allow: true
egress:
  unlisted: deny
  rules:
    - host: "*.allowed.example.com"
      tier: allow
    - host: "evil.example.com"
      tier: deny
detection:
  dns_exfil:
    enabled: true
budget:
  max_actions_per_minute: 42
"#,
        );

        let egress = p.egress().expect("the bundle's egress section converged");
        assert_eq!(
            egress.evaluate("api.allowed.example.com"),
            EgressDecision::Allow {
                rule: Some("*.allowed.example.com".into())
            }
        );
        assert!(matches!(
            egress.evaluate("evil.example.com"),
            EgressDecision::Deny { .. }
        ));
        assert!(matches!(egress.evaluate("never-listed.example"), EgressDecision::Deny { .. }));

        let detection = p.detection().expect("the bundle's detection section converged");
        assert!(detection.dns_exfil.as_ref().expect("dns_exfil configured").enabled);

        assert_eq!(p.max_actions_per_minute(), Some(42), "budgets merged under budget: converged");
    }

    #[test]
    fn retention_parses_with_shorter_io_class() {
        // Absent → indefinite retention (pre-EG-2).
        let none = policy_from(r#"rules: [{action: "*", allow: false}]"#);
        assert!(none.retention().is_none());
        // io class is shorter than the default class by design (doc 24 §4.5 / §6-P2).
        let p = policy_from(
            r#"
rules: [{action: "*", allow: false}]
retention:
  io_days: 30
  default_days: 365
"#,
        );
        let r = p.retention().expect("retention configured");
        assert_eq!(r.io_days, Some(30));
        assert_eq!(r.default_days, Some(365));
        assert!(r.io_days.unwrap() < r.default_days.unwrap());
    }

    // ─── Detection pack (doc 24 §11 B5–B12 / EG-P) ──────────────────────────────────────────────

    #[test]
    fn detection_absent_by_default_and_every_sub_detector_independently_gated() {
        let p = policy_from(r#"rules: [{action: "*", allow: true}]"#);
        assert!(
            p.detection().is_none(),
            "opting into nothing changes nothing"
        );

        // Opting into `detection:` at all must NOT silently enable any specific sub-detector.
        let p = policy_from(
            r#"
rules: [{action: "*", allow: true}]
detection: {}
"#,
        );
        let d = p.detection().expect("detection section present");
        assert!(d.dns_exfil.is_none());
        assert!(d.ssrf_guard.is_none());
        assert!(d.secret_pii.is_none());
        assert!(d.operation_rails.is_empty());
        assert!(d.canary_tokens.is_empty());
        assert!(d.connector_registry.is_none());
        assert!(d.read_only.is_empty());
        assert!(d.mcp_response.is_none());
    }

    #[test]
    fn detection_sub_policies_default_to_the_safe_never_auto_block_choice() {
        let p = policy_from(
            r#"
rules: [{action: "*", allow: true}]
detection:
  dns_exfil: {}
  secret_pii: {}
  mcp_response: {}
"#,
        );
        let d = p.detection().unwrap();
        assert_eq!(
            d.dns_exfil.as_ref().unwrap().action,
            AlertOrDeny::Alert,
            "default alert, never deny"
        );
        assert_eq!(
            d.secret_pii.as_ref().unwrap().action,
            RedactOrDeny::Redact,
            "default redact, never deny"
        );
        assert_eq!(
            d.mcp_response.as_ref().unwrap().default_class,
            TrustClass::Scan,
            "default scan, never block"
        );
        assert_eq!(d.dns_exfil.as_ref().unwrap().entropy_threshold, 4.0);
    }

    #[test]
    fn b11_read_only_denies_only_destructive_names_on_a_marked_connector() {
        let p = policy_from(
            r#"
rules:
  - action: "*"
    allow: true
detection:
  read_only: ["widgets"]
"#,
        );
        // Observe: a non-destructive tool on the read-only connector is unaffected.
        assert_eq!(p.check("widgets__list_items"), Decision::Allow);
        assert_eq!(p.check("widgets__get_item"), Decision::Allow);
        // Deny: a destructive-named tool on the read-only connector is hard-denied...
        assert_eq!(p.check("widgets__delete_item"), Decision::Deny);
        assert_eq!(p.check("widgets__wipe_all"), Decision::Deny);
        // False-positive-safety: a DIFFERENT connector's destructive tool is untouched by this
        // preset (governed only by the explicit rules, which here allow everything).
        assert_eq!(p.check("gadgets__delete_item"), Decision::Allow);
    }

    #[test]
    fn b11_read_only_override_cannot_be_widened_back_open_by_an_explicit_allow_rule() {
        // Even an operator-authored rule that explicitly allows the exact destructive action must
        // NOT override the read-only preset — it is a hard override, checked first.
        let p = policy_from(
            r#"
rules:
  - action: "widgets__delete_item"
    allow: true
  - action: "*"
    allow: true
detection:
  read_only: ["widgets"]
"#,
        );
        assert_eq!(
            p.check("widgets__delete_item"),
            Decision::Deny,
            "read-only is a hard override, not just a default"
        );
    }

    // ─── B5: DNS-exfil / subdomain-entropy ───────────────────────────────────────────────────────

    #[test]
    fn max_subdomain_entropy_ignores_the_apex_and_single_label_hosts() {
        assert_eq!(
            max_subdomain_entropy("vendor.com"),
            None,
            "apex only, nothing to inspect"
        );
        assert_eq!(max_subdomain_entropy("localhost"), None, "single label");
        assert!(
            max_subdomain_entropy("api.vendor.com").is_some(),
            "one real subdomain label"
        );
    }

    #[test]
    fn max_subdomain_entropy_stays_well_under_the_default_threshold_for_ordinary_hosts() {
        // False-positive-safety: common, legitimate subdomain shapes must not approach 4.0 bits/char.
        for host in [
            "api.vendor.com",
            "www.example.org",
            "cdn.assets.example.com",
            "eu-west-1.s3.amazonaws.com",
            "docs.github.com",
        ] {
            let e = max_subdomain_entropy(host).unwrap();
            assert!(
                e < 4.0,
                "{host} scored {e:.2}, expected well under the 4.0 default threshold"
            );
        }
    }

    #[test]
    fn max_subdomain_entropy_flags_a_base32_shaped_exfil_payload() {
        // A realistic DNS-exfil shape: encoded payload chunks as subdomain labels.
        let exfil = "khbwy4dxovss4z3jf5xweidwmn2gk4dsn5wg65lsmvzq";
        let e = max_subdomain_entropy(&format!("{exfil}.vendor.com")).unwrap();
        assert!(
            e >= 4.0,
            "expected the encoded payload label to score >= 4.0, got {e:.2}"
        );

        // Multi-label chunking: the flag must fire even if the high-entropy chunk isn't leftmost.
        let chunked = max_subdomain_entropy(&format!("a.b.{exfil}.vendor.com")).unwrap();
        assert!(
            chunked >= 4.0,
            "a high-entropy label anywhere before the apex must be caught, got {chunked:.2}"
        );
    }

    #[test]
    fn shannon_entropy_handles_degenerate_inputs_without_panicking() {
        assert_eq!(shannon_entropy(""), 0.0);
        assert_eq!(shannon_entropy("a"), 0.0);
        assert_eq!(shannon_entropy("aaaa"), 0.0, "zero variety -> zero entropy");
        assert!(shannon_entropy("abcd") > 0.0);
    }

    #[test]
    fn b11_bare_namespace_and_explicit_glob_forms_are_equivalent() {
        let bare = policy_from(
            r#"rules: [{action: "*", allow: true}]
detection: { read_only: ["widgets"] }"#,
        );
        let glob = policy_from(
            r#"rules: [{action: "*", allow: true}]
detection: { read_only: ["widgets__*"] }"#,
        );
        for p in [bare, glob] {
            assert_eq!(p.check("widgets__delete_item"), Decision::Deny);
        }
    }

    // ─── F1 model-identity gate (doc 28 §F1) ─────────────────────────────────────────────────────

    #[test]
    fn model_policy_default_warns_on_every_digest_never_blocking() {
        let policy = ModelPolicy::default();
        for digest in [Some("some-digest"), None] {
            let d = policy.evaluate(digest);
            assert!(matches!(d, ModelGateDecision::Warn { .. }), "{d:?}");
            assert!(!d.blocks());
            assert_eq!(d.facet(), "warn");
        }
    }

    #[test]
    fn model_policy_approved_digest_is_allowed() {
        let policy = ModelPolicy {
            approved: vec![ApprovedModelRule {
                digest: "abc123".to_string(),
                tier: EgressTier::Allow,
                label: None,
            }],
            unknown_model: UnknownModelAction::Warn,
        };
        let d = policy.evaluate(Some("abc123"));
        assert_eq!(
            d,
            ModelGateDecision::Allow {
                rule: Some("abc123".to_string())
            }
        );
        assert!(!d.blocks());
        assert_eq!(d.facet(), "allow");
        assert_eq!(d.matched_rule(), Some("abc123"));

        // A DIFFERENT digest is still unknown -> the default (warn) applies.
        let d2 = policy.evaluate(Some("other-digest"));
        assert!(matches!(d2, ModelGateDecision::Warn { .. }));
    }

    #[test]
    fn model_policy_per_digest_deny_and_approval_tiers_block() {
        let policy = ModelPolicy {
            approved: vec![
                ApprovedModelRule {
                    digest: "denied-digest".to_string(),
                    tier: EgressTier::Deny,
                    label: None,
                },
                ApprovedModelRule {
                    digest: "approval-digest".to_string(),
                    tier: EgressTier::Approval,
                    label: None,
                },
            ],
            unknown_model: UnknownModelAction::Warn,
        };
        let deny = policy.evaluate(Some("denied-digest"));
        assert_eq!(deny.facet(), "deny");
        assert!(deny.blocks());
        assert_eq!(deny.matched_rule(), Some("denied-digest"));

        let approval = policy.evaluate(Some("approval-digest"));
        assert_eq!(approval.facet(), "approval_required");
        assert!(
            approval.blocks(),
            "no sync approval channel in v1 — refused honestly"
        );
    }

    #[test]
    fn model_policy_unknown_model_deny_blocks_and_require_approval_blocks() {
        let deny_policy = ModelPolicy {
            approved: vec![],
            unknown_model: UnknownModelAction::Deny,
        };
        let d = deny_policy.evaluate(None);
        assert_eq!(d.facet(), "deny");
        assert!(d.blocks());
        assert_eq!(d.matched_rule(), None);

        let approval_policy = ModelPolicy {
            approved: vec![],
            unknown_model: UnknownModelAction::RequireApproval,
        };
        let a = approval_policy.evaluate(Some("unresolved-but-present"));
        assert_eq!(a.facet(), "approval_required");
        assert!(a.blocks());
    }

    #[test]
    fn model_policy_parses_from_the_same_agent_policy_yaml_shape() {
        let yaml = r#"
rules: [{action: "*", allow: true}]
model:
  approved:
    - digest: "abc123"
      tier: allow
      label: "llama3.1:8b (verified)"
  unknown_model: deny
"#;
        let policy: Policy = serde_yaml::from_str(yaml).expect("model: section parses");
        let model = policy.model().expect("model policy present");
        assert_eq!(model.approved.len(), 1);
        assert_eq!(model.approved[0].digest, "abc123");
        assert_eq!(model.unknown_model, UnknownModelAction::Deny);
    }

    #[test]
    fn model_policy_absent_from_yaml_means_the_default_warn_posture() {
        let yaml = "rules: [{action: \"*\", allow: true}]\n";
        let policy: Policy = serde_yaml::from_str(yaml).expect("parses");
        assert!(policy.model().is_none());
    }

    // ─── F4-wasm — deterministic-execution lane routing (doc 28 §F4) ─────────────────────────────

    #[test]
    fn exec_absent_from_yaml_means_no_routing_at_all() {
        let yaml = "rules: [{action: \"*\", allow: true}]\n";
        let policy: Policy = serde_yaml::from_str(yaml).expect("parses");
        assert!(policy.exec().is_none());
        assert_eq!(policy.resolve_wasm_variant("summarize_text"), None);
    }

    #[test]
    fn exec_policy_parses_from_the_same_agent_policy_yaml_shape() {
        let yaml = r#"
rules: [{action: "*", allow: true}]
exec:
  prefer_deterministic_lane: true
  wasm_variants:
    summarize_text: "tools/text-transform.wasm"
    filter_records: "tools/json-filter.wasm"
"#;
        let policy: Policy = serde_yaml::from_str(yaml).expect("exec: section parses");
        let exec = policy.exec().expect("exec policy present");
        assert!(exec.prefer_deterministic_lane);
        assert_eq!(exec.wasm_variants.len(), 2);
        assert_eq!(
            policy.resolve_wasm_variant("summarize_text"),
            Some("tools/text-transform.wasm")
        );
        assert_eq!(policy.resolve_wasm_variant("filter_records"), Some("tools/json-filter.wasm"));
    }

    #[test]
    fn exec_policy_never_routes_an_unregistered_action() {
        let yaml = r#"
rules: [{action: "*", allow: true}]
exec:
  prefer_deterministic_lane: true
  wasm_variants:
    summarize_text: "tools/text-transform.wasm"
"#;
        let policy: Policy = serde_yaml::from_str(yaml).expect("parses");
        assert_eq!(policy.resolve_wasm_variant("some_other_action"), None);
    }

    #[test]
    fn exec_policy_registry_is_inert_when_the_tier_switch_is_off() {
        // Authoring the registry ahead of flipping the switch must be safe — no surprise routing
        // change just from listing variants.
        let yaml = r#"
rules: [{action: "*", allow: true}]
exec:
  wasm_variants:
    summarize_text: "tools/text-transform.wasm"
"#;
        let policy: Policy = serde_yaml::from_str(yaml).expect("parses");
        assert!(!policy.exec().unwrap().prefer_deterministic_lane, "default is off");
        assert_eq!(
            policy.resolve_wasm_variant("summarize_text"),
            None,
            "a registered variant must not route while the tier switch is off"
        );
    }

    // ─── C2 — endpoint budget gate (doc 27 §4 / docs/design/c2-budget-gate.md) ───────────────────

    #[test]
    fn budgets_absent_from_yaml_means_no_gate_at_all() {
        let yaml = "rules: [{action: \"*\", allow: true}]\n";
        let policy: Policy = serde_yaml::from_str(yaml).expect("parses");
        assert!(policy.budgets().is_none());
    }

    #[test]
    fn budgets_parse_from_the_same_agent_policy_yaml_shape() {
        let yaml = r#"
rules: [{action: "*", allow: true}]
budgets:
  max_staleness_secs: 600
  rules:
    - id: "daily-cap"
      scope: rolling-day
      threshold_usd: 25.0
      action: require-approval
      on_missing_state: fail-closed
"#;
        let policy: Policy = serde_yaml::from_str(yaml).expect("budgets: section parses");
        let budgets = policy.budgets().expect("budgets present");
        assert_eq!(budgets.max_staleness_secs, 600);
        assert_eq!(budgets.rules.len(), 1);
        assert_eq!(budgets.rules[0].id, "daily-cap");
        assert_eq!(budgets.rules[0].scope, BudgetScope::RollingDay);
        assert_eq!(budgets.rules[0].action, BudgetBreachAction::RequireApproval);
        assert_eq!(budgets.rules[0].on_missing_state, Some(OnMissingState::FailClosed));
    }

    #[test]
    fn max_staleness_secs_defaults_to_900_when_omitted() {
        let yaml = "rules: [{action: \"*\", allow: true}]\nbudgets:\n  rules: []\n";
        let policy: Policy = serde_yaml::from_str(yaml).expect("parses");
        assert_eq!(policy.budgets().unwrap().max_staleness_secs, 900);
    }

    fn ctx<'a>(session_id: Option<&'a str>) -> BudgetCtx<'a> {
        BudgetCtx { session_id, os_user: "alice" }
    }

    #[test]
    fn deny_tier_over_threshold_denies() {
        let budgets = BudgetPolicy {
            max_staleness_secs: 900,
            rules: vec![BudgetRule {
                id: "d1".into(),
                scope: BudgetScope::Session,
                threshold_usd: 0.01,
                action: BudgetBreachAction::Deny,
                on_missing_state: None,
            }],
        };
        let state = SpendState::synthetic(Some("sheet-1"), Some("h1"), &[("s1", 0.02, 1_000)], None, None);
        match budgets.check(&state, &ctx(Some("s1")), 1_500) {
            BudgetGateDecision::Deny(r) => {
                assert_eq!(r.budget_id, "d1");
                assert_eq!(r.observed_usd, 0.02);
                assert_eq!(r.threshold_usd, 0.01);
                assert!(!r.state_stale);
                assert_eq!(r.on_missing_state, None);
                assert_eq!(r.state_source, "live-tick");
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn under_threshold_passes() {
        let budgets = BudgetPolicy {
            max_staleness_secs: 900,
            rules: vec![BudgetRule {
                id: "d1".into(),
                scope: BudgetScope::Session,
                threshold_usd: 5.0,
                action: BudgetBreachAction::Deny,
                on_missing_state: None,
            }],
        };
        let state = SpendState::synthetic(None, None, &[("s1", 1.0, 1_000)], None, None);
        assert_eq!(budgets.check(&state, &ctx(Some("s1")), 1_500), BudgetGateDecision::Pass);
    }

    #[test]
    fn missing_state_on_a_deny_rule_fails_closed_by_default() {
        let budgets = BudgetPolicy {
            max_staleness_secs: 900,
            rules: vec![BudgetRule {
                id: "d1".into(),
                scope: BudgetScope::Session,
                threshold_usd: 0.01,
                action: BudgetBreachAction::Deny,
                on_missing_state: None,
            }],
        };
        let state = SpendState::empty();
        match budgets.check(&state, &ctx(Some("s1")), 1_500) {
            BudgetGateDecision::Deny(r) => {
                assert_eq!(r.on_missing_state, Some(OnMissingState::FailClosed));
                assert!(r.state_stale);
                assert_eq!(r.state_source, "none");
            }
            other => panic!("expected fail-closed Deny, got {other:?}"),
        }
    }

    #[test]
    fn missing_state_on_a_require_approval_rule_routes_to_approval_by_default() {
        let budgets = BudgetPolicy {
            max_staleness_secs: 900,
            rules: vec![BudgetRule {
                id: "a1".into(),
                scope: BudgetScope::RollingDay,
                threshold_usd: 25.0,
                action: BudgetBreachAction::RequireApproval,
                on_missing_state: None,
            }],
        };
        let state = SpendState::empty();
        match budgets.check(&state, &ctx(None), 1_500) {
            BudgetGateDecision::Approval(r) => {
                assert_eq!(r.on_missing_state, Some(OnMissingState::RequireApproval));
            }
            other => panic!("expected Approval, got {other:?}"),
        }
    }

    #[test]
    fn missing_state_on_a_warn_rule_fails_open_by_default_but_still_receipts() {
        let budgets = BudgetPolicy {
            max_staleness_secs: 900,
            rules: vec![BudgetRule {
                id: "w1".into(),
                scope: BudgetScope::User,
                threshold_usd: 100.0,
                action: BudgetBreachAction::Warn,
                on_missing_state: None,
            }],
        };
        let state = SpendState::empty();
        match budgets.check(&state, &ctx(None), 1_500) {
            BudgetGateDecision::Warn(r) => {
                assert_eq!(r.on_missing_state, Some(OnMissingState::FailOpen));
            }
            other => panic!("expected Warn, got {other:?}"),
        }
    }

    #[test]
    fn an_explicit_fail_open_override_on_a_deny_rule_is_a_receipted_loosening_never_the_default() {
        let budgets = BudgetPolicy {
            max_staleness_secs: 900,
            rules: vec![BudgetRule {
                id: "d1".into(),
                scope: BudgetScope::Session,
                threshold_usd: 0.01,
                action: BudgetBreachAction::Deny,
                on_missing_state: Some(OnMissingState::FailOpen),
            }],
        };
        let state = SpendState::empty();
        match budgets.check(&state, &ctx(Some("s1")), 1_500) {
            BudgetGateDecision::Warn(r) => {
                assert_eq!(r.on_missing_state, Some(OnMissingState::FailOpen));
                assert_eq!(r.action, BudgetBreachAction::Deny, "the rule's OWN tier is still deny");
            }
            other => panic!("expected an explicit fail-open Warn, got {other:?}"),
        }
    }

    #[test]
    fn stale_state_is_treated_exactly_like_missing_state() {
        let budgets = BudgetPolicy {
            max_staleness_secs: 60, // 1 minute
            rules: vec![BudgetRule {
                id: "d1".into(),
                scope: BudgetScope::Session,
                threshold_usd: 0.01,
                action: BudgetBreachAction::Deny,
                on_missing_state: None,
            }],
        };
        // state as_of_ms = 0, now = 120_000ms (2 minutes) later -> 120s stale, > 60s max.
        let state = SpendState::synthetic(None, None, &[("s1", 0.02, 0)], None, None);
        match budgets.check(&state, &ctx(Some("s1")), 120_000) {
            BudgetGateDecision::Deny(r) => {
                assert!(r.state_stale);
                assert_eq!(r.on_missing_state, Some(OnMissingState::FailClosed));
            }
            other => panic!("expected stale-state Deny, got {other:?}"),
        }
    }

    #[test]
    fn a_session_scope_rule_with_no_session_id_is_missing_state_never_silently_skipped() {
        let budgets = BudgetPolicy {
            max_staleness_secs: 900,
            rules: vec![BudgetRule {
                id: "d1".into(),
                scope: BudgetScope::Session,
                threshold_usd: 0.01,
                action: BudgetBreachAction::Deny,
                on_missing_state: None,
            }],
        };
        let state = SpendState::synthetic(None, None, &[("s1", 100.0, 1_000)], None, None);
        match budgets.check(&state, &ctx(None), 1_500) {
            BudgetGateDecision::Deny(r) => {
                assert_eq!(r.scope_key, "unresolved-session");
            }
            other => panic!("expected fail-closed Deny on unresolvable scope key, got {other:?}"),
        }
    }

    #[test]
    fn strictest_wins_across_multiple_breaching_rules() {
        let budgets = BudgetPolicy {
            max_staleness_secs: 900,
            rules: vec![
                BudgetRule {
                    id: "warn-rule".into(),
                    scope: BudgetScope::Session,
                    threshold_usd: 1.0,
                    action: BudgetBreachAction::Warn,
                    on_missing_state: None,
                },
                BudgetRule {
                    id: "approval-rule".into(),
                    scope: BudgetScope::RollingDay,
                    threshold_usd: 1.0,
                    action: BudgetBreachAction::RequireApproval,
                    on_missing_state: None,
                },
                BudgetRule {
                    id: "deny-rule".into(),
                    scope: BudgetScope::User,
                    threshold_usd: 1.0,
                    action: BudgetBreachAction::Deny,
                    on_missing_state: None,
                },
            ],
        };
        let state = SpendState::synthetic(
            None,
            None,
            &[("s1", 5.0, 1_000)],
            Some((5.0, 1_000)),
            Some((5.0, 1_000)),
        );
        match budgets.check(&state, &ctx(Some("s1")), 1_500) {
            BudgetGateDecision::Deny(r) => assert_eq!(r.budget_id, "deny-rule"),
            other => panic!("expected the strictest (deny) rule to win, got {other:?}"),
        }
    }

    #[test]
    fn action_allow_plus_budget_deny_denies_never_the_reverse() {
        // Mirrors the hook-lane composition row (Red-team b): a budget can only ESCALATE an
        // Allowed action — never loosen a prior deny (which this crate's Policy::check already
        // guarantees by early-returning before the budget consult is ever reached).
        let budgets = BudgetPolicy {
            max_staleness_secs: 900,
            rules: vec![BudgetRule {
                id: "d1".into(),
                scope: BudgetScope::Session,
                threshold_usd: 0.01,
                action: BudgetBreachAction::Deny,
                on_missing_state: None,
            }],
        };
        let state = SpendState::synthetic(None, None, &[("s1", 1.0, 1_000)], None, None);
        assert!(matches!(
            budgets.check(&state, &ctx(Some("s1")), 1_500),
            BudgetGateDecision::Deny(_)
        ));
    }

    #[test]
    fn scope_key_is_hashed_never_the_raw_session_id_or_username() {
        let budgets = BudgetPolicy {
            max_staleness_secs: 900,
            rules: vec![BudgetRule {
                id: "d1".into(),
                scope: BudgetScope::Session,
                threshold_usd: 0.01,
                action: BudgetBreachAction::Deny,
                on_missing_state: None,
            }],
        };
        let state = SpendState::synthetic(None, None, &[("super-secret-session-id", 1.0, 1_000)], None, None);
        match budgets.check(&state, &ctx(Some("super-secret-session-id")), 1_500) {
            BudgetGateDecision::Deny(r) => {
                assert_ne!(r.scope_key, "super-secret-session-id");
                assert_eq!(r.scope_key.len(), 64, "a sha256 hex digest");
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    // ── D1 (doc 27 §4 / docs/design/d1-memory-receipts.md D-6): the `memory:` registry ────────────

    #[test]
    fn memory_absent_when_never_authored_bc3() {
        let p: Policy = serde_yaml::from_str("rules:\n  - action: \"*\"\n    allow: true\n").unwrap();
        assert!(p.memory().is_none(), "no `memory:` key authored ⇒ None, byte-identical to pre-D1");
        assert!(p.memory_registered_for("notes", "create_entities").is_none());
    }

    #[test]
    fn memory_registry_parses_and_looks_up_by_server_and_tool() {
        let yaml = "rules:\n  - action: \"*\"\n    allow: true\nmemory:\n  - server: notes\n    tool: create_entities\n    op: create\n    content_field: entity\n  - server: notes\n    tool: delete_entities\n    op: delete\n";
        let p: Policy = serde_yaml::from_str(yaml).unwrap();
        let entries = p.memory().expect("memory: section present");
        assert_eq!(entries.len(), 2);

        let create = p.memory_registered_for("notes", "create_entities").expect("registered");
        assert_eq!(create.op, crate::memwrite::MemoryOp::Create);
        assert_eq!(create.content_field.as_deref(), Some("entity"));
        assert_eq!(create.op.verb(), crate::memwrite::MemoryVerb::Write);

        let delete = p.memory_registered_for("notes", "delete_entities").expect("registered");
        assert_eq!(delete.op, crate::memwrite::MemoryOp::Delete);
        assert!(delete.content_field.is_none());

        // A bare name-looks-like-memory tool that was never registered is NOT found (§D-1's
        // honest default — the heuristic-honesty invariant starts here, at the policy layer).
        assert!(p.memory_registered_for("notes", "save").is_none());
        assert!(p.memory_registered_for("other-server", "create_entities").is_none());
    }

    #[test]
    fn memory_empty_list_is_present_but_matches_nothing() {
        // `memory: []` (explicitly authored, empty) is distinct from absent — still `Some(&[])`,
        // never confused with "not configured".
        let p: Policy = serde_yaml::from_str("rules:\n  - action: \"*\"\n    allow: true\nmemory: []\n").unwrap();
        assert!(p.memory().is_some(), "explicitly empty ⇒ Some(&[]), distinct from absent");
        assert_eq!(p.memory().unwrap().len(), 0);
    }

    // ── governed LLM lane: span scanner, new detectors, `llm:` section ──────────────────────

    fn types(s: &str) -> Vec<&'static str> {
        scan_secrets_pii(s)
    }

    #[test]
    fn aadhaar_verhoeff_shapes() {
        for ok in ["234567890124", "2345 6789 0124", "7890-1234-5674", "id: 234567890124."] {
            assert!(types(ok).contains(&"aadhaar"), "{ok} should match aadhaar");
        }
        for bad in [
            "234567890125",   // checksum fails
            "1234 5678 9012", // phone-like, leading 1
            "034567890124",   // leading 0
            "x234567890124",  // glued to a word
            "2345678901241",  // 13 digits
            "2345 67890 124", // wrong grouping
        ] {
            assert!(!types(bad).contains(&"aadhaar"), "{bad} must not match aadhaar");
        }
    }

    #[test]
    fn email_followed_by_sentence_punctuation_still_matches() {
        let t = "write to jane.doe@example.com. Thanks";
        assert!(types(t).contains(&"email"));
        let spans = scan_secrets_pii_spans(t);
        assert_eq!(&t[spans[0].0.clone()], "jane.doe@example.com");
        assert!(!types("a@b.c.").contains(&"email"));
    }

    #[test]
    fn pan_in_shape() {
        assert!(types("PAN ABCPE1234F on file").contains(&"pan_in"));
        assert!(types("ABCPE1234F").contains(&"pan_in"));
        assert!(!types("ABCDE1234F").contains(&"pan_in"), "4th letter D is not a holder type");
        assert!(!types("XABCPE1234F").contains(&"pan_in"), "word boundary");
        assert!(!types("ABCPE1234FX").contains(&"pan_in"), "word boundary");
        assert!(!types("abcpe1234f").contains(&"pan_in"));
    }

    #[test]
    fn credit_card_tolerates_single_space_or_dash_groups() {
        for ok in [
            "4111111111111111",
            "4111 1111 1111 1111",
            "4111-1111-1111-1111",
            "card: 4111 1111 1111 1111.",
        ] {
            assert!(types(ok).contains(&"credit_card"), "{ok}");
        }
        assert!(!types("4111 1111 1111 1112").contains(&"credit_card"), "Luhn still applies");
        assert!(!types("4111  1111 1111 1111").contains(&"credit_card"), "double space splits the run");
        assert!(!types("2024-01-15 call 555-0100").contains(&"credit_card"));
    }

    #[test]
    fn spans_report_byte_ranges_for_every_type() {
        let text = "a jane@example.com b 4111 1111 1111 1111 c 123-45-6789 d 2345 6789 0124 \
                    e ABCPE1234F f AKIAABCDEFGHIJKLMNOP g ghp_abcdefghijklmnopqrstuvwxyz0123456789 h";
        let spans = scan_secrets_pii_spans(text);
        let got: Vec<(&str, &str)> = spans.iter().map(|(r, t)| (*t, &text[r.clone()])).collect();
        assert_eq!(
            got,
            vec![
                ("email", "jane@example.com"),
                ("credit_card", "4111 1111 1111 1111"),
                ("ssn", "123-45-6789"),
                ("aadhaar", "2345 6789 0124"),
                ("pan_in", "ABCPE1234F"),
                ("aws_access_key", "AKIAABCDEFGHIJKLMNOP"),
                ("github_pat", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"),
            ]
        );
        // The boolean scanner is exactly "the distinct types the span scanner reports".
        let mut distinct: Vec<&str> = Vec::new();
        for (_, t) in &spans {
            if !distinct.contains(t) {
                distinct.push(t);
            }
        }
        let mut b = scan_secrets_pii(text);
        b.sort();
        distinct.sort();
        assert_eq!(b, distinct);
    }

    #[test]
    fn spans_cover_jwt_and_pem_blocks() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N";
        let t = format!("tok {jwt} end");
        let spans = scan_secrets_pii_spans(&t);
        assert_eq!(spans.len(), 1);
        assert_eq!(&t[spans[0].0.clone()], jwt);
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----";
        let t = format!("x {pem} y");
        let spans = scan_secrets_pii_spans(&t);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].1, "private_key");
        assert_eq!(&t[spans[0].0.clone()], pem);
    }

    #[test]
    fn scanners_are_panic_free_on_arbitrary_utf8() {
        let nasty = "é@ü.中文 ☃4111 1111 ✓ -----BEGIN 鍵 PRIVATE KEY eyJé.é. AKIA☃ 2345 6789 0124é";
        let _ = scan_secrets_pii(nasty);
        for (r, _) in scan_secrets_pii_spans(nasty) {
            assert!(nasty.is_char_boundary(r.start) && nasty.is_char_boundary(r.end));
        }
        for i in 0..nasty.len() {
            if nasty.is_char_boundary(i) {
                let _ = scan_secrets_pii_spans(&nasty[i..]);
                let _ = scan_secrets_pii_spans(&nasty[..i]);
            }
        }
    }

    #[test]
    fn llm_section_absent_present_partial_invalid() {
        let p = policy_from("rules: [{action: \"*\", allow: true}]\n");
        assert!(p.llm().is_none(), "absent ⇒ None");
        assert_eq!(LlmPolicy::default().request, LlmContentAction::Redact);
        assert_eq!(LlmPolicy::default().response, LlmContentAction::Redact);
        assert!(LlmPolicy::default().allows_provider(LlmProvider::Openai));
        assert!(LlmPolicy::default().allows_provider(LlmProvider::Anthropic));

        let p = policy_from(
            "rules: [{action: \"*\", allow: true}]\nllm:\n  request: deny\n  response: allow\n  providers: [anthropic]\n",
        );
        let l = p.llm().unwrap();
        assert_eq!(l.request, LlmContentAction::Deny);
        assert_eq!(l.response, LlmContentAction::Allow);
        assert!(!l.allows_provider(LlmProvider::Openai));
        assert!(l.allows_provider(LlmProvider::Anthropic));

        let p = policy_from("rules: [{action: \"*\", allow: true}]\nllm:\n  response: deny\n");
        let l = p.llm().unwrap();
        assert_eq!(l.request, LlmContentAction::Redact, "partial ⇒ defaults fill in");
        assert_eq!(l.response, LlmContentAction::Deny);
        assert_eq!(l.providers.len(), 2);

        for bad in [
            "llm:\n  request: scrub\n",
            "llm:\n  providers: [gemini]\n",
            "llm:\n  requests: deny\n",
        ] {
            let yaml = format!("rules: [{{action: \"*\", allow: true}}]\n{bad}");
            assert!(
                serde_yaml::from_str::<Policy>(&yaml).is_err(),
                "invalid llm section must be a parse error: {bad}"
            );
        }
    }
}
