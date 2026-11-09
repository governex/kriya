//! Router — **one MCP endpoint that multiplexes multiple governed fronts under one Governor**.
//! The broker (`kriya-gateway broker`, W2) is its consumer: a single MCP client config entry
//! points at the broker, and that one stdio session governs N upstream MCP servers at once —
//! every `tools/call` routed to the right front, all through the **same** policy + signer/audit
//! + actor.
//!
//! (Until 2026-08-07 the router also composed the macOS desktop-reach fronts — reach-in +
//! computer-use — since removed to keep the library govern/audit-only; see git history.)
//!
//! ## Why one Governor, not one-per-front
//! A standalone front like [`super::proxy_server::ProxyServer`] wires its own [`Governor`] around
//! its own [`ActionExecutor`]. The router does **not** reimplement fronts — it *composes* their
//! executors behind a single [`RouterExecutor`], wraps that one executor in **one** [`Governor`],
//! and serves the union of their tools. The result: one policy decides every front, one signing key
//! anchors one audit log, one actor attributes every receipt — the operator governs all upstreams
//! from a single, coherent governance posture.
//!
//! ## Namespacing
//! Every front contributes a `(namespace, Vec<Tool>, Box<dyn ActionExecutor>)`. The router renames
//! each tool to `"<ns>__<original_name>"` (namespace + `"__"` + name) in the served union, and the
//! [`RouterExecutor`] splits an incoming `action_id` on the **first** `"__"` back into
//! `(ns, inner)`, looks up the sub-executor for `ns`, and calls it with the *inner* (un-namespaced)
//! name — exactly the name that front's executor already understands. The `"__"` separator is the
//! standard MCP server-prefix convention; namespaces are slugified (runs of non-alphanumerics
//! collapse to a single `_`), so a namespace never contains a doubled underscore and the split is
//! unambiguous.
//!
//! ## Policy semantics
//! **Policy rules match the *namespaced* tool name.** An operator gates `notes__delete_note`, and
//! may use globs against the namespace prefix — e.g. `notes__*` to govern an entire upstream's
//! surface. Both `tools/list` filtering and `tools/call` dispatch use the namespaced name, so what
//! the agent sees and what the policy enforces are the same string.

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::sync::Arc;

use serde_json::{json, Value};

use crate::audit::{Actor, Signer};
use crate::permissions::{Decision, Policy};

use super::approval::ApprovalGate;
use super::executor::{ActionExecutor, ActionOutcome};
use super::governor::{DispatchOutcome, EgressControl, Governor, IngressControl};
use super::jsonrpc::{
    error_code, CallToolParams, CallToolResult, ListToolsResult, Request, Response, Tool,
};

/// The separator joining a namespace to an inner tool name in the served union (`"<ns>__<name>"`).
/// The MCP server-prefix convention; chosen because no synthesized base name contains it.
pub const NS_SEP: &str = "__";

/// One front to be multiplexed: a namespace, the tools it contributes, and the executor that runs
/// them. The router renames every tool to `"<namespace>__<tool.name>"` in the union and routes any
/// matching `tools/call` to `executor` (with the original, un-namespaced inner name).
pub struct Front {
    /// Short, stable namespace for this front — a slug of the upstream's name (e.g. `"notes"`,
    /// `"actual_budget"`). Must not contain [`NS_SEP`].
    pub namespace: String,
    /// The front's tools, with their **original** (un-namespaced) names — the router prefixes them.
    pub tools: Vec<Tool>,
    /// The front's executor, keyed in the [`RouterExecutor`] under `namespace`.
    pub executor: Box<dyn ActionExecutor>,
}

impl Front {
    /// Convenience constructor mirroring the `(namespace, tools, executor)` tuple shape the bin
    /// assembles each front into.
    pub fn new(
        namespace: impl Into<String>,
        tools: Vec<Tool>,
        executor: Box<dyn ActionExecutor>,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            tools,
            executor,
        }
    }
}

/// Multiplexing [`ActionExecutor`] — routes a *namespaced* `action_id` to the right sub-executor.
///
/// `execute("notes__delete_note", …)` splits on the first [`NS_SEP`] into
/// `("notes", "delete_note")`, looks up the `"notes"` sub-executor, and calls it with the
/// inner name `"delete_note"` — the un-namespaced name that front's executor was built to
/// understand. An unknown namespace (or a name with no separator) is a clean failed
/// [`ActionOutcome`], **never a panic** — the governor still signs a failure receipt over it.
pub struct RouterExecutor {
    /// namespace → that front's executor.
    fronts: HashMap<String, Box<dyn ActionExecutor>>,
}

impl RouterExecutor {
    /// Build from a namespace → executor map. The router constructs this from the per-front
    /// executors before wrapping it in the single [`Governor`].
    pub fn new(fronts: HashMap<String, Box<dyn ActionExecutor>>) -> Self {
        Self { fronts }
    }
}

impl ActionExecutor for RouterExecutor {
    fn execute(&mut self, action_id: &str, params: &Value) -> ActionOutcome {
        // Split on the FIRST "__": the namespace is a single token with no separator, but the inner
        // tool name might (in theory) contain more — splitting on the first keeps the inner intact.
        let Some((ns, inner)) = action_id.split_once(NS_SEP) else {
            return ActionOutcome::failed(format!(
                "router: tool '{action_id}' is not namespaced (expected '<front>{NS_SEP}<tool>')"
            ));
        };
        let Some(sub) = self.fronts.get_mut(ns) else {
            return ActionOutcome::failed(format!(
                "router: no front registered for namespace '{ns}' (tool '{action_id}')"
            ));
        };
        // Delegate with the inner (un-namespaced) name — exactly what the sub-executor expects.
        sub.execute(inner, params)
    }

    fn set_call_chain(&mut self, chain: Option<&str>) {
        // Every front sees the same per-call chain; only the one the call routes to will use it.
        for sub in self.fronts.values_mut() {
            sub.set_call_chain(chain);
        }
    }
}

/// One MCP endpoint over many governed fronts. Owns the union tool list (namespaced + policy
/// filtered on serve) and the single [`Governor`] wrapping the [`RouterExecutor`]. The serve loop
/// mirrors [`super::proxy_server::ProxyServer`]: `initialize` / `tools/list` (policy-filtered
/// union) / `tools/call` (→ `governor.dispatch(namespaced_name, …)` → [`CallToolResult`], a block
/// becomes an error *result*, never executed, never signed).
pub struct RouterServer {
    /// Gateway name reported in `initialize`.
    name: String,
    governor: Governor,
    policy: Arc<Policy>,
    /// The namespaced union of every front's tools, served policy-filtered.
    tools: Vec<Tool>,
}

impl RouterServer {
    /// Assemble a router server from the fronts plus the governance parts (the product path).
    ///
    /// The single [`Governor`] needs the [`RouterExecutor`] at construction, so this takes the
    /// fronts and the governor's *parts* (signer / approval / actor / policy), builds the
    /// `RouterExecutor` from the fronts' executors, wraps it in one `Governor`, and stores the
    /// namespaced union of every front's tools. One signer, one policy, one actor, one approval gate
    /// govern every front — that is the whole point of the router.
    pub fn from_parts(
        name: impl Into<String>,
        fronts: Vec<Front>,
        policy: Arc<Policy>,
        signer: Arc<Signer>,
        approval: Box<dyn ApprovalGate>,
        actor: Option<Actor>,
    ) -> Self {
        Self::from_parts_with_egress(name, fronts, policy, signer, approval, actor, None)
    }

    /// Like [`from_parts`](Self::from_parts) but installs egress governance (doc 24 §7.3) on the
    /// single governor. The broker supplies an [`EgressControl`] whose resolver maps a namespaced
    /// `<upstream>__<tool>` action to that upstream's host, so a governed call to a remote MCP
    /// upstream is allowlisted, budgeted, and receipted as `kriya.io.*`. `None` → no egress
    /// governance, identical to `from_parts`.
    pub fn from_parts_with_egress(
        name: impl Into<String>,
        fronts: Vec<Front>,
        policy: Arc<Policy>,
        signer: Arc<Signer>,
        approval: Box<dyn ApprovalGate>,
        actor: Option<Actor>,
        egress: Option<EgressControl>,
    ) -> Self {
        Self::from_parts_with_egress_and_ingress(
            name, fronts, policy, signer, approval, actor, egress, None,
        )
    }

    /// Like [`from_parts_with_egress`](Self::from_parts_with_egress) but additionally installs
    /// ingress governance (doc 24 §11 B12) on the single governor. The broker supplies an
    /// [`IngressControl`] whose resolver maps a namespaced `<upstream>__<tool>` action back to that
    /// upstream's name, so a governed call's RESPONSE is classified by the upstream's trust class
    /// and receipted as `kriya.io.ingress.*`. `None` → no ingress governance, identical to
    /// `from_parts_with_egress`.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts_with_egress_and_ingress(
        name: impl Into<String>,
        fronts: Vec<Front>,
        policy: Arc<Policy>,
        signer: Arc<Signer>,
        approval: Box<dyn ApprovalGate>,
        actor: Option<Actor>,
        egress: Option<EgressControl>,
        ingress: Option<IngressControl>,
    ) -> Self {
        let (tools, executors) = Self::namespace_and_split(fronts);
        let executor = Box::new(RouterExecutor::new(executors));
        let mut governor =
            Governor::new(policy.clone(), signer, approval, executor).with_actor(actor);
        if let Some(e) = egress {
            governor = governor.with_egress(e);
        }
        if let Some(i) = ingress {
            governor = governor.with_ingress(i);
        }
        Self {
            name: name.into(),
            governor,
            policy,
            tools,
        }
    }

    /// Test-friendly variant: take a **pre-built** [`Governor`] (already wrapping a
    /// [`RouterExecutor`] over the same fronts) plus the fronts' tool views to namespace. Lets a
    /// test wire a governor over fake sub-executors and assert routing/policy without the macOS
    /// backends. The `fronts` here carry only `(namespace, tools)` — their executors must already be
    /// inside the supplied governor's `RouterExecutor`, keyed by the same namespaces.
    pub fn with_governor(
        name: impl Into<String>,
        namespaced_tools: Vec<Tool>,
        governor: Governor,
        policy: Arc<Policy>,
    ) -> Self {
        Self {
            name: name.into(),
            governor,
            policy,
            tools: namespaced_tools,
        }
    }

    /// Rename every front's tools to `"<ns>__<name>"` and collect its executor under `ns`. Returns
    /// the namespaced union tool list and the namespace → executor map for the [`RouterExecutor`].
    fn namespace_and_split(
        fronts: Vec<Front>,
    ) -> (Vec<Tool>, HashMap<String, Box<dyn ActionExecutor>>) {
        let mut tools = Vec::new();
        let mut executors: HashMap<String, Box<dyn ActionExecutor>> = HashMap::new();
        for Front {
            namespace,
            tools: front_tools,
            executor,
        } in fronts
        {
            for t in front_tools {
                tools.push(Tool {
                    name: namespaced(&namespace, &t.name),
                    // Descriptions are kept verbatim so the agent still reads "Press the 'Delete'
                    // button" etc.; only the name carries the namespace.
                    description: t.description,
                    input_schema: t.input_schema,
                });
            }
            executors.insert(namespace, executor);
        }
        (tools, executors)
    }

    /// Build just the namespaced union tool list from a set of `(namespace, tools)` views — for the
    /// test path that constructs the governor separately. Mirrors the naming in
    /// [`namespace_and_split`](Self::namespace_and_split).
    pub fn namespaced_tools(fronts: &[(String, Vec<Tool>)]) -> Vec<Tool> {
        let mut out = Vec::new();
        for (ns, tools) in fronts {
            for t in tools {
                out.push(Tool {
                    name: namespaced(ns, &t.name),
                    description: t.description.clone(),
                    input_schema: t.input_schema.clone(),
                });
            }
        }
        out
    }

    /// Set (or clear, with `None`) the cooperative origin chain (C3) for the next request(s): every
    /// receipt the governor signs carries it as the `chain` param, and an HTTP upstream's
    /// `tools/call` carries it as `X-Kriya-Chain`. The HTTP serve mode sets it per request and clears
    /// it afterwards; the stdio serve loop never sets it (receipts stay byte-identical).
    pub fn set_call_chain(&mut self, chain: Option<Vec<String>>) {
        self.governor.set_call_chain(chain);
    }

    /// Total tools across all fronts (pre-policy) — for the startup banner.
    pub fn tool_count(&self) -> usize {
        self.tools.len()
    }

    /// Tools the agent will actually see after policy filtering on the **namespaced** name — banner.
    pub fn visible_tool_count(&self) -> usize {
        self.tools
            .iter()
            .filter(|t| self.policy.check(&t.name) != Decision::Deny)
            .count()
    }

    /// Read newline-delimited client JSON-RPC from `reader`, write responses to `writer`. Blocks
    /// until EOF. NDJSON framing identical to every other front, so the same MCP clients drive it.
    pub fn serve<R: BufRead, W: Write>(
        &mut self,
        reader: R,
        writer: &mut W,
    ) -> std::io::Result<()> {
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let response = match serde_json::from_str::<Request>(&line) {
                Ok(req) => self.handle(req),
                Err(e) => Some(Response::error(
                    Value::Null,
                    error_code::PARSE_ERROR,
                    format!("parse error: {e}"),
                )),
            };
            if let Some(resp) = response {
                writeln!(writer, "{}", resp.to_line())?;
                writer.flush()?;
            }
        }
        Ok(())
    }

    /// Route one parsed client request. Returns `None` for a notification (no reply owed). There is
    /// no single downstream to forward notifications to (each front has its own downstream), so a
    /// notification is accepted and dropped.
    pub fn handle(&mut self, req: Request) -> Option<Response> {
        if req.is_notification() {
            return None;
        }
        let id = req.id.clone().unwrap_or(Value::Null);
        let resp = match req.method.as_str() {
            "initialize" => self.handle_initialize(id),
            "tools/list" => self.handle_list(id),
            "tools/call" => self.handle_call(id, req.params),
            other => Response::error(
                id,
                error_code::METHOD_NOT_FOUND,
                format!("router server does not implement '{other}'"),
            ),
        };
        Some(resp)
    }

    /// Advertise the union under the gateway name — we *are* the server (each front's backend is the
    /// real "downstream").
    fn handle_initialize(&mut self, id: Value) -> Response {
        let result = json!({
            "protocolVersion": super::jsonrpc::PROTOCOL_VERSION,
            "capabilities": { "tools": { "listChanged": false } },
            "serverInfo": { "name": self.name, "version": env!("CARGO_PKG_VERSION") },
        });
        Response::success(id, result)
    }

    /// Serve the namespaced union, **policy-filtered on the namespaced name** so a denied capability
    /// (e.g. all of `notes__*`, or one upstream's `notes__delete_note`) never appears to the agent.
    fn handle_list(&mut self, id: Value) -> Response {
        let visible: Vec<Tool> = self
            .tools
            .iter()
            .filter(|t| self.policy.check(&t.name) != Decision::Deny)
            .cloned()
            .collect();
        Response::success(id, ok_value(ListToolsResult { tools: visible }))
    }

    /// Govern + route a `tools/call`. The governor dispatches on the **namespaced** name (so policy
    /// matches what the agent called and what `tools/list` showed); the [`RouterExecutor`] inside it
    /// splits that name back to the right front. A block maps to an MCP error *result* — exactly like
    /// [`super::proxy_server::ProxyServer`]'s call handling: well-formed but refused, never executed,
    /// never signed.
    fn handle_call(&mut self, id: Value, params: Option<Value>) -> Response {
        let Some(params) = params else {
            return Response::error(id, error_code::INVALID_PARAMS, "tools/call requires params");
        };
        let call: CallToolParams = match serde_json::from_value(params) {
            Ok(c) => c,
            Err(e) => {
                return Response::error(
                    id,
                    error_code::INVALID_PARAMS,
                    format!("bad tools/call params: {e}"),
                )
            }
        };

        let outcome = self.governor.dispatch(&call.name, &call.arguments);
        log_outcome(&call.name, &outcome);

        let result = match outcome {
            DispatchOutcome::Denied => CallToolResult::err(format!(
                "blocked by policy: '{}' is denied (deny-by-default)",
                call.name
            )),
            DispatchOutcome::NotApproved => CallToolResult::err(format!(
                "blocked: '{}' requires human approval and it was not granted",
                call.name
            )),
            DispatchOutcome::BudgetExceeded(reason) => {
                CallToolResult::err(format!("blocked: {reason}"))
            }
            DispatchOutcome::EgressDenied(reason) => {
                CallToolResult::err(format!("blocked: {reason}"))
            }
            DispatchOutcome::Executed { outcome, .. } => {
                if outcome.success {
                    CallToolResult {
                        content: content_from(outcome.data),
                        is_error: false,
                    }
                } else {
                    CallToolResult::err(outcome.error.unwrap_or_else(|| "action failed".into()))
                }
            }
        };
        Response::success(id, ok_value(result))
    }
}

/// Join a namespace and an inner tool name into the served `"<ns>__<name>"` form.
fn namespaced(ns: &str, name: &str) -> String {
    format!("{ns}{NS_SEP}{name}")
}

/// Turn an executor `data` value into MCP content blocks. The router relays whatever the chosen
/// front's executor produced: a pre-formed content block (an object carrying a `type` tag, e.g. an
/// image block) passes through as one block, an array passes through verbatim, anything else is
/// wrapped as text — so any front's output is faithfully relayed.
fn content_from(data: Value) -> Vec<Value> {
    match data {
        Value::Array(blocks) => blocks,
        Value::Null => vec![],
        // A pre-formed content block (an object with a "type" tag) — emit as one.
        Value::Object(ref map) if map.contains_key("type") => vec![data],
        other => vec![json!({ "type": "text", "text": other.to_string() })],
    }
}

fn ok_value<T: serde::Serialize>(value: T) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
}

/// One stderr line per call (stdout is the JSON-RPC channel) — the operator sees governance happen
/// and which namespaced tool ran. Mirrors the other fronts' logging.
fn log_outcome(action_id: &str, outcome: &DispatchOutcome) {
    let note = match outcome {
        DispatchOutcome::Denied => "DENIED by policy".to_string(),
        DispatchOutcome::NotApproved => "BLOCKED — approval not granted".to_string(),
        DispatchOutcome::BudgetExceeded(r) => format!("BLOCKED — {r}"),
        DispatchOutcome::EgressDenied(r) => format!("BLOCKED — egress: {r}"),
        DispatchOutcome::Executed { outcome, receipt } => format!(
            "performed ({}) · receipt sig={}…",
            if outcome.success { "ok" } else { "failed" },
            &receipt.signature[..receipt.signature.len().min(16)]
        ),
    };
    // Component name, not a subcommand: the router core serves the broker (`kriya-gateway broker`).
    eprintln!("[kriya router] tools/call {action_id}: {note}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::Signer;
    use crate::mcp::approval::{AutoApprove, DenyApproval};
    use std::sync::{Arc as StdArc, Mutex};

    /// A scriptable sub-executor that records every `(action_id, params)` it was asked to run — so a
    /// test can assert exactly which inner name reached which front (or, for a blocked call, that
    /// none did). Returns a canned success carrying its own tag so a test can tell the fronts apart.
    struct RecordingExecutor {
        tag: String,
        seen: StdArc<Mutex<Vec<(String, Value)>>>,
    }

    impl RecordingExecutor {
        fn new(tag: &str) -> (Self, StdArc<Mutex<Vec<(String, Value)>>>) {
            let seen = StdArc::new(Mutex::new(Vec::new()));
            (
                Self {
                    tag: tag.to_string(),
                    seen: seen.clone(),
                },
                seen,
            )
        }
    }

    impl ActionExecutor for RecordingExecutor {
        fn execute(&mut self, action_id: &str, params: &Value) -> ActionOutcome {
            self.seen
                .lock()
                .unwrap()
                .push((action_id.to_string(), params.clone()));
            ActionOutcome::ok(json!({ "front": self.tag, "ran": action_id }))
        }
    }

    fn tool(name: &str) -> Tool {
        Tool {
            name: name.into(),
            description: format!("desc of {name}"),
            input_schema: json!({ "type": "object", "properties": {} }),
        }
    }

    fn req(method: &str, params: Value) -> Request {
        serde_json::from_value(json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .unwrap()
    }

    // ── RouterExecutor routing ───────────────────────────────────────────────────────────────

    #[test]
    fn router_executor_routes_to_the_right_front_with_the_inner_name() {
        let (cu, cu_seen) = RecordingExecutor::new("cu");
        let (nums, nums_seen) = RecordingExecutor::new("numbers");
        let mut fronts: HashMap<String, Box<dyn ActionExecutor>> = HashMap::new();
        fronts.insert("cu".into(), Box::new(cu));
        fronts.insert("numbers".into(), Box::new(nums));
        let mut ex = RouterExecutor::new(fronts);

        let o1 = ex.execute("cu__computer_click", &json!({"x": 1, "y": 2}));
        assert!(o1.success);
        assert_eq!(o1.data["front"], "cu");
        let o2 = ex.execute("numbers__press_x", &json!({}));
        assert!(o2.success);
        assert_eq!(o2.data["front"], "numbers");

        // Each front saw exactly its own call, with the INNER (un-namespaced) name.
        assert_eq!(
            *cu_seen.lock().unwrap(),
            vec![("computer_click".to_string(), json!({"x": 1, "y": 2}))]
        );
        assert_eq!(
            *nums_seen.lock().unwrap(),
            vec![("press_x".to_string(), json!({}))]
        );
    }

    #[test]
    fn router_executor_splits_on_first_separator_only() {
        // An inner name that itself contains "__" stays intact (we split once).
        let (cu, cu_seen) = RecordingExecutor::new("cu");
        let mut fronts: HashMap<String, Box<dyn ActionExecutor>> = HashMap::new();
        fronts.insert("cu".into(), Box::new(cu));
        let mut ex = RouterExecutor::new(fronts);
        assert!(ex.execute("cu__a__b", &json!({})).success);
        assert_eq!(cu_seen.lock().unwrap()[0].0, "a__b");
    }

    #[test]
    fn router_executor_unknown_namespace_is_clean_failure_not_panic() {
        let (cu, cu_seen) = RecordingExecutor::new("cu");
        let mut fronts: HashMap<String, Box<dyn ActionExecutor>> = HashMap::new();
        fronts.insert("cu".into(), Box::new(cu));
        let mut ex = RouterExecutor::new(fronts);

        let bad = ex.execute("ghost__do_thing", &json!({}));
        assert!(!bad.success);
        assert!(bad.error.unwrap().contains("no front registered"));
        // The real front was never touched.
        assert!(cu_seen.lock().unwrap().is_empty());
    }

    #[test]
    fn router_executor_unnamespaced_name_is_clean_failure() {
        let mut ex = RouterExecutor::new(HashMap::new());
        let bad = ex.execute("not_namespaced", &json!({}));
        assert!(!bad.success);
        assert!(bad.error.unwrap().contains("not namespaced"));
    }

    // ── RouterServer: union list, policy filter, governed routing ─────────────────────────────

    /// Build a `RouterServer` over two fake fronts (cu + numbers) wrapped in ONE governor, plus a
    /// policy + approval gate. Returns the server and both fronts' record logs so a test can assert
    /// what reached each front.
    #[allow(clippy::type_complexity)]
    fn server(
        policy: Policy,
        approval: Box<dyn ApprovalGate>,
    ) -> (
        RouterServer,
        StdArc<Mutex<Vec<(String, Value)>>>,
        StdArc<Mutex<Vec<(String, Value)>>>,
    ) {
        let (cu, cu_seen) = RecordingExecutor::new("cu");
        let (nums, nums_seen) = RecordingExecutor::new("numbers");
        let policy = Arc::new(policy);
        let fronts = vec![
            Front::new(
                "cu",
                vec![tool("computer_click"), tool("list_apps")],
                Box::new(cu),
            ),
            Front::new(
                "numbers",
                vec![tool("press_button_save"), tool("press_button_delete")],
                Box::new(nums),
            ),
        ];
        let srv = RouterServer::from_parts(
            "kriya-test",
            fronts,
            policy,
            Arc::new(Signer::new()),
            approval,
            None,
        );
        (srv, cu_seen, nums_seen)
    }

    /// Allow everything so the governed path executes — for the routing assertions.
    fn allow_all() -> Policy {
        serde_yaml::from_str(
            "rules:\n  - action: \"*\"\n    allow: true\nbudget:\n  max_actions_per_minute: 60\n",
        )
        .unwrap()
    }

    /// Gate per namespaced name: cu floor allowed, one app tool approval-gated, the rest denied —
    /// proves policy matches the NAMESPACED name and that the deny/approval gates apply per front.
    fn namespaced_policy() -> Policy {
        serde_yaml::from_str(
            r#"
rules:
  - action: "cu__*"
    allow: true
  - action: "numbers__press_button_save"
    allow: true
  - action: "numbers__press_button_delete"
    allow: true
    require_approval: true
  - action: "*"
    allow: false
budget:
  max_actions_per_minute: 60
"#,
        )
        .unwrap()
    }

    #[test]
    fn initialize_advertises_under_the_gateway_name() {
        let (mut s, _, _) = server(allow_all(), Box::new(DenyApproval));
        let resp = s.handle(req("initialize", json!({}))).unwrap();
        let result = resp.result.unwrap();
        assert_eq!(result["serverInfo"]["name"], "kriya-test");
        assert!(result["capabilities"]["tools"].is_object());
    }

    #[test]
    fn tools_list_is_the_namespaced_union() {
        let (mut s, _, _) = server(allow_all(), Box::new(DenyApproval));
        assert_eq!(s.tool_count(), 4);
        let resp = s.handle(req("tools/list", json!({}))).unwrap();
        let names: Vec<String> = resp.result.unwrap()["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect();
        assert!(
            names.contains(&"cu__computer_click".to_string()),
            "{names:?}"
        );
        assert!(names.contains(&"cu__list_apps".to_string()), "{names:?}");
        assert!(
            names.contains(&"numbers__press_button_save".to_string()),
            "{names:?}"
        );
        assert!(
            names.contains(&"numbers__press_button_delete".to_string()),
            "{names:?}"
        );
    }

    #[test]
    fn tools_list_is_policy_filtered_on_the_namespaced_name() {
        // namespaced_policy denies everything but cu__* and the two numbers tools (delete gated).
        let (s, _, _) = server(namespaced_policy(), Box::new(DenyApproval));
        // 4 total; all 4 are non-Deny (delete is RequiresApproval, still visible).
        assert_eq!(s.visible_tool_count(), 4);

        // Now a policy that denies the whole numbers front: only cu__* survive.
        let only_cu: Policy = serde_yaml::from_str(
            "rules:\n  - action: \"cu__*\"\n    allow: true\n  - action: \"*\"\n    allow: false\nbudget:\n  max_actions_per_minute: 60\n",
        )
        .unwrap();
        let (mut s2, _, _) = server(only_cu, Box::new(DenyApproval));
        let names: Vec<String> = s2
            .handle(req("tools/list", json!({})))
            .unwrap()
            .result
            .unwrap()["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect();
        assert!(names.iter().all(|n| n.starts_with("cu__")), "{names:?}");
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn governed_call_routes_to_the_right_front_and_signs_a_receipt() {
        let (mut s, cu_seen, nums_seen) = server(allow_all(), Box::new(DenyApproval));
        // Route to the numbers front.
        let resp = s
            .handle(req(
                "tools/call",
                json!({"name": "numbers__press_button_save", "arguments": {}}),
            ))
            .unwrap();
        let result = resp.result.unwrap();
        assert!(result.get("isError").is_none(), "allowed call: {result}");
        // The numbers front saw the inner name; cu saw nothing.
        assert_eq!(nums_seen.lock().unwrap()[0].0, "press_button_save");
        assert!(cu_seen.lock().unwrap().is_empty());

        // Route to the cu front in the same session — proves both fronts are live under one governor.
        s.handle(req(
            "tools/call",
            json!({"name": "cu__computer_click", "arguments": {"x": 5, "y": 6}}),
        ))
        .unwrap();
        assert_eq!(cu_seen.lock().unwrap()[0].0, "computer_click");
    }

    #[test]
    fn denied_namespaced_tool_is_error_result_and_never_executed() {
        // namespaced_policy denies anything not matched; an unlisted cu tool name still matches
        // cu__*, so pick a name the policy denies outright: a third namespace.
        let only_cu: Policy = serde_yaml::from_str(
            "rules:\n  - action: \"cu__*\"\n    allow: true\n  - action: \"*\"\n    allow: false\nbudget:\n  max_actions_per_minute: 60\n",
        )
        .unwrap();
        let (mut s, _cu, nums_seen) = server(only_cu, Box::new(AutoApprove));
        let resp = s
            .handle(req(
                "tools/call",
                json!({"name": "numbers__press_button_save", "arguments": {}}),
            ))
            .unwrap();
        assert!(resp.error.is_none(), "a refused call is a result");
        let result = resp.result.unwrap();
        assert_eq!(result["isError"], true);
        // The whole point: a denied call NEVER reached the numbers front's executor.
        assert!(nums_seen.lock().unwrap().is_empty());
    }

    #[test]
    fn approval_gated_namespaced_tool_blocked_then_allowed() {
        // Under DenyApproval the delete is blocked and never executed.
        let (mut s, _cu, nums_seen) = server(namespaced_policy(), Box::new(DenyApproval));
        let resp = s
            .handle(req(
                "tools/call",
                json!({"name": "numbers__press_button_delete", "arguments": {}}),
            ))
            .unwrap();
        assert_eq!(resp.result.unwrap()["isError"], true);
        assert!(nums_seen.lock().unwrap().is_empty());

        // Under AutoApprove it runs and routes to the numbers front.
        let (mut s2, _cu2, nums_seen2) = server(namespaced_policy(), Box::new(AutoApprove));
        let resp2 = s2
            .handle(req(
                "tools/call",
                json!({"name": "numbers__press_button_delete", "arguments": {}}),
            ))
            .unwrap();
        assert!(resp2.result.unwrap().get("isError").is_none());
        assert_eq!(nums_seen2.lock().unwrap()[0].0, "press_button_delete");
    }

    #[test]
    fn unknown_namespace_call_is_a_signed_failure_result() {
        // The governor clears the name by policy (allow_all), the RouterExecutor finds no front →
        // a failed outcome surfaced as an error result (and the governor signed a failure receipt).
        let (mut s, _, _) = server(allow_all(), Box::new(DenyApproval));
        let resp = s
            .handle(req(
                "tools/call",
                json!({"name": "ghost__whatever", "arguments": {}}),
            ))
            .unwrap();
        let result = resp.result.unwrap();
        assert_eq!(result["isError"], true);
        assert!(result["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("no front registered"));
    }

    #[test]
    fn notification_gets_no_response() {
        let (mut s, _, _) = server(allow_all(), Box::new(DenyApproval));
        let note: Request =
            serde_json::from_value(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
                .unwrap();
        assert!(s.handle(note).is_none());
    }

    #[test]
    fn unknown_method_is_method_not_found() {
        let (mut s, _, _) = server(allow_all(), Box::new(DenyApproval));
        let resp = s.handle(req("resources/list", json!({}))).unwrap();
        assert_eq!(resp.error.unwrap().code, error_code::METHOD_NOT_FOUND);
    }

    #[test]
    fn with_governor_test_path_serves_prebuilt_tools() {
        // Exercise the test-friendly constructor: build the governor + executor separately, then
        // hand the server a pre-namespaced tool list.
        let (cu, cu_seen) = RecordingExecutor::new("cu");
        let mut executors: HashMap<String, Box<dyn ActionExecutor>> = HashMap::new();
        executors.insert("cu".into(), Box::new(cu));
        let policy = Arc::new(allow_all());
        let governor = Governor::new(
            policy.clone(),
            Arc::new(Signer::new()),
            Box::new(DenyApproval),
            Box::new(RouterExecutor::new(executors)),
        );
        let tools =
            RouterServer::namespaced_tools(&[("cu".to_string(), vec![tool("computer_key")])]);
        let mut s = RouterServer::with_governor("kriya-test", tools, governor, policy);
        assert_eq!(s.tool_count(), 1);
        s.handle(req(
            "tools/call",
            json!({"name": "cu__computer_key", "arguments": {"key": "return"}}),
        ))
        .unwrap();
        assert_eq!(cu_seen.lock().unwrap()[0].0, "computer_key");
    }
}
