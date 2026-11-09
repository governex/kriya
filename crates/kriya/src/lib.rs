//! `kriya` — the Rust half of the kriya framework.
//!
//! Pairs with the `kriya-core` TypeScript SDK to turn a goal + a registry of
//! typed actions into a permission-checked, budget-bounded, cryptographically-audited
//! sequence of action calls against a desktop app.
//!
//! ## Quick start (Tauri 2 backend)
//!
//! ```no_run
//! use std::collections::HashMap;
//! use std::sync::{Arc, Mutex};
//!
//! use kriya::{
//!     audit::Signer,
//!     permissions::Policy,
//!     protocol::{AgentActionResult, AgentApprovalResponse, AgentStartRequest},
//!     run_task, select_backend_with_default, ApprovalMap, HostSink, PendingMap, StepAdvanceMap,
//! };
//!
//! # struct AppState {
//! #     pending: PendingMap,
//! #     approvals: ApprovalMap,
//! #     advances: StepAdvanceMap,
//! #     policy: Arc<Policy>,
//! #     signer: Arc<Signer>,
//! # }
//! # #[derive(Default)] struct MyDeterministic;
//! # impl kriya::Inference for MyDeterministic {
//! #     fn name(&self) -> &'static str { "deterministic" }
//! #     fn next_step(&mut self, _: &kriya::StepContext) -> Result<kriya::StepDecision, String> {
//! #         Ok(kriya::StepDecision::Done { summary: "ok".into() })
//! #     }
//! # }
//! # #[cfg(feature = "tauri-host")]
//! # fn wire(app: tauri::AppHandle, state: AppState, req: AgentStartRequest) {
//! # use kriya::TauriSink;
//! let backend = select_backend_with_default(Box::new(MyDeterministic::default()));
//! // Wrap the Tauri handle in a HostSink; a sidecar/Electron host passes a stdio sink instead.
//! let sink: Arc<dyn HostSink> = Arc::new(TauriSink::new(app));
//! std::thread::spawn(move || {
//!     let _ = run_task(
//!         sink,
//!         state.pending,
//!         state.approvals,
//!         state.advances,
//!         state.policy,
//!         state.signer,
//!         backend,
//!         req,
//!     );
//! });
//! # }
//! ```

pub mod agent;
pub mod audit;
pub mod budget;
pub mod corr;
pub mod crypto;
pub mod duration;
// F1 (doc 28 §F1): the attested-local-inference proxy. Off by default so the library stays lean
// for embedders that never proxy local inference — see `llm/mod.rs` for the layering.
#[cfg(feature = "llm-proxy")]
pub mod llm;
// Shared hand-rolled HTTP/1.1 parsing + `ureq` forwarding for the std-`TcpListener` reverse proxies
// (`llm::proxy` and the governed LLM lane `mcp::llm_gateway`). Crate-private plumbing.
#[cfg(any(feature = "llm-proxy", all(feature = "contain", feature = "mcp-http")))]
pub(crate) mod http1;
pub mod mcp;
pub mod memory;
// D1 (doc 27 §4 / docs/design/d1-memory-receipts.md): memory-write receipt classifier + emitter,
// shared by the Claude Code hook (`bin/kriya-hook.rs`), the Hermes hook
// (`bin/kriya-hermes-hook.rs`), and the MCP broker (`mcp/governor.rs`). NOT the same thing as
// `memory` above (that's the in-process agent's own episodic SQLite recall) — see this module's
// doc comment for the distinction.
pub mod memwrite;
pub mod pay;
pub mod permissions;
pub mod protocol;
pub mod registry;
pub mod secrets;
// B4 (doc 27 §4 / docs/design/b4-temporal-conditions.md D2): the session-scoped event fold + cache
// feeding `permissions::TemporalPolicy::evaluate`. Always compiled (no feature gate) — the hook's
// `pre` gate needs it unconditionally, exactly like `spend_state` below.
pub mod session_cond;
/// F-6 (doc 31 §9 / doc 33 §4-C) — the runtime side of the shift lane: read the Console-written
/// armed state and clamp the action tier to the fail-closed tier on a missed heartbeat.
pub mod shift_guard;
pub mod sidecar;
pub mod spend_state;
// F4-wasm (doc 28 §F4): the Deterministic Execution lane. Off by default — pulls in `wasmtime` +
// `wasmtime-wasi`, the only heavy dependency this crate has ever added — see `wasmexec/mod.rs`'s
// module doc for the naming law vs B1 "Verified Replay" and the full deterministic-configuration
// rationale.
#[cfg(feature = "wasm-exec")]
pub mod wasmexec;

pub use registry::{json_result, Action, Param, ParamType, Params, Registry};

pub use agent::inference::retry::{RetryExhausted, RetryPolicy};
pub use agent::inference::{
    select_backend_with_default, Inference, NetworkProfile, StepContext, StepDecision, StepRecord,
};
#[cfg(feature = "tauri-host")]
pub use agent::TauriSink;
pub use agent::{
    run_task, ApprovalMap, GovernedApp, HostSink, PendingMap, SharedBudget, StepAdvanceMap,
};
pub use sidecar::{run_sidecar, SharedWriter, StdioSink};
