//! Governed MCP-server mode (roadmap **R1**).
//!
//! Exposes a kriya app's registered actions as a Model Context Protocol server over stdio so
//! an *external* agent (Claude Desktop, Cursor, …) can drive the app — but **every
//! `tools/call` is routed through the same policy → approval → budget → signed-audit gates**
//! the in-process agent host enforces. That governed routing, not the raw tool exposure, is
//! the differentiator over a vanilla MCP server: the external agent gets capability, the host
//! keeps control.
//!
//! Layering:
//! - [`jsonrpc`] — wire framing and the MCP message shapes (no policy).
//! - [`executor`] — the trait that actually runs a cleared action (Tauri / sidecar / CLI).
//! - [`approval`] — human-in-the-loop gates for guarded actions in MCP mode.
//! - [`governor`] — wraps policy → approval → budget → audit around the executor.
//! - [`server`] — the stdio JSON-RPC loop that exposes tools and routes calls.
//!
//! The thin `kriya-mcp` binary (`src/bin/kriya-mcp.rs`) wires these together from a policy
//! file + a tool-schema file + an executor command.

pub mod approval;
pub mod executor;
pub mod governor;
pub mod evidence;
pub mod jsonrpc;
pub mod server;

// Front 1 — the stdio governance proxy (D-016). Off-by-default `mcp-client` feature so the library
// stays lean for in-process embedders that never proxy a downstream server.
#[cfg(feature = "mcp-client")]
pub mod client;
#[cfg(feature = "mcp-client")]
pub mod proxy_executor;
#[cfg(feature = "mcp-client")]
pub mod proxy_server;

// Containment (EG-C, doc 24 §11 B14): the recording CONNECT proxy + Seatbelt profile generator
// that force a LAUNCHED agent's egress through the governed lane. Off-by-default `contain`
// feature; std-only, no new deps, independent of `mcp-client` (it never touches MCP — it's a raw
// TCP CONNECT tunnel). The `sandbox-exec` invocation lives in `kriya-gateway`'s `run` subcommand,
// gated `#[cfg(target_os = "macos")]` there (module doc: no Linux path in v1).
#[cfg(feature = "contain")]
pub mod contain;

// Router — ONE MCP endpoint multiplexing multiple governed fronts under ONE Governor (one
// policy, one signer/audit, one actor). The broker (`kriya-gateway broker`, W2) is its consumer:
// it multiplexes N proxied MCP upstreams behind a namespacing `RouterExecutor` and serves their
// union. Pure composition — no FFI, no OS deps — so it lives under `mcp-client` with the rest of
// the proxy machinery. (The desktop fronts it once also composed — reach-in + computer-use — were
// removed 2026-08-07; see git history.)
#[cfg(feature = "mcp-client")]
pub mod router;

#[cfg(target_os = "macos")]
pub use approval::GuiApproval;
pub use approval::{
    default_approvals_dir, ApprovalDecision, ApprovalGate, AutoApprove, DenyApproval, FileApproval,
    PendingApproval, TtyApproval, DECISIONS_FILE, PENDING_FILE,
};
pub use executor::{
    ActionExecutor, ActionOutcome, FnExecutor, HashScheme, IoDecision, IoDirection, IoKind,
    IoRecord, PersistentProcessExecutor, ProcessExecutor,
};
pub use governor::{DispatchOutcome, EgressControl, EgressTarget, Governor, IngressControl};
pub use evidence::{expand_logs, EvidenceServer, EVIDENCE_TOOL_NAMES};
pub use server::Server;

#[cfg(feature = "mcp-client")]
pub use client::McpClient;
#[cfg(feature = "mcp-client")]
pub use proxy_executor::McpProxyExecutor;
#[cfg(feature = "mcp-client")]
pub use proxy_server::ProxyServer;

#[cfg(feature = "contain")]
pub use contain::{seatbelt_profile, sha256_hex as contain_sha256_hex, ConnectProxy, RUN_EXIT, RUN_START};

// Router public surface: the multiplexing executor + the unified serve loop. Portable (no FFI) —
// the broker's engine (W2), multiplexing proxied MCP upstreams under one Governor.
#[cfg(feature = "mcp-client")]
pub use router::{Front, RouterExecutor, RouterServer};
