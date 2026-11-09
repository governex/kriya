//! [`McpProxyExecutor`] — the only new [`ActionExecutor`] Front 1 needs. It is the last hop of
//! a *cleared* `tools/call`: after the [`super::governor::Governor`] has run policy → approval →
//! budget, this forwards the call to the downstream MCP server via the [`super::client::McpClient`]
//! and reports back what happened. The governance above it never changes — that is the whole bet.
//!
//! The client is shared as `Arc<Mutex<..>>` because the proxy serve loop also needs the *same*
//! client for transparent passthrough of non-`tools/*` methods (the proxy and its executor both
//! talk to one downstream subprocess). `ActionExecutor: Send` requires the executor be `Send`, so
//! `Arc<Mutex<..>>` (not `Rc<RefCell<..>>`); the `Mutex` is uncontended in the MVP (one synchronous
//! request at a time) and is the same handle the two-reader-thread full-lifecycle version relies on.

use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use super::client::McpClient;
use super::executor::{ActionExecutor, ActionOutcome};
use super::jsonrpc::CallToolResult;

/// Forwards a cleared `tools/call` to the downstream server and maps its `CallToolResult` onto an
/// [`ActionOutcome`] the governor can sign a receipt over.
pub struct McpProxyExecutor {
    client: Arc<Mutex<McpClient>>,
}

impl McpProxyExecutor {
    pub fn new(client: Arc<Mutex<McpClient>>) -> Self {
        Self { client }
    }
}

impl ActionExecutor for McpProxyExecutor {
    fn execute(&mut self, action_id: &str, params: &Value) -> ActionOutcome {
        let mut client = self.client.lock().unwrap();
        let result = client.call_tool(action_id, params);
        // Take the governed-lane io observation the transport captured on this call (the HTTP lane
        // records dest_host + observed payload bytes + content hash; stdio records nothing — doc 24
        // §4.3). The governor turns a present `io` into a `kriya.io.*` receipt.
        let io = client.take_last_io();
        drop(client);
        match result {
            Ok(result) => map_result(result).with_io(io),
            // A dead / unreachable downstream is a failed outcome the agent can read — and one the
            // governor still signs a (failure) receipt for — never a panic that kills the session.
            Err(e) => ActionOutcome::failed(format!("downstream unavailable: {e}")).with_io(io),
        }
    }

    fn set_call_chain(&mut self, chain: Option<&str>) {
        if let Ok(mut client) = self.client.lock() {
            client.set_call_chain(chain.map(str::to_string));
        }
    }
}

/// Map a downstream `CallToolResult` onto an `ActionOutcome`:
/// - `success = !is_error` — MCP carries tool failure as `is_error: true`, not a protocol error.
/// - `data` keeps the downstream's exact `content` array, so the proxy relays the real result
///   blocks verbatim (text/json/etc.) rather than a re-stringified copy.
/// - `error` is the human-readable text of an error result, for the signed receipt + the reason
///   surfaced back to the agent.
fn map_result(result: CallToolResult) -> ActionOutcome {
    let success = !result.is_error;
    let data = json!(result.content);
    if success {
        ActionOutcome {
            success: true,
            data,
            error: None,
            io: None,
        }
    } else {
        ActionOutcome {
            success: false,
            data,
            error: Some(content_text(&result.content)),
            io: None,
        }
    }
}

/// Best-effort human-readable text from MCP content blocks: concatenate the `text` of any
/// `{"type":"text","text":..}` blocks; fall back to a generic message when there are none.
fn content_text(content: &[Value]) -> String {
    let joined: String = content
        .iter()
        .filter_map(|c| c.get("text").and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join("\n");
    if joined.is_empty() {
        "downstream tool reported an error".to_string()
    } else {
        joined
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_success_result_to_successful_outcome() {
        let result = CallToolResult {
            content: vec![json!({ "type": "text", "text": "{\"balance\":42}" })],
            is_error: false,
        };
        let outcome = map_result(result);
        assert!(outcome.success);
        assert!(outcome.error.is_none());
        // The downstream content is preserved verbatim for relay.
        assert_eq!(outcome.data[0]["text"], "{\"balance\":42}");
    }

    #[test]
    fn maps_error_result_to_failed_outcome_with_text() {
        let result = CallToolResult {
            content: vec![json!({ "type": "text", "text": "txn not found" })],
            is_error: true,
        };
        let outcome = map_result(result);
        assert!(!outcome.success);
        assert_eq!(outcome.error.as_deref(), Some("txn not found"));
    }

    #[test]
    fn error_result_without_text_gets_a_generic_reason() {
        let result = CallToolResult {
            content: vec![json!({ "type": "image" })],
            is_error: true,
        };
        let outcome = map_result(result);
        assert!(!outcome.success);
        assert!(outcome.error.as_deref().unwrap().contains("error"));
    }
}
