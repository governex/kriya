//! D1 (doc 27 §4 / `docs/design/d1-memory-receipts.md`) — memory-write receipts: SHARED,
//! non-proprietary evidence plumbing both governed-lane hook binaries call
//! (`bin/kriya-hook.rs` for Claude Code, `bin/kriya-hermes-hook.rs` for Hermes) and the MCP
//! broker (`mcp/governor.rs`) calls for a registered memory tool.
//!
//! Classifies a governed write against the four confirmed persistent-memory-surface classes
//! (§D-1) and signs a hash-only `kriya.memory.write` / `.update` / `.delete` receipt (§D-3) —
//! content is **never** recorded, only its SHA-256 + byte size. This module is deliberately
//! generic, path-classifier-shaped plumbing — no pricing, no view-model, no provenance
//! derivation (that stays Console-private, `src/lib/memory.ts`) — colocated beside the existing
//! `kriya.io.*` emitters this design mirrors (`kriya-hook.rs`'s `egress_target_for` /
//! `emit_io_ingress`).
//!
//! **Not this module's job**: deciding *whether* a call is memory-shaped based on a bare tool
//! NAME heuristic for the MCP lane — that is a registry-driven decision the caller (the broker,
//! consulting the operator-authored `memory:` policy) makes BEFORE calling
//! [`emit_memory_receipt`] (§D-1's honest default: a configurable registry, not a name guess).

use serde_json::Value;

use crate::audit::{now_ms, Actor, Receipt, SignedReceipt, Signer};
use crate::corr::{self, Correlation};

/// Reserved `params` object key all D1 fields ride under (mirrors `kriya::corr::RESERVED_KEY`'s
/// placement discipline — a dotted `kriya.` key no bare tool argument can collide with).
pub const RESERVED_KEY: &str = "kriya.memory";

/// The four confirmed governed persistent-memory-surface classes (§D-1). Closed enum, never
/// free-form — a receipt can never claim a class the detection basis doesn't support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryClass {
    /// `CLAUDE.md` / `CLAUDE.local.md` — project standing instructions.
    ClaudeMd,
    /// Auto-memory / `MEMORY.md` + memory files under a `.claude/` segment.
    ClaudeMemoryDir,
    /// `.claude/settings.json` / `settings.local.json` — standing config, NOT prose memory
    /// (labeled distinctly per §red-team-1, never conflated with the other three).
    ClaudeSettings,
    /// An operator-**registered** MCP memory tool (the broker lane; never a bare name heuristic).
    McpRegistered,
}

impl MemoryClass {
    pub fn as_str(self) -> &'static str {
        match self {
            MemoryClass::ClaudeMd => "claude-md",
            MemoryClass::ClaudeMemoryDir => "claude-memory-dir",
            MemoryClass::ClaudeSettings => "claude-settings",
            MemoryClass::McpRegistered => "mcp-registered",
        }
    }
}

/// `file` | `mcp-tool` (§D-3 `surface` field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemorySurfaceKind {
    File,
    McpTool,
}

impl MemorySurfaceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            MemorySurfaceKind::File => "file",
            MemorySurfaceKind::McpTool => "mcp-tool",
        }
    }
}

/// Coarse, envelope-safe location token for a file surface (§D-3 `root`). A best-effort
/// heuristic honestly scoped to what the hook payload actually carries — the Claude Code hook
/// payload has NO `cwd` (verified `kriya-hook.rs`'s `HookPayload`), so "project" vs "user-home"
/// is inferred from the path string alone, never a filesystem probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryRoot {
    Project,
    UserHome,
    Other,
}

impl MemoryRoot {
    pub fn as_str(self) -> &'static str {
        match self {
            MemoryRoot::Project => "project",
            MemoryRoot::UserHome => "user-home",
            MemoryRoot::Other => "other",
        }
    }
}

/// The MCP registry's declared operation (§D-1 mcp-registered bullet: `create→write,
/// update→update, delete→delete`) — what the OPERATOR authored in the `memory:` policy, never
/// inferred from a tool name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemoryOp {
    Create,
    Update,
    Delete,
}

impl MemoryOp {
    pub fn as_str(self) -> &'static str {
        match self {
            MemoryOp::Create => "create",
            MemoryOp::Update => "update",
            MemoryOp::Delete => "delete",
        }
    }

    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "create" => Some(MemoryOp::Create),
            "update" => Some(MemoryOp::Update),
            "delete" => Some(MemoryOp::Delete),
            _ => None,
        }
    }

    /// §D-1's fixed mapping: `create→write, update→update, delete→delete`.
    pub fn verb(self) -> MemoryVerb {
        match self {
            MemoryOp::Create => MemoryVerb::Write,
            MemoryOp::Update => MemoryVerb::Update,
            MemoryOp::Delete => MemoryVerb::Delete,
        }
    }
}

/// `{server, tool, op}` for an MCP memory surface (§D-3 `tool_ref`) — all already non-content.
#[derive(Debug, Clone)]
pub struct ToolRef {
    pub server: String,
    pub tool: String,
    pub op: MemoryOp,
}

/// The receipt verb — resolves 1:1 onto a `kriya.memory.*` `action_id` (§D-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryVerb {
    Write,
    Update,
    Delete,
}

impl MemoryVerb {
    pub fn action_id(self) -> &'static str {
        match self {
            MemoryVerb::Write => crate::audit::MEMORY_WRITE,
            MemoryVerb::Update => crate::audit::MEMORY_UPDATE,
            MemoryVerb::Delete => crate::audit::MEMORY_DELETE,
        }
    }
}

/// Verb-disambiguation honesty tag (§D-3). The hook is stateless per invocation and cannot
/// race-free `stat` for existence, so `write`-vs-`update` comes from tool semantics, upgraded to
/// `update` only when an in-run prior-write scan actually finds one — never a filesystem probe.
/// Always carried on the receipt so the ledger never implies certainty it doesn't have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerbBasis {
    /// The invoking tool is Edit-shaped (an existing-file mutation by construction).
    ToolEdit,
    /// The invoking tool is Write-shaped and no prior write to this path was found in this run
    /// (or the scan was not performed) — the honest default, never upgraded without evidence.
    ToolWrite,
    /// A Write-shaped call whose path already carries an earlier `kriya.memory.*` receipt
    /// earlier in THIS run's corr chain (a bounded, best-effort tail scan — §D-3/F4).
    PriorWriteSeen,
}

impl VerbBasis {
    pub fn as_str(self) -> &'static str {
        match self {
            VerbBasis::ToolEdit => "tool-edit",
            VerbBasis::ToolWrite => "tool-write",
            VerbBasis::PriorWriteSeen => "prior-write-seen",
        }
    }
}

/// A classified governed memory surface a tool call targeted (§D-1). `None` from
/// [`memory_surface_for`] means the call is OUT of D1's scope — never minted (§D-6).
#[derive(Debug, Clone)]
pub struct MemorySurface {
    pub class: MemoryClass,
    pub kind: MemorySurfaceKind,
    /// `file` surfaces only — the path exactly as the tool call carried it (absolute or
    /// agent-cwd-relative; the hook payload has no `cwd` to resolve it against, §D-1).
    pub path: Option<String>,
    pub root: Option<MemoryRoot>,
    /// `mcp-tool` surfaces only.
    pub tool_ref: Option<ToolRef>,
}

impl MemorySurface {
    fn mcp(tool_ref: ToolRef) -> Self {
        MemorySurface {
            class: MemoryClass::McpRegistered,
            kind: MemorySurfaceKind::McpTool,
            path: None,
            root: None,
            tool_ref: Some(tool_ref),
        }
    }
}

/// Tool names shaped like a file WRITE across the governed lanes this module serves — Claude
/// Code's `Write`/`Edit`/`MultiEdit`, Hermes' `write_file`/`patch`. Open-ended, never a closed
/// registry — mirrors the Console's `sessionTree.ts` `looksLikeWrite` house rule: an unmatched
/// write-shaped tool simply never classifies as memory, an honest gap, not a false claim.
fn is_write_shaped(tool_name: &str) -> bool {
    let t = tool_name.to_lowercase();
    t == "write" || t == "edit" || t == "multiedit" || t == "patch" || t.contains("write") || t.contains("edit")
}

/// Is `tool_name` specifically Edit-shaped (an existing-file mutation by construction, §D-3)? A
/// subset check of [`is_write_shaped`] — every Edit-shaped tool is also write-shaped.
fn is_edit_shaped(tool_name: &str) -> bool {
    let t = tool_name.to_lowercase();
    t == "edit" || t == "multiedit" || t.contains("edit") || t == "patch"
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn segments(path: &str) -> impl Iterator<Item = &str> {
    path.split('/').filter(|s| !s.is_empty())
}

fn has_segment(path: &str, seg: &str) -> bool {
    segments(path).any(|s| s == seg)
}

/// §D-1's four-class path classifier, run off `tool_input.file_path` ALONE (the hook payload
/// carries no `cwd`, so classification never assumes a working directory). Settings and
/// memory-dir are both gated on a `.claude/` path segment (checked before the bare `claude-md`
/// basename rule, which doesn't require one), so a `.claude/settings.json` never falls through.
fn classify_path(path: &str) -> Option<MemoryClass> {
    let base = basename(path);
    let under_dot_claude = has_segment(path, ".claude");
    if under_dot_claude && (base == "settings.json" || base == "settings.local.json") {
        return Some(MemoryClass::ClaudeSettings);
    }
    if under_dot_claude && (has_segment(path, "memory") || base == "MEMORY.md") {
        return Some(MemoryClass::ClaudeMemoryDir);
    }
    if base == "CLAUDE.md" || base == "CLAUDE.local.md" {
        return Some(MemoryClass::ClaudeMd);
    }
    None
}

/// Coarse `root` token (§D-3) — a best-effort classification off the path string alone, never a
/// filesystem probe (the hook has no `cwd`). Absolute-under-home ⇒ `user-home`; other absolute ⇒
/// `other`; relative (agent-cwd-relative — the common case for a `CLAUDE.md`/`.claude/*` write in
/// a repo) ⇒ `project`.
fn root_for(path: &str) -> MemoryRoot {
    if path.starts_with('~') || path.starts_with("/home/") || path.contains("/Users/") || path.contains("/home/") {
        MemoryRoot::UserHome
    } else if path.starts_with('/') {
        MemoryRoot::Other
    } else {
        MemoryRoot::Project
    }
}

/// Classify a hook-lane tool call against the four confirmed memory-surface classes (§D-1).
/// `None` for anything not write-shaped, without a `file_path`, or whose path matches none of the
/// four classes — OUT of scope, never minted (§D-6). `tool_name` is used only to gate on
/// write-shape (an MCP-registered surface never goes through this function — see
/// [`MemorySurface::mcp`] / the broker lane's own registry lookup).
pub fn memory_surface_for(tool_name: &str, tool_input: &Value) -> Option<MemorySurface> {
    if !is_write_shaped(tool_name) {
        return None;
    }
    let path = tool_input.get("file_path").and_then(Value::as_str)?;
    if path.is_empty() {
        return None;
    }
    let class = classify_path(path)?;
    Some(MemorySurface {
        class,
        kind: MemorySurfaceKind::File,
        path: Some(path.to_string()),
        root: Some(root_for(path)),
        tool_ref: None,
    })
}

/// The write-vs-update base verb + honesty basis from tool semantics ALONE (§D-3): `Edit`-shaped
/// ⇒ `update`/`tool-edit`; anything else write-shaped ⇒ `write`/`tool-write`. Callers that can
/// perform the in-run prior-write scan (§D-3/F4) upgrade a `write` result to
/// `(MemoryVerb::Update, VerbBasis::PriorWriteSeen)` themselves via [`prior_write_seen`] — this
/// function never does the scan itself (it has no log path to scan).
pub fn base_verb_for(tool_name: &str) -> (MemoryVerb, VerbBasis) {
    if is_edit_shaped(tool_name) {
        (MemoryVerb::Update, VerbBasis::ToolEdit)
    } else {
        (MemoryVerb::Write, VerbBasis::ToolWrite)
    }
}

/// Extract the file-lane write content to hash (§D-3): `tool_input.content` (Write) or
/// `tool_input.new_string` (Edit). Honest fallback when neither is present: the canonical whole
/// `tool_input` — still content-free on the wire (only its hash is ever recorded), just a
/// disclosure that this call's specific content field wasn't recognized rather than a silently
/// empty/wrong hash.
pub fn file_write_content(tool_input: &Value) -> Vec<u8> {
    if let Some(s) = tool_input.get("content").and_then(Value::as_str) {
        return s.as_bytes().to_vec();
    }
    if let Some(s) = tool_input.get("new_string").and_then(Value::as_str) {
        return s.as_bytes().to_vec();
    }
    canonical_json_bytes(tool_input)
}

/// Extract the MCP-lane write content to hash (§D-3): the registry's named `content_field`
/// argument (as a string verbatim, or its canonical JSON if non-string), or the full canonical
/// `arguments` when no field is named.
pub fn mcp_memory_content(arguments: &Value, content_field: Option<&str>) -> Vec<u8> {
    if let Some(field) = content_field {
        if let Some(v) = arguments.get(field) {
            return match v.as_str() {
                Some(s) => s.as_bytes().to_vec(),
                None => canonical_json_bytes(v),
            };
        }
    }
    canonical_json_bytes(arguments)
}

/// Build a [`MemorySurface`] for a registered MCP memory tool (broker lane, §D-4). The caller is
/// responsible for having already resolved `server`/`tool` from the dispatched `action_id` and
/// confirmed the tool IS registered (§D-1's honest default — never a bare name heuristic).
pub fn mcp_surface(server: &str, tool: &str, op: MemoryOp) -> MemorySurface {
    MemorySurface::mcp(ToolRef { server: server.to_string(), tool: tool.to_string(), op })
}

/// Sign + append a `kriya.memory.write` / `.update` / `.delete` receipt (§D-3). Hash-only:
/// `content` is hashed here (SHA-256 + byte size) and NEVER stored or otherwise recorded.
/// `success` mirrors the underlying tool call's own outcome (never persistence — the receipt
/// proves a governed call was made with that content-hash on that surface, not that the bytes
/// survived; §red-team pass 1). `corr` stamps the same run/agent correlation as the base action
/// receipt (via the shared, seam-authoritative [`corr::attach`]); `salt` keys the file surface's
/// `path_hmac` (ignored for an MCP surface, which has no path).
#[allow(clippy::too_many_arguments)]
pub fn emit_memory_receipt(
    signer: &Signer,
    actor: Option<&Actor>,
    verb: MemoryVerb,
    verb_basis: VerbBasis,
    surface: &MemorySurface,
    content: &[u8],
    success: bool,
    corr: &Correlation,
    salt: &[u8],
) -> SignedReceipt {
    emit_memory_receipt_chained(signer, actor, verb, verb_basis, surface, content, success, corr, salt, None)
}

/// [`emit_memory_receipt`] plus the cooperative origin chain (C3): with `Some(chain)` the receipt's
/// params carry a top-level `chain` array (the broker's HTTP serve mode); `None` is byte-identical
/// to [`emit_memory_receipt`].
#[allow(clippy::too_many_arguments)]
pub fn emit_memory_receipt_chained(
    signer: &Signer,
    actor: Option<&Actor>,
    verb: MemoryVerb,
    verb_basis: VerbBasis,
    surface: &MemorySurface,
    content: &[u8],
    success: bool,
    corr: &Correlation,
    salt: &[u8],
    chain: Option<&[String]>,
) -> SignedReceipt {
    let content_sha256 = sha256_hex(content);
    let content_bytes = content.len() as u64;

    let mut mem = serde_json::Map::new();
    mem.insert("class".to_string(), Value::String(surface.class.as_str().to_string()));
    mem.insert("surface".to_string(), Value::String(surface.kind.as_str().to_string()));
    mem.insert("content_sha256".to_string(), Value::String(content_sha256));
    mem.insert("content_bytes".to_string(), Value::from(content_bytes));
    mem.insert("verb_basis".to_string(), Value::String(verb_basis.as_str().to_string()));
    if let Some(path) = &surface.path {
        mem.insert("path".to_string(), Value::String(path.clone()));
        mem.insert("path_hmac".to_string(), Value::String(path_hmac_hex(salt, path)));
    }
    if let Some(root) = surface.root {
        mem.insert("root".to_string(), Value::String(root.as_str().to_string()));
    }
    if let Some(tr) = &surface.tool_ref {
        mem.insert(
            "tool_ref".to_string(),
            serde_json::json!({ "server": tr.server, "tool": tr.tool, "op": tr.op.as_str() }),
        );
    }

    let mut top = serde_json::Map::new();
    top.insert(RESERVED_KEY.to_string(), Value::Object(mem));
    if let Some(chain) = chain {
        top.insert(
            "chain".to_string(),
            Value::Array(chain.iter().cloned().map(Value::String).collect()),
        );
    }
    let params = corr::attach(Value::Object(top), corr);

    signer.record(
        Receipt::new(uuid::Uuid::new_v4().to_string(), verb.action_id().to_string(), params, success, now_ms())
            .with_actor(actor.cloned()),
    )
}

/// Keyed HMAC-SHA256 (lowercase hex) of `path` under `salt` (§D-3/§red-team pass 2) — the SAME
/// keyed-hash rationale as the pre-existing ingress digest (`kriya-hook.rs`'s
/// `hmac_sha256_hex`/`load_or_create_ingress_salt`): an unsalted hash of a guessable filename is
/// itself content disclosure, so the correlation hash is keyed.
pub fn path_hmac_hex(salt: &[u8], path: &str) -> String {
    hmac_sha256_hex(salt, path.as_bytes())
}

/// Bounded, best-effort scan of the audit log tail for an earlier `kriya.memory.write` /
/// `.update` receipt on the SAME `run_id` + `path_hmac` (§D-3/F4). The hook is a fresh process
/// per invocation with no persistent state, so this is the only honest way to detect "this path
/// was already written earlier in this run." Bounded to the last `max_lines` non-empty lines so a
/// large log never turns every hook call into an unbounded scan; when the bound is exhausted
/// without a match, the caller keeps the tool-semantics verb — `verb_basis` stays honest either
/// way, this function never claims certainty a bounded scan can't back.
pub fn prior_write_seen(log_path: &std::path::Path, run_id: &str, path_hmac: &str, max_lines: usize) -> bool {
    let content = match std::fs::read_to_string(log_path) {
        Ok(c) => c,
        Err(_) => return false,
    };
    for line in content.lines().rev().filter(|l| !l.trim().is_empty()).take(max_lines) {
        let v: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let action_id = v.get("action_id").and_then(Value::as_str).unwrap_or("");
        if action_id != crate::audit::MEMORY_WRITE && action_id != crate::audit::MEMORY_UPDATE {
            continue;
        }
        let params = match v.get("params") {
            Some(p) => p,
            None => continue,
        };
        let this_run = params.get(corr::RESERVED_KEY).and_then(|c| c.get("run_id")).and_then(Value::as_str);
        if this_run != Some(run_id) {
            continue;
        }
        let this_path_hmac = params.get(RESERVED_KEY).and_then(|m| m.get("path_hmac")).and_then(Value::as_str);
        if this_path_hmac == Some(path_hmac) {
            return true;
        }
    }
    false
}

/// Load (or create + persist, 0600) a device-local HMAC salt at `path` — shared plumbing so every
/// governed-lane binary keys its `path_hmac` (and, on the Claude Code lane, the pre-existing
/// ingress digest) off a device-local secret without duplicating the salt-file logic per binary.
/// Best-effort: an unwritable location returns an in-memory salt so hashing still functions
/// within the run (mirrors `kriya-hook.rs`'s original `load_or_create_ingress_salt`, which keeps
/// its own copy for the ingress lane rather than being refactored onto this one, to avoid
/// disturbing a working, already-shipped code path).
pub fn load_or_create_salt(path: &std::path::Path) -> [u8; 32] {
    if let Ok(text) = std::fs::read_to_string(path) {
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
    if std::fs::write(path, hex::encode(salt)).is_ok() {
        restrict_salt_perms(path);
    }
    salt
}

#[cfg(unix)]
fn restrict_salt_perms(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn restrict_salt_perms(_path: &std::path::Path) {}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// HMAC-SHA256 (lowercase hex), RFC 2104 — built on `sha2` so this module adds no HMAC
/// dependency, mirroring `kriya-hook.rs`'s own private copy of the identical construction.
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

/// Canonical key-sorted JSON serialization bytes — matches `kriya::audit`'s param
/// canonicalization + `kriya-hook.rs`'s own `canonical_json_string`, so the definition of
/// "canonical" is consistent everywhere a content hash is taken over structured JSON.
fn canonical_json_bytes(v: &Value) -> Vec<u8> {
    serde_json::to_vec(&canonical_value(v)).unwrap_or_default()
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── Classifier (§D-1) ──────────────────────────────────────────────────────────────────

    #[test]
    fn classifies_claude_md_any_depth() {
        let s = memory_surface_for("Write", &json!({ "file_path": "CLAUDE.md", "content": "x" })).unwrap();
        assert_eq!(s.class, MemoryClass::ClaudeMd);
        assert_eq!(s.kind, MemorySurfaceKind::File);

        let s2 = memory_surface_for(
            "Write",
            &json!({ "file_path": "/repo/deep/nested/CLAUDE.local.md", "content": "x" }),
        )
        .unwrap();
        assert_eq!(s2.class, MemoryClass::ClaudeMd);
    }

    #[test]
    fn classifies_claude_memory_dir_absolute() {
        let s = memory_surface_for(
            "Edit",
            &json!({ "file_path": "/Users/dev/.claude/projects/x/memory/MEMORY.md", "old_string": "a", "new_string": "b" }),
        )
        .unwrap();
        assert_eq!(s.class, MemoryClass::ClaudeMemoryDir);
        assert_eq!(s.root, Some(MemoryRoot::UserHome));
    }

    #[test]
    fn relative_memory_dir_write_is_an_honest_gap_not_a_false_claim() {
        // A relative memory-dir write the pattern CAN resolve (still has .claude + memory
        // segments) DOES classify — the "honest gap" the design calls out is a path where the
        // pattern genuinely can't tell (e.g. no .claude segment at all), not every relative path.
        let s = memory_surface_for("Write", &json!({ "file_path": "memory/MEMORY.md", "content": "x" }));
        assert!(s.is_none(), "no .claude segment present — correctly unclassified, not guessed");
    }

    #[test]
    fn classifies_claude_settings() {
        let s = memory_surface_for("Write", &json!({ "file_path": ".claude/settings.json", "content": "{}" })).unwrap();
        assert_eq!(s.class, MemoryClass::ClaudeSettings);

        let s2 = memory_surface_for(
            "Write",
            &json!({ "file_path": "/Users/dev/.claude/settings.local.json", "content": "{}" }),
        )
        .unwrap();
        assert_eq!(s2.class, MemoryClass::ClaudeSettings);
    }

    #[test]
    fn non_memory_paths_and_non_write_tools_are_out_of_scope() {
        assert!(memory_surface_for("Write", &json!({ "file_path": "src/main.rs", "content": "x" })).is_none());
        assert!(memory_surface_for("Read", &json!({ "file_path": "CLAUDE.md" })).is_none());
        assert!(memory_surface_for("Bash", &json!({ "command": "echo hi >> CLAUDE.md" })).is_none());
    }

    #[test]
    fn hermes_write_file_and_patch_tool_names_classify_the_same_way() {
        let s = memory_surface_for("write_file", &json!({ "file_path": "CLAUDE.md", "content": "x" })).unwrap();
        assert_eq!(s.class, MemoryClass::ClaudeMd);
        let (verb, basis) = base_verb_for("write_file");
        assert_eq!(verb, MemoryVerb::Write);
        assert_eq!(basis, VerbBasis::ToolWrite);

        let s2 = memory_surface_for("patch", &json!({ "file_path": "CLAUDE.md", "new_string": "y" })).unwrap();
        assert_eq!(s2.class, MemoryClass::ClaudeMd);
        let (verb2, basis2) = base_verb_for("patch");
        assert_eq!(verb2, MemoryVerb::Update);
        assert_eq!(basis2, VerbBasis::ToolEdit);
    }

    // ── Verb basis (§D-3) ──────────────────────────────────────────────────────────────────

    #[test]
    fn edit_tool_is_always_update_tool_edit_basis() {
        let (verb, basis) = base_verb_for("Edit");
        assert_eq!(verb, MemoryVerb::Update);
        assert_eq!(basis, VerbBasis::ToolEdit);
    }

    #[test]
    fn write_tool_is_write_tool_write_basis_by_default() {
        let (verb, basis) = base_verb_for("Write");
        assert_eq!(verb, MemoryVerb::Write);
        assert_eq!(basis, VerbBasis::ToolWrite);
    }

    // ── Hash-not-content (acceptance #2) ──────────────────────────────────────────────────

    #[test]
    fn emitted_receipt_never_contains_the_sentinel_content_only_its_hash() {
        let dir = std::env::temp_dir().join(format!("kriya-memwrite-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = dir.join("k.key");
        let log = dir.join("l.jsonl");
        let signer = Signer::with_identity(&key, log).unwrap();
        let actor = Actor::new("claude-code", "ci");

        let sentinel = "TOP-SECRET-SENTINEL-6f2c9a";
        let surface = memory_surface_for("Write", &json!({ "file_path": "CLAUDE.md", "content": sentinel })).unwrap();
        let content = file_write_content(&json!({ "file_path": "CLAUDE.md", "content": sentinel }));
        let salt = [7u8; 32];
        let corr = Correlation::run("run-1");
        let signed = emit_memory_receipt(
            &signer,
            Some(&actor),
            MemoryVerb::Write,
            VerbBasis::ToolWrite,
            &surface,
            &content,
            true,
            &corr,
            &salt,
        );

        let wire = serde_json::to_string(&signed).unwrap();
        assert!(!wire.contains(sentinel), "the sentinel content leaked into the signed receipt bytes");

        let expected_hash = sha256_hex(sentinel.as_bytes());
        let mem = signed.receipt.params.get(RESERVED_KEY).unwrap();
        assert_eq!(mem.get("content_sha256").unwrap().as_str().unwrap(), expected_hash);
        assert_eq!(mem.get("content_bytes").unwrap().as_u64().unwrap(), sentinel.len() as u64);
        assert_eq!(signed.receipt.action_id, crate::audit::MEMORY_WRITE);
        assert_eq!(mem.get("class").unwrap().as_str().unwrap(), "claude-md");
        assert_eq!(mem.get("verb_basis").unwrap().as_str().unwrap(), "tool-write");
        assert!(mem.get("path_hmac").unwrap().as_str().unwrap().len() == 64);
        // path_hmac must not be a plain unsalted hash of the guessable path.
        assert_ne!(mem.get("path_hmac").unwrap().as_str().unwrap(), sha256_hex(b"CLAUDE.md"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── prior-write-seen (§D-3/F4) ─────────────────────────────────────────────────────────

    #[test]
    fn prior_write_seen_detects_same_run_same_path_and_ignores_other_runs() {
        let dir = std::env::temp_dir().join(format!("kriya-memwrite-scan-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = dir.join("k.key");
        let log = dir.join("l.jsonl");
        let signer = Signer::with_identity(&key, log.clone()).unwrap();
        let actor = Actor::new("claude-code", "ci");
        let salt = [9u8; 32];

        let surface = memory_surface_for("Write", &json!({ "file_path": "CLAUDE.md", "content": "a" })).unwrap();
        let path_hmac = path_hmac_hex(&salt, "CLAUDE.md");

        // No prior write yet.
        assert!(!prior_write_seen(&log, "run-a", &path_hmac, 500));

        emit_memory_receipt(
            &signer,
            Some(&actor),
            MemoryVerb::Write,
            VerbBasis::ToolWrite,
            &surface,
            b"a",
            true,
            &Correlation::run("run-a"),
            &salt,
        );

        // Same run, same path: now seen.
        assert!(prior_write_seen(&log, "run-a", &path_hmac, 500));
        // Different run, same path: not seen (never cross-run).
        assert!(!prior_write_seen(&log, "run-b", &path_hmac, 500));

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── MCP lane content extraction ────────────────────────────────────────────────────────

    #[test]
    fn mcp_content_uses_named_field_or_falls_back_to_full_arguments() {
        let args = json!({ "entity": "the note body", "other": 1 });
        assert_eq!(mcp_memory_content(&args, Some("entity")), b"the note body".to_vec());
        // Unnamed field falls back to canonical full arguments (still hash-only downstream).
        let fallback = mcp_memory_content(&args, None);
        assert!(!fallback.is_empty());
    }

    #[test]
    fn op_verb_mapping_matches_d1() {
        assert_eq!(MemoryOp::Create.verb(), MemoryVerb::Write);
        assert_eq!(MemoryOp::Update.verb(), MemoryVerb::Update);
        assert_eq!(MemoryOp::Delete.verb(), MemoryVerb::Delete);
    }
}
