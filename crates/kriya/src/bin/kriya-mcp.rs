//! `kriya-mcp` — expose a kriya app's actions as a **governed** MCP server over stdio.
//!
//! An external agent (Claude Desktop, Cursor, …) speaks MCP to this binary; every
//! `tools/call` is routed through the app's policy → approval → budget → signed-audit
//! gates before — and only if — it reaches the app. This is the bolt-on that turns kriya
//! from a rewrite into an add-on: point it at a tool-schema file and an action handler and
//! the app gains a governed agent surface without touching its own code.
//!
//! Usage:
//!   kriya-mcp --tools <schemas.json> [--policy <policy.yaml>] [--exec "<cmd>"]
//!            [--approval deny|tty|gui|auto|file] [--name <name>] [--actor <agent>] [--user <user>]
//!
//!   --tools     JSON array from the SDK's getToolSchemas() (required)
//!   --policy    YAML permission policy (default: safe built-in — create/edit allow,
//!               delete requires approval, everything else denied)
//!   --exec      command run per cleared action; it reads {"action","params"} on stdin and
//!               writes {"success","data","error"} on stdout. Omit for discovery-only.
//!   --approval  how guarded actions are decided: deny (default), tty (prompt a human on
//!               the terminal), gui (native macOS dialog — works under a TUI host like Claude
//!               Code), auto (approve — trusted/testing only), or file (route to an out-of-band
//!               decider such as K-Apter via the JSONL mailbox — for a standalone headless device)
//!   --name      server name reported in `initialize` (default: kriya-mcp)
//!   --actor     identity of the agent/client driving the server — stamped into every signed
//!               receipt's `actor` field (R8). Omit to leave receipts unattributed.
//!   --user      operator identity the run acts for (default: $USER). Only used with --actor.
//!   --audit-log path for the signed-receipt JSONL log (default: $TMPDIR/kriya-audit.jsonl)

use std::path::PathBuf;
use std::process::exit;
use std::sync::Arc;

use kriya::audit::{Actor, Signer};
#[cfg(target_os = "macos")]
use kriya::mcp::GuiApproval;
use kriya::mcp::{
    ActionExecutor, ActionOutcome, ApprovalGate, AutoApprove, DenyApproval, FileApproval,
    FnExecutor, Governor, PersistentProcessExecutor, ProcessExecutor, Server, TtyApproval,
};
use kriya::permissions::Policy;
use kriya::protocol::ToolSchema;

const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

struct Args {
    tools: Option<PathBuf>,
    policy: Option<PathBuf>,
    exec: Option<String>,
    approval: String,
    name: String,
    persistent: bool,
    actor: Option<String>,
    user: Option<String>,
    audit_log: Option<PathBuf>,
    /// O-10: read-only evidence mode — serve query tools over the verified receipt store instead of
    /// the governed action gateway. When set, `--tools`/`--exec`/`--policy`/`--approval` are unused.
    evidence: bool,
    /// O-10: the audit log file or directory the evidence server reads (default: the on-device audit
    /// dir `~/.kriya/audit`). Only meaningful with `--evidence`.
    audit: Option<PathBuf>,
}

fn usage_and_exit(msg: &str) -> ! {
    eprintln!("kriya-mcp: {msg}");
    eprintln!(
        "usage: kriya-mcp --tools <schemas.json> [--policy <policy.yaml>] [--exec \"<cmd>\"] \
         [--persistent] [--approval deny|tty|gui|auto|file] [--name <name>] \
         [--actor <agent>] [--user <user>] [--audit-log <path>]\n\
         \x20      kriya-mcp --evidence [--audit <file-or-dir>] [--name <name>] \
         [--actor <agent>] [--user <user>] [--audit-log <path>]   (read-only evidence reader)"
    );
    exit(2);
}

fn parse_args() -> Args {
    let mut tools: Option<PathBuf> = None;
    let mut policy: Option<PathBuf> = None;
    let mut exec: Option<String> = None;
    let mut approval = "deny".to_string();
    let mut name = "kriya-mcp".to_string();
    let mut persistent = false;
    let mut actor: Option<String> = None;
    let mut user: Option<String> = None;
    let mut audit_log: Option<PathBuf> = None;

    let mut evidence = false;
    let mut audit: Option<PathBuf> = None;

    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        // Each flag takes one value; a missing value is a usage error.
        let mut take = |label: &str| -> String {
            it.next()
                .unwrap_or_else(|| usage_and_exit(&format!("{label} needs a value")))
        };
        match flag.as_str() {
            "--tools" => tools = Some(PathBuf::from(take("--tools"))),
            "--policy" => policy = Some(PathBuf::from(take("--policy"))),
            "--exec" => exec = Some(take("--exec")),
            "--approval" => approval = take("--approval"),
            "--name" => name = take("--name"),
            "--persistent" => persistent = true,
            "--actor" => actor = Some(take("--actor")),
            "--user" => user = Some(take("--user")),
            "--audit-log" => audit_log = Some(PathBuf::from(take("--audit-log"))),
            "--evidence" => evidence = true,
            "--audit" => audit = Some(PathBuf::from(take("--audit"))),
            "-h" | "--help" => usage_and_exit("help"),
            other => usage_and_exit(&format!("unknown argument: {other}")),
        }
    }

    // In the governed-gateway mode, --tools is required; the evidence reader takes none.
    if !evidence && tools.is_none() {
        usage_and_exit("--tools <schemas.json> is required (or use --evidence for the read-only reader)");
    }
    Args {
        tools,
        policy,
        exec,
        approval,
        name,
        persistent,
        actor,
        user,
        audit_log,
        evidence,
        audit,
    }
}

/// Build the receipt actor (R8) from the binary's identity flags. Returns `None` when
/// no `--actor` was given, leaving receipts unattributed (backward compatible). When an
/// agent id is given, the operator defaults to `$USER`, then `"local"`.
fn build_actor(agent: Option<String>, user: Option<String>) -> Option<Actor> {
    let agent = agent?;
    let user = user
        .filter(|s| !s.trim().is_empty())
        .or_else(|| std::env::var("USER").ok().filter(|s| !s.trim().is_empty()))
        .unwrap_or_else(|| "local".to_string());
    Some(Actor::new(agent, user))
}

fn load_tools(path: &PathBuf) -> Vec<ToolSchema> {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| usage_and_exit(&format!("cannot read --tools file {path:?}: {e}")));
    serde_json::from_str(&text).unwrap_or_else(|e| {
        usage_and_exit(&format!("--tools file is not a tool-schema array: {e}"))
    })
}

fn build_approval(kind: &str) -> Box<dyn ApprovalGate> {
    match kind {
        "deny" => Box::new(DenyApproval),
        "tty" => Box::new(TtyApproval),
        "auto" => Box::new(AutoApprove),
        // file: route to an out-of-band decider (K-Apter) via the JSONL mailbox — for a standalone
        // device with no tty and no window server. Deny-default on timeout/IO error.
        "file" => Box::new(FileApproval::with_default_dir()),
        // Native macOS approval dialog — works even when the server is a child of a TUI host
        // (e.g. Claude Code) that owns the controlling terminal.
        #[cfg(target_os = "macos")]
        "gui" => Box::new(GuiApproval),
        #[cfg(not(target_os = "macos"))]
        "gui" => usage_and_exit("--approval gui is only available on macOS"),
        other => usage_and_exit(&format!(
            "--approval must be deny|tty|gui|auto|file, got '{other}'"
        )),
    }
}

fn build_executor(exec: Option<String>, persistent: bool) -> Box<dyn ActionExecutor> {
    match exec {
        // Persistent: spawn the handler once and reuse it (for handlers holding an expensive
        // connection, e.g. Actual Budget). Per-call: spawn fresh each time (cheap/stateless).
        Some(cmd) if persistent => Box::new(PersistentProcessExecutor::new(&cmd)),
        Some(cmd) => Box::new(ProcessExecutor::new(&cmd)),
        // Discovery-only: tools/list works, but any call fails with a clear message.
        None => Box::new(FnExecutor(|_id: &str, _p: &serde_json::Value| {
            ActionOutcome::failed(
                "kriya-mcp started without --exec — discovery only, cannot run actions",
            )
        })),
    }
}

fn main() -> std::io::Result<()> {
    let args = parse_args();

    if args.evidence {
        return run_evidence(&args);
    }

    // Governed-gateway mode requires --tools (enforced in parse_args).
    let tools_path = args.tools.clone().expect("--tools required in gateway mode");
    let schemas = load_tools(&tools_path);
    let policy = match &args.policy {
        Some(p) => Policy::load_or_default(p),
        None => Policy::default(),
    };
    let signer = Arc::new(match &args.audit_log {
        Some(p) => Signer::with_log_path(p.clone()),
        None => Signer::new(),
    });
    let approval = build_approval(&args.approval);
    let executor = build_executor(args.exec.clone(), args.persistent);

    let actor = build_actor(args.actor.clone(), args.user.clone());
    // A4 (doc 27 / docs/design/a4-fips-lane.md D2): consistency emission (low priority — the
    // receipt is additive either way).
    signer.attest_crypto_module("kriya-mcp", actor.clone());
    let governor = Governor::new(Arc::new(policy), signer.clone(), approval, executor)
        .with_actor(actor.clone());
    let mut server = Server::new(&args.name, SERVER_VERSION, schemas, governor);

    // Banner to stderr — stdout is reserved for the JSON-RPC stream.
    let exec_desc = match (&args.exec, args.persistent) {
        (Some(cmd), true) => format!("{cmd} (persistent)"),
        (Some(cmd), false) => format!("{cmd} (per-call)"),
        (None, _) => "<none: discovery only>".to_string(),
    };
    let actor_desc = match &actor {
        Some(a) => format!("{}/{}", a.agent, a.user),
        None => "<unattributed>".to_string(),
    };
    eprintln!(
        "[kriya-mcp] serving {} governed tool(s) · approval={} · actor={} · exec={} · audit log={}",
        server.tool_count(),
        args.approval,
        actor_desc,
        exec_desc,
        signer.log_path().display()
    );

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    server.serve(stdin.lock(), &mut out)
}

/// O-10: serve the **read-only evidence reader** over the verified receipt store. Unlike the
/// governed-gateway `main` path above, there is no policy, approval, or executor — the tools only
/// query signed receipts that verify. Before serving, it signs ONE `kriya.evidence.mcp.start`
/// receipt (the reader is itself in evidence) into a dedicated evidence log, so the boot is
/// queryable through the very tools it exposes.
fn run_evidence(args: &Args) -> std::io::Result<()> {
    use kriya::audit::{default_audit_dir, now_ms, Receipt, EVIDENCE_MCP_START};
    use kriya::mcp::{expand_logs, EvidenceServer, EVIDENCE_TOOL_NAMES};

    // The source we READ: a file or directory of signed logs (default: the on-device audit dir).
    let source = args.audit.clone().unwrap_or_else(default_audit_dir);

    // Where the start receipt is SIGNED: `--audit-log` if given, else a dedicated `evidence-mcp.jsonl`
    // in the audit dir — kept apart from the governed-action logs it reads, but discoverable (dogfood:
    // when `--audit` points at the dir, the reader's own boot receipt is queryable through its tools).
    let start_log = args.audit_log.clone().unwrap_or_else(|| {
        let dir = if source.is_dir() {
            source.clone()
        } else {
            default_audit_dir()
        };
        dir.join("evidence-mcp.jsonl")
    });
    if let Some(dir) = start_log.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    // A persistent signing identity beside the evidence log (fail-open to an ephemeral key so a
    // read-only reader never refuses to start over a key-file hiccup).
    let key_path = start_log
        .parent()
        .map(|p| p.join("keys").join("evidence-mcp.key"))
        .unwrap_or_else(|| PathBuf::from(".kriya-keys/evidence-mcp.key"));
    if let Some(kd) = key_path.parent() {
        let _ = std::fs::create_dir_all(kd);
    }
    let signer = kriya::audit::Signer::with_identity(&key_path, start_log.clone()).unwrap_or_else(|e| {
        eprintln!("[kriya-mcp] evidence: {e}; falling back to an ephemeral signing key");
        kriya::audit::Signer::with_log_path(start_log.clone())
    });

    let actor = build_actor(args.actor.clone(), args.user.clone());
    let params = serde_json::json!({ "scope": "read-only", "tools": EVIDENCE_TOOL_NAMES });
    signer.record(
        Receipt::new(
            uuid::Uuid::new_v4().to_string(),
            EVIDENCE_MCP_START.to_string(),
            params,
            true,
            now_ms(),
        )
        .with_actor(actor.clone()),
    );

    let server = EvidenceServer::new(&args.name, SERVER_VERSION, vec![source.clone()]);
    let actor_desc = match &actor {
        Some(a) => format!("{}/{}", a.agent, a.user),
        None => "<unattributed>".to_string(),
    };
    // Count is re-derived on each call; report the count at boot (now includes the start receipt).
    let log_count = expand_logs(&source).len();
    eprintln!(
        "[kriya-mcp] evidence reader: {} read-only tool(s) · actor={} · reading {} log(s) from {} · start receipt → {}",
        server.tool_count(),
        actor_desc,
        log_count,
        source.display(),
        signer.log_path().display()
    );

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    server.serve(stdin.lock(), &mut out)
}
