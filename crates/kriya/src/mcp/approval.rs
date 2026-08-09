//! Human-in-the-loop approval for actions a policy marks `RequiresApproval`, in MCP mode.
//!
//! The in-process host routes approval to a Tauri modal (a human at the app). An external
//! agent driving over stdio has no such UI, so approval is a trait with a few built-ins.
//! Default posture is **deny** — a guarded action with no one to approve it must not slip
//! through just because the requester is a remote agent.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use std::time::Duration;

/// Decides whether a policy-guarded action may proceed. Called only for actions the policy
/// returned `RequiresApproval` for; `Allow`/`Deny` never reach here.
pub trait ApprovalGate: Send {
    fn request(&self, action_id: &str, params: &Value) -> bool;
}

/// Safe default: deny everything that needs approval. With no interactive operator, a
/// guarded action is held rather than waved through.
pub struct DenyApproval;

impl ApprovalGate for DenyApproval {
    fn request(&self, _action_id: &str, _params: &Value) -> bool {
        false
    }
}

/// Approve everything that needs approval. For tests and explicitly-trusted deployments
/// only — using this in production defeats the approval gate.
pub struct AutoApprove;

impl ApprovalGate for AutoApprove {
    fn request(&self, _action_id: &str, _params: &Value) -> bool {
        true
    }
}

/// Prompt a human on the controlling terminal and wait for a y/n. Opens `/dev/tty`
/// directly rather than reading stdin, because in stdio transport stdin carries the
/// JSON-RPC stream — so the operator answers out-of-band from the agent's traffic.
/// Any failure to reach a tty (no terminal, EOF, non-unix) is treated as a denial, and an
/// unanswered prompt times out — also a denial — after 300s (matches `GuiApproval`'s own bound).
pub struct TtyApproval;

impl ApprovalGate for TtyApproval {
    fn request(&self, action_id: &str, params: &Value) -> bool {
        #[cfg(unix)]
        {
            prompt_on_tty(action_id, params).unwrap_or(false)
        }
        #[cfg(not(unix))]
        {
            let _ = (action_id, params);
            false
        }
    }
}

/// Prompt a human via a native macOS dialog (`osascript`). Unlike {@link TtyApproval}, this
/// works even when the MCP server is a child of a TUI host (e.g. Claude Code) that owns the
/// controlling terminal — the dialog is drawn by the window server, out-of-band from any tty.
/// Any failure to show the dialog, a cancel, or a timeout is treated as a denial.
#[cfg(target_os = "macos")]
pub struct GuiApproval;

#[cfg(target_os = "macos")]
impl ApprovalGate for GuiApproval {
    fn request(&self, action_id: &str, params: &Value) -> bool {
        prompt_via_osascript(action_id, params).unwrap_or(false)
    }
}

#[cfg(target_os = "macos")]
fn prompt_via_osascript(action_id: &str, params: &Value) -> std::io::Result<bool> {
    use std::process::Command;

    let body = format!(
        "An external agent wants to run a guarded action:\n\naction: {action_id}\nparams: {params}"
    );
    // Deny is both default and cancel button, so Esc / dismiss also denies. `giving up after`
    // bounds the wait so an unattended host can't hang forever on a held action.
    let script = format!(
        "display dialog {body} with title \"kriya — approval required\" \
         buttons {{\"Deny\", \"Approve\"}} default button \"Deny\" cancel button \"Deny\" \
         with icon caution giving up after 300",
        body = applescript_string(&body),
    );

    let output = Command::new("osascript").arg("-e").arg(script).output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    // osascript echoes `button returned:Approve` only when Approve was clicked; a cancel exits
    // non-zero with empty stdout, and a time-out yields `gave up:true` — both deny.
    Ok(stdout.contains("button returned:Approve"))
}

/// Render a Rust string as an AppleScript string literal (quote it, escape `\`, `"`, newline).
/// osascript receives this as source, so only AppleScript escaping is needed — no shell quoting,
/// since {@link std::process::Command} passes the arg without a shell.
#[cfg(target_os = "macos")]
fn applescript_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Matches `prompt_via_osascript`'s own `giving up after 300` bound. A caller of `ApprovalGate`
/// may itself be under an external timeout shorter than an indefinite wait (e.g. Claude Code's
/// hook runner, which fails a killed/timed-out hook **open** — see `kriya-hook`'s module doc) —
/// self-bounding here means an unanswered prompt denies itself well inside that ceiling instead
/// of leaving the decision to whichever side gives up first.
#[cfg(unix)]
const TTY_APPROVAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

#[cfg(unix)]
fn prompt_on_tty(action_id: &str, params: &Value) -> std::io::Result<bool> {
    use std::fs::OpenOptions;
    use std::io::{BufRead, BufReader, Write};
    use std::sync::mpsc;

    let tty = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
    let mut writer = tty.try_clone()?;
    write!(
        writer,
        "\n[kriya] APPROVAL REQUIRED — an external agent wants to run a guarded action:\n  action: {action_id}\n  params: {params}\n[kriya] approve? [y/N] (times out after {}s): ",
        TTY_APPROVAL_TIMEOUT.as_secs()
    )?;
    writer.flush()?;

    // `read_line` has no native timeout, so read on a dedicated thread and race it against the
    // deadline. On timeout the reader thread is left blocked on the read — harmless, since the
    // process exits shortly after this function returns either way (the `pre` hook has nothing
    // left to do once the decision is made).
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(tty).read_line(&mut line).map(|_| line);
        let _ = tx.send(result);
    });

    match rx.recv_timeout(TTY_APPROVAL_TIMEOUT) {
        Ok(Ok(line)) => {
            let answer = line.trim();
            Ok(answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes"))
        }
        Ok(Err(e)) => Err(e),
        // A timeout is a denial, not an IO error — the same outcome `prompt_via_osascript`
        // produces on its own `giving up after 300` (`gave up:true` → deny), so both interactive
        // gates fail the same direction on an unanswered prompt.
        Err(mpsc::RecvTimeoutError::Timeout) => Ok(false),
        Err(mpsc::RecvTimeoutError::Disconnected) => Ok(false),
    }
}

// ---------------------------------------------------------------------------
// FileApproval — approval routed through two append-only JSONL files
// ---------------------------------------------------------------------------

/// File name of the queue this gate appends a request to. See [`FileApproval`].
pub const PENDING_FILE: &str = "pending.jsonl";
/// File name the out-of-band decider appends its answer to. See [`FileApproval`].
pub const DECISIONS_FILE: &str = "decisions.jsonl";

/// Default self-bound on an unanswered request — the same 300 s ceiling the tty/gui gates use, and
/// well under Claude Code's 600 s hook timeout (which fails **open**), so the deny is decided here.
const FILE_APPROVAL_TIMEOUT: Duration = Duration::from_secs(300);
/// How often the pending gate re-reads [`DECISIONS_FILE`] while waiting.
const FILE_APPROVAL_POLL: Duration = Duration::from_millis(500);

/// The standard on-device directory the file-approval mailbox lives in:
/// `~/.kriya/console/approvals/`. Derived from [`crate::audit::default_console_dir`] so the runtime
/// (which appends to [`PENDING_FILE`] here) and a decider such as the Console/K-Apter (which appends
/// to [`DECISIONS_FILE`]) agree on one location with no shared config. Created if missing.
pub fn default_approvals_dir() -> PathBuf {
    crate::audit::default_console_dir().join("approvals")
}

/// One line of [`PENDING_FILE`]: a guarded action held for an out-of-band decision. This is a
/// **published wire format** (docs/FILE-APPROVAL.md) — the decider is a separate program (K-Apter),
/// so it must never depend on this crate. Additive fields only; unknown fields on read are ignored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingApproval {
    /// uuid v4; the correlation key the decision echoes back. Unique per request.
    pub id: String,
    /// The policy action id the approval is for (e.g. `claude-code__bash`).
    pub action_id: String,
    /// The action's parameters, verbatim, so a human can judge the request.
    pub params: Value,
    /// When the request was written, unix epoch milliseconds.
    pub requested_at_ms: u64,
    /// PID of the process that is waiting on this decision (diagnostics; a stale line whose PID is
    /// gone was abandoned on timeout).
    pub pid: u32,
}

/// One line of [`DECISIONS_FILE`]: the decider's answer to a [`PendingApproval`], matched by `id`.
/// The decider (K-Apter) writes these; this crate only reads them. Deny-default: absence of a
/// matching decision within the timeout is a denial, so a decider that never answers cannot let a
/// guarded action through.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalDecision {
    /// The `id` of the [`PendingApproval`] this answers.
    pub id: String,
    /// `true` = approve, `false` = deny. The only field that decides the outcome.
    pub approved: bool,
    /// When the decision was made, unix epoch milliseconds (diagnostics; optional on read).
    #[serde(default)]
    pub decided_at_ms: u64,
}

/// Route approval through the file mailbox in [`default_approvals_dir`]: append a [`PendingApproval`]
/// to [`PENDING_FILE`], then poll [`DECISIONS_FILE`] for a matching [`ApprovalDecision`] until the
/// timeout. Built for a **standalone device** with no Console, no tty, and no window server — the
/// deciding UI (K-Apter's held-action notification) is a separate process watching these files.
///
/// Deny-default like every other gate: an unanswered request times out (default 300 s) to a denial,
/// and any IO error (unwritable dir, unreadable decisions file) also denies — a guarded action is
/// never waved through by a coordination failure.
pub struct FileApproval {
    dir: PathBuf,
    timeout: Duration,
    poll: Duration,
}

impl FileApproval {
    /// Gate over the mailbox in `dir`, with the default 300 s timeout and 500 ms poll.
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            timeout: FILE_APPROVAL_TIMEOUT,
            poll: FILE_APPROVAL_POLL,
        }
    }

    /// Gate over [`default_approvals_dir`] with the default timeout/poll — the wiring the binaries'
    /// `--approval file` uses.
    pub fn with_default_dir() -> Self {
        Self::new(default_approvals_dir())
    }

    /// Override the timeout and poll interval (tests use a short pair; production keeps the defaults).
    pub fn with_timeout(mut self, timeout: Duration, poll: Duration) -> Self {
        self.timeout = timeout;
        self.poll = poll;
        self
    }

    fn request_inner(&self, action_id: &str, params: &Value) -> std::io::Result<bool> {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::time::{Instant, SystemTime, UNIX_EPOCH};

        std::fs::create_dir_all(&self.dir)?;

        let id = uuid::Uuid::new_v4().to_string();
        let requested_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let pending = PendingApproval {
            id: id.clone(),
            action_id: action_id.to_string(),
            params: params.clone(),
            requested_at_ms,
            pid: std::process::id(),
        };

        // One line, appended atomically-enough: a single `write_all` of the whole line under
        // append mode. The decider tails this file.
        let mut line = serde_json::to_string(&pending)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        line.push('\n');
        {
            let mut f = OpenOptions::new()
                .create(true)
                .append(true)
                .open(self.dir.join(PENDING_FILE))?;
            f.write_all(line.as_bytes())?;
            f.flush()?;
        }

        // Poll for a decision until the deadline. A missing decisions file just means "no answer
        // yet". Malformed lines are skipped, not fatal — the decider is a separate program.
        let decisions_path = self.dir.join(DECISIONS_FILE);
        let deadline = Instant::now() + self.timeout;
        loop {
            if let Some(approved) = scan_decision(&decisions_path, &id) {
                return Ok(approved);
            }
            if Instant::now() >= deadline {
                return Ok(false); // timed out → deny
            }
            std::thread::sleep(self.poll);
        }
    }
}

impl ApprovalGate for FileApproval {
    fn request(&self, action_id: &str, params: &Value) -> bool {
        // Any IO failure denies — a coordination error must not open the gate.
        self.request_inner(action_id, params).unwrap_or(false)
    }
}

/// Read `decisions.jsonl` and return the decision for `id` if one has been written yet. Returns
/// `None` when the file is absent or holds no matching, parseable line. The **last** matching line
/// wins, so a decider that corrects itself (append-only) has its final answer honored.
fn scan_decision(path: &std::path::Path, id: &str) -> Option<bool> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut found = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(d) = serde_json::from_str::<ApprovalDecision>(line) {
            if d.id == id {
                found = Some(d.approved);
            }
        }
    }
    found
}

#[cfg(test)]
mod file_approval_tests {
    use super::*;
    use serde_json::json;
    use std::io::Write;

    fn tmp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "kriya-file-approval-{tag}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write_decision(dir: &std::path::Path, id: &str, approved: bool) {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join(DECISIONS_FILE))
            .unwrap();
        let line = serde_json::to_string(&ApprovalDecision {
            id: id.to_string(),
            approved,
            decided_at_ms: 1,
        })
        .unwrap();
        writeln!(f, "{line}").unwrap();
    }

    fn read_pending(dir: &std::path::Path) -> Vec<PendingApproval> {
        std::fs::read_to_string(dir.join(PENDING_FILE))
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[test]
    fn writes_a_pending_line_with_action_and_params() {
        let dir = tmp_dir("pending");
        // No decision will ever arrive; a short timeout keeps the test fast.
        let gate = FileApproval::new(dir.clone())
            .with_timeout(Duration::from_millis(120), Duration::from_millis(20));
        let approved = gate.request("claude-code__bash", &json!({"cmd": "rm -rf /"}));
        assert!(!approved, "no decision within the timeout must deny");

        let pend = read_pending(&dir);
        assert_eq!(pend.len(), 1);
        assert_eq!(pend[0].action_id, "claude-code__bash");
        assert_eq!(pend[0].params, json!({"cmd": "rm -rf /"}));
        assert_eq!(pend[0].pid, std::process::id());
        assert!(!pend[0].id.is_empty());
    }

    #[test]
    fn timeout_denies() {
        let dir = tmp_dir("timeout");
        let gate = FileApproval::new(dir)
            .with_timeout(Duration::from_millis(100), Duration::from_millis(20));
        assert!(!gate.request("x", &json!({})));
    }

    #[test]
    fn matching_approve_decision_allows() {
        let dir = tmp_dir("approve");
        let gate_dir = dir.clone();
        // Decider: wait for the pending line, then approve exactly its id.
        let decider = std::thread::spawn(move || {
            for _ in 0..200 {
                if let Ok(text) = std::fs::read_to_string(dir.join(PENDING_FILE)) {
                    if let Some(line) = text.lines().find(|l| !l.trim().is_empty()) {
                        let p: PendingApproval = serde_json::from_str(line).unwrap();
                        write_decision(&dir, &p.id, true);
                        return;
                    }
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            panic!("pending line never appeared");
        });

        let gate = FileApproval::new(gate_dir)
            .with_timeout(Duration::from_secs(5), Duration::from_millis(20));
        let approved = gate.request("claude-code__bash", &json!({"cmd": "deploy"}));
        decider.join().unwrap();
        assert!(approved, "a matching approve decision must allow");
    }

    #[test]
    fn matching_deny_decision_denies() {
        let dir = tmp_dir("deny");
        let gate_dir = dir.clone();
        let decider = std::thread::spawn(move || {
            for _ in 0..200 {
                if let Ok(text) = std::fs::read_to_string(dir.join(PENDING_FILE)) {
                    if let Some(line) = text.lines().find(|l| !l.trim().is_empty()) {
                        let p: PendingApproval = serde_json::from_str(line).unwrap();
                        write_decision(&dir, &p.id, false);
                        return;
                    }
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            panic!("pending line never appeared");
        });

        let gate = FileApproval::new(gate_dir)
            .with_timeout(Duration::from_secs(5), Duration::from_millis(20));
        let approved = gate.request("x", &json!({}));
        decider.join().unwrap();
        assert!(!approved, "a matching deny decision must deny");
    }

    #[test]
    fn ignores_decisions_for_other_ids_then_times_out() {
        let dir = tmp_dir("otherid");
        // A decision for an unrelated id must not satisfy this request.
        write_decision(&dir, "some-other-id", true);
        let gate = FileApproval::new(dir)
            .with_timeout(Duration::from_millis(120), Duration::from_millis(20));
        assert!(!gate.request("x", &json!({})), "an unrelated approve must not leak through");
    }

    #[test]
    fn malformed_decision_lines_are_skipped() {
        let dir = tmp_dir("malformed");
        let gate_dir = dir.clone();
        let decider = std::thread::spawn(move || {
            for _ in 0..200 {
                if let Ok(text) = std::fs::read_to_string(dir.join(PENDING_FILE)) {
                    if let Some(line) = text.lines().find(|l| !l.trim().is_empty()) {
                        let p: PendingApproval = serde_json::from_str(line).unwrap();
                        // Junk line first, then the real approval — the junk must not abort the scan.
                        let mut f = std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(dir.join(DECISIONS_FILE))
                            .unwrap();
                        writeln!(f, "{{not valid json").unwrap();
                        writeln!(f, "").unwrap();
                        write_decision(&dir, &p.id, true);
                        return;
                    }
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            panic!("pending line never appeared");
        });

        let gate = FileApproval::new(gate_dir)
            .with_timeout(Duration::from_secs(5), Duration::from_millis(20));
        let approved = gate.request("x", &json!({}));
        decider.join().unwrap();
        assert!(approved, "a valid decision after malformed lines must still be honored");
    }

    #[test]
    fn last_matching_decision_wins() {
        let dir = tmp_dir("lastwins");
        // deny then approve for the same id — the corrected (last) answer wins.
        write_decision(&dir, "fixed-id", false);
        write_decision(&dir, "fixed-id", true);
        assert_eq!(scan_decision(&dir.join(DECISIONS_FILE), "fixed-id"), Some(true));
    }

    #[test]
    fn default_approvals_dir_is_under_console() {
        let d = default_approvals_dir();
        assert!(d.ends_with("approvals"));
        assert!(d.to_string_lossy().contains("console") || d.starts_with(std::env::temp_dir()));
    }
}
