//! End-to-end smoke test for `kriya-gateway run --` (EG-C containment, doc 24 §11 B14). Builds the
//! real binary and spawns a REAL child process through it — the exact shape of the bypass this
//! feature exists to close: an agent-launched subprocess that ignores `HTTP_PROXY`/`HTTPS_PROXY`
//! and tries to connect directly. Asserts on the real OS sandbox boundary (Seatbelt), not just the
//! in-process proxy logic — that logic (allow/deny decisions, byte-tunneling, receipt shape) is
//! already covered by `mcp::contain`'s unit tests via raw sockets, which don't need `sandbox-exec`
//! at all. Together the two layers cover the whole design: this file proves a real subprocess
//! launched via `run --` cannot reach an arbitrary local port directly (the containment actually
//! contains); the unit tests prove what happens to traffic that DOES go through the proxy.
//!
//! macOS-only (Seatbelt): mirrors `kriya_hook_smoke.rs`'s self-building pattern. Gated on the
//! `contain` feature it exercises — the symbols it calls (`kriya::mcp::contain_sha256_hex`,
//! `seatbelt_profile`) are `#[cfg(feature = "contain")]` in `mcp/mod.rs`, so without this guard a
//! bare `cargo test -p kriya` fails to COMPILE the test target. Same idiom as the other
//! feature-gated suites (`fips_fixture.rs`, `pq_fixture.rs`, `broker_http.rs`,
//! `wasmexec_determinism.rs`).

#![cfg(target_os = "macos")]
#![cfg(feature = "contain")]

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;

fn build_binary() -> PathBuf {
    let status = Command::new(env!("CARGO"))
        .args([
            "build",
            "--no-default-features",
            "--features",
            "mcp-client,contain",
            "--bin",
            "kriya-gateway",
        ])
        .status()
        .expect("cargo build should run");
    assert!(status.success(), "kriya-gateway must build");

    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target/debug/kriya-gateway");
    assert!(path.is_file(), "expected binary at {}", path.display());
    path
}

/// A fresh, uniquely-named temp dir per call (mirrors `kriya_hook_smoke.rs`'s `sandbox()`).
fn workdir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "kriya-contain-smoke-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn read_lines(path: &PathBuf) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("each line is valid JSON"))
        .collect()
}

/// The core containment guarantee: a real subprocess launched through `run --`, that does NOT
/// cooperate with `HTTP_PROXY` (here: raw `nc`, which has no proxy awareness at all — exactly the
/// "spawned curl/subprocess" bypass doc 24 names throughout), cannot reach an arbitrary local
/// destination directly. This is the Seatbelt profile actually being applied to the real child,
/// not merely generating correct profile text (that's covered by the unit tests).
#[test]
fn run_blocks_a_direct_connection_a_real_subprocess_attempts_outside_the_proxy() {
    let bin = build_binary();
    let dir = workdir();

    // A "forbidden" destination the sandboxed child will try to reach DIRECTLY (never through the
    // proxy — nc doesn't know HTTP_PROXY exists). If containment works, this connection attempt
    // fails; if it succeeds, the sandbox did nothing.
    let forbidden = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let forbidden_port = forbidden.local_addr().unwrap().port();
    // Accept in the background so a (should-never-happen) successful connection doesn't hang.
    std::thread::spawn(move || {
        let _ = forbidden.accept();
    });

    let policy_path = dir.join("policy.yaml");
    std::fs::write(
        &policy_path,
        "rules:\n  - action: \"*\"\n    allow: true\negress:\n  rules: []\n  unlisted: deny\n",
    )
    .unwrap();
    let log_path = dir.join("run.jsonl");

    let status = Command::new(&bin)
        .args([
            "run",
            "--policy",
            policy_path.to_str().unwrap(),
            "--audit-log",
            log_path.to_str().unwrap(),
            "--",
            "/usr/bin/nc",
            "-zv",
            "-w",
            "2",
            "127.0.0.1",
            &forbidden_port.to_string(),
        ])
        .status()
        .expect("spawn kriya-gateway run");

    assert!(
        !status.success(),
        "a direct connection bypassing the proxy must be BLOCKED by the Seatbelt profile — the \
         sandboxed child must not reach an arbitrary local port"
    );

    // The bypass demo's other half, inline: the SAME destination, unsandboxed, must succeed —
    // proving this is genuine containment, not a coincidentally-unreachable port.
    let unsandboxed = Command::new("/usr/bin/nc")
        .args(["-zv", "-w", "2", "127.0.0.1", &forbidden_port.to_string()])
        .status()
        .expect("spawn unsandboxed nc");
    assert!(
        unsandboxed.success(),
        "the SAME destination must be reachable OUTSIDE the sandbox — the honest boundary this \
         feature draws (agents kriya launches, not host-wide)"
    );

    let lines = read_lines(&log_path);
    assert_eq!(lines.len(), 2, "expected exactly run.start + run.exit");
    assert_eq!(lines[0]["action_id"], "kriya.io.run.start");
    assert_eq!(lines[1]["action_id"], "kriya.io.run.exit");
    let exit_code = lines[1]["params"]["exit_code"].as_i64().unwrap();
    assert_ne!(
        exit_code, 0,
        "nc's own exit code must reflect the blocked connection"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// `run.start` names exactly what was enforced: re-deriving the Seatbelt profile from the
/// recorded `proxy_port` must hash to the recorded `seatbelt_profile_sha256` — so an auditor (or a
/// hostile assessor) can independently confirm the profile without trusting the log's prose.
#[test]
fn run_start_receipt_profile_hash_matches_the_actual_enforced_profile() {
    let bin = build_binary();
    let dir = workdir();
    let policy_path = dir.join("policy.yaml");
    std::fs::write(
        &policy_path,
        "rules:\n  - action: \"*\"\n    allow: true\negress:\n  rules: []\n  unlisted: deny\n",
    )
    .unwrap();
    let log_path = dir.join("run.jsonl");

    let _ = Command::new(&bin)
        .args([
            "run",
            "--policy",
            policy_path.to_str().unwrap(),
            "--audit-log",
            log_path.to_str().unwrap(),
            "--",
            "/bin/echo",
            "hi",
        ])
        .status();

    let lines = read_lines(&log_path);
    let start = &lines[0];
    assert_eq!(start["action_id"], "kriya.io.run.start");
    let port = start["params"]["proxy_port"].as_u64().unwrap() as u16;
    let recorded_sha = start["params"]["seatbelt_profile_sha256"].as_str().unwrap();

    let expected_profile = kriya::mcp::seatbelt_profile(port);
    let expected_sha = kriya::mcp::contain_sha256_hex(expected_profile.as_bytes());
    assert_eq!(
        recorded_sha, expected_sha,
        "the receipt must name exactly the profile that was actually written to disk and passed \
         to sandbox-exec — not a value that could drift from what was really enforced"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// `run` refuses to start at all without an `egress:` section — containment with no
/// operator-authored policy would sandbox the child for nothing (doc 24 §9 EG-C prompt).
#[test]
fn run_refuses_a_policy_with_no_egress_section() {
    let bin = build_binary();
    let dir = workdir();
    let policy_path = dir.join("policy.yaml");
    std::fs::write(&policy_path, "rules:\n  - action: \"*\"\n    allow: true\n").unwrap();

    let output = Command::new(&bin)
        .args([
            "run",
            "--policy",
            policy_path.to_str().unwrap(),
            "--",
            "/bin/echo",
            "hi",
        ])
        .output()
        .expect("spawn kriya-gateway run");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("egress"),
        "must name the missing egress: section, got: {stderr}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
