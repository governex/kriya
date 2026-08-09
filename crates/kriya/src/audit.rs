//! Signed audit trail. The host holds an Ed25519 key the agent never sees and signs a
//! receipt for every executed action. Receipts are appended to a JSONL log and can be
//! verified offline by anyone holding the public key.

use crate::crypto::{self, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Identity of *who* took an action: the agent that proposed it and the human/operator
/// on whose behalf it ran. Carried **inside** the signed receipt so attribution is
/// tamper-evident — rewriting who-did-what invalidates the signature, exactly like
/// rewriting the params would (R8).
///
/// Both fields are free-form strings the host supplies. `agent` is typically a backend
/// name, an MCP client id, or a model id; `user` is an OS user, an SSO subject, or any
/// app-provided operator identity. This is the *primitive* — richer identity management
/// (SSO/OIDC, RBAC) is a separate, paid concern; the signed field stays in the open core.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    /// Which agent drove the action — a backend name, MCP client id, or model id.
    pub agent: String,
    /// The human/operator identity the run acted for — an OS user, SSO subject, etc.
    pub user: String,
}

impl Actor {
    pub fn new(agent: impl Into<String>, user: impl Into<String>) -> Self {
        Self {
            agent: agent.into(),
            user: user.into(),
        }
    }
}

/// Reserved `action_id` for the R13 on-device attestation receipt — a signed record that a
/// run was sealed (the inference backend made no remote egress). Recognizable by verifiers
/// and the console as an attestation rather than an app action.
pub const ATTESTATION_ON_DEVICE: &str = "kriya.attestation.on_device";

/// Reserved `action_id` for the A4 crypto-module attestation receipt (doc 27 A4 /
/// `docs/design/a4-fips-lane.md` D2) — a signed record of WHICH crypto lane this signer's process
/// ran under (default `ed25519-dalek` or the opt-in FIPS `aws-lc-rs` lane), emitted once by the
/// binary via [`Signer::attest_crypto_module`]. New `action_id` ⇒ fully additive: no existing
/// receipt or verifier changes shape (design RT2.1). See [`crate::crypto`] for the honesty axiom
/// this attestation is bound by (a signature never reveals its own module).
pub const ATTESTATION_CRYPTO_MODULE: &str = "kriya.crypto.module";

/// Reserved `action_id` for a **retention epoch-checkpoint** receipt (doc 24 §6-P2 / EG-2). Signed
/// like any receipt and part of the chain, it seals a pruned prefix: its `params` attest
/// `{pruned_before_ts_ms, policy, prior_head_hash, pruned_count}` — "receipts before T were pruned
/// per policy P; the prior head hash was H." Verifiers accept it as a legitimate sealed chain point
/// (not a head-truncation break), so compliant deletion (GDPR erasure, retention limits) stays
/// tamper-evident instead of reading as tampering. See [`prune_and_seal`].
pub const RETENTION_CHECKPOINT: &str = "kriya.retention.checkpoint";

/// Reserved `action_id` for the A5 PQ checkpoint receipt (doc 27 A5 / `docs/design/a5-pq-dual-sig.md`
/// §4.1, D1/D4 — the DEFAULT PQ mode) — a normal signed, hash-chained receipt whose ML-DSA-87
/// countersignature (top-level `pq_*` wire siblings, see [`SignedReceipt`]) seals the chain head
/// recorded in `params.to_head_hash`, so ONE post-quantum signature transitively anchors the whole
/// sealed prefix (SHA-256 collision resistance + one ML-DSA-87 signature — design axiom §1.4).
/// Emitted every N receipts (default 256) / on a time cadence via [`Signer::pq_checkpoint`].
pub const PQ_CHECKPOINT: &str = "kriya.crypto.pq_checkpoint";

/// Reserved `action_id` for the A5 PQ key attestation/rotation receipt (design §4.2) — an
/// Ed25519-signed receipt binding an ML-DSA-87 public key to this host's pinned Ed25519 identity,
/// via [`Signer::attest_pq_key`]. A fresh attestation (new `pq_key_id`) is rotation; older
/// checkpoints/dual-signed receipts stay self-verifying under their inline old `pq_public_key`.
pub const PQ_KEY: &str = "kriya.crypto.pq_key";

/// Reserved `action_id`s for the D1 memory-write receipt family (doc 27 §4 /
/// `docs/design/d1-memory-receipts.md` §D-3) — a signed, hash-only record that a governed
/// persistent-memory surface (Claude Code's `CLAUDE.md`/memory-dir/settings files, or an
/// operator-registered MCP memory tool) was written to. Three verbs, each a fully additive new
/// `action_id`: no existing receipt or verifier changes shape (the doc-27 §3.1 pattern the
/// `kriya.crypto.*`/`kriya.retention.*`/`kriya.spend.*` constants already follow). All fields ride
/// in `params` under the reserved `kriya.memory` sub-key (mirrors `kriya.corr::RESERVED_KEY`'s
/// placement discipline) — content is NEVER recorded, only its SHA-256 + byte size (§D-3/§3 red
/// team). See [`crate::memwrite`] for the classifier + emitter.
pub const MEMORY_WRITE: &str = "kriya.memory.write";
/// See [`MEMORY_WRITE`]. An existing memory mutated (`claude-code__edit`; a `Write` to a
/// previously-seen path in this run; an MCP `update` op).
pub const MEMORY_UPDATE: &str = "kriya.memory.update";
/// See [`MEMORY_WRITE`]. A memory removed — mainly the MCP registry's `delete` op; Claude Code's
/// hook lane cannot observe a file-class delete (`Write`/`Edit` cannot delete, and `Bash` is opaque
/// to the hook), an honest gap disclosed in `docs/TRUST.md`, not filled by a guess here.
pub const MEMORY_DELETE: &str = "kriya.memory.delete";

/// Reserved `action_id` for the O-10 evidence-MCP boot receipt (doc 33 §5.8) — a signed record that
/// a **read-only** evidence MCP server ([`crate::mcp::evidence`]) started over the audit store,
/// emitted once on boot by `kriya-mcp --evidence`. The evidence reader is itself in evidence: the
/// receipt's `params` attest `{scope: "read-only", tools: [...]}` — never a query or a result. New
/// `action_id` ⇒ fully additive: no existing receipt or verifier changes shape (the doc-27 §3.1
/// pattern the other `kriya.*` constants above follow).
pub const EVIDENCE_MCP_START: &str = "kriya.evidence.mcp.start";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub step_id: String,
    pub action_id: String,
    pub params: Value,
    pub success: bool,
    pub ts_ms: u128,
    /// Who took the action (R8). Optional and **skipped when absent** so a receipt
    /// without attribution signs byte-identically to the original (pre-R8) format —
    /// every existing verifier (the offline CLI, the console's TS verifier, the 20
    /// real receipts cross-checked there) keeps validating unchanged. Declared last so
    /// the canonical serialization order of the original five fields is preserved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<Actor>,
    /// Hash of the previous receipt LINE in this audit log (R20). Chains receipts so whole-receipt
    /// deletion / truncation / reorder is detectable — turning "no retained receipt was altered"
    /// into "the log is complete." Absent on the genesis receipt (and on pre-R20 receipts), so an
    /// unchained receipt signs **byte-identically** to before. Declared last so the canonical order
    /// of the original fields + `actor` is preserved; `prev_hash` is part of the signed bytes, so
    /// the chain pointer itself can't be rewritten without invalidating the signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
}

impl Receipt {
    /// A receipt with no identity attribution (the pre-R8 shape).
    pub fn new(
        step_id: String,
        action_id: String,
        params: Value,
        success: bool,
        ts_ms: u128,
    ) -> Self {
        Self {
            step_id,
            action_id,
            params,
            success,
            ts_ms,
            actor: None,
            prev_hash: None,
        }
    }

    /// Attach (or clear) the acting identity. Chainable on top of [`Receipt::new`].
    pub fn with_actor(mut self, actor: Option<Actor>) -> Self {
        self.actor = actor;
        self
    }
}

// NOTE: no derived `Deserialize` — the `#[serde(flatten)] receipt` combined with `Receipt`'s
// `ts_ms: u128` trips serde's flatten limitation (flatten buffers through an internal `Content`
// type that cannot represent 128-bit integers). Parse lines via [`parse_signed_line`] instead,
// which reconstructs from a `serde_json::Value` and never flattens.
#[derive(Debug, Clone, Serialize)]
pub struct SignedReceipt {
    #[serde(flatten)]
    pub receipt: Receipt,
    pub public_key: String,
    pub signature: String,
    /// A5 (design D2): additive top-level wire siblings — NOT inside the signed `Receipt` bytes
    /// (same position as `public_key`/`signature` above, which are also outside the signed
    /// bytes). "ML-DSA-87" exactly, the require-if-present trigger. `None` (omitted from the
    /// wire via `skip_serializing_if`) on every pre-A5 / non-PQ receipt, so the JSON is
    /// byte-identical to today when PQ material is absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pq_alg: Option<String>,
    /// The ML-DSA-87 public key, hex — inline/self-contained (design D2: per-receipt dual-sig and
    /// the checkpoint both need offline single-line verification).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pq_public_key: Option<String>,
    /// The ML-DSA-87 signature, hex, over the identical canonical receipt bytes
    /// (`serde_json::to_vec(&receipt)`) the Ed25519 `signature` covers (design D2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pq_sig: Option<String>,
    /// First 8 bytes of SHA-256(`pq_public_key`), lowercase hex (design D2/D3) — binds this line
    /// to a `kriya.crypto.pq_key` attestation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pq_key_id: Option<String>,
}

pub struct Signer {
    key: SigningKey,
    public_hex: String,
    log_path: PathBuf,
    /// The chain head (R20): hash of the last line written to `log_path` plus the log's byte length
    /// as of that observation. Seeded at construction so a new process continues the chain; behind a
    /// `Mutex` for threads sharing one signer. The length is the cheap staleness probe for
    /// CONCURRENT writers (W1-6): under the file lock in [`Signer::record`], a length mismatch means
    /// another process appended since we last looked, and the head is re-seeded from disk before
    /// chaining — so parallel hook invocations extend one chain instead of forking it.
    chain: Mutex<ChainHead>,
    /// A4 (design §4 `key_provenance`): `"module-drbg"` when this key was freshly minted under the
    /// `fips-crypto` lane, `"external-rng"` when freshly minted under the default lane, or
    /// `"imported-seed"` when loaded from a pre-existing persisted `signing.key` — disclosed
    /// honestly rather than laundered into "module-drbg" (RT2.3).
    key_provenance: &'static str,
    /// A5 (design D1/D3/D4): `None` unless this signer was built with [`Signer::with_pq`]. Only
    /// exists when the `pq-crypto` feature is compiled in — a signer built without the feature can
    /// never carry PQ material, by construction, not by convention.
    #[cfg(feature = "pq-crypto")]
    pq: Option<PqState>,
}

/// A5: the PQ signing state attached to a [`Signer`] via [`Signer::with_pq`]. See [`PQ_CHECKPOINT`]
/// / [`PQ_KEY`] / the per-receipt `pq_*` siblings on [`SignedReceipt`].
#[cfg(feature = "pq-crypto")]
struct PqState {
    key: crypto::PqSigningKey,
    /// First 8 bytes of SHA-256(public key), lowercase hex (design D2/D3).
    key_id: String,
    /// Design §4 `key_provenance`, PQ variant: `"module-drbg"` | `"external-rng"` | `"imported-seed"`.
    key_provenance: &'static str,
    /// Design D1: the opt-in high-assurance dial — when `true`, EVERY receipt this signer records
    /// carries a per-receipt ML-DSA-87 dual signature (§2 D1's ~14.5 KiB/line cost); when `false`
    /// (the default/recommended mode), only [`Signer::pq_checkpoint`] carries PQ material. An
    /// `AtomicBool` (not a plain `bool`) because [`Signer::pq_checkpoint`] briefly forces this to
    /// `true` around its own internal `record()` call — the checkpoint's PQ signature MUST be
    /// attached before the line is serialized/persisted (`attach_pq_dual_sign` runs inside
    /// `record_persisted`, before the write), so there is no way to attach it correctly
    /// AFTER `record()` returns (the line would already be on disk without it).
    dual_sign_enabled: std::sync::atomic::AtomicBool,
    /// Running count of receipts sealed by [`Signer::record_persisted`] since this process started
    /// (design §4.1 `from_seq`/`count` basis — an in-memory counter, not a durable sequence number;
    /// see the `pq_checkpoint` doc comment for the known cross-process/restart limitation).
    seq_counter: Mutex<u64>,
    /// `seq_counter` value as of the last [`Signer::pq_checkpoint`] call (design §4.1 `from_seq`).
    last_checkpoint_seq: Mutex<u64>,
}

/// See [`Signer::chain`].
struct ChainHead {
    hash: Option<String>,
    len: u64,
}

impl Default for Signer {
    fn default() -> Self {
        Self::new()
    }
}

impl Signer {
    pub fn new() -> Self {
        Self::with_log_path(std::env::temp_dir().join("kriya-audit.jsonl"))
    }

    /// Mint a signer that appends to a specific log file. Useful for tests, demos, and
    /// any host that wants its audit trail somewhere other than the shared temp file.
    pub fn with_log_path(log_path: PathBuf) -> Self {
        let (_seed, key) = SigningKey::generate();
        let public_hex = hex::encode(key.public_key());
        let chain = Mutex::new(seed_chain_head(&log_path));
        Self {
            key,
            public_hex,
            log_path,
            chain,
            key_provenance: FRESH_KEY_PROVENANCE,
            #[cfg(feature = "pq-crypto")]
            pq: None,
        }
    }

    /// Mint a signer whose Ed25519 identity is **persisted** at `key_path` — loaded if present,
    /// else generated and written (0600 on Unix). Unlike [`Signer::new`] / [`Signer::with_log_path`]
    /// (which mint an *ephemeral* per-process key), this gives a **stable trust anchor across runs**
    /// (R20): the public key an auditor pins stays the same deployment-to-deployment, so the audit
    /// trail is verifiable over months, not just within one session. Errors if the key file exists
    /// but is unreadable/invalid — a signing identity is never silently overwritten.
    pub fn with_identity(key_path: &Path, log_path: PathBuf) -> Result<Self, String> {
        let (seed, freshly_generated) = load_or_create_seed(key_path)?;
        let key = SigningKey::from_seed(&seed);
        let public_hex = hex::encode(key.public_key());
        let chain = Mutex::new(seed_chain_head(&log_path));
        Ok(Self {
            key,
            public_hex,
            log_path,
            chain,
            key_provenance: if freshly_generated {
                FRESH_KEY_PROVENANCE
            } else {
                // A key that already existed on disk before this call — honestly disclosed as
                // imported even when the process is now running the FIPS lane (design RT2.3): we
                // cannot know under which lane it was originally minted.
                "imported-seed"
            },
            #[cfg(feature = "pq-crypto")]
            pq: None,
        })
    }

    /// A5 (design D3): attach a **persisted** ML-DSA-87 identity to this signer — loaded from
    /// `pq_key_path` if present, else minted fresh (module DRBG, design D3) and written there
    /// (0600 on Unix), mirroring [`Signer::with_identity`]'s Ed25519 discipline exactly (same
    /// on-disk-secret-is-the-seed shape, same never-silently-overwrite guarantee). Consuming
    /// builder — chain onto [`Signer::with_identity`] / [`Signer::with_log_path`].
    ///
    /// `dual_sign_enabled` is design D1's opt-in high-assurance dial: `true` makes EVERY
    /// subsequent [`Signer::record`]/[`Signer::record_persisted`] call attach a per-receipt PQ
    /// dual signature (~14.5 KiB/line — reserve this for low-volume, high-value signers: policy
    /// bundles, org-key control-plane signatures, retention checkpoints, evidence-export seals).
    /// `false` (the default/recommended mode) means only [`Signer::pq_checkpoint`] carries PQ
    /// material. Either way, [`Signer::attest_pq_key`] and [`Signer::pq_checkpoint`] become
    /// available once this is called.
    ///
    /// On error, returns `(self, reason)` — the ORIGINAL signer, unchanged, alongside the reason
    /// (mirrors [`NotPersisted`] carrying its payload) — so a caller that wants to fail open (run
    /// without the PQ lane rather than not start at all) can recover the signer it already had
    /// instead of being forced to reconstruct it from scratch.
    #[cfg(feature = "pq-crypto")]
    pub fn with_pq(mut self, pq_key_path: &Path, dual_sign_enabled: bool) -> Result<Self, (Self, String)> {
        let (seed, freshly_generated) = match load_or_create_pq_seed(pq_key_path) {
            Ok(v) => v,
            Err(e) => return Err((self, e)),
        };
        let key = match crypto::PqSigningKey::from_seed(&seed) {
            Ok(k) => k,
            Err(e) => return Err((self, format!("loading PQ (ML-DSA-87) key: {e}"))),
        };
        let key_id = pq_key_id_hex(&key.public_key());
        self.pq = Some(PqState {
            key,
            key_id,
            key_provenance: if freshly_generated {
                FRESH_PQ_KEY_PROVENANCE
            } else {
                "imported-seed"
            },
            dual_sign_enabled: std::sync::atomic::AtomicBool::new(dual_sign_enabled),
            seq_counter: Mutex::new(0),
            last_checkpoint_seq: Mutex::new(0),
        });
        Ok(self)
    }

    pub fn public_key(&self) -> &str {
        &self.public_hex
    }

    pub fn log_path(&self) -> &std::path::Path {
        &self.log_path
    }

    /// Sign a receipt and append it to the audit log. Returns the signed receipt — infallibly, for
    /// the fail-OPEN default: a receipt that could not be persisted is still returned (and the
    /// failure is swallowed), so a lost log line never takes down the caller. Callers that need to
    /// know whether the line durably hit disk — the fail-CLOSED "no receipt, no egress" mode
    /// (doc 24 B3) — use [`Signer::record_persisted`] instead.
    ///
    /// Concurrency (W1-6): the [seed tail → chain → append] window is serialized against OTHER
    /// PROCESSES by an exclusive advisory lock on the log file (Unix `flock`, auto-released on fd
    /// close — so a crashed writer never wedges the chain). Under the lock the on-disk length is
    /// compared with our last observation and the head re-seeded if someone else appended — the
    /// exact race parallel hook invocations hit (two fresh processes both seeded from the same
    /// tail would otherwise both claim the same `prev_hash`, forking the chain into what a
    /// verifier must read as tampering). Off-unix the lock is a no-op and the contract remains
    /// single-writer-per-log-at-a-time.
    pub fn record(&self, receipt: Receipt) -> SignedReceipt {
        // Fail-open: on a write failure return the signed receipt anyway (the historical contract).
        match self.record_persisted(receipt) {
            Ok(signed) => signed,
            Err(e) => e.signed,
        }
    }

    /// Sign a receipt and append it, reporting whether the **append write succeeded**. `Ok` iff the
    /// `writeln!` returned Ok (note: not `fsync`-durable — a crash before the OS flushes could still
    /// lose it); `Err(NotPersisted)` (still carrying the signed receipt) when the log was
    /// unopenable/unwritable. This is the seam for fail-closed receipt-precondition mode (doc 24 B3):
    /// the governor signs the `kriya.io.*` receipt through this before performing the egress, and a
    /// non-persisted receipt denies the egress — the receipt becomes a control, not just a record.
    // The Err intentionally carries the whole signed receipt (so the fail-OPEN wrapper can still
    // surface it), which is what makes the error type "large" — by design, not an oversight.
    #[allow(clippy::result_large_err)]
    pub fn record_persisted(&self, mut receipt: Receipt) -> Result<SignedReceipt, NotPersisted> {
        // Canonicalize before signing (R21): recursively sort `params` object keys so the signed
        // bytes never depend on a consumer's serde_json `preserve_order` feature. The offline
        // `tools/verify-receipts` applies the identical sort before re-deriving the bytes.
        receipt.params = canonical_value(&receipt.params);
        // Hash-chain (R20): link this receipt to the previous LINE so whole-receipt deletion or
        // truncation is detectable. The in-process Mutex orders threads sharing this signer; the
        // file lock below orders separate processes sharing the log.
        let mut chain = self.chain.lock().unwrap_or_else(|e| e.into_inner());
        let locked = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .ok()
            .inspect(|f| {
                lock_exclusive(f);
                // Staleness probe: a length change means another writer appended since our last
                // observation — re-seed the head from the true on-disk tail before chaining.
                let disk_len = f.metadata().map(|m| m.len()).unwrap_or(chain.len);
                if disk_len != chain.len {
                    *chain = seed_chain_head(&self.log_path);
                }
            });
        receipt.prev_hash = chain.hash.clone(); // None on the genesis receipt
                                                // Canonical bytes = compact JSON of the unsigned (key-sorted, now chained) receipt.
        let msg = serde_json::to_vec(&receipt).unwrap_or_default();
        let signature = hex::encode(self.key.sign(&msg));
        let mut signed = SignedReceipt {
            receipt,
            public_key: self.public_hex.clone(),
            signature,
            pq_alg: None,
            pq_public_key: None,
            pq_sig: None,
            pq_key_id: None,
        };
        // A5 (design D1/D2, opt-in per-receipt dual-sig): a no-op unless this signer was built
        // with `with_pq(..., dual_sign_enabled = true)`. Must run BEFORE the line is serialized
        // below so the `pq_*` siblings are part of what gets written/chained/hashed.
        self.attach_pq_dual_sign(&mut signed);
        let line = serde_json::to_string(&signed).unwrap_or_default();
        let persisted = if let Some(mut f) = locked {
            if writeln!(f, "{line}").is_ok() {
                // The exact line just written becomes the next receipt's `prev_hash`; advance the
                // observed length by what we appended (we hold the lock, nothing interleaves).
                chain.hash = Some(sha256_hex(line.as_bytes()));
                chain.len += line.len() as u64 + 1;
                // A5: count this receipt toward the next `pq_checkpoint`'s `count`/`from_seq`
                // (design §4.1) — a no-op unless a PQ key is loaded on this signer.
                self.note_pq_receipt_sealed(&signed.receipt.action_id);
                true
            } else {
                false
            }
            // Lock released when `f` drops.
        } else {
            // Unopenable: the head deliberately does NOT advance — advancing it would make the next
            // successful receipt chain to a line that never hit disk (a self-inflicted verifier
            // break on top of a lost receipt).
            false
        };
        if persisted {
            Ok(signed)
        } else {
            Err(NotPersisted {
                reason: format!("audit log {} could not be written", self.log_path.display()),
                signed,
            })
        }
    }

    /// Sign a receipt **without appending** — for callers that assemble their own file (the
    /// retention [`prune_and_seal`] re-chains retained receipts onto a checkpoint). `prev_hash` is
    /// taken from the receipt as passed (the caller sets the chain link); `params` are canonicalized
    /// exactly as [`Signer::record`] does, so a re-signed line is byte-identical to a natively
    /// recorded one.
    pub fn sign_only(&self, mut receipt: Receipt) -> SignedReceipt {
        receipt.params = canonical_value(&receipt.params);
        let msg = serde_json::to_vec(&receipt).unwrap_or_default();
        let signature = hex::encode(self.key.sign(&msg));
        SignedReceipt {
            receipt,
            public_key: self.public_hex.clone(),
            signature,
            pq_alg: None,
            pq_public_key: None,
            pq_sig: None,
            pq_key_id: None,
        }
    }

    /// A4 (design D2): emit the `kriya.crypto.module` self-attestation — a normal signed,
    /// hash-chained receipt (not a genesis; never auto-fired from a constructor, see the design's
    /// three reasons) that records which crypto lane this process ran under. `component` is the
    /// caller's binary/module name (only the binary knows it — e.g. `"kriya-gateway"`,
    /// `"kriya-hook"`); `actor` is attached like any other receipt.
    ///
    /// This is a **host self-attestation**, not a cryptographic proof (design §1, §4): the
    /// signature over this receipt proves the *receipt* is authentic and unmodified, not that the
    /// reported lane actually produced the neighboring signatures.
    pub fn attest_crypto_module(&self, component: &str, actor: Option<Actor>) -> SignedReceipt {
        let module = crypto::active_module();
        let params = serde_json::json!({
            "backend": module.backend,
            "fips_module": module.fips_module,
            "cmvp_cert": module.cmvp_cert,
            "fips_mode_active": module.fips_mode_active,
            "operational_environment": module.operational_environment,
            "key_provenance": self.key_provenance,
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "component": component,
        });
        self.record(
            Receipt::new(
                uuid::Uuid::new_v4().to_string(),
                ATTESTATION_CRYPTO_MODULE.to_string(),
                params,
                true,
                now_ms(),
            )
            .with_actor(actor),
        )
    }

    /// A5 (design D1/D2, opt-in per-receipt dual-sig): attach `pq_*` wire siblings to `signed` when
    /// this signer carries a PQ key with `dual_sign_enabled` currently `true` — either because the
    /// signer was built that way ([`Signer::with_pq`]) or because [`Signer::pq_checkpoint`]
    /// briefly forced it on around its own `record()` call (see the `PqState::dual_sign_enabled`
    /// doc comment for why). Signs the identical canonical bytes
    /// (`serde_json::to_vec(&receipt)`) the Ed25519 `signature` covers (design D2) — called after
    /// Ed25519 signing, before the line is serialized/persisted.
    #[cfg(feature = "pq-crypto")]
    fn attach_pq_dual_sign(&self, signed: &mut SignedReceipt) {
        let Some(pq) = &self.pq else { return };
        if !pq.dual_sign_enabled.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let msg = serde_json::to_vec(&signed.receipt).unwrap_or_default();
        let sig = pq.key.sign(&msg);
        signed.pq_alg = Some("ML-DSA-87".to_string());
        signed.pq_public_key = Some(hex::encode(pq.key.public_key()));
        signed.pq_sig = Some(hex::encode(sig));
        signed.pq_key_id = Some(pq.key_id.clone());
    }
    #[cfg(not(feature = "pq-crypto"))]
    fn attach_pq_dual_sign(&self, _signed: &mut SignedReceipt) {}

    /// A5: count one more receipt toward the next [`Signer::pq_checkpoint`]'s `count`/`from_seq`
    /// (design §4.1). A no-op unless a PQ key is loaded — called unconditionally from
    /// [`Signer::record_persisted`] on every successfully persisted receipt, regardless of
    /// `dual_sign_enabled`, because the checkpoint counts ALL sealed receipts, not just
    /// per-receipt-dual-signed ones. Excludes `PQ_CHECKPOINT`/`PQ_KEY` receipts themselves — a
    /// checkpoint seals the receipts BEFORE it, not itself, so it must not inflate the next
    /// checkpoint's count.
    #[cfg(feature = "pq-crypto")]
    fn note_pq_receipt_sealed(&self, action_id: &str) {
        if action_id == PQ_CHECKPOINT || action_id == PQ_KEY {
            return;
        }
        if let Some(pq) = &self.pq {
            let mut n = pq.seq_counter.lock().unwrap_or_else(|e| e.into_inner());
            *n += 1;
        }
    }
    #[cfg(not(feature = "pq-crypto"))]
    fn note_pq_receipt_sealed(&self, _action_id: &str) {}

    /// A5 (design §4.2, D3): emit the `kriya.crypto.pq_key` attestation — an **Ed25519-signed**
    /// (need not itself be dual-signed) hash-chained receipt binding this signer's ML-DSA-87
    /// public key to the pinned Ed25519 identity. Call once at startup (beside
    /// [`Signer::attest_crypto_module`]) and again on rotation (a fresh call after
    /// [`Signer::with_pq`] loads/mints a new seed) — each call records the CURRENT `pq_key_id`;
    /// older checkpoints/dual-signed lines stay self-verifying under their own inline
    /// `pq_public_key` (no history re-signing, design D3).
    ///
    /// Errors if this signer has no PQ key loaded (call [`Signer::with_pq`] first).
    #[cfg(feature = "pq-crypto")]
    pub fn attest_pq_key(&self, component: &str, actor: Option<Actor>) -> Result<SignedReceipt, String> {
        let pq = self
            .pq
            .as_ref()
            .ok_or_else(|| "attest_pq_key: no PQ key loaded (call Signer::with_pq first)".to_string())?;
        let params = serde_json::json!({
            "pq_alg": "ML-DSA-87",
            "pq_public_key": hex::encode(pq.key.public_key()),
            "pq_key_id": pq.key_id,
            "key_provenance": pq.key_provenance,
            "component": component,
        });
        Ok(self.record(
            Receipt::new(
                uuid::Uuid::new_v4().to_string(),
                PQ_KEY.to_string(),
                params,
                true,
                now_ms(),
            )
            .with_actor(actor),
        ))
    }

    /// A5 (design §4.1, D1 — the DEFAULT PQ mode): emit a `kriya.crypto.pq_checkpoint` receipt
    /// sealing every receipt recorded since the prior checkpoint (or since this signer's PQ key
    /// was attached, on the first call) under ONE ML-DSA-87 signature over the checkpoint's own
    /// canonical bytes — which include the sealed chain head in `params.to_head_hash` (design
    /// axiom §1.4: SHA-256 collision resistance + one PQ signature post-quantum-anchors the whole
    /// prefix). Call every N receipts (default 256, a policy dial — see `docs/design/a5-pq-dual-sig.md`
    /// D1) and/or on a time cadence; **never** from a constructor (no `Actor` at construction,
    /// mirrors [`Signer::attest_crypto_module`]'s reasoning).
    ///
    /// **Known limitation (in-memory counter):** `from_seq`/`count` are tracked in-process (design
    /// §4.1 basis), not read back from the log — a process restart resets the counter to 0 for
    /// THIS signer instance, so `from_seq` after a restart is relative to the restart, not the
    /// log's true absolute sequence. The checkpoint's post-quantum tamper-evidence (the actual
    /// security property, design axiom §1.4) is unaffected: `to_head_hash` is always read fresh
    /// from the real on-disk chain head, never from the in-memory counter.
    ///
    /// Errors if no PQ key is loaded, or if nothing has been recorded yet (nothing to seal).
    #[cfg(feature = "pq-crypto")]
    pub fn pq_checkpoint(&self, component: &str, actor: Option<Actor>) -> Result<SignedReceipt, String> {
        if self.pq.is_none() {
            return Err("pq_checkpoint: no PQ key loaded (call Signer::with_pq first)".to_string());
        }
        let to_head_hash = {
            let chain = self.chain.lock().unwrap_or_else(|e| e.into_inner());
            chain
                .hash
                .clone()
                .ok_or_else(|| "pq_checkpoint: no receipts recorded yet — nothing to seal".to_string())?
        };
        let (from_seq, count) = {
            let pq = self.pq.as_ref().expect("checked Some above");
            let cur = *pq.seq_counter.lock().unwrap_or_else(|e| e.into_inner());
            let mut last = pq.last_checkpoint_seq.lock().unwrap_or_else(|e| e.into_inner());
            let from_seq = *last + 1;
            let count = cur.saturating_sub(*last);
            *last = cur;
            (from_seq, count)
        };
        let params = serde_json::json!({
            "from_seq": from_seq,
            "to_head_hash": to_head_hash,
            "count": count,
            "pq_alg": "ML-DSA-87",
            "component": component,
        });
        // Carrying a PQ signature IS what makes this receipt a checkpoint (design §4.1), so it
        // must be attached UNCONDITIONALLY — regardless of this signer's `dual_sign_enabled`
        // setting. `attach_pq_dual_sign` runs INSIDE `record()`/`record_persisted`, before the
        // line is serialized and written to disk (a hard requirement — pq_* siblings aren't
        // signed, but they DO need to be present in the exact bytes that get persisted and
        // chain-hashed). So: force `dual_sign_enabled` on for the duration of this one `record()`
        // call, then restore whatever it was before. Ordering is safe because `record()` takes
        // `&self` and this signer isn't meant to be called concurrently with itself on the SAME
        // pq_checkpoint invocation; the toggle window is a single synchronous call.
        use std::sync::atomic::Ordering;
        let pq = self.pq.as_ref().expect("checked Some above");
        let was_enabled = pq.dual_sign_enabled.swap(true, Ordering::SeqCst);
        let signed = self.record(
            Receipt::new(
                uuid::Uuid::new_v4().to_string(),
                PQ_CHECKPOINT.to_string(),
                params,
                true,
                now_ms(),
            )
            .with_actor(actor),
        );
        self.pq
            .as_ref()
            .expect("checked Some above")
            .dual_sign_enabled
            .store(was_enabled, Ordering::SeqCst);
        Ok(signed)
    }

    /// A5 cadence helper (design §4.1 "`N` is a policy dial, default proposed 256"): call this
    /// after any receipt-producing event; it emits a [`Signer::pq_checkpoint`] iff at least
    /// `every_n` receipts have been sealed since the previous checkpoint (or since the PQ key was
    /// attached, on the first call), else returns `None` cheaply (just a Mutex read). Centralizes
    /// the cadence decision so callers (binaries, the governor) don't each reimplement counting —
    /// call it as often as convenient; it self-throttles.
    #[cfg(feature = "pq-crypto")]
    pub fn pq_maybe_checkpoint(
        &self,
        component: &str,
        actor: Option<Actor>,
        every_n: u64,
    ) -> Option<Result<SignedReceipt, String>> {
        let pq = self.pq.as_ref()?;
        let cur = *pq.seq_counter.lock().unwrap_or_else(|e| e.into_inner());
        let last = *pq.last_checkpoint_seq.lock().unwrap_or_else(|e| e.into_inner());
        if cur.saturating_sub(last) < every_n {
            return None;
        }
        Some(self.pq_checkpoint(component, actor))
    }
}

#[cfg(feature = "fips-crypto")]
const FRESH_KEY_PROVENANCE: &str = "module-drbg";
#[cfg(not(feature = "fips-crypto"))]
const FRESH_KEY_PROVENANCE: &str = "external-rng";

/// A5 (design §4 `key_provenance`, PQ variant): `"module-drbg"` when `pq-crypto`'s
/// `PqSigningKey::generate` sourced the seed from `aws_lc_rs::rand::fill` (always true when the
/// feature compiles — see `crypto.rs`'s `PqSigningKey::generate`), else `"external-rng"` would
/// apply to a future non-aws-lc-rs PQ backend (none exists today, so this constant is currently
/// always `"module-drbg"` for a freshly-minted PQ key).
#[cfg(feature = "pq-crypto")]
const FRESH_PQ_KEY_PROVENANCE: &str = "module-drbg";

/// A5 (design D2/D3): first 8 bytes of SHA-256(`pq_public_key` raw bytes), lowercase hex — a
/// stable short id binding a PQ-signed line to a `kriya.crypto.pq_key` attestation.
#[cfg(feature = "pq-crypto")]
fn pq_key_id_hex(pq_public_key: &[u8]) -> String {
    let full = sha256_hex(pq_public_key);
    full[..16].to_string()
}

/// A receipt was signed but could not be durably written to the audit log. Carries the signed
/// receipt (so a fail-open caller can still surface it) plus a human-readable reason.
#[derive(Debug, Clone)]
pub struct NotPersisted {
    pub signed: SignedReceipt,
    pub reason: String,
}

/// The result of a retention prune (doc 24 §6-P2).
#[derive(Debug, Clone)]
pub struct PruneReport {
    /// How many receipts were pruned (the sealed prefix).
    pub pruned: usize,
    /// How many survived and were re-chained onto the checkpoint.
    pub retained: usize,
    /// The hash of the last pruned line — the "prior head hash H" the checkpoint attests.
    pub prior_head_hash: Option<String>,
    /// The checkpoint receipt's `step_id`, when one was written.
    pub checkpoint_step_id: Option<String>,
}

/// Prune every receipt older than `cutoff_ts_ms` from `log_path` and seal the pruned prefix behind
/// a signed [`RETENTION_CHECKPOINT`] receipt — compliant deletion that stays verifiable (doc 24
/// §6-P2). Without this, deleting old receipts is indistinguishable from tampering, because it
/// breaks the hash chain; the checkpoint records "receipts before T pruned per policy P; prior head
/// hash H" so a verifier accepts the seal instead of flagging a truncation.
///
/// The pruned set is the leading, time-ordered run of receipts with `ts_ms < cutoff_ts_ms` (the log
/// is append-ordered, so this is a clean "everything before T" epoch). Survivors are **re-chained
/// onto the checkpoint** (re-signed by `signer`) so the chain is unbroken from the checkpoint
/// forward. `signer`'s key MUST match every retained receipt's `public_key`: a prune never silently
/// re-attributes a receipt to a different signer — a mismatch is a hard error and the log is left
/// untouched. A no-op (nothing older than the cutoff) writes nothing.
pub fn prune_and_seal(
    log_path: &Path,
    cutoff_ts_ms: u128,
    policy_label: &str,
    signer: &Signer,
) -> Result<PruneReport, String> {
    let content = std::fs::read_to_string(log_path)
        .map_err(|e| format!("reading {}: {e}", log_path.display()))?;
    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();

    // The log is append-ordered by time, so the pruned set is the leading run of lines older than
    // the cutoff; stop at the first line at/after the cutoff (or unparseable — treat as retained).
    let split = lines
        .iter()
        .position(|l| line_ts(l).map(|ts| ts >= cutoff_ts_ms).unwrap_or(true))
        .unwrap_or(lines.len());
    if split == 0 {
        return Ok(PruneReport {
            pruned: 0,
            retained: lines.len(),
            prior_head_hash: None,
            checkpoint_step_id: None,
        });
    }
    let (pruned, retained) = lines.split_at(split);
    let prior_head_hash = sha256_hex(pruned[pruned.len() - 1].as_bytes());

    // The checkpoint receipt, sealed to the prior head H and attesting the prune.
    let step_id = uuid::Uuid::new_v4().to_string();
    let mut checkpoint = Receipt::new(
        step_id.clone(),
        RETENTION_CHECKPOINT.to_string(),
        serde_json::json!({
            "pruned_before_ts_ms": cutoff_ts_ms as u64,
            "policy": policy_label,
            "prior_head_hash": prior_head_hash,
            "pruned_count": pruned.len(),
        }),
        true,
        now_ms(),
    );
    checkpoint.prev_hash = Some(prior_head_hash.clone());
    let checkpoint_signed = signer.sign_only(checkpoint);
    let checkpoint_line = serde_json::to_string(&checkpoint_signed)
        .map_err(|e| format!("serializing checkpoint: {e}"))?;

    // Re-chain the survivors onto the checkpoint (re-signed by this signer; same key required).
    let mut out_lines = vec![checkpoint_line.clone()];
    let mut prev = sha256_hex(checkpoint_line.as_bytes());
    for l in retained {
        let (receipt, public_key) =
            parse_stored_receipt(l).map_err(|e| format!("re-chaining retained receipt: {e}"))?;
        if public_key != signer.public_key() {
            return Err(format!(
                "retained receipt {} was signed by a different key — refusing to re-attribute it to the pruning signer",
                receipt.step_id
            ));
        }
        let mut r = receipt;
        r.prev_hash = Some(prev.clone());
        let signed = signer.sign_only(r);
        let line = serde_json::to_string(&signed)
            .map_err(|e| format!("serializing retained receipt: {e}"))?;
        prev = sha256_hex(line.as_bytes());
        out_lines.push(line);
    }

    // Rewrite via a temp file + rename so a crash mid-prune never leaves a half-written log.
    let tmp = log_path.with_extension("jsonl.prune-tmp");
    let body = out_lines.join("\n") + "\n";
    std::fs::write(&tmp, body).map_err(|e| format!("writing pruned log: {e}"))?;
    std::fs::rename(&tmp, log_path).map_err(|e| format!("replacing log: {e}"))?;

    // Re-seed the signer's in-memory chain head from the rewritten log so the NEXT `record()` chains
    // onto the last RETAINED line — never onto the pruned (now-gone) head. record()'s length-probe
    // would usually catch the change, but the pruned-vs-re-chained lengths can coincidentally match,
    // so reset explicitly rather than rely on the heuristic.
    if let Ok(mut chain) = signer.chain.lock() {
        *chain = seed_chain_head(log_path);
    }

    Ok(PruneReport {
        pruned: pruned.len(),
        retained: retained.len(),
        prior_head_hash: Some(prior_head_hash),
        checkpoint_step_id: Some(step_id),
    })
}

/// The `ts_ms` of a stored receipt line (for the retention cutoff split). `None` if unparseable.
fn line_ts(line: &str) -> Option<u128> {
    serde_json::from_str::<Value>(line)
        .ok()?
        .get("ts_ms")
        .and_then(Value::as_u64)
        .map(|t| t as u128)
}

/// Reconstruct the unsigned [`Receipt`] + `public_key` from a stored line. `Receipt` is
/// Serialize-only (its declaration order is the load-bearing signed order), so we read the wire
/// JSON by hand rather than deriving Deserialize on the frozen schema.
fn parse_stored_receipt(line: &str) -> Result<(Receipt, String), String> {
    let v: Value = serde_json::from_str(line).map_err(|e| format!("parse: {e}"))?;
    let step_id = v
        .get("step_id")
        .and_then(Value::as_str)
        .ok_or("no step_id")?
        .to_string();
    let action_id = v
        .get("action_id")
        .and_then(Value::as_str)
        .ok_or("no action_id")?
        .to_string();
    let params = v.get("params").cloned().unwrap_or(Value::Null);
    let success = v
        .get("success")
        .and_then(Value::as_bool)
        .ok_or("no success")?;
    let ts_ms = v.get("ts_ms").and_then(Value::as_u64).ok_or("no ts_ms")? as u128;
    let actor = match v.get("actor") {
        Some(a) if a.is_object() => Some(Actor {
            agent: a
                .get("agent")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            user: a
                .get("user")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        }),
        _ => None,
    };
    let public_key = v
        .get("public_key")
        .and_then(Value::as_str)
        .ok_or("no public_key")?
        .to_string();
    let mut r = Receipt::new(step_id, action_id, params, success, ts_ms);
    r.actor = actor;
    Ok((r, public_key))
}

pub fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// The standard on-device directory for kriya audit logs: `~/.kriya/audit/` (R27 / D-018). The
/// gateway defaults its signed-receipt log here so the control-plane Console can **auto-discover and
/// tail** governance with no manual file import — open the app, see your receipts. It is a shared
/// convention across the gateway (writer) and the Console (reader), so both compute it the same way.
/// The directory is created if missing. Falls back to the OS temp dir when no home directory is
/// resolvable (headless / unusual environments) so a signer always has a writable location rather
/// than silently dropping receipts.
pub fn default_audit_dir() -> PathBuf {
    match home_dir().map(|h| h.join(".kriya").join("audit")) {
        // Best-effort create; on failure (e.g. a read-only home) fall back to temp so the log still
        // lands somewhere writable.
        Some(dir) if std::fs::create_dir_all(&dir).is_ok() => dir,
        _ => std::env::temp_dir(),
    }
}

/// The standard on-device directory for the control-plane Console's local state: `~/.kriya/console/`.
/// Sibling of [`default_audit_dir`] and computed identically (same home resolution, same temp-dir
/// fallback, created if missing) so the runtime and the Console agree on where per-device
/// coordination files live — e.g. the file-approval mailbox under `console/approvals/` that
/// [`crate::mcp::default_approvals_dir`] derives. Additive: no existing path derivation changes.
pub fn default_console_dir() -> PathBuf {
    match home_dir().map(|h| h.join(".kriya").join("console")) {
        // Best-effort create; on failure (e.g. a read-only home) fall back to temp so callers still
        // have a writable location rather than silently failing.
        Some(dir) if std::fs::create_dir_all(&dir).is_ok() => dir,
        _ => std::env::temp_dir(),
    }
}

/// Resolve the user's home directory without pulling in a dependency: `$HOME` on Unix,
/// `%USERPROFILE%` on Windows. `None` if neither is set.
fn home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE").map(PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("HOME").map(PathBuf::from)
    }
}

/// Load a 32-byte Ed25519 seed from `path` (lowercase hex), or generate one and persist it there
/// (creating parent dirs; restricted to 0600 on Unix). An existing-but-invalid key file is an
/// error, never overwritten — losing a durable signing identity must be a deliberate act, not a
/// side effect of a typo'd path (R20).
/// Loads the persisted seed, or mints + persists a fresh one via the crypto facade (A4: the FIPS
/// lane's module DRBG when `fips-crypto` is on). Returns whether the seed was freshly generated
/// (`true`) vs loaded from an existing file (`false`) — [`Signer::with_identity`] uses this to set
/// `key_provenance` honestly (design RT2.3).
fn load_or_create_seed(path: &Path) -> Result<([u8; 32], bool), String> {
    if path.exists() {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("reading signing key {}: {e}", path.display()))?;
        let bytes = hex::decode(text.trim())
            .map_err(|e| format!("signing key {} is not valid hex: {e}", path.display()))?;
        let seed: [u8; 32] = bytes.try_into().map_err(|_| {
            format!(
                "signing key {} must be 32 bytes (64 hex chars)",
                path.display()
            )
        })?;
        return Ok((seed, false));
    }
    let (seed, _key) = SigningKey::generate();
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("creating key dir {}: {e}", parent.display()))?;
        }
    }
    std::fs::write(path, hex::encode(seed))
        .map_err(|e| format!("writing signing key {}: {e}", path.display()))?;
    restrict_perms(path);
    Ok((seed, true))
}

/// A5 (design D3): load a 32-byte ML-DSA-87 seed from `path` (lowercase hex), or mint one from
/// the active lane's DRBG and persist it there (0600 on Unix) — the PQ mirror of
/// [`load_or_create_seed`], deliberately kept at a SEPARATE path
/// (`~/.kriya/pq-signing.seed`, beside the existing `signing.key`, per the caller's convention;
/// this function itself is path-agnostic) so the Ed25519 and PQ identities never collide or get
/// silently conflated. Same never-silently-overwrite guarantee as the Ed25519 loader.
#[cfg(feature = "pq-crypto")]
fn load_or_create_pq_seed(path: &Path) -> Result<([u8; 32], bool), String> {
    if path.exists() {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("reading PQ signing key {}: {e}", path.display()))?;
        let bytes = hex::decode(text.trim())
            .map_err(|e| format!("PQ signing key {} is not valid hex: {e}", path.display()))?;
        let seed: [u8; 32] = bytes.try_into().map_err(|_| {
            format!(
                "PQ signing key {} must be 32 bytes (64 hex chars)",
                path.display()
            )
        })?;
        return Ok((seed, false));
    }
    let (seed, _key) = crypto::PqSigningKey::generate();
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("creating PQ key dir {}: {e}", parent.display()))?;
        }
    }
    std::fs::write(path, hex::encode(seed))
        .map_err(|e| format!("writing PQ signing key {}: {e}", path.display()))?;
    restrict_perms(path);
    Ok((seed, true))
}

#[cfg(unix)]
fn restrict_perms(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn restrict_perms(_path: &Path) {}

/// Lowercase-hex SHA-256 of `bytes`. The hash-chain links each receipt to the SHA-256 of the exact
/// previous LINE on disk, so any whole-receipt deletion/truncation/reorder breaks the chain (R20).
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Seed the chain head from an existing log: hash of the last non-empty line (so a new process
/// CONTINUES the chain instead of starting a fresh one a verifier would read as head-truncation)
/// plus the log's byte length (the staleness probe [`Signer::record`] uses under the file lock).
/// `hash: None` + `len: 0` for an absent/empty log — a genuine genesis.
fn seed_chain_head(log_path: &Path) -> ChainHead {
    match std::fs::read_to_string(log_path) {
        Ok(content) => ChainHead {
            hash: content
                .lines()
                .rev()
                .find(|l| !l.trim().is_empty())
                .map(|l| sha256_hex(l.as_bytes())),
            len: content.len() as u64,
        },
        Err(_) => ChainHead { hash: None, len: 0 },
    }
}

/// Exclusive advisory lock on the audit log (blocking). Unix `flock`: released automatically when
/// the fd closes — including on process death, so a crashed hook invocation can never wedge the
/// chain. Best-effort by design: on failure (exotic filesystems) behavior degrades to the previous
/// unlocked append rather than dropping the receipt. Off-unix this is a no-op and the log's
/// contract stays "one writer at a time".
#[cfg(unix)]
fn lock_exclusive(f: &std::fs::File) {
    use std::os::unix::io::AsRawFd;
    // SAFETY: flock on a valid, open fd; no memory is passed. Advisory only.
    unsafe {
        let _ = libc::flock(f.as_raw_fd(), libc::LOCK_EX);
    }
}
#[cfg(not(unix))]
fn lock_exclusive(_f: &std::fs::File) {}

/// Recursively sort object keys in a JSON value so its serialization is deterministic regardless of
/// serde_json's `preserve_order` feature (R21). Applied to receipt `params` before signing so the
/// signed canonical bytes are reproducible by any verifier without depending on a build flag. Arrays
/// preserve order (semantic) but their object elements are sorted; scalars pass through unchanged.
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

/// Re-derive the canonical signed bytes and check a signed receipt's Ed25519 signature against
/// its own embedded public key — the runtime's single source of truth for line verification,
/// identical to the offline CLI and the console's TS verifier. The receipt's `params` are
/// re-canonicalized (R21 key sort) before the bytes are re-derived, so verification never depends
/// on how a consumer's `serde_json` parsed the line. Only the Ed25519 lane is checked here (the
/// primary signature every receipt carries); the optional ML-DSA-87 `pq_*` siblings are a separate
/// concern (see `pq_verifies` in tests). A `signed` whose `receipt.params` were already
/// canonicalized re-verifies unchanged (the sort is idempotent).
pub fn signature_valid(signed: &SignedReceipt) -> bool {
    let pub_bytes: [u8; 32] = match hex::decode(&signed.public_key)
        .ok()
        .and_then(|b| b.try_into().ok())
    {
        Some(b) => b,
        None => return false,
    };
    let sig_bytes: [u8; 64] = match hex::decode(&signed.signature)
        .ok()
        .and_then(|b| b.try_into().ok())
    {
        Some(b) => b,
        None => return false,
    };
    // Re-derive the exact bytes the signer covered: the unsigned Receipt, params key-sorted.
    let mut receipt = signed.receipt.clone();
    receipt.params = canonical_value(&receipt.params);
    let msg = match serde_json::to_vec(&receipt) {
        Ok(m) => m,
        Err(_) => return false,
    };
    crypto::verify(&pub_bytes, &msg, &sig_bytes)
}

/// The verdict for one line of an audit log: whether it parses as a signed receipt and whether that
/// receipt's signature re-verifies. On a parse or verify failure `signed` may still be present (a
/// parsed-but-forged line) so callers can report *what* failed, and `reason` carries a short,
/// machine-stable tag. This is the primitive the evidence MCP server ([`crate::mcp::evidence`]) uses
/// so an unverifiable line is reported as such, never silently surfaced as if it were proven.
#[derive(Debug, Clone)]
pub struct LineVerdict {
    /// The signed receipt when the line parsed as one (even if its signature is bad); `None` only
    /// when the line was not valid signed-receipt JSON at all.
    pub signed: Option<SignedReceipt>,
    /// True iff the line parsed AND [`signature_valid`] returned true.
    pub verified: bool,
    /// A short reason when `!verified` (`"parse-error"` | `"bad-signature"`); `None` when verified.
    pub reason: Option<&'static str>,
}

/// Parse one audit-log line into a [`SignedReceipt`] without flattening (see the note on
/// `SignedReceipt`). Returns `None` when the line is not a well-formed signed receipt: a JSON
/// object carrying the required `step_id`/`action_id`/`params`/`success`/`ts_ms` receipt fields
/// plus `public_key` and `signature`. The `Receipt` core is reconstructed via `from_value`
/// (unknown keys — `public_key`, `signature`, `pq_*` — are ignored), and the wire siblings are
/// pulled off the same object.
pub fn parse_signed_line(line: &str) -> Option<SignedReceipt> {
    let v: Value = serde_json::from_str(line).ok()?;
    if !v.is_object() {
        return None;
    }
    let public_key = v.get("public_key")?.as_str()?.to_string();
    let signature = v.get("signature")?.as_str()?.to_string();
    let receipt: Receipt = serde_json::from_value(v.clone()).ok()?;
    let pull = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
    Some(SignedReceipt {
        receipt,
        public_key,
        signature,
        pq_alg: pull("pq_alg"),
        pq_public_key: pull("pq_public_key"),
        pq_sig: pull("pq_sig"),
        pq_key_id: pull("pq_key_id"),
    })
}

/// Verify a single audit-log line: parse it as a [`SignedReceipt`] and re-check its signature.
pub fn verify_signed_line(line: &str) -> LineVerdict {
    match parse_signed_line(line) {
        Some(signed) => {
            let verified = signature_valid(&signed);
            LineVerdict {
                signed: Some(signed),
                verified,
                reason: if verified { None } else { Some("bad-signature") },
            }
        }
        None => LineVerdict {
            signed: None,
            verified: false,
            reason: Some("parse-error"),
        },
    }
}

/// The verdict for a whole audit log: how many lines it holds, whether every line both verifies AND
/// links to the SHA-256 of the exact previous line (the R20 hash-chain — so whole-receipt
/// deletion/truncation/reorder is detectable), and the index of the first line that broke either
/// property. Genesis (`prev_hash: None` on line 0) is legitimate; a `None` `prev_hash` on a later
/// line is tolerated as *unchained* (pre-R20 shape) rather than reported as a break — only a
/// *present* `prev_hash` that mismatches the previous line's hash, or an invalid signature, breaks
/// the chain. Empty/blank lines are skipped (they are not receipts).
#[derive(Debug, Clone)]
pub struct ChainVerdict {
    /// Count of non-blank receipt lines examined.
    pub lines: usize,
    /// True iff no line failed signature verification and no present `prev_hash` mismatched.
    pub verified: bool,
    /// 0-based index (among non-blank lines) of the first break, if any.
    pub first_break: Option<usize>,
}

/// Verify a full audit log presented as raw lines (each the exact bytes written, no trailing
/// newline). See [`ChainVerdict`] for the exact break semantics.
pub fn verify_chain(raw_lines: &[String]) -> ChainVerdict {
    let mut prev_line_hash: Option<String> = None;
    let mut idx = 0usize;
    for raw in raw_lines {
        if raw.trim().is_empty() {
            continue;
        }
        let verdict = verify_signed_line(raw);
        let ok = match &verdict.signed {
            Some(s) if verdict.verified => {
                // Signature is good; now check the chain link where one is present.
                match (&s.receipt.prev_hash, &prev_line_hash) {
                    // A present prev_hash must equal the SHA-256 of the actual previous line.
                    (Some(ph), Some(expected)) => ph == expected,
                    // prev_hash present but this is line 0 (no previous line) — a dangling link.
                    (Some(_), None) => false,
                    // Unchained line (pre-R20) — tolerated, not a break.
                    (None, _) => true,
                }
            }
            _ => false,
        };
        if !ok {
            return ChainVerdict {
                lines: raw_lines.iter().filter(|l| !l.trim().is_empty()).count(),
                verified: false,
                first_break: Some(idx),
            };
        }
        prev_line_hash = Some(sha256_hex(raw.as_bytes()));
        idx += 1;
    }
    ChainVerdict {
        lines: idx,
        verified: true,
        first_break: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use serde_json::json;

    /// Re-derive the canonical bytes and verify a signed receipt against its own embedded
    /// public key — the same check the offline CLI and the console's TS verifier perform.
    fn verifies(signed: &SignedReceipt) -> bool {
        let pub_bytes: [u8; 32] = match hex::decode(&signed.public_key)
            .ok()
            .and_then(|b| b.try_into().ok())
        {
            Some(b) => b,
            None => return false,
        };
        let sig_bytes: [u8; 64] = match hex::decode(&signed.signature)
            .ok()
            .and_then(|b| b.try_into().ok())
        {
            Some(b) => b,
            None => return false,
        };
        let key = match VerifyingKey::from_bytes(&pub_bytes) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let sig = Signature::from_bytes(&sig_bytes);
        let msg = serde_json::to_vec(&signed.receipt).unwrap();
        key.verify(&msg, &sig).is_ok()
    }

    fn signer() -> Signer {
        // A UNIQUE log per call so each test's first record() is a genuine genesis (no chain seeding
        // from a leftover shared file) and concurrent tests never fight over the audit file.
        Signer::with_log_path(
            std::env::temp_dir().join(format!("kriya-audit-test-{}.jsonl", uuid::Uuid::new_v4())),
        )
    }

    /// A5: a fresh `Signer` with a PQ key attached — a unique log + a unique PQ seed path per
    /// call, so each test is a genuine genesis and independent PQ identity.
    #[cfg(feature = "pq-crypto")]
    fn pq_signer(dual_sign_enabled: bool) -> Signer {
        let id = uuid::Uuid::new_v4();
        signer()
            .with_pq(
                &std::env::temp_dir().join(format!("kriya-pq-seed-test-{id}.hex")),
                dual_sign_enabled,
            )
            .map_err(|(_, e)| e)
            .expect("with_pq")
    }

    /// A5: verify the ML-DSA-87 `pq_*` siblings on a signed receipt, mirroring [`verifies`]'s
    /// Ed25519 check. `None` (no PQ material) is treated as "nothing to verify" — callers assert
    /// presence separately.
    #[cfg(feature = "pq-crypto")]
    fn pq_verifies(signed: &SignedReceipt) -> bool {
        let (Some(alg), Some(pk_hex), Some(sig_hex)) =
            (&signed.pq_alg, &signed.pq_public_key, &signed.pq_sig)
        else {
            return false;
        };
        if alg != "ML-DSA-87" {
            return false;
        }
        let pk = match hex::decode(pk_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sig = match hex::decode(sig_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let msg = serde_json::to_vec(&signed.receipt).unwrap();
        crypto::pq_verify(&pk, &msg, &sig)
    }

    #[test]
    fn round_trip_without_actor_verifies() {
        let s = signer();
        let signed = s.record(Receipt::new(
            "step-1".into(),
            "create_note".into(),
            json!({ "title": "hi" }),
            true,
            1_700_000_000_000,
        ));
        assert!(signed.receipt.actor.is_none());
        assert!(verifies(&signed), "actor-less receipt must verify");
    }

    #[test]
    fn round_trip_with_actor_verifies() {
        let s = signer();
        let signed = s.record(
            Receipt::new(
                "step-2".into(),
                "categorize_transaction".into(),
                json!({ "id": "txn-1" }),
                true,
                1_700_000_000_001,
            )
            .with_actor(Some(Actor::new("claude-desktop", "alice"))),
        );
        assert_eq!(
            signed.receipt.actor,
            Some(Actor::new("claude-desktop", "alice"))
        );
        assert!(verifies(&signed), "actor-bearing receipt must verify");
    }

    #[test]
    fn actorless_receipt_serializes_to_the_original_five_fields() {
        // The whole point of skip_if_none: byte-identical to the pre-R8 format, so the
        // existing verifiers (and the cross-checked real receipts) keep validating.
        let r = Receipt::new("s".into(), "a".into(), json!({}), true, 1);
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(
            json,
            r#"{"step_id":"s","action_id":"a","params":{},"success":true,"ts_ms":1}"#
        );
        assert!(
            !json.contains("actor"),
            "absent actor must not appear in the signed bytes"
        );
    }

    #[test]
    fn actor_appears_last_when_present() {
        let r = Receipt::new("s".into(), "a".into(), json!({}), true, 1)
            .with_actor(Some(Actor::new("agentX", "userY")));
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(
            json,
            r#"{"step_id":"s","action_id":"a","params":{},"success":true,"ts_ms":1,"actor":{"agent":"agentX","user":"userY"}}"#
        );
    }

    #[test]
    fn tampering_the_actor_breaks_the_signature() {
        let s = signer();
        let mut signed = s.record(
            Receipt::new(
                "step-3".into(),
                "delete_transaction".into(),
                json!({}),
                true,
                7,
            )
            .with_actor(Some(Actor::new("claude-desktop", "alice"))),
        );
        assert!(verifies(&signed), "control: untampered must verify");
        // Forge a different operator after signing — the attribution is signed, so this fails.
        signed.receipt.actor = Some(Actor::new("claude-desktop", "mallory"));
        assert!(
            !verifies(&signed),
            "swapping the acting user must invalidate the receipt"
        );
    }

    #[test]
    fn tampering_params_breaks_the_signature() {
        let s = signer();
        let mut signed = s.record(Receipt::new(
            "step-4".into(),
            "edit_note".into(),
            json!({ "amount": 10 }),
            true,
            9,
        ));
        signed.receipt.params = json!({ "amount": 1_000_000 });
        assert!(
            !verifies(&signed),
            "tampered params must invalidate the receipt"
        );
    }

    /// A fresh, untampered signed receipt to mutate in the tamper tests below.
    fn baseline() -> (Signer, SignedReceipt) {
        let s = signer();
        let signed = s.record(Receipt::new(
            "step-x".into(),
            "delete_transaction".into(),
            json!({ "id": "txn-9", "amount": 250 }),
            true,
            1_700_000_000_123,
        ));
        assert!(verifies(&signed), "control: untampered receipt must verify");
        (s, signed)
    }

    #[test]
    fn tampering_the_action_id_breaks_the_signature() {
        let (_s, mut signed) = baseline();
        signed.receipt.action_id = "list_transactions".into(); // disguise a delete as a read
        assert!(
            !verifies(&signed),
            "rewriting which action ran must invalidate the receipt"
        );
    }

    #[test]
    fn tampering_the_success_flag_breaks_the_signature() {
        let (_s, mut signed) = baseline();
        signed.receipt.success = false; // claim a successful action failed (or vice versa)
        assert!(
            !verifies(&signed),
            "flipping the outcome must invalidate the receipt"
        );
    }

    #[test]
    fn tampering_the_step_id_breaks_the_signature() {
        let (_s, mut signed) = baseline();
        signed.receipt.step_id = "step-other".into();
        assert!(
            !verifies(&signed),
            "rewriting the step id must invalidate the receipt"
        );
    }

    #[test]
    fn tampering_the_timestamp_breaks_the_signature() {
        let (_s, mut signed) = baseline();
        signed.receipt.ts_ms = 0; // backdate the action
        assert!(
            !verifies(&signed),
            "rewriting when it happened must invalidate the receipt"
        );
    }

    #[test]
    fn adding_an_actor_after_signing_breaks_the_signature() {
        // The inverse of tampering an existing actor: an actor-less receipt was signed over five
        // fields, so attaching attribution afterward changes the canonical bytes and fails.
        let (_s, mut signed) = baseline();
        assert!(signed.receipt.actor.is_none());
        signed.receipt.actor = Some(Actor::new("forged-agent", "mallory"));
        assert!(
            !verifies(&signed),
            "fabricating attribution after signing must fail"
        );
    }

    #[test]
    fn a_forged_signature_does_not_verify() {
        let (_s, mut signed) = baseline();
        // Flip the first hex nibble — still well-formed 64-byte hex, but not the real signature.
        let mut chars: Vec<char> = signed.signature.chars().collect();
        chars[0] = if chars[0] == '0' { '1' } else { '0' };
        signed.signature = chars.into_iter().collect();
        assert!(!verifies(&signed), "a forged signature must not verify");
    }

    #[test]
    fn a_mismatched_public_key_does_not_verify() {
        let (_s, mut signed) = baseline();
        // Swap in a *different* signer's public key — the signature was made by the original key,
        // so claiming a different signer produced it must fail (no key-substitution attack).
        let other = signer();
        signed.public_key = other.public_key().to_string();
        assert!(
            !verifies(&signed),
            "a receipt must not verify against the wrong public key"
        );
    }

    #[test]
    fn malformed_signature_or_pubkey_hex_does_not_verify() {
        let (_s, mut signed) = baseline();
        let good_sig = signed.signature.clone();
        signed.signature = "not-hex".into();
        assert!(
            !verifies(&signed),
            "non-hex signature must be rejected, not panic"
        );
        signed.signature = good_sig;
        signed.public_key = "deadbeef".into(); // valid hex but wrong length (not 32 bytes)
        assert!(
            !verifies(&signed),
            "wrong-length public key must be rejected, not panic"
        );
    }

    #[test]
    fn params_are_canonically_key_sorted_before_signing() {
        // R21: params keys are recursively sorted into the signed (and stored) receipt — including
        // nested objects and objects inside arrays — so the canonical bytes don't depend on any
        // consumer's serde_json `preserve_order` feature.
        let s = signer();
        let signed = s.record(Receipt::new(
            "s".into(),
            "a".into(),
            json!({ "z": 1, "a": { "y": 2, "b": 3 }, "m": [ { "q": 1, "p": 2 } ] }),
            true,
            1,
        ));
        assert!(verifies(&signed), "canonicalized receipt must verify");
        let serialized = serde_json::to_string(&signed.receipt.params).unwrap();
        assert_eq!(
            serialized,
            r#"{"a":{"b":3,"y":2},"m":[{"p":2,"q":1}],"z":1}"#
        );
    }

    #[test]
    fn durable_identity_is_stable_across_runs() {
        // R20: a persisted key means the public identity an auditor pins stays the same run-to-run,
        // unlike the ephemeral with_log_path key. Two signers loading the same key file match.
        let dir = std::env::temp_dir().join(format!("kriya-r20a-{}", uuid::Uuid::new_v4()));
        let key = dir.join("signing.key");
        let log = dir.join("audit.jsonl");

        let s1 = Signer::with_identity(&key, log.clone()).expect("mint identity");
        let pk1 = s1.public_key().to_string();
        let s2 = Signer::with_identity(&key, log.clone()).expect("reload identity");
        assert_eq!(
            pk1,
            s2.public_key(),
            "persisted identity must be stable across runs"
        );

        let signed = s1.record(Receipt::new("s".into(), "a".into(), json!({}), true, 1));
        assert!(verifies(&signed), "durable-key receipt must verify");
        assert_eq!(
            std::fs::read_to_string(&key).unwrap().trim().len(),
            64,
            "key persists as 64 hex"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn receipts_are_hash_chained() {
        // R20: each receipt after the genesis carries prev_hash = SHA-256 of the previous LINE, so
        // whole-receipt deletion/truncation/reorder is detectable. Chained receipts still verify
        // (prev_hash is inside the signed bytes).
        let dir = std::env::temp_dir().join(format!("kriya-r20b-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("audit.jsonl");
        let s = Signer::with_log_path(log.clone());

        let r1 = s.record(Receipt::new("s1".into(), "a".into(), json!({}), true, 1));
        let r2 = s.record(Receipt::new("s2".into(), "b".into(), json!({}), true, 2));
        let r3 = s.record(Receipt::new("s3".into(), "c".into(), json!({}), true, 3));

        assert!(
            r1.receipt.prev_hash.is_none(),
            "genesis must have no prev_hash"
        );
        let lines: Vec<String> = std::fs::read_to_string(&log)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(
            r2.receipt.prev_hash.as_deref(),
            Some(sha256_hex(lines[0].as_bytes()).as_str())
        );
        assert_eq!(
            r3.receipt.prev_hash.as_deref(),
            Some(sha256_hex(lines[1].as_bytes()).as_str())
        );
        assert!(
            verifies(&r2) && verifies(&r3),
            "chained receipts must still verify"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_new_signer_continues_the_chain_on_an_existing_log() {
        // Cross-restart: a second host process appending to the same log links its first receipt to
        // the last line already on disk, so resuming a deployment doesn't read as a truncation.
        let dir = std::env::temp_dir().join(format!("kriya-r20b-cont-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("audit.jsonl");

        let s1 = Signer::with_log_path(log.clone());
        let _ = s1.record(Receipt::new("s1".into(), "a".into(), json!({}), true, 1));
        drop(s1);

        let s2 = Signer::with_log_path(log.clone()); // a fresh "process" seeds from the existing log
        let r2 = s2.record(Receipt::new("s2".into(), "b".into(), json!({}), true, 2));
        let lines: Vec<String> = std::fs::read_to_string(&log)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        assert_eq!(
            r2.receipt.prev_hash.as_deref(),
            Some(sha256_hex(lines[0].as_bytes()).as_str()),
            "the continuation receipt must link to the last line of the prior run"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_key_file_is_an_error_not_overwritten() {
        let dir = std::env::temp_dir().join(format!("kriya-r20a-bad-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = dir.join("signing.key");
        std::fs::write(&key, "not-valid-hex").unwrap();
        assert!(
            Signer::with_identity(&key, dir.join("a.jsonl")).is_err(),
            "an invalid key file must error, not be silently regenerated"
        );
        assert_eq!(
            std::fs::read_to_string(&key).unwrap(),
            "not-valid-hex",
            "key left untouched"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// R27: the standard audit dir resolves to an existing, writable directory; with `$HOME` set
    /// (the normal case, incl. CI) it lands at `~/.kriya/audit/` so the Console can auto-discover it.
    #[test]
    fn default_audit_dir_is_a_writable_directory() {
        let dir = default_audit_dir();
        assert!(
            dir.is_dir(),
            "default audit dir should exist after the call: {}",
            dir.display()
        );
        if std::env::var_os("HOME").is_some() && cfg!(not(windows)) {
            assert!(
                dir.ends_with("audit") && dir.to_string_lossy().contains(".kriya"),
                "with HOME set the default dir should be ~/.kriya/audit, got {}",
                dir.display()
            );
        }
        // Prove it is actually writable (a signer must be able to append a receipt here).
        let probe = dir.join(format!("kriya-r27-probe-{}.tmp", uuid::Uuid::new_v4()));
        std::fs::write(&probe, b"ok").expect("default audit dir must be writable");
        let _ = std::fs::remove_file(&probe);
    }

    /// W1-6: many CONCURRENT signer instances over one log + one persisted key — the parallel
    /// hook-invocation model (each instance owns its fd, so the flock path is exercised exactly as
    /// it is between processes). The chain must come out fork-free: every line's `prev_hash` equals
    /// the hash of the exact line before it, every line parses (no torn writes), every signature
    /// verifies, and nothing is lost. Before the record()-time lock + re-seed, two writers seeded
    /// from the same tail would both claim the same parent — a fork a verifier must flag.
    #[test]
    #[cfg(unix)]
    fn concurrent_signers_extend_one_chain_without_forking() {
        let dir = std::env::temp_dir().join(format!("kriya-flock-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = dir.join("hook.key");
        let log = dir.join("claude-code.jsonl");

        // Mint the shared identity first (parallel first-ever key creation is out of scope here).
        drop(Signer::with_identity(&key, log.clone()).unwrap());

        let n_threads = 4;
        let per_thread = 25;
        let handles: Vec<_> = (0..n_threads)
            .map(|t| {
                let key = key.clone();
                let log = log.clone();
                std::thread::spawn(move || {
                    // A FRESH Signer per thread — like a fresh process, it seeds its chain head
                    // once (possibly mid-hammering) and must reconcile under the lock thereafter.
                    let s = Signer::with_identity(&key, log).unwrap();
                    for i in 0..per_thread {
                        let signed = s.record(Receipt::new(
                            format!("t{t}-s{i}"),
                            "claude-code__bash".into(),
                            json!({ "thread": t, "seq": i }),
                            true,
                            now_ms(),
                        ));
                        assert!(verifies(&signed), "receipt t{t}-s{i} must verify");
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        let text = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(
            lines.len(),
            n_threads * per_thread,
            "no receipt lost, no line torn"
        );
        let mut prev: Option<String> = None;
        for (i, line) in lines.iter().enumerate() {
            let v: serde_json::Value = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("line {} is torn/unparseable: {e}", i + 1));
            let declared = v
                .get("prev_hash")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string);
            assert_eq!(
                declared,
                prev,
                "chain fork at line {} — a receipt claims a stale parent",
                i + 1
            );
            prev = Some(sha256_hex(line.as_bytes()));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ─── EG-2: fail-closed record + retention checkpoint (doc 24 §6-P2, B3) ──────────────────────

    #[test]
    fn record_persisted_reports_write_success_and_failure() {
        // A writable log: record_persisted succeeds and the line hits disk.
        let s = signer();
        let ok = s.record_persisted(Receipt::new("s".into(), "a".into(), json!({}), true, 1));
        assert!(ok.is_ok(), "a writable log must persist");
        assert!(verifies(&ok.unwrap()));

        // An UNWRITABLE log (the path is a directory) — the append can never open it. Fail-closed
        // mode reads this Err as "no receipt" and denies the egress (doc 24 B3).
        let dir = std::env::temp_dir().join(format!("kriya-b3-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let blocked = Signer::with_log_path(dir.clone()); // log_path IS a directory
        let err =
            blocked.record_persisted(Receipt::new("s".into(), "a".into(), json!({}), true, 1));
        assert!(
            err.is_err(),
            "an unwritable log must be reported, not swallowed"
        );
        // The infallible wrapper still returns the signed receipt (fail-open default).
        let signed = blocked.record(Receipt::new("s".into(), "a".into(), json!({}), true, 1));
        assert!(!signed.signature.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prune_and_seal_produces_a_verifiable_sealed_chain() {
        // A durable key so the retained receipts can be re-chained onto the checkpoint by the SAME
        // signer (a prune never re-attributes across keys).
        let dir = std::env::temp_dir().join(format!("kriya-retention-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = dir.join("s.key");
        let log = dir.join("audit.jsonl");
        let s = Signer::with_identity(&key, log.clone()).unwrap();

        // Four receipts at t = 100, 200, 300, 400.
        for (i, ts) in [100u128, 200, 300, 400].into_iter().enumerate() {
            s.record(Receipt::new(
                format!("s{i}"),
                "kriya.io.egress.mcp.allow".into(),
                json!({"seq": i}),
                true,
                ts,
            ));
        }
        let pruned_head = {
            let lines: Vec<String> = std::fs::read_to_string(&log)
                .unwrap()
                .lines()
                .map(str::to_string)
                .collect();
            sha256_hex(lines[1].as_bytes()) // the ts=200 line is the last pruned
        };

        // Prune everything before t = 300 (seals the first two).
        let report = prune_and_seal(&log, 300, "io-30d", &s).expect("prune");
        assert_eq!(report.pruned, 2);
        assert_eq!(report.retained, 2);
        assert_eq!(
            report.prior_head_hash.as_deref(),
            Some(pruned_head.as_str())
        );

        // The sealed log: checkpoint first (sealing to H), then the two survivors re-chained onto it.
        let lines: Vec<String> = std::fs::read_to_string(&log)
            .unwrap()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(str::to_string)
            .collect();
        assert_eq!(lines.len(), 3, "checkpoint + 2 retained");

        let cp: SignedReceipt = {
            // Parse the checkpoint via the verify helper's shape by round-tripping the fields.
            let v: Value = serde_json::from_str(&lines[0]).unwrap();
            assert_eq!(v["action_id"], RETENTION_CHECKPOINT);
            assert_eq!(
                v["prev_hash"],
                Value::String(pruned_head.clone()),
                "checkpoint seals to prior head H"
            );
            assert_eq!(
                v["params"]["prior_head_hash"],
                Value::String(pruned_head.clone())
            );
            assert_eq!(v["params"]["pruned_count"], json!(2));
            reparse_signed(&lines[0])
        };
        assert!(verifies(&cp), "the checkpoint itself must verify");

        // Every line verifies, and the chain is contiguous FROM the checkpoint forward.
        let mut prev = sha256_hex(lines[0].as_bytes());
        for l in &lines[1..] {
            let signed = reparse_signed(l);
            assert!(verifies(&signed), "re-chained retained receipt must verify");
            let v: Value = serde_json::from_str(l).unwrap();
            assert_eq!(
                v["prev_hash"],
                Value::String(prev.clone()),
                "retained receipt chains onto the checkpoint"
            );
            prev = sha256_hex(l.as_bytes());
        }

        // A second prune with nothing older is a clean no-op.
        let noop = prune_and_seal(&log, 50, "io-30d", &s).expect("noop prune");
        assert_eq!(noop.pruned, 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ─── A5 (design docs/design/a5-pq-dual-sig.md) ─────────────────────────────────────────

    #[cfg(feature = "pq-crypto")]
    #[test]
    fn no_pq_key_no_pq_material_ed25519_still_verifies() {
        let s = signer();
        let signed = s.record(Receipt::new(
            "step-1".into(),
            "kriya.test.noop".into(),
            json!({}),
            true,
            now_ms(),
        ));
        assert!(verifies(&signed));
        assert!(signed.pq_alg.is_none());
        assert!(signed.pq_sig.is_none());
        // Byte-for-byte with a pre-A5 receipt: serializing omits every pq_* field.
        let line = serde_json::to_string(&signed).unwrap();
        assert!(!line.contains("pq_"));
    }

    #[cfg(feature = "pq-crypto")]
    #[test]
    fn dual_sign_disabled_by_default_even_with_pq_key_loaded() {
        // A PQ key is loaded, but dual_sign_enabled = false (checkpoint-only mode, design D1
        // default): ordinary record() calls must NOT carry per-receipt pq_* siblings.
        let s = pq_signer(false);
        let signed = s.record(Receipt::new(
            "step-1".into(),
            "kriya.test.noop".into(),
            json!({}),
            true,
            now_ms(),
        ));
        assert!(verifies(&signed));
        assert!(signed.pq_alg.is_none(), "checkpoint-only mode must not dual-sign every receipt");
    }

    #[cfg(feature = "pq-crypto")]
    #[test]
    fn dual_sign_enabled_attaches_verifying_pq_siblings_to_every_receipt() {
        let s = pq_signer(true);
        let signed = s.record(Receipt::new(
            "step-1".into(),
            "kriya.test.noop".into(),
            json!({"x": 1}),
            true,
            now_ms(),
        ));
        assert!(verifies(&signed), "Ed25519 must still verify (design axiom §1.1)");
        assert_eq!(signed.pq_alg.as_deref(), Some("ML-DSA-87"));
        assert!(pq_verifies(&signed), "ML-DSA-87 signature must verify");
        // Wire sizes match design §2 D1's size table.
        assert_eq!(signed.pq_public_key.as_ref().unwrap().len(), 5184);
        assert_eq!(signed.pq_sig.as_ref().unwrap().len(), 9254);
        assert_eq!(signed.pq_key_id.as_ref().unwrap().len(), 16);

        // Tamper the PQ signature only — Ed25519 must still verify (row 3 of the design §5
        // matrix): the PQ tamper is distinct and does not touch the Ed25519-signed bytes.
        let mut tampered = signed.clone();
        tampered.pq_sig = Some("00".repeat(4627));
        assert!(verifies(&tampered), "Ed25519 unaffected by a PQ-only tamper");
        assert!(!pq_verifies(&tampered), "tampered PQ signature must not verify");
    }

    #[cfg(feature = "pq-crypto")]
    #[test]
    fn attest_pq_key_without_a_loaded_key_errors() {
        let s = signer();
        assert!(s.attest_pq_key("kriya-test", None).is_err());
    }

    #[cfg(feature = "pq-crypto")]
    #[test]
    fn attest_pq_key_binds_pq_pubkey_under_the_ed25519_identity() {
        let s = pq_signer(false);
        let attestation = s.attest_pq_key("kriya-test", None).unwrap();
        assert_eq!(attestation.receipt.action_id, PQ_KEY);
        assert!(verifies(&attestation), "the attestation itself is Ed25519-signed");
        assert_eq!(
            attestation.receipt.params["pq_alg"].as_str(),
            Some("ML-DSA-87")
        );
        assert!(attestation.receipt.params["pq_public_key"]
            .as_str()
            .unwrap()
            .len()
            == 5184);
    }

    #[cfg(feature = "pq-crypto")]
    #[test]
    fn pq_checkpoint_without_prior_receipts_errors() {
        let s = pq_signer(false);
        assert!(s.pq_checkpoint("kriya-test", None).is_err());
    }

    #[cfg(feature = "pq-crypto")]
    #[test]
    fn pq_checkpoint_seals_the_chain_head_with_a_verifying_pq_signature() {
        let s = pq_signer(false);
        for i in 0..5 {
            s.record(Receipt::new(
                format!("step-{i}"),
                "kriya.test.noop".into(),
                json!({"i": i}),
                true,
                now_ms(),
            ));
        }
        // Read the true on-disk chain head independently of the signer's in-memory state.
        let expected_head = seed_chain_head(&s.log_path).hash.expect("5 records exist");

        let checkpoint = s.pq_checkpoint("kriya-test", None).unwrap();
        assert_eq!(checkpoint.receipt.action_id, PQ_CHECKPOINT);
        assert!(verifies(&checkpoint), "checkpoint is Ed25519-signed + chained like any receipt");
        assert!(pq_verifies(&checkpoint), "checkpoint's own pq_sig must verify");
        assert_eq!(
            checkpoint.receipt.params["to_head_hash"].as_str(),
            Some(expected_head.as_str())
        );
        assert_eq!(checkpoint.receipt.params["from_seq"], 1);
        assert_eq!(checkpoint.receipt.params["count"], 5);
        // The design's pq_alg-authority rule (§4.1): signed params.pq_alg and the unsigned
        // top-level sibling MUST agree.
        assert_eq!(
            checkpoint.receipt.params["pq_alg"].as_str(),
            checkpoint.pq_alg.as_deref()
        );

        // A second checkpoint after 3 more receipts seals only the NEW receipts (from_seq
        // continues where the last checkpoint left off).
        for i in 5..8 {
            s.record(Receipt::new(
                format!("step-{i}"),
                "kriya.test.noop".into(),
                json!({"i": i}),
                true,
                now_ms(),
            ));
        }
        let checkpoint2 = s.pq_checkpoint("kriya-test", None).unwrap();
        assert_eq!(checkpoint2.receipt.params["from_seq"], 6);
        assert_eq!(checkpoint2.receipt.params["count"], 3);
    }

    #[cfg(feature = "pq-crypto")]
    #[test]
    fn pq_siblings_do_not_break_the_hash_chain() {
        // Axiom §1.3: the chain hashes the raw line verbatim, so pq_* siblings (present via
        // dual-sign) are naturally chain-covered with no chain-logic change.
        let s = pq_signer(true);
        for i in 0..4 {
            s.record(Receipt::new(
                format!("step-{i}"),
                "kriya.test.noop".into(),
                json!({"i": i}),
                true,
                now_ms(),
            ));
        }
        let content = std::fs::read_to_string(&s.log_path).unwrap();
        let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(lines.len(), 4);
        // Every line after the first carries a prev_hash equal to the SHA-256 of the previous
        // raw line INCLUDING its pq_* siblings.
        for w in lines.windows(2) {
            let expected_prev = sha256_hex(w[0].as_bytes());
            let v: Value = serde_json::from_str(w[1]).unwrap();
            assert_eq!(v["prev_hash"].as_str(), Some(expected_prev.as_str()));
        }
    }

    #[cfg(feature = "pq-crypto")]
    #[test]
    fn pq_maybe_checkpoint_self_throttles_on_cadence() {
        let s = pq_signer(false);
        // No PQ key loaded scenario is covered elsewhere; here: below the cadence, no checkpoint.
        for i in 0..3 {
            s.record(Receipt::new(
                format!("step-{i}"),
                "kriya.test.noop".into(),
                json!({}),
                true,
                now_ms(),
            ));
        }
        assert!(s.pq_maybe_checkpoint("kriya-test", None, 5).is_none());

        for i in 3..5 {
            s.record(Receipt::new(
                format!("step-{i}"),
                "kriya.test.noop".into(),
                json!({}),
                true,
                now_ms(),
            ));
        }
        let cp = s
            .pq_maybe_checkpoint("kriya-test", None, 5)
            .expect("cadence reached")
            .expect("checkpoint succeeds");
        assert_eq!(cp.receipt.action_id, PQ_CHECKPOINT);
        assert!(pq_verifies(&cp));

        // Immediately after, the cadence resets — nothing new to seal yet.
        assert!(s.pq_maybe_checkpoint("kriya-test", None, 5).is_none());
    }

    /// Re-hydrate a stored line into the local `SignedReceipt` shape so the test's `verifies` helper
    /// can re-derive its canonical bytes. Mirrors what `parse_stored_receipt` does internally.
    fn reparse_signed(line: &str) -> SignedReceipt {
        let v: Value = serde_json::from_str(line).unwrap();
        let actor = v.get("actor").and_then(|a| {
            Some(Actor::new(
                a.get("agent")?.as_str()?,
                a.get("user")?.as_str()?,
            ))
        });
        let mut r = Receipt::new(
            v["step_id"].as_str().unwrap().to_string(),
            v["action_id"].as_str().unwrap().to_string(),
            v["params"].clone(),
            v["success"].as_bool().unwrap(),
            v["ts_ms"].as_u64().unwrap() as u128,
        );
        r.actor = actor;
        r.prev_hash = v
            .get("prev_hash")
            .and_then(Value::as_str)
            .map(str::to_string);
        SignedReceipt {
            receipt: r,
            public_key: v["public_key"].as_str().unwrap().to_string(),
            signature: v["signature"].as_str().unwrap().to_string(),
            pq_alg: v.get("pq_alg").and_then(Value::as_str).map(str::to_string),
            pq_public_key: v
                .get("pq_public_key")
                .and_then(Value::as_str)
                .map(str::to_string),
            pq_sig: v.get("pq_sig").and_then(Value::as_str).map(str::to_string),
            pq_key_id: v
                .get("pq_key_id")
                .and_then(Value::as_str)
                .map(str::to_string),
        }
    }

    // ---- Public verifier (verify_signed_line / verify_chain / signature_valid) ----

    /// Record a small chain into a fresh log and return its exact on-disk lines.
    fn recorded_lines(receipts: Vec<Receipt>) -> (Vec<String>, Signer) {
        let s = signer();
        for r in receipts {
            s.record(r);
        }
        let text = std::fs::read_to_string(s.log_path()).unwrap();
        (text.lines().map(str::to_string).collect(), s)
    }

    #[test]
    fn verify_signed_line_accepts_a_genuine_line() {
        let (lines, _s) = recorded_lines(vec![Receipt::new(
            "step-1".into(),
            "create_note".into(),
            json!({ "b": 2, "a": 1 }),
            true,
            1_700_000_000_000,
        )]);
        let v = verify_signed_line(&lines[0]);
        assert!(v.verified, "genuine line must verify: {:?}", v.reason);
        assert_eq!(v.signed.unwrap().receipt.action_id, "create_note");
    }

    #[test]
    fn verify_signed_line_rejects_a_tampered_param() {
        let (lines, _s) = recorded_lines(vec![Receipt::new(
            "step-1".into(),
            "wire.transfer".into(),
            json!({ "amount": 100 }),
            true,
            1_700_000_000_000,
        )]);
        // Flip the amount in the raw line without re-signing.
        let tampered = lines[0].replace("\"amount\":100", "\"amount\":999999");
        assert_ne!(tampered, lines[0], "the replace must have changed the line");
        let v = verify_signed_line(&tampered);
        assert!(!v.verified, "a tampered line must not verify");
        assert_eq!(v.reason, Some("bad-signature"));
        // It still parsed — the caller can see WHAT was forged.
        assert!(v.signed.is_some());
    }

    #[test]
    fn verify_signed_line_reports_parse_error_for_garbage() {
        let v = verify_signed_line("{not json");
        assert!(!v.verified);
        assert_eq!(v.reason, Some("parse-error"));
        assert!(v.signed.is_none());
    }

    #[test]
    fn verify_chain_accepts_an_intact_log() {
        let (lines, _s) = recorded_lines(vec![
            Receipt::new("s1".into(), "a.one".into(), json!({}), true, 1),
            Receipt::new("s2".into(), "a.two".into(), json!({}), true, 2),
            Receipt::new("s3".into(), "a.three".into(), json!({}), true, 3),
        ]);
        let v = verify_chain(&lines);
        assert!(v.verified, "intact chain must verify; break at {:?}", v.first_break);
        assert_eq!(v.lines, 3);
        assert_eq!(v.first_break, None);
    }

    #[test]
    fn verify_chain_flags_a_deleted_middle_line() {
        let (lines, _s) = recorded_lines(vec![
            Receipt::new("s1".into(), "a.one".into(), json!({}), true, 1),
            Receipt::new("s2".into(), "a.two".into(), json!({}), true, 2),
            Receipt::new("s3".into(), "a.three".into(), json!({}), true, 3),
        ]);
        // Drop the middle line: line 2's signature is fine, but its prev_hash points at the
        // deleted line 1, so the chain link mismatches.
        let mutated = vec![lines[0].clone(), lines[2].clone()];
        let v = verify_chain(&mutated);
        assert!(!v.verified, "a deleted line must break the chain");
        assert_eq!(v.first_break, Some(1));
    }
}
