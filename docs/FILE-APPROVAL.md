# File-mediated approval (`--approval file`)

A published, stable wire format for routing a policy-guarded action to an **out-of-band decider**
when there is no interactive operator on the device — no controlling terminal (`tty`), no window
server (`gui`), and no in-process Console modal. It is the mechanism a standalone, headless kriya
device uses to hold a `require_approval` action while a separate program (e.g. the K-Apter menu-bar
agent) shows the request to a human and answers it.

The runtime binaries that gate actions — `kriya-gateway`, `kriya-mcp`, `kriya-govern`, `kriya-hook`
— all accept `--approval file`. When selected, a guarded action is decided through two append-only
JSONL files instead of a prompt.

## Location

```
~/.kriya/console/approvals/
├── pending.jsonl     # the runtime appends one request per line
└── decisions.jsonl   # the decider appends one answer per line
```

The directory is `~/.kriya/console/approvals/` (sibling of the audit dir `~/.kriya/audit/`), created
on first use. It falls back to the OS temp dir when no home directory is resolvable. Both sides
compute the path the same way with no shared configuration.

## Flow

1. A guarded action reaches the gate. The runtime writes one `PendingApproval` line to
   `pending.jsonl` (append + flush) and begins polling `decisions.jsonl`.
2. The decider (a separate program) tails `pending.jsonl`, shows the request to a human, and appends
   one `ApprovalDecision` line to `decisions.jsonl` whose `id` echoes the pending request's `id`.
3. The runtime sees the matching decision and proceeds (`approved: true`) or blocks
   (`approved: false`).
4. **Deny-default.** If no matching decision is written within the timeout (default **300 s**, well
   under Claude Code's 600 s hook ceiling, which fails *open*), the action is **denied**. Any I/O
   error also denies — a coordination failure never opens the gate.

## `pending.jsonl` — one `PendingApproval` per line

```json
{
  "id": "b1c2d3e4-...-uuid-v4",
  "action_id": "claude-code__bash",
  "params": { "cmd": "deploy --prod" },
  "requested_at_ms": 1754870400000,
  "pid": 41234
}
```

| field | type | meaning |
|---|---|---|
| `id` | string (uuid v4) | correlation key; unique per request. The decision echoes this. |
| `action_id` | string | the policy action id the approval is for. |
| `params` | object | the action's parameters, verbatim, for the human to judge. |
| `requested_at_ms` | number | when the request was written (unix epoch milliseconds). |
| `pid` | number | PID of the waiting process (diagnostics; a stale line whose PID is gone was abandoned on timeout). |

## `decisions.jsonl` — one `ApprovalDecision` per line

```json
{ "id": "b1c2d3e4-...-uuid-v4", "approved": true, "decided_at_ms": 1754870412000 }
```

| field | type | meaning |
|---|---|---|
| `id` | string | the `id` of the `PendingApproval` this answers. |
| `approved` | bool | `true` = approve, `false` = deny. The only field that decides the outcome. |
| `decided_at_ms` | number | when decided (unix epoch milliseconds); optional on read. |

## Rules for a decider

- **Match by `id`.** Ignore any pending request you do not intend to answer; a decision for a
  different `id` never satisfies another request.
- **Append only.** Never rewrite or truncate either file. If you correct an answer, append a new
  line for the same `id` — the runtime honors the **last** matching decision.
- **Malformed lines are skipped**, not fatal, on the reading side, so a partial write is not
  catastrophic. Still, write one complete line (with trailing newline) per decision.
- **Deny is the safe default.** A decider that is absent, slow, or crashed simply lets the request
  time out to a denial. You do not need to answer every request — only the ones you approve or
  explicitly deny.
- **This format is the contract, not a shared library.** A decider must not depend on the runtime
  crate; it reads and writes JSON lines as documented here. Fields are additive — unknown fields on
  read are ignored, and new optional fields may appear over time.
