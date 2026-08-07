# Security Review: windows-local-mcp-python

## Scope

All 26 current repository files were statically reviewed.

- Scan mode: repository
- Target kind: git_revision
- Target ID: target_sha256_5977c329cc2487c89c4e2272409dc3e2dbb1ab275b38ee589a9ef68fb8320387
- Revision: f9074999ac43edb593400d47c33a52560080f3a5
- Inventory strategy: repository
- Included paths: .
- Excluded paths: none
- Runtime or test status: Dependencies absent; repository unchanged and worktree clean.
- Artifacts reviewed: README.md, SPEC.md, VERIFICATION.md, config.example.toml, pyproject.toml, run-server.ps1, run-approvals.ps1, src/windows_local_mcp/, tests/

Limitations and exclusions:
- AST parsing succeeded for 16 Python files; pytest/ruff/MCP runtime could not run because dependencies are not installed.
- No live Git exploit, Flutter, Dart, ADB, PowerShell, MCP Inspector, or Secure MCP Tunnel execution was performed.

### Scan Summary

| Field | Value |
| --- | --- |
| Reportable findings | 11 |
| Severity mix | high: 4, medium: 4, low: 3 |
| Confidence mix | high: 11 |
| Coverage | partial |
| Validation mode | Parent validation plus independent baseline and two focused investigations. |

Canonical artifacts: `scan-manifest.json`, `findings.json`, and `coverage.json`. This report is a deterministic projection of those files.

## Threat Model

An MCP client controls tool arguments and workspace content; the Windows process runs as the local user. Boundaries are workspace containment, Tier-1 policy, human approval, transport authentication, and audit storage.

### Assets

- Host-user files and credentials
- Files outside workspace_root
- Host process authority
- Android targets
- Approval and audit integrity

### Trust Boundaries

- MCP client to handlers
- Workspace content to subprocesses
- Tier 1 to approval
- Approval to later effective code
- Transport to Windows account
- Workspace to data_dir

### Attacker Capabilities

- Choose MCP arguments
- Read/write allowed workspace files
- Invoke Tier-1 commands
- Manage job and approval IDs

### Security Objectives

- No unapproved external filesystem access
- No arbitrary host/device execution in Tier 1
- Fresh approval binds effective code
- Authenticated owner-scoped access
- Bounded resources and trustworthy audit

### Assumptions

- Not Administrator
- Default data_dir outside workspace
- Secure MCP Tunnel external and unverified
- OS/network sandbox absent as documented

## Findings

| Finding | Severity | Confidence | Detailed write-up |
| --- | --- | --- | --- |
| [Allowlisted command arguments can read or write outside the workspace](#finding-1) | high | high | inline below |
| [Tier-1 ADB shell permits destructive and potentially arbitrary device operations](#finding-2) | high | high | inline below |
| [Approval hash does not bind the executable content or scripts the user reviewed](#finding-3) | high | high | inline below |
| [Tier-1 Dart, Flutter, and mutable safe scripts can execute arbitrary host code without approval](#finding-4) | high | high | inline below |
| [Unbounded file edits and command output can exhaust memory and disk](#finding-5) | medium | high | inline below |
| [Optional Streamable HTTP exposes privileged tools without authentication or caller ownership](#finding-6) | medium | high | inline below |
| [expected_sha256 does not prevent concurrent lost updates](#finding-7) | medium | high | inline below |
| [Approved host commands remain executable after the configured TTL](#finding-8) | medium | high | inline below |
| [Denied and control-plane operations are not consistently audited](#finding-9) | low | high | inline below |
| [stop_job can kill unrelated processes after stale PID reuse](#finding-10) | low | high | inline below |
| [Configuration permits audit and backup data inside the writable workspace](#finding-11) | low | high | inline below |

### Confidence Scale

| Label | Meaning |
| --- | --- |
| high | Direct evidence supports the finding with no material unresolved blocker. |
| medium | Evidence supports a plausible issue, but material runtime or reachability proof remains. |
| low | Evidence is incomplete and the item is retained only for explicit follow-up. |

<a id="finding-1"></a>

### [1] Allowlisted command arguments can read or write outside the workspace

| Field | Value |
| --- | --- |
| Severity | high |
| Confidence | high |
| Confidence rationale | After checking args\[0\], _result forwards args unchanged. Git diff accepts external paths and --output; Dart format accepts file operands. |
| Category | path-traversal |
| CWE | CWE-22, CWE-73 |
| Affected lines | src/windows_local_mcp/policy.py:52-84, src/windows_local_mcp/policy.py:169-182, src/windows_local_mcp/worker.py:48-63 |

#### Summary

cwd is confined, but child-program path operands and output options are not.

#### Root Cause

After checking args\[0\], _result forwards args unchanged. Git diff accepts external paths and --output; Dart format accepts file operands.

#### Validation

After checking args\[0\], _result forwards args unchanged. Git diff accepts external paths and --output; Dart format accepts file operands.

#### Dataflow

MCP args -\> first-token check -\> unchanged args -\> external child path/output

#### Reachability

Direct when Git or Dart is installed.

#### Severity

**High** — cwd is confined, but child-program path operands and output options are not.

Additional runtime or deployment evidence could raise or lower this severity.

#### Remediation

Use complete deny-by-default argument grammars; resolve every path/output/config operand through Workspace and route unknown forms to approval.

<a id="finding-2"></a>

### [2] Tier-1 ADB shell permits destructive and potentially arbitrary device operations

| Field | Value |
| --- | --- |
| Severity | high |
| Confidence | high |
| Confidence rationale | pm, am, input, wm, dumpsys, and screencap receive unrestricted remaining arguments; exec-out is the only exact pattern. |
| Category | improper-authorization |
| CWE | CWE-284, CWE-78 |
| Affected lines | src/windows_local_mcp/policy.py:126-137, src/windows_local_mcp/worker.py:48-63 |

#### Summary

ADB shell validates only the first device-side command family.

#### Root Cause

pm, am, input, wm, dumpsys, and screencap receive unrestricted remaining arguments; exec-out is the only exact pattern.

#### Validation

pm, am, input, wm, dumpsys, and screencap receive unrestricted remaining arguments; exec-out is the only exact pattern.

#### Dataflow

execute adb shell family unrestricted-action -\> attached Android target

#### Reachability

Requires an adb-visible physical device or emulator.

#### Severity

**High** — ADB shell validates only the first device-side command family.

Additional runtime or deployment evidence could raise or lower this severity.

#### Remediation

Remove generic adb shell from Tier 1; expose exact fixed read-only operations and approve state-changing/device-shell actions.

<a id="finding-3"></a>

### [3] Approval hash does not bind the executable content or scripts the user reviewed

| Field | Value |
| --- | --- |
| Severity | high |
| Confidence | high |
| Confidence rationale | approval_hash contains executable path, args, cwd, network flag, reason and risk only. write_file can change a referenced workspace script after approval. |
| Category | time-of-check-time-of-use |
| CWE | CWE-367 |
| Affected lines | src/windows_local_mcp/policy.py:186-200, src/windows_local_mcp/server.py:430-455, src/windows_local_mcp/worker.py:48-63 |

#### Summary

Approval hashes argv/cwd strings, not behavior-determining file bytes or identity.

#### Root Cause

approval_hash contains executable path, args, cwd, network flag, reason and risk only. write_file can change a referenced workspace script after approval.

#### Validation

approval_hash contains executable path, args, cwd, network flag, reason and risk only. write_file can change a referenced workspace script after approval.

#### Dataflow

benign script -\> approval -\> content replacement -\> execute_approved -\> new bytes run

#### Reachability

Direct for approved commands referencing writable workspace content.

#### Severity

**High** — Approval hashes argv/cwd strings, not behavior-determining file bytes or identity.

Additional runtime or deployment evidence could raise or lower this severity.

#### Remediation

Hash/snapshot executable scripts and all behavior-determining inputs; revalidate immediately and execute immutable staged copies.

<a id="finding-4"></a>

### [4] Tier-1 Dart, Flutter, and mutable safe scripts can execute arbitrary host code without approval

| Field | Value |
| --- | --- |
| Severity | high |
| Confidence | high |
| Confidence rationale | FLUTTER_ALLOWED includes test/build; DART_ALLOWED includes test. Only args\[0\] or a mutable script path is trusted. |
| Category | command-injection |
| CWE | CWE-78, CWE-94 |
| Affected lines | src/windows_local_mcp/policy.py:24-28, src/windows_local_mcp/policy.py:74-84, src/windows_local_mcp/server.py:168-234, src/windows_local_mcp/worker.py:48-63 |

#### Summary

The safe tier includes code-loading test/build runners and path-only trusted scripts.

#### Root Cause

FLUTTER_ALLOWED includes test/build; DART_ALLOWED includes test. Only args\[0\] or a mutable script path is trusted.

#### Validation

FLUTTER_ALLOWED includes test/build; DART_ALLOWED includes test. Only args\[0\] or a mutable script path is trusted.

#### Dataflow

write_file -\> workspace code -\> execute/start_command -\> allowlist -\> subprocess as Windows user

#### Reachability

Direct with installed toolchain and documented write/execute access.

#### Severity

**High** — The safe tier includes code-loading test/build runners and path-only trusted scripts.

Additional runtime or deployment evidence could raise or lower this severity.

#### Remediation

Move code-loading operations to approval or a real Windows sandbox; keep trusted scripts outside the writable workspace and bind immutable digests.

<a id="finding-5"></a>

### [5] Unbounded file edits and command output can exhaust memory and disk

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Complete logs are read before truncate_middle; max_text_file_bytes is not applied to write_file or prior files. |
| Category | resource-exhaustion |
| CWE | CWE-400 |
| Affected lines | src/windows_local_mcp/worker.py:95-112, src/windows_local_mcp/server.py:168-234, src/windows_local_mcp/worker.py:27-63 |

#### Summary

Writes/diffs/backups and captured stdout/stderr have no byte quota.

#### Root Cause

Complete logs are read before truncate_middle; max_text_file_bytes is not applied to write_file or prior files.

#### Validation

Complete logs are read before truncate_middle; max_text_file_bytes is not applied to write_file or prior files.

#### Dataflow

large edit or verbose child -\> unbounded artifacts/logs -\> memory/disk exhaustion

#### Reachability

Direct through write_file or an allowed verbose command.

#### Severity

**Medium** — Writes/diffs/backups and captured stdout/stderr have no byte quota.

Additional runtime or deployment evidence could raise or lower this severity.

#### Remediation

Add pre-diff/write caps, bounded artifact cleanup, byte-quota log capture, bounded head/tail previews, and retention quotas.

<a id="finding-6"></a>

### [6] Optional Streamable HTTP exposes privileged tools without authentication or caller ownership

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | LOCAL_MCP_HOST is passed to mcp.run; no auth provider is configured and session_id is unused. |
| Category | missing-authentication |
| CWE | CWE-306, CWE-862 |
| Affected lines | src/windows_local_mcp/server.py:478-485, src/windows_local_mcp/server.py:32-43, src/windows_local_mcp/audit.py:94-137 |

#### Summary

HTTP can bind arbitrarily with no repository authenticator; operations are global.

#### Root Cause

LOCAL_MCP_HOST is passed to mcp.run; no auth provider is configured and session_id is unused.

#### Validation

LOCAL_MCP_HOST is passed to mcp.run; no auth provider is configured and session_id is unused.

#### Dataflow

reachable HTTP client -\> global MCP tools/audit -\> host operation

#### Reachability

Conditional on HTTP; remote access needs non-loopback binding or forwarding.

#### Severity

**Medium** — HTTP can bind arbitrarily with no repository authenticator; operations are global.

Additional runtime or deployment evidence could raise or lower this severity.

#### Remediation

Keep HTTP disabled unless authenticated; enforce loopback otherwise and principal ownership on operation access.

<a id="finding-7"></a>

### [7] expected_sha256 does not prevent concurrent lost updates

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Two writers can read the same bytes, pass the same expected hash, and both later report successful replacement. |
| Category | race-condition |
| CWE | CWE-367 |
| Affected lines | src/windows_local_mcp/server.py:176-234, src/windows_local_mcp/paths.py:51-58 |

#### Summary

Hash comparison and os.replace are separated without per-target serialization.

#### Root Cause

Two writers can read the same bytes, pass the same expected hash, and both later report successful replacement.

#### Validation

Two writers can read the same bytes, pass the same expected hash, and both later report successful replacement.

#### Dataflow

two concurrent writes -\> same old hash -\> two replaces -\> last writer wins

#### Reachability

Requires concurrent same-target calls.

#### Severity

**Medium** — Hash comparison and os.replace are separated without per-target serialization.

Additional runtime or deployment evidence could raise or lower this severity.

#### Remediation

Lock per canonical target across check/artifact/replace and revalidate object and parent identity immediately before replacement.

<a id="finding-8"></a>

### [8] Approved host commands remain executable after the configured TTL

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | claim_approved checks only approval_status='approved' and status='approved'; the UI no longer sees approved rows. |
| Category | session-expiration |
| CWE | CWE-613 |
| Affected lines | src/windows_local_mcp/audit.py:300-320, src/windows_local_mcp/approval_ui.py:36-54, src/windows_local_mcp/server.py:430-455 |

#### Summary

Expiry is UI-only for pending items; execution claim has no time predicate.

#### Root Cause

claim_approved checks only approval_status='approved' and status='approved'; the UI no longer sees approved rows.

#### Validation

claim_approved checks only approval_status='approved' and status='approved'; the UI no longer sees approved rows.

#### Dataflow

old approved row -\> status-only claim -\> worker

#### Reachability

Any holder of an approved, unclaimed ID can invoke it indefinitely.

#### Severity

**Medium** — Expiry is UI-only for pending items; execution claim has no time predicate.

Additional runtime or deployment evidence could raise or lower this severity.

#### Remediation

Store expires_at and enforce freshness atomically at decision and claim; use a short grant-to-execution TTL.

<a id="finding-9"></a>

### [9] Denied and control-plane operations are not consistently audited

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | high |
| Confidence rationale | normalize_safe can reject before _queue_command creates an operation; stop_job/poll_job and audit access do not use _log_simple. |
| Category | insufficient-logging |
| CWE | CWE-778 |
| Affected lines | src/windows_local_mcp/server.py:302-313, src/windows_local_mcp/server.py:351-360, SPEC.md:65-71 |

#### Summary

Validation occurs before audit creation and some control tools bypass logging.

#### Root Cause

normalize_safe can reject before _queue_command creates an operation; stop_job/poll_job and audit access do not use _log_simple.

#### Validation

normalize_safe can reject before _queue_command creates an operation; stop_job/poll_job and audit access do not use _log_simple.

#### Dataflow

denied or control call -\> response/exception -\> no durable request record

#### Reachability

Direct for rejected paths/commands and unlogged control calls.

#### Severity

**Low** — Validation occurs before audit creation and some control tools bypass logging.

Additional runtime or deployment evidence could raise or lower this severity.

#### Remediation

Add request-boundary audit middleware with redaction and outcome logging; explicitly log job stop, approval claim/poll, and audit access.

<a id="finding-10"></a>

### [10] stop_job can kill unrelated processes after stale PID reuse

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | high |
| Confidence rationale | Cancellation calls terminate_process_tree on stored child_pid/worker_pid only; crashes/reboots can leave nonterminal rows. |
| Category | race-condition |
| CWE | CWE-362 |
| Affected lines | src/windows_local_mcp/executor.py:60-79, src/windows_local_mcp/process_utils.py:38-60, src/windows_local_mcp/worker.py:119-129 |

#### Summary

Durable jobs trust recyclable integer PIDs without process identity checks.

#### Root Cause

Cancellation calls terminate_process_tree on stored child_pid/worker_pid only; crashes/reboots can leave nonterminal rows.

#### Validation

Cancellation calls terminate_process_tree on stored child_pid/worker_pid only; crashes/reboots can leave nonterminal rows.

#### Dataflow

stale row -\> PID reuse -\> stop_job -\> unrelated process tree terminated

#### Reachability

Requires a stale nonterminal row and PID reuse.

#### Severity

**Low** — Durable jobs trust recyclable integer PIDs without process identity checks.

Additional runtime or deployment evidence could raise or lower this severity.

#### Remediation

Use Windows Job Objects or verify PID creation time, executable and nonce; reconcile startup state and use conditional terminal updates.

<a id="finding-11"></a>

### [11] Configuration permits audit and backup data inside the writable workspace

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | high |
| Confidence rationale | An overlapping data_dir makes text outputs, diffs, backups, and snapshots accessible to file tools; default LOCALAPPDATA is outside. |
| Category | security-misconfiguration |
| CWE | CWE-668 |
| Affected lines | src/windows_local_mcp/config.py:44-56, src/windows_local_mcp/server.py:69-85 |

#### Summary

workspace_root and data_dir are normalized independently with no overlap rejection.

#### Root Cause

An overlapping data_dir makes text outputs, diffs, backups, and snapshots accessible to file tools; default LOCALAPPDATA is outside.

#### Validation

An overlapping data_dir makes text outputs, diffs, backups, and snapshots accessible to file tools; default LOCALAPPDATA is outside.

#### Dataflow

overlap config -\> audit artifacts under workspace -\> read_file/write_file

#### Reachability

Requires operator overlap configuration.

#### Severity

**Low** — workspace_root and data_dir are normalized independently with no overlap rejection.

Additional runtime or deployment evidence could raise or lower this severity.

#### Remediation

Reject equal/nested data_dir, deny the subtree in Workspace, reject reparse overlap, and apply restrictive ACLs.

## Reviewed Surfaces

| Surface | Risk Area | Outcome | Notes |
| --- | --- | --- | --- |
| Workspace paths and file tools | not recorded | Reported | No additional canonical notes were recorded. |
| Git Flutter Dart ADB and PowerShell policy | not recorded | Reported | No additional canonical notes were recorded. |
| Approval request hash decision claim and execution | not recorded | Reported | No additional canonical notes were recorded. |
| Worker lifecycle output timeout polling and cancellation | not recorded | Reported | No additional canonical notes were recorded. |
| SQLite audit events artifacts and access | not recorded | Reported | No additional canonical notes were recorded. |
| stdio optional HTTP SDK CLI and launch scripts | not recorded | Needs follow-up | No additional canonical notes were recorded. |
| Settings data paths executable discovery and defaults | not recorded | Reported | No additional canonical notes were recorded. |
| README SPEC VERIFICATION packaging and tests | not recorded | Needs follow-up | No additional canonical notes were recorded. |

## Open Questions And Follow Up

- Does the deployed Secure MCP Tunnel enforce the intended authenticated boundary and clean stdio lifecycle?
- Which exact MCP SDK 2.x and adb versions will be deployed and pass integration tests?
- Dependencies and toolchains are absent; live Windows PowerShell Flutter Dart ADB and process tests were not run.
  - Follow-up prompt: Review deferred unit windows_integration and close its stated proof gap. Paths: VERIFICATION.md.
- No tunnel configuration exists and Secure MCP Tunnel is explicitly untested.
  - Follow-up prompt: Review deferred unit secure_tunnel_integration and close its stated proof gap. Paths: README.md, VERIFICATION.md.
