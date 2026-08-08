# Windows Local MCP Security Specification

## 1. Scope and trust model

One server process represents exactly one explicitly configured `workspace_root`. The MCP client controls tool arguments and may modify ordinary workspace files. The Windows account, installed OS/toolchains, `data_dir`, and the local approver are trusted. The process must not run as Administrator.

Security objectives:

1. No direct workspace escape through file paths or automatic command operands.
2. No arbitrary host/device code execution in the automatic tier.
3. Approval binds every MCP-influenceable behavior input and is fresh, atomic, one-shot.
4. Audit/output/storage remain bounded and outside the workspace.
5. Process cancellation never trusts a recyclable PID alone.
6. Low-risk development operations remain automatic.

## 2. Capability switches

`filesystem_enabled`, `git_enabled`, `flutter_enabled`, `dart_enabled`, `adb_enabled`, and `powershell_enabled` are independent. A disabled capability is disabled in both the automatic and approval paths; approval does not override an explicit `false`. Disabled optional tools are not resolved at startup. `workspace_root` is mandatory; there is no current-directory fallback.

Dangerous configuration combinations fail startup validation:

- lexical or resolved overlap between `workspace_root` and `data_dir`
- workspace/data root reparse points
- non-loopback unauthenticated HTTP
- multi-principal HTTP without authenticated ownership enforcement
- PowerShell safe-script configuration while PowerShell is disabled

## 3. Filesystem broker

All MCP file paths pass through `Workspace`.

- Reject absolute, drive-qualified, UNC, ADS, reserved device, trailing-dot/space, and NUL paths.
- Resolve every existing component and reject workspace escape.
- Reject symlink, junction, mount/reparse components.
- Reject regular files with `st_nlink > 1`.
- Apply protected-name, read-denied, and write-denied policy separately.
- Keep `.git` directly unreadable/unwritable; obtain state only through Git subprocesses.

`write_file` additionally:

1. takes a target-scoped cross-process mutation slot plus the canonical-target thread lock;
2. re-resolves target and reads/checks expected SHA inside the locks;
3. captures the before checkpoint and fsyncs a write-ahead recovery journal before replacement;
4. enforces old/new/diff/backup/data quotas before replacement;
5. writes and fsyncs a same-directory temporary file;
6. revalidates parent `(device,inode)` and target full identity immediately before `os.replace`;
7. verifies and journals the after checkpoint, and restores the before checkpoint after a detected failure. Interrupted writes are reconciled on startup and unresolved recovery checkpoints are retention-protected.
6. verifies resulting SHA.

Target slots are selected from the canonical target path. Different slots can proceed concurrently; the same target always maps to the same slot, while a hash collision only causes extra serialization. A workspace-wide writer acquires every slot, so it still excludes all target writes.

Ordinary file reads do not take a mutation lock.

## 4. Automatic command tier

Automatic execution uses complete subcommand grammars, not a first-token allowlist. Unknown flags, positional forms, config/output paths, or unsafe ambiguity are rejected and can be resubmitted through approval.

The MCP surface is split after the deny-by-default grammar succeeds:

- `execute_readonly`: safe Git reads, `flutter analyze`, `dart analyze`, and non-writing `dart format`.
- `execute_workspace_write`: automatic commands intentionally modifying workspace source; currently writing `dart format`.
- `adb_read`: only the fixed read-only ADB grammar.

The split is presentation and host-policy metadata, not a second authorization system. All three call the same `CommandPolicy.normalize_safe()` and the same queue/executor path. A command routed to the wrong surface is rejected and directed to the matching tool.

### Git

Automatic subcommands: `status`, `diff`, `log`, `show`, restricted `rev-parse`, and `ls-files`.

- Force no pager; diff/show force `--no-ext-diff --no-textconv`.
- Disallow `-C`, `--git-dir`, `--work-tree`, `--output`, config injection, pager/external helpers, and unknown flags.
- Pathspec is accepted only after `--` and resolved inside workspace.
- Git repository/config override environment variables are removed before Git subprocesses run.
- `git_info` returns branch, HEAD, status, working diff, staged diff, recent log, and changed files through bounded subprocess capture.

### Flutter and Dart

- `flutter analyze` only; force `--no-pub` and validate every explicit path.
- `dart analyze` and constrained `dart format` only.
- `flutter test/build/run` and `dart test/run/compile` are never automatic.
- analyze is executed from a fixed snapshot; format that writes uses full source manifest plus the execution lock.

### ADB

ADB is separately disabled by default. Automatic forms are exact:

- `adb devices [-l]`
- `adb -s SERIAL get-state`
- fixed read-only `getprop`, `wm`, and `dumpsys` forms
- `adb -s SERIAL exec-out screencap -p`

Targeted calls require serial validation. `adb_emulator_only=true` requires an `emulator-*` serial and a successful `adb emu avd name` preflight. Optional `adb_allowed_serials` further narrows targets. General shell and state changes require approval.

### Execution lock policy

The workspace-wide mutation lock is no longer held for every command for the full child-process lifetime.

- Safe Git reads, safe ADB reads, `flutter analyze`, `dart analyze`, and non-writing `dart format` execute without the workspace-wide mutation lock.
- Approved code-loading commands in immutable `staged-cwd` snapshot mode, including test/build-style execution, run without the workspace-wide mutation lock because they execute from `data_dir`, not the original workspace.
- A writing `dart format`, an approved command marked `workspace_write=true`, and approved commands that still execute against the original workspace keep the exclusive workspace-wide mutation lock through verification and child execution.
- Snapshot/manifest creation may still take the workspace-wide lock briefly so the captured input set is coherent.
- `write_file` uses one target slot rather than all slots, so unrelated file writes can proceed concurrently while still conflicting with workspace-wide writers.
- Old approval rows that do not contain explicit snapshot metadata fail conservatively and keep the workspace-wide lock.

This permits long-running isolated tests/builds, read-only analysis, and unrelated target writes to overlap without weakening the source-write boundary.

## 5. Approval and immutable execution

Preferred flow:

```text
request_host_command
  -> pending immutable manifest with request TTL
  -> local UI verifies and atomically approve+claims
  -> MCP worker runs fixed content once
  -> ChatGPT poll_approval / poll_job
```

`request_host_command` only stages local approval state and immutable inputs; it does not launch the requested process. Dangerous execution starts only from the local approval UI after the human approves it. There is no model-facing `execute_approved` tool, which avoids a second destructive/open-world MCP call after local approval.

The approval hash covers normalized command, cwd, network flag, reason, risk, and manifest digest. The manifest covers:

- main executable bytes and filesystem identity;
- complete argv;
- effective Settings digest;
- relevant environment digest;
- every regular file in the MCP-influenceable execution scope;
- external regular-file operands where complete binding is possible;
- Dart/Flutter package closure resolved from `package_config.json`;
- Git HEAD/status/working diff/staged diff for Git host operations.

### Snapshot mode

Code-loading commands that do not need to mutate the source run from an immutable copy of their `cwd`. Paths outside `cwd` are not reachable through the original workspace because:

- standalone workspace paths are rewritten to the copy;
- embedded workspace paths and external code-loader paths are rejected;
- symlink/junction/reparse/hardlink entries are rejected;
- MCP configuration variables and language/module injection variables are removed from the child environment;
- HOME/USERPROFILE/APPDATA/LOCALAPPDATA/TEMP/PUB_CACHE point to an operation-local runtime directory;
- file-based Dart/Flutter package dependencies outside `cwd` are copied and `package_config.json` is rewritten;
- non-file or non-enumerable dependencies fail closed.

The immutable copy is verified after local approval. The worker then creates a separate writable disposable run copy, so build artifacts cannot mutate the approved input copy. Unrelated workspace changes outside the approved `cwd` do not invalidate snapshot execution. Snapshot-backed child execution does not hold the workspace-wide mutation lock.

Installed OS/toolchains are the trusted computing base. Their primary executable is content-bound. Complete OS DLL/toolchain virtualization is not provided.

### Source-write mode

Commands intended to mutate the original workspace require `workspace_write=true`. The complete workspace (excluding direct `.git` bytes) is manifested, all source files are revalidated, and execution occurs while holding the workspace-wide form of the same mutation-lock family used by target writes. Any workspace addition, deletion, or content change after request invalidates approval.

Git host operations additionally bind Git state obtained through Git. Direct `.git` MCP access remains prohibited.

### Expiry and one-shot semantics

- Pending request expiry is stored in `request_expires_at` and enforced by SQL predicates.
- Separately approved compatibility grants have `approval_expires_at`.
- Local approve-and-run performs approval and `claimed_at` assignment in one transaction.
- Claim predicates require the correct status, future expiry, and `claimed_at IS NULL`.
- The worker rechecks `approval_expires_at` immediately before `subprocess.Popen()`; an expired grant never starts the child process.

## 6. Process lifecycle

Executor creates a random nonce inherited by worker and child. Durable identity contains PID, process creation time, executable path, and nonce. `stop_job` terminates only if all identity fields still match. A mismatch marks the job `interrupted` without killing a process. Server startup reconciles stale queued/running rows the same way.

On Windows, processes use a new process group and no window. On other platforms they use a new session. This is lifecycle control, not an OS sandbox.

## 7. Resource limits and retention

- file read/write/image/directory entry limits;
- pre-replacement backup and streamed diff limits;
- command count/argument/reason limits;
- approval file-count/byte limits;
- stdout/stderr pipes drained by bounded head/tail collectors;
- bounded Git snapshots;
- total `data_dir` quota;
- Safe Tier runtime byte and filesystem-entry quotas, with reparse points, non-regular entries, and NTFS alternate data streams rejected;
- age and terminal-operation-count retention.

Retention deletes only known artifact roots and skips artifacts whose operation is nonterminal.

## 8. Audit

All important MCP boundary actions create operations/events, including rejection before normalization, job poll/stop, approval poll/claim, audit access, timeout, stale identity, lock selection, and startup reconciliation. Secret-like fields are redacted; file content is represented by byte count and SHA. stdout/stderr and full file content are never copied into unbounded audit fields.

### Activity Timeline

`activity_timeline` is a summary projection only: operation/time/tool/type/status, a short command or target, changed-file and line counts, point-in-time rollback/selective-Undo availability, conflict state, network enforcement, and important risk. It never expands unified diffs, output previews, events, or full path lists. `activity_get(operation_id)` is the bounded detail projection for those artifacts and technical fields. The CLI follows the same list/detail split. Reading either view is audited and creates no execution route.

The same projection is available locally with `windows-local-mcp timeline --limit 20` or `windows-local-mcp timeline --operation OPERATION_ID`.

Workspace-mutating operations capture complete pre/post manifests outside the workspace while the existing workspace-wide mutation lock is held. File bytes are stored by SHA-256 in a content-addressed blob store, so unchanged content is not copied for each operation. Manifests still cover created, modified, deleted, untracked, and Git-ignored MCP-writable files. Retention removes operation manifests before garbage-collecting unreferenced blobs.

`request_workspace_rollback` means point-in-time rollback. `request_selective_undo` means remove only one operation's delta. Both create local approval requests, bind an exact preview/current manifest into the request hash, and are recorded as normal mutation operations with before/after state so the rollback or Undo can itself be selectively undone.

Before either mutation writes the workspace, every referenced blob is re-hashed, the current state is checked against the approval preview, and required target bytes are staged. A durable transaction journal records preflight, staging, applying, recovery, and completion. Apply failures automatically attempt restoration of the transaction-start state. A recovered failure is `failed_recovered`; a failed recovery is `recovery_required`. Startup reconciliation surfaces non-terminal journals after process interruption. `complete` is written only after the final workspace hashes match the intended target. This is failure-atomic best effort over multiple files, not a claim of an OS filesystem transaction.

Selective Undo compares operation-before, operation-after, and current content. Exact unchanged results are reverted directly. UTF-8 text uses bounded-context reverse hunks so independent later edits can remain. Ambiguous/overlapping text, changed binary content, and ambiguous file-lifecycle changes stop as conflicts before approval; no guessed overwrite is performed.

### Safe-tier network policy

Every safe command receives an explicit per-command network policy in audit and Timeline. Git/Dart/Flutter safe grammars receive an offline policy; ADB receives a separate loopback-only profile and a fixed loopback server socket. Proxy, package-host, and Git transport environment values remain defense in depth.

The default `appcontainer` mode launches the Safe Tier root with the stable AppContainer `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` mechanism and no Internet/LAN capability SIDs. Descendants inherit the AppContainer token and are placed in a per-operation Job Object with kill-on-close. Offline and ADB-loopback profiles are separate. One-time local setup creates the profiles and ACLs the workspace and explicitly configured toolchain paths; each disposable runtime tree receives its ACL only when launched. Dart workspace formatting runs in that disposable tree and only broker-validated target changes are applied to the real workspace. If profile creation, ACL setup, loopback exemption, Job assignment, or AppContainer process creation fails, Safe Tier fails closed and is not relaunched as a normal user process.

The implementation deliberately uses the documented AppContainer APIs available since Windows 8 instead of the experimental Windows Sandbox `CreateProcessInSandbox` API. Microsoft AppContainer provides token/capability, filesystem-ACL, process/credential, and network isolation; omitting network capability SIDs denies Internet/LAN, while the dedicated ADB profile gets only an explicit loopback exemption. OpenAI's current stronger Codex Windows sandbox instead uses one-time administrator-approved setup with dedicated lower-privilege users, filesystem permissions, firewall rules, and local policy. This project does not claim equivalence with that whole-system setup: AppContainer was selected for a public, per-workspace MCP because it is stable, inherited by descendants, compatible with explicit path ACLs, and normally set up on user-owned paths without running the server as Administrator. Windows 10/11 are the supported project targets; toolchains installed in locations not readable by the AppContainer must be listed in local configuration.

`compatibility` is an explicit legacy mode. It retains grammar/environment controls but is labelled `compatibility-command-and-environment-only`; it is never reported as OS isolation and is not an implicit fallback. AppContainer can reduce toolchain compatibility because required executable/runtime paths need explicit read/execute ACLs. Host-approved commands deliberately continue to run with the real Windows user token after approval.

### Configuration selection and local profiles

An explicit `LOCAL_MCP_CONFIG` must contain `workspace_root` and the selected config file itself must be outside that workspace, so MCP writes cannot downgrade a later worker's security settings. Every queued Safe Tier request also binds the canonical effective-settings digest and the worker rechecks it before launch. A simultaneous `LOCAL_MCP_ROOT` is accepted only when it resolves to the same path; a mismatch fails startup instead of overriding the chosen config. Missing config/workspace paths never fall back. `session_info` reports the effective workspace, capabilities, config selection source, workspace source, and whether an ambient root was present without dumping secret values.

Public code and `config.example.toml` remain generic. Machine/private values belong in ignored `config.toml`, `config.local.toml`, `config.*.local.toml`, or `.local-mcp/`. Launchers keep explicit `-Config` selection; there is no private-project schema switch or private branch requirement.

## 9. data_dir protection

`data_dir` is resolved independently and must not lexically or effectively overlap workspace. Both roots must not be reparse points. On Windows, `protect_data_dir_acl=true` removes inherited ACLs and grants Full Control only to the current token SID and SYSTEM.

ACL cannot distinguish two processes running as the same Windows user. MCP filesystem tools still cannot reach `data_dir` because it is outside workspace, and artifact paths are validated before special retrieval such as ADB screenshots.

## 10. Transport and ownership

Default transport is stdio. Streamable HTTP currently fails closed even when requested because authenticated principal ownership is not yet implemented.

Authenticated multi-principal HTTP is not implemented. Setting `http_multi_principal_enabled=true` fails startup. Therefore no supported configuration exposes globally shared job/approval/audit identifiers to distinct authenticated principals. A future implementation must persist `principal_id` on every operation and include it in every create/get/list/poll/claim/execute/cancel/audit SQL predicate.

## 11. MCP annotations

Annotations describe the real action performed by each model-facing call:

- pure local reads and `execute_readonly`: read-only, non-destructive, closed-world;
- `adb_read`: read-only, non-destructive, closed-world;
- `write_file` and `execute_workspace_write`: non-read-only, destructive, closed-world;
- `request_host_command`: non-read-only, non-destructive, closed-world because it only creates an approval request and cannot launch the host command;
- polls: read-only;
- process-stop controls remain explicitly mutating/destructive where appropriate.

The generic `execute`, `start_command`, and `execute_approved` surfaces are not exposed to MCP clients. This prevents one broad annotation from making read-only Git/analyze calls appear destructive and prevents a second model-facing dangerous execution step after local approval.

Annotations are host hints and never replace server-side enforcement. The ChatGPT/MCP host may still apply its own confirmation policy.
