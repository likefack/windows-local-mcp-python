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

`git_enabled` and `adb_enabled` do not make their broker helpers available by themselves. Automatic helper execution requires an explicit absolute executable path and operator-pinned SHA-256. PATH discovery is not a trust source. Session capability data reports configured, enabled, and available separately.

Dangerous configuration combinations fail startup validation:

- lexical or resolved overlap between `workspace_root` and `data_dir`
- workspace/data root reparse points
- physical overlap among workspace, data, and Sandbox scratch after Windows handle/volume identity resolution
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
3. captures a before checkpoint scoped to the known target path and fsyncs a write-ahead recovery journal before replacement;
4. enforces old/new/diff/backup/data quotas before replacement;
5. writes and fsyncs a same-directory temporary file;
6. revalidates parent `(device,inode)` and target full identity immediately before `os.replace`;
7. verifies and journals the target-scoped after checkpoint, and restores only that declared scope after a detected failure. Interrupted writes are reconciled on startup and unresolved recovery checkpoints are retention-protected.
6. verifies resulting SHA.

Target slots are selected from canonical paths. Known source→destination mutations acquire the deduplicated source and destination slots in deterministic order. Different slots can proceed concurrently; the same path always maps to the same slot, while a hash collision only causes extra serialization. A workspace-wide writer acquires every slot, so it still excludes all target writes.

Ordinary file reads do not take a mutation lock.

### Structured file processing

`structured_file_inspect` and `structured_file_apply` accept only bounded declarative operations. Parsing and transformation happen outside the workspace-wide mutation lock; commit rechecks the raw source hash and applies the artifact through the normal checkpoint, journal, atomic replacement, audit, and recovery path.

DOCX and XLSX use two preservation modes. Documents without detected unsupported package features use the normal document library path. When unsupported package features are present, a narrow package-patch path permits only operations whose effects are confined to known XML parts: DOCX `replace_text` and `metadata_set`; XLSX `cell_set`, `range_set`, and `range_clear`. Every unmodified ZIP member payload and metadata is carried into the output. Digitally signed packages and any operation outside the narrow set fail closed instead of silently discarding features.

CSV/TSV semantic cells plus encoding/BOM/delimiter/newline properties are preserved where determinable. Editing uses a whole-document writer, so original lexical quoting and byte identity are explicitly reported as not preserved after an edit. ZIP paths, collisions, entry count, and expanded size are bounded. Image decoded pixels/memory are bounded, metadata is preserved unless explicitly removed, and unsupported multi-frame transformations fail closed. Image format conversion uses a distinct extension-matched output path with separate source and existing-destination hashes. Generic artifact transfer is byte-exact, chunked, and whole-artifact hash-bound. Downloads read chunks from a verified immutable control-plane snapshot; uploads reserve their full declared size before accepting chunks. Commits use the same broker mutation path, and transfer does not authorize execution.

## 4. Broker-fixed command operations

Automatic broker execution uses complete subcommand grammars, not a first-token allowlist. Unknown flags, positional forms, config/output paths, or unsafe ambiguity are rejected. Open-ended execution and project-controlled code are routed to Codex Sandbox; they are not expanded into another broker policy tier.

The MCP surface is split after the deny-by-default grammar succeeds:

- `execute_readonly`: fixed Git reads only.
- `execute_workspace_write`: retained as a compatibility tool surface, but project-controlled formatting is rejected and directed to Codex Sandbox.
- `adb_read`: only the fixed read-only ADB grammar.

The split is presentation and host-policy metadata, not a second authorization system. All three call the same `CommandPolicy.normalize_safe()` and the same queue/executor path. A command routed to the wrong surface is rejected and directed to the matching tool.

### Git

Automatic subcommands: `status`, `diff`, `log`, `show`, restricted `rev-parse`, and `ls-files`.

- Force no pager; diff/show force `--no-ext-diff --no-textconv`.
- Disallow `-C`, `--git-dir`, `--work-tree`, `--output`, config injection, pager/external helpers, and unknown flags.
- Pathspec is accepted only after `--` and resolved inside workspace.
- Git repository/config override environment variables are removed before Git subprocesses run.
- Git is resolved only from the explicitly configured path/hash identity. The worker revalidates it and holds a Windows read-only-share handle against writes/replacement through process completion.
- `git_info` returns branch, HEAD, status, working diff, staged diff, recent log, and changed files through bounded subprocess capture.

### Project-controlled tools

- Python, Node, PowerShell, Dart, Flutter, project scripts, plugins, tests, builds, and formatting can load project-controlled code or configuration.
- These operations are never broker commands. They require a separately approved Codex Sandbox request.
- An operation that needs real Windows user authority beyond Codex Sandbox requires a new, separately approved Host request; Sandbox failure does not create or approve it.

### ADB

ADB is separately disabled by default. Automatic forms are exact:

- `adb -s SERIAL get-state`
- fixed read-only `getprop`, `wm`, and `dumpsys` forms
- `adb -s SERIAL exec-out screencap -p`

Targeted calls require serial validation. `adb_emulator_only=true` requires an `emulator-*` serial and a successful `adb emu avd name` preflight. Optional `adb_allowed_serials` further narrows targets. General shell and state changes require approval.

Automatic device enumeration is rejected because its raw output can disclose or expand attention to non-allowlisted physical devices. ADB uses the same explicit executable path/hash/identity/hold boundary as Git.

### Execution lock policy

The workspace-wide mutation lock is no longer held for every command for the full child-process lifetime.

- Fixed Git and ADB reads execute without the workspace-wide mutation lock.
- Approved code-loading commands in immutable `staged-cwd` snapshot mode, including test/build-style execution, run without the workspace-wide mutation lock because they execute from `data_dir`, not the original workspace.
- A Codex Sandbox or Approved Host command marked `workspace_write=true`, and approved commands that still execute against the original workspace, keep the exclusive workspace-wide mutation lock through verification and child execution.
- Snapshot/manifest creation may still take the workspace-wide lock briefly so the captured input set is coherent.
- `write_file` uses one target slot rather than all slots, so unrelated file writes can proceed concurrently while still conflicting with workspace-wide writers.
- Old approval rows that do not contain explicit snapshot metadata fail conservatively and keep the workspace-wide lock.

This permits long-running isolated tests/builds, read-only analysis, and unrelated target writes to overlap without weakening the source-write boundary.

## 5. Approval and immutable execution

Preferred flows:

```text
request_sandbox_command | request_host_command
  -> pending immutable manifest with request TTL
  -> local UI verifies and atomically approve+claims
  -> MCP worker runs fixed content once in the selected boundary
  -> ChatGPT poll_approval / poll_job
```

`request_sandbox_command` selects Codex Sandbox; `request_host_command` selects Approved Host. Both only stage local approval state and immutable inputs. There is no implicit Codex Sandbox to Approved Host fallback and no model-facing `execute_approved` tool.

Approval binding version 3 hashes the complete canonical security-sensitive request, including execution boundary, normalized command/cwd, executable identity, workspace-write and runtime limits, escalation facts, risk, immutable manifest fields, effective policy, and Codex Sandbox backend identity. The manifest covers:

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

Protected file names and generated/dependency trees such as `.venv`, `node_modules`, `build`, and `__pycache__` are excluded from ordinary staging. An exclusion is not treated as an OS read-denial property: execution remains unavailable unless current-backend live evidence independently verifies direct protected-information denial and source/outside-user filesystem boundaries for descendants as well as the initial process.

The immutable copy is verified after local approval. The worker then creates a separate writable disposable run copy, so build artifacts cannot mutate the approved input copy. Unrelated workspace changes outside the approved `cwd` do not invalidate snapshot execution. Snapshot-backed child execution does not hold the workspace-wide mutation lock.

Installed OS/toolchains are the trusted computing base. Their primary executable is content-bound. Complete OS DLL/toolchain virtualization is not provided.

### Source-write mode

Commands intended to mutate the original workspace require `workspace_write=true`. The complete workspace (excluding direct `.git` bytes) is manifested, all source files are revalidated, and execution occurs while holding the workspace-wide form of the same mutation-lock family used by target writes. Any workspace addition, deletion, or content change after request invalidates approval.

Git Host operations additionally bind Git state obtained through the fixed broker Git reader. Direct `.git` MCP access remains prohibited.

### Expiry and one-shot semantics

- Pending request expiry is stored in `request_expires_at` and enforced by SQL predicates.
- Claimed one-shot execution grants have `approval_expires_at`.
- Local approve-and-run performs approval and `claimed_at` assignment in one transaction.
- Claim predicates require the correct status, future expiry, and `claimed_at IS NULL`.
- The worker rechecks `approval_expires_at` immediately before `subprocess.Popen()`; an expired grant never starts the child process.

## 6. Process lifecycle

Executor creates a random nonce inherited by worker and child. Durable identity contains PID, process creation time, executable path, and nonce. `stop_job` terminates only if all identity fields still match. A mismatch marks the job `interrupted` without killing a process. Server startup reconciles stale queued/running rows the same way.

On Windows, both Approved Host and Codex Sandbox parents are launched suspended, assigned to a per-operation Windows Job Object, and resumed only after assignment. Approved Host uses the Job for kill-on-close and descendant-lifecycle accounting; after the Job reports zero active descendants, it also waits for newly observed same-user processes relative to a pre-launch process baseline before control-plane postflight. This closes the WMI `Win32_Process.Create` path, whose process is outside the per-operation Job. An unenumerable or still-running same-user process fails the Approved Host postflight closed. A descendant that outlives the operation deadline is terminated with the complete Job and the operation times out. Codex Sandbox additionally enforces active-process and aggregate committed-memory limits over the complete launcher/command descendant tree. On other platforms processes use a new session. Process groups/sessions alone are lifecycle control, not an OS sandbox.

Every normalized Approved Host or Sandbox target executable is identity-bound. Immediately before launch, the worker verifies path/hash/device/inode/size/mtime and, on Windows, keeps a FILE_SHARE_READ-only handle open through child completion so same-user replacement or in-place writes fail.

## 7. Resource limits and retention

- file read/write/image/directory entry limits;
- pre-replacement backup and streamed diff limits;
- command count/argument/reason limits;
- approval file-count/byte limits;
- stdout/stderr pipes drained by bounded head/tail collectors;
- bounded Git snapshots;
- total `data_dir` quota;
- Codex Sandbox staging/runtime byte and filesystem-entry quotas, with reparse points, non-regular entries, and NTFS alternate data streams rejected;
- a per-Codex-Sandbox Windows Job Object active-process limit and aggregate committed-memory limit, both bound into the approved backend identity;
- age and terminal-operation-count retention.

Retention deletes only known artifact roots and skips artifacts whose operation is nonterminal.

## 8. Audit

All important MCP boundary actions create operations/events, including rejection before normalization, job poll/stop, approval poll/claim, audit access, timeout, stale identity, lock selection, and startup reconciliation. Secret-like fields are redacted; file content is represented by byte count and SHA. stdout/stderr and full file content are never copied into unbounded audit fields.

### Activity Timeline

`activity_timeline` is a summary projection only: operation/time/tool/type/status, a short command or target, changed-file and line counts, point-in-time rollback/selective-Undo availability, conflict state, network enforcement, and important risk. It never expands unified diffs, output previews, events, or full path lists. `activity_get(operation_id)` is the bounded detail projection for those artifacts and technical fields. The CLI follows the same list/detail split. Reading either view is audited and creates no execution route.

The same projection is available locally with `windows-local-mcp timeline --limit 20` or `windows-local-mcp timeline --operation OPERATION_ID`.

Workspace-mutating operations record an explicit checkpoint scope. Known-target broker operations capture only the declared target paths; arbitrary or not-yet-closed output sets retain a complete workspace scope. Restore, conflict detection, post-apply verification, recovery, Timeline, and Undo use the same recorded scope. This preserves unrelated concurrent changes without weakening race detection for any in-scope path. File bytes are stored by SHA-256 in a content-addressed blob store, and retention removes operation manifests before garbage-collecting unreferenced blobs.

`request_workspace_rollback` means point-in-time rollback. `request_selective_undo` means remove only one operation's delta. Both create local approval requests, bind an exact preview/current manifest into the request hash, and are recorded as normal mutation operations with before/after state so the rollback or Undo can itself be selectively undone.

Before either mutation writes the workspace, every referenced blob is re-hashed, the current state is checked against the approval preview, and required target bytes are staged. A durable transaction journal records preflight, staging, applying, recovery, and completion. Apply failures automatically attempt restoration of the transaction-start state. A recovered failure is `failed_recovered`; a failed recovery is `recovery_required`. Startup reconciliation surfaces non-terminal journals after process interruption. `complete` is written only after the final workspace hashes match the intended target. This is failure-atomic best effort over multiple files, not a claim of an OS filesystem transaction.

Selective Undo compares operation-before, operation-after, and current content. Exact unchanged results are reverted directly. UTF-8 text uses bounded-context reverse hunks so independent later edits can remain. Ambiguous/overlapping text, changed binary content, and ambiguous file-lifecycle changes stop as conflicts before approval; no guessed overwrite is performed.

### Broker helper network policy

Every fixed broker helper receives an explicit per-command network policy in audit and Timeline. Git receives an offline policy. ADB receives a loopback-only requested profile and the fixed `ADB_SERVER_SOCKET=tcp:127.0.0.1:5037` environment. These broker restrictions and sanitized environment are not represented as a fifth OS sandbox or policy tier.

### Execution boundary policy

1. `broker`: closed-world file, fixed Git-read, fixed ADB-read, checkpoint, transaction, rollback, and audit operations.
2. `structured_processing`: declarative DOCX/XLSX/CSV/TSV/ZIP/image processing and hash-bound artifact commit.
3. `codex_sandbox`: open-ended or project-controlled execution after one-shot local approval.
4. `approved_host`: real Windows user authority after a separate one-shot local approval.

Legacy Safe Tier, AppContainer, and compatibility-mode configuration is obsolete and fails startup. Codex Sandbox failure never falls back to Approved Host. Ordinary non-zero exit, test failure, compile/lint failure, and application error remain failures in the selected boundary.

Codex Sandbox uses the installed Codex CLI sandbox-only entrypoint with `windows.sandbox="elevated"`. WLMCP supplies an explicit managed sandbox-state containing restricted filesystem entries, protected-name deny patterns, explicit source/dependency/scratch roots, and restricted network state; it also requests direct-network disable. The launcher plus adjacent command-runner and sandbox-setup helper form the minimum executable dependency closure: each must be validly Authenticode-signed by OpenAI, is path/hash/stat/signer-bound, revalidated after approval, and held against replacement through the child lifetime. Host-side launcher cwd is the trusted install directory, and relative, workspace, data, and scratch PATH entries are removed before launch. The launcher is assigned to a bounded Windows Job Object before its initial thread is resumed. The elevated WFP Guard channel accepts read-back evidence only when the process represented by the handle returned from `runas` is the fixed `.venv\Scripts\python.exe` venv launcher, and the named-pipe client PID reported by Windows is that launcher or its direct child whose executable is the corresponding `sys.base_prefix\python.exe` base interpreter. A matching parent PID without these executable-path checks is not accepted; the channel does not depend on environment inheritance across UAC. Then `codex --version` is recorded and the fixed command is launched through `codex sandbox`. This does not start a Codex agent, send a prompt, authenticate with OpenAI, or perform model/API inference. Read-only code-loading commands operate on an immutable staged copy; source-write commands require `workspace_write=true`, a full manifest, and the workspace mutation lock.

Policy input acceptance is not equivalent to a verified boundary. Live evidence version 3 records `filesystem_read`, `filesystem_write`, `protected_information_read`, `internet`, `lan`, `loopback`, `descendant_containment`, `termination`, and `resource_bound` separately as `verified`, `failed`, or `unverified`. `failed` requires an executed probe to observe a boundary escape; launch failure, timeout, listener or probe setup failure, and other diagnostic inability are `unverified`. Descendant containment individually measures source-write, outside-user read, protected-information read, control-plane read/write, Internet, LAN, and loopback for child and grandchild. Resource verification exceeds both Job limits and proves violation reporting, safe termination, zero remaining descendants, and WLMCP exit-state collection. Old evidence, evidence with a different `isolation_context_digest`, and partially verified property sets are rejected. The isolation context binds the installed launcher/helper identities, physical roots, protected names and directories, dependency-readable paths, policy generations, scratch quota, and process/memory limits. Session status keeps dependency/startup `available`, aggregate `windows_live_verified`, and policy-gated `execution_route_available` separate. The latter two become true only when every required property is verified for the exact backend and isolation context. Local configuration cannot disable this requirement, and failure never creates an Approved Host fallback.

The selected distribution mode is installed-Codex dependency. It reuses upstream's CLI/setup helper/command runner/security update chain without copying Windows sandbox internals into this repository. Apache-2.0 permits a future standalone distribution, but safely redistributing the coordinated binaries, versioned policy/protocol, setup behavior, signing, notices, and update channel is deferred. Missing CLI, incomplete UAC setup, incompatible backend, initialization/policy/launch failure, or timeout fails closed. Host execution requires a new `approved_host` request.

The WFP Guard resolves the fixed `CodexSandboxOffline` target with this PC's computer name as the account qualifier. It accepts the result only when the returned referenced domain matches this PC's physical NetBIOS name and `SID_NAME_USE` is `SidTypeUser` (`1`); otherwise the Codex Sandbox route fails closed.

### Configuration selection and local profiles

An explicit `LOCAL_MCP_CONFIG` must contain `workspace_root` and the selected config file itself must be outside that workspace, so MCP writes cannot downgrade a later worker's security settings. Every queued command request binds the canonical effective-settings digest and the worker rechecks it before launch. A simultaneous `LOCAL_MCP_ROOT` is accepted only when it resolves to the same path; a mismatch fails startup instead of overriding the chosen config. Missing config/workspace paths never fall back. `session_info` reports the effective workspace, capabilities, config selection source, workspace source, and whether an ambient root was present without dumping secret values.

Public code and `config.example.toml` remain generic. Machine/private values belong in ignored `config.toml`, `config.local.toml`, `config.*.local.toml`, or `.local-mcp/`. Launchers keep explicit `-Config` selection; there is no private-project schema switch or private branch requirement.

## 9. data_dir protection

`data_dir` and Sandbox scratch are resolved independently and must not lexically or effectively overlap workspace or each other. Roots must not be reparse points. On Windows, handle-resolved volume-GUID paths and stable file identities also reject aliases such as SUBST that identify the same or nested physical namespace. `protect_data_dir_acl=true` removes inherited ACLs and grants Full Control only to the current token SID and SYSTEM.

ACL cannot distinguish two processes running as the same Windows user. MCP filesystem tools still cannot reach `data_dir` because it is outside workspace, and artifact paths are validated before special retrieval such as ADB screenshots.

## 10. Transport and ownership

Default transport is stdio. Streamable HTTP currently fails closed even when requested because authenticated principal ownership is not yet implemented.

`session_info.transport` reports stdio and HTTP independently with configured/enabled/available and startup-validation state; it does not describe rejected HTTP as optional or available.

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
