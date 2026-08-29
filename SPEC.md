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

`adb_enabled` does not make its broker helper available by itself. Automatic ADB helper execution requires an explicit absolute executable path and operator-pinned SHA-256. PATH discovery is not a trust source.

`git_enabled` also does not make Automatic Git available by itself. Automatic Git requires an explicit Git path/hash identity, the current generic Codex Sandbox live evidence, every Sandbox security property verified for the stricter Automatic Git policy, and an exact Git-specific live marker produced by `verify-git-broker`. The marker is bound to the Git identity, Sandbox/backend evidence, workspace, configured scratch quota, containment-policy generation v6, Automatic Git command-policy generation v5, trusted process-cwd/fixed-`-C` policy, exact projection ownership-trust policy, sanitized `core.autocrlf` semantics, and required-builtin policy. `git_info` / `execute_readonly` remain public surfaces regardless of current availability, so session capability data must keep configured, enabled, available, and Windows-live-verified separate. A missing, failed, or stale Git-specific marker is a fail-closed unavailable state, not a reason to run a weaker Git child.

`approved_host_enabled` expresses configuration intent but does not by itself make Approved Host available. Production execution additionally requires an immutable Program Files runtime and a healthy authenticated LocalSystem authority service. The monitor/postflight worker runs as LocalSystem while the final command uses the verified non-elevated requester token. Pending/approved rows never bypass this authority gate, and same-desktop UAC elevation is not accepted as the security boundary. WLMCP-R2-001 completed its required normal/abnormal/recovery Windows live lifecycle on 2026-08-28; current-machine execution availability still requires the runtime and authority preflight to pass.

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
- Keep `.git` directly unreadable/unwritable through ordinary filesystem Broker tools. Automatic Git state tools use only a bounded sanitized disposable repository projection; they do not grant ordinary Broker filesystem access to live `.git`.
- `list_directory` は検証済み parent directory の child 名だけを列挙し、entry type は target を追跡しない metadata で判定します。symlink／junction／その他の reparse entry は `reparse` として返し、Broker 権限で target の種類や到達可能性を確認しません。

`write_file` additionally:

1. takes a target-scoped cross-process mutation slot plus the canonical-target thread lock;
2. re-resolves target and reads/checks expected SHA inside the locks;
3. captures a before checkpoint scoped to the known target path and fsyncs a write-ahead recovery journal before replacement;
4. enforces old/new/diff/backup/data quotas before replacement;
5. writes and fsyncs a same-directory temporary file;
6. revalidates parent `(device,inode)` and target full identity immediately before `os.replace`;
7. verifies and journals the target-scoped after checkpoint, and restores only that declared scope after a detected failure. Interrupted writes are reconciled on startup and unresolved recovery checkpoints are retention-protected.
8. verifies resulting SHA.

Target slots are selected from canonical paths. Known source→destination mutations acquire the deduplicated source and destination slots in deterministic order. Different slots can proceed concurrently; the same path always maps to the same slot, while a hash collision only causes extra serialization. A workspace-wide writer acquires every slot, so it still excludes all target writes.

Ordinary file reads do not take a mutation lock.

### Structured file processing

`structured_file_inspect` and `structured_file_apply` accept only bounded declarative operations. Parsing and transformation happen outside the workspace-wide mutation lock; commit rechecks the raw source hash and applies the artifact through the normal checkpoint, journal, atomic replacement, audit, and recovery path.

DOCX and XLSX use two preservation modes. Documents without detected unsupported package features use the normal document library path. When unsupported package features are present, a narrow package-patch path permits only operations whose effects are confined to known XML parts: DOCX `replace_text` and `metadata_set`; XLSX `cell_set`, `range_set`, and `range_clear`. Every unmodified ZIP member payload and metadata is carried into the output. Digitally signed packages and any operation outside the narrow set fail closed instead of silently discarding features.

CSV/TSV semantic cells plus encoding/BOM/delimiter/newline properties are preserved where determinable. Editing uses a whole-document writer, so original lexical quoting and byte identity are explicitly reported as not preserved after an edit. ZIP paths, collisions, entry count, and expanded size are bounded. Image decoded pixels/memory are bounded, metadata is preserved unless explicitly removed, and unsupported multi-frame transformations fail closed. Image format conversion uses a distinct extension-matched output path with separate source and existing-destination hashes. Generic artifact transfer is byte-exact, chunked, and whole-artifact hash-bound. Downloads read chunks from a verified immutable control-plane snapshot; uploads reserve their full declared size before accepting chunks. Commits use the same broker mutation path, and transfer does not authorize execution.

## 4. Broker-fixed command operations

Automatic broker execution uses complete subcommand grammars, not a first-token allowlist. Unknown flags, positional forms, config/output paths, or unsafe ambiguity are rejected. Open-ended execution and project-controlled code are routed to Codex Sandbox; they are not expanded into another broker policy tier.

The MCP surface is split after the deny-by-default grammar succeeds:

- `execute_readonly`: narrow read-only command surface. Fixed metadata-only Git reads use the dedicated Automatic Git Broker worker only when Git-specific live verification is current.
- `execute_workspace_write`: retained as a compatibility tool surface, but project-controlled formatting is rejected and directed to Codex Sandbox.
- `adb_read`: only the fixed read-only ADB grammar.

The split is presentation and host-policy metadata, not a second authorization system. All candidate commands pass `CommandPolicy.normalize_safe()`. Git is then deliberately routed away from the normal Broker worker into the dedicated Git Broker worker; there is no unrestricted `subprocess.Popen()` fallback for Git. A command routed to the wrong surface is rejected and directed to the matching tool.

### Automatic Git Broker

Automatic Git is a Broker primitive, not a fifth policy tier. Its candidate grammar is limited to `status`, metadata-only `diff`, `log`, metadata-only `show`, restricted `rev-parse`, and `ls-files`.

Controls required for every Automatic Git operation:

- Force no pager; diff/show force `--no-ext-diff --no-textconv`.
- Disallow user-controlled `-C`, `--git-dir`, `--work-tree`, `--output`, config injection, pager/external helpers, and unknown flags. The Broker may insert its own fixed `-C <sanitized projection cwd>` and command-scope security configuration.
- `diff`／`show` are metadata-only. `--patch`, `-p`, `--binary`, `--check`, and pathspec forms that would otherwise imply patch/body output are not Automatic Git operations and are directed to `request_sandbox_command`.
- A current workspace path that passes Broker path validation is not evidence that a blob reached through a tree, commit, or index is provenance-safe. An attacker can attach protected historical blob bytes to a safe-looking path. Therefore no Automatic Git mode may materialize object-backed file bodies merely because the path looks allowed.
- User-supplied `diff`／`show` revisions are forced through `^{commit}` and both endpoints of a revision range are commit-bound as defense-in-depth. Commit binding is not treated as a substitute for the metadata-only output boundary.
- Pathspec is accepted only after `--`, only for explicit metadata-only forms, and resolved inside workspace; absolute workspace operands are rewritten to the disposable projection before launch.
- Git repository/config override environment variables are removed. Raw system/global Git config and system attributes are disabled in the child. Credential prompting, optional locking, and Git protocol access are disabled. The Broker reconstructs only the trusted scalar `core.autocrlf` semantics required for working-tree status/diff behavior.
- Git is resolved only from the explicitly configured path/hash identity. The worker revalidates it and holds a Windows FILE_SHARE_READ-only handle against writes/replacement through process completion.
- The live repository is never the Git child filesystem. Broker creates `sandbox_scratch_dir/git-broker/<operation>/repository`, verifies bounded size/entry count, rejects reparse/ADS/hardlink/external gitdir/commondir/config.worktree/object-alternate forms, and removes project-controlled hooks, modules, `.gitattributes`, and `.git/info/attributes`.
- Source `.git/config` raw bytes are read through a verified Broker handle and parsed in trusted memory. Raw config is not written to scratch. The projection emits only inert `core.repositoryformatversion=0`, `filemode`, `bare=false`, `logallrefupdates`, `ignorecase`, and normalized `autocrlf` values. Repository extensions are rejected. A direct repository-local `core.autocrlf` scalar overrides the inherited trusted scalar with normal precedence.
- Trusted inherited `core.autocrlf` is limited to `true`, `false`, or `input` and is resolved from trusted Git-for-Windows config locations without exposing those raw files to the sandbox child. include/includeIf semantics, invalid scalar values, config paths overlapping workspace/`data_dir`/scratch, and unsupported runtime/config layouts fail closed rather than broadening child config access.
- Git repository ownership trust is command-scoped to `safe.directory=<exact operation projection>`. Automatic Git does not use `safe.directory=*`, does not trust the source workspace or scratch parent, and does not persist a global `safe.directory` change.
- Protected worktree paths such as `.env`/configured blocked names are not copied into the projection.
- Repository projection bytes are limited to at most half of configured `max_sandbox_scratch_bytes`, leaving the remaining scratch budget for operation runtime/transient output. The implementation does not introduce a hard-coded repository-size floor that can exceed the configured quota. Entry count is enforced during the copy itself as well as preflight/post-copy scanning so concurrent directory growth cannot amplify an unbounded scratch tree before final validation.
- The child runs through the installed Codex Windows Sandbox containment engine with original `workspace_root` and `data_dir` denied, only the disposable Git operation root writable, direct network disabled, WFP loopback guard verified, Windows Job process/memory/kill-on-close limits active, and brokered `Win32_Process.Create` denial rechecked.
- Generic Codex Sandbox residual-risk acceptance does not authorize Automatic Git. Every security property (`filesystem_read`, `filesystem_write`, `protected_information_read`, `internet`, `lan`, `loopback`, `descendant_containment`, `termination`, `resource_bound`) must be `verified`.
- Git-specific live marker schema v1 binds pinned Git identity, current Sandbox backend, current generic live-evidence digest, containment-policy generation v6, workspace, configured scratch quota, command-policy generation v5, trusted process-cwd/fixed-`-C`, exact projection ownership trust, sanitized EOL semantics, and required-builtin policy. `verify-git-broker` runs real pinned Git under the same containment, requires worktree recognition and read-only `status` to succeed under strict source-workspace deny, and requires the probe batch to remain bound to one valid sanitized-projection snapshot digest before atomically issuing the marker. User-facing `--show-toplevel` path remapping is not treated as independent projection proof.
- Normal operations never create or silently repair the Git-specific marker. The dedicated worker and direct `git_info` runner path recheck it immediately before Git execution.
- Sandbox/marker failure never falls back to the normal Broker worker or Approved Host.

`git_info` batches its fixed snapshot commands through this same runner. Its snapshot is limited to branch/HEAD/status, diff/staged stat or name-status, recent log metadata, and changed-file metadata; it does not intentionally emit blob bodies. `execute_readonly` Git commands queue the same dedicated worker. Thus both public Git surfaces converge on one containment primitive.

### Project-controlled tools

- Python、Node、PowerShell、Dart、Flutter、project scripts、plugins、tests、builds、formatting 等の project-controlled code-loader は Codex Sandbox 専用です。
- Codex Sandbox は original `workspace_root` を通常の project filesystem capability として渡さず、承認時に bounded な workspace projection を snapshot 化し、実行時は operation 固有の writable run copy を使用します。source workspace deny は defense-in-depth として要求・検証しますが、workspace 内 protected-information direct read の完全遮断は general Codex Sandbox current v1 の保証に含めません。この residual-risk allowance は Automatic Git には適用しません。
- trusted toolchain executable と `sandbox_dependency_readable_paths` で明示した workspace／data／scratch 外 dependency だけを追加 read root として許可します。
- Approved Host は project-controlled code-loader と workspace 内 executable を Host request で拒否します。eligible non-project-controlled Host command は LocalSystem monitor／requester-user child boundary を満たす場合だけ separate approval 後に実行でき、Sandbox failure からの fallback はありません。

### ADB

ADB is separately disabled by default. Automatic forms are exact:

- `adb -s SERIAL get-state`
- fixed read-only `getprop`, `wm`, and `dumpsys` forms
- `adb -s SERIAL exec-out screencap -p`

Targeted calls require an explicitly configured non-empty `adb_allowed_serials`; an empty list authorizes no targets and fails closed. `adb_emulator_only=true` additionally requires an `emulator-*` serial and a successful `adb emu avd name` preflight. A target must satisfy both the explicit allowlist and the emulator validation. General shell and state changes require approval.

Automatic device enumeration is rejected because its raw output can disclose or expand attention to non-allowlisted physical devices. ADB uses an explicit executable path/hash/identity/hold boundary.

### Execution lock policy

Approved execution は承認時 snapshot の整合性確保と Broker mutation の defense-in-depth のため workspace-wide mutation lock を使用します。Codex Sandbox は snapshot/run projection と source-workspace deny policy により live workspace 参照を避け、一般 source canary の read/write denial を route の必須境界として検証します。ただし workspace 内 protected information の direct read denial は general Codex Sandbox current installed backend で完全保証できないため、別 property として実測結果を保持する受容済み残存 risk です。

- snapshot／manifest 作成は workspace-wide lock 下で coherent input set を取得します。
- Approved Sandbox は実行前 binding 検証から child／descendant 終了まで workspace-wide Broker mutation lock を保持します。
- Automatic Git は live workspace を child に渡さず disposable projection を作成するため、Git child の filesystem capability と live workspace mutation serialization を分離します。snapshot 作成中の source path validation は Windows handle pinning/reparse/hardlink/ADS checks を通します。
- Approved Host は同じ workspace-wide lock／manifest binding を維持し、LocalSystem worker が verified postflight 完了まで security-critical control interval を所有します。
- `write_file` は target slot を使用するため、workspace-wide approved execution と必ず競合します。

## 5. Approval and immutable execution

Preferred Sandbox flow:

```text
request_sandbox_command
  -> pending immutable manifest with request TTL
  -> local UI verifies and atomically approve+claims
  -> MCP worker runs fixed content once in Codex Sandbox
  -> ChatGPT poll_approval / poll_job
```

Automatic Git does not use this human-approval flow; it uses its fixed Broker grammar plus the stricter Git-specific live-verification gate described above.

`request_host_command` stages a separate local one-shot approval and immutable input binding. After local approve-and-claim, eligible Host operations execute only through the authenticated LocalSystem authority service. Upgrade-existing queued/approved rows still pass current control-plane generation, immutable manifest, executable identity, TTL, requester identity, runtime immutability, and authority-health checks before any SYSTEM worker or requester-user child launch. There is no implicit Codex Sandbox to Approved Host fallback and no model-facing `execute_approved` tool.

Approval binding version 3 hashes the complete canonical security-sensitive request, including execution boundary, normalized command/cwd, executable identity, workspace-write and runtime limits, escalation facts, risk, immutable manifest fields, effective policy, and Codex Sandbox backend identity. The manifest covers:

- main executable bytes and filesystem identity;
- complete argv;
- effective Settings digest;
- relevant environment digest;
- every regular file in the MCP-influenceable execution scope;
- external regular-file operands where complete binding is possible;
- Dart/Flutter package closure resolved from `package_config.json`;
- bounded Git repository metadata state for human-approved Git operations.

### Snapshot mode

Codex Sandbox の open-ended execution は program 名の allowlist に依存せず、原則として bounded な workspace-wide snapshot projection から実行します。projection は original workspace の相対 layout と requested cwd を保持し、worker は immutable projection の検証後、operation 固有の writable `runs/<operation>/workspace` へ materialize します。

- original `workspace_root` は Sandbox filesystem policy で parent／child／grandchildから read／write deny を要求する。一般 source canary の denial は route の必須検証だが、workspace 内 protected-information direct read は general Sandbox の別の受容済み残存 risk として扱う。
- workspace-relative argv は snapshot/run projection へ書き換える。source absolute path が code 本文に残っていても live workspace を参照しないよう deny policy を要求するが、general Sandbox の workspace 内 protected information secrecy まで保証したとは扱わない。
- `.git`、`.env` 等の protected file、`.venv`、`node_modules`、`build`、`__pycache__` は ordinary snapshot へ自動追加しない。
- Dart／Flutter の file package dependency は既存の bounded dependency staging と package-config rewrite を維持する。
- trusted toolchain primary executable は workspace／data／scratch 外に置き、明示的 external dependency もこれら protected root と重ならないことを設定時と policy construction 時に検査する。
- file count、byte count、scratch quota、reparse／hardlink／ADS 等の既存 bound を越える projection は fail closed にする。

Sandbox filesystem policy generation の変更は live-verification context digest を変更し、旧 marker を stale にします。新 policy では `source_workspace_read_denied` と protected-information denial を親・child・grandchildで実測します。一般 source-workspace read/write denial は必須 route 境界ですが、`protected_information_read` と対応する child／grandchild protected-information denial は LAN と同様に general Sandbox の受容済み残存 risk として結果を保持し、失敗または未検証だけでは general route を unavailable にしません。Automatic Git はこの例外を使用しません。

### Source-write mode

Codex Sandbox の `workspace_write=true` も original workspace 上では実行しません。同じ full snapshot projection の writable run copy を処理し、終了後に bounded output tree を検査して workspace-relative delta を抽出します。Broker は承認時 source binding と workspace-wide lock を保持したまま transaction／commit-time validation を通して delta を original workspace へ反映します。source workspace の追加・削除・content change が approval 後に発生した場合は commit 前に fail closed します。

Approved Host の non-project-code-loader path は Codex Sandbox と同じ source-read isolation を暗黙に主張しません。LocalSystem monitor／durable state／requester-user child authority boundary と one-shot immutable approval contract を満たす場合だけ実行します。

### Expiry and one-shot semantics

- Pending request expiry is stored in `request_expires_at` and enforced by SQL predicates.
- Claimed one-shot execution grants have `approval_expires_at`.
- Local approve-and-run performs approval and `claimed_at` assignment in one transaction.
- Claim predicates require the correct status, future expiry, and `claimed_at IS NULL`.
- The approved-operation worker rechecks `approval_expires_at` immediately before its child launch; an expired grant never starts the child process.
- Approved Host additionally rechecks immutable runtime, current control-plane generation, approval binding, authenticated authority health, requester process identity, and durable authority state before launch; old approved rows do not bypass current security gates.

## 6. Process lifecycle

Executor creates a random nonce inherited by worker and child. Durable identity contains PID, process creation time, executable path, and nonce. `stop_job` terminates only if all identity fields still match. A mismatch marks the job `interrupted` without killing a process. Server startup reconciles stale queued/running rows the same way, except an active Approved Host operation currently owned by the authority service is not incorrectly reconciled away.

Automatic Git queued operations are routed to `git_broker_worker` from `Executor.launch()` only after the normalized command is identified as `program_key=git`. That worker revalidates the original safe request, effective settings, control-plane generation, pinned Git identity, and Git-specific live marker before launching the sandboxed Git child. It never invokes the general Broker worker as a fallback.

Approved Host workers are launched only by the authenticated LocalSystem authority service. The SYSTEM worker owns the Job Object, requester-user process census, postflight, durable active/recovery state, and final completion proof. The final command runs under the verified non-elevated requester token. Runtime-user `stop_job` cannot terminate an active authority-owned Host monitor, and stale/already-approved operations cannot bypass runtime immutability, generation, approval, requester identity, or authority-health gates.

On Windows, Codex Sandbox parents are launched suspended, assigned to a per-operation Windows Job Object, and resumed only after assignment. A descendant that outlives the operation deadline is terminated with the complete Job and the operation times out. Codex Sandbox enforces active-process and aggregate committed-memory limits over the complete launcher/command descendant tree. WMI/CIM brokered process creation is separately denied and live-verified because a provider-created process could otherwise be outside this Job. On other platforms processes use a new session. Process groups/sessions alone are lifecycle control, not an OS sandbox.

Every normalized Sandbox target executable is identity-bound. Automatic Git additionally pins the operator-configured Git executable identity. Approved Host uses the immutable runtime plus approval-bound target identity and revalidates the relevant execution inputs before the authority service launches the requester-user child. Replacement protection remains held for the applicable child lifetime.

## 7. Resource limits and retention

- file read/write/image/directory entry limits;
- pre-replacement backup and streamed diff limits;
- command count/argument/reason limits;
- approval file-count/byte limits;
- stdout/stderr pipes drained by bounded head/tail collectors;
- bounded Automatic Git repository projection and output capture; repository projection is at most half of configured Sandbox scratch quota;
- bounded broker snapshots and approval metadata inventories;
- total `data_dir` quota;
- Codex Sandbox staging/runtime byte and filesystem-entry quotas, with reparse points, non-regular entries, and NTFS alternate data streams rejected;
- per-operation Windows Job Object active-process and aggregate committed-memory limits; Automatic Git uses a tighter cap bounded by the verified backend limits;
- Approved Host deadline, Job descendant, requester-user process-census, and durable recovery bounds;
- age and terminal-operation-count retention.

Retention deletes only known artifact roots and skips artifacts whose operation is nonterminal.

## 8. Audit

All important MCP boundary actions create operations/events, including rejection before normalization, job poll/stop, approval poll/claim, audit access, timeout, stale identity, lock selection, startup reconciliation, Automatic Git dedicated-worker start/finish, Git live-marker recheck, Approved Host authority preflight/launch, postflight, and recovery transitions. Secret-like fields are redacted; file content is represented by byte count and SHA. stdout/stderr and full file content are never copied into unbounded audit fields.

### Activity Timeline

`activity_timeline` is a summary projection only: operation/time/tool/type/status, a short command or target, changed-file and line counts, point-in-time rollback/selective-Undo availability, conflict state, network enforcement, and important risk. It never expands unified diffs, output previews, events, or full path lists. `activity_get(operation_id)` is the bounded detail projection for those artifacts and technical fields. The CLI follows the same list/detail split. Reading either view is audited and creates no execution route.

The same projection is available locally with `windows-local-mcp timeline --limit 20` or `windows-local-mcp timeline --operation OPERATION_ID`.

Workspace-mutating operations record an explicit checkpoint scope. Known-target broker operations capture only the declared target paths; arbitrary or not-yet-closed output sets retain a complete workspace scope. Restore, conflict detection, post-apply verification, recovery, Timeline, and Undo use the same recorded scope. This preserves unrelated concurrent changes without weakening race detection for any in-scope path. File bytes are stored by SHA-256 in a content-addressed blob store, and retention removes operation manifests before garbage-collecting unreferenced blobs.

`request_workspace_rollback` means point-in-time rollback. `request_selective_undo` means remove only one operation's delta. Both create local approval requests, bind an exact preview/current manifest into the request hash, and are recorded as normal mutation operations with before/after state so the rollback or Undo can itself be selectively undone.

Before either mutation writes the workspace, every referenced blob is re-hashed, the current state is checked against the approval preview, and required target bytes are staged. A durable transaction journal records preflight, staging, applying, recovery, and completion. Apply failures automatically attempt restoration of the transaction-start state. A recovered failure is `failed_recovered`; a failed recovery is `recovery_required`. Startup reconciliation surfaces non-terminal journals after process interruption. `complete` is written only after the final workspace hashes match the intended target. This is failure-atomic best effort over multiple files, not a claim of an OS filesystem transaction.

Selective Undo compares operation-before, operation-after, and current content. Exact unchanged results are reverted directly. UTF-8 text uses bounded-context reverse hunks so independent later edits can remain. Ambiguous/overlapping text, changed binary content, and ambiguous file-lifecycle changes stop as conflicts before approval; no guessed overwrite is performed.

### Broker helper network policy

Automatic Git receives no network capability. The disposable Git child runs through the Codex restricted-network state plus the current WFP loopback guard and requires every network property, including LAN, to be `verified` in Git-specific live verification. `GIT_ALLOW_PROTOCOL` is cleared and credential prompting is disabled as defense-in-depth; these environment controls are not substitutes for the OS boundary.

ADB receives a loopback-only requested profile and the fixed `ADB_SERVER_SOCKET=tcp:127.0.0.1:5037` environment. Broker helper restrictions and sanitized environment are not represented as a fifth policy tier.

### Execution boundary policy

1. `broker`: closed-world file, Automatic Git fixed metadata read, fixed ADB-read, checkpoint, transaction, rollback, and audit operations. Automatic Git internally borrows the live-verified Codex Windows containment engine but remains a Broker primitive with stricter Git-specific availability gates.
2. `structured_processing`: declarative DOCX/XLSX/CSV/TSV/ZIP/image processing and hash-bound artifact commit.
3. `codex_sandbox`: open-ended or project-controlled execution after one-shot local approval.
4. `approved_host`: separate one-shot approval route using a LocalSystem monitor/postflight authority and ordinary non-elevated requester-user command token; unavailable unless current immutable-runtime and authenticated-authority preflight both pass.

Legacy Safe Tier, AppContainer, and compatibility-mode configuration is obsolete and fails startup. Codex Sandbox or Automatic Git containment failure never falls back to Approved Host. Ordinary non-zero exit, test failure, compile/lint failure, and application error remain failures in the selected boundary.

Codex Sandbox uses the installed Codex CLI sandbox-only entrypoint with `windows.sandbox="elevated"`. WLMCP supplies an explicit managed sandbox-state containing restricted filesystem entries, protected-name deny patterns, explicit source/dependency/scratch roots, and restricted network state; it also requests direct-network disable. Desktop/program/standalone installs retain the adjacent command-runner and sandbox-setup helper closure. The official Windows npm global package is resolved from its package manifest and exact target architecture; its PATH codex.ps1/codex.cmd/codex files are locator-only, never trusted or executed, and its native codex.exe plus adjacent codex-code-mode-host.exe form the minimum npm dependency closure. In both distributions, every launcher and helper must have a valid OpenAI Authenticode signature and is bound to its canonical path, content SHA-256, Windows handle-derived stable file identity, size, actual version where applicable, leaf signer subject, and leaf certificate thumbprint. These identities are revalidated after approval and held against replacement through the child lifetime; mtime is only an auxiliary drift signal. Host-side launcher cwd is the trusted install directory, and relative, workspace, data, and scratch PATH entries are removed before launch. The launcher is assigned to a bounded Windows Job Object before its initial thread is resumed. The elevated WFP Guard channel accepts read-back evidence only when the process represented by the handle returned from `runas` is the fixed `.venv\Scripts\python.exe` venv launcher, and the named-pipe client PID reported by Windows is that launcher or its direct child whose executable is the corresponding `sys.base_prefix\python.exe` base interpreter. A matching parent PID without these executable-path checks is not accepted; the channel does not depend on environment inheritance across UAC. Then `codex --version` is recorded and the fixed command is launched through `codex sandbox`. This does not start a Codex agent, send a prompt, authenticate with OpenAI, or perform model/API inference. Read-only code-loading commands operate on an immutable staged copy; source-write commands require `workspace_write=true`, a full manifest, and the workspace mutation lock.

Policy input acceptance is not equivalent to a verified boundary. Live evidence schema v5 records `filesystem_read`, `filesystem_write`, `protected_information_read`, `internet`, `lan`, `loopback`, `descendant_containment`, `termination`, and `resource_bound` separately as `verified`, `failed`, or `unverified`, and additionally requires `brokered_process_creation_denied=true`. `failed` requires an executed probe to observe a boundary escape; launch failure, timeout, listener or probe setup failure, and other diagnostic inability are `unverified`. Descendant containment individually measures source-write, outside-user read, protected-information read, control-plane read/write, Internet, LAN, and loopback for child and grandchild. Resource verification exceeds both Job limits and proves violation reporting, safe termination, zero remaining descendants, and WLMCP exit-state collection. Schema v1-v4, missing mandatory fields, a changed `isolation_context_digest`, a missing/false brokered-process denial, and partially verified mandatory property sets are rejected without inference or migration. Schema v5 binds the exact imported WFP Guard module canonical paths, content SHA-256 values, Windows stable file identities, sizes, Guard version, policy generation, Windows product/build/UBR/native architecture, Sandbox account identity, and stable WFP read-back identity. The isolation context additionally binds the installed launcher/helper identities, physical roots, protected names and directories, dependency-readable paths, policy generations, scratch quota, and process/memory limits. A stale marker makes the normal operation route unavailable and never triggers automatic live verification. If every marker identity remains current and an exact static non-persistent WFP object is merely absent, the trusted Guard may recreate it, but complete read-back and `wfp_guard_verified` must precede child launch. Existing security-relevant mismatches or conflicting objects are never silently repaired. Session status keeps dependency/startup `available`, aggregate `windows_live_verified`, and policy-gated `execution_route_available` separate.

Workspace-local protected-information read and LAN access are accepted residual risks only for the general human-approved Codex Sandbox route. Their failed/unverified result remains recorded and visible without alone blocking that route. Automatic Git uses the same underlying containment implementation but imposes a stricter gate: all security properties must be verified and an exact Git-specific marker must additionally be current.

The selected distribution mode is installed-Codex dependency. It reuses upstream's CLI/setup helper/command runner/security update chain without copying Windows sandbox internals into this repository. Apache-2.0 permits a future standalone distribution, but safely redistributing the coordinated binaries, versioned policy/protocol, setup behavior, signing, notices, and update channel is deferred. Missing CLI, incomplete UAC setup, incompatible backend, initialization/policy/launch failure, or timeout fails closed. A separate Approved Host request is never an automatic fallback and follows its own immutable-runtime, one-shot approval, LocalSystem authority, requester-token, postflight, and recovery contract.

The WFP Guard resolves the fixed `CodexSandboxOffline` target with this PC's computer name as the account qualifier. It accepts the result only when the returned referenced domain matches this PC's physical NetBIOS name and `SID_NAME_USE` is `SidTypeUser` (`1`); otherwise the Codex Sandbox route fails closed.

### Configuration selection and local profiles

An explicit `LOCAL_MCP_CONFIG` must contain `workspace_root` and the selected config file itself must be outside that workspace, so MCP writes cannot downgrade a later worker's security settings. Every queued command request binds the canonical effective-settings digest and the worker rechecks it before launch. A simultaneous `LOCAL_MCP_ROOT` is accepted only when it resolves to the same path; a mismatch fails startup instead of overriding the chosen config. Missing config/workspace paths never fall back. `session_info` reports the effective workspace, capabilities, config selection source, workspace source, and whether an ambient root was present without dumping secret values.

Public code and `config.example.toml` remain generic. Machine/private values belong in ignored `config.toml`, `config.local.toml`, `config.*.local.toml`, or `.local-mcp/`. Launchers keep explicit `-Config` selection; there is no private-project schema switch or private branch requirement.

### ローカル起動ランチャー

`configure-localmcp.bat` は対話型設定管理の正式入口であり、`%LOCALAPPDATA%\WindowsLocalMCP\active-config.txt` に次回起動で使う config の絶対 path を保存します。初回はかんたんセットアップ、導入後は現在の設定の概要表示・変更・診断を選べます。新規設定は Codex Sandbox と Automatic Git を有効、Approved Host を無効にし、三つを後から個別に切り替えられます。有効化は route intent だけを変更し、live marker、実体、設定、workspace の現在の binding 検証を省略しません。無効化は検証記録を削除せず、再有効化時に現在の文脈で再検証します。旧 `start-localmcp.bat` はこの正式入口へ転送する互換ラッパーです。設定の workspace 変更は新しい内容を既存の設定ローダーで検証してから原子的に反映し、失敗時は旧設定を維持します。セットアップは任意で Secure MCP Tunnel の profile と client を検証し、config ごとの state/profile を同じ state root に保存します。`run-localmcp.bat` は `run-localmcp.ps1` を経由して selector または明示された第 1 引数を UTF-8 で読みます。Tunnel が有効な場合は、Credential Manager から Runtime API Key を実行時だけ child environment へ渡し、検証済み `tunnel-client run --profile-file <profile>` が state に固定した正規の `powershell.exe -NoProfile -File <server runtime>\run-server.ps1 -Config <absolute config>` を一度だけ起動します。通常は開発用 runtime、Approved Host 用 state では Program Files 配下の変更不能性を検証した運用用 runtime を使用し、運用用 runtime の検証失敗を開発用 runtime への fallback で迂回しません。Tunnel が未設定・無効なら選択済み runtime の `run-server.ps1 -Config <path>` へ直接渡します。バッチは config の中身を解釈して security setting を上書きせず、server の既存の config binding／startup validation を経由させます。

`run-localmcp.bat` は LocalMCP と同じ寿命の活動監視プロセスを起動します。監視プロセスは `<data_dir>\audit.db` を SQLite の読み取り専用モードで定期確認し、起動後に作成または状態変更された操作だけを、操作 ID、ツール、実行経路、状態、承認状態、伏せ字化して長さを制限したコマンド／パス／対象の要約の一行として起動ターミナルと `<data_dir>\logs\localmcp-activity.log` へ同時出力します。承認待ちは明示しますが、承認／拒否は別のローカル承認プロセスが所有します。監視ログは 5 MiB、10世代でファイルを切り替え、生の要求／結果 JSON、ファイル内容、差分、標準出力／標準エラーのプレビュー、Tunnel client の生出力、認証情報は複製しません。監視の起動失敗は server route の security gate ではないため警告して server 起動を継続しますが、Tunnel／runtime／credential の失敗は従来どおり fail closed です。

1つの config と1つの server process は、1つの `workspace_root` にだけバインドされます。複数フォルダーを同時に扱う場合は、パス識別子、承認、履歴、Git、Sandbox の各境界を定義する仕様変更が必要です。現行ランチャーでは、フォルダーごとに設定を分け、明示的な `-Config` またはセットアップ画面で切り替えます。

通常の server は管理者権限で起動しません。Approved Host の immutable runtime／authority service の導入、Codex Sandbox の live verification、Automatic Git の marker 作成、ADB serial の許可は、検証結果を省略しない明示的な手順として扱います。Sandbox から Approved Host への自動 fallback は行いません。

Secure MCP Tunnel の導入は optional です。Tunnel ID は `tunnel_` + 32 桁の小文字 hexadecimal として入力検証し、Runtime API Key は非表示入力で受け取ります。Key 本体は config、profile、workspace、`data_dir`、Git、ログ、監査、argv、永続環境変数へ保存せず、current Windows user の Credential Manager に config path 由来の target で保存します。起動時にその credential を読み取れない場合は Tunnel 経由の起動を fail closed します。profile は `api_key: env:WLMCP_TUNNEL_RUNTIME_API_KEY` という参照だけを持ち、Tunnel の実行終了後に親プロセスの環境へ key を残しません。

既存の profile/runtime 設定は、workspace、`data_dir`、リポジトリ内の executable を自動採用せず、profile の MCP command、Tunnel ID、client の実体・SHA-256 を検証したうえで非破壊に再利用できます。既存 profile を変更しない再利用では、既存の安全な `env:`／`file:`／ambient reference` をそのまま使います。新しい managed profile、Tunnel ID 変更、Key rotation、無効化、credential 削除は設定用メニューから行い、profile/state の更新は staging、doctor、atomic replacement、既存 backup、credential rollback を組み合わせます。Runtime API Key の単独ローテーションでは新しい key の `doctor` が成功するまで既存 credential を変更せず、成功後も Tunnel、profile、connector を作り直しません。Tunnel が設定済みで不整合な場合、Tunnel を迂回する direct-server fallback は行いません。client の path は PATH や profile の文字列だけで信用せず、実体が workspace／`data_dir`／リポジトリの外にあり、reparse point でなく、実行時 SHA-256 が state と一致する場合だけ受理します。

Tunnel の検証失敗は、LocalMCP 側の state/profile binding の `ReasonCode` と、`tunnel-client doctor` が出力する `FAILED_CHECKS` の check 名を区別して表示します。doctor は `config_source`、`profile_load`、`control_plane_api_key`、`tunnel_id`、`mcp_command_executable`／`mcp_server_reachable`、`health_listener`、`oauth_metadata`、その他の `control_plane_*` を別の診断コードへ分類します。構造化された check がない旧 client の出力だけ、HTTP status や限定したエラー表現による fallback 分類を行い、単なる `profile`、`config`、`mcp` という語だけでは原因を決めません。画面には診断コード、check 名、終了コードだけを表示し、doctor の生出力を state、ログ、監査へ保存しません。未知の check や分類不能な終了は一般 client 失敗として fail closed し、direct-server 起動へ切り替えません。managed profile の staging file も v0.0.10 の `--profile-file` 要件を満たす `.yaml` suffix とし、同じ directory 内での doctor 成功後に atomic replacement します。

## 9. data_dir protection

`data_dir` and Sandbox scratch are resolved independently and must not lexically or effectively overlap workspace or each other. Roots must not be reparse points. On Windows, handle-resolved volume-GUID paths and stable file identities also reject aliases such as SUBST that identify the same or nested physical namespace. `protect_data_dir_acl=true` removes inherited ACLs and grants Full Control only to the current token SID and SYSTEM.

ACL cannot distinguish two processes running as the same Windows user. MCP filesystem tools still cannot reach `data_dir` because it is outside workspace, and artifact paths are validated before special retrieval such as ADB screenshots. Approved Host therefore does not rely on same-user `data_dir` ACLs as its monitor boundary: the LocalSystem authority service owns the authoritative ProgramData active/recovery state, while user-owned control-plane state remains an independently checked postflight input.

## 10. Transport and ownership

Default transport is stdio. Streamable HTTP currently fails closed even when requested because authenticated principal ownership is not yet implemented.

`session_info.transport` reports stdio and HTTP independently with configured/enabled/available and startup-validation state; it does not describe rejected HTTP as optional or available.

Authenticated multi-principal HTTP is not implemented. Setting `http_multi_principal_enabled=true` fails startup. Therefore no supported configuration exposes globally shared job/approval/audit identifiers to distinct authenticated principals. A future implementation must persist `principal_id` on every operation and include it in every create/get/list/poll/claim/execute/cancel/audit SQL predicate.

## 11. MCP annotations

Annotations describe the real action performed by each model-facing call:

- pure local reads and `execute_readonly`: read-only, non-destructive, closed-world. Git requests either execute through the verified metadata-only Automatic Git Broker or fail closed before Git child creation;
- `adb_read`: read-only, non-destructive, closed-world;
- `write_file` and `execute_workspace_write`: non-read-only, destructive, closed-world;
- `request_host_command`: non-read-only, non-destructive, closed-world because it only creates an approval request; any later execution requires local approve-and-claim plus immutable binding, runtime-immutability, requester-identity, and LocalSystem authority checks;
- polls: read-only;
- process-stop controls remain explicitly mutating/destructive where appropriate.

The generic `execute`, `start_command`, and `execute_approved` surfaces are not exposed to MCP clients. This prevents one broad annotation from obscuring the narrow tool boundaries and prevents a second model-facing dangerous execution step after local approval. The presence of a surface does not claim that its candidate execution route is currently available.

Annotations are host hints and never replace server-side enforcement. The ChatGPT/MCP host may still apply its own confirmation policy.
