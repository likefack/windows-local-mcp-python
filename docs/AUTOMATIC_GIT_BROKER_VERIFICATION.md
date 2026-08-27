# Automatic Git Broker verification

## Status

Automatic Git Broker の source／unit／Windows CI remediation と、実機 route verification を分離して記録します。

- implementation: source/CI complete on `fix/automatic-git-broker-sandbox`
- source/code-freeze SHA: `2655ed7a34f24aec83f585c6663cff9e5895e42d`
- Git-specific live marker schema: v1 implemented
- Automatic Git command-policy generation: v3
- ordinary-operation auto verification/repair: prohibited
- Windows CI: run #273 succeeded for the code-freeze SHA
- focused Automatic Git regression: 67 passed
- full pytest: 472 passed
- Ruff: passed
- compileall: passed
- diff whitespace: passed
- Windows real-machine `verify-git-broker`: NOT RUN in this remediation session
- merge state: PR #26 remains draft/unmerged until the required real-machine verification is completed

CI が green であっても、この PC で `verify-git-broker` を実行して current Git-specific marker が生成されるまでは Automatic Git の machine-local execution availability を証明しません。

## Source-level security properties

Current implementation requires all of the following before a model-facing Automatic Git child can run:

1. `git_enabled=true` and an operator-pinned absolute Git runtime executable path/SHA-256 outside workspace, `data_dir`, and Sandbox scratch.
2. Git for Windows の既知 `cmd\git.exe`／root `bin\git.exe` wrapper・redirector を trust anchor として受理せず、実際の runtime executable（通常 `mingw64\bin\git.exe`、architecture により `clangarm64\bin\git.exe`／`mingw32\bin\git.exe`）を直接 pin します。
3. Current generic Codex Windows Sandbox live evidence for the exact backend/isolation context.
4. Automatic Git-specific strict gating: every Sandbox security property, including `protected_information_read` and LAN, must be `verified`; generic Sandbox residual-risk acceptance is not inherited.
5. Git-specific marker schema v1 bound to the pinned Git identity, Sandbox backend, complete generic live-evidence digest, workspace root, scratch quota, Automatic Git containment-policy digest, command-policy generation, trusted process-cwd policy, and required-builtin policy.
6. The common Git runner revalidates the Git-specific marker immediately before every ordinary child launch, including direct `git_info` snapshot execution. Only the explicit `verify-git-broker` bootstrap probe may bypass the marker it is creating.
7. Dedicated Git worker routing for current `broker` and legacy queued `safe_command` / `safe_sandbox` Git operations. These operations do not fall through to the standard worker.
8. A bounded disposable repository projection. The Git child does not receive the original workspace as its repository filesystem.
9. The Windows Git process itself starts with the pinned runtime executable directory as its process cwd. The Broker inserts a fixed `git -C <sanitized-projection-cwd>` operand so repository selection does not require an attacker-controlled process cwd. This closes the projection-current-directory DLL preload surface without removing the Automatic Git capability.
10. Project-controlled execution metadata is removed or rejected: hooks, attributes, external alternates, extended/worktree metadata, nested `.git`, reparse points, hardlinks, and NTFS ADS are not accepted as Automatic Git behavior inputs.
11. Source `.git/config` is parsed only in Broker memory, is capped at 1 MiB, requires repository format v0, and produces only an inert sanitized `core` configuration in the projection.
12. Git object database bytes are not considered provenance-safe merely because a tree/index path looks safe. Automatic `diff` / `show` are therefore metadata-only: patch, binary patch, `--check`, and implicit patch output are rejected and directed to `request_sandbox_command`. Revisions remain commit-bound with `^{commit}` and ranges bind both endpoints as defense-in-depth.
13. The fixed Automatic Git capability remains available for status, metadata-only diff/show, log metadata, rev-parse, ls-files, and `git_info` snapshots; the hardening does not globally disable Automatic Git.
14. `verify-git-broker` queries the exact pinned runtime with `--list-cmds=builtins` and requires all Automatic subcommands (`status`, `diff`, `log`, `show`, `rev-parse`, `ls-files`) to be builtin in that runtime. A runtime that would delegate one of these commands to an external `git-*` helper does not receive a current marker.
15. Every Automatic Git launch fixes `maintenance.auto=false` and `gc.auto=0` in the Broker runner, in addition to disabling fsmonitor, untracked cache, external diff/textconv, credentials, optional locks, protocol access, system/global config, and system attributes.
16. The Git process runs through the live-verified Codex Windows Sandbox/WFP/Job boundary with source workspace/data_dir deny, network deny, descendant/resource controls, and brokered-process-creation denial.
17. Git executable, Codex backend, and WFP Guard implementation identities are held against replacement during the batch. Scratch projection cleanup runs in `finally`, and stale `git-broker` scratch roots are included in retention cleanup.
18. Repository projection bytes are limited to at most half of configured `max_sandbox_scratch_bytes`, leaving the remaining budget for operation runtime/transient output. No hard-coded repository-size floor may exceed the operator quota. Entry count is enforced during the copy itself as well as bounded scans.
19. No Automatic Git failure falls back to the normal Broker worker or Approved Host.
20. The explicit Git-specific verifier does not use remapped `git rev-parse --show-toplevel` output as independent projection proof. It requires pinned Git worktree recognition and read-only status success under the stricter source-workspace-deny containment, requires the allowed command set to be builtin, and requires all probe results from the batch to carry the same valid sanitized-projection snapshot digest before a marker can be issued.

## Regression coverage

Focused Windows CI includes the Automatic Git environment/staging tests, launch-time marker-gate tests, Git-specific marker tests, scratch-resource tests, object-access tests, current/legacy worker-routing tests, helper/runtime-identity tests, trusted-cwd/fixed-`-C` tests, builtin-command tests, and directory TOCTOU tests.

At source/code-freeze SHA `2655ed7a34f24aec83f585c6663cff9e5895e42d`, Windows CI run #273 recorded:

- focused process-identity security regression: 17 passed
- focused race/recovery/transaction regression: 38 passed
- focused Automatic Git Broker regression: 67 passed
- full pytest: 472 passed
- Ruff: success
- compileall: success
- diff whitespace: success

The object-access regressions cover two distinct unsafe Git behaviors:

- `git show --no-patch <blob-sha>` prints blob bytes unless the revision is forced through a commit peel.
- A protected blob can be attached to an apparently safe path in an attacker-controlled tree/commit. Normal `git show --patch <commit> -- safe.txt` then prints the protected blob even when the current workspace `safe.txt` is benign. Therefore path validation plus commit binding alone is not a protected-content boundary; Automatic content-bearing output is denied.

The runtime-dependency regressions verify that known Git for Windows wrapper/redirector paths are rejected when an actual architecture runtime exists, the direct runtime is accepted, the child process cwd is the trusted runtime directory, repository selection is broker-inserted through `-C`, and the Git-specific verifier refuses a runtime whose allowed Automatic commands are not all builtin.

The scratch-resource regressions verify that projection byte limits never exceed half of configured scratch quota, the old 16 MiB floor is not reintroduced, and copy-time entry growth is bounded before final post-copy validation.

The live-verifier regressions require a consistent sanitized-projection snapshot digest across the explicit probe batch and reject mismatched digests. This avoids treating the user-facing source-path remap performed on Git output as evidence that the child actually executed against the disposable projection.

## Required real-machine completion step

Run only by explicit trusted-operator action on the target Windows PC after generic Sandbox verification is current. Configure and hash the actual Git runtime executable, not a Git for Windows wrapper/redirector. A typical 64-bit Git for Windows installation uses `C:\Program Files\Git\mingw64\bin\git.exe`.

```powershell
$gitPath = 'C:\Program Files\Git\mingw64\bin\git.exe'
$gitHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $gitPath).Hash.ToLowerInvariant()
```

Set those values as `git_executable_path` / `git_executable_sha256`, then run:

```powershell
$env:LOCAL_MCP_CONFIG = 'C:\path\to\config.local.toml'
.\.venv\Scripts\python.exe -m windows_local_mcp.cli verify-codex-sandbox
.\.venv\Scripts\python.exe -m windows_local_mcp.cli verify-git-broker
```

A successful `verify-git-broker` must create a schema-v1 marker whose exact context, including current command-policy generation v3, trusted process-cwd policy, builtin-command requirement, and scratch quota, is still current. Missing, failed, stale, or mismatched evidence leaves Automatic Git fail closed. This document must not be changed to claim Windows live verification merely because CI passes.

## Finalization record

Source/code is frozen at `2655ed7a34f24aec83f585c6663cff9e5895e42d`; Windows CI run #273 is the corresponding source/CI evidence. Documentation-only commits after that SHA do not change the code-freeze identity and are not treated as self-referential proof. Real-machine evidence remains explicitly `NOT RUN` until it is actually performed.
