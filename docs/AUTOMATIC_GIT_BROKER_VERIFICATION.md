# Automatic Git Broker verification

## Status

Automatic Git Broker の source／unit／Windows CI remediation と、実機 route verification を分離して記録します。

- implementation source/test freeze: `86dde9409990aea42681e3d96b4c42b50127f451`
- product-invariant synchronization head validated by CI: `a901ac711639cf508d137e472ff5174c46365877`
- Git-specific live marker schema: v1 implemented
- Automatic Git command-policy generation: v4
- Automatic Git containment-policy generation: v4
- ordinary-operation auto verification/repair: prohibited
- Windows CI: run #312 succeeded for the PR state containing the frozen source/tests
- focused process-identity security regression: 17 passed
- focused race/recovery/transaction regression: 38 passed
- focused Automatic Git Broker regression: 81 passed
- full pytest: 486 passed
- Ruff: passed
- compileall: passed
- diff whitespace: passed
- Windows real-machine `verify-git-broker` on this final remediation source: NOT RUN
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
10. Project-controlled execution metadata is removed or rejected: hooks, attributes, external alternates, extended/worktree metadata, nested `.git`, reparse points, and security-relevant hardlinks are not accepted as Automatic Git behavior inputs. Source named ADS are not copied into newly materialized projection files, while the completed projection is still checked fail-closed for named ADS.
11. Source `.git/config` is parsed only in Broker memory, is capped at 1 MiB, requires repository format v0, and produces only an inert sanitized `core` configuration in the projection.
12. Git object database bytes are not considered provenance-safe merely because a tree/index path looks safe. Automatic `diff` / `show` are therefore metadata-only: patch, binary patch, `--check`, and implicit patch output are rejected and directed to `request_sandbox_command`. Revisions remain commit-bound with `^{commit}` and ranges bind both endpoints as defense-in-depth.
13. The fixed Automatic Git capability remains available for status, metadata-only diff/show, log metadata, rev-parse, ls-files, and `git_info` snapshots; the hardening does not globally disable Automatic Git.
14. `verify-git-broker` queries the exact pinned runtime with `--list-cmds=builtins` and requires all Automatic subcommands (`status`, `diff`, `log`, `show`, `rev-parse`, `ls-files`) to be builtin in that runtime. A runtime that would delegate one of these commands to an external `git-*` helper does not receive a current marker.
15. Every Automatic Git launch fixes `maintenance.auto=false` and `gc.auto=0` in the Broker runner, in addition to disabling fsmonitor, untracked cache, external diff/textconv, credentials, optional locks, protocol access, system/global config, and system attributes.
16. The Git process runs through the live-verified Codex Windows Sandbox/WFP/Job boundary with source workspace/data_dir deny, network deny, descendant/resource controls, and brokered-process-creation denial.
17. Git executable, Codex backend, and WFP Guard implementation identities are held against replacement during the batch. Scratch projection cleanup runs in `finally`, and stale `git-broker` scratch roots are included in retention cleanup.
18. Repository projection bytes are limited to at most half of configured `max_sandbox_scratch_bytes`, leaving the remaining budget for operation runtime/transient output. No hard-coded repository-size floor may exceed the operator quota. Entry count is enforced during the copy itself as well as bounded scans.
19. Projection pruning is input-driven rather than filename-whitelisted. A root ignored/generated subtree is omitted only when the batch does not observe ignored untracked entries, a conservatively parsed root `.gitignore` single-component directory-only pattern matches it, and the pinned ordinary Git index proves that no tracked descendant exists. Both root-anchored forms such as `/.dev-tmp/` and unanchored forms such as `.venv/` may prove the corresponding root entry ignored. Unsupported/split index, negation/complex ignore semantics, a tracked descendant, or an observable ignored-tree command disables pruning and required unreadable input remains fail closed.
20. Source paths that are valid in the live workspace but would cross the currently supported Windows legacy path boundary only after the scratch/projection prefix is added are classified explicitly as `GitBrokerUnavailable` before materialization instead of leaking a raw `FileNotFoundError`. Extended-length path execution is not silently enabled without a verified security/TOCTOU integration.
21. No Automatic Git failure falls back to the normal Broker worker or Approved Host.
22. The explicit Git-specific verifier does not use remapped `git rev-parse --show-toplevel` output as independent projection proof. It requires pinned Git worktree recognition and read-only status success under the stricter source-workspace-deny containment, requires the allowed command set to be builtin, and requires all probe results from the batch to carry the same valid sanitized-projection snapshot digest before a marker can be issued.

## Regression coverage

Focused Windows CI includes the Automatic Git environment/staging tests, launch-time marker-gate tests, Git-specific marker tests, scratch-resource tests, object-access tests, current/legacy worker-routing tests, helper/runtime-identity tests, trusted-cwd/fixed-`-C` tests, builtin-command tests, projection-boundary tests, and directory TOCTOU tests.

At implementation source/test freeze `86dde9409990aea42681e3d96b4c42b50127f451`, the PR state was subsequently validated by Windows CI run #312 with product-invariant documentation synchronized at `a901ac711639cf508d137e472ff5174c46365877`:

- focused process-identity security regression: 17 passed
- focused race/recovery/transaction regression: 38 passed
- focused Automatic Git Broker regression: 81 passed
- full pytest: 486 passed
- Ruff: success
- compileall: success
- diff whitespace: success

The projection-boundary regressions cover the original whole-workspace availability failure and its follow-up cases. They verify that a proven ignored/untracked root tree is not opened, including the repository's real-world unanchored `.venv/` form; that a tracked descendant prevents pruning; that `ls-files --others` without `--exclude-standard` prevents pruning because ignored/untracked entries become observable; that source named ADS such as `Zone.Identifier` do not cross the projection boundary; and that reparse points, relevant hardlinks, nested `.git`, external alternates, and unreadable security-relevant Git metadata remain fail closed. A dedicated path regression verifies the case where the source path is below the Windows legacy limit but the longer scratch projection path crosses it and must produce an explicit broker-unavailable classification.

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

A successful `verify-git-broker` must create a schema-v1 marker whose exact context, including current command-policy generation v4, containment-policy generation v4, trusted process-cwd policy, builtin-command requirement, and scratch quota, is still current. Missing, failed, stale, or mismatched evidence leaves Automatic Git fail closed. This document must not be changed to claim Windows live verification merely because CI passes.

## Finalization record

Implementation source/tests are frozen at `86dde9409990aea42681e3d96b4c42b50127f451`; Windows CI run #312 is the corresponding source/CI evidence for the PR state with synchronized product invariant at `a901ac711639cf508d137e472ff5174c46365877`. This verification-record commit is documentation-only and does not change the code/test freeze identity. Real-machine `verify-git-broker` evidence remains explicitly `NOT RUN` on the final remediation source until it is actually performed.
