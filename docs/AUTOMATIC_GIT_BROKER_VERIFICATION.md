# Automatic Git Broker verification

## Status

Automatic Git Broker の source／unit／Windows CI remediation、Windows real-machine route verification、model-facing MCP E2E を分離して記録します。

- implementation source/test freeze: `7f2382f4a9a7d6140523c7f58f405edb916a13f3`
- Git-specific live marker schema: v1
- Automatic Git command-policy generation: v4
- Automatic Git containment-policy generation: v6
- ordinary-operation auto verification/repair: prohibited
- Windows CI: run #346 succeeded on source/test freeze `7f2382f4a9a7d6140523c7f58f405edb916a13f3`
- focused process-identity security regression: 17 passed
- focused race/recovery/transaction regression: 38 passed
- focused Automatic Git Broker regression: 106 passed
- full pytest: 511 passed
- Ruff: passed
- compileall: passed
- diff whitespace: passed
- Windows real-machine generic `verify-codex-sandbox`: PASS
- Windows real-machine `verify-git-broker`: PASS
- model-facing MCP `session_info` / `git_info` / `execute_readonly` E2E on this final remediation source: NOT RUN
- merge state: PR #26 remains draft/unmerged until the model-facing MCP E2E and final documentation/security review are completed

CI と machine-local verification は別の証拠です。2026-08-28 JST に target Windows PC で current source/test freeze を fast-forward し、clean source status のまま generic Sandbox verification と Git-specific verification を明示実行しました。Git-specific marker は schema v1、`route_eligible=true` で生成されています。通常 operation は marker を作成・repair しません。

## Source-level security properties

Current implementation requires all of the following before a model-facing Automatic Git child can run:

1. `git_enabled=true` and an operator-pinned absolute Git runtime executable path/SHA-256 outside workspace, `data_dir`, and Sandbox scratch.
2. Git for Windows の既知 `cmd\git.exe`／root `bin\git.exe` wrapper・redirector を trust anchor として受理せず、実際の runtime executable（通常 `mingw64\bin\git.exe`、architecture により `clangarm64\bin\git.exe`／`mingw32\bin\git.exe`）を直接 pin します。
3. Current generic Codex Windows Sandbox live evidence for the exact backend/isolation context.
4. Automatic Git-specific strict gating: every Sandbox security property, including `protected_information_read` and LAN, must be `verified`; generic Sandbox residual-risk acceptance is not inherited.
5. Git-specific marker schema v1 bound to the pinned Git identity, Sandbox backend, complete generic live-evidence digest, workspace root, scratch quota, Automatic Git containment-policy digest, command-policy generation, trusted process-cwd policy, required-builtin policy, exact projection ownership-trust policy, and sanitized EOL-semantics policy.
6. The common Git runner revalidates the Git-specific marker immediately before every ordinary child launch, including direct `git_info` snapshot execution. Only the explicit `verify-git-broker` bootstrap probe may bypass the marker it is creating.
7. Dedicated Git worker routing for current `broker` and legacy queued `safe_command` / `safe_sandbox` Git operations. These operations do not fall through to the standard worker.
8. A bounded disposable repository projection. The Git child does not receive the original workspace as its repository filesystem.
9. The Windows Git process starts with the pinned runtime executable directory as process cwd. The Broker inserts a fixed `git -C <sanitized-projection-cwd>` operand so repository selection does not require an attacker-controlled process cwd.
10. Repository ownership trust is granted only to the operation-specific disposable projection with command-scope `-c safe.directory=<exact stage.repository>`. Wildcard trust, source-workspace trust, scratch-parent trust, and global persistent `safe.directory` changes are not used by Automatic Git.
11. Project-controlled execution metadata is removed or rejected: hooks, attributes, external alternates, extended/worktree metadata, nested `.git`, reparse points, and security-relevant hardlinks are not accepted as Automatic Git behavior inputs. Source named ADS are not copied into newly materialized projection files, while the completed projection is still checked fail-closed for named ADS.
12. Source `.git/config` is parsed only in Broker memory, is capped at 1 MiB, requires repository format v0, and produces only an inert sanitized `core` configuration in the projection.
13. `core.autocrlf` semantics are reconstructed without exposing raw system/global Git config to the child. The Broker resolves only the trusted scalar value (`true` / `false` / `input`), rejects include/includeIf semantics or config paths overlapping workspace/`data_dir`/scratch, and emits the scalar into sanitized repository config. A direct repository-local scalar override retains normal precedence; invalid or unverifiable semantics fail closed.
14. Git object database bytes are not considered provenance-safe merely because a tree/index path looks safe. Automatic `diff` / `show` are therefore metadata-only: patch, binary patch, `--check`, and implicit patch output are rejected and directed to `request_sandbox_command`. Revisions remain commit-bound with `^{commit}` and ranges bind both endpoints as defense-in-depth.
15. The fixed Automatic Git capability remains available for status, metadata-only diff/show, log metadata, rev-parse, ls-files, and `git_info` snapshots; the hardening does not globally disable Automatic Git.
16. `verify-git-broker` queries the exact pinned runtime with `--list-cmds=builtins` and requires all Automatic subcommands (`status`, `diff`, `log`, `show`, `rev-parse`, `ls-files`) to be builtin in that runtime. A runtime that would delegate one of these commands to an external `git-*` helper does not receive a current marker.
17. Every Automatic Git launch fixes `maintenance.auto=false` and `gc.auto=0` in the Broker runner, in addition to disabling fsmonitor, untracked cache, external diff/textconv, credentials, optional locks, protocol access, raw system/global config in the child, and system attributes.
18. The Git process runs through the live-verified Codex Windows Sandbox/WFP/Job boundary with source workspace/data_dir deny, network deny, descendant/resource controls, and brokered-process-creation denial.
19. Git executable, Codex backend, and WFP Guard implementation identities are held against replacement during the batch. Scratch projection cleanup runs in `finally`, and stale `git-broker` scratch roots are included in retention cleanup.
20. Repository projection bytes are limited to at most half of configured `max_sandbox_scratch_bytes`, leaving the remaining budget for operation runtime/transient output. No hard-coded repository-size floor may exceed the operator quota. Entry count is enforced during the copy itself as well as bounded scans.
21. Projection pruning is input-driven rather than filename-whitelisted. A root ignored/generated subtree is omitted only when the batch does not observe ignored untracked entries, a conservatively parsed root `.gitignore` single-component directory-only pattern matches it, and the pinned ordinary Git index proves that no tracked descendant exists. Unsupported/split index, negation/complex ignore semantics, a tracked descendant, or an observable ignored-tree command disables pruning and required unreadable input remains fail closed.
22. Loose-ref projection is command-observability driven rather than a blanket copy of `.git/refs`. HEAD-derived batches pin `.git/HEAD`, the current symbolic loose-ref chain, and `packed-refs` when present, then omit unrelated loose-ref namespaces and reflogs before opening or materializing them. Commands that can observe unrelated refs retain the full required namespace and remain fail closed if those inputs are unsafe or unreadable. `refs/replace` remains conservatively retained.
23. Source paths that are valid in the live workspace but would cross the currently supported Windows legacy path boundary only after the scratch/projection prefix is added are classified explicitly as `GitBrokerUnavailable` before materialization. Extended-length path execution is not silently enabled without verified security/TOCTOU integration.
24. No Automatic Git failure falls back to the normal Broker worker or Approved Host.
25. The explicit Git-specific verifier requires pinned Git worktree recognition, read-only status success under the stricter source-workspace-deny containment, required builtin commands, and one consistent sanitized-projection snapshot digest across the probe batch before a marker can be issued.

## Regression coverage

Windows CI run #346 validated source/test freeze `7f2382f4a9a7d6140523c7f58f405edb916a13f3`:

- focused process-identity security regression: 17 passed
- focused race/recovery/transaction regression: 38 passed
- focused Automatic Git Broker regression: 106 passed
- full pytest: 511 passed
- Ruff: success
- compileall: success
- diff whitespace: success

The focused Automatic Git set includes environment/staging, trusted EOL semantics, exact `safe.directory` launch ownership trust, launch-time marker gate, Git-specific marker, scratch-resource, object-access, current/legacy worker routing, helper/runtime identity, trusted-cwd/fixed-`-C`, builtin-command, projection-boundary, ref-projection, and directory TOCTOU regressions.

The EOL regression creates a real Git-for-Windows `core.autocrlf=true` checkout rather than manually rewriting bytes. It proves that the source repository is clean, the projection remains clean when the trusted scalar is preserved, and a control projection with `core.autocrlf=false` becomes dirty. This prevents a test fixture from masking or inventing the Windows line-ending semantics being protected.

The ownership-trust regression requires `_prepare_git_launch` to insert exactly one command-scope `safe.directory` for the generated projection and not for the source workspace or a wildcard/parent scope.

The projection-boundary regressions cover ignored/untracked generated trees, workspace-local `.venv/`, named ADS, reparse points, hardlinks, nested `.git`, external alternates, required unreadable metadata, and destination-only Windows path-length overflow. Ref-projection regressions verify that unrelated deep `.git/refs/codex/...` namespaces are not opened by HEAD-only batches while full-ref commands remain fail closed on required unreadable refs.

## Windows real-machine evidence

Target machine verification was executed on source/test freeze `7f2382f4a9a7d6140523c7f58f405edb916a13f3` after `git fetch`, `git switch`, clean `git status`, and `git merge --ff-only` confirmed the local branch was current.

Generic `verify-codex-sandbox` evidence:

- live marker schema: v5
- backend: OpenAI Codex Windows Sandbox `0.150.0-alpha.8`
- `passed=true`
- `route_eligible=true`
- source workspace read/write denial: verified
- control-plane read/write denial: verified
- protected-information denial: verified
- Internet/LAN/loopback denial: verified
- child/grandchild containment: verified
- timeout/process/memory/filesystem bounds: verified
- `brokered_process_creation_denied=true`
- WMI result: `WLMCP_WMI_STATUS=-2147217405`, `WLMCP_BROKERED_PROCESS=DENIED`

Git-specific `verify-git-broker` evidence:

- marker schema: v1
- `verified_at`: `2026-08-27T19:55:20.507898+00:00`
- command-policy generation: v4
- containment-policy generation: v6
- exact Git runtime: `C:\Program Files\Git\mingw64\bin\git.exe`
- Git SHA-256: `fe0e064c8283dc50b1ce11a8b90d2ec1b68b5dc714ff0b8a8534bb9c43d1d02e`
- Git stable file identity: bound
- source workspace access: `deny`
- execution input: `sanitized-disposable-repository-snapshot`
- network: `deny`
- host fallback: `false`
- `git_inside_worktree=true`
- `git_projection_snapshot_bound=true`
- `git_status_readonly=true`
- `git_allowed_commands_builtin=true`
- `route_eligible=true`

This is valid machine-local route evidence for the current source/test freeze. It is not yet model-facing MCP E2E evidence for `session_info`, `git_info`, and `execute_readonly`.

## Remaining completion step

With the current marker loaded by the WLMCP server, complete model-facing E2E and record the results:

1. `session_info()` reports the Git Broker helper truthfully configured/enabled/available/live-verified on this machine.
2. `git_info` succeeds through Automatic Git Broker.
3. `execute_readonly` succeeds for `git status --short` and metadata-only `git diff --stat`.
4. content-bearing `git show --patch`, `git diff --patch`, and `git diff --check` do not execute through Automatic Git and do not fall back to Approved Host; they are rejected/routed to `request_sandbox_command` according to policy.
5. operation/audit evidence records Broker Git containment and `host_fallback_performed=false`.

PR #26 remains draft/unmerged until this E2E, final documentation synchronization, and final security review are complete.

## Finalization record

Source/tests are frozen at `7f2382f4a9a7d6140523c7f58f405edb916a13f3`. Windows CI run #346 and the Windows real-machine generic/Git-specific verifier evidence above validate that source/test state. Documentation commits after the freeze do not redefine the tested source identity. Model-facing MCP E2E remains explicitly `NOT RUN` until separately executed and recorded.
