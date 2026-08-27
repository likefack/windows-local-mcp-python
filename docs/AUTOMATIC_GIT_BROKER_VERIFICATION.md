# Automatic Git Broker verification

## Status

Automatic Git Broker の source／unit／Windows CI remediation と、実機 route verification を分離して記録します。

- implementation: in progress on `fix/automatic-git-broker-sandbox`
- Git-specific live marker schema: v1 implemented
- Automatic Git command-policy generation: v2
- ordinary-operation auto verification/repair: prohibited
- Windows real-machine `verify-git-broker`: NOT RUN in this remediation session
- merge state: PR #26 remains draft/unmerged until the required real-machine verification is completed

CI が green であっても、この PC で `verify-git-broker` を実行して current Git-specific marker が生成されるまでは Automatic Git の machine-local execution availability を証明しません。

## Source-level security properties

Current implementation requires all of the following before a model-facing Automatic Git child can run:

1. `git_enabled=true` and an operator-pinned absolute Git executable path/SHA-256 outside workspace, `data_dir`, and Sandbox scratch.
2. Current generic Codex Windows Sandbox live evidence for the exact backend/isolation context.
3. Automatic Git-specific strict gating: every Sandbox security property, including `protected_information_read` and LAN, must be `verified`; generic Sandbox residual-risk acceptance is not inherited.
4. Git-specific marker schema v1 bound to the pinned Git identity, Sandbox backend, complete generic live-evidence digest, workspace root, scratch quota, Automatic Git containment-policy digest, and command-policy generation.
5. The common Git runner revalidates the Git-specific marker immediately before every ordinary child launch, including direct `git_info` snapshot execution. Only the explicit `verify-git-broker` bootstrap probe may bypass the marker it is creating.
6. Dedicated Git worker routing for current `broker` and legacy queued `safe_command` / `safe_sandbox` Git operations. These operations do not fall through to the standard worker.
7. A bounded disposable repository projection. The Git child does not receive the original workspace as its repository filesystem.
8. Project-controlled execution metadata is removed or rejected: hooks, attributes, external alternates, extended/worktree metadata, nested `.git`, reparse points, hardlinks, and NTFS ADS are not accepted as Automatic Git behavior inputs.
9. Source `.git/config` is parsed only in Broker memory, is capped at 1 MiB, requires repository format v0, and produces only an inert sanitized `core` configuration in the projection.
10. Git object database bytes are not considered provenance-safe merely because a tree/index path looks safe. Automatic `diff` / `show` are therefore metadata-only: patch, binary patch, `--check`, and implicit patch output are rejected and directed to `request_sandbox_command`. Revisions remain commit-bound with `^{commit}` and ranges bind both endpoints as defense-in-depth.
11. The fixed Automatic Git capability remains available for status, metadata-only diff/show, log metadata, rev-parse, ls-files, and `git_info` snapshots; the hardening does not globally disable Automatic Git.
12. The Git process runs through the live-verified Codex Windows Sandbox/WFP/Job boundary with source workspace/data_dir deny, network deny, descendant/resource controls, and brokered-process-creation denial.
13. Git executable, Codex backend, and WFP Guard implementation identities are held against replacement during the batch. Scratch projection cleanup runs in `finally`, and stale `git-broker` scratch roots are included in retention cleanup.
14. Repository projection bytes are limited to at most half of configured `max_sandbox_scratch_bytes`, leaving the remaining budget for operation runtime/transient output. No hard-coded repository-size floor may exceed the operator quota.
15. No Automatic Git failure falls back to Approved Host.
16. The explicit Git-specific verifier does not use remapped `git rev-parse --show-toplevel` output as independent projection proof. It requires pinned Git worktree recognition and read-only status success under the stricter source-workspace-deny containment, and requires all probe results from the batch to carry the same valid sanitized-projection snapshot digest before a marker can be issued.

## Regression coverage

Focused Windows CI includes the Automatic Git environment/staging tests, launch-time marker-gate tests, Git-specific marker tests, scratch-resource tests, object-access tests, current/legacy worker-routing tests, helper-identity tests, and directory TOCTOU tests. Full pytest, Ruff, compileall, and diff-whitespace checks remain required before this document can record source/CI completion.

The object-access regressions cover two distinct unsafe Git behaviors:

- `git show --no-patch <blob-sha>` prints blob bytes unless the revision is forced through a commit peel.
- A protected blob can be attached to an apparently safe path in an attacker-controlled tree/commit. Normal `git show --patch <commit> -- safe.txt` then prints the protected blob even when the current workspace `safe.txt` is benign. Therefore path validation plus commit binding alone is not a protected-content boundary; Automatic content-bearing output is denied.

The scratch-resource regressions verify that projection byte limits never exceed half of configured scratch quota and that the old 16 MiB floor is not reintroduced.

The live-verifier regressions also require a consistent sanitized-projection snapshot digest across the explicit probe batch and reject mismatched digests. This avoids treating the user-facing source-path remap performed on Git output as evidence that the child actually executed against the disposable projection.

## Required real-machine completion step

Run only by explicit trusted-operator action on the target Windows PC after generic Sandbox verification is current:

```powershell
$env:LOCAL_MCP_CONFIG = 'C:\path\to\config.local.toml'
.\.venv\Scripts\python.exe -m windows_local_mcp.cli verify-codex-sandbox
.\.venv\Scripts\python.exe -m windows_local_mcp.cli verify-git-broker
```

A successful `verify-git-broker` must create a schema-v1 marker whose exact context, including current command-policy generation and scratch quota, is still current. Missing, failed, stale, or mismatched evidence leaves Automatic Git fail closed. This document must not be changed to claim Windows live verification merely because CI passes.

## Finalization record

The source/code-freeze SHA, focused-test count, full pytest count, and Windows CI run will be recorded here after the source/CI tree is frozen. The later documentation-only verification-record commit is not treated as a self-referential code-freeze identifier. Real-machine evidence will remain explicitly `NOT RUN` until it is actually performed.
