# Automatic Git Broker verification

## Status

Automatic Git Broker の source／unit／Windows CI remediation と、実機 route verification を分離して記録します。

- implementation: in progress on `fix/automatic-git-broker-sandbox`
- Git-specific live marker schema: v1 implemented
- ordinary-operation auto verification/repair: prohibited
- Windows real-machine `verify-git-broker`: NOT RUN in this remediation session
- merge state: PR #26 remains draft/unmerged until the required real-machine verification is completed

CI が green であっても、この PC で `verify-git-broker` を実行して current Git-specific marker が生成されるまでは Automatic Git の machine-local execution availability を証明しません。

## Source-level security properties

Current implementation requires all of the following before a model-facing Automatic Git child can run:

1. `git_enabled=true` and an operator-pinned absolute Git executable path/SHA-256 outside workspace, `data_dir`, and Sandbox scratch.
2. Current generic Codex Windows Sandbox live evidence for the exact backend/isolation context.
3. Automatic Git-specific strict gating: every Sandbox security property, including `protected_information_read` and LAN, must be `verified`; generic Sandbox residual-risk acceptance is not inherited.
4. Git-specific marker schema v1 bound to the pinned Git identity, Sandbox backend, complete generic live-evidence digest, workspace root, and Automatic Git containment-policy digest.
5. Worker-side marker revalidation before Git execution.
6. Dedicated Git worker routing for current `broker` and legacy queued `safe_command` / `safe_sandbox` Git operations. These operations do not fall through to the standard worker.
7. A bounded disposable repository projection. The Git child does not receive the original workspace as its repository filesystem.
8. Project-controlled execution metadata is removed or rejected: hooks, attributes, external alternates, extended/worktree metadata, nested `.git`, reparse points, hardlinks, and NTFS ADS are not accepted as Automatic Git behavior inputs.
9. Source `.git/config` is parsed only in Broker memory, is capped at 1 MiB, requires repository format v0, and produces only an inert sanitized `core` configuration in the projection.
10. `show` and user-supplied `diff` revisions are commit-bound with `^{commit}`. Revision ranges bind both endpoints. This prevents raw blob/tree object IDs from being used to read protected historical object content. `diff --check` is accepted only with a Broker-validated regular-file pathspec.
11. The Git process runs through the live-verified Codex Windows Sandbox/WFP/Job boundary with source workspace/data_dir deny, network deny, descendant/resource controls, and brokered-process-creation denial.
12. Git executable, Codex backend, and WFP Guard implementation identities are held against replacement during the batch. Scratch projection cleanup runs in `finally`, and stale `git-broker` scratch roots are included in retention cleanup.
13. No Automatic Git failure falls back to Approved Host.

## Regression coverage

Focused Windows CI includes the Automatic Git environment/staging tests, Git-specific marker tests, object-access tests, current/legacy worker-routing tests, helper-identity tests, and directory TOCTOU tests. Full pytest, Ruff, compileall, and diff-whitespace checks remain required before this document can record source/CI completion.

The object-access regression specifically covers a Git behavior that is unsafe without the commit binding: `git show --no-patch <blob-sha>` still prints the blob bytes. The fixed grammar therefore does not treat `--no-patch` as an object-type boundary.

## Required real-machine completion step

Run only by explicit trusted-operator action on the target Windows PC after generic Sandbox verification is current:

```powershell
$env:LOCAL_MCP_CONFIG = 'C:\path\to\config.local.toml'
.\.venv\Scripts\python.exe -m windows_local_mcp.cli verify-codex-sandbox
.\.venv\Scripts\python.exe -m windows_local_mcp.cli verify-git-broker
```

A successful `verify-git-broker` must create a schema-v1 marker whose exact context is still current. Missing, failed, stale, or mismatched evidence leaves Automatic Git fail closed. This document must not be changed to claim Windows live verification merely because CI passes.

## Finalization record

The final branch SHA, focused-test count, full pytest count, and Windows CI run will be recorded here after the source/CI tree is frozen. Real-machine evidence will remain explicitly `NOT RUN` until it is actually performed.
