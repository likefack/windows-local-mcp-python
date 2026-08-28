# Automatic Git Broker verification

## Status

Automatic Git Broker の source／unit／Windows CI remediation、Windows real-machine route verification、model-facing MCP E2E を分離して記録します。

- final source/test head before this documentation update: `bca06c6f40767e857820342536208f5edeb21f89`
- Git-specific live marker schema: v1
- Automatic Git command-policy generation: v5
- Automatic Git containment-policy generation: v6
- ordinary-operation auto verification/repair: prohibited
- Windows CI: run #414 succeeded on PR head `bca06c6f40767e857820342536208f5edeb21f89`
- focused process-identity security regression: 17 passed
- focused race/recovery/transaction regression: 38 passed
- focused Automatic Git Broker regression: 121 passed
- full pytest: 525 passed
- Python 3.13 wheel-install MCP stdio negotiation: passed
- Ruff: passed
- compileall: passed
- diff whitespace: passed
- Windows real-machine generic `verify-codex-sandbox`: PASS
- Windows real-machine `verify-git-broker`: PASS
- model-facing MCP `session_info` / `git_info` / `execute_readonly` E2E: PASS
- MCP protocol negotiated in final E2E: `2026-07-28`
- merge state: PR #26 remains draft/unmerged; verification completion does not authorize merge

CI と machine-local verification は別の証拠です。2026-08-28 JST に target Windows PC で current branch を `bca06c6f40767e857820342536208f5edeb21f89` へ fast-forward し、clean source status のまま external non-editable production-shaped runtime へ wheel install して実機確認しました。Git-specific marker は schema v1、command-policy generation v5、`route_eligible=true` で生成されています。通常 operation は generic marker／Git-specific marker を作成・repair しません。

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
24. `git_info` command batches use a batch budget derived from the number of fixed commands rather than incorrectly sharing one per-command timeout across the entire batch; this preserves fail-closed timeout behavior without making normal multi-command snapshots spuriously unavailable.
25. Generic worker before/after Git snapshots are optional telemetry (`required=False`) and cannot make unrelated non-Git execution fail merely because Automatic Git trust configuration is unavailable. Direct `git_info` remains required and propagates its root cause.
26. Model-visible Sandbox reroute guidance uses a dedicated `SandboxRouteRequiredError` that remains a `PermissionError` while also being an MCP `ToolError`. Only fixed policy rejections intended to instruct the model to use `request_sandbox_command` are surfaced; unexpected permission/runtime failures remain generic and are not turned into diagnostic disclosure.
27. No Automatic Git failure falls back to the normal Broker worker or Approved Host.
28. The explicit Git-specific verifier requires pinned Git worktree recognition, read-only status success under the stricter source-workspace-deny containment, required builtin commands, and one consistent sanitized-projection snapshot digest across the probe batch before a marker can be issued.

## Regression coverage

Windows CI run #414 validated PR source/test head `bca06c6f40767e857820342536208f5edeb21f89`:

- focused process-identity security regression: 17 passed
- focused race/recovery/transaction regression: 38 passed
- focused Automatic Git Broker regression: 121 passed
- full pytest: 525 passed
- Python 3.13 wheel-install MCP stdio negotiation: passed
- Ruff: success
- compileall: success
- diff whitespace: success

The focused Automatic Git set includes environment/staging, trusted EOL semantics, exact `safe.directory` launch ownership trust, launch-time marker gate, Git-specific marker, scratch-resource, object-access, current/legacy worker routing, helper/runtime identity, trusted-cwd/fixed-`-C`, builtin-command, projection-boundary, ref-projection, directory TOCTOU, Git snapshot diagnostic/budget behavior, MCP policy-error visibility, and MCP stdio integration regressions.

The EOL regression creates a real Git-for-Windows `core.autocrlf=true` checkout rather than manually rewriting bytes. It proves that the source repository is clean, the projection remains clean when the trusted scalar is preserved, and a control projection with `core.autocrlf=false` becomes dirty. This prevents a test fixture from masking or inventing the Windows line-ending semantics being protected.

The ownership-trust regression requires `_prepare_git_launch` to insert exactly one command-scope `safe.directory` for the generated projection and not for the source workspace or a wildcard/parent scope.

The projection-boundary regressions cover ignored/untracked generated trees, workspace-local `.venv/`, named ADS, reparse points, hardlinks, nested `.git`, external alternates, required unreadable metadata, and destination-only Windows path-length overflow. Ref-projection regressions verify that unrelated deep `.git/refs/codex/...` namespaces are not opened by HEAD-only batches while full-ref commands remain fail closed on required unreadable refs.

The MCP policy visibility regression verifies that content-bearing Git policy rejections retain `request_sandbox_command` guidance over MCP without exposing arbitrary internal `PermissionError` text. The stdio integration regression is included in the focused Automatic Git CI set and the separate Python 3.13 wheel-shaped stdio job also passed.

## Windows real-machine evidence

Target machine verification was executed on source/test head `bca06c6f40767e857820342536208f5edeb21f89` after `git fetch`, `git switch`, clean `git status`, and `git merge --ff-only` confirmed the local branch was current. The package was installed as a non-editable wheel into an external runtime under `%LOCALAPPDATA%`, not imported from the target workspace.

Installed-runtime inspection confirmed:

- package import path is external `site-packages`
- Automatic Git command-policy generation: v5
- seven-command `git_info` batch budget: `420.0` seconds
- `SandboxRouteRequiredError` is both `ToolError` and `PermissionError`

### Stale-marker fail-closed proof

Immediately after reinstalling the current package, the first model-facing E2E did not run a Git child. `session_info()` reported:

- configured: `true`
- enabled: `true`
- available: `false`
- live_verified: `false`
- windows_live_verified: `false`
- unavailable reason: generic Codex Sandbox live verification missing/failed/stale for the current backend/isolation identity

This was expected: reinstalling the package changed runtime module stable file identities and therefore invalidated the old generic live marker. No ordinary operation silently repaired it. Only after the operator explicitly reran `verify-codex-sandbox` and `verify-git-broker` did the route become available. This proves the intended `stale -> fail closed -> explicit verification -> route restore` lifecycle on the target machine.

### Generic `verify-codex-sandbox`

Final current-runtime evidence:

- live marker schema: v5
- `verified_at`: `2026-08-27T23:16:24.158569+00:00`
- backend: OpenAI Codex Windows Sandbox `0.150.0-alpha.8`
- backend digest: `0611a127ce15997800d7098caac9d50e38593247c61acb443d8a45e6988f55eb`
- guard implementation digest: `39713d1cf308d311eb45d67ea86e478e3c9370560c26baad44711f145d577df3`
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

### Git-specific `verify-git-broker`

Final current-runtime evidence:

- marker schema: v1
- `verified_at`: `2026-08-27T23:17:13.673602+00:00`
- command-policy generation: v5
- containment-policy generation: v6
- exact Git runtime: `C:\Program Files\Git\mingw64\bin\git.exe`
- Git SHA-256: `fe0e064c8283dc50b1ce11a8b90d2ec1b68b5dc714ff0b8a8534bb9c43d1d02e`
- Git stable file identity: bound
- containment policy digest: `d944b3b4fb19f956941b1346e047639b1ab2fdbf22ea45228aba9f7b62023a19`
- generic Sandbox live-evidence digest: `465805fb9716ab21d91dbc13f65df17e210c636e5d22e3a5f2b0ce5b30abb9e9`
- Git verification context digest: `d8ff109314409065e8b048c23261e4bd4edfa1a5e8de49c1542f5b86024ddedb`
- source workspace access: `deny`
- execution input: `sanitized-disposable-repository-snapshot`
- network: `deny`
- host fallback: `false`
- `git_inside_worktree=true`
- `git_projection_snapshot_bound=true`
- `git_status_readonly=true`
- `git_allowed_commands_builtin=true`
- `route_eligible=true`

## Model-facing MCP E2E

Final E2E ran through a real MCP stdio client/server pair using MCP protocol `2026-07-28` and the external production-shaped runtime.

`session_info()` reported the Git Broker helper:

- configured: `true`
- enabled: `true`
- available: `true`
- live_verified: `true`
- windows_live_verified: `true`
- verification scope: `git-specific-live-marker`
- provenance: `explicit-local-config`
- Git SHA-256: `fe0e064c8283dc50b1ce11a8b90d2ec1b68b5dc714ff0b8a8534bb9c43d1d02e`

`git_info` succeeded:

- operation id: `49358c5e-6e92-4c02-bd14-6396c666cd80`
- snapshot bytes: `12412`

`execute_readonly` succeeded for `git status --short`:

- operation id: `0727133e-fcdc-4655-8f05-0e88e5bf36eb`
- status: `succeeded`
- exit code: `0`
- stdout: empty, confirming no false dirty state from EOL reconstruction
- execution tier: `broker`
- Git Broker sandbox: `git-live-verified-codex-windows-sandbox`
- source workspace access: `deny`
- host fallback performed: `false`
- containment policy digest: `d944b3b4fb19f956941b1346e047639b1ab2fdbf22ea45228aba9f7b62023a19`
- repository snapshot digest: `f91a870c4149e7ad95dd00a3fdf309714015aaf75b39fbe9199fce05a0ee0a6c`

`execute_readonly` succeeded for metadata-only `git diff --stat`:

- operation id: `4c014c3f-3b88-4dd5-86e8-85613f0dc426`
- status: `succeeded`
- exit code: `0`
- stdout: empty
- execution tier: `broker`
- Git Broker sandbox: `git-live-verified-codex-windows-sandbox`
- source workspace access: `deny`
- host fallback performed: `false`
- containment policy digest: `d944b3b4fb19f956941b1346e047639b1ab2fdbf22ea45228aba9f7b62023a19`
- repository snapshot digest: `f91a870c4149e7ad95dd00a3fdf309714015aaf75b39fbe9199fce05a0ee0a6c`

Content-bearing requests were rejected before Automatic Git execution and retained safe model-facing reroute guidance:

- `git show --patch`: rejected; `content-bearing Git show output is not eligible for Automatic Git; use request_sandbox_command`
- `git diff --patch`: rejected; `content-bearing Git diff output is not eligible for Automatic Git; use request_sandbox_command`
- `git diff --check`: rejected; `content-bearing Git diff output is not eligible for Automatic Git; use request_sandbox_command`

Final E2E result: `e2e_passed=true`.

## Final security review

The final implementation/evidence was reviewed against the security boundary after E2E completion:

- no `safe.directory=*`
- no source-workspace or scratch-parent `safe.directory`
- no persistent/global Automatic Git `safe.directory` change
- raw system/global Git config remains unavailable to the child
- only normalized trusted `core.autocrlf` scalar semantics are reconstructed
- source workspace and `data_dir` remain denied to the Git child
- Internet/LAN/loopback and descendant/resource controls remain required for Automatic Git
- brokered WMI process creation denial remains mandatory
- no Approved Host or unrestricted host-Git fallback
- ignored `.venv`, `.dev-tmp`, stale pytest artifacts, unrelated refs, and benign source ADS are not deleted from the source workspace merely to obtain availability
- content-bearing Git remains outside Automatic Git and is directed to normal Sandbox approval
- internal/unexpected permission failures remain masked; only fixed Sandbox-reroute policy text is intentionally model-visible
- marker identity drift remains fail closed and requires explicit verifier execution

No security-boundary weakening was introduced to recover availability.

## Finalization record

Source/tests validated by Windows CI and final target-machine E2E are at `bca06c6f40767e857820342536208f5edeb21f89`. Windows CI run #414 completed successfully with 121 focused Automatic Git tests and 525 full-suite tests. Generic Sandbox verification, Git-specific verification, stale-marker fail-closed behavior, MCP stdio negotiation, model-facing successful Automatic Git operations, model-facing content-bearing rejection guidance, and Broker containment/audit fields were all verified on the target Windows machine.

Verification is complete for the Automatic Git remediation at the recorded pre-integration source/test head. PR #26 remains draft/unmerged because verification completion does not authorize merge.

## Concurrent-main integration verification

After the Automatic Git target-machine E2E completed, `main` advanced to `63e3e75b4bf9fb1cf9ce8cef9c4eb1380b3e264a` through the WLMCP-R2-001 Approved Host LocalSystem authority remediation. The overlapping source, workflow, README, Security Contract, and specification changes were resolved together on the isolated integration branch rather than by choosing either side wholesale.

Current synthetic integration candidate before this documentation-only record: `c0ff548dbba40abdb370dca33552b7e8efaa55d3`.

The integration preserves both execution boundaries:

- Automatic Git remains a `broker` operation routed only to the dedicated `git_broker_worker`, with current Git-specific marker enforcement, sanitized projection containment, strict all-property Sandbox gating, and `host_fallback_performed=false`.
- Approved Host remains a separate one-shot approval route. `Executor` sends only `approved_host` operations to the authenticated LocalSystem authority service, while the final command uses the verified non-elevated requester token.
- `session_info()` retains the Git helper's `git-specific-live-marker` availability semantics and the Approved Host capability's `runtime_and_authority_preflight_only` semantics simultaneously. A dedicated integration regression now locks this combined model-facing surface.
- README, `SECURITY_CONTRACT.md`, and `SPEC.md` describe Automatic Git as an active verified Broker capability and Approved Host as an active authority-separated route. The former temporary fail-closed descriptions are retained only as historical context, not current capability state.
- Automatic Git containment failure still has no normal-worker or Approved Host fallback.

Windows CI run #426 on `c0ff548dbba40abdb370dca33552b7e8efaa55d3` completed successfully on Windows Server 2025 / Python 3.12, with the production-shaped MCP stdio check also run under Python 3.13:

- focused process-identity security regression: 17 passed
- focused race/recovery/transaction regression: 38 passed
- focused WLMCP-R2-001 Approved Host authority regression: 49 passed
- focused Automatic Git Broker regression, including the integrated capability-surface test: 122 passed
- full pytest: 595 passed in 134.13 seconds
- Ruff: passed
- compileall: passed
- PowerShell parser: passed
- diff whitespace: passed
- Python 3.13 wheel-install real MCP stdio negotiation: passed

The pre-integration target-machine Automatic Git E2E remains valid evidence for the Automatic Git implementation and containment design that was carried into the integrated tree. It is not promoted to evidence for the final integrated commit identity. Because shared `executor.py` and `server.py` changed during concurrent-main integration, the final PR #26 integrated head still requires one target-Windows revalidation of `verify-codex-sandbox`, `verify-git-broker`, MCP stdio negotiation, successful metadata-only Automatic Git operations, content-bearing rejection guidance, and audit/result boundary fields before integrated-head live verification can be called complete.

Until that revalidation is performed, the correct state is: source-level integration and hosted Windows regression PASS; final integrated-head target-machine E2E pending. PR #26 must remain draft/unmerged.
