# Automatic Git Broker verification

## Status

Automatic Git Broker の availability remediation、security boundary、current-main integration、Windows real-machine verification を分離して記録します。

Final integrated source/test commit verified on the target Windows machine:

- PR #26 integrated head: `926fc24a46f2d2afe0d2ddc05f32fb9c6d55dad0`
- parent 1: prior PR #26 head `16f64b7c96093dcaa47462acc83e9b2b6231a282`
- parent 2: current `main` at integration time `63e3e75b4bf9fb1cf9ce8cef9c4eb1380b3e264a`
- integrated source/test tree: `c3ccdebbbdcbea47c72cb953d337fb1315edb13c`
- final PR #26 documentation-only head: `d7953aed01fcb664ce6f68db11a7c8c2e69149ec`
- PR #26 final tree / merged main tree: `ce021bf7a468db5083632471ba92bc2954f7d62c`
- final main merge commit: `a466f86e46a635e9390569971d6d1ee160d77dbf`
- PR #26 state: merged / closed on 2026-08-28
- Git-specific live marker schema: v1
- Automatic Git command-policy generation: v5
- Automatic Git containment-policy generation: v6
- ordinary-operation auto verification/repair: prohibited
- formal PR-head Windows CI run #428: PASS
- final documentation-only PR-head Windows CI run #429: PASS after rerun; no source change between attempts
- target-machine generic `verify-codex-sandbox`: PASS
- target-machine `verify-git-broker`: PASS
- target-machine MCP stdio / `session_info` / `git_info` / `execute_readonly` E2E: PASS
- MCP protocol: `2026-07-28`
- final E2E result: `e2e_passed=true`

The live evidence is bound to the integrated source/test tree `c3ccdebbbdcbea47c72cb953d337fb1315edb13c`. The later PR documentation-only head and final main merge commit preserve that verified source/test content while adding closure documentation.

## Problem and remediation scope

The original availability failure was not one defect. Automatic Git repository staging/preflight treated several workspace or host conditions as if they were semantically required Git inputs, and the sanitized Git child also lost host Git semantics needed for a faithful read-only projection.

Observed root causes included:

- stale or inaccessible pytest temporary trees
- benign source `Zone.Identifier` ADS
- large ignored `.dev-tmp` / `.venv` trees
- unrelated deep loose-ref namespaces
- disposable-projection ownership mismatch causing Git dubious-ownership rejection
- sanitized child losing effective trusted `core.autocrlf` semantics and reporting false modifications
- readonly projection cleanup interfering with MCP startup lifecycle
- fixed `git_info` batch sharing a single-command timeout budget
- MCP SDK v2 masking normal `PermissionError` text that carried Sandbox reroute guidance
- required Git snapshot telemetry leaking into unrelated generic worker execution

The remediation does not delete or mutate irrelevant source artifacts merely to make Automatic Git available. It instead narrows repository projection to command-observable inputs, validates those inputs conservatively, and preserves required trusted Git semantics without exposing raw host configuration.

## Source-level security properties

The integrated implementation requires the following before a model-facing Automatic Git child can run:

1. `git_enabled=true` and an operator-pinned absolute Git executable path/SHA-256 outside workspace, `data_dir`, and Sandbox scratch.
2. Known Git-for-Windows wrapper/redirector entry points are not accepted as the trust anchor; the real runtime executable is pinned directly.
3. Current generic Codex Windows Sandbox live evidence must match the exact backend/isolation context.
4. Automatic Git applies stricter all-property Sandbox gating, including protected-information, LAN, loopback, descendant, resource, and brokered-process denial properties.
5. Git-specific marker schema v1 binds the pinned Git identity, Sandbox evidence, workspace, scratch quota, command-policy generation, containment-policy digest, process-cwd policy, required-builtin policy, projection ownership policy, and sanitized EOL semantics.
6. The Git-specific marker is revalidated immediately before ordinary Git child launch. Only the explicit verifier may bootstrap the marker it is creating.
7. Automatic Git `broker` operations route only to the dedicated Git Broker worker and do not fall through to the normal worker or Approved Host.
8. The Git child receives a bounded sanitized disposable repository projection, not the source workspace as its repository filesystem.
9. The Git child process cwd is the trusted runtime directory and the Broker fixes repository selection with `-C <sanitized projection>`.
10. Ownership remediation is command-scope `-c safe.directory=<exact operation projection>` only. No wildcard, source-workspace, scratch-parent, global, or persistent Automatic Git trust is used.
11. Hooks, attributes, external alternates, extended/worktree metadata, nested `.git`, reparse points, and security-relevant hardlinks are removed or rejected as Automatic Git behavior inputs.
12. Source named ADS are not copied to newly materialized projection files; the completed projection is still checked fail closed for named ADS.
13. Source `.git/config` is parsed only in Broker memory, capped at 1 MiB, requires repository format v0, and emits only inert sanitized configuration.
14. Raw system/global Git configuration remains unavailable to the child.
15. Only the normalized trusted `core.autocrlf` scalar (`true`, `false`, or `input`) may be reconstructed. include/includeIf, invalid values, unsafe config locations, or unknown layout fail closed.
16. A direct repository-local `core.autocrlf` scalar preserves normal precedence.
17. Automatic `diff` / `show` are metadata-only. Patch, binary patch, `--check`, and implicit content-bearing output are rejected and directed to `request_sandbox_command`.
18. Automatic Git remains available for status, metadata-only diff/show, log metadata, rev-parse, ls-files, and `git_info`; the hardening does not disable the capability globally.
19. `verify-git-broker` requires all Automatic Git subcommands to be builtins of the exact pinned runtime.
20. Child Git environment disables maintenance/gc, fsmonitor, untracked cache, external diff/textconv, credentials, optional locks, protocols, raw system/global config, and system attributes as applicable.
21. Source workspace and `data_dir` remain denied to the Git child; Internet, LAN, and loopback remain denied.
22. Job Object descendant/termination/resource limits and brokered `Win32_Process.Create` denial remain mandatory.
23. Git executable, Codex backend, and WFP Guard implementation identities are held against replacement during the relevant batch.
24. Repository projection bytes and entry count are bounded during materialization as well as later scanning.
25. Ignored/generated root pruning requires command non-observability, conservative root `.gitignore` semantics, and a pinned ordinary index proof that no tracked descendant exists.
26. Loose-ref projection is command-observability driven. HEAD-only batches do not need unrelated deep loose-ref namespaces; commands that observe broader refs retain the required namespace and remain fail closed if it is unsafe.
27. Destination-only Windows path overflow is classified explicitly as `GitBrokerUnavailable`; extended-length execution is not silently enabled.
28. Generic worker before/after Git snapshots are optional telemetry, while direct `git_info` remains required.
29. Only fixed `SandboxRouteRequiredError` policy guidance is model-visible; unexpected permission/runtime failures remain masked.
30. No Automatic Git failure falls back to Approved Host or unrestricted host Git.

## Regression and hosted Windows CI

The pre-integration Automatic Git source/test head `bca06c6f40767e857820342536208f5edeb21f89` passed Windows CI run #414:

- focused process identity: 17 passed
- focused race/recovery/transaction: 38 passed
- focused Automatic Git Broker: 121 passed
- full pytest: 525 passed
- Python 3.13 wheel-install MCP stdio negotiation: passed
- Ruff / compileall / diff whitespace: passed

After `main` advanced through PR #27 with the WLMCP-R2-001 Approved Host authority separation, overlapping `executor.py`, `server.py`, workflow, README, Security Contract, and specification changes were conflict-resolved together on an isolated integration branch. Neither side was accepted wholesale.

Synthetic integration CI run #426 and documentation-only run #427 both passed before the verified tree was placed onto formal PR #26.

Formal PR-head Windows CI run #428 on the integrated tree completed successfully:

- focused process-identity security regression: 17 passed
- focused race/recovery/transaction regression: 38 passed
- focused WLMCP-R2-001 Approved Host authority regression: 49 passed
- focused Automatic Git Broker regression, including integrated capability-surface coverage: 122 passed
- full pytest: 595 passed
- Python 3.13 wheel-install real MCP stdio negotiation: passed
- Ruff: passed
- compileall: passed
- PowerShell parser: passed
- diff whitespace: passed

The integrated capability regression simultaneously locks:

- Git helper `verification_scope=git-specific-live-marker`
- Approved Host `verification_scope=runtime_and_authority_preflight_only`
- Approved Host preflight is not misreported as release-level live verification
- Automatic Git containment failure does not route to Approved Host

The temporary integration PR #28 was closed unmerged after the exact verified tree was transferred to PR #26.

## Target Windows verification environment

On 2026-08-28 JST the operator fast-forwarded the local `fix/automatic-git-broker-sandbox` branch to exact integrated head `926fc24a46f2d2afe0d2ddc05f32fb9c6d55dad0` and installed that package non-editably into the external production-shaped runtime under `%LOCALAPPDATA%`.

The package was therefore imported from external `site-packages`, not from the target workspace.

Target host evidence:

- Windows 10 Home 25H2
- build 26200, UBR 9168, amd64
- Codex Sandbox backend `0.150.0-alpha.8`
- sandbox account `CodexSandboxOffline`
- sandbox SID は検証時の専用Sandbox accountと完全一致（生値は保存しない）
- pinned Git runtimeのstable executable identityとSHA-256を取得・保持（機械固有のpathと生値は保存しない）

## Final integrated-head generic Sandbox verification

`verify-codex-sandbox` generated current schema-v5 evidence at:

- `verified_at`: `2026-08-28T00:57:12.754146+00:00`
- backend、isolation context、guard implementation、WFP guard bindingの各digestを取得し相互bindingを検証（生値は保存しない）
- `passed=true`
- `route_eligible=true`

All required checks were true, including:

- source workspace read/write denial
- outside-user read/write denial
- protected-information denial
- control-plane read/write denial
- Internet/LAN/loopback denial
- child and grandchild inheritance of those boundaries
- timeout termination and descendant drain
- filesystem byte and entry limits
- process count limit
- process-tree memory limit
- brokered process creation denial

The brokered-process probe returned:

- `WLMCP_WMI_STATUS=-2147217405`
- `WLMCP_BROKERED_PROCESS=DENIED`

This preserves the mandatory Job-external process-creation denial used by the Sandbox route.

## Final integrated-head Git-specific verification

`verify-git-broker` generated current schema-v1 evidence at:

- `verified_at`: `2026-08-28T00:58:13.594831+00:00`
- command-policy generation: v5
- containment-policy generation: v6
- exact Git runtime: configured executableのstable identityとSHA-256にbinding（機械固有のpathと生値は保存しない）
- Git process cwd policy: `trusted-executable-directory-before-fixed--C`
- required subcommands: builtins
- containment policy、generic Sandbox live evidence、Git verification contextの各digestを取得し相互bindingを検証（生値は保存しない）
- source workspace access: `deny`
- execution input: `sanitized-disposable-repository-snapshot`
- network: `deny`
- host fallback: `false`
- `git_inside_worktree=true`
- `git_projection_snapshot_bound=true`
- `git_status_readonly=true`
- `git_allowed_commands_builtin=true`
- `route_eligible=true`

## Final integrated-head model-facing MCP E2E

A real MCP stdio client/server pair negotiated protocol `2026-07-28` against the external runtime installed from exact integrated head `926fc24a46f2d2afe0d2ddc05f32fb9c6d55dad0`.

`session_info()` reported the Automatic Git helper:

- configured: `true`
- enabled: `true`
- available: `true`
- live_verified: `true`
- windows_live_verified: `true`
- verification scope: `git-specific-live-marker`
- provenance: `explicit-local-config`
- Git executable identity: live markerと実行時のstable identity／SHA-256が一致

`git_info` succeeded:

- operation id: 監査記録へ保存済み（生値は保存しない）
- snapshot bytes: `15540`

`execute_readonly git status --short` succeeded:

- operation id: 監査記録へ保存済み（生値は保存しない）
- status: `succeeded`
- exit code: `0`
- stdout: empty
- execution tier: `broker`
- Git Broker sandbox: `git-live-verified-codex-windows-sandbox`
- source workspace access: `deny`
- host fallback performed: `false`
- containment policyとrepository snapshotのdigest bindingを検証（生値は保存しない）

`execute_readonly git diff --stat` succeeded with the same containment and repository snapshot binding:

- operation id: 監査記録へ保存済み（生値は保存しない）
- status: `succeeded`
- exit code: `0`
- stdout: empty
- execution tier: `broker`
- source workspace access: `deny`
- host fallback performed: `false`
- containment policyとrepository snapshotのdigest bindingを検証（生値は保存しない）

The empty status/diff-stat output confirms that the sanitized projection did not reintroduce false EOL dirtiness on this target machine.

Content-bearing requests were rejected before Automatic Git execution with model-visible fixed reroute guidance:

- `git show --patch` -> rejected; `use request_sandbox_command`
- `git diff --patch` -> rejected; `use request_sandbox_command`
- `git diff --check` -> rejected; `use request_sandbox_command`

Final result: `e2e_passed=true`.

## Approved Host integration boundary

This Automatic Git E2E does not claim to be a new Approved Host release-level live verification. Approved Host authority separation remains the separate capability introduced and verified through PR #27, which was subsequently merged to `main` as `63e3e75b4bf9fb1cf9ce8cef9c4eb1380b3e264a` before the final PR #26 integration.

What PR #26 integration establishes is narrower and explicit:

- shared `executor.py` still routes only `approved_host` operations to the authenticated LocalSystem authority service
- Automatic Git remains a separate dedicated Broker route
- Automatic Git containment failure cannot escalate to Approved Host
- model-facing capability scopes for Git and Approved Host coexist correctly under integration regression
- formal PR-head CI #428 reran the 49 focused Approved Host authority regressions together with the 122 focused Automatic Git regressions and the full 595-test suite

Therefore the current evidence is sufficient to close the concurrent-main integration blocker for PR #26 without falsely reclassifying an Automatic Git E2E as Approved Host live evidence.

## Final security review

After final integrated-head target-machine E2E, the following invariants remain satisfied:

- no `safe.directory=*`
- no source-workspace or scratch-parent `safe.directory`
- no persistent/global Automatic Git `safe.directory` mutation
- raw system/global Git config unavailable to the Git child
- only normalized trusted `core.autocrlf` scalar semantics reconstructed
- source workspace and `data_dir` denied to the Git child
- Internet/LAN/loopback denial mandatory
- descendant termination/resource bounds mandatory
- brokered WMI process creation denial mandatory
- no Approved Host or unrestricted host-Git fallback
- irrelevant `.venv`, `.dev-tmp`, stale pytest artifacts, unrelated refs, and benign source ADS are not deleted or modified to manufacture availability
- content-bearing Git remains outside Automatic Git and is directed to normal Sandbox approval
- unexpected internal permission/runtime failures remain masked
- marker identity drift remains fail closed and requires explicit verifier execution

No security-boundary weakening was introduced to recover Automatic Git availability.

## Finalization record

Automatic Git remediation and current-main source integration are verified at all required levels:

- source/security review: PASS
- focused regression: PASS
- full hosted Windows regression: PASS
- production-shaped MCP stdio: PASS
- final integrated-head generic Sandbox verification: PASS
- final integrated-head Git-specific verification: PASS
- final integrated-head model-facing Automatic Git E2E: PASS
- PR #26 final documentation-only CI: PASS
- PR #26 merged to `main`: PASS

The live-verified integrated source/test commit is `926fc24a46f2d2afe0d2ddc05f32fb9c6d55dad0` with integrated source/test tree `c3ccdebbbdcbea47c72cb953d337fb1315edb13c`.

PR #26 was merged and closed on 2026-08-28. The final merge commit is `a466f86e46a635e9390569971d6d1ee160d77dbf`, and its tree `ce021bf7a468db5083632471ba92bc2954f7d62c` is identical to the final PR documentation-only head tree. There is no remaining Automatic Git integration verification or merge blocker recorded by this document.

## 2026-08-31 status／diff consistency regression

`CMD-02` で、通常の `git status --short --branch` は clean な tracked files を、Automatic Git の metadata-only `git diff` だけが多数の binary modification として報告する不一致を再現しました。

原因は、Git LFS や `working-tree-encoding` により index blob と working-tree bytes が意図的に異なる repository で、sanitized projection が project attributes を除外しながら source index の ctime を新しい projection file identity へ結び直していなかったことです。`status` は内容を検査して clean と判断できても、`diff` は除外済みの属性変換なしで bytes を比較し、異なる結果になりました。

修正後は、worktree `.gitattributes` を同じ長さと改行位置を持つ inert comment placeholder に置き換え、source index の ctime／mtime／size が source file と完全一致する entry だけ projection stat へ再結合します。source stat evidence が stale の attribute-controlled repository は、外部 filter を実行したり意味を推測したりせず fail closed します。

この投影意味論の変更は Automatic Git containment-policy generation v7 とし、generation v6 の既存 Git-specific marker は自動移行せず stale にします。

検証範囲は次のとおりです。

- Git 組み込みの `working-tree-encoding=UTF-16` を使った再現 fixture: 修正前は projected `status` と `diff` が不一致、修正後は双方 empty
- stale source index stat の対照: projection 作成前に fail closed
- `tests/test_git_semantics.py`: PASS

この項目は source-level regression evidence です。通常 Windows host 上の Codex Sandbox／Automatic Git marker、UAC／WFP、model-facing MCP E2E を再検証済みとは扱いません。
