# 検証記録

## 2026-08-29 Secure MCP Tunnel onboarding／LocalMCP ランチャー統合

### 対象と仕様変更

- 対象 baseline: `09730fcb837d98532dc96ccc283a240f48de85f0`（`09730fc ランチャーのUXを改善`）。
- 初回セットアップで ChatGPT Secure MCP Tunnel の利用を任意に設定でき、設定後は `run-localmcp.bat` が Tunnel client と LocalMCP を一つの起動経路として扱うようにした。未設定・スキップ・無効化時は、従来どおり `run-server.ps1 -Config` による LocalMCP 単体起動を維持する。
- Tunnel ID は厳密な形式で検証し、profile は LocalMCP の専用 stdio command と完全一致する場合だけ採用する。既存 profile は内容を変更せず、安全に検証できるものだけ再利用する。
- runtime API key は Windows のユーザー資格情報領域（Credential Manager）へ保存し、profile、state、argv、launcher の標準出力・標準エラーへ平文を出さない。プロファイル・state・client の場所、hash、config binding、process identity を起動ごとに再検証し、不一致時は fail closed とする。
- managed profile／state の保存は staging、doctor、atomic replace、旧ファイル退避、credential/profile/state のロールバックを行う。Tunnel の起動失敗から LocalMCP 単体へ自動フォールバックしない。
- `SECURITY_CONTRACT.md`、Approved Host、Codex Sandbox、Automatic Git の境界は変更していない。

### 今回の回帰検証

- Tunnel／launcher focused pytest: `27 passed in 12.46s`。
- focused Ruff: pass（`tests/test_tunnel_integration.py`、`tests/test_local_launchers.py`、`tests/test_powershell_scripts.py`）。
- PowerShell parser: pass（`secure-mcp-tunnel.ps1`、`setup-localmcp.ps1`、`run-localmcp.ps1`、既存の主要 launcher）。
- Credential Manager の保存・読み出し・rotation・削除: Windows API を使った実行確認 pass。テスト出力への secret 混入なし。
- profile 生成、`channel: main`、canonical LocalMCP command、argv と child environment の secret 分離、state/profile binding、改変時 fail closed、既存 profile の安全な候補検出: pass。
- Python `compileall`: pass。`git diff --check`: whitespace errorなし（既存の改行コード変換 warningのみ）。

### リポジトリ全体検証の制限

- 全体 pytest: `649 passed, 7 skipped, 3 failed`。失敗3件は今回の Tunnel 変更対象外の並行作業差分に含まれる `src/windows_local_mcp/sandbox_backend.py` の未定義 `_NPM_*` 定数による2件と、`test_snapshot_execution_succeeds_when_bound_workspace_is_unchanged` が `running` のまま終了した1件。今回の focused suite は成功しているが、リポジトリ全体の合格状態とは扱わない。
- 全体 Ruff: 今回の変更対象外の `src/windows_local_mcp/sandbox_backend.py` にある未定義 `_NPM_*` 定数と、既存テストの `PLR0402` により未通過。対象ファイルの focused Ruff は通過している。

### Windows／外部サービス検証の境界

- Windows API レベルの Credential Manager 検証は実施した。
- この環境では `tunnel-client.exe`／`tunnel-client` を検出できなかったため、実 client の doctor／run、OpenAI control plane、ChatGPT 側の Tunnel 表示・tool refresh を通した本番相当 E2E は未実施。ローカル focused test の成功を Secure MCP Tunnel／ChatGPT の接続成功とはみなさない。
- 実機で残る確認は、公式 client の安全な配置後に、通常の Windows user 権限で `setup-localmcp.bat` の初回設定、`run-localmcp.bat` の ready 応答、ChatGPT 側の Tunnel／tool refresh、key rotation／無効化／再設定を一続きで確認することである。

## 2026-08-28 Security Scan Round 2 post-merge targeted review

### 対象と判定

- current main baseline: `6aed125b1b5b326c89f237162465c36e6ba55cb2`
- Security diff scan: prior Round 2 closure `68b02ef1af57bef6cd1f8716e0d618d7b0de3768` から Automatic Git統合main `a466f86e46a635e9390569971d6d1ee160d77dbf` まで。準備された36件のsecurity-relevant review receiptをすべて閉じ、新規reportable findingは0件。
- mainがscan開始後に進んだため、`a466f86e` から `6aed125` のContext Export v2、Context Read、pytest shard、workflow、文書差分を別のtargeted supplementとしてsource-to-sink reviewした。
- 総合判定: `PASS WITH RESIDUAL RISK`。
- known Critical: 0。known High: 0。
- C8 production-route E2E: 実施へ進んでよい。
- release: C8 production-route E2Eが通常Windows user文脈で成功するまで条件付き。Codex Desktop内の入れ子Sandboxでは代替しない。

### Finding disposition

- `WLMCP-R2-001 — High`: `fixed / live verified` を維持。LocalSystem authority、非昇格requester-token child、dual-latch coordinated recovery、worker loss／service restart／post-recovery normal lifecycleを実証済み。後続統合でauthority境界を変更していないことを差分と回帰で再確認した。
- `WLMCP-R2-002 — Medium`: `fixed / live verified for recorded environment`。Sandbox accountからの `Win32_Process.Create` 到達性を三値分類し、明示的denial以外をroute unavailableとする。current live evidenceを伴う実payload起動では、payloadより前に同じSandbox backendでdenialを再確認する。成功・到達・不明・timeout・drain不成立の各failure pathと実行順序をテストし、Automatic Gitでも必須条件としている。
- `WLMCP-R2-003 — Medium`: historical directory reparse finding。既存の `fixed` 判定を維持。
- `WLMCP-R2-004 — Low`: `fixed`。Context Readの不正なremote nodeがPydantic validation errorへprivate title等の値断片を含め、その例外文がdurable auditへ複製され得た。受信modelに `hide_input_in_errors=true` を設定し、failure auditは例外classだけを保存する。private field非表示、監査非漏えい、sidecar identity変更、writable-root配置拒否、control-plane failureの回帰を追加した。

### pytest仕様監査

- 新規 `xfail` はなし。
- skipはWindowsで非昇格processがsymlinkを作成できない場合等の環境前提だけで、deny／fail-closed期待値をsuccessへ変更していない。
- `tests/ci_shards.py` はfull collectionとcore／runtime-closure shardのnode ID集合を比較し、missing／extra／overlapをfailureにする。今回 `full=644 / core=643 / runtime_closure=1` で成功した。
- Automatic Gitのcontent-bearing patch拒否、Sandbox brokered-process preflight順序、Approved Host authority、Context bridge control-plane gateは維持されている。

### 修正後 regression

- focused security tests: `80 passed, 1 skipped in 10.34s`
- full pytest: `637 passed, 7 skipped in 241.46s`
- Ruff: pass
- compileall: pass
- pytest shard completeness: pass（644 node IDs）
- git diff --check: pass

### 残存risk

- 一般Codex Sandboxで明示的に受容されているworkspace内 `protected_information_read` とLAN accessの残存riskは継続する。Automatic Gitはこの例外を継承しない。
- C8は未実施であり、current installed runtime、実MCP stdio、Sandbox/WFP marker、Automatic Git marker、Approved Host service／approval routeを一続きのproduction routeとして再確認する必要がある。
- security scanのraw/generated artifactと機械固有SID／PID／絶対path／digest生値はGit管理しない。

## 2026-08-28 WLMCP-R2-001 LocalSystem authority remediation — LIVE VERIFIED

### Current verdict

- Finding: `WLMCP-R2-001 — High`。
- Root cause 判定: `valid`。旧 architecture では Approved Host child と monitor／postflight worker が同一 Windows user authority にあり、child が監視側を停止すると trusted postflight path を失い、restart reconciliation だけでは durable tamper latch が残らなかった。
- Remediation: monitor／postflight authority を LocalSystem service 配下へ分離し、実 command だけを verified non-elevated requester-user token で起動する構成へ変更した。same-desktop UAC elevation は security boundary として採用しない。
- Final disposition: `fixed / live verified`。
- Security code candidate: `bb66eb30a6b7a8cf3f174d576f8eaed0687eb14c`。
- 下記の実機 security evidence は上記 candidate を対象とする。その後の Automatic Git／Context bridge 統合は共有 executor・server・worker を変更したため、authority boundary を変更していないことを差分と回帰テストで再確認した。これらを R2-001 の新しい実機証拠とは扱わない。
- PR #27 は 2026-08-28 に merge / closed。main merge commit は `63e3e75b4bf9fb1cf9ce8cef9c4eb1380b3e264a`。
- 後続の PR #26 Automatic Git integration は Approved Host authority separation を保持したまま main へ統合され、最終 main merge commit は `a466f86e46a635e9390569971d6d1ee160d77dbf`。Automatic Git の実機 E2E を Approved Host の新しい release-level live verification として扱わない。

pre-closure の詳細な検証履歴、過去の capability-reduction checkpoint、Security Scan Round 2 の当時判定、Codex Sandbox／WFP／その他の historical evidence は `VERIFICATION_HISTORY_PRE_R2_001_CLOSURE.md` に byte-identical blob として保存する。historical section 内の `pending`／`unresolved`／`BLOCKED` は各時点の記録であり、この current verdict を上書きしない。

### Current security boundary

- production service: `WindowsLocalMCPApprovedHost` / LocalSystem / protected SCM DACL。
- durable state: `%ProgramData%\WindowsLocalMCP\ApprovedHostAuthority` / LocalSystem owner / protected SYSTEM+Administrators DACL。
- final command: authenticated pipe requester PID／create-time／SID／non-elevated token を検証し、`CreateProcessAsUserW` で suspended child を作成する。child を SYSTEM へ昇格しない。
- SYSTEM worker-owned Job Object へ child を assign してから resume する。
- requester-user WMI／CIM process census を保持し、`Win32_Process.Create` 等による Job 外 same-user helper を postflight まで fail closed に追跡する。
- SYSTEM-owned immutable `active.json` は normal verified completion まで残す。worker loss、service restart、channel loss、postflight uncertainty、epoch mismatch では解除せず `recovery_required` とする。
- user-owned `approved-host-postflight-pending.json` を第二 latch とし、SYSTEM authority state だけの解除で operations が自動再開しないようにする。
- explicit recovery は elevated Administrator の reviewed coordinated recovery のみ。bound postflight marker を operation id、SHA-256、stable file identity で確認・quarantine してから subordinate state を処理し、immutable `active.json` を最後に削除する。
- runtime user／Approved Host child に service stop/change-config、monitor cancellation、SYSTEM worker の terminate／suspend／duplicate-handle／VM-write／token-manipulation authority を与えない。
- project-controlled code-loader と workspace executable は Approved Host で拒否し、Sandbox failure から Host へ automatic fallback しない。

### Final hosted regression checkpoint

Security code candidate `bb66eb30a6b7a8cf3f174d576f8eaed0687eb14c` に対する Windows CI run #402 / run id `33122963524` は全 job 成功。

- focused process identity security regression: `17 passed`
- focused race／recovery／transaction regression: `38 passed`
- focused WLMCP-R2-001 authority regression: `49 passed`
- full pytest: `506 passed in 111.26s`
- Ruff: pass
- compileall: pass
- PowerShell parser: pass
- diff whitespace: pass

Hosted CI は OS authority separation の代替証拠ではないため、以下の実 Windows lifecycle を別途完了した。

### Immutable runtime live verification

通常の非管理者 runtime user から `verify-approved-host-runtime.ps1` を実行。

- scope: `complete-runtime`
- runtime digest: 取得・固定済み（機械固有の生値はリポジトリへ保存しない）
- ancestor directories: `2`
- directories: `1211`
- files: `14818`
- paths: `16031`
- result: `Approved Host immutable-runtime verification PASSED.`

### Normal path before fault injection — PASS

同一実機上の独立した正常 operation。

- child authority: same non-elevated runtime user
- durable authority state: runtime-user enumerate/write denied
- monitor authority: LocalSystem sensitive rights denied to runtime user
- requester SID: 実行時の非昇格 requester identity と完全一致
- service epoch: operation 前後で同一
- status: `passed`
- final output: `Approved Host authority normal-path live verification PASSED.`

### Fresh synchronized abnormal path — PASS

同一実機上の同期済み異常系 operation。

- SYSTEM worker: PID／create-time／executable identity を fault injection 直前に再検証
- WMI／`Win32_Process.Create` Job-external helper: PID／create-time／system executable identity を各段階で再検証
- service epoch: restart 前後の遷移を検証
- Arm remained alive after `ABNORMAL_ARM_READY` and observed authenticated recovery after the service epoch changed。
- elevated `KillAndRestart` verified exact SYSTEM worker identity before fault injection and exact WMI helper PID／create-time／executable before worker loss、after worker loss、after service restart。
- immutable `active.json` SHA-256 は kill 前、kill 後、restart 後、evidence review 時で同一。
- `active-status.json.state` remained `recovery_required` across service restart。

Abnormal `Check` result:

- `authority_healthy=false` — explicit recovery 前の期待値
- `legacy_generation_blocked=true`
- `legacy_worker_spawn_blocked=true`
- `service_epoch_transition_verified=true`
- `state_tamper_denied=true`
- WMI helper survived worker loss／restart, exact identity was reverified, then only that helper was cleaned up
- status: `passed`
- final output: `Abnormal worker-loss/WMI/restart/legacy-approval verification PASSED.`

### Durable recovery evidence review — PASS

handoff、administrator evidence、`active.json`、`active-status.json`、user-owned postflight marker はすべて同一の異常系 operation に binding されていた。

- `active-status.json.state = recovery_required`
- postflight marker state: `postflight_pending`
- postflight marker SHA-256: recovery前後で同一bindingを検証
- independent `tamper-detected.json`: absent
- authority service: Running / Auto / LocalSystem

### Coordinated recovery — PASS

Current `recover-approved-host-authority.ps1 -ConfigPath ... -AcknowledgeReviewedState` のみを使用した。historical split-recovery compatibility path は使用していない。

Recovery archive と quarantine はそれぞれ所定の保護領域に作成され、operation binding と stable file identity を確認した。機械固有の絶対 path と識別子はリポジトリへ保存しない。

- archive version: `2`
- archive state: `operator_recovered`
- postflight preflight／quarantine operation id: fresh abnormal operation と一致
- quarantine SHA-256: preflight marker と同一
- stable file identity: quarantine move 前後で同一
- `quarantined=true`
- `resumed_partial_recovery=false` — fresh coordinated path が最初から最後まで完了した証拠
- recovery 後 `active.json`／`active-status.json` は absent
- authority service は Running / Auto / LocalSystem へ復帰
- independent tamper marker を recovery path は解除していない

### Post-recovery normal path — PASS

recovery後の独立した正常 operation。

- child authority: same non-elevated runtime user
- durable authority state: runtime-user enumerate/write denied
- monitor authority: LocalSystem sensitive rights denied to runtime user
- requester SID: 実行時の非昇格 requester identity と完全一致
- service epoch: operation 前後で同一
- status: `passed`
- final output: `Approved Host authority normal-path live verification PASSED.`

### Additional real-machine blockers discovered and remediated

Live verification 自体を security design review の一部として扱い、実機で露呈した blocker も closure 前に root fix した。

1. historical split recovery が SYSTEM-owned authority latch だけを解除し、user-owned `approved-host-postflight-pending.json` を残して後続 operation を恒久停止させ得た。標準 recovery を authority＋bound postflight の coordinated transaction に変更した。
2. recovery script は authority service を意図的に停止する一方、recovery helper が normal-operation 用 authority health gate を呼び、停止した同じ pipe を要求する self-dependency があった。recovery-specific marker verification を normal authority-availability gate から分離し、通常 operation の authenticated service requirement は維持した。
3. `_acl_state_digest()` が directory と exact file を区別せず全 root に `icacls <root> /T /C` を実行し、実機では単一config fileのpreflightが30秒timeoutした。directory は recursive `/T /C` を維持し、single file は exact-file `/C` のみに変更した。directory recursion を弱めず root type ごとの regression を追加した。
4. immutable-runtime installer／ACL preflight の複数の実機 blockerについて、runtime user RX、SYSTEM/Admin F、protected root inheritance、safe old-runtime replacement、volume-root DELETE semantics を修正し、最終 complete-runtime verification を通過した。

### Closure rule

以上により、security code candidate `bb66eb30a6b7a8cf3f174d576f8eaed0687eb14c` では次の mandatory lifecycle が同一 real Windows environment で完了した。

`normal operation → SYSTEM worker loss → Job-external WMI helper survival → service restart + durable recovery_required → stale/legacy execution rejection → exact helper cleanup → reviewed coordinated recovery → restored normal operation`

WLMCP-R2-001 は `fixed / live verified` とする。これは別 PC、別 runtime、別 service configuration、または authority/security-boundary code の変更後にも自動的に live-verified とみなす意味ではない。production execution は各環境で immutable runtime と authenticated LocalSystem authority service の current preflight を引き続き要求し、security boundary を変更した場合は normal／abnormal／recovery lifecycle を再検証する。

## Historical verification record

WLMCP-R2-001 closure 前の詳細な repository-wide verification chronology は `VERIFICATION_HISTORY_PRE_R2_001_CLOSURE.md` を参照する。そこに記録された古い `LIVE VERIFICATION PENDING`、capability-reduction、Round 2 `unresolved / release blocker` 等は historical point-in-time evidence として保持し、上記 current verdict により supersede される。
