# 検証記録

## 2026-08-27 Sandbox workspace protected-read residual-risk policy correction

- trusted operator の設計判断として、2026-08-14 に実機確認した workspace 内 protected information の direct-read failure は current v1 の受容済み残存 risk とする。2026-08-26 の snapshot-only source isolation は defense-in-depth として維持するが、この残存 risk を解消した保証とは扱わない。
- `sandbox-state` の original workspace deny、immutable snapshot／operation 固有 run projection、protected file の staging exclusion、parent／child／grandchild の direct-read probe は維持する。probe の `failed`／`unverified` は削除・成功化せず evidence と capability 表示へ残す。
- route gate では `protected_information_read` と対応する child／grandchild protected-information denial を LAN と同様の accepted residual risk として分離する。それらだけが `failed`／`unverified` でも、その他の mandatory property／descendant check が成立すれば `execution_route_available` を妨げない。
- 一般 source-workspace read/write、workspace 外 user／protected read、control-plane read/write、Internet、未許可 loopback、termination、resource bound 等は引き続き mandatory であり、今回の受容範囲を拡張しない。
- 下記 2026-08-26 記録の「protected-information denial を必須 property とする」という分類は、その時点の実装判断の履歴として残すが、この 2026-08-27 correction により current policy としては superseded された。snapshot-only mechanism 自体は supersede されない。

## 2026-08-27 Approved Host capability verification truthfulness

- 修正前の `session_info()` は `assert_approved_host_runtime_immutable()` の成功だけで Approved Host capability 全体の `live_verified=true`、Windows では `windows_live_verified=true` を返していた。これは current runtime の immutability preflight という限定された evidence を、control-plane tamper detection、approval integrity、Job descendant handling、Job 外 same-user process detection、timeout termination を含む capability 全体の live verification へ拡張して表示していた。
- 修正後は既存の `configured`／`enabled`／`available`／`live_verified`／`windows_live_verified` と `runtime_preflight` を維持しつつ、`verification_scope=runtime_immutability_preflight_only` と `properties` を追加する。runtime preflight が成功しても capability 全体の `live_verified`／`windows_live_verified` は `false` のままとし、Windows 上で実測した `runtime_immutability` だけを `verified` とする。
- control-plane tamper detection、approval integrity、Job descendant handling、Job 外 same-user process detection、timeout termination は既存 regression coverage を `unit_tested=true` として区別し、current-machine live evidence をこの code path が生成しない限り `unverified` と表示する。
- `available=true` は Approved Host の runtime preflight と local execution prerequisite が解決したことを示すだけで、capability 全体の Windows live verification を意味しない。実行直前の runtime immutability recheck と既存の tamper／approval／process／timeout mechanism は変更しない。

## 2026-08-26 Sandbox snapshot-only source isolation

- Codex Sandbox の filesystem policy から original `workspace_root` の read capability を除去し、source workspace／`data_dir` を明示 deny、operation 固有 run projection だけを write root とする設計へ変更した。
- open-ended Sandbox request は code-loader 名に依存せず bounded な full workspace projection を承認時に snapshot 化し、worker は immutable projection の検証後に writable run copy へ materialize する。workspace-relative cwd／sibling layout を維持する。
- Approved Host は project-controlled code-loader と workspace 内 primary executable を request 時点で拒否する。
- Sandbox isolation/state policy generation と isolation-context version を更新したため、旧 live-verification marker は意図的に stale になる。新 route は通常 Windows user 文脈で `verify-codex-sandbox` を再実行し、parent／child／grandchild の `source_workspace_read_denied`、source write denial、protected-information denialを含む必須 property が実測されるまで fail closed のままとする。この protected-information mandatory 分類は 2026-08-27 correction により current policy として superseded され、現在は direct-read probe を維持した accepted residual risk として扱う。
- GitHub Hosted Windows で unit／integration／policy regression、Ruff、compileall を実行する。Hosted runner は installed production Codex Windows Sandbox の通常 user 実機境界ではないため、新しい source-read denial の OS-level 成立をそこで証明したとは扱わない。


## 2026-08-20 C7 verified state identity binding

### baseline と実装前 checkpoint

- `git pull --ff-only origin main` を通常 Windows user 文脈で実行し、`HEAD=b81ebe654bf99d0e64d9b4e1c7a7bc1bb04d9026`、同期済み、作業開始時 clean を確認した。
- 既知の一時 failure 対象 `test_approved_host_control_plane_tamper_is_detected_and_blocks_future_work` は 5 回連続で通過した。
- 実装前 full pytest 中に `test_approved_host_detects_wmi_process_outside_job_before_postflight` の遅延 canary が一度だけ欠落した。operation 自体は成功しており、WMI が venv launcher を起動した後に launcher が先に終了できる test fixture の不安定性だった。WMI が `sys.base_prefix\python.exe` を直接作成するよう fixture を限定修正し、対象 5 回連続と実装前 full pytest `288 passed, 2 skipped` を確認した。
- 実装前 Ruff、compileall、`git diff --check` は通過した。

### C7 identity と fail-closed behavior

- live marker を schema v4 へ切り替え、v1～v3または必須 field 欠損から C7 evidence を推測・移行しない。
- 実際に import された Guard module closure を canonical path、content SHA-256、Windows handle 由来の volume serial number / file index、size、Guard version、policy generation へ結合する。mtime は補助 drift signal であり、単独では trust anchor にしない。
- Codex launcher / helper を content SHA-256、Windows stable file identity、size、実際の version、Authenticode `Valid`、leaf signer subject、leaf certificate thumbprintへ結合する。
- Windows product / build / UBR / native architecture、local physical computer へ完全修飾した Sandbox account identity、stable WFP read-back binding を marker へ結合する。
- marker identity mismatch は通常 operation を live verification、Guard UAC probe、child launch、Approved Host fallback へ進めず、`verify-codex-sandbox` の明示実行を要求する。
- marker identity がすべて現在値と一致し、static non-persistent WFP fixed object が単に missing の場合だけ trusted Guard の ensure / recreate を許可する。existing mismatch / conflict は silent repair せず、missing と mismatch が混在する場合も object を追加しない。
- launch ordering は `ensure → complete read-back → wfp_guard_verified → child launch` を維持する。Guard module と Codex executable closure は security check から child lifetime まで置換・書込みを拒否する handle を保持する。

### 自動回帰と静的検査

- C7重点回帰: `92 passed`。schema v1～v3、backend / Guard / policy / account / OS /必須 field mismatch、stale marker、missing exact object、existing conflict、mixed missing / conflict、read-back / launch ordering、actual imported module identity / hold を含む。
- 通常 Windows user 文脈の full pytest: `304 passed, 2 skipped in 81.75s`。
- Ruff: `.venv\Scripts\python.exe -m ruff check --no-cache src tests` は pass。
- compileall: `.venv\Scripts\python.exe -m compileall -q src tests` は通常 Windows user 文脈で pass。制限環境からは通常 user の full pytest が生成した `tests\__pycache__` への一時 `.pyc` 書込みが拒否されたため、同じ通常 user 文脈で再実行した。
- `git diff --check`: pass。LF / CRLF の将来変換 warning のみ。

### 実装時点の検証境界

- C7 実装 commit 時点の通常 Windows user 回帰は unit / mock /既存 integration の検証であり、その時点では C7変更後の `verify-codex-sandbox`、UAC画面、live WFP objectの欠損再構築、実通信、production route E2E は未実施だった。
- Codex Desktop自身の制限環境内からstdio MCP子プロセスを起動するfull pytestは、子プロセス作成前で停止した。この入れ子実行は製品回帰の証拠に使わず、通常 Windows user 文脈のfull pytest結果だけを採用した。

### 後続の C7 実機 checkpoint — PASS

C7 実装後、通常 Windows user / production route で未検証だった境界を追加確認した。

- `verify-codex-sandbox` を実行し、marker schema v4、route eligibility、installed Codex backend identity / version / Authenticode、Guard implementation digest、Windows build / UBR、完全修飾した Sandbox account identity、WFP Guard binding digest を実機取得した。
- live marker を変更せず、maintenance cleanup で WLMCP の exact Guard sublayer と V4/V6 fixed filter だけを削除した。cleanup 前後で marker SHA-256 が不変であることを確認した。
- その状態から通常の `request_sandbox_command` production route を one-shot approval で実行し、missing fixed object が再構築されたことを audit と管理者 read-back で確認した。再構築後の runtime filter ID は削除前と異なり、同一 object が残っていたのではない。
- 再構築後も V4/V6 `effective_weight` は削除前と一致し、C7 marker binding が成立した。`FWP_EMPTY` 再作成で effective weight が変わり、missing-only recovery が binding mismatch になる懸念はこの実機では再現しなかった。
- audit event 順序は `sandbox_policy_prepared → wfp_guard_verified → sandbox_policy_applied → child_started → worker_finished`。Guard read-back verification 完了前に child は起動していない。
- operation は `codex_sandbox` tier、`status=succeeded`、`exit_code=0`。該当 operation に fallback / host / escalation event はなく、Approved Host への自動 fallback は発生していない。
- 再構築後に `Invoke-CodexLoopbackProbe.ps1 -RunSandboxProbe` を実行した。IPv6 UDP listener の diagnostic bug を発見し、`215d46b98515e487eb26d7500ed148f80e47f744` (`fix(diagnostics): IPv6 UDP listenerのDualMode設定順を修正`) で、未bind IPv6 socketへ `DualMode=false` を設定してから `::1` に bind するよう修正し、TCP/UDP の失敗処理も分離した。
- diagnostic 修正後は `listener_errors=[]`。TCP IPv4 / IPv6 は parent / child / grandchild すべてで localhost connection が成立せず host token 受信なし。UDP IPv4 / IPv6 は Sandbox 側 `Send()` は成功したが host token 受信なし。setup marker は probe 前後で不変だった。
- direct traffic probe では Codex 側 Firewall rule も有効なため、実通信 drop の唯一の原因を WLMCP custom Guard に帰属する証拠とはしない。Phase B の Guard 有無対照試験と、今回の production-route reconstruction / complete read-back / launch ordering を組み合わせて評価する。

以上により、C7 の実機 checkpoint は PASS とする。詳細な localhost / WFP Guard 系列の証拠は `WFP_GUARD_VALIDATION.md` に記録する。

## 2026-08-19 Approved Host 子孫プロセスの事後改ざん防止

### 再現と修正

- 修正前は、Approved Host の親が子プロセスを残して終了すると operation が `succeeded` になり、その後に子が `data_dir/control-plane` へ書き込めることを実プロセスで再現した。
- Windows の Approved Host 親を一時停止状態で起動し、kill-on-close を設定した operation 固有 Job Object へ割り当ててから再開するようにした。
- 親の終了だけでは事後検査へ進まず、Job の active process が0になるまで待つ。実行期限を超えた子孫は Job 全体で終了し、子孫0を確認できない場合は改ざん検査境界を検証不能として fail closed にする。
- Codex Sandbox は同じ Job Object 実装を従来どおり process 数・job memory 上限付きで使用し、Approved Host には Sandbox 用の resource 上限を流用しない。

### Windows 回帰結果

- 修正前の攻撃再現: 対象テストは `succeeded` と遅延書込みを観測して失敗した。
- 修正後の攻撃回帰: 親の後に残った子の書込みを事後検査が検出し、operation は `control_plane_tamper` で失敗、tamper marker を作成した。
- 正常系: 親の後に短時間だけ動く子は完了まで待機し、許可された出力を残して operation が成功した。
- timeout 系: 実行期限を超える子を Job 全体で停止し、operation は `runtime_limit`、停止後の遅延書込みは発生しなかった。
- Approved Host integration: 7 passed。
- full pytest: 260 passed、2 skipped（固有の `--basetemp` を使用）。
- `ruff check .`: pass。
- `python -m compileall -q src tests`: pass。
- `git diff --check`: pass（LF／CRLF の将来変換 warning のみ）。

## 2026-08-13 Codex Sandbox実境界の修正

### 対象と変更

- 基準: 作業開始時の`main` / `d65f91f`。`SECURITY_CONTRACT.md`は変更していない。commit／pushも実施していない。
- legacy `:workspace`指定を実行時の境界入力にせず、Codex CLIの`--sandbox-state-json`で限定read root、operation固有write root、protected-name deny、restricted networkを渡し、`--sandbox-state-disable-network`も併用した。
- Codex launcherを`CREATE_SUSPENDED`で起動し、active process数、job全体commit memory、kill-on-closeを設定したWindows Job Objectへ割り当ててから初期threadを再開するようにした。launcher、command runner、child、grandchildを同じjobに収容する。
- Verifierはchild／grandchildそれぞれについてsource write、outside-user read、protected read、control-plane read/write、Internet、LAN、loopbackを個別に検査する。独立した起動probeの例外は診断として残し、残りの安全なprobeを継続する。

### installed Codex／Windows機構の調査

- installed Codex CLI: `0.147.0-alpha.6.6`、`windows.sandbox="elevated"`。
- CLIは限定filesystem entry、deny path/glob、restricted networkを含むsandbox-stateを受理し、Windows backendには専用local user、deny-read ACL helper、Firewall／WFP実装がある。
- この環境のsetup markerはversion 5、offline userは`CodexSandboxOffline`、`proxy_ports=[]`、`allow_local_binding=false`だった。registryにはoffline user SIDを対象とするloopback TCP／UDPとnon-loopback outboundの3 block ruleが存在した。
- それにもかかわらず実connectionはLAN／loopbackで成功した。設定またはruleの存在を境界成立の証拠にはしていない。
- `deny_read_acl_state.json`は`{"principals": {}}`のままで、ログはread ACL処理成功を記録したがdeny ACEを1件も保持していなかった。限定policyを渡した実processはoutside-user canaryとworkspace内`.env`を読めたため、native Windows backendのdeny-readが実効化されていない。
- WLMCP側で既存Codex sandbox userへuser-profile全域のdeny ACLを付ける案は、同じprincipalを使う別Codex実行へ影響し、必要toolchain rootを安全に再許可できず、異常終了時にuser file ACLを残す。WLMCP専用local user／restricted token／AppContainerとACL provisioning、または専用WFP policyを組み合わせる案は管理者セットアップとcredential／ACL／filter lifecycleを持つ別sandbox backendの新規開発になるため、この変更範囲では採用していない。

### Windows実機結果

同一Windows環境でhost listenerと実process treeを使って9 propertyを再測定した。

| property | 結果 | 実測の要点 |
| --- | --- | --- |
| `filesystem_read` | failed | source read／control-plane read denialは成功、outside-user file read denialは失敗 |
| `filesystem_write` | verified | scratch write、source／outside-user／control-plane write denialが成功 |
| `protected_information_read` | failed | workspace内`.env`を親processが読めた |
| `internet` | verified | host controlが到達可能な`1.1.1.1:443`をSandboxから拒否 |
| `lan` | failed | host側LAN listenerへ接続できた |
| `loopback` | failed | host側`127.0.0.1` listenerへ接続できた |
| `descendant_containment` | failed | child／grandchildともoutside-user、protected、LAN、loopbackの拒否に失敗。source write、control-plane read/write、Internet拒否は成功 |
| `termination` | verified | timeout後にjob全体を停止し、heartbeat停止とdescendant 0を確認 |
| `resource_bound` | verified | process上限8で`process_count_limit`、memory上限192 MiBで`process_tree_memory_limit`を受信し、いずれもjob全停止、descendant 0、終了状態回収を確認。memory probeのpeak job memoryは226,209,792 bytes |

集約結果は`passed=false`、`windows_live_verified=false`、`execution_route_available=false`である。AとBはinstalled backendの実効境界不足により修正不能、Cは修正済み。Sandbox失敗からApproved Hostへのautomatic fallbackはない。

### 回帰確認

- 関連pytest: 36 passed。
- full pytestをACL汚染のない一時rootへ明示して実行: 221 passed、2 skipped。
- 指定どおりの`pytest -q`も実行したが、既存`.pytest-tmp-default`をpytestが削除できない`WinError 5`により43 passed、180 setup errors。テスト本体の失敗ではなく、同じsuiteを別`--basetemp`で全通過した。既存directoryは削除・ACL変更していない。
- `ruff check .`: pass。
- `python -m compileall -q src tests`: pass。
- `git diff --check`: pass（LF／CRLF変換warningのみ）。

## 2026-08-13 既知セキュリティ問題の再検証と修正

### 対象と基準

- 最終確認対象: `main` / `30cd90f709793088621f5bc2224077d5b0c374b`
- 作業開始時は `81c8e86d39900d9ca0fcf4bb75ea1bc91b7dba31` だったが、作業中に別プロセスの `git pull origin main` が `0bcac0e` と `30cd90f` を fast-forward した。巻き戻さず、追加された Timeline 実装と回帰も含む現在の `main` で再検証した。
- 基準: `SECURITY_CONTRACT.md`、SHA-256 `abc0c0bf47dd2952d97dbbc52b01f65e8b091fd8ce1f49cb98d955dc4e54c0e1`
- `SECURITY_CONTRACT.md` 自体は変更していない。
- 作業開始時の working tree は clean で、既存 user changes はなかった。commit／push は実施していない。

### Section 6 の判定

判定は修正前の現行コードを基準にし、右端にこの作業後の扱いを記録する。

| # | 重点確認項目 | 判定 | この作業後の扱い |
| --- | --- | --- | --- |
| 1 | Broker helper executable の provenance／path／hash／file identity と差し替え耐性 | still valid | Git／ADB を明示 path・SHA-256・file identity に固定し、Windows では実行中の差し替えを拒否 |
| 2 | legacy `:workspace` と `workspace_write=false` の実効 filesystem boundary | reformulated | profile 名や staging 表示を OS 境界の証拠にせず、必要 property 未検証時は実行経路を unavailable にする |
| 3 | Sandbox runtime から protected information を直接読める可能性 | reformulated | staging 漏えいを除去し、process／descendant の直接 read denial が実機未検証なら実行不可 |
| 4 | `.env`／dependency tree を含む過剰 staging | still valid | 保護 file と `.venv`／`node_modules`／`build`／`__pycache__` 等を除外 |
| 5 | known-path operation の full workspace checkpoint | still valid | 単一・複数の既知 path scope と source／destination の決定順 lock へ局所化 |
| 6 | artifact chunk ごとの全 file 再hash | already fixed | 不変 snapshot と開始／完了／commit 境界の検証を維持し、回帰なし |
| 7 | ChatGPT container source→result binding | already fixed | 既存拘束を維持し、派生出力の置換後 source 再検証と復旧を追加 |
| 8 | Sandbox launcher の host-side cwd／DLL／search-path | still valid | host cwd を信頼済み install directory に固定し、相対・workspace・data・scratch・利用不能 PATH entry を除外 |
| 9 | Internet／LAN／loopback と child／grandchild containment | partially fixed | property を分離し、現在の実機で未確認のためすべて unverified、実行不可 |
| 10 | Sandbox property ごとの live verification と aggregate 表示 | still valid | marker v2、9 property、backend digest 拘束、旧／部分 marker 拒否、`available`／`windows_live_verified`／`execution_route_available` 分離 |
| 11 | DOCX／XLSX の過剰な file-wide rejection と保存能力表示 | already fixed | package patch と既存保存回帰を確認、変更なし |
| 12 | 画像 format conversion の実用性と capability 表示 | still valid | extension が一致する別 `output_path` と source／既存 destination hash を導入 |
| 13 | CSV／TSV preservation 表示 | reformulated | semantic preservation と lexical quoting／byte identity 非保証を明示 |
| 14 | workspace／data／scratch の Windows physical identity | partially fixed | 3 root を安定 identity と handle-resolved physical path で比較し、SUBST 別名を実機拒否 |
| 15 | control-plane tamper、worker／approval／process lifecycle | partially fixed | 既存 one-shot／TTL／claim／tamper guard を維持し、承認後 executable identity と実行中 hold を追加 |
| 16 | checkpoint／CAS／GC concurrency と rollback／Undo | already fixed | 既存 journal／CAS／GC／Undo 整合性を維持し、checkpoint scope を全経路へ伝播 |
| 17 | resource admission、protected information leakage | partially fixed | 既存上限・redaction を維持。Sandbox の process／memory 等は未検証なので resource property と経路を fail closed |
| 18 | Live Activity／Timeline／preview／conflict／recovery 表示 | already fixed | 作業中に更新された現在の main の binary transfer lifecycle 修正と既存 Activity 回帰を含め全回帰通過 |
| 19 | ADB emulator 固定 read integration | partially fixed | 固定 target 文法・emulator policy を維持し、helper trust anchor を追加、未許可 device 列挙を自動文法から除外 |
| 20 | transport の startup 可用性と session／UI／documentation 表示 | still valid | stdio／HTTP の configured・enabled・available・startup validation を分離し、拒否される HTTP を available としない |
| 21 | 古い README／SPEC／VERIFICATION | still valid | README／SPEC／この検証記録を現行実装と現在の検証限界へ更新 |

内訳は `already fixed` 5、`obsolete` 0、`partially fixed` 5、`still valid` 8、`reformulated` 3、合計 21 項目。

### 自動回帰と静的検査

- 全回帰: `.venv\Scripts\python.exe -m pytest -q --basetemp .pytest-tmp-task3-final` は 215 passed、2 skipped。skip はこの権限で symlink／junction を作成できない 2 件で、hardlink 回帰と Windows 固有回帰は通過した。
- 対象回帰: helper trust／実行中差し替え、実 Git stdio、approval TTL／one-shot／tamper、Sandbox marker／PATH／timeout、scoped checkpoint／lock／rollback、artifact source binding、image／CSV／ZIP、transport 表示を実行し通過した。
- 変更 file に対する Ruff: pass。
- `python -m compileall -q src tests`: pass。
- `git diff --check`: pass。LF／CRLF の将来変換 warning のみ。
- repository-wide `ruff check .` は、作業中に現在の main へ追加された `src/windows_local_mcp/timeline.py` の import order 1 件で failure。この独立した非 security 変更は本作業で書き換えていない。

### Windows 実機確認

- 実 Git を明示 path／SHA-256 で固定した stdio MCP から `git_info` と固定文法 `git status --short` を実行した。
- Win32 file sharing を使い、保持中の helper file replacement と親 directory rename が拒否され、解放後だけ成功することを確認した。
- subprocess timeout 時に identity-bound parent と descendant を終了し、grandchild heartbeat が停止することを Windows process-tree probe で確認した。これは Codex Sandbox 内の descendant containment の証拠ではない。
- `SUBST W:` で workspace の別名を data path として構成し、physical overlap として設定拒否されることを確認した。割り当ては試験内で解除した。
- installed Codex CLI `0.147.0-alpha.6.6` の backend identity／version 解決を確認した。
- 以前記録した「最小 `codex sandbox` command が 20 秒で timeout し、全 property が `unverified`」という結果は、Codex Desktop 自身の Sandbox 内から別の Codex Sandbox を起動した入れ子の検証だった。最上位 Sandbox process の PID は生成されたが、backend log に対象 `cmd.exe /d /c exit 0` の `START` はなく、対象 command の開始前で停止していた。通常ユーザー文脈では同じ backend と WLMCP の `WindowsSandboxJob` 経路が正常終了するため、この timeout を WLMCP の回帰または command 終了後の結果回収待ちとは判定しない。
- 通常ユーザー文脈での最小実行は、WLMCP 経路 5 回が 0.279～0.339 秒、WLMCP を介さない直接 Codex CLI が 0.209 秒、live verifier 内の最小 command が 0.358 秒で、すべて exit code 0 かつ descendant drain 完了だった。
- 同じ通常ユーザー文脈で live verifier 全体は 20.491 秒で完了した。最新 marker は `passed=false`、実行経路 unavailable で、property は次の結果だった。
  - `filesystem_read`: `verified`。workspace 外のユーザーファイルは parent／child／grandchild のすべてで読み取りを拒否した。
  - `filesystem_write`: `verified`。
  - `internet`: `verified`。
  - `protected_information_read`: `failed`。workspace 内の保護対象 `.env` を parent／child／grandchild のすべてで読み取れた。
  - `lan`: `failed`。parent／child／grandchild のすべてで LAN 接続に成功した。
  - `loopback`: `failed`。parent／child／grandchild のすべてで localhost 接続に成功した。
  - `descendant_containment`: `failed`。
  - `termination`: `verified`。
  - `resource_bound`: `verified`。
- Sandbox 実行ユーザー SID は firewall rule と一致し、setup marker も成功状態だったが、LAN／localhost の実接続は遮断されなかった。設定の存在だけでは Windows 内部での強制を証明できない。WFP の詳細確認や管理者権限での修復は実施していない。
- Sandbox live verifier の初回実行で、アクセス不能な Windows App Execution Alias が host PATH sanitization を停止させる問題を再現した。信頼済み root の解決失敗は fail closed のまま、ambient PATH の利用不能 entry だけを除外する修正後に backend version 解決まで進むことを確認した。

### unit／mock／integration のみで確認した範囲

- Sandbox property marker の旧版／部分成功／backend mismatch 拒否と、全 property 成功時だけの経路許可。
- Sandbox 失敗／未検証から Approved Host へ自動 fallback しない control flow。
- protected file／dependency tree の staging 除外。ただし Sandbox process 自身の OS read denial の代替証拠ではない。
- approval request hash、argv／cwd／executable／input／settings binding、stale／double claim／expiry／cancel terminal race。
- Approved Host 後の control-plane tamper detection と後続 fail closed。
- scoped checkpoint／CAS／journal／rollback／selective Undo、source・destination concurrent modification、ZIP transaction recovery。
- DOCX／XLSX／CSV／TSV／ZIP／image の malformed／preservation／resource 回帰。
- stdio transport と HTTP startup rejection の表示整合性。

### 未検証

- 上記 9 つの Codex Sandbox OS property と、Sandbox 内での simple command／developer command 成功経路。
- Codex Sandbox の process 数、memory、filesystem entry を含む完全な resource bound。
- real ADB server／emulator／device identity／5037／screenshot と MCP ADB E2E。この端末では `adb` が見つからなかった。
- Secure MCP Tunnel／ChatGPT E2E、deployment、外部 service、実運用負荷。
- hardware power loss の全 fsync／SQLite timing に対する永続性。
- Section 7 の release 用 repository-wide 2 回連続独立 review pass。本作業は既知問題と修正箇所の回帰に限定した。

### 性能・実用性への影響

- known-path mutation は full workspace scan／checkpoint から対象 path scope へ縮小した。ZIP 複数展開も source と既知出力 path の lock／checkpoint だけを使う。
- 別 target slot の mutation は並行可能で、同一 source／destination と workspace-wide writer は引き続き競合する。
- Git snapshot の固定コマンド群は helper identity hold を共有し、Windows での helper 全体 hash は一連の snapshot 当たり trust capture と hold 開始の 2 回へ集約した。
- `.venv`／`node_modules`／`build` 等の不要な staging copy を除去した。
- artifact chunk は開始時の不変 snapshot を読み、chunk ごとの全 file rehash／data_dir 全走査を行わない既存実装を維持した。
- 定量 benchmark は実施していないため、速度向上率は保証しない。

### 次の新規セキュリティ監査への引き継ぎ

- 本作業中に、既知問題と独立した新規脆弱性は確認していない。
- 次タスクでは未知問題の探索と、本記録の未検証項目を区別する。特に Codex Sandbox の 9 property を実測できる backend／setup が得られた場合は、property ごとの probe を再実行する。
- repository-wide Ruff の `timeline.py` import order は独立した非 security 品質事項であり、新規脆弱性としては扱わない。

## 8. Security Scan Round 2（2026-08-27）

### 対象と方法

- start revision は `d6dae8cfec769270f68152da2a913b9f3515ddac`。C7 完了後の `main` 全体に Standard Security Scan を 1 回実行した。scan ID は `df9f57d8-08c4-45eb-b8d8-f97d414e9b6e`。
- `SECURITY_CONTRACT.md` の invariant、WFP Guard schema v4 identity binding、Approved Host、Codex Sandbox、Broker filesystem、workspace transaction、artifact processing、process lifecycle、runtime provenance、resource bound を source から sink まで確認した。
- Windows 全体の ACL／Firewall／WFP は変更していない。Codex Desktop 自身の Sandbox からの入れ子実行を通常 host の live WFP／UAC 証拠として扱っていない。

### Finding と処置

| ID | Severity | 結果 | 概要 |
| --- | --- | --- | --- |
| WLMCP-R2-001 | High | unresolved / release blocker | Approved Host child と同じ user principal で動く監視 worker は child から停止可能である。child が control-plane を改変して worker を停止すると postflight が実行されず、startup reconciliation も stale operation を `interrupted` にするだけなので、永続 tamper latch が残らない。guard lifecycle と latch を child の kill／write authority から分離する必要がある。 |
| WLMCP-R2-002 | Medium | unresolved | Approved Host では `Win32_Process.Create` による Job 外 process を補助 census で扱う一方、Codex Sandbox live verification は通常の child／grandchild と Job termination だけを測定する。Sandbox account が WMI／CIM process creation を利用できる環境では descendant termination／resource bound を迂回し得る。現在の host での到達性は未検証なので、identity-bound live denial probe を追加し、不明も route unavailable とする必要がある。 |
| WLMCP-R2-003 | Medium | fixed | `list_directory` が workspace-controlled child に `Path.is_dir()` を使用し、symlink／junction／UNC target を Broker authority で追跡していた。`os.scandir` と `DirEntry.stat(follow_symlinks=False)` へ変更し、reparse entry を target 非追跡の `reparse` type として返す。 |

既知 Critical は 0、既知 High は 1。したがって Round 2 の release 判定は `BLOCKED` とする。`SECURITY_CONTRACT.md` の保証は弱めていない。

### 修正後の再確認

- directory listing の正常な directory／file 分類と非追跡 metadata 呼び出しは focused test で通過した。実 symlink 作成が許可されない環境の adversarial test は skip し、同じ sink を test double で `follow_symlinks=False` と検証した。
- Windows HANDLE を使う directory TOCTOU／safe process／Git snapshot の focused host test は 6 passed、1 skipped。skip は symlink 作成権限による。
- Approved Host tamper、Sandbox route、WFP identity／runtime を含む focused security suite は初回 94 passed、1 skipped、1 timing failure。失敗した tamper parameter 群を直ちに単独再実行して 7 passed、続く full suite も通過したため、今回の差分による再現性のある regression とは判定しない。
- final full suite は `.venv\Scripts\python.exe -m pytest -q --basetemp .dev-tmp\pytest\round2-full-final` で 396 passed、5 skipped。skip は権限または platform prerequisite を明示した既存の安全な skip である。
- repository-wide Ruff、`python -m compileall -q src tests`、`git diff --check` は final tree で通過した。`diff --check` の出力は LF／CRLF の将来変換 warning だけだった。

### 残存 risk と次の security 作業

- WLMCP-R2-001 は既知 High なので C8 production-route E2E より前に解消する。最低条件は abnormal worker／server termination を Approved Host child から独立して検出し、Sandbox live marker を失効させ、明示的な再検証まで後続 operation を拒否することである。
- WLMCP-R2-002 は現在の Sandbox account と backend identity に binding した WMI／CIM provider process-creation denial probe を追加する。process 作成成功、結果不明、cleanup 不成立はすべて fail closed とする。
- WLMCP-R2-003 の元 attack path、child replacement race、junction／symlink／UNC variant、hidden-name 判定を再確認し、target を追跡する別経路は変更差分内に確認していない。
