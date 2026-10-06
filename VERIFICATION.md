# 検証記録

## 2026-10-06 運用環境更新後の接続設定を対話なしで更新

- `setup-localmcp.ps1 -RefreshApprovedHostTunnel` を追加。既存の設定を使い、対話メニューと
  共通の運用環境・authority service・Tunnel doctor 検証と保存・復元処理へ接続する。
  `-Config` を省略すると通常起動と同じ active config／既定設定を選び、選択ファイルは変更しない。
- Windows PowerShell 5.1 の非対話試験8件と既存ランチャー試験21件が成功（`29 passed`、45.49秒）。
  日本語・空白を含む設定パス、入力なしの成功、起動中Tunnel、運用環境／authority／資格情報の
  検証失敗、保存失敗時の設定復元、非managed設定の拒否、設定不在時の終了コードを確認した。
  追加試験の Ruff と差分空白検査も成功。運用環境・資格情報・保存先は試験内で代替しており、
  本番の接続設定をこの作業で更新したものではない。手順は [ローカル起動ランチャー](docs/LOCAL_LAUNCHERS.md)。

## 2026-10-06 複数クライアント・並行タスクの監査

- 新規操作に接続／プロセスの監査用 `session_id` と発行元を記録し、各ツールの省略可能な
  `task_id` で同一接続を共有する会話も区別する。履歴の接続・タスク絞り込み、イベント側の
  発行元、旧DB移行、表示、実行枠の同時取得、別プロセス起動時の復旧を確認した。
  仕様と適用方法は [複数クライアント・並行タスクの監査](docs/MULTI_CLIENT_AUDIT.md) を参照。
- Python `3.13.15`／MCP SDK `2.1.1` で、実SDKの独立接続と同一接続内の並行要求、要求ごとの
  スレッドへの発行元引き継ぎ、2プロセスからのDB移行・記録、旧記録の保持、検索条件を件数上限より
  先に適用することを検証した。発行元情報は認可・操作所有権には使用しない。
- 最終の対象確認は `86 passed`（26.01秒）。`test_request_origin.py`、
  `test_multi_client_operations.py`、`test_audit_origin.py`、`test_concurrent_startup.py`、
  `test_origin_views.py`、`test_performance_trace.py` と、下記ファイル置換試験の再確認を含む。
  結果原本は `.dev-tmp/multi-client-confirm-20261006.xml`。
- 並行作業による表示処理の更新後にも発行元表示と従来表示の回帰を確認し、`54 passed`
  （1.71秒）。原本は `.dev-tmp/multi-client-views-final-20261006.xml`。
  本件の変更対象モジュール・追加試験の Ruff と差分の空白検査も成功した。
- 広い関連回帰は `206 passed, 1 skipped, 6 failed`（179.65秒）。結果原本は
  `.dev-tmp/multi-client-final-20261006.xml`。1件の失敗はテスト用領域のファイル置換で発生した
  `WinError 5` で、ACLを変更せず別の一時領域で再実行した
  `test_workspace_checkpoint_restores_new_and_changed_files` は成功した。
  skip は検証用シンボリックリンクを作成できない環境条件による。
- 残る5件は Approved Host の監査完全性の実行試験で未解決。3件は承認用パイプへの接続で
  `CreateFileW(Approved Host authority pipe) failed: WinError 2`、2件は試験用操作が待機期限後も
  `queued` で実行結果を持たず、期待する改変シナリオを確認できなかった。これらの失敗原因を
  すべて環境由来と確定したものではなく、全リポジトリ試験や Approved Host 実機検証の成功とは扱わない。
- 試験用書き込みが制限環境で拒否されたため、専用の `.dev-tmp/pytest/multi-client-*` を使い
  許可されたホスト実行で確認した。運用中のサーバー、サービス、権限設定は変更していない。
  Program Files 配下の運用runtimeへの反映と再接続、および実際の ChatGPT／Tunnel を通した
  複数会話の確認は未実施。Sandbox／Approved Host の隔離保証をこの試験結果から主張しない。

## 2026-09-09 WFP 読み取り権限と Sandbox 復旧

- 通常 Windows user で App Isolation サブレイヤーの `FwpmSubLayerGetByKey0` が `0x00000005` を返すことを再現。管理者では同一 object が読み取り可能で、正しい provider／weight 7 を確認した。独自 Guard のサブレイヤーと IPv4／IPv6 フィルターは欠損していた。
- 完全 policy 検証後、正確な欠損だけを構築し、固定4個の object へ実行者 SID の `FWPM_ACTRL_READ=0x80` だけを追加する明示的セットアップを実装した。Windows SDK `10.0.26100.0/um/fwpmu.h` の権限値を照合。既存 ACE／拒否／所有者を保持した DACL 読み戻しが成功し、通常ユーザーの全 WFP 読み戻しも成功した。
- WFP／CLI／実装 identity 関連 `56 passed`、worker／Sandbox lifecycle／architecture 関連 `73 passed`、対象 Ruff 成功。最初の広い試験は既存 `.dev-tmp/pytest/default` の削除拒否で fixture 初期化に失敗したため、権限を変更せず専用の `.dev-tmp/pytest/wfp-read-regression` で再実行した。全リポジトリ試験の成功は主張しない。
- 通常 Windows host から実際の LocalMCP 設定で `verify-codex-sandbox` を実行し、2026-09-09 17:52 JST に `verification_status=verified`、`route_eligible=true` を確認。全9 property と `brokered_process_creation_denied`、通常 command／Python child／scratch write が成功。Codex 内に入れ子で起動した結果ではない。
- 接続中 MCP の `session_info` でも `execution_route_available=true`、`windows_live_verified=true`、`live_verification_status=verified`、失敗理由なしを確認した。読み取り権限設定や単体テストだけを隔離の実証として扱っていない。
- 元の `cmd.exe /c echo sandbox-test-ok` を MCP の Sandbox 要求として再申請できた。`poll_approval` は HTTP 504 となったため、ローカル監査 DB を読み取り専用で照合し、`pending_approval`／`approval_status=pending`／実行結果なしを確認した。この追加の承認付き MCP command E2E は未完了であり、実行成功とは記録しない。
- 検証対象は Codex backend `0.153.4`、Windows build `26200.9445`（amd64）。Guard 実装 digest は `bd430d3a15467d05f8a2cdfc35a8871b4c988813640c794e3a09067d5c747114`。この記録を別の runtime や設定へ流用しない。
- ローカル診断の原本は `.dev-tmp/wfp-access/normal.json`、`admin.json`、`prepare.json`、`live-verification.json`。この PC と検証時の runtime／設定 identity に限定した結果であり、Windows／backend 更新、WFP／policy 変更、marker 期限切れでは再検証する。
- 原因・設定範囲・初回設定と通常確認の手順は [WFP 読み取り権限](docs/WFP_READ_ACCESS.md) を参照。安全条件の緩和や Host への自動移行はない。

## 2026-09-09 Audit の処理段階別時間計測

- 同期 Broker の全体時間と最大128段階を `perf_counter_ns()` で計測し、Audit の nullable
  `timing_json` 列へ終了時に保存する。既存 DB 移行、失敗段階、復旧、Activity の非汚染を検証した。
- 広い関連回帰は `182 passed, 2 skipped, 2 deselected`。既存 Audit event 保存も計測した後の
  最終関連確認は `71 passed`、計測専用は `16 passed`。対象 Ruff、compileall、差分空白検査は成功。
- 分離した Windows transaction 競合テスト2件は、計測を完全に無効にした対照でも失敗した。
  全リポジトリの合格とは扱わない。途中に検出した traceback／HANDLE 保持による move 回帰は修正済み。
- 各12回の外部 latency 中央値は read `42.419 → 53.770 ms`、write `189.944 → 208.139 ms`。
  特に短い read の追加負荷は無視できない。実測 write 1件は total `220.073 ms`、
  before／after checkpoint 約72 ms、既存 Audit 保存約44 ms。約16 ms は独立 phase 未付与。
- schema、移行、試験範囲、未検証事項、全ファイル一覧と実測内訳は
  [Audit 処理時間診断の検証記録](docs/AUDIT_PERFORMANCE_VERIFICATION.md) を参照。
  仕様は [Audit の処理時間診断](docs/AUDIT_PERFORMANCE.md)。

### Audit の詳細計測と監査モニター（2026-10-06）

- schema v2 の親子関係・自己時間・上限超過後も続く処理別集計、内部保存処理の細分化、
  起動端末での時間表示を追加した。Live Activity の実装はこの作業では変更していない。
- 計測・監査モニター・Broker 操作の統合テスト74件と、Live Activity 関連83件が成功。
- 合成ファイルの書込から監査モニター表示まで確認。計測収集・DB保存の負荷も別途測定した。
- 運用 runtime への配備・再起動と実承認の確認は未実施。
- 試験条件、途中の失敗と再確認、計測値と限界は
  [Audit 詳細計測の検証記録](docs/AUDIT_DETAIL_VERIFICATION_2026_10_06.md) を参照。

## 2026-09-08 Binary transfer admission lifecycle

### 原因と修正

- 修正前は `artifact_download_chunk` が最後の byte を返して `complete=true` になっても durable manifest が `open` のままで、upload／download 共通の `max_open_transfers` 枠を TTL まで消費していた。
- download の terminal chunk と 0 byte begin を `completed` へ自動遷移させ、`preparing`／`open` だけを admission 対象とした。中断 transfer には冪等な `artifact_transfer_cancel` を追加し、`completed` snapshot は応答消失時の同一 chunk retry のため保持する。
- 追加レビューで、bounded audit retention により begin の親 operation が snapshot より先に削除されると、終端 retry の event 追加が外部キー違反になり得ることを確認した。親 operation の存在確認と event 追加を一つの SQL 文にし、親が既にない場合は独立した監査 operation を作るよう修正した。

### 自動回帰

- 最新作業ツリーで binary lifecycle、transfer timeline、artifact fast path、audit をまとめて実行し、`24 passed, 1 skipped`。
- skip は制限された Codex Desktop 文脈で `sc.exe query WindowsLocalMCPApprovedHost` が exit 5 となった公開 MCP stdio 試験であり、Secure MCP Tunnel／ChatGPT E2E の成功証拠にはしない。
- 監査親 operation 削除後の terminal chunk retry が byte-exact に成功し、新しい独立 audit operation が残る回帰を追加した。別視点の読み取り専用レビューでも、対象差分に具体的な迂回、監査欠落、通常挙動の回帰、テストの偽陽性は確認されなかった。
- 本件の変更ファイルに対する Ruff と `git diff --check` は pass。リポジトリ全体 pytest は 53% で約90秒進捗が止まったため中断し、中断前にも複数 failure があった。最初の failure を `-x` で個別化すると `test_real_config_selection_survives_worker_context_round_trip` が制限環境の SCM query（`sc.exe exited with 5`）で fail closed しており、binary transfer 経路ではなかった。したがって作業ツリー全体を green とは扱わない。

### Windows 実機と Tunnel の境界

- この作業では ChatGPT／Secure MCP Tunnel／実 Windows LocalMCP を通る再試験を実施していない。修正後 runtime に結合した `download begin → terminal chunk → 複数回反復 → upload begin/chunk/commit → SHA-256 一致` は未検証であり、`Windows E2E verified` とは記録しない。

## 2026-09-03 Codex Sandbox live verification の自動復旧 lifecycle

### 原因と変更

- 既存実装は schema v5 marker の backend／helper／WFP Guard／Windows／account／physical roots／保護対象／依存読取 path／環境変数／policy generation／scratch／process／memory binding と実行直前 gate を持っていたが、通常 LocalMCP startup から hardened verifier を呼ぶ lifecycle がなかった。このため missing／stale marker は再起動後も fail closed のまま、手動 `verify-codex-sandbox` が必要だった。変更後のmarkerは lifecycle状態を必須にしたschema v6であり、旧v5は自動再検証対象になる。
- server startup から daemon lifecycle を開始し、Broker transport readiness を待たせずに marker を検査する。有効 marker は TTL 内で再利用し、missing／stale／schema incompatible／backend identity mismatch／isolation context mismatch／policy generation mismatch／TTL expiry だけを自動検証対象にした。
- process-shared OS file lock の取得後に marker を再検査し、同一 identity の重複 full probe を防ぐ。実行経路も同じlockをmarker再確認からchild生成完了まで保持し、preflight後にmarkerを再読込するため、検証開始、marker置換、TTL切れとの起動競合はfail closedになる。OS が process 終了時に lock を解放するため、process crash／power loss で永続 lock は残らない。failed／unverified／途中終了は別の identity-bound attempt state に保存し、同一 identity の自動 retry は cooldown する。retry identityにはcurrent Sandbox accountとWFP bindingのread-back結果も含め、境界実体の変更時は直前の失敗cooldownを引き継がない。
- 自動／手動は同じ hardened verifier を使用する。forced verification 開始時は既存 marker を `verifying` へ置換し、base probe の暫定結果は marker へ公開せず、必須 `brokered_process_creation_denied` を含む全 phase 完了後だけ最終 marker を atomic／fsync 保存する。
- `session_info` に `live_verification_status`、`last_verified_at`、`last_verification_attempt_at`、`live_verification_stale_reason`、`verification_failure_reason`、cooldown 情報を追加した。既存の `available`、`live_verified`、`windows_live_verified`、`execution_route_available` は維持する。

### 自動回帰

- lifecycle 専用は 14 件 pass。valid marker の restart reuse、missing／stale success、failed／unverified、同時 startup、verifier crash と OS lock 解放、cooldown、backend／Sandbox account／WFP identity 変更、未来時刻の attempt state が cooldown を設定上限より延長しないこと、manual force、non-blocking background startup、CLI と自動経路の共通 core を確認した。
- Sandbox 関連 8 ファイルは `85 passed`。schema v6と必須lifecycle状態、identity／TTL、検証lockとpreflight後marker再確認、mandatory property、residual-risk policy、terminal status、source ACL、brokered-process、scratch retention を含む。
- request gate の実行直前 marker 再検証は `2 passed`。process-local lifecycle が checking 中でも有効 marker を不必要に止めず、durable marker が verifying の場合は fail closed し、Approved Host を呼ばない。
- config は `16 passed, 2 skipped`。`compileall -q src/windows_local_mcp` と今回の security-critical source／test の Ruff は pass。
- repository 全体 pytest は 53% で 2 failure を記録後、Windows process／handle 系ケースが長時間進行しなかったため中断した。最初の failure を個別化すると `test_approved_host_allows_legitimate_descendant_to_finish` が期待 `succeeded` に対して既存の `running` となり、今回変更していない Approved Host 統合経路だった（そこまで `36 passed`）。制限環境の `test_server_operations.py` には `sc.exe exited with 5` による 8 failure があるが、今回の request gate 2件は通常 Windows user 文脈で pass した。したがってリポジトリ全体を green とは扱わない。

### Windows 実機と Tunnel の境界

- 通常 Windows user 文脈で、専用 workspace／config／data／scratch を互いに分離した canary profile を使用した。2026-09-09 JSTの再確認ではinstalled Codex Desktop backend `0.153.4`、OpenAI Authenticode、launcher/helper hash と stable file identity の解決は成功した。
- marker missing の LocalMCP startup では、最初の `session_info` が `broker.available=true`、`live_verification_status=verifying`、`execution_route_available=false` を返した。server／Broker は probe 完了を待たずに応答した。
- 実 probe は `WfpGuardError: FwpmSubLayerGetByKey0 failed with WFP status 0x00000005` で `unverified` になった。`failed` へ誤分類せず、Sandbox route だけを閉じ、Broker は `available=true` のまま維持した。既存 WFP object が unreadable な状態を missing と推測して昇格 repair する変更は行っていない。
- schema v6変更後の同一 identity の直後再起動では `retry_after_seconds=254`、`last_verified_at=null`、`last_verification_attempt_at` 不変となり、full probe を再実行しなかった。これにより実 Windows 上で cooldown と verification-storm 抑制を再確認した。
- cooldown中の同じserverへ実際に`request_sandbox_command`を送ると、`ApprovedSandboxUnavailable`（`status=unverified`と同じWFP failure reason）でchild生成・承認登録前に拒否された。canary configでは`approved_host_enabled=false`であり、Host fallbackは発生していない。
- A の「全 property verified」、B の有効 marker 再利用、C の stale marker から成功 marker 更新、ローカル承認後の実 Sandbox command は、上記 WFP read-back failure のため未達である。security boundary を弱めた synthetic marker や Approved Host fallback では代替していない。D の unverified／Sandbox-only fail-closed／Broker 継続は実機確認済み。
- Secure MCP Tunnel／ChatGPT E2E は実施していない。Windows local E2E と別の未検証項目として残す。

## 2026-08-31 Approval UI Live Activity の人間向け表示

### 実装と自動回帰

- Approval UI専用のread-only投影を`live_activity.py`へ分離し、Audit／Activity Monitor／Timeline／承認実行の責務を変更せず、Read、Edited、Running、Finished、Approval、Uploaded、Downloaded、Failed、Rejected、Interrupted、Cancelled、Undone、Rolled back等へ分類した。
- structured processingはAuditで確定したformatとtargetだけを使用する。artifact transferはbegin operation、chunk event、commit operationをtransfer IDで相関し、chunkごとの行を抑止した。Selective Undoとpoint-in-time rollbackは承認requestのbounded preview metadataだけを表示に使い、両者とUndoのUndoを区別する。
- Live Activityのsummaryはallowlistしたmetadataだけを使用し、redaction、C0／C1、ANSI、双方向制御、surrogate、200文字上限を適用する。通常行にoperation ID、request hash、approval statusを出さず、request payload、stdout／stderr、file content、diffを読んでsummaryを作らない。
- focused Live Activity: `30 passed`。Activity Monitor、transfer Timeline、rollback／Undo、approval、audit、server operation、structured file、approval UI launcher、Approved Host承認実行統合を含む最終関連回帰は、通常Windows user文脈で`142 passed, 1 skipped`。
- 同じ関連回帰を制限環境内で先に実行した結果は、SCM queryが`sc.exe exited with 5`となり`31 failed, 102 passed, 1 skipped`だった。通常Windows user文脈で全対象が合格したため、これはLive Activity回帰ではなく制限環境のSCMアクセス境界として扱う。
- repository全体のRuff `--no-cache`、`compileall -q src tests`、`git diff --check`はpass。Audit schema、server operation記録、承認claim、checkpoint、transaction、recovery、Approved Host／Sandbox／Automatic Gitの実行経路は変更していない。

### 実機E2Eの境界

- ChatGPT -> Secure MCP Tunnel -> 実Windows Local MCP -> 実workspace／Audit DB／Approval UIの受入試験は、この実装環境からは未実施。
- 完成した試験手順は`docs/LIVE_ACTIVITY_E2E_ACCEPTANCE_PROMPT.md`に保存した。実経路、実ファイル、実Live Activity、Audit／Activity、ローカル承認後のUndo／rollbackを確認できるまで、実機E2EをPASSと扱わない。

## 2026-08-31 Approved Sandbox child 起動前の execution TTL 消費

### 実 audit による原因確定

- 対象は 2026-08-29 の Approved Sandbox 2件。いずれも `approval_execution_ttl_seconds=60`、`approval_bundle_verified`、`worker_started` までは成功し、`child_pid` がないまま `approval execution grant expired before child start` で終了した。
- 1件目は `worker_started` から pre-Git snapshot 生成まで約83.7秒、その後の workspace checkpoint が約2.7秒。2件目はそれぞれ約75.2秒、約0.3秒だった。失効 event は workspace checkpoint 完了直後に記録されていた。
- 失敗後も optional な post-Git snapshot が約77秒動いたため、operation 全体は約160～173秒になった。主原因は recovery 待機や workspace checkpoint ではなく、Approved Sandbox child 起動前後に暗黙実行していた複数の Automatic Git Sandbox 起動だった。
- 同じ `data_dir` の `workspace_recovery_required` が成立する場合、worker は approval bundle 検証より前に `workspace_recovery_required` event を記録して停止する。対象2件の event 列はこの経路ではないため、先行する `recovery_required` の直接的な二次障害ではない。
- validity は `valid`、remediation decision は `proportionate-fix`。攻撃者による権限拡大や境界越えではないが、通常の一回承認で再現し、Approved Sandbox の中核機能を child 起動前に失敗させる可用性障害である。TTL 延長や fail-open ではなく、security／rollback に不要な任意 telemetry だけを外す小さい修正で解消できるため、残存 risk として受容しない。

### 修正と回帰検証

- Approved Sandbox は承認済み immutable projection と complete workspace checkpoint を維持し、child 起動前後の optional Git telemetry だけを実行経路から外した。Approved Host の Git telemetry、one-shot TTL、child 直前の expiry 再確認、workspace lock／checkpoint、Host への自動 fallback 禁止は変更していない。
- checkpoint の開始・完了、所要時間、file count、total bytes を audit event に追加し、今後の pre-child 遅延を Git telemetry と checkpoint で切り分けられるようにした。
- canonical `codex_sandbox` と旧 `approved_sandbox` alias の双方が Git telemetry を一度も呼ばず、workspace checkpoint 後に TTL freshness check を通って child を起動し成功する回帰、worker identity 再結合、既に失効した grant が child を起動しない対照試験: `4 passed in 6.45s`（通常 Windows user 文脈）。
- worker／Git snapshot focused suite: `17 passed in 7.35s`。変更ファイルの Ruff `--no-cache` と compileall: pass。
- Approved Host 統合は通常 Windows user 文脈で `5 passed, 3 failed`。失敗は WMI／descendant 経路の期待状態 `failed`／`succeeded`／`timed_out` に対して `running`／`failed` となったもの。今回の条件分岐は Approved Host では従来どおり Git telemetry を実行するため、この3件を本修正の合格根拠にも新規回帰の根拠にも数えず、別の未解決全体回帰として残す。
- 共有作業ツリー全体の pytest も実行したが、並行中の Automatic Git／WFP／Approved Host 変更を含む状態で50%までに多数失敗し、Windows 設定／ACL 系テストで CPU と生成物更新が約4分停止したため中断した。リポジトリ全体の合格状態とは扱わない。共有ツリー全体の Ruff `--no-cache` と今回変更ファイルの `git diff --check` は pass。

### 実機確認の境界

- 修正後の production `request_sandbox_command` を新しい人間承認で実行する clean-state Windows 実機 E2E は未実施。Codex Desktop の制限環境から入れ子の Sandbox を起動した結果を通常 host の実機証拠とは扱わない。
- ローカル回帰は原因となった呼び出しが child 前後に存在しないこと、必須 checkpoint と TTL fail-closed が残ることを確認したが、installed Codex／WFP／UAC を通る production child の起動成功そのものは次の明示的な実機再承認で確認する。

## 2026-08-30 Secure MCP Tunnel の失敗原因表示

### 変更内容

- `tunnel-client doctor --explain` の失敗を、単語 `profile` などの広い部分一致ではなく、`FAILED_CHECKS` の check 名を優先して分類するよう変更した。
- 画面には診断コード、失敗した check 名、doctor の終了コードを表示し、profile 読み込み、Runtime API Key、Tunnel ID、MCP command、health listener、OAuth metadata、control plane、未知の check を区別する。
- doctor の生の標準出力・標準エラーは診断結果、state、ログへ保持せず、Runtime API Key などの秘密情報が表示されない境界を維持した。
- LocalMCP 側の state/profile binding 失敗では、既存の `ReasonCode` と、秘密を含まない内部検出メッセージを表示する。Tunnel 失敗時の fail-closed と direct-server への自動 fallback 禁止は変更していない。
- `configure-localmcp.bat` の Windows PowerShell 環境で `Get-FileHash` を自動読込できない場合があるため、Tunnel client／profile の SHA-256 は PowerShell module に依存しない .NET `SHA256` で計算する。

### 回帰検証

- 通常の Windows user 文脈で Tunnel／launcher／PowerShell focused pytest: `39 passed in 24.25s`。
- 制限環境内の先行実行では `34 passed, 4 deselected`。除外した4件は、Credential Manager 書き込み1件と既存 `.bat` 読み取り3件が制限環境で拒否されたためであり、同じ4件を含む上記の通常 Windows user 実行では成功した。
- 新しい分類テストは、`profile-file` という語を含む API Key check が profile 異常へ誤分類されないこと、既知 check ごとの分類、未知 check の fail-closed、限定 fallback、doctor 生出力の非保持を確認した。
- v0.0.10 の `config_source` が `--profile-file` の `.yaml` suffix を要求するため、managed staging path も `.yaml` で終わることを回帰テストで固定した。`config_source` と `profile_load` は別の診断コードとして扱う。
- focused Ruff `--no-cache`: pass。変更した PowerShell 3ファイルの parser: pass。`git diff --check`: whitespace error なし（既存の改行コード warning のみ）。

### 外部接続検証の境界

- ローカル回帰検証は、実 Runtime API Key、OpenAI control plane、ChatGPT connector を通した接続成功の証明ではない。実 client による再試行では、表示された診断コード、失敗 check、終了コードを使って原因を切り分ける。
- 修正後の `configure-localmcp.bat` を通常の設定経路で再試行し、従来は一般文へ潰れていた最初の失敗が、Windows PowerShell 実行環境で `Get-FileHash` を利用できないことだと確認した。.NET `SHA256` へ変更後は同じ v0.0.10 client を受理し、Tunnel ID 検証を通過して Runtime API Key の非表示入力欄まで到達した。control plane を使う `doctor` は key 入力前のため未実行。
- ユーザーの key 入力を伴う次の再試行では `FAILED_CHECKS config_source`、終了コード `2` を確認した。v0.0.10 の公式実装は `--profile-file` path が `.yaml` で終わることを要求する一方、旧 staging path は `.yaml.tmp-<PID>-<GUID>` で終わっていたため、内容を読む前に拒否されていた。staging path 修正後の実 key／control plane 再試行は未実施。

## 2026-08-29 Secure MCP Tunnel onboarding／LocalMCP ランチャー統合

### 対象と仕様変更

- 対象 baseline: `09730fcb837d98532dc96ccc283a240f48de85f0`（`09730fc ランチャーのUXを改善`）。
- 初回セットアップで ChatGPT Secure MCP Tunnel の利用を任意に設定でき、設定後は `run-localmcp.bat` が Tunnel client と LocalMCP を一つの起動経路として扱うようにした。未設定・スキップ・無効化時は、従来どおり `run-server.ps1 -Config` による LocalMCP 単体起動を維持する。
- Tunnel ID は厳密な形式で検証し、profile は LocalMCP の専用 stdio command と完全一致する場合だけ採用する。既存 profile は内容を変更せず、安全に検証できるものだけ再利用する。
- runtime API key は Windows のユーザー資格情報領域（Credential Manager）へ保存し、profile、state、argv、launcher の標準出力・標準エラーへ平文を出さない。プロファイル・state・client の場所、hash、config binding、process identity を起動ごとに再検証し、不一致時は fail closed とする。
- managed profile／state の保存は staging、doctor、atomic replace、旧ファイル退避、credential/profile/state のロールバックを行う。Tunnel の起動失敗から LocalMCP 単体へ自動フォールバックしない。
- `SECURITY_CONTRACT.md`、Approved Host、Codex Sandbox、Automatic Git の境界は変更していない。

### 今回の回帰検証

- Tunnel／launcher focused pytest: `30 passed in 13.60s`。
- focused Ruff: pass（`tests/test_tunnel_integration.py`、`tests/test_local_launchers.py`、`tests/test_powershell_scripts.py`）。
- PowerShell parser: pass（`secure-mcp-tunnel.ps1`、`setup-localmcp.ps1`、`run-localmcp.ps1`、既存の主要 launcher）。
- Credential Manager の保存・読み出し・rotation・削除: Windows API を使った実行確認 pass。テスト出力への secret 混入なし。
- profile 生成、`channel: main`、canonical LocalMCP command、argv と child environment の secret 分離、state/profile binding、改変時 fail closed、既存 profile の安全な候補検出: pass。
- Python `compileall`: pass。`git diff --check`: whitespace errorなし（既存の改行コード変換 warningのみ）。

### リポジトリ全体検証の制限

- 全体 pytest（安定スナップショット）: `660 passed, 7 skipped, 1 failed`。失敗は今回の Tunnel 変更対象外の Approved Host 統合テスト `test_approved_host_terminates_descendants_at_runtime_limit` で、期待値 `timed_out` に対して `failed` が返ったもの。Tunnel focused suite は成功しているが、リポジトリ全体の合格状態とは扱わない。
- 全体 Ruff: pass。並行作業を含む現在の全体で確認した。

### Windows／外部サービス検証の境界

- Windows API レベルの Credential Manager 検証は実施した。
- この環境では `tunnel-client.exe`／`tunnel-client` を検出できなかったため、実 client の doctor／run、OpenAI control plane、ChatGPT 側の Tunnel 表示・tool refresh を通した本番相当 E2E は未実施。ローカル focused test の成功を Secure MCP Tunnel／ChatGPT の接続成功とはみなさない。
- 実機で残る確認は、公式 client の安全な配置後に、通常の Windows user 権限で `configure-localmcp.bat`（旧 `start-localmcp.bat` からも到達可能）の初回設定、`run-localmcp.bat` の ready 応答、ChatGPT 側の Tunnel／tool refresh、key rotation／無効化／再設定を一続きで確認することである。

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
- final command: authenticated pipe requester PID／create-time／SID／non-elevated token を検証し、`CreateProcessAsUserW` で suspended child を作成する。child を SYSTEM に昇格しない。
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

## 2026-09-21 ローカル起動・Approved Host・Sandbox 再検証

### `run-localmcp.bat` — PASS

ショートカットと同じ `run-localmcp.bat` → Windows PowerShell 5.1 → Tunnel → Program Files 運用用 runtime の経路を通常ユーザー文脈で起動した。数秒後にも親ランチャーは終了せず、次の process chain が継続していることを確認した。

- `run-localmcp.ps1`
- Program Files runtime の activity monitor
- approvals listener
- `tunnel-client run --profile-file ...`
- Program Files runtime の `windows_local_mcp.cli server`

同じ config の Tunnel が稼働中にショートカット相当の起動を再実行した。起動 mutex は取得できなかったが、固定済み tunnel-client 実体、同じ profile の process、loopback ready 応答を再確認し、終了コード0で「起動済み」となった。再クリック側は Runtime API Key を取得せず、追加の doctor process も起動しない。再実行前後の正規 tunnel-client process 数は1で、新しい process は作成されなかった。その後、最初の検証 process を `Ctrl+C` で終了して process 数0を確認し、修正後コードで停止状態から再起動して ready 応答まで到達した。

失敗時は batch が exit code を保持し、`WLMCP_NO_PAUSE=1` が指定されていない対話起動では画面を閉じずにエラーを確認できる。Tunnel／設定読み込みの失敗を direct server や別 execution boundary へ自動切り替えない。

### Approved Host normal path — PASS

- installer は wheel 導入後に `pip check` を必須化し、不整合時は同じ wheel を一度だけ再導入して再確認する。
- immutable runtime verification: PASS
- `WindowsLocalMCPApprovedHost`: Running / LocalSystem
- reviewed coordinated recovery: PASS
- recovery 後の独立した normal operation: PASS
- child authority: requester と同じ非昇格ユーザー
- LocalSystem monitor と durable authority state: runtime user から操作不可
- service epoch: operation 前後で同一

この回では abnormal worker-loss fault injection を再実行していない。過去の abnormal lifecycle 証拠を今回の再実行結果として扱わない。

### Codex Sandbox — FAIL CLOSED

自動選択 Codex `0.155.0-alpha.2.6` は、WLMCP の最小読み取りポリシーに対して ``elevated Windows sandbox requires effective `:root` read access`` で foundational command を開始できなかった。読み取り範囲を `:root` へ広げる変更は行っていない。

公式 npm 版 Codex `0.146.0` を正式設定へ一時指定した実機検査では、親側の filesystem／network／resource／WFP／brokered-process check は成功したが、次の必須境界が失敗した。

- `child_outside_user_read_denied=false`
- `grandchild_outside_user_read_denied=false`
- `descendant_containment=failed`
- `passed=false`

子プロセスは現在ユーザーではなく `CodexSandboxOffline` 専用ローカルアカウントで動作していたが、ユーザープロファイル直下の outside canary を読み取れた。失敗した `0.146.0` 固定は検証後に元の自動選択へ戻した。Sandbox route は unavailable、Approved Host への自動 fallback なしとする。詳細は `docs/SANDBOX_RECOVERY_2026_09_21.md` を参照する。

### Automated regression

- focused pytest: `111 passed, 2 skipped`
- 再クリック修正後の launcher／Tunnel／approval UI 対象 pytest: `38 passed`
- broader selected regression: `115 passed, 2 skipped, 2 failed`。2件は Approved Host audit operation が並行実行時に `running` のまま期限へ達した timing failure で、同 audit file の単独再実行は `8 passed`
- Ruff changed Python files: PASS
- `compileall src/windows_local_mcp`: PASS
- Windows PowerShell 5.1 parser（`run-localmcp.ps1`、`secure-mcp-tunnel.ps1`、`install-approved-host-runtime.ps1`）: PASS
- `git diff --check`: substantive error なし（既存の LF／CRLF warning のみ）

## 2026-08-31 Sandbox／Automatic Git の UAC 再試行抑止

通常の Sandbox／Automatic Git 起動では WFP Guard の確認を read-back のみに限定し、missing、不一致、読み取り不能のいずれでも自動昇格や自動再構築を行わず fail closed とする。WFP object の変更を許可するのは、operator が明示的に開始した `verify-codex-sandbox` の先頭で exact missing を確認できた場合だけである。管理者権限が必要な場合、この検証単位で WLMCP が開始する UAC は原則 1 回であり、同じ検証内の後続 probe は再昇格しない。

Codex Windows Sandbox 自身の初期セットアップが最初の固定 probe で失敗した場合は、その時点で後続 probe と Automatic Git の追加 probe を停止する。WFP の読み取り不能、identity／policy／binary／config mismatch など、exact missing と確認できない状態を「修復可能」と推測して再昇格することは禁止する。通常起動は Approved Host へ自動 fallback せず、明示的な再検証を案内する。

Automated verification:

- `python -m pytest -q tests/test_wfp_guard_runtime.py tests/test_sandbox_source_acl_verifier.py tests/test_git_broker_launch_gate.py --basetemp=.dev-tmp/pytest/uac-review-final`: `22 passed`
- `python -m pytest -q tests -k "wfp or sandbox or git_broker" --basetemp=.dev-tmp/pytest/uac-related-host`: `162 passed, 1 skipped, 547 deselected`（通常 Windows 文脈）
- `python -m ruff check --no-cache .`: PASS
- `python -m compileall -q src/windows_local_mcp`: PASS
- `git diff --check`: substantive error なし（既存の LF／CRLF warning のみ）

Full-suite limitation:

- 制限環境では `.bat` launcher の読み取りが `PermissionError` となるため、該当 launcher test は通常 Windows 文脈で再実行して PASS を確認した。
- full pytest は `tests/test_mcp_stdio_integration.py::test_saved_acl_config_starts_through_normal_launcher` で長時間応答がなく、同 test は通常 Windows 文脈の個別再実行でも 60 秒を超えて完了しなかったため中断した。この test と関連する `tests/test_mcp_stdio_integration.py`、`paths.py`、`server.py` の変更は、作業中に別処理が作成した current HEAD `604ec84` に含まれるが、本 UAC 対応の経路とは独立している。

Live verification limitation:

- 現在の Codex Desktop 内から入れ子の Windows Sandbox／UAC を起動した結果は通常 Windows host の実機証拠として扱わないため、UAC の実表示回数、再起動後、BFE／WFP state 消失後、実 Codex Sandbox helper の初回セットアップは未検証である。
- 通常 Windows PowerShell から明示 verifier を実行し、初回成功後の通常 Sandbox／Automatic Git 起動で追加 UAC がないこと、および再起動・WFP state 消失・binding 変更後に自動再昇格せず停止することを確認するまで、live verification verdict は `pending` とする。

## 2026-09-21 Sandbox 最小ポリシー互換性の追加調査

判定は **未解決／復旧条件未達**。表示修正を Sandbox の復旧完了として扱わない。

- 通常ユーザー・非昇格・非制限トークンの経路で、Program Files 配下の導入済み runtime による正式 `verify-codex-sandbox` を再実行した。Desktop `0.155.0-alpha.2.6` は固定コマンドで ``requires effective `:root` read access`` を返し、`verification_status=unverified`、`route_eligible=false`、`passed=false`。後続境界は未検証のまま保持した。
- 分離取得した署名済み公式 npm 安定版 `0.155.1` も、同じ最小ポリシーの固定診断で同じ拒否を返した。正式 marker や運用設定を候補用に置き換えていない。
- `0.153.4` の追加診断は設定読み込み中の filesystem replace 検査が `WinError 32` で停止し、時間を空けた再実行でも backend 実行へ到達していない。既知の `0.146.0` の子・孫 outside-user read 失敗、過去の `0.153.4` の成功記録とも今回の実測を混同しない。
- `request_sandbox_command` を実際の MCP から呼び、未検証 marker を理由とする登録前の拒否と監査 `rejected` を確認した。承認後の一回限りの実行、`poll_approval` の正常な結果、stdout、終了コード、正常終端監査は未検証。Windows local の正常実行 E2E と Secure MCP Tunnel／ChatGPT connector の正常実行 E2E はどちらも未達。
- 実装修正は `dependency_available`、現在の正式証拠に結合した `policy_compatibility`、全必須境界の実行 gate の分離。ポリシー非互換・未検証で `available=true` と表示しない。署名、helper、hash、stable identity、version、policy generation、Windows、WFP、TTL の binding と全既存実行 gate は維持した。
- 広い関連回帰: **263 passed, 2 skipped, 2 failed**。Sandbox、WFP、承認、Automatic Git、resource bound、descendant containment、server の対象を実行。失敗は `test_approval_execution_integration.py` の正常 snapshot と WMI 子プロセス検出で、期限時点の `running` と期待する終端状態の不一致だった。
- 対象を絞った再確認: **38 passed, 1 skipped, 1 failed**。先の2件は成功したが、同ファイルの `test_approved_host_allows_legitimate_descendant_to_finish` が `running` のままで失敗。承認統合テスト全体が安定して成功したとは主張しない。
- 最終の互換性・Sandbox architecture・残存リスク契約回帰: **62 passed**。変更した Python 4ファイルの Ruff `--no-cache`: PASS。`git diff --check`: エラーなし（既存の改行形式警告のみ）。各 pytest 実行は `.dev-tmp/pytest/turn2-*` の固有ディレクトリを使用した。
- 今回の変更は作業ツリーのみ。変更不能な運用 runtime へ表示修正を再配布しておらず、接続中 MCP の表示を修正済みとは主張しない。既存・並行作業の変更は維持し、コミットしていない。

原因、候補別証拠、次の選択肢は `docs/SANDBOX_RECOVERY_2026_09_21.md` を参照。

同日後続の `0.153.4` 候補診断では設定読み込みを通過したが、親・子・孫の outside-user read denial がすべて失敗し、`passed=false`。
通常 Windows user 文脈・導入済み runtime による `persist_evidence=False` の診断であり、正式 marker の更新や候補の運用採用はしていない。
証拠は `.dev-tmp/sandbox-native-implementation-20260921/candidate-01534.json`。正式 CLI の全工程、承認後 E2E、Tunnel／ChatGPT connector の正常実行 E2E の成功証拠とは扱わない。
OS は Windows 11 Home と確認した。Microsoft Windows Sandbox への方式変更は対応エディションまたは別仮想化製品の選択を必要とし、未実装・未検証。

## Historical verification record

WLMCP-R2-001 closure 前の詳細な repository-wide verification chronology は `VERIFICATION_HISTORY_PRE_R2_001_CLOSURE.md` を参照する。そこに記録された古い `LIVE VERIFICATION PENDING`、capability-reduction、Round 2 `unresolved / release blocker` 等は historical point-in-time evidence として保持し、上記 current verdict により supersede される。

<!-- CHATGPT_LIVE_TEST_PROGRESS_V1:BEGIN -->
## CHATGPT_LIVE_TEST_PROGRESS_V1

- run_id: `20260831T2250JST-chatgpt-live`
- test_definition_version: `CHATGPT_LIVE_TEST_V1`
- target_repository: `likefack/windows-local-mcp-python`
- tested_code_revision_baseline: `a09cf5372be147f46eb1f5a63e7cf4f64f659c7a`
- progress_document_commit: `d042752254c1c7549fcca70275d739b3d7301771`（直前の進捗コミット。現在更新はこの commit の後続）
- fixture_root: `.dev-tmp/chatgpt-live/20260831T2250JST-chatgpt-live`

| case_id | test_definition_version | status | tested_code_revision | main_tip_at_test | live_runtime_fingerprint | config_policy_fingerprint | executed_at | evidence_summary | operation_id または監査参照 | reusable | rerun_condition |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| CONN-01 | CHATGPT_LIVE_TEST_V1 | PASS_NONREUSABLE | target=a09cf5372be147f46eb1f5a63e7cf4f64f659c7a; runtime_revision=unverified | fb96dcc783dfc8104580770fcb2c5358ec93db9a | backend=openai-codex-windows-sandbox; provenance=openai-codex-desktop-install-root; exact WLMCP code revision not exposed | config_source=LOCAL_MCP_CONFIG; exact config digest not exposed | 2026-08-31T22:53:16+09:00 | ChatGPT connected MCP tool から実 Windows LocalMCP `session_info` が成功し、audit でも tier=broker/status=succeeded。stdio startup validation=accepted。runtime revision/config digest を target main に binding できないため reusable にはしない。 | session_info 0f911f52-d393-482b-8199-9636411daff3; audit_get same id | false | runtime revision と config/policy fingerprint を current main に結合できる識別情報を取得して再実行する。 |
| CONN-02 | CHATGPT_LIVE_TEST_V1 | PASS_NONREUSABLE | target=a09cf5372be147f46eb1f5a63e7cf4f64f659c7a; runtime_revision=unverified | ef2c4c19cf67bd3852fd35463a7e9cc1ff3635bc | backend=openai-codex-windows-sandbox; live marker stale; exact runtime revision not exposed | config_source=LOCAL_MCP_CONFIG; capability truthfulness observed; exact digest not exposed | 2026-08-31T22:57:32+09:00 | `session_info` を再取得。Codex Sandbox は configured/enabled/dependency_available=true と live_verified/windows_live_verified/execution_route_available=false を分離。Git は configured/enabled=true, available/live_verified/windows_live_verified=false。Approved Host は configured/enabled=true だが runtime_immutability failed により available/execution_route_available=false。ADB は configured/enabled=false。監査でも session_info 成功を確認。 | session_info 16f094fc-f45d-4e7e-9dfd-584ac0befc48; audit_get same id | false | current runtime revision と config digest を target code へ binding できる識別情報が得られれば reusable 判定のため再実行する。 |
| CONN-03 | CHATGPT_LIVE_TEST_V1 | PASS_NONREUSABLE | target=a09cf5372be147f46eb1f5a63e7cf4f64f659c7a; runtime_revision=unverified | 3af2a262219583de5ad12dff10d6b5548b9c783a | published surface metadata from active connector; exact runtime revision not exposed | current session capability states from session_info; exact config digest not exposed | 2026-08-31T22:59:00+09:00 | Active connector から 41 tools を再取得。ユーザー指定/current spec の 41 surfaces と一致し、欠落・余分なし。disabled ADB も surface は存在し capability は false と別表示。runtime revision binding がないため reusable にはしない。 | connector tool discovery; related session_info 16f094fc-f45d-4e7e-9dfd-584ac0befc48 | false | exact runtime revision を current main に binding できる状態で surface を再取得する。 |
| CONN-04 | CHATGPT_LIVE_TEST_V1 | PASS_NONREUSABLE | target=a09cf5372be147f46eb1f5a63e7cf4f64f659c7a; runtime_revision=unverified | d042752254c1c7549fcca70275d739b3d7301771 | workspace=C:\dev\decision-deck-localmcp-test; data_dir isolated; exact runtime revision not exposed | config_source=LOCAL_MCP_CONFIG; workspace_source=explicit_config; ambient_root_present=false; exact digest not exposed | 2026-08-31T23:02:43+09:00 | current `session_info` と audit を再取得。workspace/data directory は分離、config は LOCAL_MCP_CONFIG から explicit、ambient root は不存在かつ override=false。stdio configured/enabled/available=true・startup accepted。HTTP configured/enabled/available=false。表示上の暗黙 fallback は観測されない。runtime/config exact fingerprint を target main に結合できないため reusable にはしない。 | session_info 09f10c81-df4a-4e1b-97b0-2d6ce2f6a6e1; audit_get same id | false | exact runtime revision/config policy digest を得て同じ確認を再実行する。 |
| FS-01 | CHATGPT_LIVE_TEST_V1 | RUNNING | a09cf5372be147f46eb1f5a63e7cf4f64f659c7a | d042752254c1c7549fcca70275d739b3d7301771 | pending | pending | 2026-08-31T23:03:11+09:00 | 開始前記録。fixture root の存在可否を含め、list_directory/read_file の通常動作、UTF-8、行範囲、改行、行数、SHA-256 を実経路で確認する。 | pending | false | fixture と安全な既存テキストを read/list して監査と結果を確認する。 |
<!-- CHATGPT_LIVE_TEST_PROGRESS_V1:END -->
# 2026-09-21 Approved Host source-workspace 実行準備

- 非 code-loader の `source-workspace` と `workspace_write=false` で、存在しない `staged_cwd` を参照して child 起動前に失敗する問題を再現した。
- source／Git source mode は既存の入力照合を維持し、manifest と一致する元 cwd／引数を保持するよう修正した。承認説明の「実行用コピー」も実際の source mode に合わせた。token、Job、postflight、durable recovery の処理は変更していない。
- 修正後の対象回帰: **230 passed**。承認・入力改変拒否、既存 snapshot／Git、Approved Host、runtime installer、control-plane、timeout、異常終了、復旧を含む。追加回帰20件を含む。Ruff `--no-cache` は成功。
- 運用用成果物は現在の導入版を基準に `approval.py` と `risk.py` だけを変更し、依存パッケージの版も現在の導入版へ固定した。同成果物で承認・source mode・policy・authority state・recovery の **68 passed** を確認した。
- 管理者更新の UAC が「この操作はユーザーによって取り消されました」で終了し、インストーラーは未開始。既存ランチャーは稼働したままで、運用 runtime は未更新。修正後の Windows E2E は未完了。新しいローカル承認、child の通常ユーザー権限、標準出力、postflight、latch 解除、異常終了・復旧は今回の実機確認として未実施。[調査・検証記録](docs/APPROVED_HOST_SOURCE_WORKSPACE_2026_09_21.md) に再開手順を記載した。自動回帰を実機成功の代替としない。
- 後続の実機テスト指示により17:47 JSTに運用 runtime 更新を完了。導入後ソース照合と非昇格ユーザーの変更不能性検証が成功した。MCP `session_info` も新 digest `4e1de0f5ccc5c0388fd97b941be8ccdeb416c541965334d265d201103d62b8c3` に対し runtime／authority preflight 成功、`available=true`、`execution_route_available=true`。新規の読み取り専用承認 `4c711aa2-a394-4401-b427-18a460764a7b` はローカル承認待ちであり、修正後 E2E 成功の判定はまだ行わない。
- 同承認を18:08:43 JSTにローカル承認。元のcwd欠損は解消してbundle検証を通過したが、事前検証完了まで約118秒かかり、実行承認期限60秒を超えたため最終状態は **expired**。child未起動、終了コードなし、標準出力0バイト。終了後のauthenticated authorityはhealthy／activeなし、ユーザー側tamper／postflight markerもなし。180秒設定で再申請するか60秒維持で高速化するかはユーザー判断待ちで、設定・期限チェックは変更していない。E2E成功、child権限、正常child postflight、worker-loss／復旧の実機検証完了とは扱わない。
- ユーザー許可で運用設定の承認後実行期限を180秒に変更し、運用 runtime の読み込みと再起動後のruntime／authority事前確認を再検証した。続くMCP申請3件はいずれも人が承認。1件は制御面容量上限で安全に拒否され、今回の終了済み申請3件の一時入力だけを整理して上限を変えずに解消した。残る2件はbundle・checkpoint・制御面guardを通過後、要求元PID不在で子プロセス作成前に失敗した。直近失敗後に承認UIプロセスは存在しなかったが、終了の正確な時点・理由は未確定。`docs/APPROVED_HOST_RUNTIME.md`のserviceによるtoken複製という記述と、workerが子起動直前に複製する現行実装の不一致を発見し、どちらを正とするか利用者に確認中。今回の読み取り専用Approved Host E2E、child権限、正常postflight、異常終了・復旧の実機確認は引き続き未完了。[操作別の監査結果](docs/APPROVED_HOST_SOURCE_WORKSPACE_2026_09_21.md)を参照。
- 利用者は上記の不一致について、service が検証時に通常ユーザー token を保持して SYSTEM worker へ安全に渡す方針を仕様として選択した。開いた requester process HANDLE の作成時刻、SID／非昇格／primary token、明示的な継承 HANDLE list、worker の token 再検証と一度限りの使用へ実装を変更した。要求元終了後の token 継承の Windows 回帰と service の capture-before-arm／handle-list 回帰は実施中。更新後の運用 runtime による child／postflight／復旧の実機確認前に release-level 完了とは扱わない。
- 上記3ファイルを運用 runtime へ更新し、導入後 SHA-256 照合と runtime／authority preflight 成功を確認した。MCP 読み取り専用申請 `6b39baf2-8f64-4470-8f90-699e8920160c` は人による承認後、`poll_approval`／監査で `succeeded`、終了コード0、child PID 58824、stdout に通常ユーザー SID の `whoami /user` 結果を確認。別の実機観測で同じ PID の SID と非昇格を確認した。`postflight_error=null`、再接続後の authority は同じ epoch で healthy／active なし、user-owned tamper／postflight pending marker なし。関連回帰42件成功。操作後に Tunnel／MCP server は停止して HTTP 504 となったが、LocalSystem service は Running、監査結果は成功のままだった。Tunnel 再起動後に MCP `poll_approval` から成功結果を再取得した。Tunnel 終了原因と、今回変更した token 境界の abnormal／recovery 実機 fault injection は未確認。[詳細](docs/APPROVED_HOST_SOURCE_WORKSPACE_2026_09_21.md)。
- 再起動後の `run-localmcp.bat` 再クリックで端末が即閉じる事象を実機で再現した。既存 Tunnel と loopback ready は正常で、PowerShell／バッチの終了コードは0だった。失敗時だけ `pause` するバッチ分岐が原因である。正常に処理が戻った場合も、対話起動では結果を読めるまで待つよう変更した。修正後の対話型再クリックは「起動済み」を表示してキー入力まで5秒以上継続し、入力後に終了コード0。既存 Tunnel を停止してから同バッチで新規起動すると local ready 成功、端末は稼働継続、MCP `session_info` は Approved Host の runtime／authority preflight 成功、`available=true`、`execution_route_available=true`、active operation なしを確認した。`WLMCP_NO_PAUSE=1` の自動実行経路は再クリック後も終了コード0で即時返却。ランチャー回帰21件成功。停止原因の再現・特定や token 境界の abnormal／recovery 実機確認とは区別する。
- 上の「結果表示後にキー入力待ち」だけでは、利用者が求める起動状態を回復できなかった。既存 Tunnel が健康な場合、再クリック側は正常終了せず同じ Tunnel の process HANDLE を待ち、承認画面の自動起動設定が有効なら選択済みの Program Files runtime から承認画面を開き直すよう修正した。MCP server／Tunnel を重複起動せず、ready と process identity が不明な状態は従来どおり拒否する。非対話の `WLMCP_NO_PAUSE=1` は健康確認後に即時0を返す。通常ユーザーの対話型バッチで再クリックした実機試験では、端末が継続し承認画面の PowerShell／Python が起動、Tunnel PID は不変で1個だった。デスクトップの実ショートカットからも通常ユーザーの端末と承認処理が継続し、MCP `session_info` は `available=true`／`execution_route_available=true`、runtime／authority preflight 成功、active operation なし。ランチャー回帰21件成功。Codex の対話端末から開始した試験用承認画面では Ctrl+C 後に `CloseMainWindow()` が終了を確認できず、試験用の正確な子孫 PID だけを照合して終了した。実デスクトップ画面が利用者に表示されているかはプロセス検査だけでは確定しないため別途確認する。
# ChatGPT 添付取り込みの検証（2026-10-06）

`artifact_import_file` と公式 `openai/fileParams` の接続を追加した。設計・設定・
operatorが受容した会話所属検証の限界は [添付取り込み](docs/CHATGPT_ATTACHMENT_IMPORT.md) を参照。
既存の512 KiBチャンク既定値を下げず、Base64文字数のdecode前検査とToolError識別を追加した。

主担当が通常Windows環境・Python 3.13.15／MCP SDK 2.1.1で以下を独立実行した。
制限環境では `.dev-tmp` 作成がWinError 5になったため、ACL変更を行わず通常環境で再実行した。

```powershell
.venv/Scripts/python.exe -m pytest tests/test_attachment_import.py tests/test_attachment_import_server.py tests/test_artifact_transfer_errors.py tests/test_artifact_fast_path.py tests/test_binary_transfer_lifecycle.py tests/test_transfer_timeline.py tests/test_high_level_operations.py tests/test_structured_files.py tests/test_structured_resource_admission.py tests/test_config.py tests/test_config_binding.py tests/test_audit.py tests/test_windows_transaction.py --basetemp=.dev-tmp/pytest/attachment-final-20261006
```

- **176 passed、4 skipped、2 failed、68.50秒**。追加した添付取得58件、添付保存12件、転送5件はすべて成功。
- 数百KBのPillow生成JPEGを、合成HTTP応答から実取得処理・実保存処理まで通し、保存バイト列と元ハッシュの一致を確認した。元の名刺画像は未提供であり、その実ファイルの検証ではない。
- 実ローカルMCP stdio ClientSessionで、乱数相当512 KiB・Base64 699,052文字をupload／commit／downloadし、全バイトとSHA-256の一致を確認した。512 KiB+1は同じBase64文字数でもraw上限で拒否した。
- 不正参照、非公開IP、DNS再解決回避、HTTPS証明書検証設定、リダイレクト、曖昧なHTTP framing、受信中上限超過、途中切断、形式矛盾、SHA不一致を確認した。
- 保存先検証、既存CAS、取得中の競合、checkpoint、書き込み後障害の自動回復、未完了ダウンロードの未確定を確認した。
- 正常／拒否時の監査、およびSDK引数検証エラーでURLやBase64本体が露出しないことを確認した。必須path欠落時のSDKによる入力全体の表示も抑止した。
- 4 skippedはシンボリックリンク作成に必要な権限がない環境での既存設定テスト。
- 2 failedは変更していない `test_windows_transaction.py` のコピー／移動先作成競合テスト。単独再実行でも同じ2件が失敗した。別の限定診断では `_before_commit` の競合側 `destination.write_bytes` 自体がOSErrorとなり、元ファイルは不変、保存先は存在しなかった。テストが期待する「競合側のファイルが残る」と一致しない。関連実装 `windows_transaction.py` と当該テストは変更しておらず、今回の添付経路もコピー／移動関数を使わない。この既存テスト結果を成功扱いにしたり、テスト期待値を緩めたりしていない。

変更箇所のRuffは一度すべて通過した。その後の最終確認中、別タスクによる
`server.py` の `transfer_receipts` 関連変更と `artifact_errors.py` の追加変更を検出した。ユーザーが並行作業を確認し、
その変更を保持して本作業を仕上げるよう指示したため、上書きしていない。
上記テスト結果は実行時点のものであり、その後の並行変更を含む最終統合状態の成功を保証しない。
並行編集中の静的検査では一時的に `ArtifactTransferNotFoundError` の重複定義も観測したが、
その後の読み取りでは解消していた。本作業からは編集していない。

未検証: 実ChatGPTが渡す添付参照、実配信ホストの特定・TLS取得、OpenAI Tunnelを含む往復、
運用immutable runtimeへの配備・再起動・ツール再登録、当該会話への所属の独立検証。
許可ホスト設定は空のまま維持した。自動テストの合成応答や外部authority検査のstubを、
実ChatGPT／本番運用・SCM／WFP／Approved Hostの検証とみなさない。

## バイナリ転送の再送・状態照会・期限分離（2026-10-06）

- 新規uploadに永続受信記録を追加し、同一チャンクの冪等再送、内容不一致の拒否、再起動後の再開を確認した。記録領域を事前予約し、通常チャンクのquota全走査を増やしていない。
- `artifact_transfer_status` はmanifest／workspaceを変更せずに状態を返す。`binary_transfer_ttl_seconds` は既定1800秒、30〜86400秒で、承認期限と終端retentionを分離した。
- チャンクの既存Base64事前上限を維持し、正規形検査とone-shotの文字数先行検査を補強した。512 KiB／699,052文字は実MCP stdioで成功。プロセス再起動後のstatus・再送・commitも成功した。
- 転送関連の最終回帰は **250 passed, 6 skipped**。スキップはWindowsのシンボリックリンク作成権限不足。性能試験は **5 passed**。変更箇所のRuffと差分空白検査も成功した。
- download開始は前後とも論理読込3N・コピー書込N。安全性を保ったI/O削減の根拠が不足しており、処理は維持した。測定値から高速化達成とは判定しない。
- 全体テストはランチャー起動試験で待機し900秒で打ち切った。その後の未完了範囲は **520 passed, 4 skipped, 2 failed, 1 deselected**。残る2失敗は変更していないWindows transactionのcopy／move競合試験で、独立再実行でも再現した。初回の転送manifest競合は修正済み。他領域5失敗は独立再実行で成功したが、全体成功とは扱わない。
- fileParamsによる既存添付取り込みを追加検証した。許可配信ホスト設定、運用runtime配備、実ChatGPT／Tunnelの添付E2Eは未実施。通常ChatGPTへの直接exportを成立させる正式な配送形式を確認できず、独自方式は追加していない。

条件・全コマンド・区間別性能・失敗の切り分け・未検証範囲は [検証記録](docs/BINARY_TRANSFER_VERIFICATION_2026_10_06.md)、利用方法と仕様は [転送の復旧仕様](docs/BINARY_TRANSFER_RESUME.md) を参照。

## 2026-10-06 決定済みファイル操作の一括実行・CAS内部化・完全一致置換

`workspace_batch`、`workspace_replace`、`workspace_plan_apply` を追加した。仕様と判断理由、変更ファイル、再現手順は [決定済みファイル操作](docs/DETERMINISTIC_WORKSPACE_OPERATIONS.md)、3標本の比較結果は [測定JSON](docs/DETERMINISTIC_WORKSPACE_BENCHMARK_2026_10_06.json) に記録した。

- 新規テストは分割実行で62成功・1保留。最終統合27件、計画処理35件が成功。シンボリックリンク作成権限不足1件を保留し、Windowsの実junctionとハードリンクの拒否は確認した。
- 広い対象回帰は182成功・5保留・既存2件分離、初期化WinError 5で3失敗。失敗対象の別一時フォルダーでの再試験は4成功。最終レビュー後の関連回帰と故障注入も再確認した。詳細と中間失敗の扱いは上記文書を参照。
- Windowsコピー／移動の保存先競合テスト2件は、一括操作の実装時には未変更・未解決として今回の成功数に含めなかった。その後の追跡調査でテストの前提誤りを修正した。次節の結果を参照。
- 添付取り込み・チャンク再送・再開等との互換性は113成功・1保留。並行artifact変更を上書きせず、同じcheckoutで共存を確認した。
- 最終実装のローカル比較で、batchは5呼出→1呼出、検索・置換は3呼出→1呼出。生SHA-256の転記はそれぞれ128文字→0文字、256文字→0文字。処理全体の中央値は889.248ms→431.279ms、779.741ms→639.491ms。既存の詳細フェーズ上限を維持し、最終の監査・性能テスト8件も成功した。
- 実行は合成workspaceのBroker経路で、外部authority確認はテスト用に置き換えている。実ChatGPT/Tunnelの通信・LLM生成時間、運用runtimeの配備・再起動、SCM/WFP/Sandbox/Approved Hostの実機受容を証明するものではない。

## 2026-10-06 Windowsコピー・移動の保存先競合テストの追跡修正

- 過去に分離していた2件は、TxFによる名前予約後の競合側ファイル作成が成功するというテストの前提誤りだった。競合側の例外を本体全体の `pytest.raises(OSError)` が捕捉し、作成されなかったファイルの存在を要求して失敗していた。
- 通常Windowsプロセスで競合側の `CreateFileW` がエラー6800（`ERROR_TRANSACTIONAL_CONFLICT`）となることを確認。競合側の拒否を適切に扱うとコピー・移動本体は成功し、内容と識別情報も期待どおりだった。保存先を先に作られる条件でも第三者ファイルは保持された。
- 対象2テストを修正し、ファイルHANDLEを閉じてからcommitするまでの保護、保存先確保前の衝突、コールバック例外時の復元と再実行を追加した。実行ロジック・CAS・権限・復旧仕様は変更せず、実装側はコメントのみ訂正した。
- トランザクション試験全体は **15 passed**。対象2件を除外しない関連回帰は **105 passed, 1 skipped**。Ruff（キャッシュなし）と差分の空白検査は成功。過去の失敗記録は当時の結果として保持する。
- このPCの通常Windows/NTFS上で合成データを使用した。全リポジトリ、他のWindows環境、実ChatGPT/Tunnel、Approved Host/Sandboxの実機受容を検証した結果ではない。

原因・根拠・変更ファイル・再実行コマンドは [保存先競合の調査記録](docs/WINDOWS_TRANSACTION_DESTINATION_RACE_2026_10_06.md) を参照。

## 2026-10-06 Live Activityの完全差分・所要時間・操作IDによる変更取得

局所操作の完全差分、非テキスト変更の概要、実行中の経過時間と完了時の所要時間を追加した。
高水準操作は概要表示とし、`operation_changes` で変更一覧・完全差分・変更前後のバイト列を
ページ取得する。`operation_report` に操作IDによる承認付きUndo／完了時点への復元の
呼び出し情報を追加した。仕様は [Live Activityの変更表示](docs/LIVE_ACTIVITY_CHANGES.md) を参照。
過去の「差分を表示しない」という受容記録は当時の仕様であり、今回の表示要件は同文書に従う。

通常Windows環境のリポジトリ内 `.venv` で、主担当が次の既存機能回帰を実行した。

```powershell
$env:PYTHONIOENCODING='utf-8'
.venv/Scripts/python.exe -m pytest tests/test_timeline_and_rollback.py tests/test_high_level_operations.py tests/test_structured_files.py tests/test_filesystem_primitives.py tests/test_server_operations.py tests/test_deterministic_workspace_operations.py --basetemp=.dev-tmp/pytest/live-activity-regression-20261006-01 -q
```

- **129 passed, 2 skipped、107.57秒**。履歴・取り消し・高水準操作・構造化変換・基本ファイル操作・一括操作の回帰を確認した。スキップ2件は成功数に含めない。
- 表示・変更取得API・発行元表示の統合テストは以下の実行で **124 passed, 1 failed、19.55秒**。失敗1件は初期化時の既存ファイル置換確認が `WinError 5` となり、改変検出本体に到達していなかった。その1件を検査や実装を変更せず独立実行し、**1 passed、0.40秒**。125件は分割実行で成功を確認した結果であり、単一実行の全成功とは記録しない。

  ```powershell
  $env:PYTHONIOENCODING='utf-8'
  .venv/Scripts/python.exe -m pytest tests/test_operation_changes_server.py tests/test_operation_changes.py tests/test_live_activity_changes.py tests/test_live_activity.py tests/test_live_activity_operation_id.py tests/test_origin_views.py --basetemp=.dev-tmp/pytest/live-activity-integration-20261006-05 -q
  .venv/Scripts/python.exe -m pytest tests/test_operation_changes.py::test_same_size_blob_tamper_is_rejected_before_return --basetemp=.dev-tmp/pytest/live-activity-tamper-20261006-01 -q
  ```

- 保存プレビューを超える完全差分、後続手動変更の混入防止、非テキストの変更前後バイト列、UTF-8をまたぐページ境界、名前空間・ハッシュ・許可パスの検証、欠落記録、承認前に変更を戻さないこと、200件を超える集計、変換開始前の操作表示、待機時間の分離、表示の抑止・再開・重複防止を確認した。
- 変更対象のRuff、Python構文検査、差分の空白検査は成功した。
- 開発中、並行する時間計測タスクのフェーズ登録待ちによりテスト読込が停止した。そのタスクの修正後に実行した結果を上記に記載した。時間計測と発行元表示の並行変更は保持した。
- 制限環境の一時ディレクトリ作成は `WinError 5` となったため、ACLを変更せず承認された通常Windows環境で再実行した。
- 検証は合成データと保存済みチェックポイントを使う自動テスト。実承認画面の操作、実ChatGPT／Tunnel経由の新ツール取得、運用runtimeへの配備・再起動は未実施。既存のローカル承認・競合検知・復旧経路は維持し、通常ユーザーの承認操作を自動テストで代替したとは扱わない。
- 本文ページ取得は対象内容全体のハッシュ検証、差分の再生成を行う。大容量ファイルを小ページで反復取得する場合の処理量は残る。チェックポイント保存期限後の完全取得は保証しない。

## 添付取り込みの実接続復旧とホスト診断（2026-10-06）

- 添付取り込み3テストファイルと追加診断テスト: **83 passed in 10.02s**。通信は合成。DNSホスト名だけを返し、署名URL・ファイルIDを表示せず、監査にはホスト名も保存しないことを確認した。
- 運用版の欠落依存5件を同じ版へ復元。`pip check` 成功、既存サービスRunning、実接続の通常ファイル操作復旧を確認した。診断2ファイル以外の既存2,587ファイルは復旧前のハッシュを維持。変更不能性と認証付きauthority接続の検査も成功した。
- 実添付で観測した正確な配信ホスト1件を設定し、画像の直接取り込みに成功。元添付と保存先はともに198,917バイトで、PowerShellによる独立したSHA-256計算も一致。成功した呼び出しは10,331ms。別経路との最速比較ではない。
- 依存を消失させた操作は未特定。再接続中に監査未到達のタイムアウトが1件あり、その後の再試行で成功した。別ホスト・別クライアント・Approved Hostの承認後実行と異常終了回復は今回再検証していない。
- 原因、配備範囲、運用設定、成功operation_id、復旧時の制約は [調査・復旧記録](docs/ATTACHMENT_IMPORT_RECOVERY_2026_10_06.md) を参照。

## 添付参照の拒否診断とクライアント実体化（2026-10-06）

今回の変更は `ATTACHMENT_REFERENCE_REJECTED` の診断追加とツール説明の明確化である。
受理条件、fileParams schema、既存upload、Broker／Sandbox／Approved Hostの境界は変更しない。
検査層・入力分類・拒否理由・期待形式を固定ラベルで返し、入力のURL・ID・名前・未知キーを
エラーや監査へ転記しない。仕様・発生条件・未確認範囲は [調査記録](docs/ATTACHMENT_REFERENCE_INVESTIGATION_2026_10_06.md)。

主担当が通常Windows環境で実行した最終回帰:

```powershell
$env:PYTHONIOENCODING='utf-8'
.venv/Scripts/python.exe -B -m pytest tests/test_attachment_import.py tests/test_attachment_import_server.py tests/test_attachment_import_additional.py tests/test_attachment_import_host_diagnostic.py tests/test_attachment_reference_diagnostics.py tests/test_attachment_transfer_benchmark.py tests/test_artifact_transfer_errors.py tests/test_artifact_fast_path.py tests/test_transfer_resume.py tests/test_transfer_receipts.py tests/test_binary_transfer_lifecycle.py --basetemp=.dev-tmp/pytest/ar-final -ra
```

- **217 passed、2 failed、1 skipped、61.57秒**。失敗2件は初期化時のファイル置換が `WinError 5` となり、検査本体に未到達だった。スキップはシンボリックリンク作成が利用できない既存試験1件。
- 失敗2件と、日本語の元添付名も確認するよう強化したPNG保存試験を、検査・ACLを変えず別の専用パスで再実行し **3 passed、1.71秒**。219件の成功を分割実行で確認した。一括実行の全成功とは記録しない。
- 新規診断41件は入力分類、全拒否理由、MCP応答・監査の秘匿、拒否時の通信／保存未到達、PNG保存、日本語と空白を含む名前を確認する。新規測定2件は実JPEG／PNG、複数チャンク、最後の短いチャンク、保存・前後チェックポイント・ハッシュ、本文非出力、画像生成の再現性を確認する。
- 既存試験でJPEG保存、同名保存先のCAS、取得中の保存先変更、workspace外・path traversal、改ざん、hash mismatch、サイズ制限、通信中断時の非変更性、既存uploadの再送／再開／整合性／保存回帰を確認した。
- 制限環境では一時ディレクトリとRuffキャッシュの作成が拒否された。ホスト環境で再実行し、ACL・ownerや検査を変更していない。Ruffと差分の空白検査は成功。
- 測定用の深い一時パスでは子プロセスが失敗したため、測定スクリプトのディレクトリ名を短縮した。長い専用basetempで測定2件の成功も確認した。製品のBroker保存・チェックポイント処理は置き換えていない。

限定再実行:

```powershell
$env:PYTHONIOENCODING='utf-8'
.venv/Scripts/python.exe -B -m pytest tests/test_attachment_import_additional.py::test_size_limit_failure_audit_omits_url_file_id_and_body 'tests/test_transfer_resume.py::test_invalid_or_noncanonical_base64[\u3042-INVALID]' tests/test_attachment_reference_diagnostics.py::test_mcp_fileparams_schema_and_real_png_save_with_japanese_and_spaces --basetemp=.dev-tmp/pytest/ar-recheck-host -q
```

実Codex／MCP／HTTPS取得経路で、非機密の161バイトPNG、4,183,461バイトJPEG、4,193,968バイトPNGを
各1回の取り込みで保存した。JPEGの保存先は日本語と空白を含む。取得元ハッシュを指定し、
応答と保存先の独立した `Get-FileHash` が一致した。呼び出し全体は2,547ms／6,293ms／7,437ms。
新規診断は運用版へ未配備なので、これは変更前の直接取り込み経路の成功証拠である。
元ChatGPTセッションの添付JPEGや変換後参照は取得できておらず、その変換内容を断定しない。

最終性能測定は `scripts/benchmark_attachment_transfer.py --samples 1` の12ケース。
実画像・SDKクライアント・Broker保存を使い、DNS／HTTPSとhealth確認は合成。約4MiBのJPEGは
直接取得555.14ms／1呼び出し／本文Base64 0文字、分割upload1,177.36ms／10呼び出し／5,577,960文字。
両方式とも本文はクライアントプログラム内に保持し、モデルへ展開していない。
Python追跡対象の最大割り当ては13.49MiB／15.37MiB、RSS増加の観測値は11.32MiB／16.65MiB。
実通信・LLM・ChatGPTの速度比較ではなく、計測負荷・OSキャッシュを含む単一観測である。
測定中に並行変更を検出した回は採用せず、開始・終了の全Pythonソースハッシュが一致した回だけを採用した。
原データと条件は `.dev-tmp/attachment-reference-20261006/benchmark.json`。

保護された運用runtime、許可ホスト設定、承認サービス、回復状態は変更していない。
会話所属の独立証明、元ChatGPTクライアントでの3失敗の再現、運用版の新診断は未検証。
検証用に今回作った3画像は設定済みworkspaceに残した。小PNGの削除呼び出しの成功は確認できなかった。
