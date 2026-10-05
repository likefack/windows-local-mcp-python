# Approved Host の source-workspace 実行準備の調査

## 調査対象

2026-09-21、承認 ID `39c8aced-3007-4389-be0b-0562e758c092` を MCP の
`audit_get` で再確認した。対象は `C:\Windows\System32\whoami.exe /user`、
`cwd=.`、`workspace_write=false`、`network_required=false`、実行上限30秒。
接続先 workspace は `C:\dev\decision-deck-localmcp-test`。

監査記録ではローカル承認と一度限りの claim、runtime の変更不能性検証、authority
service の検証、LocalSystem worker の起動まで成功している。child PID、終了コード、
標準出力はなく、実行準備が存在しない `approval-inputs/<operation>/cwd` の解決に失敗した。

## 原因と修正方針

`src/windows_local_mcp/approval.py` の `prepare_approval_bundle()` は非 code-loader
について `source-workspace` を選び、承認時入力を `workspace` へコピーする一方、
実行コマンドの cwd と引数は元の値を保持する。`staged_cwd` は作成しない。
`worker.py` は読み取り専用の Approved Host も `verify_approval_bundle()` の後で
`materialize_execution_copy()` へ渡す。同関数が `staged_cwd` の欠損を `cwd` コピーの
存在と取り違えるため、実コマンドより前に失敗する。

`SPEC.md` の Source-write mode は非 code-loader の Approved Host に Sandbox と同じ
source-read isolation を主張しない。一方、`src/windows_local_mcp/risk.py` は
`workspace_write=false` の Host を `staged execution copy` と説明し、この説明は
今回の承認記録にも含まれる。ユーザーの続行指示を受け、検証済みの元 cwd／引数を
保持し、承認説明を訂正する方針を採用した。

実行準備は `source-workspace` と `git-state-source-workspace` を明示的に判別し、
コマンドが manifest の実行内容と一致することを確認して保持する。入力の検証は
引き続き `verify_approval_bundle()` が先に実施する。書き込み指定だけを根拠にした
検証省略は追加しない。その他の snapshot mode、LocalSystem／通常ユーザー token、
Job、postflight、durable recovery の実装は変更しない。

## 調査時の検証

- 追加回帰13件を主担当が再実行: source の root／nested cwd、書き込み指定の有無、
  Git source mode、相対／絶対／外部入力を含む7件で同じ `FileNotFoundError` を再現。
  workspace／実行ファイル／外部入力／manifest／設定／環境の変更拒否6件は成功。
- 既存の approval、Git staging、Approved Host policy、authority state、recovery の
  48件は通常 Windows 文脈で成功。Sandbox 内では SCM 照会が `sc.exe exited with 5`
  になった2件を、同じ境界を維持したまま通常文脈で再確認した。
- 承認、control-plane、authority、runtime installer、正常／異常／復旧関連の
  広い既存回帰は161件成功、timeoutの1件が失敗。テストの監査記録では
  `approved_host_untracked_process_detected` により postflight が安全側で拒否され、
  `control_plane_tamper_unknown` になった。単独再実行は成功。本体修正前の結果であり、
  同時実行時の安定性まで確認できたとは扱わない。
- 新規テストの Ruff `--no-cache` と `git diff --check` は成功。
- 現在の MCP `session_info` は runtime／authority preflight が成功し、
  `available=true`、`execution_route_available=true`、active operation なし。
  これは修正後のコマンド実行成功を示すものではない。
- 通常 Windows 確認用シェルは承認者のユーザー SID、非昇格。
  Program Files 内の `approval.py` と開発版は調査時点で同一 SHA-256
  `8e55fad3c9b3b56f18a0e187079e1864421f020110f9779eac7cb84228b2052f`。

作業開始時の差分、既存変更15ファイルのコピーと SHA-256、テストログは
`.dev-tmp/approved-source-fix/` に保存した。コミットは行わない。

## 修正後の自動回帰と導入成果物

- `tests/test_approval_source_materialization.py` は20件成功。既知の欠損 cwd、root／nested
  cwd、書き込み指定、Git、相対／絶対／外部入力、改変拒否、materialize 時のコマンド
  不一致拒否、承認説明を検証した。
- 主担当が関連回帰をまとめて再実行し **230 passed**。承認、Host policy、runtime、
  installer、control-plane、timeout、異常終了・復旧、既存 snapshot／Git を含む。
  コマンドと出力は `.dev-tmp/approved-source-fix/fixed-regression.log` を参照。
- 対象 Python ファイルの Ruff `--no-cache` は成功。
- 再開時に他作業の変更が増えていたため、再開時差分も保存した。導入成果物は
  既存 Program Files package のコピーに今回の `approval.py` と `risk.py` だけを
  重ね、その他のソースと運用スクリプトを現在の導入版に維持した。既存依存36個の
  バージョンも固定した。この成果物で対象 **68 passed** を確認した。
- 事前レビュー用 wheel の SHA-256:
  `be139db27e03255861bd3b788a916be407692620a14df25f45f10fd481e367a2`。
  管理者インストーラーは同じレビュー済みソースから wheel を作成し、導入前後に
  ソース SHA-256 を照合する。既存 active／recovery latch がある場合は更新しない。

## 未完了の確認

管理者更新を Windows UAC 経由で開始したが、`この操作はユーザーによって取り消されました`
で終了した。インストーラーの実行ログ／完了記録は作成されず、元ランチャー
PID 37464 の継続を確認した。運用 runtime は今回の修正をまだ含まない。
UAC の自動再試行、runtime の ACL 緩和、承認の自動化は行わない。

### 2026-09-21 実機テスト再開

ユーザーの実機テスト指示で更新を再開し、17:47 JST に管理者インストーラーで
Program Files runtime の更新を完了した。更新補助スクリプトの PowerShell 5.1 の
JSON 配列扱いと、親終了時に子が消える競合を修正した。製品の承認・監視境界は
変更せず、停止対象は PID／作成時刻／実行ファイルを確認し保持した handle で扱った。
導入後の全ソース指紋の照合は成功し、導入前との差分は `approval.py` と `risk.py` のみ。

非昇格ユーザーによる `verify-approved-host-runtime.ps1` は成功した。
新 runtime digest は `4e1de0f5ccc5c0388fd97b941be8ccdeb416c541965334d265d201103d62b8c3`。
接続を継続セッションで再起動した後の MCP `session_info` は runtime／authority
preflight 成功、`available=true`、`execution_route_available=true`、active operation
なし。service epoch は `f439005a7bffc5f9bdadfb48d9d7d7435e49060e636f8603e24dd0c67e86f309`。

MCP から `whoami.exe /user` を元と同じ cwd、書き込みなし、通信要求なし、上限30秒で
再申請した。新承認 ID は `4c711aa2-a394-4401-b427-18a460764a7b`。
現時点は `pending_approval`。ローカルユーザーへ承認操作を依頼しており、
実コマンドの child、終了コード、標準出力、postflight／正常完了はまだ未確認。
通常ユーザーの読み取り専用 token 観測も開始したが、別プロセスの観測をこの承認の
child 証拠として転用せず、監査の child PID と作成時刻が一致する記録だけを採用する。

### ローカル承認後の実機結果: 期限切れで起動拒否

同承認は18:08:43 JSTにローカルユーザーが承認し、最終状態は `expired`。
修正した materialization と `approval_bundle_verified` は通過したが、必須事前検証が
設定済みの `approval_execution_ttl_seconds=60` を超えたため、起動直前に
`approval execution grant expired before child start` で拒否した。
child PID、終了コードはなく、標準出力は0バイト。E2E成功とは判定しない。

| 監査時刻（JST） | 確認内容 |
| --- | --- |
| 18:08:43.267 | ローカル承認と一度限りのclaim |
| 18:09:20.591 | runtimeの変更不能性検証成功 |
| 18:09:20.608 | authority検証成功 |
| 18:09:20.766 | authority-separated worker起動 |
| 18:09:25.530 | approval bundle検証成功 |
| 18:09:35.206–18:09:38.184 | workspace checkpoint（330ファイル、約13.9 MB） |
| 18:10:40.514 | control-plane guard準備完了（5,619ファイル、258,494,068バイト） |
| 18:10:41.276 | 起動直前の承認期限チェックで拒否 |
| 18:11:11.118 | worker終了 |

実機の設定項目は5～600秒を許容し、現在は既定値の60秒。
承認から起動までの待機許容時間を180秒へ変更して再申請するか、60秒を維持して
必須検証の高速化を調査するかをユーザーへ確認した。まだ設定は変更していない。
期限切れの承認の再利用や、期限チェックの省略は行わない。

終了後の `session_info` で runtime／authority preflight成功、同じservice epoch、
`healthy=true`、`active_operation_id=null`、実行経路利用可能を再確認した。
ユーザー側の `tamper-detected.json` と `approved-host-postflight-pending.json` は存在しない。
token観測は正常終了させた。この操作にはchildがないため、観測した他のwhoamiを
成功証拠に使わない。監査証拠は `.dev-tmp/approved-source-fix/live-whoami-audit.json` に保存した。

運用 runtime 更新、新しい MCP 要求のローカル承認、通常ユーザー child と標準出力、
postflight、正常完了証明、両 latch の解除を含む実機確認が必要。
異常終了・復旧の実機確認も今回は未実施であり、過去の成功を今回の証拠として再利用しない。
手順は `docs/APPROVED_HOST_RUNTIME.md` に従う。
単体テスト、サービス稼働、事前確認を E2E 成功の代替にしない。

### 更新の再開

レビュー済み成果物は `.dev-tmp/approved-source-fix/release-source/`。
管理者 PowerShell から次を実行する。元 runtime／成果物の SHA-256、active／recovery
state、停止対象の PID／作成時刻／実行ファイルを確認してから既存インストーラーへ渡す。
環境が変わって拒否された場合は、検査を外さず対象を再調査する。

```powershell
& 'C:\dev\windows-local-mcp-python\.dev-tmp\approved-source-fix\install-reviewed-runtime.ps1'
```

成功後は通常の非昇格 PowerShell に戻り、変更不能性を再検証して既存接続を再起動する。

```powershell
& 'C:\Program Files\WindowsLocalMCP\verify-approved-host-runtime.ps1'
& 'C:\dev\windows-local-mcp-python\run-localmcp.ps1' `
  -Config 'C:\Users\22905\AppData\Local\WindowsLocalMCP\config.toml'
```

その後 `session_info` を確認し、元の失敗した承認を再利用せず、`whoami.exe /user` を
`workspace_write=false`、`network_required=false`、上限30秒で MCP から新たに申請する。
ローカルユーザーが内容を確認して承認し、`poll_approval` と監査で結果を確認する。

### 180秒設定後の実機確認と残る停止要因

ユーザーの許可により、通常ユーザーの active config に
`approval_execution_ttl_seconds = 180` を追加した。運用 runtime の設定ローダーで
180秒として読み込まれることを確認し、Tunnel を再起動した。新しい `session_info` は
runtime／authority preflight 成功、Approved Host `available=true`、
`execution_route_available=true` を示した。期限切れチェック自体は変更していない。

同じ `whoami.exe /user` を新たに3回申請し、いずれも人がローカル承認した。

| 承認 ID | 結果 | child 起動前に確認した事実 |
| --- | --- | --- |
| `01d97537-b49a-424e-be6c-df4b8ec2d51a` | `failed` | bundle 検証、checkpoint、control-plane guard 準備を通過。`WindowsUserProcessUnavailable: requester process identity is unavailable`。child PID、終了コード、標準出力なし。 |
| `bbd0f387-06e4-44c2-856e-e6ce1bfcb4c4` | `failed` | 承認 UI の存続を確認したが、control-plane guard が容量上限を超えて起動前に拒否。上限は変更していない。 |
| `c1241689-f361-437b-924e-4fc18fbac3c7` | `failed` | このタスクで終了済みの申請3件の一時入力だけを整理後、bundle 検証、checkpoint、guard 準備（5,627ファイル、259,771,306バイト）を通過。再び要求元 PID 不在で停止。child PID、終了コード、標準出力なし。 |

容量整理の対象は `4c711aa2-a394-4401-b427-18a460764a7b`、
`01d97537-b49a-424e-be6c-df4b8ec2d51a`、
`bbd0f387-06e4-44c2-856e-e6ce1bfcb4c4` の終了済み `approval-inputs` のみ。
各監査結果と service の `active_operation_id=null` を確認し、正規の scratch root、
reparse point 不在、各約13.9 MB を確認して削除した。監査記録、workspace 履歴、
他の承認入力、容量・件数の検査は変更していない。

現行実装は service の launch RPC 時に pipe peer の PID／作成時刻／SID／非昇格を
検証するが、通常ユーザー primary token の複製は SYSTEM worker の実コマンド起動直前に
`windows_user_process.py` が行う。直近2回の失敗後、承認 UI の PowerShell／Python
プロセスはいずれも存在せず、子プロセス起動時の要求元 PID 不在という監査エラーと整合する。
UI が終了した正確な時点・原因は未確定。`docs/APPROVED_HOST_RUNTIME.md` は service が
検証済み token を複製すると記していた。利用者は文書の方針を仕様として選択した。
実装は service が認証済み pipe peer の PID／作成時刻／SID／非昇格を検証し、同じ
process HANDLE から primary token を複製して SYSTEM worker に明示的な HANDLE list で
渡す方式へ変更した。worker は継承 token の SID／非昇格／primary type を再検証し、
元 PID が後で終了しても token を取り直さない。Job／postflight／durable state の
役割は維持する。

### token 保持方式の更新後の実機確認

変更不能な `C:\Program Files\WindowsLocalMCP` の運用 runtime へ更新し、導入した3つの
Python ファイルを更新元と SHA-256 で照合した。通常ユーザーからの `session_info` は
runtime／LocalSystem authority の事前確認成功、`available=true`、
`execution_route_available=true` を示した。

MCP で `whoami.exe /user` を読み取り専用 Approved Host として再申請した承認 ID
`6b39baf2-8f64-4470-8f90-699e8920160c` は、人によるローカル承認後、
`poll_approval` と監査の双方で `succeeded`／終了コード0となった。監査には運用 runtime
不変性と authority service の実行時再確認、承認 bundle 検証、制御面 guard の arm、
SYSTEM worker、requester-user child PID 58824 の起動が記録されている。別の観測処理は
同じ child PID の SID `S-1-5-21-1787218830-4025776409-3138769905-1001` と非昇格を
確認した。stdout は同じ SID の `whoami /user` 結果を含み、stderr は空である。
結果の `postflight_error` は null で、再接続後の authority preflight は同一 service epoch、
`healthy=true`、`active_operation_id=null` を示した。通常ユーザー側に現在の tamper／
postflight pending marker はない。正常な完了と latch 解除を確認した。

操作完了後、Tunnel／MCP server の実行プロセスが見つからず MCP は HTTP 504 を返した。
LocalSystem service は Running で、監査上の操作成功は維持されていた。通常ユーザー文脈で
Tunnel を再起動すると local ready が成功し、MCP `poll_approval` から同じ成功結果を
再取得できた。Tunnel 終了の原因は未特定で、Approved Host child の失敗とは区別する。

関連する自動回帰は通常ユーザー文脈で42件成功した。今回変更した token 境界について、
異常終了・復旧の実機 fault injection はまだ再実行していないため、その範囲の新たな
実機証拠とは扱わない。
