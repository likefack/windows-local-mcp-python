# バイナリ転送の検証記録（2026-10-06）

## 結論と対象

転送に関係する最終回帰は **250 passed, 6 skipped**。性能比較は **5 passed**。
実MCP stdio通信で512 KiBチャンク、再送、状態照会、再起動後の再開・commitを確認した。
ChatGPT／Secure MCP Tunnelの添付受信と直接ファイル出力の実運用E2Eは未検証である。
全体テストは完走していないため、リポジトリ全体が正常とは判定しない。

7項目の設計判断、公式仕様の出典、利用方法、期限の移行は
[転送の復旧仕様](BINARY_TRANSFER_RESUME.md)に記載した。
作業開始時点で `artifact_import_file`、`attachment_import.py`、チャンクBase64事前上限が
未コミットの変更として存在していたため、それらを再利用・追加検証した。
並行作業のworkspace操作、Approved Host、Sandbox、ランチャーの変更は本作業の成果に含めない。
運用runtimeの更新、ホスト許可設定、コミット、pushは行っていない。

## 元のJPEG転送失敗の評価

524,288バイトをクライアント側でBase64化した699,052文字の入力は、実MCP経路でも成功した。
512 KiB設定そのものを障害原因とする証拠はない。元のJPEG失敗時の実リクエスト、
ChatGPT／MCP各層のログがないため、`INVALID_ARGUMENT` が発生した層と具体的な破損は未確定。
長いBase64をモデルが生成・転記・分割する方式は完全一致を保証できず、通常の添付保存には
fileParamsを使う。ただし、この設計上の弱点を元の障害の実証済み原因とは記録しない。

## 追加・補強した保護

- 新規uploadは固定長48バイトの受信記録を使う。境界、長さ、SHA-256、保存済み範囲を検査し、
  同一チャンクを二重書き込みしない。本文全体のhashは再送ごとに行わない。
- 本文fsync、受信記録fsync、manifest原子的置換の順に受信位置を確定する。
  記録領域は開始時に予約して容量へ計上し、通常チャンクの全ディレクトリ走査は増やさない。
  多数の極小チャンクで予約不足になった場合は、追加分の容量確認を本文書込より先に行う。
- 内容が違う同境界再送はintegrity errorとして失敗状態にする。位置の修正で回復できる
  future offset／部分overlap、未完了commitは転送を破棄しない。
- statusは本文・内部パス・URLを返さず、期限切れの照会でもmanifestを書き換えない。
  downloadで受信済み位置を推測しない。
- Base64文字数をdecode前に検査し、decode後のraw上限、正規のpadding・alphabetも検査する。
  JSON受信前のrequest envelope制限を実装したという主張はしない。
- 新規transferの絶対期限を保存し、承認期限と分離。終端状態のretentionは変更しない。
- Windowsでmanifestの読取と原子的置換が競合しないよう、受付走査にも転送単位ロックを使う。
- 添付取り込みは既存の完全一致ホスト許可、公開IP確認・接続先固定、HTTPS証明書検証、
  redirect／proxy拒否、取得途中のサイズ制限を維持する。失敗時のpartial確定を拒否し、
  URL・token・bodyを監査に残さない。

CAS、source binding、verified handle、immutable snapshot、全体SHA-256、checkpoint、
transaction、rollback、quota、admissionを削除していない。添付内容の保存からコード実行への
暗黙移行、Sandbox／Approved Hostへの自動切り替えは追加していない。

## テスト範囲

| 対象 | 確認した内容 |
|---|---|
| 添付取り込み | JPEG相当・数百KB・上限・上限+1、SHA一致、取得途中失敗、不正参照／URL、redirect、SSRF／非公開DNS、workspace逸脱、CAS不一致、partial非残留、監査の秘匿 |
| upload | 通常・過去チャンクの同一再送、長さ／本文不一致、future／overlap、commit後再送、manifest確定前の中断、本文改変、旧version継続、容量追加失敗 |
| status | open、受信完了・未commit、committed、download open／completed、cancelled／expired／failed、不正・不存在ID、状態不変、本文非読取 |
| Base64 | raw／encodedの上限、上限超過、padding、非canonical、非ASCII、巨大one-shot／chunkのdecode前拒否 |
| TTL | 上下限、承認設定との独立、期限内／超過、再起動後の期限維持、終端状態非変更 |
| download | 0・4 KiB・512 KiB・4 MiB、同一ハンドル保持、途中変更・置換、保存済みsnapshot改変、SHA一致、終端再送 |
| 並行処理 | 同時begin／完了／cancelの受付上限、実際の読取ハンドルを保持したmanifest読取・置換の直列化 |

新しいテストファイルは `test_transfer_resume.py`、`test_transfer_receipts.py`、
`test_attachment_import_additional.py`、`test_artifact_route_measurement.py`、
`test_artifact_transfer_measurement.py`。
既存の `test_binary_transfer_lifecycle.py` の期限試験は、固定期限を使う新仕様に合わせて
`created_at` と `expires_at` の両方を期限切れにしている。

Windowsのsource変更・置換試験では、実際の保持ハンドルが書込／置換を拒否することを確認した。
別の故障注入試験では、意図的に保持を解放して変更を注入し、後段の再検査が失敗を検出することを
確認した。この注入を、通常状態で保持ハンドルを突破できた証拠として扱わない。

## 実MCPの確認

`mcp.client.stdio` と `ClientSession` から独立したserverプロセスへ接続した。
Python関数の直接呼び出しだけではない。

1. `list_tools` にfileParamsメタデータと4項目の参照スキーマがあることを確認。
2. 512 KiB／699,052文字のチャンクを送信し、その応答を失った場合を模擬。
3. serverプロセスを終了・新規起動し、statusで同じ期限と受信位置を確認。
4. 同一チャンクを再送し、commit後のSHA-256と保存内容の完全一致を確認。
5. 文字数超過が `TRANSFER_BASE64_LIMIT` として見え、不正添付参照の秘密文字列が返らないことを確認。
6. `artifact_transfer_status` のread-only注釈と、未実装の `artifact_export_file` が公開されないことを確認。

応答消失はクライアントが成功応答を採用しないことで模擬した。ネットワーク障害注入や
ChatGPT側の実ファイル置換ではない。実際の添付本文のHTTPS取得は合成通信による試験であり、
本番配信ホスト・TLS・ChatGPT画面を通した保存はまだ確認していない。

## 性能測定

Windows／Python 3.13.15／MCP SDK 2.1.1、同一PC・同一入力・同一設定で各3回の中央値。
時間はローカル処理の観測値であり、性能保証やChatGPTの応答時間ではない。
計測時には別の回帰試験も進行しており、負荷やファイルキャッシュの影響は除去していない。

### 保存経路

同じ入力・新規保存先で全体SHA-256、保存後本文、成功監査を照合した。
importは実際の取得・保存コードを使い、HTTP応答だけを合成した。one-shot上限は256 KiB、
chunk上限は512 KiB、全体上限は2 MiBで3経路共通。本文Base64は計測クライアントが生成した。

| サイズ | import ms | one-shot ms | begin＋chunk＋commit ms | Base64方式の文字数 |
|---|---:|---:|---:|---:|
| 0 | 179.79 | 181.16 | 315.38 | 0 |
| 4 KiB | 305.45 | 311.76 | 390.24 | 5,464 |
| 256 KiB | 284.14 | 274.11 | 455.58 | 349,528 |
| 512 KiB | 357.24 | 対象外・同設定の上限超過 | 522.20 | 699,052 |

importの本文Base64文字数はすべて0。ローカル処理時間だけで常に速いとはいえないが、
モデルの引数に長大な本文を載せない効果は確認できた。実ネットワーク待ち時間を含めた比較は未実施。

### download beginの変更前後

作業開始時に保存した `server.py` からdownload開始とコピーの2関数だけを取り出し、
現在の同じruntime・設定・監査コード上で旧処理と最終処理を交互に3回実行した。
旧環境全体や旧配布版との比較ではない。全体上限は5 MiB、chunk上限は512 KiB。

| サイズN | 変更前 ms | 最終 ms | 読込量・前後共通 | コピー書込量・前後共通 | SHA-256 |
|---|---:|---:|---:|---:|---|
| 0 | 77.35 | 77.03 | 0 | 0 | 一致 |
| 4 KiB | 103.70 | 97.11 | 12,288 | 4,096 | 一致 |
| 512 KiB | 150.39 | 130.91 | 1,572,864 | 524,288 | 一致 |
| 4 MiB | 160.20 | 184.93 | 12,582,912 | 4,194,304 | 一致 |

主要区間の中央値（変更前 → 最終、ms）:

| サイズ | コピー処理全体 | 初回同一ハンドル読取 | 初回hash | 元ファイル再読取 | 再読取hash | 保存済みsnapshot読取・hash |
|---|---:|---:|---:|---:|---:|---:|
| 0 | 2.719 → 2.658 | 0.452 → 0.511 | 0.024 → 0.037 | 0.387 → 0.525 | 0.010 → 0.010 | 0.332 → 0.377 |
| 4 KiB | 4.738 → 4.644 | 0.837 → 0.817 | 0.028 → 0.027 | 0.674 → 0.701 | 0.015 → 0.021 | 1.574 → 1.517 |
| 512 KiB | 16.543 → 14.846 | 1.399 → 1.186 | 0.416 → 0.305 | 1.149 → 0.891 | 0.401 → 0.306 | 9.696 → 9.256 |
| 4 MiB | 25.008 → 29.497 | 5.686 → 7.587 | 2.654 → 3.290 | 5.539 → 6.861 | 2.373 → 3.157 | 12.739 → 13.996 |

コピー処理全体には初回読取・hash・書込・fsyncを含むため、区間値を単純合算しない。
読込量は計測したヘルパーの論理バイト数であり、OSキャッシュを除外した物理ディスクI/Oではない。
コピーは取得済みデータをhashしており、初回hashのためだけの追加読取は元からない。
元ファイル再読取と永続snapshot検証は異なる保証を担うため維持した。I/O削減は0、
速度差も一方向ではない。今回、download開始を高速化したという結論にはしない。

## 再実行コマンドと結果

以下はリポジトリルートで実行する。PowerShellの出力とファイル読取はUTF-8を使用した。
制限環境での `.dev-tmp` 作成時にWinError 5が出たため、ACL／ownerを変更せず、
承認された通常Windows環境でテストを再実行した。

```powershell
$env:PYTHONIOENCODING = 'utf-8'
.venv\Scripts\python.exe -m pytest -q tests/test_transfer_resume.py tests/test_transfer_receipts.py tests/test_binary_transfer_lifecycle.py tests/test_artifact_transfer_errors.py tests/test_artifact_fast_path.py tests/test_attachment_import.py tests/test_attachment_import_server.py tests/test_attachment_import_additional.py tests/test_structured_files.py tests/test_structured_resource_admission.py tests/test_transfer_timeline.py tests/test_audit.py tests/test_config.py tests/test_config_binding.py tests/test_paths.py --basetemp=.dev-tmp/pytest/artifact-target-final-20261006 -ra
.venv\Scripts\python.exe -m pytest -q -s tests/test_artifact_route_measurement.py tests/test_artifact_transfer_measurement.py --basetemp=.dev-tmp/pytest/artifact-measurement-final-20261006
```

- 最終回帰: **250 passed, 6 skipped in 92.05s**。
- 性能比較: **5 passed in 17.62s**。
- スキップ6件: transfer_receipts 1、config 2、config_binding 2、paths 1。
  いずれも実シンボリックリンク作成が権限不足で使えないため。リンク検査を削除したものではない。
- Ruff: 今回変更したPython実装・追加テスト10ファイルを `ruff check --no-cache` で確認し成功。
- `git diff --check`: 成功。既存のLF／CRLF警告は残る。

比較テストは `.dev-tmp/artifact-20261006/baseline/server.py` を必要とする。
別checkoutでこの作業開始時の保存ファイルがない場合、前後比較4ケースは理由付きでskipする。
生の計測値は `.dev-tmp/artifact-20261006/measurement-<bytes>.json`、
保存経路の値は `measurement-final.log`、最終回帰は `target-final.log` にある。
これらは開発用の一時証拠であり、この文書に条件と結果を残す。

## 失敗の切り分けと全体検証の限界

初回の広い回帰では、追加したsource変更試験がWindowsの保持ハンドルに拒否された。
試験を「実ハンドルによる拒否」と「保持解除後の故障注入」に分離した。
受信記録追加時にチャンクごとの容量走査を増やしてしまった退行は、開始時の予約に変更して解消した。
受付走査とmanifest置換の競合も再現試験を追加して修正し、最終回帰で通過した。

`test_windows_transaction.py` のcopy／move先作成競合2件は、期待する競合先ファイルが
存在しないとして失敗する。対象テストと `windows_transaction.py` はHEADとの差分なしで、
serverを経由しない独立実行でも同じ2件が失敗した。別の添付取り込み作業でも先に記録されていた。
今回の転送変更の退行とは切り分けるが、そのWindows transaction試験を成功とは扱わない。

```powershell
.venv\Scripts\python.exe -m pytest -q tests/test_transfer_resume.py::test_admission_read_serializes_with_terminal_manifest_replacement tests/test_windows_transaction.py::test_transactional_copy_destination_creation_race_never_overwrites tests/test_windows_transaction.py::test_transactional_move_destination_creation_race_never_overwrites --basetemp=.dev-tmp/pytest/artifact-final-isolated-20261006
```

結果は新しいmanifest競合試験1件成功、既存transaction試験2件失敗。

全体 `pytest -vv -ra --basetemp=.dev-tmp/pytest/artifact-full-complete-20261006` は
1137件を収集し、55%の `test_saved_acl_config_starts_through_normal_launcher` で待機。
実行全体を900秒で打ち切った。そこまでのログは595成功、6失敗、4スキップであり、
pytestの完了サマリーではない。先行した240秒制限の全体実行も39%付近で未完了だった。

6失敗のうち1件は上記manifest競合で修正済み。残る5件はconfig改変、Approved Hostの
子孫待機・監査改変、並行開発中のworkspace staging、旧safe_commandのGit経路の試験。
独立した同一5件の再実行は **5 passed in 35.26s**。
初回失敗を無効化せず、実行順序・負荷・環境・並行変更の影響は未確定として残す。
証拠は `full-pytest-complete.log` と `other-failures.log`。

待機したランチャー試験を除き、ファイル名が `test_mcp_stdio_integration.py` 以降の全テストを
独立実行した結果は **520 passed, 4 skipped, 2 failed, 1 deselected in 272.82s**。
失敗は前述のtransaction 2件のみ。4スキップはpaths、server_operations、transfer_receipts、
workspace_replace_plannerの実シンボリックリンク作成権限不足。除外1件は待機中のランチャー試験。
runtime複製試験もこの実行では完了した。`suite-remainder.log` に記録した。

```powershell
$remaining = Get-ChildItem tests/test_*.py | Where-Object { $_.Name -ge 'test_mcp_stdio_integration.py' } | Sort-Object Name
.venv\Scripts\python.exe -m pytest -vv $remaining.FullName -k 'not test_saved_acl_config_starts_through_normal_launcher' --basetemp=.dev-tmp/pytest/artifact-suite-remainder-20261006 -ra
```

残りの試験がruntime複製で待機していた間に、`test_runtime_closure_integration.py` より後も
別途実行した。結果は **425 passed, 3 skipped, 3 failed in 143.90s**。
重複するため成功件数は合算しない。transaction 2件に加え、Sandbox表示試験1件で
設定初期化時のfilesystem semantics検査が一度失敗した。これは転送処理に到達する前の失敗で、
上の520件実行では同じ試験が成功した。記録は `suite-last.log`。
この表示試験をさらに単独で実行して **1 passed in 0.35s** を確認した。

```powershell
$retryCases = @(
  'tests/test_active_config_security_integration.py::test_real_approved_host_config_tamper_fails_closed'
  'tests/test_approval_execution_integration.py::test_approved_host_waits_for_descendants_before_control_plane_postflight'
  'tests/test_approved_host_audit_integrity.py::test_approved_host_current_audit_tamper_is_detected[insert_event]'
  'tests/test_deterministic_workspace_operations.py::test_identity_change_during_staging_is_rejected_before_mutation'
  'tests/test_git_worker_routing.py::test_git_operations_use_dedicated_worker_for_current_and_legacy_tiers[safe_command]'
)
.venv\Scripts\python.exe -m pytest -q --tb=short $retryCases --basetemp=.dev-tmp/pytest/artifact-other-failures-20261006 -ra
.venv\Scripts\python.exe -m pytest -q 'tests/test_server_operations.py::test_sandbox_dependency_availability_is_separate_from_live_verified_route[accepted]' --basetemp=.dev-tmp/pytest/artifact-filesystem-probe-recheck-20261006
```

## 運用上の残課題

- `attachment_import_allowed_hosts` は初期値の空を維持。実際の配信ホストの確認と許可設定が必要。
- fileParamsは会話への所属の暗号学的証明ではない。この制約は既存のoperator decisionを維持。
- 運用immutable runtimeの更新、再起動、ツール再登録、本物の添付参照での取り込みは未実施。
- 通常ChatGPTへ直接exportする正式な結果形式・配送方法を確認できず、未実装。
  デスクトップの `openai/files/open` やFiles APIを会話添付の代替として扱わない。
- request envelope全体の受信前上限、実ChatGPTの上限、ネットワーク障害時のE2Eは未確定。
- commit応答消失時はstatusの `committed` を確認する。workspace保存とtransfer manifest更新の
  あらゆる瞬間でのプロセス強制終了に対するcommit自動再実行は、今回の追加機能ではない。
- 最終回帰の成功はSCM／WFP／Approved HostやSandboxの実機セキュリティ証明ではない。

コミットメッセージ案: `feat: バイナリ転送の冪等再送・状態照会・専用TTLを追加`

## 添付取り込みの実運用前テスト（2026-10-06・後続確認）

利用者の「添付取り込みを実運用で使える状態にする項目をテストから実施する」依頼で、
現行checkoutを再検証し、接続中MCPと導入済みruntimeを読み取り専用で確認した。

```powershell
$env:PYTHONIOENCODING = 'utf-8'
.venv\Scripts\python.exe -m pytest -q tests/test_attachment_import.py tests/test_attachment_import_server.py tests/test_attachment_import_additional.py tests/test_transfer_resume.py::test_real_stdio_resume_and_schema_across_restart --basetemp=.dev-tmp/pytest/attachment-live-readiness-host-20261006 -ra
```

- 結果: **80 passed in 14.11s**。失敗・スキップなし。
- JPEGの完全一致、サイズ上限、途中切断、許可外URL／SSRF、保存先逸脱、CAS、checkpoint、
  保存後失敗時の復旧、監査の秘匿、fileParamsスキーマ、実stdioでの定義公開・再起動を含む。
- 添付のHTTP応答は合成。実stdio試験はツール定義・不正添付参照の拒否と従来uploadの再開を
  確認するもので、本物のChatGPT添付の取得成功を確認した試験ではない。
- 最初の制限環境では59件成功、21件が一時フォルダー作成時のWinError 5でsetup error。
  ACL／ownerを変更せず、通常Windows環境の別basetempで上記80件を再実行した。
- ログ: `.dev-tmp/artifact-20261006/attachment-live-readiness.log`。

実運用の観測:

- 接続中のWindows Local MCPの `session_info` は成功し、workspaceは
  `C:\Users\22905\Personal_knowledge`。この作業で同workspaceへファイルを保存していない。
- このチャットに公開されたツール一覧には `artifact_import_file` がない。
- `C:\Program Files\WindowsLocalMCP\runtime\Lib\site-packages\windows_local_mcp` の
  `server.py` に `artifact_import_file` と `openai/fileParams` がなく、
  `attachment_import.py` も存在しない。`config.py` に許可ホスト設定の定義がない。
- 導入済みserver.pyのSHA-256は
  `ce56626086f39696089441b012c46730b2cdf6d62984e2ad6d91d5c0ed1a76dc`、
  config.pyは `5ee4820106bc106a80e4ea86a2f899ee4263b181a1b5b6278b02df605e46fd5f`。
- active-config.txtが指す運用設定には `attachment_import_allowed_hosts` の指定がない。
  設定全体や秘密情報は出力せず、関連項目だけを確認した。

結論: **開発版の対象テストは成功。運用版には添付取り込み機能が未配備で、実添付E2Eは未実施**。
次の工程は運用runtimeの更新・再起動とクライアント側のツール定義更新。その後、実際に渡される
添付参照の配信ホストを確認し、完全一致の許可設定を行って、元ファイルとのSHA-256一致まで
検証する。URLを推測した許可登録、任意URLの代用、Base64転記による代用は行っていない。
今回の変更はこの検証記録だけで、製品コード・運用設定・runtimeを変更していない。

利用者による再起動・再読み込み後にも再確認した。MCP `session_info` は成功
（operation_id: `288a132d-a454-47d2-bcd9-eb54358994e2`）し、workspaceと運用設定の選択は同じ。
runtime digestは `f104022ac75412dd334b407ab14350ff79ed4500c0c156959d9ffd87838070e5`。
導入済みserver.py／config.pyのSHA-256は上記と一致し、添付取り込み関数・fileParams定義・
attachment_import.pyは引き続き存在しない。公開ツールにも取り込み操作はない。
再読み込みの問題だけではなく、運用runtimeへの新実装の配備が未実施であることを確認した。
本物の添付参照による保存は開始していない。設定変更・runtime更新は行っていない。

## 後続の運用配備

その後、利用者の依頼とWindows管理者確認により、添付取り込みに必要な4ファイル分だけを
既存運用版へ反映した。旧54ツールを維持し、新ツールを含め55ツールになった。
通常ユーザーでのruntime／authority preflightと、ChatGPT接続経由の更新後runtime確認も成功した。
転送再開・状態照会・専用TTLはこの限定配備に含めていない。
詳細・証拠・残る実添付検証は [運用配備記録](ATTACHMENT_IMPORT_DEPLOYMENT_2026_10_06.md) を参照。
