# Audit 処理時間診断の検証記録（2026-09-09）

## 原因と設計

既存 Audit は operation の作成・状態更新・完了日時と event を保存していましたが、
Broker 内部の処理境界を測定する仕組みがありませんでした。`duration_ms` は nullable 列で、
worker と Git worker は明示的に値を設定する一方、同期 Broker の完了経路は設定していませんでした。
AuditStore が自動計算する実装もなかったため、成功した Broker 操作でも NULL になっていました。

今回、同期 Broker の呼び出しを `ContextVar` で分離し、`perf_counter_ns()` の整数値で
全体と処理段階を測定します。順序、offset、duration、段階の成功／失敗、最終例外の段階を
収集します。既存の status、tier、route 情報、rollback state と合わせて解析します。
最大 128 段階をメモリ内で記録し、終了時に一括保存します。

既存方式に合わせて `operations.timing_json TEXT` を追加し、過去の行は NULL のまま維持します。
新規 DB と既存 DB の両方に対応します。診断保存は既存の Audit lock・容量検査を通し、
`updated_at` と event を変更しません。Activity の通常表示へ phase の行を追加しません。
既存 Audit や journal の保存失敗を握りつぶす変更はなく、追加した診断保存の失敗だけを
本来の結果・例外から分離します。詳細な schema と時間の意味は
[Audit の処理時間診断](AUDIT_PERFORMANCE.md) を参照してください。

## 対象ファイル

- `src/windows_local_mcp/performance_trace.py`: 計測、固定語彙、上限、schema 検証、例外段階の識別。
- `src/windows_local_mcp/audit.py`: nullable 列の追加、診断保存、`audit_get` 向け decode、既存監査保存の計測。
- `src/windows_local_mcp/server.py`: 同期 Broker 呼び出し、検査、hash、checkpoint、commit、復旧等の計測。
- `src/windows_local_mcp/paths.py`: path／identity 検査、read、CAS、commit の共通境界。
- `src/windows_local_mcp/workspace_history.py`: checkpoint、diff、staging、復旧、journal の確定。
- `src/windows_local_mcp/windows_transaction.py`: HANDLE 取得、hash、staging、OS transaction 確定。
- `src/windows_local_mcp/structured_files.py`: 形式検査、parse、transform、encoding、ZIP read。
- `tests/test_performance_trace.py`、`tests/test_broker_performance.py`: 計測・移行・失敗・復旧・API互換性。
- `README.md`、`SPEC.md`、`VERIFICATION.md`、本書、`AUDIT_PERFORMANCE.md`: 仕様と検証記録。

現在の checkout を使用し、作業開始前および並行作業による変更を保持しました。
同じ server／Audit ファイル内の転送 lifecycle 等、今回の時間計測以外の差分も存在します。
`SECURITY_CONTRACT.md` の並行差分を、この作業の契約変更として扱っていません。
コミット・push はしていません。サブエージェントは利用上限で停止したため、残りは主担当が実装・検証しました。

## 自動試験と回帰

- 計測専用テスト: 最終 `16 passed`。fresh DB、既存行を保持した列追加、整数精度、
  wall clock 変更、入れ子の順序と上限、例外時の途中結果、型・名称・duration 不正、
  context 分離、診断保存失敗時の元の結果保持、phase 中の DB 保存ゼロ・終了時1回を検証。
- 新規 Broker テスト: read、write、CSV apply／inspect、artifact upload commit、ZIP 複数展開、
  入力不正、CAS 不一致、transform 失敗、commit 失敗、post-write failure と自動復旧を検証。
  total と各 phase の非負・包含関係、失敗段階、Audit／Activity の互換性を確認。
- 広い関連回帰: `182 passed, 2 skipped, 2 deselected`。Audit、Activity、server、構造化処理、
  artifact、transfer lifecycle、checkpoint、Undo／rollback、filesystem primitive、Windows transaction を対象。
  XML は `.dev-tmp/performance/regression-final.xml`。
- 既存 Audit event 保存の計測追加後の最終関連確認: `71 passed`。
- 対象ファイルの Ruff、compileall、`git diff --check` は成功。
- path／workspace history／Windows transaction／structured files は、計測デコレーターと import を
  除去した構文木が元の制御フローと一致することを確認。

制限環境内の初回 server 回帰では、SCM 読み取りが `sc.exe exited with 5` で拒否されました。
通常 Windows user 文脈で同じ対象を実行すると `21 passed, 1 skipped` でした。
広い回帰の途中では filesystem probe の `os.replace` 失敗2件もありましたが、独立再実行で成功しました。

次の既存競合テスト2件は、時間計測デコレーターをテストプロセス内で完全に無効にしても
同じ `destination.bin` 不在で失敗しました。したがって時間計測による回帰とは区別し、
全リポジトリが合格したとは報告しません。期待や transaction の拒否条件を弱める修正はしていません。

- `test_transactional_copy_destination_creation_race_never_overwrites`
- `test_transactional_move_destination_creation_race_never_overwrites`

## 検出して修正した HANDLE 保持

途中実装で失敗した例外本体を collector に保持すると、その traceback がローカル変数と
Windows HANDLE の解放を遅らせ、後続 move の `CreateFileTransactedW` が失敗しました。
計測無効の対照では move／Undo が成功したため、計測側の回帰と判定しました。
例外と traceback を保持しない数値識別方式へ修正し、関連確認は `39 passed, 1 skipped`、
その後の広い回帰でも正常でした。捕捉済み例外のローカル資源が解放される専用回帰テストも追加しました。

## 性能実測

通常 Windows user 文脈の専用 test workspace／data で、同一コードの計測無効と有効を
交互に実行しました。最初の2組をウォームアップとし、各12回の中央値を比較しています。
制御群は entrypoint の `__wrapped__` を呼び、下位計測は非アクティブです。
過去コミットの別 checkout との比較ではありません。payload は 1,344 byte の UTF-8 text、
read は同じファイル、write は毎回新規の別ファイルです。外部計測は診断 DB 保存も含みます。

| 操作 | 計測無効 | 計測有効 | 差 | 比率 |
|---|---:|---:|---:|---:|
| read_file | 42.419 ms | 53.770 ms | +11.351 ms | +26.8% |
| write_file | 189.944 ms | 208.139 ms | +18.195 ms | +9.6% |

100 段階の収集・schema 検証・JSON 化だけを DB なしで300回測定した中央値は **0.334 ms** でした。
ただし外部計測の差全体を DB だけに帰属させる分離測定はしていません。
大きな phase ごとの SQLite commit は追加していませんが、終了時の追加保存は無料ではありません。
特に短い read について「追加負荷は無視できる」「latency regression がない」とは結論しません。
測定は小さなローカル試料であり、大規模文書、低速媒体、高競合時の分布は未検証です。

実測した write 1件の total は **220.073 ms** でした。入れ子を重複加算せず、最上位の
互いに重ならない区間を同名ごとに合算すると、主な内訳は以下です。

| 区間 | 所要時間 |
|---|---:|
| 既存 Audit 保存 | 43.785 ms |
| after checkpoint | 38.346 ms |
| before checkpoint | 33.644 ms |
| 入力・実行前検査 | 26.542 ms |
| transactional commit | 15.891 ms |
| rollback 最終確定 | 10.512 ms |
| diff 生成 | 9.997 ms |
| rollback metadata 保存 | 9.303 ms |
| checkpoint integrity 検証 | 6.346 ms |
| transaction 準備 | 5.493 ms |
| post-write 検証 | 2.743 ms |
| その他の短い計測段階 | 1.517 ms |
| 独立 phase を付けていない時間 | 15.954 ms |

丸めによる微差があります。before／after checkpoint が合計約72 ms、既存 Audit 保存が約44 ms を
占めていました。約16 ms の未分類区間の内訳は推測で埋めていません。
最後の診断値保存はこの total の外で、上の外部 latency 比較には含まれます。
生の試料・全 phase は `.dev-tmp/performance/results.json` に保存しています。

## 安全性の確認と限界

phase 名は固定語彙、payload は schema・件数・bytes を検証し、保存前に正規化します。
ユーザーの本文・path・credential・command argument・例外本文は時間情報へコピーしません。
承認、route 選択、identity、CAS、transaction、checkpoint、rollback の判断には計測値を使いません。
Live Activity／Timeline へ内部 event を流さず、診断保存で `updated_at` を変えません。
ユーザーによる選択的 Undo と手動操作の分離を維持し、カスケードを自動決定しません。

強制終了ではメモリ内 trace が失われます。既存の durable Audit と transaction journal が
中断・復旧の根拠であり、trace 欠損を成功や安全性の証拠にしません。
MCP transport、診断保存自身、非同期 worker 内部の細分化、起動時 recovery、transfer chunk 単位、
個々のロック待ちは今回の観測外または未分類です。
次の候補はロック待ち、backup、checkpoint 内の hash／blob 保存の分離、および診断保存の追加負荷削減です。

これはローカル試験の記録です。Tunnel／ChatGPT 経由、Approval UI の実画面、実承認を伴う
Sandbox／Approved Host、停電・プロセス強制終了の実機試験を完了したという意味ではありません。
