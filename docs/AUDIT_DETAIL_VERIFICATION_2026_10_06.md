# Audit 詳細計測と監査モニターの検証（2026-10-06）

## 変更内容

同期 Broker の処理時間を、ロック取得、容量走査、チェックポイントのハッシュ・保存・検証、
バックアップ、進行記録、監査 DB の接続・SQL・確定・取消しまで分けた。
ワンショット転送と添付ファイル取り込みは外側の呼び出しも計測し、変換・取得を区別する。

新しい schema v2 では、開始順の最大128段階に親番号と自己時間を持たせ、固定名称ごとの
回数・失敗回数・包括時間・自己時間・最小・最大を集計する。詳細上限を超えても集計を継続する。
旧 v1 の読み取り、64 KiB 制限、診断保存の一括処理、既存の監査・復旧の永続性を維持する。
保存時には親子の包含関係、自己時間、集計値と明細の整合性も検証する。

起動端末の Activity Monitor に `TIMING`、`TIMING_SUMMARY`、`TIMING_PHASE` を追加した。
監視は読み取り専用で、毎周期は時間列の型だけを調べ、保存された行だけ詳細を読む。
不正な記録は内容を転記せず `TIMING_UNAVAILABLE reason=invalid_payload` と表示する。
Live Activity の実装・表示処理は、この作業では編集していない。

作業開始時から未コミット変更があり、別タスクの発行元識別・実行枠管理・Live Activity 等の
変更も進行していた。作業開始時のコピーと局所差分を基準に、それらを保持した。
コミットは作成していない。

## 自動テスト

次の最終実行は **74 passed、11.26秒**。

```powershell
$env:PYTHONIOENCODING='utf-8'
.\.venv\Scripts\python.exe -m pytest tests/test_performance_trace.py tests/test_audit_performance_detail.py tests/test_audit_timing_guard.py tests/test_storage_performance_detail.py tests/test_activity_monitor.py tests/test_origin_views.py tests/test_broker_performance.py -q --basetemp=.dev-tmp/pytest/audit-detail-verified
```

確認した主な性質:

- 制御した時計で親80 ns・子30 nsの自己時間と未分類時間を照合。
- 詳細上限後のハッシュ集計と後半の失敗箇所、旧 v1、破損データ拒否。
- 別 thread のコピー済みコンテキストを親の計測へ混ぜないこと。
- 例外の traceback に含まれる資源の解放を遅らせないこと。
- SQLite の通常確定、明示確定、取消し、遅延制約による commit 失敗後の rollback。
- 既存の改変検出用 SQL コールバックが計測付き接続でも継続すること。
- チェックポイント再利用、破損検出、復元、失敗後の復旧、ロック取得待ちと保持時間の分離。
- 時間の遅延保存、同じ記録の再表示防止、旧 DB、不正入力、発行元表示、読み取り専用。
- Broker の書込・読込・構造化処理・転送・ZIP・失敗時の計測と復旧。

Live Activity 関連は別実行で **83 passed、1.05秒**。

```powershell
$env:PYTHONIOENCODING='utf-8'
.\.venv\Scripts\python.exe -m pytest tests/test_live_activity.py tests/test_live_activity_changes.py tests/test_live_activity_operation_id.py -q --basetemp=.dev-tmp/pytest/audit-detail-live-regression
```

先に行った広範囲の回帰は **227 passed、6 failed、4 skipped**。6件は並行編集途中の
Live Activity の試験であり、こちらからその実装を変更せず、上記83件の再実行ですべて成功を
確認した。単一実行で全件成功した結果へ置き換えない。残りの回帰では、発行元・ファイル操作・
高水準操作・容量とロック・履歴と取り消し・分割転送・添付取り込みを確認した。

変更ファイル一式の Ruff と、Windows の改行を考慮した差分の空白検査は成功。
一時フォルダー／キャッシュへの制限環境の書き込みが
`WinError 5` となった検証は、ACL を変更せず、承認された通常 Windows 文脈で再実行した。

## 合成ファイル操作と監査表示

専用の一時 workspace にある `measure.txt` を `before` から `after` へ変更した。
実際の `write_file`、監査 DB 保存、読み取り専用モニターを接続した確認で、内容の一致と
次回 poll の出力0行を確認した。新規 lifecycle 1行と診断175行が表示された。

この1試料の全体時間は **505.332 ms**。詳細128段階・省略52段階で、全180段階の集計を保持した。
自己時間の上位は次のとおり。繰り返し測定した代表値ではなく、同時に他の検証も進行していた
ローカル環境の1試料なので、性能目標や最適化効果の根拠にはしない。

| 処理 | 回数 | 自己時間合計 |
| --- | ---: | ---: |
| 制御領域の健全性確認 | 1 | 97.854 ms |
| ファイル同一性検証 | 25 | 64.671 ms |
| 容量走査 | 7 | 51.228 ms |
| 監査 SQL | 17 | 47.423 ms |
| 監査 DB 確定 | 4 | 32.408 ms |
| 復旧用の進行記録保存 | 3 | 18.397 ms |

これにより、操作全体の遅さをどの内部処理へ切り分けるか判断できる。回数、最大時間、
自己時間を組み合わせて調べ、安全性検証や永続化を単純に削減する理由にはしない。

## 計測自体の負荷

空のハッシュ段階を同一プロセスで実行し、作業開始時の v1 と最終 v2 を交互に31回測定した。
各条件3回の事前実行後の中央値。以下は計測収集と最初の schema 検証・JSON化を含み、
DB保存を含まない。実際のファイル操作の速度比較ではない。

| 段階数（外側1段階を含む） | 旧 v1 | 新 v2 | 新 v2 の JSON |
| --- | ---: | ---: | ---: |
| 101 | 0.3650 ms | 0.6713 ms | 13,408 bytes |
| 1,001 | 1.4881 ms | 2.9731 ms | 16,946 bytes |

1,001段階では詳細873件を省略しても、ハッシュ段階1,000回の集計が残った。
別に、新 v2 の101段階を実際の AuditStore に保存するまでを31回測定した中央値は
**13.2045 ms**（最小11.1551／最大26.4392 ms）。これは従来にも存在する診断保存を含み、
旧版に対する増分ではない。保存負荷を無視できるとは扱わない。

開発用の生結果と表示は `.dev-tmp/audit-detail-benchmark.json`、
`.dev-tmp/audit-detail-smoke.json`、`.dev-tmp/audit-detail-monitor.log` に保存した。
これらは開発用一時出力であり、継続保存の根拠は本記録の条件と数値とする。

## 検証していない範囲

- 稼働中の Tunnel／ChatGPT 経由の通信と表示、承認画面の GUI 操作、運用 runtime への配備・再起動。
- Approved Host／Sandbox の通常経路の OS 境界や実承認。今回のテストをその実証に代用しない。
- 非同期 worker 内部、転送 chunk 単位、起動時処理、通信の個別段階。
- 大規模監査 DB を用いた長時間の監視負荷。

仕様・区間の正本は [Audit の処理時間診断](AUDIT_PERFORMANCE.md)。
