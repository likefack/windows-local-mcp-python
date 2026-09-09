# Audit の処理時間診断

Audit は機械解析、障害解析、性能分析、回帰試験のための詳細記録です。
通常の監視には Live Activity、`activity_timeline`、`activity_get` を使用します。
処理段階の開始・終了を Activity の行として追加しません。

## 時間の意味

`created_at`、`updated_at`、`finished_at`、event の `occurred_at` は、発生した日時を
表す時計です。処理時間はこの差から計算せず、`time.perf_counter_ns()` で測ります。
そのため日時の補正や NTP 同期を処理時間に混入させません。

同期 Broker の `duration_ms` は、計測対象のサーバー関数に入ってから、正常 return
または例外処理を終えるまでの経過時間です。入力検査、ロック待ち、既存の監査書き込み、
必要な復旧処理を含みます。MCP が関数を呼ぶ前の引数検証、通信、関数から戻った後の
MCP 応答エンコードは含みません。診断値自身を最後に保存する SQLite 書き込みも含みません。
保存処理が自分自身の終了時刻を記録するために繰り返し更新することはしません。

内部では整数ナノ秒を保持します。既存の `duration_ms` は整数ミリ秒への切り捨てで、
1 ms 未満は 0 です。細かい比較には `timings` の整数値を使用してください。
非同期 job の既存 `duration_ms` は worker 側の実行区間です。承認・キュー待ちを含む
依頼の寿命へ意味を変えません。過去の行、未計測の操作、プロセス中断時の記録について、
欠損値を日時差や 0 で補完しません。

## 計測区間

`read_file`、構造化ファイルの inspect/apply、`write_file`、artifact upload commit、
ZIP の読み取り・展開、ファイル操作 primitive、まとめた読み取り・編集を対象にします。
互換名からの呼び出しや入れ子の同期操作では、外側の計測区間を共有します。
transfer の chunk event を独立した operation に変換しません。

実際の処理に応じて、入力・path・identity 検査、read、hash、decode/parse、transform、
encoding、before/after checkpoint、diff、staging、CAS、transaction、書き込み後検証、
復旧、rollback metadata の確定、既存 Audit の永続化を記録します。
存在しない処理のために空の段階を追加しません。

処理段階は開始順で、operation 開始からの offset と経過時間を記録します。
親の段階は子の時間を含みます。**入れ子の段階をすべて加算して total と比較しないでください。**
各段階の終了は total の範囲内です。同じ名称が複数回現れることがあります。
`result_serialization` はサーバー内の結果辞書構築であり、MCP transport の
wire serialization とは区別します。

## 永続性と安全性

計測値は診断データであり、承認、権限、実行経路、CAS、transaction、rollback の
安全性判定には使用しません。名称はコード内の固定語彙です。引数、path、本文、credential、
例外本文を計測 payload に保存しません。

各段階ではメモリだけを更新します。既存の durable Audit と transaction journal は
従来どおり保存し、詳細時間は関数の終了時に一括保存します。プロセス強制終了や
停電では未保存の時間が失われ得ます。これを操作成功や復旧完了の根拠にしません。
例外で終わった段階と、完了済みの段階を保存し、復旧が実行された場合も同じ区間に含めます。
診断値の保存失敗は、本来の操作結果や例外を置き換えません。

診断保存では lifecycle の `updated_at` や event を更新しません。
Live Activity／Activity Monitor に二重の完了通知や内部段階の行を作りません。
詳細は `audit_get`、一覧の通常監視は従来の Activity を使用してください。

## 互換性と保存上限

既存の列追加方式で `operations.timing_json` を nullable TEXT として追加します。
新規 DB にも同じ列を作り、既存行は NULL のまま維持します。
`audit_get` の `timings` は追加フィールドです。既存の request/result、status、tier、
rollback state、event と組み合わせて解析します。一覧に phase payload は展開しません。

schema version は 1、段階数の上限は 128 です。超過は件数として示し、無制限に蓄積しません。
`dropped_phase_count` は 131,072 で飽和します。その値は「少なくともその件数」を意味します。
JSON 自体は 64 KiB 以下、かつ `max_audit_record_bytes` 以下です。同じ呼び出しが
既存の失敗処理で複数の Audit 行を作る場合、最大 8 行に同じ呼び出し区間を関連付けます。
JSON の型、固定語彙、非負の整数、順序、total 内への収まりを保存前に検証します。
既存の監査レコードサイズ・DB 容量・operation retention 制限も適用します。
計測値だけを別の無期限イベント表に蓄積しません。

手動操作、ユーザーが選ぶ選択的 Undo、時点指定 rollback の意味と承認経路は変更しません。
カスケードを自動選択・自動実行する機能はこの変更に含みません。

## schema v1 と解析例

以下は構造の説明用の値で、実測値ではありません。

```json
{
  "schema_version": 1,
  "total_ns": 1000000,
  "total_ms": 1.0,
  "status": "succeeded",
  "phases": [
    {"sequence": 1, "name": "source_read", "offset_ns": 100000,
     "duration_ns": 500000, "status": "succeeded"}
  ],
  "dropped_phase_count": 0,
  "failed_phase": null
}
```

`status` は呼び出しの正常 return／例外伝播を示します。権威ある operation status は
既存の Audit 行の `status` です。`failed_phase` は最終例外の発生段階を示し、
原因例外を最大 16 段階まで追います。未計測の部分で発生した例外は `operation_body` までしか
絞れない場合があります。新規ファイルの存在確認など、正常処理で捕捉した検査例外は個々の
phase には `failed` として残りますが、呼び出し成功時の `failed_phase` は null です。
計測は例外本体や traceback を保持しないため、そこに含まれるファイル HANDLE の解放を遅らせません。

SQLite の JSON 関数が利用できる解析環境では、例えば以下で順序と時間を取り出せます。

```sql
SELECT o.id, o.tool_name, o.tier, o.status, o.rollback_state, o.duration_ms,
       json_extract(p.value, '$.sequence') AS sequence,
       json_extract(p.value, '$.name') AS phase_name,
       json_extract(p.value, '$.duration_ns') / 1000000.0 AS phase_ms
FROM operations AS o, json_each(o.timing_json, '$.phases') AS p
WHERE o.id = ?
ORDER BY sequence;
```

`tier` と既存 request/result の route 情報を併用してください。時間計測が新しい実行経路を
選択することはありません。`transaction_open` は transaction 内の対象 HANDLE の取得、
`transaction_finish` は OS transaction の commit／rollback 確定を含む区間です。

## 未計測の区間と今後の候補

- MCP transport と呼び出し前の引数検証、診断値自身の最終 DB 保存は total の外です。
- 各 phase は網羅的な命令トレースではありません。ロック待ち、バックアップ作成、
  一部の補助処理は total に含まれても独立 phase にならず、未分類の差分が残ります。
- 非同期 worker の細分化、起動時 reconciliation、transfer chunk 単位の所要時間、
  メタデータ・監視 API の全体時間は今回の対象外です。
- 次の候補は、ロック待ちの独立計測、backup と checkpoint 内の hash／blob 保存の分離、
  診断保存の待ち時間の縮小です。既存のロック・永続性・復旧順序を維持することを条件とします。
