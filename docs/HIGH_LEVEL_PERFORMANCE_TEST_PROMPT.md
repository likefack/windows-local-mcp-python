# 高水準操作の性能試験とデータ採取

目的は、高水準操作の往復削減効果と Broker 内部の支配的な処理を分けて調べ、速度改善後に
同じ条件で比較できるデータを残すことです。下のプロンプトを実装用 Codex に渡してください。
これは試験用プログラムの作成・試験実行の依頼文であり、この文書だけで試験を実行した記録ではありません。

## 採取する三つの時間

| 指標 | 測る範囲 | 用途 |
|---|---|---|
| `client_elapsed_ns` | クライアントが1回の MCP 呼び出しを始め、結果を受け取るまで | 通信、応答量、診断保存を含む実際の呼び出しコスト |
| `workflow_elapsed_ns` | 目的を達成するための最初の呼び出しから最後の結果まで | 高水準1回と低水準複数回の比較 |
| `timings.total_ns` と `phases` | 同期 Broker 関数内 | checkpoint、検査、commit、Audit 等の改善箇所を特定 |

外側の時間もクライアントプログラムの `perf_counter_ns()` 等で測ります。
ChatGPT の返答時刻、モデルの思考時間、手動のストップウォッチは性能比較に使いません。
外側と Audit の差は通信だけではありません。引数処理・応答エンコード・最後の診断保存も含みます。

現行コードでは `workspace_tree`、`workspace_search`、`read_files`、`text_file_apply`、
`workspace_apply` は内部計測対象です。`operation_report` は `audit_activity.duration_ms` を返しますが、
詳細な `timings.phases` は返しません。`audit_get(operation_id)` から採取してください。
`artifact_download`／`artifact_upload` の一括操作と `operation_report` 自身には、現時点では
呼び出し全体の内部計測がありません。実行時に再確認し、欠損は NULL／未計測として扱います。

## 最初に比較するケース

| 目的 | 高水準操作 | 比較対象 | 最初の規模 |
|---|---|---|---|
| 複数ファイルを読む | `read_files` | 同じ範囲の `read_file` を順次実行 | 1／10／50ファイル、各4 KiB |
| 一意な文字列を置換 | `text_file_apply` | `read_file` と CAS 付き `write_file` | 4／64 KiB、設定内なら256 KiB |
| 複数ファイルを編集 | `workspace_apply` | `text_file_apply` を順次実行 | 1／5／20ファイル、各4 KiB |
| ツリーを取得 | `workspace_tree` | `list_directory` の再帰取得 | 10／100／500エントリー、深さ2〜4 |
| 文字列を検索 | `workspace_search` | 列挙・読み取り・クライアントで同じリテラル検索 | 10／50ファイル、各4 KiB |
| 状態と変更概要を取得 | `operation_report` | 必要な `audit_get`／`activity_get` の組み合わせ | 同じ完了済み操作を対象 |
| バイナリ転送 | 一括 `artifact_download`／`artifact_upload` | begin／chunk／commit による転送 | 4／64 KiB、設定内なら256 KiB |

実際の上限を先に確認し、超える場合は規模を下げて記録してください。
比較結果は必要な情報の同等性を確認します。検索範囲・行範囲・打ち切り・取得フィールドが違う
結果を、単に速かったという理由で同等とみなしません。
`workspace_apply` と複数の独立した編集は、まとめて復旧できる範囲が異なります。
速度比較はできますが、同じ transaction 保証を持つ代替経路とは扱いません。

## 渡すプロンプト

```text
対象: likefack/windows-local-mcp-python の現在の checkout。

高水準操作のパフォーマンスを測り、今後の速度改善前後を比較するための、再実行可能な
試験プログラムとデータ採取・集計手順を用意し、実行可能な範囲で実測してください。
この段階では製品の速度改善を実装せず、まず再現可能な基準データを確立してください。

AGENTS.md、README、SPEC、Audit の性能仕様、高水準操作と既存 MCP integration test を確認し、
実際のツール引数、設定上限、計測対象、起動方法に合わせて設計してください。
docs/HIGH_LEVEL_PERFORMANCE_TEST_PROMPT.md の比較ケースと採取形式を基準にしてください。
試験の実現手法は既存設計に合わせて選択して構いません。

要件:
1. 現在の checkout と無関係な変更を保持する。既存の利用中 workspace／data を試験データで
   汚さず、専用 workspace・data・設定と決定的な合成データを使う。一時出力は .dev-tmp 配下。
   再利用する試験プログラムと説明書は適切な場所に残す。commit／push はしない。
2. 実 MCP クライアントからの通常呼び出しを主測定とする。直接 Python 関数を呼ぶ補助測定、
   stdio、Tunnel の測定結果を混同しない。Tunnel が使えなければ未実施と記録する。
   モデルの思考時間を含めず、クライアントプログラムで単調増加時計による時間を採る。
3. read_files、text_file_apply、workspace_apply を優先し、workspace_tree、workspace_search、
   operation_report、一括 artifact 操作を続ける。高水準操作単体のコストと、同じ目的を
   低水準操作の組み合わせで達成するコストを比較する。
4. まず各ケース少数回の動作確認を行う。正常なケースをウォームアップ3回、測定30回で採る。
   成功確認後に増やすこと。初回起動・初回呼び出しは別に記録し、安定後の分布に混ぜない。
   コールドキャッシュと未検証の状態を断定しない。初期試験は並列度1。
5. 両方式の順序を交互にする等、実行順・キャッシュの偏りを抑える。OS、runtime、設定、
   応答範囲、データ、計測ON状態を揃える。DB／WAL／履歴の増加を記録し、無視しない。
6. 各反復は同じ開始内容と同じ編集効果を持たせる。fixture復元・準備・事後検証は測定区間から
   外すが、現実の操作に必要なhash取得等はworkflow測定に含める。hash既知の操作単体試験も
   行う場合は別ケースとして記録する。復元にUndo／rollbackを自動利用しない。
7. 成功条件を本文／hash／対象ファイル数／検索結果等で確認する。部分取得・打ち切り・
   件数不足・誤った出力・競合失敗を成功試料に混ぜない。試料を黙って除外しない。
8. 1回ごとのクライアント時間、workflow時間、MCP呼び出し数、操作ID一覧、入力規模、
   応答bytes、statusを記録する。返却bytesはどの表現を数えたか明記する。
9. 測定呼び出しの応答後に時計を止め、それから対象IDのAuditを採取する。audit_getや
   operation_reportによる診断取得を、対象操作の時間・呼び出し数へ加算しない。
   ただしoperation_report自体の比較ケースでは、その本来の呼び出しを測る。
10. Auditからduration_ms、timings全体、phase順序、status、route関連情報、rollback stateを
    取得する。operation_reportだけではphase情報が揃うと仮定しない。
    内部計測欠損、phase上限による省略、採取前のretention削除は明示する。欠損を0にしない。
11. mutation失敗を速度上の勝利として扱わない。CAS不一致、一意でない置換、上限拒否を
    少数の独立した失敗ケースとして採り、正常系と分ける。commit失敗の注入や復旧試験は
    隔離した自動テストで行い、稼働中のサーバーや実データには注入しない。
12. 既存の承認、CAS、identity、checkpoint、transaction、rollback、監査の永続性、容量上限を
    弱めない。phaseをLive Activityの大量の行にしない。安全性検査を省いて高速化しない。
    カスケード選択的Undoはユーザーの選択に委ね、手動操作との分離を維持する。
13. request／response全文やcredentialは採取ファイルへ無条件に保存しない。合成fixtureの
    内容は生成条件とhashで再現し、試験データは必要最小限の情報を保存する。

集計:
- ケース別・方式別に成功件数、失敗件数、欠損件数、中央値、p95、最小・最大を示す。
  p95の計算法を固定し、30件での裾の推定は粗いことを明記する。
- 高水準化による総時間、呼び出し数、応答量の変化を比較する。
- 内部phaseは入れ子の重複加算を避け、operation_bodyを別の処理として足さない。
  未分類時間と省略ありの試料を明示する。同じ呼び出しに属する複数Audit行も二重加算しない。
- 成功結果の正しさを維持した上で、改善候補を根拠・見込める効果・変更リスクの順にまとめる。
  未分類の時間を通信やロック待ち等と断定しない。

成果物:
再実行コマンド、fixture生成条件、run_metadata.json、samples.jsonl、audit_timings.jsonl、
集計CSV、結果説明を残す。失敗・未実施・未計測も報告する。
試験コードの確認と動作検証を行い、初心者が同じ手順で再採取できるよう案内する。
OSの不可避な承認を除き、独立して進められる部分は自律的に進めてください。
```

## データの保存方法

各実行を `.dev-tmp/performance/<run_id>/` に分けます。改善前のフォルダーは上書きせず、
改善後は別の run_id へ採取してください。採取完了後は比較に必要なファイルを保存します。

| ファイル | 内容 |
|---|---|
| `run_metadata.json` | UTC日時、HEAD、未コミット差分の識別用hash、実際に読み込んだruntimeの版／source hash、Python／OS、transport、秘密を除いた有効設定、fixture hash、反復数、並列度、初期／終了時DB・WALサイズ |
| `samples.jsonl` | 1呼び出しまたは1workflowごとの未集計値。sample_id、case_id、方式、反復、warmup区分、成功／失敗、client/workflow時間、call数、operation_ids、bytes、検証結果 |
| `audit_timings.jsonl` | sample_idとoperation_id、tool、tier／route、status、rollback_state、duration_ms、timings。request/result全文は除く |
| `summary.csv` | ケース・方式・規模ごとの件数、欠損、中央値、p95、最小・最大 |
| `report.md` | 比較結果、支配的なphase、改善候補、試験条件の差、未検証事項 |

操作IDは原則として各ツールの戻り値から記録します。失敗時に返らない場合は、専用サーバーで
前後のAudit ID差分とtool／順序を照合し、曖昧なら関連付け不能とします。
「最後のAudit行」を無条件に選ぶと、診断取得自身や別操作の行を拾うので避けます。

大量採取では、対象IDを控えてからローカルの Audit DB を読み取り専用で採取する方法も使えます。
稼働中の `audit.db` だけを単独コピーするとWAL内の記録を落とす可能性があるため、
SQLiteの整合した読み取り／backupを使ってください。複製DBの外部共有は不要です。
通常は操作ごと、または小さな測定ブロックごとに採取すれば、履歴の削除による欠損を減らせます。

## 速度改善に使う順序

1. `read_files` と複数 `read_file` のworkflow中央値、呼び出し数を比較する。
2. `workspace_apply` のファイル数別の全体時間を確認し、checkpoint／Audit／commitの増え方を見る。
3. 同じfixtureと採取手順を固定して、一度に一つの改善を行う。
4. 改善前後で出力・失敗時の保護・復旧を確認し、性能差が反復のばらつきより大きいか評価する。
5. ローカル内部の改善が確認できてから、必要に応じて同じworkflowをTunnel経由でも比較する。

外側が短縮し内部時間が同程度なら、往復や応答量の削減が寄与した可能性があります。
内部時間も短縮した場合はphaseの差を確認します。どちらも因果の断定には条件を揃えた対照が必要です。
