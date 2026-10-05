# 決定済みのファイル操作をサーバー内で完了する

## 対象と設計判断

2026-10-06。既存の `workspace_apply` は複数のUTF-8テキスト編集を一つの復元処理にまとめるが、作成・コピー・移動・削除は別々の呼び出しが必要だった。`text_file_apply` / `workspace_apply` には読取結果のSHA-256の転記も必要であり、`workspace_search` の一致行から置換要求を構成する処理もクライアント側に残っていた。

次の三つを追加する。既存APIの引数と動作は維持する。

| API | 役割 |
| --- | --- |
| `workspace_batch(operations, preview=False, reason="")` | 決定済みの操作列を事前検証し、一つの変更計画として適用する |
| `workspace_replace(path, old_text, new_text, expected_total_matches, ..., preview=False)` | 範囲内の完全一致検索・件数確認・UTF-8置換・CAS・結果検証をサーバー内で実行する |
| `workspace_plan_apply(plan_id, reason="")` | プレビューで確定した計画を、内容・識別情報を再検証して一度だけ適用する |

`preview=True` はワークスペースを変更せず、対象・件数と `plan_id` を返す。実行時に対象を追加したり、別パスへ計画を流用したりする引数はない。新しく追加されたファイルはプレビューの対象に含まれず、適用時に自動追加しない。範囲を再探索したい場合は新しい計画を作る。

一般的な `read_file` 全体に永続的なファイル参照を導入することは見送った。今回の用途は、操作内部の検証済み読取と、必要な場合だけ保存する短命な計画で、生SHA-256の転記を除去できる。意味判断に必要な内容確認は引き続き `read_files`、`workspace_search` と既存のCAS付き編集を利用する。

## 操作列

```json
[
  {"op": "mkdir", "path": "output"},
  {"op": "create", "path": "output/new.txt", "content": "確定した内容"},
  {"op": "move", "source": "output/new.txt", "destination": "output/final.txt"},
  {"op": "replace", "path": "existing.txt", "old_text": "旧表記", "new_text": "新表記"},
  {"op": "copy", "source": "source.bin", "destination": "output/copy.bin"},
  {"op": "delete", "path": "unneeded.txt"}
]
```

操作列の順序で仮想的な状態を計算し、全ての検証が終わるまで書き込まない。新規フォルダー内への作成、新規作成ファイルの置換・移動を扱う。既存ファイルの変更には必要に応じて `expected_sha256` を指定できる。省略時はサーバーが要求内で読んだ状態をCASの基準とするため、以前クライアントが読んだ状態との一致を約束するものではない。その保証が必要ならプレビューまたは既存のCAS APIを使う。

新規保存先は未作成であることを要求し、上書き・既存ディレクトリの移動や削除・大文字小文字だけの改名は扱わない。衝突、同一対象への矛盾した更新、曖昧な依存関係は拒否する。従来の `move_file` などの機能は維持する。コピー・移動は既存ファイルのバイト列を使用し、文字列やBase64へ変換しない。バイナリの外部送受信は `artifact_import_file` / `artifact_upload` / `artifact_download` 系の責務のままとする。

batchは最終的なファイル内容とディレクトリ構成を適用する方式である。中間ファイルを実際に作る必要がなければ作らない。コピー・移動による保存先は内容を再作成するため、元のWindowsファイルID、ACL、時刻などのメタデータ保持は保証しない。既存のファイルオブジェクトをそのまま改名する必要がある場合は `move_file` を使う。

## 検索・置換

必須の `path` は探索ルートまたは単一ファイル、`old_text` / `new_text` は意味判断済みの文字列、`expected_total_matches` は非重複一致の合計件数である。直接適用する場合は件数を必須とし、不一致は変更前に拒否する。`preview=True` では件数を省略でき、返された件数と対象を確認してから計画IDで適用できる。`file_glob` はファイル名のパターンであり、パスパターンではない。

- `case_sensitive=True` が既定。文字列とglobの両方に適用する。
- `case_sensitive=False` の文字列一致はPythonのUnicode `re.IGNORECASE` と同じ大文字小文字対応とする。入力はリテラルとしてエスケープされ、置換文字列の逆参照も解釈しない。`ß` と `ss` のような長さの変わるcasefold一致は行わない。globは既存方式と同じcasefold後のファイル名一致である。
- `match_mode="all"` は各ファイルの全一致、`"unique_per_file"` は一致する各ファイルにつき厳密に1件を要求する。
- 空の検索文字列、NULを含むテキスト、UTF-8でない対象ファイルは拒否する。改行やBOMなど、置換範囲外のバイト表現を保つ。
- 最大深さは対象範囲の一部である。探索ファイル数・エントリ数・読取バイト数・一致数・変更ファイル数・出力バイト数の超過は、途中結果の適用ではなく要求全体の拒否となる。
- 文脈によって置換可否が異なる場合は使わない。公開APIとしての正規表現置換は追加しない。

## CAS・識別情報・保存期間

検証済みの読取ハンドルから取得したバイト列、ハッシュ、Windowsのvolume/file identityを内部で保持する。計画に含まれる変更しないコピー元や一致なしファイルも再検証する。対象・保存先・親ディレクトリの境界と識別情報を検査し、対象スロットとスレッドロックを決定的な順序で取得する。変更しないコピー元と既存の親ディレクトリのハンドルは適用中も保持する。

計画IDは192ビットのランダム値から作る32文字の不透明な参照で、パス・内容・ハッシュ・秘密情報を埋め込まない。サーバープロセス内だけで有効、有効期間は作成から300秒、最大4件、保持する全計画のバイト列合計は `max_high_level_total_bytes` 以下とする。失効済み計画は次の保存・取得時に破棄する。再起動後は全て無効になる。適用開始時に参照を消費し、失敗時も再使用しない。監査には計画IDを保存しない。

## トランザクションと復旧

全体の事前検証後、対象に限定したcheckpoint、内容アドレス付きの変更先manifest、永続journalを既存の `restore_workspace_state` へ渡す。checkpointの内容が計画時点の読取結果と一致することも確認し、途中で取得した新しいcheckpointをCASの基準にすり替えない。適用直前と各ファイルのcommitで元のファイル識別情報を検証する。各ファイルは既存のWindowsトランザクション付きプリミティブを使う。

複数ファイル全体は既存仕様どおり、途中失敗時に開始状態を自動復元する方式である。全ファイルの変更が他プロセスから一瞬で見えるOS全体の原子性は約束しない。事後checkpointと変更先manifestを比較し、ハッシュとディレクトリ状態の一致を確認する。

失敗して復元できた場合は `failed_recovered`、復元が失敗した場合は `recovery_required` を記録し、後続変更を拒否する。中間失敗を通常成功として返さず、低水準APIへの自動切替や二重実行をしない。Undo・rollbackは既存の承認と復旧経路を利用する。

完了イベントと監査成功行の保存を、journalの確定より先に行う。保存に失敗した場合も復元可能な状態を残す。事前検証中にjournalが作られた後で拒否した場合は、`failed_preflight` と監査の終端状態を照合し、未実行の要求が後続変更を永久に止めないようにする。新規ディレクトリは既存のトランザクション付き作成を使い、直前に現れた別プロセスのディレクトリを採用しない。所有を確認できない衝突ディレクトリは、空でも自動削除せず `recovery_required` へ残す。

## 上限・監査・既存機能との境界

既存設定の `max_high_level_files`、`max_high_level_total_bytes`、`max_text_file_bytes`、`max_write_bytes`、探索深さ・エントリ数・一致数上限、checkpoint・diff・data directoryの容量制限を利用する。APIの上限指定は設定上限を引き上げない。

プレビューと適用はそれぞれ一つの監査operationとなり、内部の事前検証・ロック・ステージング・完了・失敗をeventとして追跡できる。通常のActivityには操作全体を表示し、詳細な時間測定は `audit_get`、概要は `operation_report` で確認する。置換文字列とファイル内容を計画の監査要求に記録しない。

Live Activity では高水準操作の変更件数・概要・経過時間・所要時間だけを表示する。保存プレビュー上限を超える完全な差分や変更前後のバイト列は `operation_changes(operation_id)` でページ取得する。その操作だけを取り消す場合は `request_selective_undo(operation_id)` でローカル承認を要求する。詳細は [Live Activity の変更表示と取り消し](LIVE_ACTIVITY_CHANGES.md) を参照。

添付ファイル取り込み、直接export、チャンク再送、再開、Base64上限、転送TTL、downloadのI/Oは本変更の対象外である。既存artifact APIを利用してワークスペースへ置いたファイルを、その後のbatchで扱える。転送状態やチャンク管理を変更計画へ持ち込まない。

## 検証と測定

自動検証は専用の一時workspaceと合成データで行う。測定スクリプト `scripts/benchmark_deterministic_operations.py` は、旧APIを組み立てる方式と新APIについて、呼出数、入出力JSONの文字数・UTF-8バイト数、ハッシュ転記量、ローカル経過時間、監査内処理時間、監査event・SQL書込回数を比較する。

この測定はPythonからMCPツールの入口を直接呼ぶ比較であり、ChatGPT・ネットワーク・MCP転送・LLM生成待ちを含む実測ではない。

### 完成した実装での測定結果

2026-10-06、日本時間。各方式3標本の中央値。batchはmkdir→作成→移動→既存ファイル削除、置換は4ファイル各1一致。旧batchも作成結果のハッシュを移動へ再利用し、読取は削除対象の状態確認に使う。準備・診断取得は時間計測の対象外とし、全標本で旧方式と新方式の最終ファイル内容・構成の一致を確認した。

| 指標 | batch 旧→新 | 検索・置換 旧→新 |
| --- | --- | --- |
| ツール呼出数 | 5→1 | 3→1 |
| 入力JSON文字数 / UTF-8 bytes | 715→328 | 1,281→382 |
| 出力JSON文字数 / UTF-8 bytes | 3,767→1,100 | 3,289→1,176 |
| 生SHA-256の転記文字数 | 128→0 | 256→0 |
| ローカル処理全体、ms | 889.248→431.279 | 779.741→639.491 |
| 監査内の処理時間合計、ms | 818.584→418.889 | 744.884→627.310 |
| 監査イベント数 | 13→7 | 13→7 |
| 監査SQLiteへの書込文実行数 | 32→11 | 23→11 |
| 監査SQLite接続数 | 27→10 | 20→10 |

入力例はASCIIなので文字数とUTF-8バイト数が等しい。JSONは引数・結果をコンパクトに直列化した推定通信量で、MCPの包絡情報・転送ヘッダー等は含まない。SQL書込文実行数は監査DBのみを数え、journal・checkpoint・blobのファイル書込回数ではない。3標本の小さい合成例であり、すべての規模で同じ短縮率になる保証はない。

監査の詳細時間は既存の128フェーズ上限を維持する。多数の検証を行う要求では後半の詳細フェーズが省略され、`dropped_phase_count` に記録される。上表の内部時間は省略されない `timings.total_ns` の合計であり、入れ子フェーズの合算ではない。最終の監査・性能テスト8件も成功した。

確認を挟む方式では、プレビューと適用の2呼出で32文字の計画IDだけを引き継ぐ。これはAPI構成とテストで確認した動作であり、上表の時間測定は直接適用方式である。LLMから検索結果の再構築、ファイルごとのSHA-256転記、操作途中の状態管理を除去できた。

生データは [測定記録JSON](DETERMINISTIC_WORKSPACE_BENCHMARK_2026_10_06.json)、再実行は次のコマンドを用いる。

```powershell
$env:PYTHONIOENCODING = 'utf-8'
.\.venv\Scripts\python.exe scripts/benchmark_deterministic_operations.py --samples 3
```

### 検証結果と制約

- 新規テスト4ファイルは分割実行で62成功、1保留。最終統合27件と、batch計画11件・置換計画19件・計画保存5件が成功した。保留1件はWindowsのシンボリックリンク作成権限不足である。実junction・ハードリンクによる境界確認は成功した。
- 正常混合操作、事前検証失敗時の無変更、衝突・矛盾・stale CAS、途中失敗の復元、復元不能時の後続拒否、監査完了故障、所有不明のディレクトリ競合、事後検証失敗、checkpoint取得時の競合、非UTF-8、サイズ上限、旧SHA-256 APIの維持を確認した。
- 広い対象回帰は182成功、5保留、既存の競合テスト2件を分離し、初期化中のWinError 5で3件失敗した。失敗対象だけを別の一時フォルダーで再試験し、パラメーター違いを含む4件すべて成功した。さらにレビュー修正後の対象回帰では72成功・1保留、追加テストの監査概要取得方法に2件の誤りがあったため修正し、最終統合27件を再実行して成功した。
- 既存 `test_windows_transaction.py` の `test_transactional_copy_destination_creation_race_never_overwrites` と `test_transactional_move_destination_creation_race_never_overwrites` は最初の回帰で失敗し、一括操作の実装時には変更せず未解決として記録した。その後の2026-10-06の追跡調査で、TxFによる名前予約後も競合側の作成が成功するというテストの前提誤りを確認し、テストを修正した。トランザクション試験15件、関連回帰105件が成功。過去の成功数に遡って加算しない。原因と検証範囲は [保存先競合の調査記録](WINDOWS_TRANSACTION_DESTINATION_RACE_2026_10_06.md) を参照。
- checkoutに存在した添付取り込み・転送再送・再開等との互換性試験は113成功、1保留。artifact側の実装・設定・既存ドキュメント更新は保持し、送受信機構の重複実装は行っていない。
- 変更範囲のRuff静的検査と差分の空白検査は成功。性能測定の再試行も含め、初期化時の一時的なWinError 5に対してACL変更や安全検査の迂回はしていない。
- 通常Windowsプロセスで合成workspaceのBroker操作を検証した。制限環境では `.dev-tmp` のACLによる拒否があったため、許可されたホスト実行を使用した。テストではApproved Host等の外部健全性確認を置き換えており、SCM/WFP/Sandbox/Approved Hostの実機受容試験ではない。
- 実ChatGPT/Tunnelを含むMCP往復、LLM生成待ち、運用runtimeへの配備・再起動・ツール再登録、実ユーザーデータは未検証。複数ファイル全体のOS原子性、メタデータを保持したbatch移動、永続的な汎用ファイル参照は今回実装していない。

### 変更ファイルと理由

| ファイル | 変更の目的 |
| --- | --- |
| `src/windows_local_mcp/workspace_batch.py` | 操作列の仮想実行、衝突・前提・サイズ検証を変更前に完了する |
| `src/windows_local_mcp/workspace_replace.py` | 範囲探索、完全一致件数、出力容量予測、置換をサーバー内に移す |
| `src/windows_local_mcp/workspace_plan.py` | 検証済み状態・親識別情報と、期限・容量制限付き計画IDを保持する |
| `src/windows_local_mcp/workspace_operations.py` | 一つの監査操作から既存checkpoint・journal・復元・検証を呼ぶ |
| `src/windows_local_mcp/workspace_history.py` | 計画時のファイル識別情報をcommitへ渡し、ディレクトリ衝突を原子的作成と復旧状態で扱う |
| `src/windows_local_mcp/server.py` | 新しい3ツールの登録と利用説明。並行artifact変更は保持 |
| `src/windows_local_mcp/live_activity.py` | 一つの操作として表示し、プレビューを編集完了と表示しない |
| `tests/test_deterministic_workspace_operations.py` | 成功・競合・故障・復旧・監査・互換性の統合試験 |
| `tests/test_workspace_batch_planner.py` / `tests/test_workspace_replace_planner.py` / `tests/test_workspace_plan_store.py` | 計画・資源上限・一致規則・IDの寿命と一度だけの消費を確認 |
| `scripts/benchmark_deterministic_operations.py` | 比較条件・最終状態一致・呼出数・通信量推定・時間・監査を再計測可能にする |
| `README.md` / `SPEC.md` / `VERIFICATION.md` / 本書 / 測定JSON | 公開仕様、判断理由、検証結果、未検証範囲を記録する |

コミットメッセージ案: `feat: ワークスペース一括操作とCAS内包の完全一致置換を追加`
