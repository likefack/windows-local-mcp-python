# Windows Local MCP

ChatGPT から、指定した 1 つの Windows 作業領域を安全に読み書きするためのローカル MCP サーバーです。ファイル編集、構造化ファイル処理、監査、承認付きコマンド、変更履歴、Undo／rollback を提供します。

通常起動は管理者権限で行わないでください。`workspace_root` はプロジェクト単位で指定し、ドライブ直下やユーザーフォルダー全体を指定しないでください。

## 実行構成

処理は次の 4 種類に分かれます。安全性を安価に閉じられる処理まで Sandbox に送らず、作用範囲を閉じられない処理だけを隔離します。

1. **WLMCP Broker**
   - 対象パス、入出力、容量、副作用を WLMCP が限定できる処理です。
   - ファイル read/write、差分、固定文法の Git 読み取り、固定 ADB 読み取り、バイナリ転送、checkpoint、transaction、Undo／rollback を直接扱います。
2. **構造化処理**
   - DOCX、XLSX、CSV／TSV、ZIP、一般画像を宣言的な操作として処理します。
   - 現在は WLMCP 管理処理を使用し、処理結果を artifact として検証してから Broker の transaction で反映します。将来の ChatGPT container 処理も同じバイナリ転送境界へ接続できます。
3. **Codex Sandbox**
   - 任意コード、project script／plugin、test／build、一般コマンドなど、WLMCP だけで副作用を閉じにくい処理を実行します。
   - 利用にはローカル承認と、この PC での Sandbox 実機検証成功が必要です。失敗時に Host へ自動移行しません。
4. **Approved Host**
   - 実際の Windows ユーザー権限が必要な処理だけを、Sandbox とは別の承認で 1 回実行します。
   - OS、ネットワーク、device、`.git`、外部サービス等への作用は workspace checkpoint だけでは戻せません。

旧 Safe Tier／AppContainer は現行の方針には存在しません。旧設定が残っている場合は、弱い互換動作へ移らず起動を拒否します。

## セットアップ

Python 3.11 以上を使用します。

```powershell
Set-Location C:\dev\windows-local-mcp-python
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
Copy-Item config.example.toml config.local.toml
```

`config.local.toml` で少なくとも次を設定します。このファイルと `data_dir` は workspace 外へ置いてください。

```toml
workspace_root = "C:\\dev\\your-project"
data_dir = "C:\\Users\\you\\AppData\\Local\\windows-local-mcp\\your-project"
protect_data_dir_acl = true
```

起動は次のとおりです。設定が不正な場合は、workspace を操作する前に起動を拒否します。

```powershell
.\run-server.ps1 -Config .\config.local.toml
```

Secure MCP Tunnel には、Shell 文字列ではなく次の argv を登録します。

```text
powershell.exe -NoProfile -File C:\dev\windows-local-mcp-python\run-server.ps1 -Config C:\path\to\config.local.toml
```

複数 workspace は別々の `config`、`data_dir`、Sandbox scratch を使用してください。namespace marker が workspace、data_dir、実体識別子の混在を拒否します。

## 主な機能

| 用途 | 経路 | 主な tool |
| --- | --- | --- |
| テキスト／バイナリの読み書き | Broker | `read_file`, `write_file`, artifact transfer |
| Git 状態、差分、履歴 | Broker | `git_info`, 固定文法の `execute_readonly` |
| Emulator の限定読み取り | Broker | `adb_read`, `get_adb_screenshot` |
| DOCX／XLSX／CSV／TSV／ZIP／画像 | 構造化処理 | `structured_file_inspect`, `structured_file_apply` 等 |
| Python、PowerShell、Node、test、build、project script | Codex Sandbox | `request_sandbox_command` |
| Sandbox 外の Windows 権限／network が必要な処理 | Approved Host | `request_host_command` |
| 状態確認、停止、監査 | Broker | `poll_job`, `stop_job`, `activity_get`, `audit_get` |
| 変更取消 | Broker | selective Undo、point-in-time rollback |

`execute_workspace_write` は互換用の公開面を残していますが、Dart／Flutter 等の project-controlled 処理は拒否され、`request_sandbox_command` を案内します。

バイナリのダウンロード転送は、開始時に元ファイルの前後同一性と SHA-256 を確認した不変スナップショットを制御領域へ固定し、各チャンクでは必要範囲だけを読み取ります。アップロード転送は開始時に申告済み全容量を予約するため、チャンクごとのデータ領域全走査を行いません。別々の転送は並行できますが、同一転送内のオフセット順序、fsync、完了時の全体 SHA-256、元ファイルと出力先の同時変更検知は維持します。監査は転送開始を親操作、各チャンクを SHA-256 付きの永続イベントとして記録し、チャンク数に比例するタイムライン行と同期書き込みを抑えます。

## 構造化ファイル

- **DOCX**: paragraph／run、検索置換、表、header/footer、style、section、page 設定、metadata。通常文書は文書ライブラリで処理します。追跡変更、コメント、macro、埋め込み object、データ連動 Custom XML などがある文書でも、電子署名がなく、操作が `replace_text` または `metadata_set` に限定される場合は、対象 XML 部分だけを書き換えて未対応部分を保持します。それ以外の操作は拒否します。
- **XLSX**: 値／数式、範囲、行列、sheet、copy/fill、書式、merge、freeze pane、filter、Table、入力規則、条件付き書式、基本 chart／page setup。macro、pivot、外部接続、未対応拡張等がある workbook でも、電子署名がなく、操作が `cell_set`、`range_set`、`range_clear` に限定される場合は、対象 worksheet XML だけを書き換えて未対応部分を保持します。それ以外の操作は拒否します。
- **CSV／TSV**: 範囲、cell／row／column、append／insert／delete。encoding、delimiter、quote、newline を識別して保持し、判定が曖昧なら拒否します。
- **ZIP**: listing、read、create/update、複数展開。traversal、絶対 path、ADS、予約名、大小文字衝突、件数、展開後容量を検査し、複数 file は transaction で一括反映します。
- **画像**: inspect、resize、thumbnail、crop、rotate、flip、変換、quality、metadata 除去。pixel／decoded memory を制限し、未対応の multi-frame は破壊的変換せず拒否します。

変換中は workspace-wide lock を保持しません。commit 直前に source の raw bytes identity を再確認し、別処理による変更があれば conflict として拒否します。Office macro を含む bytes の転送・保存と、macro の実行は別の能力です。

## 承認と実行時 binding

`request_sandbox_command` と `request_host_command` は要求を作るだけで、その呼び出し時にはコマンドを実行しません。ローカル承認 UI で承認された要求を 1 回だけ claim して実行します。

承認には、argv、cwd、実行ファイルと入力の hash、checkpoint、workspace／data_dir の実体 identity、設定、WLMCP build と policy generation、Sandbox backend を結合します。更新や設定変更後の古い承認、二重 claim、replay は拒否します。

Approved Host は同一ユーザー権限で制御領域へ到達し得るため、実行中の audit、approval staging、CAS、journal、transfer、worker context を監視し、整合性を確認できない場合は fail closed marker を残して以後の処理を停止します。これは別 OS アカウントや service による完全な権限分離ではなく、改ざん検出境界です。

## Codex Sandbox

`config.local.toml` で installed Codex CLI を指定できます。

```toml
approved_sandbox_enabled = true
approved_sandbox_codex_path = "C:\\path\\to\\codex.exe"
approved_sandbox_require_live_verification = true
sandbox_dependency_readable_paths = []
```

WLMCP は `codex sandbox` 専用 entrypoint を argv で起動し、agent／model API は使用しません。launcher と helper の path、署名、hash、file identity を承認と実行時に検証します。

設定されていること、機能が有効なこと、backend を解決できること、この PC で security boundary まで実機検証済みであることは別々に表示されます。実機検証は次を確認します。

```powershell
$env:LOCAL_MCP_CONFIG = 'C:\path\to\config.local.toml'
.\.venv\Scripts\python.exe -m windows_local_mcp.cli verify-codex-sandbox
```

検証対象は simple command、Python child、source read、scratch write、control-plane denial、network deny、child／grandchild containment、timeout／termination、filesystem resource admission です。1 項目でも失敗した marker は「検証済み」として受理されません。

## ファイルと制御領域の保護

- workspace path は canonical path、reparse point、hardlink、予約名、ADS、親／target identity を検査します。
- optimistic concurrency には表示用文字列ではなく raw file bytes の SHA-256 を使います。CRLF も raw identity に含まれます。
- 書き込みは checkpoint、durable journal、atomic replacement、post-write 検証を通します。第三者変更を復旧処理が上書きしません。
- `data_dir`、Sandbox scratch、workspace は分離し、起動時に lock／atomic replacement／filesystem identity の前提を確認します。
- `.env`、credential 等の保護対象は通常の read、diff、Git snapshot から返しません。audit、approval、Activity、argv、stdout／stderr preview は secret を伏せ字にします。
- 同時 job、pending approval、出力、artifact、data_dir、Sandbox scratch、structured element／pixel／archive 展開量に上限があります。

## Activity、Undo、rollback

Live Activity と Timeline は Read／Edited／Running／Finished、実行境界、network policy、before／after、conflict、failure／recovery、bounded stdout／stderr preview、rollback 可否を記録します。詳細は `activity_get`／`audit_get` で確認します。

checkpoint が戻せるのは、manifest に含まれる通常の workspace file bytes です。`.git`、ACL、device、network、外部サービス、別 process の副作用は戻せません。selective Undo は独立した text 変更を保持できますが、binary／曖昧な競合では停止します。

## 検証範囲

unit／integration test、Windows 上の Sandbox 実機検証、Secure MCP Tunnel／ChatGPT E2E は別の証拠です。テスト成功だけで OS 隔離や Tunnel E2E を検証済みとは表示しません。

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Sandbox が利用不能、未検証、timeout、setup failure、command failure の場合は、その operation を unavailable／failed として表示します。Approved Host へ自動 fallback しません。
