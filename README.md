# Windows Local MCP

Windows上の1つの作業フォルダを、MCP経由で安全寄りに操作するためのPython実装です。

中村さん（nakasyou）の `local-mcp` が採用する以下の考え方を参考に、Windows向けにゼロから構成しています。

- ファイル閲覧・編集とコマンド実行をMCPツールとして公開
- 低リスク操作と、ホスト権限を使う操作を分離
- 長時間コマンドをジョブとして管理
- 人間が承認または拒否
- 操作履歴と結果を永続保存

この実装は `nakasyou/local-mcp` の直接移植ではなく、独立した参照実装です。

## 実装済み

### ファイル操作

- `session_info`
- `list_directory`
- `read_file`
- `get_image`
- `write_file`

`write_file` は変更前後のSHA-256、unified diff、変更前バックアップを保存します。

### 制限付きコマンド実行

- `execute`
- `start_command`
- `poll_job`
- `stop_job`

`execute` は1つの共通実行窓口です。Git、Flutter、Dart、ADBごとにプロセス起動、出力回収、タイムアウト、ログ保存を重複実装しません。

既定で許可する例:

- `git status`
- `git diff`
- `git log`
- `flutter analyze`
- `flutter test`
- `flutter build`
- `dart analyze`
- `dart format`
- `adb devices`
- 制限された `adb shell`
- 設定ファイルで明示したPowerShellスクリプト

`git push`、`git reset --hard`、任意の `powershell -Command` は通常の `execute` では拒否されます。

### 承認付きホストコマンド

- `request_host_command`
- `poll_approval`
- `execute_approved`

任意PowerShell、ネットワークを使う処理、削除やプロセス操作などは、まず承認要求としてSQLiteへ保存します。

別ターミナルの承認UIで、利用者が実行コマンド全文、作業ディレクトリ、理由、ネットワーク要否、リスク説明、要求ハッシュを確認します。

承認後も、承認対象のハッシュが一致しなければ実行されません。

### 耐久性のある監査ログ

標準では次に保存します。

```text
%LOCALAPPDATA%\WindowsLocalMCP\
├─ audit.db
├─ outputs\
├─ diffs\
├─ backups\
└─ git-snapshots\
```

記録項目:

- 操作ID
- MCPツール名
- リスク階層
- コマンドと引数
- 作業ディレクトリ
- 承認状態、承認者、承認時刻、メモ
- 開始・終了時刻
- PID
- 終了コード
- stdout / stderr
- 実行前後のGit状態
- ファイル差分
- エラー
- 状態遷移イベント

## 安全上の限界

中村さん版はLinuxのLandlock/bubblewrap、macOSのSeatbeltを使ってOSレベルで隔離します。

このWindows版は、現時点では同等のWindows AppContainerまたはWindows Sandbox隔離を実装していません。

代わりに次を行います。

- 作業フォルダ外の読み書きを拒否
- 秘密情報らしいファイルを拒否
- `subprocess` を `shell=False` で起動
- 許可プログラムとサブコマンドを限定
- 任意PowerShellは承認付き経路へ送る
- 直接コミット、push、削除を既定で許可しない
- すべて監査ログへ記録

Windows OSレベルの「ネットワーク無効化」は保証していません。安全コマンドには既知のネットワーク操作を含めませんが、許可したプログラム自体の挙動までは完全には隔離できません。

## 必要環境

- Windows 10または11
- Python 3.11以上
- Git
- 必要に応じてFlutter、Dart、Android SDK Platform Tools
- ChatGPTへ接続する場合は、そのアカウントで利用可能なDeveloper ModeとローカルMCP接続手段

## 導入

```powershell
cd C:\path\to\windows-local-mcp-python
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"
Copy-Item .\config.example.toml .\config.toml
```

`config.toml` の作業フォルダを変更します。

```toml
workspace_root = "C:\\dev\\decision-deck"
```

MCP Inspectorで確認します。

```powershell
$env:LOCAL_MCP_CONFIG = "$PWD\config.toml"
mcp dev .\src\windows_local_mcp\server.py
```

通常起動:

```powershell
.\run-server.ps1 `
  -Root "C:\dev\decision-deck" `
  -Config "$PWD\config.toml"
```

別のPowerShellで承認UIを起動します。

```powershell
.\run-approvals.ps1 -Config "$PWD\config.toml"
```

承認UI:

- `y`: 承認
- `n`: 拒否
- `s`: 保留
- `q`: 終了

## ChatGPTへの接続

このサーバーは既定でstdio transportを使います。ChatGPT Developer ModeやSecure MCP Tunnelへ接続する場合は、その時点の公式手順とアカウント上の提供状態を優先してください。

認証情報やトンネルIDはこのリポジトリに保存しないでください。

まずMCP Inspectorでローカル動作を確認し、その後にトンネル側から `run-server.ps1` を起動させます。

## 典型例

安全コマンド:

```json
{
  "program": "flutter",
  "args": ["analyze"],
  "cwd": "app",
  "foreground_timeout_seconds": 30,
  "max_runtime_seconds": 900
}
```

30秒を超えると `job_id` が返り、処理はバックグラウンドで続きます。

任意PowerShellの承認要求:

```json
{
  "command": [
    "powershell.exe",
    "-NoProfile",
    "-File",
    "scripts\\run-all.ps1"
  ],
  "cwd": ".",
  "reason": "API、Worker、Emulator、Flutterを起動する",
  "network_required": false,
  "risk_summary": "複数のローカルプロセスを起動する"
}
```

## ADB

このMCPがWindows上の `adb.exe` を呼ぶ場合、操作対象はそのADBに接続されているWindows上のAndroid端末またはAndroid Emulatorです。

`adb devices` に `emulator-5554` が出れば、通常はそのエミュレータを操作します。OpenAI側の一時コンテナ内のエミュレータではありません。

## 未実装

- Windows AppContainerによるOSレベル隔離
- スマホのDecision Deckを使った遠隔承認
- Git commit / push専用ツール
- 自動ロールバック
- 複数ユーザー認証
- 暗号署名付き監査ログ
- ChatGPT会話を外部から能動的に再開する機能
