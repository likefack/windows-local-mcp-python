# Windows Local MCP

OpenAI Secure MCP Tunnelを介して、ChatGPTから1つのWindows開発workspaceを操作するためのローカルMCPサーバーです。ファイル編集、Git状態取得、静的解析、承認付きtest/build、限定ADB操作を、監査ログと容量制限付きで提供します。

> このソフトウェアはWindows Sandboxではありません。安全性は、1インスタンス1workspace、厳格な引数文法、不変snapshot、ローカル承認、プロセスidentity、監査によって成立します。管理者権限では起動しないでください。

## まず選ぶ手順

- GitやPowerShellに慣れていない場合: [非エンジニア向けセットアップ](#非エンジニア向けセットアップ)
- Git/Python環境を自分で管理できる場合: [エンジニア向けセットアップ](#エンジニア向けセットアップ)

## 非エンジニア向けセットアップ

### 1. 用語

- **workspace**: ChatGPTに操作を許可するプロジェクトフォルダーです。PC全体や`C:\Users`を指定しないでください。
- **仮想環境（venv）**: このソフト専用のPython部品置き場です。他のアプリへ影響しにくくします。
- **MCP**: ChatGPTが外部ツールを呼び出すための仕組みです。
- **Tunnel**: インターネットへサーバーを公開せず、ローカルMCPの標準入出力をChatGPTへ安全に中継するOpenAI側の接続機能です。
- **承認**: test/build、一般shell、削除、端末状態変更などを実行する前に、Windows側の利用者が最終判断する操作です。

### 2. 必要なもの

1. Windows 10または11。
2. Python 3.11以上。Pythonのインストーラーでは「Add Python to PATH」を有効にします。
3. OpenAI Secure MCP Tunnelを利用できるChatGPT環境。
4. Gitは任意です。Gitがない場合もZIP版でセットアップできます。

Flutter、Dart、ADBを使わない場合、それらをインストールする必要はありません。対応機能を`false`のままにしてください。

### 3. Gitを使わずに入手する

1. GitHubのリポジトリ画面で緑色の「Code」ボタンを選びます。
2. 「Download ZIP」を選びます。
3. ダウンロードしたZIPを右クリックし、「すべて展開」を選びます。
4. 展開先フォルダーを開きます。
5. フォルダー内の何もない場所を右クリックし、「ターミナルで開く」を選びます。Windows 10ではエクスプローラーのアドレス欄へ`powershell`と入力してEnterでも構いません。

### 4. Python環境を作る

開いたPowerShellへ、次を1行ずつ貼り付けます。

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
Copy-Item .\config.example.toml .\config.toml
notepad .\config.toml
```

`py`が見つからない場合、Pythonが正しくインストールされていません。Pythonを再インストールしてから、新しいPowerShellを開いてください。

### 5. 設定ファイルを編集する

メモ帳で最初の`workspace_root`を、ChatGPTに操作させたいプロジェクトへ変更します。`\`は2つ重ねます。

```toml
workspace_root = "C:\\Projects\\my-app"
```

最初は次のままが安全です。

```toml
git_enabled = true
flutter_enabled = false
dart_enabled = false
adb_enabled = false
powershell_enabled = false
http_enabled = false
```

Gitも入っていない場合は`git_enabled = false`へ変更します。保存してメモ帳を閉じます。`workspace_root`が未設定・存在しない・`data_dir`と重なる場合、サーバーは安全側に起動失敗します。

### 6. ローカル承認画面を起動する

1つ目のPowerShellで次を実行し、開いたままにします。

```powershell
.\run-approvals.ps1 -Config "$PWD\config.toml"
```

承認要求が来ると、コマンド、理由、risk、固定したファイル数/容量、hash、有効期限が表示されます。

- `y`: 内容を再検証し、その場で1回だけ実行
- `n`またはEnter: 拒否
- `s`: 今は判断せず次へ
- `q`: 承認画面を終了

ChatGPT側で`execute_approved`をもう一度実行する必要はありません。ChatGPTは`poll_approval`で結果を確認します。

### 7. Secure MCP Tunnelへ登録する

Tunnelの接続追加画面で、ローカルコマンドとして次を登録します。画面の名称はChatGPT/Tunnelのバージョンや契約で異なるため、利用中のOpenAI公式画面の案内を優先してください。

- Program / executable: `powershell.exe`
- Arguments:
  - `-NoProfile`
  - `-File`
  - `C:\path\to\windows-local-mcp-python\run-server.ps1`
  - `-Config`
  - `C:\path\to\windows-local-mcp-python\config.toml`
- Working directory: このリポジトリの展開先

`run-server.ps1`はambientな`python`ではなく、このリポジトリの`.venv\Scripts\python.exe`だけを使います。Tunnel ID、API key、認証情報は設定ファイルやリポジトリへ保存しないでください。

### 8. 動作確認

ChatGPTへ順に依頼します。

1. 「`session_info`でworkspaceと有効機能を表示して」
2. 「workspace直下を一覧表示して」
3. 「`mcp-test.txt`へ`hello`と書き、読み戻して」
4. Gitを有効にした場合は「現在のbranch、HEAD、status、diff、staged diff、最近のcommitを`git_info`で表示して」

表示されたworkspaceが意図したフォルダーと違う場合は、操作を続けずTunnelと承認画面を終了し、`config.toml`を直してください。

### 9. ZIP版を更新する

新しいZIPを別フォルダーへ展開し、古い`config.toml`の設定内容だけを新しい`config.example.toml`へ手作業で反映してください。古い`.venv`をコピーせず、手順4を再実行します。監査データは既定では`%LOCALAPPDATA%\WindowsLocalMCP`にあるため、リポジトリ更新とは分離されています。

## エンジニア向けセットアップ

```powershell
git clone <repository-url>
cd windows-local-mcp-python
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
Copy-Item config.example.toml config.toml
# config.toml: set an explicit workspace_root and enable only needed capabilities
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\ruff.exe check .
```

stdio起動:

```powershell
.\run-server.ps1 -Config "$PWD\config.toml"
```

承認UI:

```powershell
.\run-approvals.ps1 -Config "$PWD\config.toml"
```

Tunnelへは`powershell.exe -NoProfile -File <repo>\run-server.ps1 -Config <repo>\config.toml`をargv配列として登録します。shell文字列へ連結しないでください。

複数プロジェクトでは、親フォルダーを巨大workspaceにせず、`config.project-a.toml`、`config.project-b.toml`のようにprofileを分け、1 MCPプロセスにつき1 workspaceを割り当てます。

## 能力と境界

| 操作 | 既定 | 自動実行の条件 |
| --- | --- | --- |
| workspace read/write/list/image | 有効 | path broker、容量、秘密名、reparse/hardlink、競合検証を通る |
| Git status/diff/staged/branch/HEAD/log/changed files | 有効 | 読取専用の固定文法。`.git`直接アクセスは不可 |
| `flutter analyze` | 無効 | 有効化後、`--no-pub`、検証済みpath、固定snapshotとdependency closure |
| `dart analyze` / 制約付き`dart format` | 無効 | 有効化後、完全文法とsnapshot。formatは実workspace全体を直前固定 |
| Flutter/Dart test/build | 承認 | 安全Tierではない。承認済みcwd snapshotから1回実行 |
| ADB devices/固定read-only/screenshot | 無効 | Emulator検証、serial allowlist、固定操作文法 |
| ADB state change/general shell | 承認 | ローカル利用者の承認が必要 |
| PowerShell/general host command/network/delete | 承認 | 対応機能、全入力manifest、期限、一回性を検証 |
| Streamable HTTP | 無効 | loopbackのみ。multi-principal modeは未実装のため起動拒否 |

`execute`の安全文法に入らない形式は、推測で安全扱いせず`request_host_command`へ送るか拒否します。

## 承認snapshot

`request_host_command`は次を固定します。

- 実行ファイルのbytes/identity
- argv、cwd、reason、risk、network/workspace-write指定
- 実効Settingsとコマンドへ影響する環境のdigest
- MCPが変更可能な実行scopeの全regular file（追加・削除も検出）
- Dart/Flutterの`package_config.json`から解決したcwd外/path dependency
- Gitの場合はHEAD、status、working diff、staged diff

読取型code loaderは`cwd`と列挙済みdependencyを`data_dir`の不変領域へコピーし、検証後に別の使い捨てrun copyを作って実行します。元workspaceの兄弟フォルダーにある無関係な変更では失効しません。absolute/embedded workspace path、非file dependency、外部directory、symlink/junction/reparse、hardlink、上限超過など、closureを保証できない入力はfail-closedです。

元workspaceを変更する承認操作では`workspace_write=true`が必要です。この場合はworkspace全体を固定し、MCP writeとcommand executionをcross-process lockで直列化します。したがって承認後の無関係なworkspace変更も意図的に失効させます。

test/buildはread-only安全Tierではありません。元workspaceを変更しない場合でも、任意コードを実行するためローカル承認済みsnapshot実行です。

## ファイル保護

- `hidden_directories`: 一覧から除外するだけ
- `read_denied_directories`: AIの直接読取を禁止
- `write_denied_directories`: AIの直接書換えを禁止
- `blocked_file_names`: 名前単位で直接read/writeを禁止

既定では`.git`をread/write禁止、`.venv`、`node_modules`、`.dart_tool`、`build`、`__pycache__`を一覧非表示かつ直接write禁止にします。これらのソース参照が必要な場合、readは可能です。

NTFS ADS、Windows予約デバイス名、末尾dot/space、workspace外、symlink/junction/reparse、複数hardlinkを拒否します。writeはcanonical target単位のthread lockとdata_dir上のcross-process lockを取り、親/target identityをreplace直前に再検証します。

## ADB

ADBはworkspace filesystemと別の権限境界です。既定は完全無効です。

```toml
adb_enabled = true
adb_emulator_only = true
adb_allowed_serials = ["emulator-5554"]
```

自動許可は`devices`、target指定`get-state`、限定`getprop`、`wm size/density`、限定`dumpsys`、`exec-out screencap -p`だけです。実行直前に`adb emu avd name`でEmulatorであることも確認します。`input`、`am`、`pm`、install、push/pull、汎用shell等は承認経路です。screenshot jobの完了後は`get_adb_screenshot`で画像を取得できます。

## Transportとprincipal

既定かつ推奨は`stdio + OpenAI Secure MCP Tunnel`です。HTTPは明示的な`http_enabled=true`が必要で、`127.0.0.1`、`::1`、`localhost`以外を拒否します。

この版は認証済みmulti-principal HTTPを実装していません。`http_multi_principal_enabled=true`は起動時に拒否されます。そのため、principal ownershipなしに他利用者のjob/approval/auditへアクセスできる構成は作れません。将来multi-principal HTTPを実装する場合は、operation所有者を認証principalへ永続化し、poll/claim/execute/cancel/auditの全照会にownership条件を必須化する必要があります。

## data_dir、ACL、容量、保持

`data_dir`はworkspaceと別の実効pathでなければなりません。通常のcontainmentと設定時のlexical containmentを両方検査するため、workspace内junctionを介して外へ向けたdata_dirも拒否します。data_dir自体のreparseも拒否します。

Windowsでは`protect_data_dir_acl=true`が既定で、継承ACLを外し、現在のsecurity principalとSYSTEMへFull Controlを付与します。同一Windowsユーザー権限で動く任意プロセスからの改変まではACLで分離できません。MCPの通常ファイルツールからはdata_dirがworkspace外のため到達不能です。

write、既存read、diff、backup、stdout/stderr、image、directory、approval manifest、data_dir全体に上限があります。stdout/stderrはpipeを常時drainし、bounded head/tailだけを保存するため、全量をメモリやdiskへ載せません。既定保持は14日/2000 terminal operationsで、active jobとpending approvalのartifactは削除しません。

## 監査

SQLiteの`operations`と`events`へ、成功だけでなく拒否、path/command validation失敗、poll/stop、approval poll/claim、audit閲覧、stale job整理も記録します。contentやsecret-like fieldはbytes/hash/redactionに置き換え、巨大入力をそのまま保存しません。

監査場所の既定:

```text
%LOCALAPPDATA%\WindowsLocalMCP\
  audit.db
  outputs\
  diffs\
  backups\
  git-snapshots\
  approval-staging\
```

## 制約

- Windows AppContainer/VMによる完全なOS sandboxではありません。
- 同一Windowsユーザーの別プロセスがdata_dirやtoolchainを悪意を持って改変する脅威は完全には隔離できません。
- Flutter/Dart/ADBがない環境では、その実commandの成功は検証できません。機能を無効にすればインストールなしで起動できます。
- Secure MCP Tunnelのアカウント側availability、認証、UIはOpenAI側機能です。このリポジトリへsecretを保存しません。

実装の詳細は[仕様](SPEC.md)、実行済み検証は[検証記録](VERIFICATION.md)を参照してください。
