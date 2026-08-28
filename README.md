# Windows Local MCP

ChatGPT から、指定した 1 つの Windows 作業領域を安全に読み書きするためのローカル MCP サーバーです。ファイル編集、構造化ファイル処理、監査、承認付きコマンド、変更履歴、Undo／rollback を提供します。

通常起動は管理者権限で行わないでください。`workspace_root` はプロジェクト単位で指定し、ドライブ直下やユーザーフォルダー全体を指定しないでください。

## はじめに

Windows Local MCP は、ChatGPT などの MCP クライアントから、指定した一つの Windows 作業フォルダーを扱うためのローカルサーバーです。読み取り、編集、構造化ファイルの処理、Git や ADB の限定的な確認、承認が必要なコマンドの実行、監査、変更の取り消しを、操作の種類ごとに分けて提供します。

最初に覚えることは次の三つだけです。

1. MCP が操作できる場所は `workspace_root` で指定した一つの作業領域です。
2. 設定ファイル、監査記録、バックアップを保存する `data_dir` は、作業領域の外に置きます。
3. 普通のファイル操作はそのまま実行できますが、任意コマンドや通常の Windows 権限が必要な処理は、別の実行経路と明示的な承認を使います。

この README は、上から順に「概要」「知識がない方向けの準備」「開発者向け設定」「仕様と検証」の順に読めるようにしています。セキュリティ上の約束を変更する文書ではなく、現在の実装と正本仕様へ案内する入口です。

## かんたん導入

開発環境に詳しくない場合は、まず配布パッケージを展開したフォルダーで `start-localmcp.bat` をダブルクリックしてください。表示された画面で「初心者向け」または「環境設定済み」を選択すると、ウィザードが必要な確認を順番に案内します。

初心者向けの場合は、MCP から操作したい既存のプロジェクトフォルダーを選びます。ウィザードは Python／依存パッケージ、workspace、Git の実 runtime、設定ファイルの分離を確認します。環境設定済みの場合は、既存設定をコピーせず、そのファイルを次回の active config として選択します。

設定は次の場所に保存されます。

~~~text
%LOCALAPPDATA%\WindowsLocalMCP\config.toml
%LOCALAPPDATA%\WindowsLocalMCP\active-config.txt
~~~

設定完了後の通常起動は `run-localmcp.bat` だけで行えます。設定ファイルを明示する場合は、`run-localmcp.bat C:\path\to\config.toml` または `run-localmcp.bat -Config C:\path\to\config.toml` と指定できます。設定が見つからない場合、バッチは勝手に推測せず、`start-localmcp.bat` の実行を案内します。

通常のサーバーは管理者権限で起動しません。Approved Host の runtime や authority service の導入だけは、別の管理者手順で行います。ランチャーは既存の production runtime や service を勝手に置き換えません。

MCP クライアントの stdio 設定は、ランチャーのバッチではなく、後述の `run-server.ps1 -Config` を明示したコマンドと引数の組み合わせを使います。詳しい挙動は [docs/LOCAL_LAUNCHERS.md](docs/LOCAL_LAUNCHERS.md) を参照してください。

## できることと、実行経路の違い

| 目的 | 主な経路 | 承認 | 概要 |
| --- | --- | --- | --- |
| ファイルを読む、画像を見る、ファイルを編集する | WLMCP Broker | 通常不要 | 作業領域、容量、対象パスを WLMCP が管理します |
| DOCX、XLSX、CSV／TSV、ZIP、画像を扱う | 構造化処理 | 操作による | 入出力を検査し、必要に応じて artifact と transaction で反映します |
| テスト、ビルド、スクリプト、任意コードを動かす | Codex Windows Sandbox | ローカル承認が必要 | operation ごとの作業コピーと Windows の隔離境界を使います |
| Broker や Sandbox では実行できない eligible command | Approved Host | 別の一回限りの承認が必要 | 通常の Windows ユーザー権限で実行します。管理者権限で実行する経路ではありません |
| 設定した外部記憶から文脈を読む | Context Read | 設定による | 固定 URL から JSON を取得し、検索結果を外部の未信頼データとして扱います |
| 作業結果の文脈を外部記憶へ送る | Context Export | 設定による | 固定 URL へ、モデルが明示した内容だけを送ります |

Sandbox が使えないときに Approved Host へ自動的に切り替えることはありません。反対に、Approved Host を無効にしてセキュリティ上の問題を解消したことにすることもできません。Approved Host は、必要な承認と実行時検証を伴う中核の実行経路です。

## 利用前のチェックリスト

### 最小構成（ファイルの読み書きだけを使う場合）

- [ ] Windows 上でこのリポジトリを取得している
- [ ] Python 3.11 以上がインストールされている
- [ ] PowerShell を使える
- [ ] MCP から操作したいプロジェクトのフォルダーを一つ決めている
- [ ] `workspace_root` をそのプロジェクトのフォルダーに設定する
- [ ] `data_dir` を `workspace_root` の外に設定する
- [ ] 通常の起動を管理者権限で行わない
- [ ] 設定ファイルを Git にコミットしない

### 必要に応じて追加するもの

- [ ] Git を使う場合：実行ファイルの絶対パスと SHA-256 を設定し、Git 専用の実機検証を完了する
- [ ] Sandbox を使う場合：この PC で Codex Sandbox の実機検証を完了する
- [ ] ADB を使う場合：Android SDK の `adb.exe` の絶対パス、SHA-256、対象シリアルを設定する
- [ ] Approved Host を使う場合：immutable runtime と LocalSystem authority service を管理者手順でインストールする
- [ ] Context Read／Export を使う場合：対応する sidecar 設定と、送受信先の認証情報を用意する

`.env`、秘密鍵、認証情報ファイル、`.git`、`.venv`、`node_modules`、`build` などを作業領域に置く場合、その内容を MCP や Sandbox が返せるかどうかは経路ごとに異なります。秘密情報を扱う作業では、各経路の制約と残存リスクを確認してください。

## 初回セットアップ（手動・開発者向け）

ランチャーを使わずに環境を構成する場合の手順です。通常は、先に「かんたん導入」の `start-localmcp.bat` を使ってください。Git、ADB、Sandbox、Approved Host、Context Read／Export は、最小構成が動いてから追加します。

### 1. Python とリポジトリを確認する

PowerShell を開き、次を実行します。

~~~powershell
Set-Location C:\dev\windows-local-mcp-python
py -3.11 --version
~~~

`Python 3.11` 以上が表示されれば進めます。`py` が見つからない場合は、Python をインストールしてから再度実行してください。会社の PC などで Python のインストールが制限されている場合は、管理者または PC の管理担当者に確認してください。

### 2. 専用の仮想環境を作る

~~~powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
~~~

`.venv` はこのリポジトリ内の開発用環境です。運用用の Approved Host runtime と同じものではありません。

### 3. 自分用の設定ファイルを作る

サンプルをコピーして、`config.local.toml` を作ります。

~~~powershell
Copy-Item .\config.example.toml .\config.local.toml
~~~

テキストエディターで `config.local.toml` を開き、少なくとも次の二つを自分の環境に合わせて変更します。

~~~toml
workspace_root = "C:\\work\\your-project"
data_dir = "C:\\Users\\your-name\\AppData\\Local\\WindowsLocalMCP\\your-project"
protect_data_dir_acl = true
approved_host_enabled = false
~~~

`workspace_root` は MCP に操作させたいプロジェクトのフォルダーです。`data_dir` は監査記録やバックアップの保存先なので、作業領域の中ではなく別の場所にします。二つを同じ場所や、一方が他方の中になるように設定すると起動できません。

初回は `approved_host_enabled = false` で構いません。Approved Host を使う場合の正しい有効化方法は、後述の「Approved Host の設定」を読んでから行ってください。秘密情報を含む設定ファイルはリポジトリへコミットしないでください。

### 4. 設定を確認する

~~~powershell
$env:LOCAL_MCP_CONFIG = (Resolve-Path .\config.local.toml).Path
.\.venv\Scripts\python.exe -m windows_local_mcp.cli audit --limit 20
~~~

設定に問題がある場合は、作業領域を操作する前にエラーになります。特に `workspace_root` と `data_dir` の存在、パスの重なり、TOML の引用符、Windows パスの `\\` を確認してください。

### 5. 承認画面を必要なときだけ起動する

Sandbox や Approved Host などの承認が必要な処理を使う場合は、別の PowerShell ウィンドウで承認プロセスを起動します。

~~~powershell
Set-Location C:\dev\windows-local-mcp-python
.\run-approvals.ps1 -Config C:\path\to\config.local.toml
~~~

ファイルの読み書きだけなら、承認プロセスは通常必要ありません。承認画面に表示された理由、対象、実行経路を確認してから承認してください。分からない操作は承認せず、監査記録と operation の詳細を確認します。

### 6. MCP サーバーを起動する

別の PowerShell ウィンドウで次を実行します。

~~~powershell
Set-Location C:\dev\windows-local-mcp-python
.\run-server.ps1 -Config C:\path\to\config.local.toml
~~~

サーバーは MCP クライアントから接続されるまで、そのウィンドウで待機します。終了するときは、その PowerShell で `Ctrl+C` を押します。

### 7. MCP クライアントへ登録する

MCP クライアントには、Shell の一行文字列ではなく、コマンドと引数を分けて登録します。

~~~text
command: powershell.exe
args:
  -NoProfile
  -File
  C:\dev\windows-local-mcp-python\run-server.ps1
  -Config
  C:\path\to\config.local.toml
~~~

Secure MCP Tunnel などで JSON を直接入力する場合も、上記の `args` を配列として指定してください。`config.local.toml` のパスは、実際に作成した絶対パスへ置き換えます。

接続後は最初に `session_info` を呼び出し、`workspace_root`、`data_dir`、transport、利用可能な capability を確認します。画面に入力欄が見えているだけでは接続確認になりません。

### 8. 最初の操作を試す

最初は次の順で、影響の小さい操作から確認します。

1. `list_directory` で作業領域の直下を確認する。
2. `read_file` で小さなテキストファイルを読む。
3. 必要なら `write_file` で新しいテストファイルを作る。
4. `activity_timeline` または `audit_list` で記録を確認する。
5. 不要なテストファイルを通常の編集または rollback で戻す。

実ファイルの編集を始める前に、プロジェクトのバックアップ方針と Git の状態を確認してください。WLMCP の checkpoint は便利ですが、外部サービス、ネットワーク、別プロセス、ACL、デバイスの状態まで元に戻すものではありません。

## 実行構成

処理は次の 4 種類に分かれます。安全性を安価に閉じられる処理まで Sandbox に送らず、作用範囲を閉じられない処理だけを隔離します。

1. **WLMCP Broker**
   - 対象パス、入出力、容量、副作用を WLMCP が限定できる処理です。
   - ファイル read/write、差分、固定 ADB 読み取り、固定 Git metadata 読み取り、バイナリ転送、checkpoint、transaction、Undo／rollback を直接扱います。
   - Automatic Git Broker は pinned Git runtime、bounded／sanitized disposable repository projection、live-verified Codex Windows Sandbox containment、Git-specific live marker がすべて current の場合だけ `git_info`／`execute_readonly` の固定 Git grammar を実行します。Automatic `diff`／`show` は metadata-only で、patch／binary patch／`--check`／暗黙 patch output は対象外です。marker が missing／stale／failed の PC では Git child を起動せず fail closed します。
2. **構造化処理**
   - DOCX、XLSX、CSV／TSV、ZIP、一般画像を宣言的な操作として処理します。
   - 現在は WLMCP 管理処理を使用し、処理結果を artifact として検証してから Broker の transaction で反映します。将来の ChatGPT container 処理も同じバイナリ転送境界へ接続できます。
3. **Codex Sandbox**
   - 任意コード、project script／plugin、test／build、一般コマンドなど、WLMCP だけで副作用を閉じにくい処理を実行します。
   - 承認済み workspace snapshot から作った operation 固有 run copy を project filesystem として使用し、original `workspace_root` は parent／child／grandchild から read／write deny を要求します。この snapshot-only 構成は defense-in-depth として維持します。
   - current v1 の一般 Codex Sandbox route では workspace 内 protected information の direct read denial を完全保証できません。`protected_information_read` と LAN access は受容済み残存 risk として実測結果を保持・表示し、それだけでは一般 route を unavailable にしません。この residual-risk allowance は Automatic Git には適用しません。
   - 利用にはローカル承認と、この PC での Sandbox 実機検証が必要です。その他の必須境界が失敗した場合は利用できず、Host へ自動移行しません。
4. **Approved Host**
   - Codex Sandbox／Broker では満たせない eligible command を、separate one-shot local approval 後に通常の Windows user authority で実行する route です。
   - monitor／postflight worker は LocalSystem service が所有し、実 command は verified non-elevated requester token で起動します。same-desktop UAC elevation を security boundary としません。
   - `%ProgramData%\WindowsLocalMCP\ApprovedHostAuthority` の LocalSystem-owned durable latch は normal verified completion まで残り、worker kill／service restart／postflight failure では explicit administrator recovery を要求します。
   - project-controlled code-loader と workspace executable は引き続き Host で拒否し、Sandbox failure から Host へ automatic fallback しません。
   - WLMCP-R2-001 は implementation と required Windows normal／abnormal／recovery live verification を完了し、2026-08-28 の実機 evidence に基づき `fixed / live verified` とします。per-machine execution availability は引き続き immutable runtime と authenticated LocalSystem authority service の current preflight を必要とします。

旧 Safe Tier／AppContainer は現行の方針には存在しません。旧設定が残っている場合は、弱い互換動作へ移らず起動を拒否します。

## 開発者向け設定（詳細）

Python 3.11 以上を使用します。repository checkout と `.venv` は通常 user が編集できる開発環境であり、Broker／Codex Sandbox の開発・テスト用です。Approved Host production execution は immutable Program Files runtime と LocalSystem authority service を必要とするため、editable checkout では `approved_host_enabled = false` を推奨します。

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
approved_host_enabled = false
```

Broker が自動実行する ADB helper は `PATH` 上の同名ファイルを使用しません。workspace、`data_dir`、Sandbox scratch の外にある絶対 path と SHA-256 を対で設定してください。未設定時は capability が有効でも実行を拒否します。

Automatic Git Broker も `PATH` discovery を trust source にせず、workspace／`data_dir`／Sandbox scratch の外にある実 Git runtime executable の絶対 path と SHA-256 を必要とします。Git for Windows の `cmd\git.exe` や install-root の `bin\git.exe` は wrapper／redirector になり得るため、Automatic Git の trust anchor には使用しません。典型的な 64-bit Git for Windows では `mingw64\bin\git.exe` を直接 pin します。path／hash を設定しただけでは execution availability にはなりません。まず generic Codex Sandbox live verification を成立させ、そのうえで同じ containment 内の pinned runtime を使う `verify-git-broker` を明示実行して Git-specific marker schema v1 を作成する必要があります。

```powershell
$gitPath = 'C:\Program Files\Git\mingw64\bin\git.exe'
$gitHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $gitPath).Hash.ToLowerInvariant()
```

```toml
git_executable_path = "C:\\Program Files\\Git\\mingw64\\bin\\git.exe"
git_executable_sha256 = "ここを64桁のSHA-256へ置換"
```

```powershell
$env:LOCAL_MCP_CONFIG = 'C:\path\to\config.local.toml'
.\.venv\Scripts\python.exe -m windows_local_mcp.cli verify-codex-sandbox
.\.venv\Scripts\python.exe -m windows_local_mcp.cli verify-git-broker
```

`verify-git-broker` は通常 operation から自動実行されません。Git runtime identity、Sandbox backend、generic live evidence、workspace、scratch quota、Automatic Git containment-policy generation v6、command-policy generation v5、trusted process-cwd policy、exact projection ownership-trust policy、sanitized `core.autocrlf` semantics、required-builtin policy のいずれかが変わった場合は marker が stale になり、再検証するまで Automatic Git は `available=false` です。verifier は `status`／`diff`／`log`／`show`／`rev-parse`／`ls-files` が exact pinned runtime の builtin command であることも確認します。Git-specific route は general Sandbox で residual risk として許容する `protected_information_read`／LAN を継承せず、全 Sandbox security property が `verified` の場合だけ route eligible です。

開発 server は次のとおり起動します。設定が不正な場合は、workspace を操作する前に起動を拒否します。

```powershell
.\run-server.ps1 -Config .\config.local.toml
```

Secure MCP Tunnel には、Shell 文字列ではなく次の argv を登録します。

```text
powershell.exe -NoProfile -File C:\dev\windows-local-mcp-python\run-server.ps1 -Config C:\path\to\config.local.toml
```

複数 workspace は別々の `config`、`data_dir`、Sandbox scratch を使用してください。namespace marker が workspace、data_dir、実体識別子の混在を拒否します。Windows では handle から得た volume GUID 付きの物理 path も比較するため、junction／reparse point だけでなく SUBST 等の別名で同じ領域を指定した場合も起動を拒否します。

## Approved Host の現行仕様

Approved Host の production route は immutable runtime と LocalSystem authority service の両方を前提にします。`approved_host_enabled=true` や `request_host_command` surface、pending／approved row だけでは execution availability を意味しません。

通常の導入順序は `install-approved-host-runtime.ps1` → non-elevated `verify-approved-host-runtime.ps1` → elevated `install-approved-host-authority.ps1` → non-elevated `verify-approved-host-authority.ps1` です。WLMCP-R2-001 の security boundary を変更する場合は `verify-approved-host-authority-abnormal.ps1` の Arm／KillAndRestart／Check、coordinated recovery、post-recovery normal path まで再検証します。

`session_info()` の `available=true` は immutable runtime と authenticated authority service の current preflight が通ったことだけを意味します。Hosted CI や service health を full capability の `live_verified`／`windows_live_verified` へ自動昇格しません。WLMCP-R2-001 は 2026-08-28 に normal → SYSTEM worker loss／WMI Job 外 helper survival → service restart／`recovery_required` → stale execution rejection → coordinated recovery → post-recovery normal の実機 lifecycle を完了し、`fixed / live verified` です。

詳細は `docs/APPROVED_HOST_RUNTIME.md` と `docs/APPROVED_HOST_PRODUCT_INVARIANT.md` を参照してください。

## 主な機能

| 用途 | 経路 | 主な tool |
| --- | --- | --- |
| テキスト／バイナリの読み書き | Broker | `read_file`, `write_file`, artifact transfer |
| 固定 Git metadata 読み取り | Automatic Git Broker | `git_info`, `execute_readonly` |
| content-bearing／一般／変更系 Git、project-controlled 処理 | Codex Sandbox（適用可能な場合） | `request_sandbox_command` |
| Emulator の限定読み取り | Broker | `adb_read`, `get_adb_screenshot` |
| DOCX／XLSX／CSV／TSV／ZIP／画像 | 構造化処理 | `structured_file_inspect`, `structured_file_apply` 等 |
| Python、PowerShell、Node、test、build、project script | Codex Sandbox | `request_sandbox_command` |
| Sandbox 外の Windows 権限／network が必要な eligible 処理 | Approved Host | `request_host_command` → local approval → LocalSystem monitor／ordinary user child |
| 状態確認、停止、監査 | Broker | `poll_job`, `stop_job`, `activity_get`, `audit_get` |
| 変更取消 | Broker | selective Undo、point-in-time rollback |

`execute_workspace_write` は互換用の公開面を残していますが、Dart／Flutter 等の project-controlled 処理は拒否され、`request_sandbox_command` を案内します。

`git_info` と `execute_readonly` の固定 Git grammar は、current Git-specific marker が成立した Windows PC では Automatic Git Broker として実行できます。Git child は live workspace を直接読まず、operation ごとの bounded／sanitized projection を処理します。Git process 自体の Windows process cwd は pinned runtime directory に固定し、repository selection は Broker が argv へ挿入する `git -C <sanitized projection cwd>` で行うため、project-controlled projection を current-directory DLL search surface にしません。repository ownership trust は command-scope `-c safe.directory=<exact operation projection>` に限定し、wildcard、source workspace、scratch parent、global persistent `safe.directory` は Automatic Git では使用しません。`.gitattributes`、hooks、object alternates、external／extended repository metadata、nested `.git`、reparse／hardlink／ADS 等は除外または拒否し、source `.git/config` は raw bytes を scratch へ保存せず Broker memory 上で解析して inert `core` settings だけを書き出します。config parsing は 1 MiB で fail closed します。

raw system/global Git config は sandbox child に再公開しません。working-tree semantics に必要な `core.autocrlf` は trusted Broker 側で `true`／`false`／`input` の scalar としてだけ解決し、sanitized `.git/config` に投影します。repository-local の直接 scalar override は通常の precedence を維持します。一方、include/includeIf、workspace／`data_dir`／scratch と重なる config path、invalid value、未知で安全に解決できない Git runtime/config semantics は fail closed します。

Git object database には、現在の working-tree policy では protected な内容を含む historical blob が残り得ます。また攻撃者はその blob を一見安全な tree／commit／index path に再結合できます。そのため current workspace path の検証や `^{commit}` binding だけを content provenance とみなしません。Automatic `diff`／`show` は `--stat`、`--name-only`、`--name-status`、`--quiet`、`--no-patch` 等の metadata-only output に限定し、`--patch`／`-p`／`--binary`／`--check`／pathspec 付き暗黙 patch は `request_sandbox_command` の対象です。`git_info` snapshot も status、diff stat/name-status、log metadata 等に限定します。marker がない／stale な PC では process creation 前に拒否し、Approved Host へ fallback しません。

Automatic Git repository projection の byte limit は configured `max_sandbox_scratch_bytes` の 1/2 以下です。残りを operation 固有 runtime／transient output 用に残し、operator quota を超える hard-coded repository-size floor は使用しません。runner は `maintenance.auto=false` と `gc.auto=0` も固定し、automatic maintenance／GC を通常の Automatic Git command semantics から除外します。

ADB helper は設定済み path、SHA-256、file identity を正規化時と worker 実行直前に再検証し、Windows では child の終了まで実行ファイルを差し替え不能な共有モードで保持します。ADB の自動処理は allowlist 済み emulator serial を明示する固定読み取りだけで、`adb devices` による未許可 device の列挙は行いません。

バイナリのダウンロード転送は、開始時に元ファイルの前後同一性と SHA-256 を確認した不変スナップショットを制御領域へ固定し、各チャンクでは必要範囲だけを読み取ります。アップロード転送は開始時に申告済み全容量を予約するため、チャンクごとのデータ領域全走査を行いません。別々の転送は並行できますが、同一転送内のオフセット順序、fsync、完了時の全体 SHA-256、元ファイルと出力先の同時変更検知は維持します。監査は転送開始を親操作、各チャンクを SHA-256 付きの永続イベントとして記録し、チャンク数に比例するタイムライン行と同期書き込みを抑えます。

## 構造化ファイル

- **DOCX**: paragraph／run、検索置換、表、header/footer、style、section、page 設定、metadata。通常文書は文書ライブラリで処理します。追跡変更、コメント、macro、埋め込み object、データ連動 Custom XML などがある文書でも、電子署名がなく、操作が `replace_text` または `metadata_set` に限定される場合は、対象 XML 部分だけを書き換えて未対応部分を保持します。それ以外の操作は拒否します。
- **XLSX**: 値／数式、範囲、行列、sheet、copy/fill、書式、merge、freeze pane、filter、Table、入力規則、条件付き書式、基本 chart／page setup。macro、pivot、外部接続、未対応拡張等がある workbook でも、電子署名がなく、操作が `cell_set`、`range_set`、`range_clear` に限定される場合は、対象 worksheet XML だけを書き換えて未対応部分を保持します。それ以外の操作は拒否します。
- **CSV／TSV**: 範囲、cell／row／column、append／insert／delete。encoding、BOM、delimiter、quote 設定、newline、final newline を識別して保持し、判定が曖昧なら拒否します。ただし編集後は CSV writer が全体を書き直すため、未変更 cell の意味は保持しても元の quoting 表記や byte identity は保証しません。この範囲は inspect／apply 結果の `preservation_capabilities` に表示します。
- **ZIP**: listing、read、create/update、複数展開。traversal、絶対 path、ADS、予約名、大小文字衝突、件数、展開後容量を検査し、複数 file は transaction で一括反映します。
- **画像**: inspect、resize、thumbnail、crop、rotate、flip、形式変換、quality、metadata 除去。形式変換では `output_path` を別指定し、入力には `expected_sha256`、既存出力には `expected_output_sha256` を使います。pixel／decoded memory を制限し、未対応の multi-frame は破壊的変換せず拒否します。

変換中は workspace-wide lock を保持しません。commit 直前に source の raw bytes identity を再確認し、別処理による変更があれば conflict として拒否します。Office macro を含む bytes の転送・保存と、macro の実行は別の能力です。

## 承認と実行時 binding

`request_sandbox_command` と `request_host_command` は要求を作るだけで、その呼び出し時にはコマンドを実行しません。`request_sandbox_command` はローカル承認 UI で承認された要求を 1 回だけ claim して Sandbox 実行へ進みます。`request_host_command` も separately human-approved one-shot request として current generation、immutable manifest、TTL、executable identity を検証し、authenticated LocalSystem authority service の SYSTEM worker から verified non-elevated requester token の child を起動します。Sandbox failure からの implicit fallback や model-facing `execute_approved` surface はありません。

承認には、argv、cwd、実行ファイルと入力の hash、checkpoint、workspace／data_dir の実体 identity、設定、WLMCP build と policy generation、Sandbox backend を結合します。更新や設定変更後の古い承認、二重 claim、replay は拒否します。

承認後の Sandbox 実行ファイルも実行直前に path、SHA-256、device／inode、size、mtime を照合し、Windows では実行終了まで差し替えを拒否する handle を保持します。

Approved Host は runtime immutability、LocalSystem-owned Job Object／monitor、requester-user WMI／CIM process census、control-plane preflight／postflight、SYSTEM-owned durable `active.json` latch と user-owned bound postflight latch を組み合わせます。normal verified completion の場合だけ latch を解除し、SYSTEM worker loss／service restart／postflight uncertainty は `recovery_required` のまま fail closed にし、elevated Administrator の reviewed coordinated recovery を要求します。

## Codex Sandbox

Live verification は各 property を `verified`、`failed`、`unverified` の三値で保存します。`failed` は実際の probe が境界脱出を観測した場合だけ、`unverified` は起動失敗、タイムアウト、listener または probe 環境の準備失敗、出力を測定できない場合に使います。current v1 の一般 Codex Sandbox route では workspace 内 `protected_information_read` と LAN access を受容済み残存 risk として分離します。これらの failure／unverified は隠さず保持しますが、それだけでは一般 route を unavailable にしません。Automatic Git はこの例外を継承しません。一般 source-workspace read/write、workspace 外 user/protected read、control-plane、Internet、loopback、termination、resource bound、WMI／CIM brokered process creation denial 等の必須境界は引き続き fail closed です。Approved Host へ自動移行しません。

live marker は schema v5 です。launcher／helper の canonical path、content SHA-256、Windows stable file identity、size、実際の version、Authenticode の Valid status・leaf signer subject・leaf certificate thumbprint に加え、実際に import された WFP Guard module 群の canonical path／SHA-256／stable file identity／size、Guard version、policy generation、Sandbox account、Windows product／build／UBR／architecture、WFP read-back identity を結合します。mtime は補助的な drift signal であり、単独では security identity として扱いません。`isolation_context_digest` はさらに workspace の実体、保護名・拒否 directory、`sandbox_dependency_readable_paths`、Sandbox policy generation、process 数・process-tree memory 上限、scratch 上限、許可環境変数などを結合します。これらを変更した場合、marker は stale として拒否され、通常 operation は live verification や UAC probe を自動実行しません。明示的に `verify-codex-sandbox` を再実行してください。v1～v4 marker から v5 を推測・移行しません。

marker v5 の identity がすべて現在値と一致し、static non-persistent WFP fixed object が単に missing の場合だけ、trusted Guard が exact object を再構築できます。この場合も complete read-back、`wfp_guard_verified`、child 起動の順序を維持します。既存 object の security-relevant field 不一致、conflicting object、または marker identity 不一致は silent repair せず fail closed にします。

Sandbox account から `Win32_Process.Create` を含む WMI／CIM brokered process creation が拒否されることを live verification で確認し、`brokered_process_creation_denied=true` を必須 evidence とします。この check が欠損または false の marker は route eligible ではありません。これにより Job 外 process を使った termination／process／memory bound の迂回を current mandatory boundary として扱います。

`config.local.toml` で installed Codex CLI を指定できます。

```toml
approved_sandbox_enabled = true
approved_sandbox_codex_path = "C:\\path\\to\\codex.exe"
approved_sandbox_require_live_verification = true
sandbox_dependency_readable_paths = []
max_sandbox_processes = 64
max_sandbox_memory_bytes = 4294967296
```

WLMCP は `codex sandbox` 専用 entrypoint を argv で起動し、agent／model API は使用しません。launcher と helper の path、署名、hash、file identity を承認と実行時に検証します。

Sandbox 起動直前には、この PC のコンピューター名で完全修飾した `CodexSandboxOffline` の SID を Windows から解決し、返された参照ドメインがこの PC の物理 NetBIOS 名と一致すること、`SID_NAME_USE` が `SidTypeUser`（1）であることを確認します。単純名から信頼ドメインへ広がる解決や、ユーザー以外の SID は受け入れません。そのうえで ALE_AUTH_CONNECT_V4／V6 の loopback BLOCK を direct WFP で ensure して全項目を read-back します。Guard の sublayer は現在の App Isolation sublayer より高い weight を必要とし、object は static、non-dynamic、non-persistent です。正しい既存 object は再利用し、不一致や検証不能時は Sandbox を起動せず、Approved Host へ移行しません。通常権限側は、`runas` が返した process handle の PID の実体が固定の `.venv\Scripts\python.exe` であることを確認します。named pipe が報告する接続元 PID はその同一 launcher、またはその直接の子 process に限り、直接の子 process を受け入れる場合も実体が `sys.base_prefix\python.exe` の base Python executable と一致することを確認します。UAC で継承されない環境変数へ依存せず、起動した管理者 Guard 本人からの read-back 証拠だけを受理します。BLOCK は各 Sandbox の終了、timeout、launcher failure、Job Object 違反では削除せず、Windows 再起動または BFE 停止後の次回起動前に再作成します。WFP 変更だけを固定操作の昇格 Guard に隔離し、WLMCP server／worker 自体は通常権限のままです。

明示的な管理者メンテナンスだけは次の固定コマンドを使用できます。通常の worker 経路から cleanup は呼び出されません。

```powershell
.\.venv\Scripts\python.exe -m windows_local_mcp.wfp_guard_runtime --maintenance-verify
.\.venv\Scripts\python.exe -m windows_local_mcp.wfp_guard_runtime --maintenance-ensure
.\.venv\Scripts\python.exe -m windows_local_mcp.wfp_guard_runtime --maintenance-cleanup
```

起動時には legacy profile 名だけに依存せず、source workspace の read deny、operation 固有 scratch の write、明示した依存 root の read、保護名の deny、network restricted を含む `sandbox-state` を Codex CLI へ渡します。さらに launcher を一時停止状態で起動し、Windows Job Object へ割り当ててから再開します。Job Object は launcher を含む子孫全体の process 数、commit memory、終了時 kill を OS で強制します。上限違反は job 全体を停止し、WLMCP は子孫が 0 になったことと終了状態を回収できたことを確認します。

Sandbox staging は `.env` 等の保護対象と、`.venv`、`node_modules`、`build`、`__pycache__` 等の生成・依存 tree を一律 copy しません。必要な外部依存は `sandbox_dependency_readable_paths` 等の明示的で検証可能な入力として扱い、暗黙に source workspace を参照させません。source-workspace deny と protected-information direct-read probe は defense-in-depth として維持しますが、staging exclusion や deny policy の設定だけを workspace 内 secret の完全遮断保証とは扱いません。direct-read probe が `failed`／`unverified` の場合も、その結果を一般 Codex Sandbox route の受容済み残存 risk として保持・表示します。

設定されていること、機能が有効なこと、backend を解決できること、この PC で security boundary まで実機検証済みであることは別々に表示されます。実機検証は次を確認します。

```powershell
$env:LOCAL_MCP_CONFIG = 'C:\path\to\config.local.toml'
.\.venv\Scripts\python.exe -m windows_local_mcp.cli verify-codex-sandbox
```

検証結果は `filesystem_read`、`filesystem_write`、`protected_information_read`、`internet`、`lan`、`loopback`、`descendant_containment`、`termination`、`resource_bound` の property と、必須 check `brokered_process_creation_denied` を保存します。schema v5 以外、必須 identity／check field が欠けた marker、現在の実体に結合しない marker は受理しません。`available` は依存関係と起動前提、`windows_live_verified` は OS 境界の実測、`execution_route_available` は必須 route property を満たして実行可能かを別々に示します。`approved_sandbox_require_live_verification=false` で実行条件を回避することはできません。

検証器は親・child・grandchild の filesystem／network 境界に加え、process 数上限と process-tree memory 上限の超過、違反時の全子孫停止、終了状態回収、brokered process creation denial まで実測します。独立 probe が例外になった場合、その probe を `unverified` として残し、安全に続行できる残りの probe を継続します。一般 source workspace read/write、workspace 外 read、control-plane、Internet、loopback、WMI/CIM process creation denial 等の mandatory check は fail closed します。一方、workspace 内 `protected_information_read` と対応する child／grandchild protected-information denial、LAN access は一般 Codex Sandbox route の受容済み残存 risk として `failed`／`unverified` を保持・表示したまま route 判定から分離します。Automatic Git は全 property の `verified` を要求します。その他の必須境界が成立する場合に限り一般 Sandbox 経路を利用でき、利用できない場合も Approved Host へ自動移行しません。

## ファイルと制御領域の保護

- workspace path は canonical path、reparse point、hardlink、予約名、ADS、親／target identity を検査します。
- optimistic concurrency には表示用文字列ではなく raw file bytes の SHA-256 を使います。CRLF も raw identity に含まれます。
- 書き込みは checkpoint、durable journal、atomic replacement、post-write 検証を通します。第三者変更を復旧処理が上書きしません。
- `data_dir`、Sandbox scratch、workspace は分離し、起動時に lock／atomic replacement／filesystem identity と Windows の物理 path の前提を確認します。
- `.env`、credential 等の保護対象は通常の Broker read、automatic helper／snapshot から返しません。Automatic Git Broker は live workspace を Git child に渡さず、sanitized projection から protected worktree file／behavior metadata を除外します。Git object database の historical blob は path validation だけで safe content とみなさず、Automatic Git の content-bearing diff/show を禁止します。audit、approval、Activity、argv、stdout／stderr preview は secret を伏せ字にします。一般 Codex Sandbox から workspace 内 protected information を direct read できる可能性は別途受容済み残存 risk として明示します。
- 同時 job、pending approval、出力、artifact、data_dir、Sandbox scratch、structured element／pixel／archive 展開量に上限があります。

## Activity、Undo、rollback

Live Activity と Timeline は Read／Edited／Running／Finished、実行境界、network policy、before／after、conflict、failure／recovery、bounded stdout／stderr preview、rollback 可否を記録します。詳細は `activity_get`／`audit_get` で確認します。

checkpoint が戻せるのは、manifest に含まれる通常の workspace file bytes です。`.git`、ACL、device、network、外部サービス、別 process の副作用は戻せません。selective Undo は独立した text 変更を保持できますが、binary／曖昧な競合では停止します。

`write_file`、1 file の構造化編集、artifact commit、複数の既知 entry の ZIP 展開は、manifest に明示した対象 path だけを checkpoint／競合検査します。派生物では入力元と全出力先の path lock を同時に保持し、rollback 表示にも反映範囲を含めます。任意コード等で出力先が事前に閉じない処理は従来どおり full workspace checkpoint を使用します。

## Context Read と Context Export（任意の連携）

Context Read と Context Export は、外部の記憶サービスや Decision Deck などと作業文脈を連携するための任意機能です。最小構成では無効のままで問題ありません。メイン設定とは別の sidecar 設定を使うため、利用するときは送受信先と認証情報を明示してください。

### Context Read

Context Read は、sidecar に固定した URL から JSON を取得し、WLMCP のローカル検索で必要な文脈を返します。モデルが URL、クエリ、ヘッダーを自由に指定する機能ではありません。

設定ファイルの選択順は次のとおりです。

1. 環境変数 `LOCAL_MCP_CONTEXT_READ_CONFIG` で指定したファイル
2. 現在のメイン設定ファイルと同じフォルダーにある `context-read.toml`
3. それ以外は無効

~~~powershell
Copy-Item .\context-read.example.toml .\context-read.toml
$env:LOCAL_MCP_CONTEXT_READ_CONFIG = (Resolve-Path .\context-read.toml).Path
~~~

読み取りは固定の GET、直接接続、リダイレクトなし、プロキシ・Cookie・暗黙の認証情報なしで行います。応答は厳格な JSON 配列として検証し、応答全体は 2 MiB、1 ノードは 512 KiB、ノード数は 5000 件までです。通信のタイムアウトはサンプルで 10 秒、許容される上限は 60 秒です。ループバック以外への平文 HTTP は既定で許可しません。

取得した結果は `external_untrusted` として扱います。結果の文章に命令が含まれていても、README やシステムの指示を上書きするものとして扱いません。全文を読みたい場合は、返された安定 ID を使って `context_read` を呼び出します。

### Context Export

Context Export は、モデルが明示した文脈を、sidecar に固定した URL へ送ります。設定ファイルの選択順は Context Read と同じで、環境変数は `LOCAL_MCP_CONTEXT_EXPORT_CONFIG`、標準ファイル名は `context-export.toml` です。

~~~powershell
Copy-Item .\context-export.example.toml .\context-export.toml
$env:LOCAL_MCP_CONTEXT_EXPORT_CONFIG = (Resolve-Path .\context-export.toml).Path
~~~

送信先 URL や認証情報をモデルから上書きすることはできません。送信内容は、文脈の本文、種類、範囲、題名、形式、タグ、メタデータ、観測時刻、冪等性キーなどの入力項目から作られます。完全な正規化 JSON 本文は 256 KiB までで、成功時も相手側の応答本文を読み取って返しません。監査記録には本文、トークン、パスを保存しません。

sidecar は起動時と各 export 前に実体とハッシュを確認します。起動後にファイルを置き換えたり内容を変更したりした場合は、再起動するまで export を fail closed にします。Bearer token は設定ファイルへ直接書く場合でも Git にコミットせず、共有端末ではファイルのアクセス権も確認してください。

## 設定項目の詳細

設定の出発点は [config.example.toml](config.example.toml) です。TOML は未知の項目を受け付けないため、名前を自己流に変えないでください。`workspace_root`、`data_dir`、各 helper のパスとハッシュは、実際の環境に合わせて変更します。

### 作業領域と保存先

| 項目 | 役割 | 注意点 |
| --- | --- | --- |
| `workspace_root` | MCP が操作する一つの作業領域 | 実在するプロジェクトのフォルダーを指定します。ドライブ全体やユーザーフォルダーを指定しません |
| `data_dir` | 監査、checkpoint、バックアップ、operation 状態の保存先 | 空文字の場合は `%LOCALAPPDATA%\WindowsLocalMCP` が使われます。必ず workspace の外に置きます |
| `sandbox_scratch_dir` | Sandbox の operation 固有 scratch | 省略時は data directory の隣に自動作成されます |
| `protect_data_dir_acl` | data directory の ACL 保護 | 通常は `true` のままにします |

workspace、data directory、scratch directory は、文字列上の重なりだけでなく、実体、volume、reparse point も検査されます。junction や別名パスで検査をすり抜ける構成は利用できません。

### 機能の有効化

| 項目 | 既定の例 | 有効にすると |
| --- | ---: | --- |
| `filesystem_enabled` | `true` | Broker のファイル操作を有効にします |
| `git_enabled` | `true` | Automatic Git の前提機能を有効にします。実行可能になるには別途 helper と live marker が必要です |
| `flutter_enabled` | `false` | Flutter 関連コマンドを Sandbox の対象にします |
| `dart_enabled` | `false` | Dart 関連コマンドを Sandbox の対象にします |
| `adb_enabled` | `false` | 固定 grammar の ADB 読み取りを有効にします |
| `powershell_enabled` | `false` | 許可された PowerShell 実行を有効にします |

機能を `true` にするだけでは実行可能になりません。helper の実体確認、承認、Sandbox の live verification、経路ごとの capability 判定がすべて別に行われます。

### helper、Sandbox、ADB

| 項目 | 内容 |
| --- | --- |
| `git_executable_path` と `git_executable_sha256` | Automatic Git が使う実行ファイルの絶対パスと 64 桁の SHA-256。片方だけの設定、PATH 上の探索、workspace 内の実体は受け付けません |
| `adb_executable_path` と `adb_executable_sha256` | Automatic ADB が使う `adb.exe` の絶対パスと SHA-256。片方だけの設定や PATH 上の同名ファイルは受け付けません |
| `approved_sandbox_enabled` | Codex Windows Sandbox 経路の有効化 |
| `approved_sandbox_backend` | 現行の標準値は `codex_cli` |
| `approved_sandbox_codex_path` | Codex 実行ファイルを明示する場合の絶対パス |
| `approved_sandbox_windows_mode` | 現行のサンプル値は `elevated`。Sandbox の起動準備を示す値で、任意コマンドを管理者権限で実行する意味ではありません |
| `approved_sandbox_permission_profile` | サンプル値は `:workspace`。実際の権限は `sandbox-state` と OS 検証で判定します |
| `approved_sandbox_require_live_verification` | `true` のままにします。実機検証を設定で省略することはできません |
| `child_environment_allowlist` | 子プロセスへ渡す環境変数名の明示的な許可リスト |
| `sandbox_dependency_readable_paths` | Sandbox から読む必要がある、workspace 外の依存先の明示的なパス |
| `adb_emulator_only` | `true` の場合、ADB の対象をエミュレーターに限定します |
| `adb_allowed_serials` | ADB で使用できるシリアルの許可リスト。空の場合でも任意端末の列挙を許可する意味ではありません |

Git は `git.exe` の場所とハッシュを設定しただけでは使えません。まず `verify-codex-sandbox`、続けて `verify-git-broker` を実行し、現在の PC、runtime、Sandbox policy、Git runtime に結び付いた marker を作成します。

ADB は任意コマンドを実行する機能ではありません。`adb_read` は `-s SERIAL` を必須とし、許可された固定形式の状態確認、画面サイズ、密度、電池、表示、window／activity、許可された `getprop`、screenshot だけを扱います。`adb devices` による端末一覧の取得や、シリアルを省略した操作は自動経路では許可しません。

### 承認と Approved Host

| 項目 | 内容 |
| --- | --- |
| `approved_host_enabled` | Approved Host を利用する設定。設定モデルの既定値は `true` ですが、editable checkout の開発環境では `false` を推奨します |
| `approval_request_ttl_seconds` | 承認要求の有効期間。サンプルは 1800 秒 |
| `approval_execution_ttl_seconds` | 承認後の実行有効期間。サンプルは 60 秒 |
| `default_approver` | 既定の承認者識別子。サンプルは `local-user` |
| `approval_manifest_max_files`／`approval_manifest_max_bytes` | 承認対象 manifest のファイル数と合計サイズの上限 |

Approved Host は、Broker や Sandbox で実行できない eligible command のための中核経路です。immutable な Program Files runtime、LocalSystem authority service、current approval、manifest、generation、postflight を組み合わせ、実コマンドは検証済みの通常ユーザー token で起動します。サービスの停止、worker の消失、postflight の不確実性がある場合は recovery required となり、ユーザー権限から勝手に修復しません。

Approved Host の導入・復旧は、通常の editable checkout を起動する手順とは別です。詳細は [docs/APPROVED_HOST_PRODUCT_INVARIANT.md](docs/APPROVED_HOST_PRODUCT_INVARIANT.md) とリポジトリ内の install／verify／recover script を確認してください。Sandbox の失敗を理由に Host へ自動 fallback することはありません。

### 容量、時間、出力の上限

次は `config.example.toml` の基準値です。値を大きくする場合は、メモリ、ディスク、監査保管量、Sandbox の資源上限を合わせて見直してください。

| 項目 | 基準値 |
| --- | ---: |
| `max_text_file_bytes`／`max_write_bytes` | 2 MiB／2 MiB |
| `max_diff_bytes`／`max_backup_bytes` | 4 MiB／16 MiB |
| `max_image_bytes`／`max_structured_file_bytes` | 10 MiB／64 MiB |
| `max_transfer_chunk_bytes` | 512 KiB |
| `max_zip_entries`／`max_zip_expanded_bytes` | 10,000 件／256 MiB |
| `max_structured_elements`／`max_image_pixels` | 250,000 要素／40,000,000 画素 |
| `max_output_bytes_per_stream` | 16 MiB（stdout／stderr 各ストリーム） |
| `max_data_dir_bytes` | 512 MiB |
| `max_directory_entries` | 3,000 件 |
| `max_sandbox_processes`／`max_sandbox_memory_bytes` | 64 プロセス／4 GiB |
| `output_preview_characters` | 12,000 文字 |
| `max_command_arguments`／`max_command_argument_characters` | 64 個／1,024 文字 |
| `max_reason_characters`／`max_audit_record_bytes` | 4,000 文字／128 KiB |
| `retention_days`／`retention_max_operations` | 14 日／2,000 operation |
| `approval_manifest_max_files`／`approval_manifest_max_bytes` | 10,000 ファイル／256 MiB |
| `default_foreground_timeout_seconds`／`default_max_runtime_seconds` | 30 秒／1,800 秒 |

`max_concurrent_jobs`、`max_pending_approvals`、`max_open_transfers`、`max_image_decoded_bytes`、`max_sandbox_scratch_bytes` などの設定モデル項目も、実装上の同時実行、展開、転送、画像復号、scratch 使用量を制限します。これらを変更する場合は、サンプル設定にないから不要なのではなく、現在の `Settings` 定義と `SPEC.md` を確認してください。

### 保護対象と HTTP

既定の保護対象には `.env`、`.env.local`、`.env.production`、`id_rsa`、`id_ed25519`、`credentials.json`、`service-account.json` が含まれます。`.git` は読み取り・書き込みの制御領域として扱い、`.dart_tool`、`build`、`node_modules`、`.venv`、`__pycache__` などは隠し・生成ディレクトリとして扱います。必要な依存先は `sandbox_dependency_readable_paths` などで明示してください。

`http_enabled`、`http_host`、`http_port`、`http_multi_principal_enabled` は設定項目として存在しますが、現行の単一ユーザー版では principal ownership が未実装のため、HTTP を有効にすると起動時に拒否されます。現在の利用可能な transport はローカル stdio です。`127.0.0.1` を指定してもこの制約は変わりません。

## MCP ツールの使い分け

実際に公開されるツールは設定や capability によって変わります。最初に `session_info` を確認し、必要な操作に対応するツールだけを使ってください。

| 用途 | 主なツール |
| --- | --- |
| 接続先と capability の確認 | `session_info` |
| フォルダーとファイル | `list_directory`、`read_file`、`get_image`、`write_file` |
| 構造化ファイル | `structured_file_inspect`、`structured_file_apply` |
| ZIP | `zip_entry_read`、`zip_entry_extract`、`zip_extract_many` |
| 大きなファイルの送受信 | `artifact_download_begin`／`artifact_download_chunk`、`artifact_upload_begin`／`artifact_upload_chunk`／`artifact_upload_commit` |
| 固定範囲の読み取り・書き込み | `execute_readonly`、`execute_workspace_write` |
| Git と ADB | `git_info`、`adb_read`、`get_adb_screenshot` |
| 非同期 operation | `poll_job`、`stop_job` |
| Sandbox／Host の承認 | `request_sandbox_command`、`request_host_command`、`poll_approval` |
| 監査と活動履歴 | `audit_list`、`audit_get`、`activity_timeline`、`activity_get` |
| 変更の復旧 | `request_workspace_rollback`、`request_selective_undo` |
| 外部文脈 | `context_read_info`、`context_search`、`context_read`、`context_export_info`、`export_context` |

`write_file`、構造化編集、artifact commit、既知 entry の ZIP 展開などは、対象 manifest と競合検査を持つ transaction として扱われます。任意コードの出力先を事前に閉じられない場合は、より広い checkpoint と Sandbox 境界が必要になります。

## 現行仕様を確認するときの見方

設定されていること、機能を有効にしたこと、backend を解決できること、Windows の境界を実機で検証したこと、実際にその route が利用可能であることは、すべて別の状態です。`session_info` や監査記録では、少なくとも次を区別して確認します。

- `configured`：設定値が存在し、形式が正しい。
- `enabled`：その capability を設定で有効にしている。
- `available`：依存関係、承認、current marker、runtime などを含む実行前提がそろっている。
- `windows_live_verified`：この PC の Windows 境界を実測した証拠がある。
- `execution_route_available`：その route の必須 property を満たして、実行を受け付けられる。

テスト、marker の存在、WFP object の存在、Sandbox の起動ログだけでは、通常の Windows user としての UAC、LocalSystem service、Job／WMI process census、worker 消失後の recovery、実トラフィック遮断、Secure MCP Tunnel／ChatGPT の E2E を証明しません。証拠の種類を混ぜず、未検証のものは未検証として扱います。

## よくある問題

| 症状 | 確認すること |
| --- | --- |
| 起動直後に設定エラーになる | `workspace_root` と `data_dir` が存在するか、相互に重なっていないか、Windows パスの `\\` と TOML の引用符を確認します |
| `config.local.toml` が見つからない | `-Config` に絶対パスを渡すか、`LOCAL_MCP_CONFIG` を設定します。`LOCAL_MCP_ROOT` との併用時は同じ設定を指している必要があります |
| ファイル操作はできるが Git が unavailable | Git の path／SHA-256 の組、pinned runtime、Sandbox の live marker、`verify-git-broker` の結果、policy generation の変更を確認します |
| Sandbox が unavailable | 承認プロセス、Codex path、WFP／Job／process census を含む live verification、scratch quota、必須 property を確認します。Host へ自動移行はしません |
| Approved Host が unavailable または recovery required | service、immutable runtime、承認世代、postflight、durable authority state を確認し、必要な場合だけ管理者の recovery 手順を実行します |
| ADB が拒否される | `adb.exe` の絶対 path と SHA-256、`-s SERIAL`、`adb_allowed_serials`、emulator-only 条件、固定 read grammar を確認します |
| 承認要求が処理されない | `run-approvals.ps1` が同じ設定を使って起動しているか、要求の TTL が切れていないか、理由と manifest が表示されているかを確認します |
| Context が無効になる | sidecar のファイル名・環境変数、固定 endpoint、認証情報、サイズ上限を確認します。sidecar を変更した後はサーバーを再起動します |
| 変更を戻せない | checkpoint の対象外である `.git`、ACL、外部サービス、ネットワーク、別プロセス、デバイスの副作用でないか、または競合が発生していないかを確認します |

## ドキュメントと検証コマンド

仕様や運用を変更するときは、README だけでなく関係する正本も確認します。

| 文書 | 内容 |
| --- | --- |
| [SPEC.md](SPEC.md) | 実装仕様、経路、データモデル、制約 |
| [SECURITY_CONTRACT.md](SECURITY_CONTRACT.md) | セキュリティ上の不変条件と禁止事項 |
| [VERIFICATION.md](VERIFICATION.md) | 実行済み検証、証拠の範囲、残存リスク |
| [WFP_GUARD_VALIDATION.md](WFP_GUARD_VALIDATION.md) | Windows Sandbox／WFP 境界の検証記録 |
| [docs/APPROVED_HOST_PRODUCT_INVARIANT.md](docs/APPROVED_HOST_PRODUCT_INVARIANT.md) | Approved Host を中核 capability として維持する条件 |
| [config.example.toml](config.example.toml) | 設定項目の基準値 |
| [context-read.example.toml](context-read.example.toml)／[context-export.example.toml](context-export.example.toml) | Context Read／Export の sidecar 設定例 |

開発時の基本確認は次のとおりです。

~~~powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m windows_local_mcp.cli verify-codex-sandbox
.\.venv\Scripts\python.exe -m windows_local_mcp.cli verify-git-broker
~~~

最初のコマンドはテスト、後二つはこの PC の現在の実行環境に依存する実機検証です。テストが成功しても、実機検証、通常ユーザーの UAC／LocalSystem lifecycle、Secure MCP Tunnel／ChatGPT E2E、実ネットワークの遮断が完了したことにはなりません。

## 検証範囲

unit／integration test、Windows 上の Sandbox／Automatic Git 実機検証、Secure MCP Tunnel／ChatGPT E2E は別の証拠です。テスト成功だけで OS 隔離や Tunnel E2E を検証済みとは表示しません。

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Automatic Git の unit／CI regression が green でも、この PC で `verify-git-broker` が成功して current Git-specific marker が存在するまでは `available=false` が正しい状態です。通常 operation は marker を作成・repair しません。Git runtime identity、Sandbox backend／live evidence、workspace、scratch quota、Automatic Git containment-policy generation v6、command-policy generation v5、trusted process-cwd policy、exact projection ownership-trust policy、sanitized `core.autocrlf` semantics、required-builtin policy が変われば marker は stale になり、Git child spawn 前に fail closed します。

Sandbox が利用不能、必須境界が未検証、timeout、setup failure、command failure の場合は、その operation を unavailable／failed として表示します。一般 Sandbox で受容済み残存 risk の `protected_information_read`／LAN failure はそのまま表示し、その他の mandatory route gate と分離します。Automatic Git はこの residual-risk allowance を使用せず、全 property が verified でなければ unavailable です。Approved Host へ自動 fallback しません。

Approved Host は current v1 で、`approved_host_enabled=true`、immutable runtime、authenticated LocalSystem authority service、current approval／generation／manifest checks が成立する eligible command に限って production execution を許可します。WLMCP-R2-001 の authority separation は 2026-08-28 に実 Windows normal／abnormal／recovery lifecycle で検証済みですが、別 PC や runtime／service／policy 変更後の current preflight を省略できる意味ではありません。

`session_info.transport` は stdio と HTTP を別々に `configured`／`enabled`／`available` で表示します。現行版で利用可能なのは single-user local stdio だけで、HTTP は loopback 指定であっても startup validation が拒否します。
