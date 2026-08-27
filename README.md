# Windows Local MCP

ChatGPT から、指定した 1 つの Windows 作業領域を安全に読み書きするためのローカル MCP サーバーです。ファイル編集、構造化ファイル処理、監査、承認付きコマンド、変更履歴、Undo／rollback を提供します。

通常起動は管理者権限で行わないでください。`workspace_root` はプロジェクト単位で指定し、ドライブ直下やユーザーフォルダー全体を指定しないでください。

## 実行構成

処理は次の 4 種類に分かれます。安全性を安価に閉じられる処理まで Sandbox に送らず、作用範囲を閉じられない処理だけを隔離します。

1. **WLMCP Broker**
   - 対象パス、入出力、容量、副作用を WLMCP が限定できる処理です。
   - ファイル read/write、差分、固定 ADB 読み取り、固定 Git metadata 読み取り、バイナリ転送、checkpoint、transaction、Undo／rollback を直接扱います。
   - Automatic Git Broker は pinned `git.exe`、bounded／sanitized disposable repository projection、live-verified Codex Windows Sandbox containment、Git-specific live marker がすべて current の場合だけ `git_info`／`execute_readonly` の固定 Git grammar を実行します。Automatic `diff`／`show` は metadata-only で、patch／binary patch／`--check`／暗黙 patch output は対象外です。marker が missing／stale／failed の PC では Git child を起動せず fail closed します。
2. **構造化処理**
   - DOCX、XLSX、CSV／TSV、ZIP、一般画像を宣言的な操作として処理します。
   - 現在は WLMCP 管理処理を使用し、処理結果を artifact として検証してから Broker の transaction で反映します。将来の ChatGPT container 処理も同じバイナリ転送境界へ接続できます。
3. **Codex Sandbox**
   - 任意コード、project script／plugin、test／build、一般コマンドなど、WLMCP だけで副作用を閉じにくい処理を実行します。
   - 承認済み workspace snapshot から作った operation 固有 run copy を project filesystem として使用し、original `workspace_root` は parent／child／grandchild から read／write deny を要求します。この snapshot-only 構成は defense-in-depth として維持します。
   - current v1 の一般 Codex Sandbox route では workspace 内 protected information の direct read denial を完全保証できません。`protected_information_read` と LAN access は受容済み残存 risk として実測結果を保持・表示し、それだけでは一般 route を unavailable にしません。この residual-risk allowance は Automatic Git には適用しません。
   - 利用にはローカル承認と、この PC での Sandbox 実機検証が必要です。その他の必須境界が失敗した場合は利用できず、Host へ自動移行しません。
4. **Approved Host**
   - `request_host_command` と設定 schema は compatibility／将来拡張のため残っていますが、current v1 の execution route は WLMCP-R2-001 の capability reduction により unavailable です。
   - Approved Host child と worker／postflight monitor が同一 Windows user authority にある現行構成では、monitor termination／postflight bypass を security contract 上閉じられないため、worker spawn 前に fail closed します。
   - `approved_host_enabled=true`、immutable runtime、pending／approved operation の存在は execution availability を意味しません。upgrade 前の queued／approved operation も同じ production gate で拒否します。
   - same-desktop UAC elevation だけを monitor authority separation の根拠にはしません。再有効化には別 user／session、SYSTEM service 等の実証済み Windows security boundary と restart-persistent tamper state が必要です。

旧 Safe Tier／AppContainer は現行の方針には存在しません。旧設定が残っている場合は、弱い互換動作へ移らず起動を拒否します。

## Developer editable setup

Python 3.11 以上を使用します。repository checkout と `.venv` は通常 user が編集できる開発環境であり、Broker／Codex Sandbox の開発・テスト用です。Approved Host は current v1 では runtime が immutable かどうかにかかわらず execution unavailable です。開発中は `approved_host_enabled = false` を推奨します。

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

Automatic Git Broker も `PATH` discovery を trust source にせず、workspace／`data_dir`／Sandbox scratch の外にある Git executable の絶対 path と SHA-256 を必要とします。path／hash を設定しただけでは execution availability にはなりません。まず generic Codex Sandbox live verification を成立させ、そのうえで同じ containment 内の pinned Git を使う `verify-git-broker` を明示実行して Git-specific marker schema v1 を作成する必要があります。

```powershell
$gitPath = (Get-Command git.exe).Source
$gitHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $gitPath).Hash.ToLowerInvariant()
```

```toml
git_executable_path = "C:\\Program Files\\Git\\cmd\\git.exe"
git_executable_sha256 = "ここを64桁のSHA-256へ置換"
```

```powershell
$env:LOCAL_MCP_CONFIG = 'C:\path\to\config.local.toml'
.\.venv\Scripts\python.exe -m windows_local_mcp.cli verify-codex-sandbox
.\.venv\Scripts\python.exe -m windows_local_mcp.cli verify-git-broker
```

`verify-git-broker` は通常 operation から自動実行されません。Git executable identity、Sandbox backend、generic live evidence、workspace、scratch quota、containment policy、Automatic Git command-policy generation のいずれかが変わった場合は marker が stale になり、再検証するまで Automatic Git は `available=false` です。Git-specific route は general Sandbox で residual risk として許容する `protected_information_read`／LAN を継承せず、全 Sandbox security property が `verified` の場合だけ route eligible です。

開発 server は次のとおり起動します。設定が不正な場合は、workspace を操作する前に起動を拒否します。

```powershell
.\run-server.ps1 -Config .\config.local.toml
```

Secure MCP Tunnel には、Shell 文字列ではなく次の argv を登録します。

```text
powershell.exe -NoProfile -File C:\dev\windows-local-mcp-python\run-server.ps1 -Config C:\path\to\config.local.toml
```

複数 workspace は別々の `config`、`data_dir`、Sandbox scratch を使用してください。namespace marker が workspace、data_dir、実体識別子の混在を拒否します。Windows では handle から得た volume GUID 付きの物理 path も比較するため、junction／reparse point だけでなく SUBST 等の別名で同じ領域を指定した場合も起動を拒否します。

## Approved Host current status

Approved Host の immutable runtime installer／verifier は、将来この route を安全に再有効化する場合の runtime immutability layer として残しています。ただし immutable runtime は WLMCP／Python の永続改変を防ぐ一層であり、same-user child による worker／monitor kill や postflight bypass を防ぐ authority boundary ではありません。

そのため current v1 では、Program Files 配下へ runtime を provision し lower-level immutability verification が成功しても Approved Host command は実行できません。production gate は worker spawn 前に必ず fail closed します。既存 installer／verifier の意味、将来の再有効化条件は `docs/APPROVED_HOST_RUNTIME.md` を参照してください。

`session_info()` の Approved Host capability は current v1 では `available=false`、`live_verified=false`、`windows_live_verified=false` です。設定上の intent や runtime immutability の unit／preflight evidence を、Approved Host 全体の live verification として扱いません。

## 主な機能

| 用途 | 経路 | 主な tool |
| --- | --- | --- |
| テキスト／バイナリの読み書き | Broker | `read_file`, `write_file`, artifact transfer |
| 固定 Git metadata 読み取り | Automatic Git Broker | `git_info`, `execute_readonly` |
| content-bearing／一般／変更系 Git、project-controlled 処理 | Codex Sandbox（適用可能な場合） | `request_sandbox_command` |
| Emulator の限定読み取り | Broker | `adb_read`, `get_adb_screenshot` |
| DOCX／XLSX／CSV／TSV／ZIP／画像 | 構造化処理 | `structured_file_inspect`, `structured_file_apply` 等 |
| Python、PowerShell、Node、test、build、project script | Codex Sandbox | `request_sandbox_command` |
| Sandbox 外の Windows 権限／network が必要な処理 | current v1 では unavailable | `request_host_command` は compatibility staging のみ |
| 状態確認、停止、監査 | Broker | `poll_job`, `stop_job`, `activity_get`, `audit_get` |
| 変更取消 | Broker | selective Undo、point-in-time rollback |

`execute_workspace_write` は互換用の公開面を残していますが、Dart／Flutter 等の project-controlled 処理は拒否され、`request_sandbox_command` を案内します。

`git_info` と `execute_readonly` の固定 Git grammar は、current Git-specific marker が成立した Windows PC では Automatic Git Broker として実行できます。Git child は live workspace を直接読まず、operation ごとの bounded／sanitized projection を処理します。`.gitattributes`、hooks、object alternates、external／extended repository metadata、nested `.git`、reparse／hardlink／ADS 等は除外または拒否し、source `.git/config` は raw bytes を scratch へ保存せず Broker memory 上で解析して inert `core` settings だけを書き出します。config parsing は 1 MiB で fail closed します。

Git object database には、現在の working-tree policy では protected な内容を含む historical blob が残り得ます。また攻撃者はその blob を一見安全な tree／commit／index path に再結合できます。そのため current workspace path の検証や `^{commit}` binding だけを content provenance とみなしません。Automatic `diff`／`show` は `--stat`、`--name-only`、`--name-status`、`--quiet`、`--no-patch` 等の metadata-only output に限定し、`--patch`／`-p`／`--binary`／`--check`／pathspec 付き暗黙 patch は `request_sandbox_command` の対象です。`git_info` snapshot も status、diff stat/name-status、log metadata 等に限定します。marker がない／stale な PC では process creation 前に拒否し、Approved Host へ fallback しません。

Automatic Git repository projection の byte limit は configured `max_sandbox_scratch_bytes` の 1/2 以下です。残りを operation 固有 runtime／transient output 用に残し、operator quota を超える hard-coded repository-size floor は使用しません。

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

`request_sandbox_command` と `request_host_command` は要求を作るだけで、その呼び出し時にはコマンドを実行しません。`request_sandbox_command` はローカル承認 UI で承認された要求を 1 回だけ claim して Sandbox 実行へ進みます。`request_host_command` は current v1 では compatibility staging に留まり、承認済みでも `Executor` の production gate が worker spawn 前に拒否します。

承認には、argv、cwd、実行ファイルと入力の hash、checkpoint、workspace／data_dir の実体 identity、設定、WLMCP build と policy generation、Sandbox backend を結合します。更新や設定変更後の古い承認、二重 claim、replay は拒否します。

承認後の Sandbox 実行ファイルも実行直前に path、SHA-256、device／inode、size、mtime を照合し、Windows では実行終了まで差し替えを拒否する handle を保持します。

Approved Host 用に既存の runtime immutability、Job Object、same-user process census、control-plane preflight／postflight code は残っていますが、WLMCP-R2-001 capability reduction 中は active security guarantee として扱いません。same-user child が監視側を停止できる architecture のままこれらを組み合わせても、postflight の実行そのものを保証できないためです。再有効化には monitor／postflight owner と durable tamper state を child から保護する別 authority boundary が必要です。

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

## 検証範囲

unit／integration test、Windows 上の Sandbox／Automatic Git 実機検証、Secure MCP Tunnel／ChatGPT E2E は別の証拠です。テスト成功だけで OS 隔離や Tunnel E2E を検証済みとは表示しません。

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Automatic Git の unit／CI regression が green でも、この PC で `verify-git-broker` が成功して current Git-specific marker が存在するまでは `available=false` が正しい状態です。通常 operation は marker を作成・repair しません。Git executable、Sandbox backend／live evidence、workspace、scratch quota、containment policy または command-policy generation が変われば marker は stale になり、Git child spawn 前に fail closed します。

Sandbox が利用不能、必須境界が未検証、timeout、setup failure、command failure の場合は、その operation を unavailable／failed として表示します。一般 Sandbox で受容済み残存 risk の `protected_information_read`／LAN failure はそのまま表示し、その他の mandatory route gate と分離します。Automatic Git はこの residual-risk allowance を使用せず、全 property が verified でなければ unavailable です。Approved Host へ自動 fallback しません。

Approved Host は current v1 では execution unavailable です。この capability reduction の回帰では「Host worker が一度も spawn されないこと」を検証し、将来再有効化する場合にだけ別 Windows authority boundary の live verification を要求します。

`session_info.transport` は stdio と HTTP を別々に `configured`／`enabled`／`available` で表示します。現行版で利用可能なのは single-user local stdio だけで、HTTP は loopback 指定であっても startup validation が拒否します。
