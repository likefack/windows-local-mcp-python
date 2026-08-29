# ローカル起動ランチャー

## 目的

Windows Local MCP の初回設定、設定確認・変更、通常起動を、長い README を読まずに進めるための入口です。

- `configure-localmcp.bat`: 設定を管理する正式な入口（初回セットアップと設定確認・変更）
- `start-localmcp.bat`: 旧名称から正式入口へ転送する互換ラッパー（非推奨）
- `run-localmcp.bat`: 2 回目以降の通常起動
- `setup-localmcp.ps1`: `configure-localmcp.bat` から呼び出す対話型設定管理
- `run-localmcp.ps1`: active config の読み取り、Tunnel の検証・起動、または既存サーバー起動スクリプトへの委譲
- `secure-mcp-tunnel.ps1`: Tunnel profile、Credential Manager、client／ready 検証を共有する内部ヘルパー

バッチは人間がダブルクリックするための入口です。MCP クライアントの stdio 設定は、既存の `run-server.ps1 -Config` を明示的に指定する契約を維持します。

## 初回設定

1. `configure-localmcp.bat` を実行します。
2. `1. かんたんセットアップ` または `2. 現在の設定を確認・変更する` を選びます。
3. `かんたんセットアップ` では、MCP から操作したい既存のプロジェクトフォルダーを指定します。
4. フォルダーの場所が分からない場合は、エクスプローラーで目的のフォルダーを開き、上のアドレスバーをクリックして `Ctrl+C`。この画面に戻って `Ctrl+V` で貼り付けます。
5. Python 3.11 以上があり、パッケージを import できない場合は、専用の `.venv` を作成してこのパッケージを editable install します。
6. Python 自体が見つからない場合は、ウィザードに表示される [Python の公式ダウンロードページ](https://www.python.org/downloads/windows/) を開き、Windows 用の Python 3.11 以上を用意してから再実行します。
7. 設定と workspace／data／Sandbox scratch の分離を実際に検証します。
8. 「ChatGPT Secure MCP Tunnel を設定しますか」と表示されたら、使う場合は Tunnel ID と Runtime API Key を案内に従って入力します。使わない場合はスキップできます。
9. 保存先と、次回に使う設定ファイルを表示します。

検証が終わった後も、active config、Codex Sandbox、Tunnel の追加確認が続くことがあります。無表示の待機に見えないよう、ウィザードは `[進行中] 65% | 経過時間 00:00.123 | ...` のように段階と経過時間を表示します。割合は処理段階の目安であり、残り時間の予測ではありません。`[OK] 設定ファイルの検証が完了しました。` に続いてこの表示が出た場合は、画面を閉じずに待ちます。

設定は次の場所に保存されます。

```text
%LOCALAPPDATA%\WindowsLocalMCP\config.toml
%LOCALAPPDATA%\WindowsLocalMCP\active-config.txt
%LOCALAPPDATA%\WindowsLocalMCP\tunnel-profiles\localmcp-<config fingerprint>.yaml
%LOCALAPPDATA%\WindowsLocalMCP\tunnel-state\<config fingerprint>.json
```

新しい設定を作るとき、既存の `config.toml` は日時付き `.backup-YYYYMMDD-HHMMSS` として保存します。既存設定を使う場合は内容をコピーせず、そのファイルを active config として選択します。

Tunnel profile と state には API Key 本体を保存しません。Runtime API Key は現在の Windows ユーザーに紐付く Credential Manager へ保存し、`run-localmcp.bat` の子プロセス環境へ実行時だけ渡します。コマンドライン、`config.toml`、workspace、`data_dir`、profile、ログ、監査記録には書き込みません。

## Secure MCP Tunnel の初回設定

Tunnel ID は OpenAI の Tunnels 管理画面で確認または作成する識別子です。既存 Tunnel があれば再利用でき、新規作成を強制しません。Runtime API Key は [OpenAI Platform の API Keys](https://platform.openai.com/settings/organization/api-keys) で作成し、Tunnel の `Read` + `Use` だけを持つ Restricted key を使います。キー全文は作成時だけ表示され、後から再表示できないため、紛失時は新しいキーを作成してください。Tunnel ID の確認・作成画面は [Tunnels](https://platform.openai.com/settings/organization/tunnels) です。

設定完了後の基本操作は次のとおりです。

```text
初回:       configure-localmcp.bat → かんたんセットアップ → workspace → Tunnel → 完了 → 今すぐ起動
通常:       run-localmcp.bat
設定変更:   configure-localmcp.bat → 現在の設定を確認・変更する
```

設定済みの場合、`run-localmcp.bat` が `tunnel-client doctor` 相当の事前確認を行い、Tunnel client から現在の `run-server.ps1 -Config <absolute config>` を一度だけ起動します。Tunnel 未設定またはスキップ済みの場合は、従来どおり `run-server.ps1` を直接起動します。通常の LocalMCP server は管理者権限で起動しません。

新しい設定では Codex Sandbox と Automatic Git を有効、Approved Host を無効にします。設定確認・変更メニューから三つを個別に切り替えられます。Sandbox／Automatic Git を有効にしても実機検証を省略せず、保存済み marker が現在の実体・設定・workspace と一致する場合だけ利用できます。無効化では marker を削除しません。再有効化時は通常の起動前検証を通過した場合だけ再利用します。

既存の profile／runtime 設定が検出された場合は、再利用、managed profile の新規設定、スキップを選べます。既存 profile の内容を無断で上書き・削除・再生成しません。`configure-localmcp.bat` の `2. 現在の設定を確認・変更する` から、LocalMCP 全体を初期化せずに次の操作ができます。

- Tunnel ID の変更
- Runtime API Key の再入力・ローテーション
- Tunnel integration の無効化
- 保持済み profile／Tunnel ID／Runtime API Key を再作成しない再有効化
- 保存済み API Key の削除
- 既存 profile と client の診断
- Codex Sandbox／Automatic Git の有効化・無効化
- Approved Host 運用用実行環境の検証、Tunnel profile との結び付け、無効化

設定確認・変更モードでは、最初に workspace、active config、Tunnel の有効状態、Tunnel ID、Runtime API Key の登録状態（secret 本体は非表示）、tunnel-client の検出状態を表示します。workspace の変更は、副作用のない候補検証を行ってから config を原子的に置換し、最終 config path で通常検証を完了した場合だけ確定します。候補検証では一時 config path に namespace／ACL marker やディレクトリを作りません。置換後の検証に失敗した場合は旧 config を復元します。Runtime API Key の更新は新しい key の `doctor` 成功後に credential だけを切り替え、失敗時は旧 key を維持します。

`tunnel-client doctor --explain` が失敗した場合は、単語の部分一致ではなく、client が出力する `FAILED_CHECKS` の check 名を優先して原因を分類します。画面には `診断コード`、失敗した check 名、終了コードを表示し、認証情報、Tunnel ID、profile 読み込み、MCP command、health listener、OAuth metadata、control plane を区別します。将来の client が未知の check を返した場合も、その check 名を表示して fail closed します。doctor の生の標準出力・標準エラーは API Key などを含む可能性があるため、画面、ログ、state へ保存しません。

`config_source` は profile-file の指定自体を解決できない失敗、`profile_load` は解決したファイルを読み取れない失敗として別の診断コードにします。managed profile の staging file は v0.0.10 の `--profile-file` が要求する `.yaml` suffix を維持し、doctor 成功後に同じ directory 内で atomic replacement します。

Tunnel client が見つからない場合は、[公式 Tunnels 管理画面](https://platform.openai.com/settings/organization/tunnels) または [公式リリース](https://github.com/openai/tunnel-client/releases/latest) の案内を確認し、workspace・`data_dir`・リポジトリの外へ配置してから再実行します。ChatGPT 側で接続やツールが表示されない場合は、Tunnel／connector の tool refresh や再接続が必要になることがあります。

手入力した tunnel-client の path が拒否された場合は、存在確認、通常ファイルか、reparse point か、workspace／`data_dir`／リポジトリ内か、SHA-256 を計算できるかのうち、失敗した具体的な理由を表示します。

Tunnel client と profile の SHA-256 計算は、Windows PowerShell の module 自動読込状態に依存しない .NET `SHA256` を使用します。

managed profile の MCP command に含める Windows path は、tunnel-client v0.0.10 でも drive path を安全に解釈できる `C:/...` 形式へ正規化します。空白や日本語を含む path は引用符内にそのまま保持します。

## 手動で設定を変更する場合

設定完了後に項目を手動で調整する場合は、表示された `config.toml` をメモ帳やエディターで開きます。`workspace_root` は MCP から操作したいフォルダー、`data_dir` はその外側の保存場所です。保存後は次のように明示して検証・起動できます。

```text
run-localmcp.bat -Config C:\path\to\config.toml
```

別の設定ファイルへ切り替える場合は、`configure-localmcp.bat` の `2. 現在の設定を確認・変更する` から `active config を変更する` を選びます。`active-config.txt` はウィザードが管理するため、通常は直接編集しません。

## 通常起動

設定完了後は `run-localmcp.bat` を実行します。第 1 引数に別の設定ファイルを指定することもできます。

```text
run-localmcp.bat
run-localmcp.bat C:\path\to\config.toml
run-localmcp.bat -Config C:\path\to\config.toml
```

`run-localmcp.bat` は `run-localmcp.ps1` を呼び出します。PowerShell 側で UTF-8 の active config を読み、Tunnel integration が有効なら profile／client／Credential Manager／ready 状態を確認して Tunnel 経由で `run-server.ps1 -Config` を一度だけ起動します。無効または未設定なら、従来の `run-server.ps1 -Config` へ直接渡します。

起動中は、`activity_timeline`／`audit_list` と同じ `<data_dir>\audit.db` を別プロセスが読み取り専用で確認し、起動後に発生した操作と状態変化をこのウィンドウへ一行ずつ表示します。表示項目は操作 ID、ツール、実行経路、状態、承認状態、安全に伏せ字化したコマンドまたは対象の短い要約です。承認待ちは `PENDING_APPROVAL 要承認` と表示します。承認の実行は権限境界を混ぜないため `run-approvals.ps1` の別画面に残します。

表示した行は `<data_dir>\logs\localmcp-activity.log` にも UTF-8 で保存し、5 MiB ごとに切り替えて過去10ファイルまで保持します。生の要求・結果、ファイル内容、標準出力・標準エラーは監視ログへ複製しません。Tunnel client の生出力も Runtime API Key などを含む可能性があるため、画面・ログへ転送しません。活動監視だけを開始できなかった場合は警告を出して LocalMCP を起動しますが、Tunnel や実行経路の安全性検証を迂回することはありません。

Windows PowerShell 5.1 を正式サポートする配布対象の `.ps1`（setup、run、server、approvals、Tunnel helper）は、ソース内の日本語を正しく解釈できるよう UTF-8 BOM 付きで保存します。PowerShell 7 だけでなく、実際の Windows PowerShell 5.1 parser でも配布対象全体を検証します。

stdio server の初期化に成功すると、`起動に成功しました`、`ChatGPT からの接続を待っています`、`このウィンドウを閉じないでください`、`Ctrl+C` で終了できることを標準エラーへ表示します。MCP protocol が使用する標準出力には人向け案内を出しません。

そのため、設定ファイルのパスに日本語が含まれていても、コマンドプロンプトの文字コードに依存しません。設定がない場合は自動的に設定を推測せず、`configure-localmcp.bat` の実行を案内します。

通常のサーバーは管理者権限で起動しません。管理者権限が必要な Approved Host の runtime／authority service の導入は、通常起動とは別の明示的な手順です。ウィザードは既存の Program Files runtime と authority service を検証して Tunnel profile へ結び付けられますが、production runtime／service を勝手にインストール・置換しません。Approved Host 用 state では `run-server.ps1` の絶対 path と SHA-256 を保存し、起動ごとに runtime の変更不能性を検証します。失敗時に開発用 runtime へ戻しません。

Tunnel の設定不整合、client の変更、API Key の取得失敗、認証失敗、LocalMCP server の起動失敗、ready 応答未確認は、それぞれ別の案内を表示して起動を停止します。Tunnel を設定済みの状態で問題がある場合に、Tunnel を迂回して LocalMCP を直接公開する自動 fallback は行いません。二重起動を避けるため、起動中のプロセスを確認できない場合も停止します。

`data_dir ACL changed after provisioning` が出た場合は、Win32 security descriptor から取得した SID、ACE 種別、継承フラグ、権限値を固定 policy と比較して fail closed にします。`.acl-policy.json` の削除による通常起動への復帰や自動 ACL 再設定は行いません。旧 marker が `icacls` の表示文字列ハッシュを保持している場合だけ、現在の ACL が固定 policy と完全一致することを確認して新形式へ移行します。実際の ACL 差分がある場合は移行しません。エラー時は `data_dir` と marker を保全して ACL 差分を確認し、既存 state を引き継がない新しい config／`data_dir` を作るか、確認済み ACL を明示的に再設定してから再検証します。

## 自動設定しないもの

- Automatic Git は `Git\mingw64\bin\git.exe` のような実 runtime だけを候補にし、検出時に SHA-256 を設定します。`verify-git-broker` の live verification は明示的に実行する必要があります。
- ADB は SDK を検出しても、許可する emulator serial を利用者が確認していないため自動有効化しません。
- Codex Sandbox は、設定の有効化、backend の安全な解決、Windows の live verification を別々に表示します。セットアップの「利用可能」は native `codex.exe`、必要な helper、Authenticode、SHA-256、安定ファイル識別、version を同じ production resolver で確認できたことを意味し、live verification の完了を意味しません。Windows の公式 npm global install では PATH 上の `codex.ps1`、`codex.cmd`、`codex` を locator としてだけ使い、公式 `@openai/codex` package manifest が示す対象 architecture の native `codex.exe` と同梱 `codex-code-mode-host.exe` を解決します。shim 自体を Sandbox の trusted executable として実行することはありません。Codex が見つからない、package 配置が不正、署名または helper 閉包を確認できない場合は、ファイルの読み書きだけを残して Sandbox 経路を fail closed にします。導入は [OpenAI 公式の Codex CLI 案内](https://developers.openai.com/codex/cli/) を確認し、導入後に `configure-localmcp.bat` を再実行します。
- Sandbox の失敗を理由に Approved Host へ自動 fallback しません。

## 複数のフォルダー

現在は、1つの `config.toml` と1つの MCP サーバープロセスにつき、操作対象の `workspace_root` を1つだけ指定します。複数のフォルダーを使う場合は、それぞれに別の `config`、`data_dir`、Sandbox の一時領域を用意し、`run-localmcp.bat -Config <path>` またはセットアップ画面で設定を切り替えます。同じプロセスから複数フォルダーを同時に操作する機能は、パスの指定方法だけでなく承認・履歴・Git・Sandbox の境界を含む仕様変更が必要です。

## GitHub Release での配布

利用者にはリポジトリのソースを個別に構成させず、GitHub Release のバージョン付きパッケージを配布します。少なくとも次を同じリリースへ含めます。

- 2 本のバッチ
- `setup-localmcp.ps1`、`run-localmcp.ps1`、`run-server.ps1`、`run-approvals.ps1`
- `secure-mcp-tunnel.ps1`
- `pyproject.toml`、`src`、設定テンプレート
- 配布物の SHA-256、可能なら署名または署名付き installer

`main` の raw URL から PowerShell を取得して実行する方式は使いません。更新時も、設定・監査領域を上書きせず、検証済みのバージョン付き配布物だけを明示的な利用者操作で更新します。
