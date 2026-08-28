# ローカル起動ランチャー

## 目的

Windows Local MCP の初回設定と通常起動を、長い README を読まずに進めるための入口です。

- `start-localmcp.bat`: 初回設定・既存設定の診断
- `run-localmcp.bat`: 2 回目以降の通常起動
- `setup-localmcp.ps1`: `start-localmcp.bat` から呼び出す対話型セットアップ
- `run-localmcp.ps1`: active config の読み取り、Tunnel の検証・起動、または既存サーバー起動スクリプトへの委譲
- `secure-mcp-tunnel.ps1`: Tunnel profile、Credential Manager、client／ready 検証を共有する内部ヘルパー

バッチは人間がダブルクリックするための入口です。MCP クライアントの stdio 設定は、既存の `run-server.ps1 -Config` を明示的に指定する契約を維持します。

## 初回設定

1. `start-localmcp.bat` を実行します。
2. `1. かんたんセットアップ` または `2. 既存の設定を使う` を選びます。
3. `かんたんセットアップ` では、MCP から操作したい既存のプロジェクトフォルダーを指定します。
4. フォルダーの場所が分からない場合は、エクスプローラーで目的のフォルダーを開き、上のアドレスバーをクリックして `Ctrl+C`。この画面に戻って `Ctrl+V` で貼り付けます。
5. Python 3.11 以上があり、パッケージを import できない場合は、専用の `.venv` を作成してこのパッケージを editable install します。
6. Python 自体が見つからない場合は、ウィザードに表示される [Python の公式ダウンロードページ](https://www.python.org/downloads/windows/) を開き、Windows 用の Python 3.11 以上を用意してから再実行します。
7. 設定と workspace／data／Sandbox scratch の分離を実際に検証します。
8. 「ChatGPT Secure MCP Tunnel を設定しますか」と表示されたら、使う場合は Tunnel ID と Runtime API Key を案内に従って入力します。使わない場合はスキップできます。
9. 保存先と、次回に使う設定ファイルを表示します。

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
初回:   start-localmcp.bat → workspace 指定 → Tunnel 設定 → 完了
2回目以降: run-localmcp.bat
```

設定済みの場合、`run-localmcp.bat` が `tunnel-client doctor` 相当の事前確認を行い、Tunnel client から現在の `run-server.ps1 -Config <absolute config>` を一度だけ起動します。Tunnel 未設定またはスキップ済みの場合は、従来どおり `run-server.ps1` を直接起動します。通常の LocalMCP server は管理者権限で起動しません。

既存の profile／runtime 設定が検出された場合は、再利用、managed profile の新規設定、スキップを選べます。既存 profile の内容を無断で上書き・削除・再生成しません。`start-localmcp.bat` の `3. Secure MCP Tunnel の設定・診断だけを行う` から、LocalMCP 全体を初期化せずに次の操作ができます。

- Tunnel ID の変更
- Runtime API Key の再入力・ローテーション
- Tunnel integration の無効化
- 保存済み API Key の削除
- 既存 profile と client の診断

Tunnel client が見つからない場合は、[公式 Tunnels 管理画面](https://platform.openai.com/settings/organization/tunnels) または [公式リリース](https://github.com/openai/tunnel-client/releases/latest) の案内を確認し、workspace・`data_dir`・リポジトリの外へ配置してから再実行します。ChatGPT 側で接続やツールが表示されない場合は、Tunnel／connector の tool refresh や再接続が必要になることがあります。

## 手動で設定を変更する場合

設定完了後に項目を手動で調整する場合は、表示された `config.toml` をメモ帳やエディターで開きます。`workspace_root` は MCP から操作したいフォルダー、`data_dir` はその外側の保存場所です。保存後は次のように明示して検証・起動できます。

```text
run-localmcp.bat -Config C:\path\to\config.toml
```

別の設定ファイルへ切り替える場合は、`start-localmcp.bat` の `2. 既存の設定を使う` を選びます。`active-config.txt` はウィザードが管理するため、通常は直接編集しません。

## 通常起動

設定完了後は `run-localmcp.bat` を実行します。第 1 引数に別の設定ファイルを指定することもできます。

```text
run-localmcp.bat
run-localmcp.bat C:\path\to\config.toml
run-localmcp.bat -Config C:\path\to\config.toml
```

`run-localmcp.bat` は `run-localmcp.ps1` を呼び出します。PowerShell 側で UTF-8 の active config を読み、Tunnel integration が有効なら profile／client／Credential Manager／ready 状態を確認して Tunnel 経由で `run-server.ps1 -Config` を一度だけ起動します。無効または未設定なら、従来の `run-server.ps1 -Config` へ直接渡します。

そのため、設定ファイルのパスに日本語が含まれていても、コマンドプロンプトの文字コードに依存しません。設定がない場合は自動的に設定を推測せず、`start-localmcp.bat` の実行を案内します。

通常のサーバーは管理者権限で起動しません。管理者権限が必要な Approved Host の runtime／authority service の導入は、通常起動とは別の明示的な手順です。この初版のウィザードは既存の production runtime／service を勝手に置き換えません。

Tunnel の設定不整合、client の変更、API Key の取得失敗、認証失敗、LocalMCP server の起動失敗、ready 応答未確認は、それぞれ別の案内を表示して起動を停止します。Tunnel を設定済みの状態で問題がある場合に、Tunnel を迂回して LocalMCP を直接公開する自動 fallback は行いません。二重起動を避けるため、起動中のプロセスを確認できない場合も停止します。

## 自動設定しないもの

- Automatic Git は `Git\mingw64\bin\git.exe` のような実 runtime だけを候補にし、検出時に SHA-256 を設定します。`verify-git-broker` の live verification は明示的に実行する必要があります。
- ADB は SDK を検出しても、許可する emulator serial を利用者が確認していないため自動有効化しません。
- Codex Sandbox は設定を有効にしたまま、Codex CLI の存在と live verification の状態を別々に表示します。Codex CLI が見つからなくてもファイルの読み書きは利用できますが、Python・テスト・ビルドなどの Sandbox 経路は利用できません。導入は [OpenAI 公式の Codex CLI 案内](https://developers.openai.com/codex/cli/) を確認し、導入後に `start-localmcp.bat` を再実行します。検出だけでは Sandbox 利用可能とは判定せず、署名・ハッシュ・実体の識別情報と、この PC でのライブ検証を別途確認します。
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
