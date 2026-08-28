# ローカル起動ランチャー

## 目的

Windows Local MCP の初回設定と通常起動を、長い README を読まずに進めるための入口です。

- `start-localmcp.bat`: 初回設定・既存設定の診断
- `run-localmcp.bat`: 2 回目以降の通常起動
- `setup-localmcp.ps1`: `start-localmcp.bat` から呼び出す対話型セットアップ
- `run-localmcp.ps1`: active config の読み取りと既存サーバー起動スクリプトへの委譲

バッチは人間がダブルクリックするための入口です。MCP クライアントの stdio 設定は、既存の `run-server.ps1 -Config` を明示的に指定する契約を維持します。

## 初回設定

1. `start-localmcp.bat` を実行します。
2. `1. 初心者向け` または `2. 環境設定済み` を選びます。
3. 初心者向けの場合は workspace の既存フォルダーを指定します。
4. Python 3.11 以上があり、パッケージを import できない場合は、専用の `.venv` を作成してこのパッケージを editable install します。
5. 設定と workspace／data／Sandbox scratch の分離を実際に検証します。
6. 保存先と、次回に使う設定ファイルを表示します。

設定は次の場所に保存されます。

```text
%LOCALAPPDATA%\WindowsLocalMCP\config.toml
%LOCALAPPDATA%\WindowsLocalMCP\active-config.txt
```

新しい設定を作るとき、既存の `config.toml` は日時付き `.backup-YYYYMMDD-HHMMSS` として保存します。既存設定を使う場合は内容をコピーせず、そのファイルを active config として選択します。

## 通常起動

設定完了後は `run-localmcp.bat` を実行します。第 1 引数に別の設定ファイルを指定することもできます。

```text
run-localmcp.bat
run-localmcp.bat C:\path\to\config.toml
run-localmcp.bat -Config C:\path\to\config.toml
```

`run-localmcp.bat` は `run-localmcp.ps1` を呼び出します。PowerShell 側で UTF-8 の active config を読み、保存済みの設定を既存の `run-server.ps1 -Config` に渡します。

そのため、設定ファイルのパスに日本語が含まれていても、コマンドプロンプトの文字コードに依存しません。設定がない場合は自動的に設定を推測せず、`start-localmcp.bat` の実行を案内します。

通常のサーバーは管理者権限で起動しません。管理者権限が必要な Approved Host の runtime／authority service の導入は、通常起動とは別の明示的な手順です。この初版のウィザードは既存の production runtime／service を勝手に置き換えません。

## 自動設定しないもの

- Automatic Git は `Git\mingw64\bin\git.exe` のような実 runtime だけを候補にし、検出時に SHA-256 を設定します。`verify-git-broker` の live verification は明示的に実行する必要があります。
- ADB は SDK を検出しても、許可する emulator serial を利用者が確認していないため自動有効化しません。
- Codex Sandbox は設定を有効にしたまま、Codex CLI の存在と live verification の状態を別々に表示します。検証されていない境界を成功とは表示しません。
- Sandbox の失敗を理由に Approved Host へ自動 fallback しません。

## GitHub Release での配布

利用者にはリポジトリのソースを個別に構成させず、GitHub Release のバージョン付きパッケージを配布します。少なくとも次を同じリリースへ含めます。

- 2 本のバッチ
- `setup-localmcp.ps1`、`run-localmcp.ps1`、`run-server.ps1`、`run-approvals.ps1`
- `pyproject.toml`、`src`、設定テンプレート
- 配布物の SHA-256、可能なら署名または署名付き installer

`main` の raw URL から PowerShell を取得して実行する方式は使いません。更新時も、設定・監査領域を上書きせず、検証済みのバージョン付き配布物だけを明示的な利用者操作で更新します。
