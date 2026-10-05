# 添付取り込みの運用版への反映（2026-10-06）

## 対象

利用者の依頼により、`C:\Program Files\WindowsLocalMCP` の既存運用版へ
`artifact_import_file` を追加する。開発フォルダー全体を運用版へ上書きせず、
導入済みコードを基準に、今回の添付取り込みに必要な変更だけを組み込む。

- 追加: `attachment_import.py`、`artifact_errors.py`。
- 更新: `config.py` の許可ホスト・取得期限設定、`server.py` の新ツール・入力秘匿・説明。
- 他の製品Pythonファイル71件、既存の起動・承認・復旧スクリプトは導入済み版と一致。
- 転送再開・状態照会・専用TTL、一括ワークスペース操作、別作業の修正は今回配備しない。
- 依存35件とpipは導入済みの版に固定する。
- 運用設定、ワークスペース、data_dir、資格情報は変更しない。

配備用一式は `.dev-tmp/attachment-import-deploy-20261006/`。
`release-manifest.json` に旧版と候補のSHA-256、`reviewed-changes.patch` に製品コードの差分を記録する。

## 配備前の検証

運用Python 3.14と導入済みMCP 2.2.0・依存ライブラリを使用し、配備候補のimport元を確認して実行した。

- 添付取り込み3テストファイル: **79 passed, 2 warnings in 8.83s**。
  警告はpytest補助ライブラリanyioの事前importについてで、テストの省略はない。
- 最初の長い一時パスでは73件成功・6件失敗。保存処理の一時パスがWindowsのパス長制限を
  超えたため、リポジトリ直下の `.dev-tmp/pytest/imp314` を指定して全79件を再実行した。
  ACL・所有者・製品コードを変更してこの失敗を回避したものではない。
- 実stdio: 旧54ツールの定義が完全一致し、新ツール1件を加えた55ツールを公開。
  fileParams定義、既存read_file、必須引数欠落時のURL秘匿、許可ホスト未設定時の拒否を確認した。
- HTTPの成功応答は合成。実ChatGPT添付の取得成功・元ファイルとの一致はまだ検証していない。

## 更新手順

`deploy-reviewed-runtime.ps1` はWindowsの管理者確認を経て実行する。
標準インストーラーで別のProgram Files配下に候補を構築・検証してから、処理中・承認待ち操作が
ないことを再確認し、本人の接続に属するWindows Local MCPのプロセスだけを停止する。
同じTunnelに接続された別用途のCodex app-serverとTunnel本体は停止しない。

旧版を `C:\Program Files\WindowsLocalMCP.before-attachment-20261006` に退避し、
候補を元の運用パスへ移す。旧版の保護ACLを緩めたり、旧版を削除したりしない。
切替・検証・サービス再起動に失敗した場合は旧版へ戻す。結果は `installation-result.json` に残す。
更新後は通常ユーザーの権限で変更不能性・authority接続・実stdioを検証する。

設定項目追加で設定ダイジェストは変化する。旧承認やSandbox/Git検証結果を新環境の成功証拠として
使わず、既存の世代検査・再検証に従う。Approved Hostの実行や異常終了・回復の再検証まで
今回の添付試験で完了したとは扱わない。

## 残る実運用確認

`attachment_import_allowed_hosts` は空のまま。実際のChatGPT添付参照で配信ホストを確認し、
正確なホストを許可した後に取得と元データの一致を検証する。
推測したホストの許可、署名URLのチャット貼付、Base64転記による代用は行わない。

## 運用版への切替結果

利用者がWindowsの管理者確認を承認し、2026-10-06 04:04:03 JSTに切替が完了した。
更新スクリプトの終了コードは0、結果は `installation-result.json` の `installed`。
旧版は予定どおり保護されたProgram Files配下へ退避し、設定のSHA-256一致を確認した。

最初の管理者起動では、更新スクリプトのUTF-8 BOMなし保存がWindows PowerShell 5.1で
構文エラーとなり、処理開始前に終了した。UTF-8 BOM付きへ修正し、同じPowerShell 5.1で
更新用・インストール済みスクリプトすべての構文を検証してから、本人の再承認後に実行した。
この最初の失敗では運用版・サービスを変更していない。

更新後に通常ユーザーで確認した結果:

- 変更不能性検証: 成功。runtime digestは
  `10537e096bbde6ab75a7a208e9b570feccffc328ec43ed49412f7d3e38e613b9`。
- 認証付きauthority接続: `ok=true`、`healthy=true`、active operationなし。
- インストール済み版の実stdio: 55ツール。旧54ツールの定義は完全一致。
  fileParams、read_file、引数不足時のURL秘匿、許可ホスト未設定時の拒否がすべて成功。
- 証拠: `installation.log`、`post-install-security.json`、`stdio-installed-result.json`。

共用Tunnelを直接停止しない手順を採用したが、切替後の接続確認では応答がタイムアウトし、
その後の実機確認で旧ランチャーとTunnelが終了していることを確認した。
終了原因を断定せず、同一Tunnelが起動していないことを確認して通常ランチャーを再起動した。
通常ランチャー再起動後、Tunnelの `/readyz` はHTTP 200。MCP server、活動表示、
ローカル承認画面が起動した。ChatGPT接続経由の `session_info` も成功した。

- operation_id: `40f4674f-64d2-4f7c-a2cf-5c8ced565650`。
- workspace: `C:\Users\22905\Personal_knowledge`。設定は従来と同じ明示config。
- runtime digestは上記の更新後ハッシュと一致。
- Approved Hostは `available=true`、`execution_route_available=true`。
  runtime／authority preflightはともにpassed。実際の承認後実行を検証した意味ではない。
- 活動表示・永続ログを担当するプロセスと、ローカル承認UIのプロセスを確認した。
- 証拠: `live-connection-result.json`。

この会話に公開済みのクライアント側ツール一覧には、新ツールがまだ含まれていない。
運用版と接続は更新済みなので、次にChatGPTの接続設定画面で「更新する」を実行する。
実添付の配信ホスト確認・許可設定・SHA-256一致試験は引き続き未実施。

コミットメッセージ案: `docs: 添付取り込み限定版の運用配備と検証結果を記録`
