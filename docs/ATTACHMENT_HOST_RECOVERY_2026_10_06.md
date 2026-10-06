# 配信ホスト変更による添付取り込み拒否（2026-10-06）

## 今回確認した原因

19:33以降の再確認では、`WindowsLocalMCPApprovedHost` は `RUNNING`（PID 38472）で、
実接続の認証付き事前検査も `healthy=true`、`active_operation_id=null` だった。
`00_受け取り` の一覧取得も成功した。以前のサービス停止を現在の障害原因とは扱わない。

試験PNGを `artifact_import_file` に渡すと、`reference_kind=file_params_object`、
`reason=host_not_permitted` を返した。今回はクライアントによるfileParams変換は成功しており、
設定済みの1ホストと配信ホストが異なることが直接原因である。
汎用の `INVALID_ARGUMENT` だけを根拠に、添付の実体化失敗と断定してはいけない。

診断修正後に実際に観測したホストは `sdmntprjapaneast.oaiusercontent.com` と
`sdmntprcentralus.oaiusercontent.com`、`sdmntprseasia.oaiusercontent.com`。
再試行でも配信地域が切り替わった。
既存 `sdmntprkoreacentral.oaiusercontent.com` を保持し、この3件だけを設定へ追加した。
[OpenAI公式のネットワーク案内](https://help.openai.com/en/articles/9247338-network-recommendations-for-chatgpt-errors-on-web-and-apps)
で `oaiusercontent.com` が利用ドメインであることも確認した。ただしこれは個々の添付の会話所属を
保証しない。ワイルドカード許可には変更していない。今後別の未登録ホストへ切り替われば、
同じ診断で拒否し、個別確認が必要になる。

## 診断の修正

許可リストが空の場合だけでなく、設定済みホストと一致しない場合も、DNS形式の検査に通った
ホスト名だけを応答へ表示する。既存エラーコードと `reason=host_not_permitted` は維持する。
URLのパス・クエリ・ファイルID・元ファイル名を追加せず、ホスト名は監査にも保存しない。
不正なDNS名とIPリテラルは表示しない。許可リストの自動変更、任意URL取得、Base64への迂回はない。

運用版を基準に `attachment_import.py` と `server.py` の今回の2ハンクだけを反映した。
リポジトリ内の他の未コミット変更は配備していない。設定ハッシュ、処理中操作、復旧状態、
運用ファイルのハッシュを確認した。サービス登録・ACL・回復状態は変更していない。
最初の配備は対象サーバー数の検査で停止し、運用版は未変更。その後対象2プロセスを識別して配備した。

サーバー終了時にTunnelも終了し、最初の取り込み再試行はタイムアウトした。
通常ランチャーの初回再起動は別起動処理との競合検出で停止したため、競合処理の終了後に再起動した。
これらの失敗を取り込み成功として数えない。

19:52には別作業の `verify-user-entry.ps1` → `update-localmcp.bat` →
`update-localmcp.ps1` が並行実行されていることを確認した。
以後こちらからの運用変更・再起動を止め、並行更新の完了を待った。
サービスは再照会でもRunningだがPIDは56604へ変化した。
並行更新は19:56:24に終了コード1で終了した。その後既存の通常ランチャーを起動し、
接続準備完了と画像保存を確認した。並行更新自体の成功を主張するものではない。

## 検証

実装担当の関連5ファイル135テストが成功。主担当も診断・参照形式の56テストを独立実行し成功。
`git diff --check` 成功。これらは配信先通信の実証とは区別する。

配備候補・元ファイル・ハッシュ・配備結果は `.dev-tmp/attachment-host-current/`。
元の相談の画像2枚はこのチャットに添付されていないため、本人の画像保存とは区別する。

## 最終確認：試験画像の直接保存成功

`artifact_import_file` は `status=succeeded`、`source_sha256_verified=true`、
`rollback_state=complete` を返した。Base64生成・転記・分割uploadは行っていない。

- 保存先: `C:\Users\22905\Personal_knowledge\00_受け取り\画像転送確認_20261006_1935.png`
- サイズ: 161バイト（PNG）。
- 元画像・保存後SHA-256: `be883ccd8d000bf0edabfcab8f85c9d6c71175547a7a7a3f056066759cf97c89`
- 取り込みoperation_id: `3ab698d3-8847-4e86-80c7-0739b97b7189`
- 保存後一覧operation_id: `0a55eee8-a946-4887-8b3d-25ace93f8f1e`

MCPの応答とは別に、ホストから元画像・保存画像を `Get-FileHash` で読み直し、一致を確認した。
証拠は `readback.json` と `successful-import.json`。サービスは最終照会でもRunning。
試験画像は利用者が確認できるよう上記の場所に保持した。

今回のCodex接続での端末パス→fileParams→HTTPS取得→原子的保存の成功であり、
未添付の元画像2枚、他のクライアント、未登録配信ホストでの成功まで保証するものではない。
Approved Hostの承認後コマンド実行・異常終了回復や別件のCodex Sandbox障害は再検証していない。

コミットメッセージ案: `fix: 添付配信ホスト不一致の安全な診断を追加`
