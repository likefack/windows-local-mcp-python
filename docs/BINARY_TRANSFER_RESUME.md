# バイナリ転送の復旧とChatGPT連携（2026-10-06）

## 今回の判断

| 項目 | 対応 | 理由・実装箇所 |
|---|---|---|
| ChatGPT添付の直接取り込み | 既存の未コミット実装を維持し、追加検証 | `artifact_import_file`、`attachment_import.py`。fileParams、取得制限、既存transactionを再利用 |
| upload再送 | 実装 | `server.py`、`transfer_receipts.py`。応答消失後も受信済みチャンクを安全に再送できる |
| transfer status | 実装 | `artifact_transfer_status`。本文を読まず、公開メタデータだけを返す |
| decode前Base64上限 | 既存チャンク検査を維持・補強 | 非canonical表現の拒否、one-shotの文字数検査をASCII走査より前へ移動、MCP向けエラー識別 |
| 転送専用TTL | 実装 | `binary_transfer_ttl_seconds`。新規転送は絶対期限をmanifestへ保存 |
| download開始I/O | 計測のうえ維持 | 元ファイル再検査と保存済みsnapshot検証を削る根拠が不足。読込量は3N、コピー書込はN |
| ChatGPTへの直接ファイル出力 | 未実装 | 通常のChatGPT／Secure MCP TunnelでローカルMCPの出力をファイルとして取り込む正式な結果形式と配送方法を確認できない |

今回の基準は作業開始時点の作業ツリーであり、Git HEADではない。取り込み・Base64事前上限は
開始時から存在していた。並行変更やApproved Host／Sandboxの作業を巻き戻していない。

## 公式仕様の確認

2026-10-06に以下の本文を確認した。

- [OpenAI Plugins Reference / File APIs](https://developers.openai.com/plugins/reference#file-apis):
  `openai/fileParams` に指定したトップレベル引数へ、必須の `download_url` と `file_id`、
  任意の `mime_type` と `file_name` が届く。4項目ともスキーマに宣言する。
- [Build an MCP server](https://developers.openai.com/plugins/build/mcp-server) と
  [Plugin Extensions](https://developers.openai.com/plugins/build/extensions):
  正式な拡張仕様への参照を確認した。
- 上記から参照された [OpenAI MCP Extensions仕様](https://github.com/openai/mcp-extensions/blob/main/docs/spec.md):
  ローカルファイルを開く `openai/files/open` は、同じ実行ホストの絶対パスを使う
  デスクトップ向けUI機能。Tunnel先のファイルを通常ChatGPTへ配送する仕様とは異なる。
- [MCP Python SDK v2のエラー処理](https://py.sdk.modelcontextprotocol.io/v2/servers/handling-errors):
  想定内のエラーは `ToolError` としてモデルへ返す。通常例外はSDKが詳細を伏せる。

Referenceはtool resultのファイル参照に言及するが、その記述だけではローカルバイト列から
ChatGPTファイルへの登録形式・転送先・有効期間を確定できない。MCP標準のresource/blobを
返せることも、ChatGPTが添付ファイルとして受け取り、本文をモデルから隠す保証にはならない。
APIのFiles APIへの登録はChatGPT会話への登録と同一ではない。
このため `artifact_export_file` や独自URL配信サーバーを追加していない。
出力要件の将来の再評価には、対象ChatGPT環境での正式な仕様と受信確認が必要である。

## 使い方

ChatGPTからWindowsへは、ファイルを添付して、保存先と必要ならハッシュを指定した
`artifact_import_file` を使う。モデルに本文Base64を作らせない。許可する配信ホストの設定、
CAS、取得失敗時の扱い、会話への所属検証の限界は
[ChatGPT添付取り込み](CHATGPT_ATTACHMENT_IMPORT.md)を参照。
今回、実際の配信ホストの許可設定や運用runtimeへの配備は行っていない。

WindowsからChatGPTへの新しい直接出力経路はない。バイト列を処理できるMCPクライアントは、
引き続き `artifact_download` または `artifact_download_begin`／`artifact_download_chunk` を使う。
長いBase64をモデルに転記・再構成させることを通常経路にはしない。

プログラムによるuploadで応答が失われた場合:

1. `artifact_transfer_status(transfer_id)` を呼ぶ。
2. `state="open"` の `next_offset` から再開するか、応答が失われたチャンクを同じ位置・長さ・本文で再送する。
3. `complete=true`、`can_commit=true` になったら `artifact_upload_commit` を呼ぶ。
4. `state="committed"` なら再保存しない。`expired`／`cancelled`／`failed` は新しい転送を開始する。

同じチャンクを再送した応答の `received` は現在の累積受信量であり、過去の応答の値を
そのまま再現するとは限らない。完全一致の再送で本文・受信記録・manifestは書き直さない。
監査イベントは呼び出しごとに記録する。commit後も保持中の正当なチャンク再送は受理するが、
commitそのものの自動再実行機能は追加していない。

## statusの意味

`transfer_id`、`direction`、`state`、`total_bytes`、`received_bytes`、`next_offset`、
`chunk_bytes`、`chunk_bytes_max`、`sha256`、`created_at`、`expires_at`、`complete`、
`can_commit` を返す。内部パス、URL、本文、エラー詳細、source binding、ファイルidentityは返さない。

- uploadの `received_bytes`／`next_offset` は永続manifestの受信位置。
- `can_commit` はバイト数がそろったことを表す。全体ハッシュ・保存先CAS・source bindingはcommitで検査する。
- downloadは任意順のチャンク読取が可能で、応答がクライアントへ届いたかはサーバーでは分からない。
  そのため受信量と再開位置は `null`。クライアント側で取得済み位置を管理する。
- downloadの `completed` は従来どおり最終チャンクを生成した状態。全チャンクの受信保証ではない。
- 照会中に期限超過していたactive transferは、計算した `state="expired"` を返す。
  manifestやworkspaceは書き換えない。後続の転送操作・admissionで期限切れ状態を永続化する。
- 終端状態は期限で上書きせず、通常のartifact retentionまで照会できる。保持期間中も容量整理で
  削除される場合があり、その後は `TRANSFER_NOT_FOUND` になる。

## upload受信記録と障害時の整合性

新規uploadはmanifest version 5を使う。`chunks.bin` はチャンクごとに48バイト
（offset 8、長さ8、SHA-256 32）を記録する。JSON manifestには `receipt_count` だけを追加し、
小さいチャンクの大量送信でJSONや応答が増大することを避ける。記録領域は開始時にまとめて予約しdata quotaへ計上する。通常のチャンクごとの容量再走査は行わず、極小チャンクで予約を使い切った場合だけ1024件単位で追加予約する。
探索は固定長記録の二分探索で、再送時に本文全体を読み直したりhashしたりしない。
一致する記録に加えて、保存済み本文の該当範囲だけを照合する。

本文fsync → 記録fsync → manifestの原子的置換の順に確定する。
manifest更新前の中断で未確認の末尾記録や予約領域が残っても、確認済み件数だけを採用し、次回書込で
未確認の末尾を置き換える。既受信範囲は変更しない。記録の欠落、切り詰め、リンク等は拒否する。

受付数・期限を調べるmanifest読取にも既存の転送単位ロックを適用する。Windowsで読取中の
ハンドルが別スレッドの原子的置換を拒否する競合を避け、終端処理と受付判定を直列化する。

同じ境界で長さまたは内容が異なる再送は `TRANSFER_DUPLICATE_MISMATCH` として拒否し、
active transferを `failed` にする。future offsetやチャンク途中からのoverlapは
`TRANSFER_OFFSET_INVALID` として拒否し、修正して再送できる。
旧version 1〜4には信頼できるチャンク境界の記録がないため、過去範囲の冪等受理は推測しない。
statusで確認した次の位置からの継続と既存commitは維持する。

## TTLと設定移行

`binary_transfer_ttl_seconds` は既定1800秒、範囲30〜86400秒。
従来の既定approval TTLと同じ30分にし、既定設定の転送寿命を維持した。
`preparing`／`open` にのみ適用し、終端snapshotの保持期間や承認の寿命を変えない。
新規転送には `expires_at` を保存するため、再起動や後からの設定変更で既存期限は延長されない。

旧manifestに絶対期限がない場合は `created_at + binary_transfer_ttl_seconds` を使う。
旧版で承認TTLを転送時間の調整に使っていた環境は、更新時に同じ値を転送専用設定へ明示する。
既存configは必須項目を増やさず読み込めるが、このカスタム設定の引き継ぎは自動推測しない。
新設定を省略すると30分になることに注意する。承認設定を以後変更しても転送には影響しない。

## 入力上限とエラー

チャンクraw上限は既定524,288バイトを維持。decode前に `4 * ((raw上限 + 2) // 3)` を
文字数上限とし、既定699,052文字を許可する。その後raw長、正規のpadding／alphabetを検査する。
raw上限+1が同じBase64文字数になる場合もあるため、decode後のraw検査は残す。
one-shotも先に文字数を検査し、巨大な入力全体のASCII走査やdecodeを避ける。

これらはJSON受信・解析後の本文上限であり、request envelope全体の上限ではない。
導入済みSDKのstdio経路で、JSON受信前に適用される製品側のサイズ上限は確認できない。
SDKのHTTP既定上限をstdio/Tunnelの保証に流用しない。

`TRANSFER_BASE64_LIMIT`／`INVALID`／`NONCANONICAL`、`TRANSFER_CHUNK_LIMIT`、
`TRANSFER_OFFSET_INVALID`、`TRANSFER_DUPLICATE_MISMATCH`、`TRANSFER_EXPIRED`、
`TRANSFER_TERMINAL`、`TRANSFER_NOT_FOUND`、`TRANSFER_INCOMPLETE`、
`TRANSFER_SHA256_MISMATCH`、`TRANSFER_SOURCE_CHANGED`、`TRANSFER_CAS_MISMATCH` 等を
既存例外の派生型と標準ToolError本文で区別する。独自JSON-RPCエラー番号は追加しない。

## 障害原因の評価

512 KiBのrawチャンクと699,052文字のBase64が通る実MCPテストを維持している。
これを上限設定の問題と断定する根拠はない。元の失敗リクエストと各層のログがないため、
モデルによるBase64生成・分割・転記の破損とクライアント引数検証を切り分けられない。
fileParamsはこの不確実な転記を通常の取り込み経路から除くための対策である。

測定結果、検証コマンド、既存失敗との切り分け、未検証範囲は
[検証記録](BINARY_TRANSFER_VERIFICATION_2026_10_06.md)にまとめる。
