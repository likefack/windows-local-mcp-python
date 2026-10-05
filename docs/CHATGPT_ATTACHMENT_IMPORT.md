# ChatGPT 添付ファイルの取り込み

## 原因の判断

2026-10-06 の依頼では、元画像約239,448バイトをモデルがBase64へ変換して渡すと
`INVALID_ARGUMENT` が発生した一方、プログラムで生成した512 KiBのチャンクは受理された。
この観測は512 KiBという設定上限が原因との説明を支持しない。長いBase64の生成・保持・再構築、
またはクライアント側の引数検証が有力な候補だが、失敗した実リクエストと各層のログがないため
発生層・破損箇所は確定していない。元画像を縮小することも対策にはしていない。

導入済みMCP Python SDKでは、ツール本体の通常のValueError/RuntimeErrorを汎用メッセージへ
伏せる処理がある。想定内の転送エラーをToolErrorとして識別可能にする改善は行うが、
これが今回のChatGPT側のINVALID_ARGUMENTを発生させたとの断定はしない。

## 公式仕様と採用する境界

[OpenAI公式リファレンス](https://developers.openai.com/plugins/reference#file-apis)を
2026-10-06に確認した。ツールの `_meta["openai/fileParams"] = ["file"]` により、
ChatGPTは `download_url` と `file_id`、任意で `mime_type` と `file_name` を渡す。
4プロパティすべてをスキーマに宣言し、必須は最初の2つだけにする。
本体のBase64表現をモデルに作らせる必要はない。

公開仕様には、サーバーが当該会話への所属を独立検証する署名・照会APIや固定配信先一覧を
確認できなかった。fileParamsやfile_idの形式は出所の証明ではなく、モデルの申告も信用しない。
この制約を説明したうえで、ユーザーは「管理者が確認した正確な配信ホストへの限定取得」を
承認した。会話への所属検証を達成したとは扱わない。同じ許可ホスト上の別リソースを指す
参照までは区別できない。配信ホストを汎用URL取得サービスや転送サービスにしてはならない。

## 使用方法

1. 管理者がChatGPTから実際に渡るファイル配信先を確認し、信頼できるファイル専用ホストの
   小文字DNS名を、信頼済みローカル設定 `attachment_import_allowed_hosts` に登録する。
   初期値は空。推測したOpenAIドメイン、共有クラウド全体、ワイルドカードは登録しない。
   一時URLや署名クエリを設定ファイル、チャット、監査へ貼り付けない。
2. 通常の配備手順でサーバーを更新・再起動し、ChatGPT側でもツール定義を更新する。
   immutable runtimeを使う環境ではソース変更だけでは配備されない。
3. ファイルを添付し、`artifact_import_file(file=<ChatGPTが渡す参照>, path="cards/input.jpg")`
   を使う。親ディレクトリは既存である必要がある。`file_name` は保存先に使わない。
4. 元データのSHA-256がプログラムから取得できるなら `sha256` を指定する。
   既存ファイルを置き換える場合はその現在のハッシュを `expected_sha256` に指定する。
   2つは別の目的であり、取り違えない。
5. 結果の `after_bytes`、`after_sha256`、`operation_id` と必要に応じて取得元ハッシュを確認する。
   送信元ハッシュがない場合、受信データのハッシュを計算したことだけでは元ファイルとの
   独立した一致証明にならない。`source_sha256_verified` がその違いを表す。

fileParams非対応のクライアントや配信先が未設定の環境では、この経路は使えない。
モデルにBase64をコピーさせて代用せず、バイト列を持つプログラムから従来の転送APIを使う。

## 処理と保存の保証

参照と保存先・CASを事前検証 → 許可ホストのDNS解決 → 全候補IP検証 → 検査済みIPへ
TLS接続 → サイズを制限して受信・SHA-256計算 → ハッシュ／既知形式のシグネチャ確認 →
既存 `_atomic_binary_mutation` によるCAS再検査、checkpoint、原子的保存、事後検証。

取得中はワークスペースを変更せず、全体上限付きメモリへ受信する。同時取得は名前付きロックで
1件に制限する。Base64化、永続的なURL保存、新しい転送セッション形式は不要。
保存開始後の失敗は既存のtransaction／rollback／recovery状態をそのまま利用し、自動再試行しない。
取得中に新規保存先が作成された場合も、既存ファイル用CASがなければ上書きしない。

## 通信と入力の制限

- 正確な許可ホスト、HTTPS、443番だけ。資格情報付きURL、fragment、制御文字、非ASCII URLを拒否。
- DNSの全結果を検査し、loopback、private/LAN、link-local、非公開・予約・multicast、
  IPv4埋込み／遷移IPv6を拒否。検査済み数値IPを直接接続先として使用し、再解決しない。
  TLS証明書は元ホスト名で検証し、環境プロキシ、Cookie、任意認証ヘッダーを使用しない。
- 全リダイレクトを拒否。通信先障害でも別ホストへフォールバックしない。
- Content-Lengthと実受信量を別々に制限する。重複Length、LengthとTransfer-Encodingの併用、
  不正な転送符号化、圧縮Content-Encodingを拒否する。上限を超える1バイトで受信を停止。
  Lengthもchunked終端もないEOF区切りは、元ファイルのSHA-256が指定された場合だけ許可する。
  これにより、途中切断を正常なファイル末尾として保存することを避ける。
- `attachment_import_timeout_seconds`（既定60秒）と各ソケット操作最大10秒を使用し、
  接続後はタイマーによるshutdownで遅いヘッダー／本文も中止する。
  DNS解決呼出し自体の待ち時間はOSリゾルバーに依存し、その途中をPythonから強制中断しない。
- JPEG/PNG/GIF/WebP/PDF等のシグネチャを検出し、対応する申告MIMEとの矛盾を拒否する。
  完全なデコード検証やマルウェア検査ではない。未知形式はopaque binaryとして保存し、実行しない。
- URL、file_id、元ファイル名、HTTPヘッダー、Base64本体は監査に残さない。
  取得失敗はURLを含まない固定エラーへ変換する。保存処理にはこれらの入力を渡さない。
  添付／upload系ツールのSDK生成引数モデルにも `hide_input_in_errors` を設定し、
  必須引数欠落時に入力全体がエラーへ含まれることを防ぐ。SDK内部の引数モデルへの依存は
  回帰テスト対象であり、その構造が変わった場合は起動を失敗させて確認を求める。

これはBrokerの狭い追加操作であり、Sandbox子プロセス、Git、ADB、Approved Hostの通信権限や
承認・分離・回復の境界を変更しない。

## 従来転送と上限

| 層 | 上限・役割 |
|---|---|
| チャンクのraw bytes | `max_transfer_chunk_bytes`、既定524,288バイトを維持 |
| チャンクBase64 | decode前に `4 * ceil(raw上限 / 3)`。既定699,052文字。その後raw上限も検査 |
| one-shot | `max_one_shot_artifact_bytes`、既定262,144バイト。既存のBase64上限も維持 |
| ファイル全体 | `max_structured_file_bytes`、既定64 MiB。取り込み、転送、保存で共用 |
| MCPメッセージ全体 | JSONキー、他の引数、envelope等を含む。上記Base64上限とは別。ChatGPT、SDK、transport、proxy各層の制約に依存 |

導入済みMCP Python SDK 2.1.1のstdio受信経路では明示的なメッセージバイト上限は見つからなかった。
一方、SDKのStreamable HTTP/SSEには既定4 MiBのrequest body上限があり、宣言長と実受信量を検査する。
本製品はstdio専用で、Secure MCP Tunnelもstdio childを中継するため、このHTTP上限をそのまま
今回の経路の上限とは扱わない。Tunnel clientやChatGPTの独自上限は未確認であり、
特に長いモデル出力の安定性を保証しない。
one-shotとbegin/chunk/commitは、クライアントプログラムが本体バイト列を保持する用途で継続利用する。

## エラーと検証

転送エラーは `TRANSFER_BASE64_INVALID`、`TRANSFER_BASE64_LIMIT`、`TRANSFER_CHUNK_LIMIT`、
`TRANSFER_BOUNDARY_INVALID`、`TRANSFER_OFFSET_INVALID`、`TRANSFER_TOTAL_SIZE_LIMIT`、
`TRANSFER_INCOMPLETE`、`TRANSFER_INTEGRITY`、`TRANSFER_SHA256_MISMATCH` を区別する。
添付取得は `ATTACHMENT_REFERENCE_REJECTED`、`ATTACHMENT_IMPORT_NOT_CONFIGURED`、
`ATTACHMENT_ADDRESS_REJECTED`、`ATTACHMENT_REDIRECT_REJECTED`、`ATTACHMENT_ENCODING_REJECTED`、
`ATTACHMENT_LENGTH_INVALID`、`ATTACHMENT_LENGTH_REQUIRED`、`ATTACHMENT_SIZE_LIMIT`、`ATTACHMENT_INCOMPLETE`、
`ATTACHMENT_TIMEOUT`、`ATTACHMENT_FETCH_FAILED`、`ATTACHMENT_FORMAT_MISMATCH`、
`ATTACHMENT_SHA256_INVALID`、`ATTACHMENT_SHA256_MISMATCH`、`ATTACHMENT_PATH_REJECTED`、
`ATTACHMENT_CAS_REQUIRED`、`ATTACHMENT_CAS_MISMATCH` を使用する。
保存処理開始後のCAS／回復エラーは既存transactionの意味を維持する。
Python例外にはcode属性がある。MCP wire上では標準ToolErrorの本文接頭辞としてコードを返し、
独自JSON-RPCエラーコードの追加は行わない。

ローカルテストの結果と実ChatGPTへの接続未検証範囲は `VERIFICATION.md` を参照。
