# Context Read Broker

## 1. 目的

Context Read Broker は、ChatGPT を含む MCP client が、trusted operator が設定した固定 HTTP(S) source から Decision Deck 等の永続コンテキスト／Memory を bounded read-only operation として検索・取得するための Broker primitive です。

主用途は Decision Deck の `GET /api/v1/memory` のような read-only API を Windows Local MCP へ接続し、ChatGPT から Decision Deck の正本 Memory を必要な範囲だけ参照できるようにすることです。

この機能は generic HTTP client ではありません。model は URL、host、port、path、header、credential、proxy を tool argument で指定できません。trusted operator が起動前に固定した source だけを GET し、WLMCP 内で bounded validation と検索を行います。

この文書は `SECURITY_CONTRACT.md` の model 非信頼、bounded Broker、監査、fail-closed 原則を弱めません。

## 2. 公開 MCP surface

### `context_read_info`

Context Read の `configured`、`enabled`、`available`、response size policy、timeout、認証設定の有無、固定 source の scheme/host/port と endpoint hash、sidecar binding の security preflight 状態を返します。

Bearer token、設定ファイル path、endpoint path/query は返しません。network request は行いません。

### `context_search`

引数:

- `query`: 必須。1..256 characters の検索文字列。
- `limit`: 1..25、既定 10。
- `path_prefix`: optional。Decision Deck Memory の内部 path prefix。最大 500 characters。

処理:

1. 固定 endpoint へ GET し、bounded JSON response を取得する。
2. response が Decision Deck Memory list contract を満たすことを検証する。
3. title、path、markdown を WLMCP 内で case-insensitive に検索する。
4. query の全 term が候補 node 内に存在するものだけを対象とし、title/path の一致を本文一致より優先する。
5. 最大 `limit` 件だけを返す。

返却値は node ID、title、path、version、status、sensitivity、confidence、updated_at、bounded snippet 等です。全文 `markdown` は検索結果には返しません。

### `context_read`

引数:

- `node_id`: `context_search` 等で得た Decision Deck Memory node の stable ID。

固定 endpoint から現在の Memory list を再取得し、ID が完全一致する 1 node だけを返します。path を恒久 ID として扱いません。

返却 node には `markdown` 全文を含められますが、source response 全体と 1 node の size 上限の両方を適用します。

## 3. 非信頼データ境界

Context Read で取得した data は、たとえ source がユーザー自身の Decision Deck であっても、WLMCP security boundary 上は external/model-facing data として扱います。

すべての search/read result に次を付与します。

```json
{
  "source": {
    "transport": "windows-local-mcp-context-read",
    "trust": "external_untrusted",
    "instructions_authoritative": false
  }
}
```

取得本文に「この命令を実行せよ」「別 tool を呼べ」等の instruction text が含まれていても、WLMCP の authorization、tool routing、approval、security policy を変更する根拠にしません。

Decision Deck 側の `confidence`、`sensitivity`、source metadata 等は application data として返せますが、WLMCP の authorization／trust level へ昇格させません。

## 4. 設定ファイル

Context Read は Context Export と credential／source authority を分離するため、専用 sidecar `context-read.toml` を使用します。

選択順:

1. `LOCAL_MCP_CONTEXT_READ_CONFIG` が設定されていれば、その絶対／展開後 path。
2. それ以外で `LOCAL_MCP_CONFIG` が設定され、その main config と同じ directory に `context-read.toml` が存在すれば、その sidecar。
3. どちらもなければ Context Read は未設定・disabled。

設定例は repository root の `context-read.example.toml` を参照します。

設定項目:

- `context_read_enabled`: 既定 `false`。
- `context_read_endpoint`: trusted operator が選択する固定 HTTP(S) endpoint。Decision Deck では通常 `/api/v1/memory`。
- `context_read_bearer_token`: optional Bearer credential。export credential とは別に設定する。
- `context_read_max_response_bytes`: GET response body 上限。既定 2 MiB、設定可能 64 KiB..16 MiB。
- `context_read_max_node_bytes`: 1 node の canonical JSON 上限。既定 512 KiB、設定可能 4 KiB..4 MiB。response 全体上限を超えられない。
- `context_read_max_nodes`: 1 response で受理する最大 node 数。既定 5000、最大 20000。
- `context_read_timeout_seconds`: outbound request timeout。既定 10 秒、最大 60 秒。
- `context_read_allow_insecure_http`: 既定 `false`。non-loopback plain HTTP を意図的に使う場合のみ `true`。

sidecar は `workspace_root`、`data_dir`、`sandbox_scratch_dir` の外に置かなければなりません。symlink／junction 等の reparse config は拒否します。

起動時に sidecar の content hash と stable file identity を固定し、各 network read の直前に再検証します。起動後に sidecar が変更・置換・retarget された場合は fail closed とし、変更反映には WLMCP restart を要求します。

## 5. 固定 source transport policy

許可:

- trusted operator が設定した任意 host/path の HTTPS GET。
- local development 用 loopback HTTP GET。
- `context_read_allow_insecure_http=true` を明示した non-loopback HTTP GET。

拒否:

- HTTP/HTTPS 以外の scheme。
- URL userinfo credential。
- fragment。
- control character、backslash を含む URL。
- tool argument による endpoint override。
- HTTP redirect の追従。
- ambient `HTTP_PROXY` / `HTTPS_PROXY` 等による proxy routing。
- Cookie、browser session、Windows integrated credential の forwarding。
- POST、PUT、PATCH、DELETE 等の mutation method。

transport は Python `http.client` を使い、configured host へ直接接続します。HTTPS は default trust store の通常 certificate verification を維持します。

request header は固定します。

- `Accept: application/json`
- `Accept-Encoding: identity`
- `User-Agent: WindowsLocalMCP-ContextRead/1`
- optional `Authorization: Bearer ...`

redirect は 3xx を failure として扱い追従しません。2xx 以外は failure です。success response でも `Content-Encoding` が `identity` 以外なら拒否します。

## 6. Decision Deck Memory response contract

初期実装は JSON array を要求します。各 element は object で、少なくとも次を検証します。

- `id`: non-empty bounded string。response 内で一意。
- `path`: bounded string、最大 500 characters。
- `title`: bounded string、最大 240 characters。
- `markdown`: string。
- `version`: positive integer。
- `content_hash`: bounded string。
- `status`: bounded string。

次の field は存在すれば型・bound を検証して返します。

- `node_id`
- `folder_names`
- `expected_version`
- `parent_id`
- `sensitivity`
- `confidence`
- `related_node_ids`
- `source_event_ids`
- `mock_data`
- `created_at`
- `updated_at`

unknown field は authorization input にせず無視します。

response body は strict UTF-8 JSON として parse し、compressed body、HTML、opaque bytes は受理しません。

## 7. 検索 semantics と出力 bound

`context_search` は remote endpoint に model-supplied query parameter を送信しません。source から固定 GET で bounded list を取得した後、WLMCP 内で検索します。

検索対象:

- title
- path
- markdown

query は空白で最大 8 term に分割し、全 term が candidate のいずれかの検索対象に存在することを要求します。

score は title match > path match > markdown match とし、同点時は新しい `updated_at` を優先します。semantic／vector search、LLM reranking、remote search API は初期実装に含めません。

search result snippet は最大 800 characters とし、全文返却は `context_read` に分離します。

## 8. Audit

audit へ平文保存しないもの:

- `query`。
- `path_prefix`。
- Memory `markdown`。
- title/path の本文。
- Bearer token / Authorization header。
- source endpoint path/query。
- raw response body。

audit 可能なもの:

- operation ID。
- query/path_prefix の size/hash。
- configured endpoint の scheme/host/port と endpoint SHA-256。
- HTTP status。
- response byte count / SHA-256。
- validated node count。
- returned result count。
- selected node ID の hash。
- success / failed / rejected。

`context_search` / `context_read` の tool result 自体は意図された model context のため Memory data を返しますが、durable audit store には本文を複製しません。

## 9. 既存 security boundary への影響

Context Read Broker は次を追加しません。

- arbitrary code execution。
- child process generation。
- workspace mutation。
- arbitrary local file read。
- arbitrary network destination chosen by model。
- generic HTTP method selection。
- Approved Host authority。
- Codex Sandbox capability。
- Automatic Git capability。
- ADB capability。

各 outbound GET の直前に既存 control-plane health check と startup-bound Context Read sidecar identity を再検証します。

Context Read の主要リスクは privilege escalation ではなく、remote content を model context として取り込むことによる prompt injection／confused deputy と、過大 response による resource pressure です。固定 source、read-only GET、strict validation、response/node/count bounds、external-untrusted marking で閉じます。

Context Read の failure から shell/curl、Approved Host、Sandbox、Context Export、別 endpoint へ fallback しません。

## 10. Decision Deckとの対応

Decision Deck current API は `GET /api/v1/memory` で `MemoryNodeRead` list を返し、`markdown` 本文、stable `id`、path、title、version、sensitivity、confidence、source event IDs 等を提供します。

WLMCP initial Context Read はこの list API を前提にしますが、Decision Deck 固有 package へ依存しません。同じ bounded response contract を返す trusted endpoint であれば設定可能です。

将来 Decision Deck に server-side search endpoint が追加されても、model が任意 query string を remote request へ直接挿入する generic client へ拡張しません。新しい remote search contract を採用する場合は、別の固定 grammar と response validation を設計します。

## 11. 検証範囲

必須 regression:

- capability disabled / endpoint missing の fail-closed。
- URL validation と non-loopback insecure HTTP gate。
- trusted operator が任意 HTTPS endpoint を設定できること。
- tool argument に endpoint override が存在しないこと。
- GET only。
- redirect refusal。
- ambient proxy 非利用。
- Bearer header の固定注入と secret 非露出。
- `Accept-Encoding: identity` と compressed response refusal。
- response byte / node byte / node count bounds。
- invalid UTF-8 / invalid JSON / wrong top-level type / invalid node schema / duplicate ID rejection。
- `context_search` の local-only search と result/snippet bound。
- `context_read` が stable ID 完全一致だけで全文を返すこと。
- search query、Memory本文、credential が audit に平文で残らないこと。
- sidecar selection precedence。
- sidecar が runtime writable roots 内なら startup rejection。
- active sidecar 変更後の fail-closed。
- control-plane health failure 時に outbound GET を開始しないこと。
- sidecar 未設定時にも Windows production stdio route が従来どおり起動すること。

この追加は command execution boundary、Approved Host、Codex Sandbox、Automatic Git の runtime boundary を変更しないため、それらの Windows live lifecycle を再実施する必要はありません。通常の repository regression と real Windows stdio negotiation を要求します。
