# Context Export Broker

## 1. 目的

Context Export Broker は、ChatGPT を含む MCP client が現在利用できる会話文脈、Memory 由来情報、作業状態、要約、判断材料その他のテキスト情報を、trusted operator が設定した外部受信先へ明示的に送り出すための bounded Broker primitive です。

主用途は、Decision Deck が将来提供する受信 API へ ChatGPT 側の利用可能コンテキストを取り込み、Decision Deck の共通コンテキスト／Memory 層で再利用できるようにすることです。ただし WLMCP は Decision Deck 固有実装へ依存せず、同一 payload contract を受けられる任意の HTTP(S) endpoint を trusted operator が設定できます。

この機能は ChatGPT の内部 Memory database、全会話履歴、非公開内部状態を WLMCP が直接読み出す機能ではありません。WLMCP が export できるのは、MCP client が `export_context` の tool argument として明示的に渡した情報だけです。

この文書は Context Export Broker の機能別仕様・セキュリティ追補です。既存の `SECURITY_CONTRACT.md` が定める model 非信頼、Broker の bounded side effect、監査、fail-closed 原則を弱めません。

## 2. 公開 MCP surface

### `export_context`

引数:

- `content`: 必須の本文。
- `kind`: bounded な分類文字列。固定 enum に閉じない。
- `title`: 任意の短いタイトル。
- `tags`: 任意の bounded tag list。
- `metadata`: 任意の bounded JSON-compatible object。
- `idempotency_key`: retry 用の任意 key。未指定時は WLMCP が生成する。

tool argument に URL、host、port、path、HTTP header、proxy、Bearer token を含めません。送信先と認証は trusted operator の設定だけから決まります。

成功時に返すのは `export_id`、`idempotency_key`、schema version、HTTP status、payload/content byte 数、content SHA-256、WLMCP audit operation ID 等の receipt metadata だけです。receiver response body は読み取り・返却しません。

### `context_export_info`

Context Export の `configured`、`enabled`、`available`、schema version、size/timeout policy、認証設定の有無、送信先の scheme/host/port と endpoint hash、sidecar binding の security preflight 状態を返します。

Bearer token、設定ファイル path、endpoint path/query は返しません。

## 3. 設定ファイル

既存の core `config.toml` は execution policy と control-plane binding を持つため、Context Export は専用 sidecar `context-export.toml` に分離します。これにより、外部 sink の設定追加だけで Approved Host、Codex Sandbox、Automatic Git 等の core Settings schema を拡張しません。

選択順:

1. `LOCAL_MCP_CONTEXT_EXPORT_CONFIG` が設定されていれば、その絶対／展開後 path。
2. それ以外で `LOCAL_MCP_CONFIG` が設定されており、その main config と同じ directory に `context-export.toml` が存在すれば、その sidecar。
3. どちらもなければ Context Export は未設定・disabled。

設定例は repository root の `context-export.example.toml` を参照します。

設定項目:

- `context_export_enabled`: 既定 `false`。
- `context_export_endpoint`: trusted operator が選択する固定 HTTP(S) endpoint。
- `context_export_bearer_token`: optional Bearer credential。
- `context_export_max_bytes`: canonical JSON request body の最大 byte 数。既定 256 KiB。
- `context_export_timeout_seconds`: outbound request timeout。既定 10 秒、最大 60 秒。
- `context_export_allow_insecure_http`: 既定 `false`。non-loopback plain HTTP を意図的に使う場合のみ `true`。

sidecar は `workspace_root`、`data_dir`、`sandbox_scratch_dir` の外に置かなければなりません。symlink／junction 等の reparse config は拒否します。

起動時に sidecar の content hash と stable file identity を固定し、各 `export_context` の直前に再検証します。起動後に sidecar が変更・置換・retarget された場合、送信先を動的に切り替えず fail closed にし、変更の反映には WLMCP restart を要求します。

## 4. 任意宛先と固定宛先の両立

trusted operator は `context_export_endpoint` へ任意の受信先を設定できます。一方、model は tool call ごとに宛先を指定できません。

許可:

- 任意 host/path の HTTPS。
- local development 用の loopback HTTP。
- `context_export_allow_insecure_http=true` を明示した non-loopback HTTP。

拒否:

- HTTP/HTTPS 以外の scheme。
- URL userinfo に埋め込んだ credential。
- fragment。
- control character または backslash を含む URL。
- non-ASCII の生 URL。必要な path data は percent-encode する。
- tool argument による endpoint override。
- HTTP redirect の追従。
- ambient `HTTP_PROXY` / `HTTPS_PROXY` 等による proxy routing。

送信は Python `http.client` から configured host へ直接行い、method は `POST` 固定です。HTTPS は default trust store による通常の certificate verification を維持します。

## 5. Payload schema v1

```json
{
  "schema_version": 1,
  "export_id": "uuid",
  "idempotency_key": "caller-or-generated-key",
  "created_at": "RFC3339 UTC",
  "source": {
    "transport": "windows-local-mcp",
    "trust": "model_supplied"
  },
  "context": {
    "kind": "conversation_summary",
    "title": "optional title",
    "content": "text supplied by MCP client",
    "tags": ["optional"],
    "metadata": {}
  }
}
```

`source.trust = model_supplied` は security invariant です。WLMCP は、本文が本当に ChatGPT Memory 由来か、ユーザー明示発言か、会話要約か、model inference かを独立に検証できません。

caller が `metadata` 内で provenance を申告しても、それだけを根拠に WLMCP または receiver が `user_stated` / `user_approved` 等へ trust 昇格してはなりません。

## 6. 入力 bound

初期実装:

- canonical JSON request body: 既定 256 KiB、設定可能範囲 4 KiB..4 MiB。
- `kind`: 1..64 characters。
- `title`: optional、最大 512 characters。
- `tags`: 最大 32 個、各最大 128 characters。
- `metadata`: 最大 depth 4、最大 64 entries、string 最大 4096 characters、64-bit integer、finite float のみ。
- `idempotency_key`: optional、visible ASCII 1..128 characters。
- Bearer token: optional、ASCII、最大 8192 characters、whitespace/control character 不可。
- timeout: 1..60 秒。

個別 field bound より、最終 serialized body byte limit を authoritative とします。

## 7. HTTP transport policy

固定事項:

- method: `POST`。
- `Content-Type: application/json; charset=utf-8`。
- `Accept: application/json`。
- `Idempotency-Key` と `X-WLMCP-Export-ID` は WLMCP が設定。
- optional Bearer credential は `Authorization: Bearer ...` のみ。
- ambient Cookie、browser session、OS credential forwarding、generic proxy は使用しない。
- redirect を追従しない。
- 2xx のみ success。
- receiver response body を read、parse、model input 化しない。
- transport failure から shell/curl、Approved Host、Sandbox、別 endpoint へ fallback しない。

## 8. Audit と秘密情報

audit へ平文保存しないもの:

- exported `content`。
- `title` の本文。
- `tags` の本文。
- `metadata` の本文。
- Bearer token / Authorization header。
- caller-supplied `idempotency_key` の平文。
- receiver response body。
- endpoint path/query。

audit 可能なもの:

- operation/export ID。
- `kind`。
- content/title/tags/metadata/idempotency の size/hash。
- payload byte count / SHA-256。
- endpoint の scheme/host/port と endpoint SHA-256。
- HTTP status または bounded error class。
- success / failed / rejected。

MCP tool result には retry のため actual `idempotency_key` を返しますが、audit 側では hash のみ保持します。

## 9. 既存 security boundary への影響

Context Export Broker は次を追加しません。

- arbitrary code execution。
- child process generation。
- workspace mutation。
- arbitrary local file read。
- Approved Host authority。
- Codex Sandbox capability。
- Automatic Git capability。
- ADB capability。
- runtime tool argument からの arbitrary network destination。

`export_context` の直前に既存 control-plane health check を行い、Context Export sidecar の startup-bound identity も再検証します。

この機能の主要リスクは privilege escalation ではなく information disclosure / unintended export です。trusted operator が設定した sink へ本文が開示されること自体は意図された side effect です。

既存 Approved Host の LocalSystem authority separation、SYSTEM worker-owned Job、durable recovery/postflight latch、requester binding、control-plane tamper detection、Codex Sandbox live marker、Automatic Git live marker/WFP/Job boundary は変更しません。

## 10. Decision Deck 受信側の将来契約

Decision Deck の receiver は今回の WLMCP repository では実装しません。将来 Decision Deck 側で次を実装する前提です。

1. Context Export payload v1 専用 endpoint。
2. Bearer 等の receiver authentication。
3. `Idempotency-Key` / payload `idempotency_key` による retry deduplication。
4. 同一 idempotency key + 同一 payload は重複保存しない。
5. 同一 key + 異なる payload は conflict。
6. 受信内容はまず import/context inbox 等へ staging。
7. `model_supplied` context を受信しただけで Decision Deck の長期 Memory 正本へ確定しない。
8. Decision Deck の既存 Memory policy に従い、`user_stated`、`user_approved`、`external_source`、`inferred`、一時状態、会話 archive 等へ分類。
9. ChatGPT 内部 Memory を Decision Deck の正本と扱わないという `Decision-deck/docs/MEMORY.md` の方針を維持。
10. 他 model/provider へ再送する場合は Decision Deck 側の提供範囲・機密度 policy を別途適用。

これにより、将来 Decision Deck が Playwright で Web ChatGPT に要求を送り、ChatGPT が `export_context` を呼ぶ経路を作った場合でも、WLMCP は「要求を生成するブラウザ側」と「情報を受け取る Decision Deck 側」の間にある一方向の bounded export primitive に留まります。

## 11. 検証範囲

必須 regression:

- capability disabled / endpoint missing の fail-closed。
- URL validation と non-loopback insecure HTTP gate。
- trusted operator が任意 HTTPS endpoint を設定できること。
- tool argument に endpoint override が存在しないこと。
- redirect refusal。
- ambient proxy 非利用。
- Bearer header の固定注入と secret 非露出。
- response body 非利用。
- payload/field/metadata limits。
- payload schema v1。
- idempotency key generation / preservation。
- 2xx success / non-2xx failure。
- exported context と idempotency key が audit に平文で残らないこと。
- sidecar selection precedence。
- sidecar が runtime writable roots 内なら startup rejection。
- active sidecar 変更後の fail-closed。
- control-plane health failure 時に outbound side effect を開始しないこと。
- Windows production stdio route が sidecar 未設定時にも従来どおり起動すること。

Context Export は既存 command execution boundary を変更しないため、この追加だけを理由に Approved Host normal/abnormal/recovery の Windows live lifecycle や Automatic Git / Codex Sandbox の live verification を再実施する必要はありません。ただし WLMCP runtime source の変更自体によって既存 live evidence が runtime identity に binding されている場合、その既存 route の通常の stale-evidence policy に従います。

## 12. 非目標

初期実装では次を行いません。

- ChatGPT Web の Playwright 操作。
- ChatGPT Memory の直接列挙・dump。
- Decision Deck Memory 正本への直接 mutation。
- receiver discovery。
- model 指定 URL への送信。
- generic webhook / arbitrary HTTP client。
- file attachment / binary export。
- receiver response を次の model instruction として利用すること。

Playwright による Decision Deck -> ChatGPT Web の要求送信は別 capability です。Context Export Broker は ChatGPT -> WLMCP -> configured receiver の明示的な情報出口だけを担当します。
