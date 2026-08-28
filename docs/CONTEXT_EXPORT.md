# Context Export Broker 要件

## 1. 目的

Windows Local MCP に、ChatGPT を含む MCP client が現在利用できる会話文脈、Memory 由来情報、作業状態、要約、判断材料その他のテキスト情報を、trusted operator が設定した外部受信先へ明示的に送り出すための bounded Broker primitive を追加する。

主用途は、Decision Deck が将来提供する受信 API へ ChatGPT 側の利用可能コンテキストを取り込み、Decision Deck 側の共通コンテキスト／Memory 層で再利用できるようにすることである。ただし WLMCP は Decision Deck 固有実装へ依存せず、同一の固定 payload 契約を受けられる任意の HTTP(S) endpoint を trusted operator が設定できるものとする。

この機能は ChatGPT の内部 Memory database、全会話履歴、非公開内部状態を WLMCP が直接読み出す機能ではない。MCP client が tool argument として明示的に渡した情報だけを export する。

## 2. Product capability

公開 MCP tool は `export_context` とする。

`export_context` は次を満たす。

- 本文 `content` を必須とする。
- 会話要約、Memory 由来情報、作業引き継ぎ、プロジェクト文脈、設定・好み、判断記録など用途を固定 enum に閉じず、bounded な `kind` 文字列で表現できる。
- 任意の短い `title`、bounded な `tags`、JSON-compatible な bounded metadata を添付できる。
- caller が retry 用 `idempotency_key` を指定でき、未指定時は WLMCP が生成する。
- WLMCP は export ごとに独立した `export_id`、作成時刻、payload schema version を付与する。
- tool argument に送信 URL、host、port、path、HTTP header、proxy、認証 token を含めない。
- operation が成功した場合は `export_id`、`idempotency_key`、HTTP status、送信 byte 数等の bounded receipt metadata のみを返す。受信側の任意 response body は model へ返さない。

## 3. 設定と宛先

送信先は trusted operator が WLMCP の設定ファイルで指定する。

予定する設定項目:

- `context_export_enabled`: 既定 `false`。false の場合 `export_context` は fail closed。
- `context_export_endpoint`: 固定 HTTP(S) endpoint。model/tool argument から変更できない。
- `context_export_bearer_token`: optional Bearer token。MCP result、session info、audit 本文へ出さない。
- `context_export_max_bytes`: serialized request body の上限。
- `context_export_timeout_seconds`: outbound request の短い timeout。
- `context_export_allow_insecure_http`: 既定 `false`。HTTPS と loopback HTTP は通常設定可能とし、loopback 以外の平文 HTTP を意図的に使用する場合だけ trusted operator が明示的に true とする。

`context_export_endpoint` は trusted configuration なので任意 host/path を設定可能とする。一方、次を禁止する。

- HTTP/HTTPS 以外の scheme。
- URL userinfo による credential 埋め込み。
- fragment。
- control character を含む URL。
- runtime tool argument による endpoint override。
- HTTP redirect の追従。
- ambient `HTTP_PROXY` / `HTTPS_PROXY` 等を利用した proxy 経由送信。

これにより、trusted operator は Decision Deck、localhost の開発 receiver、private cloud endpoint 等を選択できる一方、untrusted model input は送信先を拡張できない。

## 4. 送信 payload v1

受信側との最小 interoperability contract は次の概念構造とする。

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

`source.trust = model_supplied` は重要な境界である。WLMCP は、送られた本文が実際に ChatGPT Memory 由来か、ユーザー明示発言か、model inference かを独立に検証できない。caller が metadata で provenance を申告しても、それだけを根拠に WLMCP または receiver が `user_stated` / `user_approved` 等へ昇格させてはならない。

## 5. Decision Deck 受信側への要求

Decision Deck 側の受信基盤は今回の WLMCP 実装範囲外とするが、将来の実装は次を前提とする。

- Context Export payload を受け取る専用 endpoint を設ける。
- `Idempotency-Key` または payload の `idempotency_key` を使い、同一 key + 同一 payload の retry は重複保存しない。
- 同一 key が異なる payload に再利用された場合は conflict とする。
- WLMCP から受けた context を、受信しただけで Decision Deck の長期 Memory 正本へ直接確定保存しない。
- まず import/context inbox または同等の staging 概念として受け、Decision Deck の Memory policy に従って `user_stated`、`inferred`、一時状態、会話 archive 等へ分類する。
- ChatGPT 内部 Memory は Decision Deck の正本ではないという `docs/MEMORY.md` の現行方針を維持する。
- receiver が Bearer 認証を採用する場合、token はログ・エラー・UIへ露出しない。
- 受信本文を他 model/provider へ再送する場合は Decision Deck 側の機密度・提供範囲 policy を適用し、WLMCP export 成功を第三者提供への包括同意として扱わない。

## 6. セキュリティ境界

Context Export Broker は arbitrary code execution、workspace mutation、Approved Host、Codex Sandbox、Automatic Git、ADB の authorization を追加しない。

必須 invariant:

1. `export_context` は process を生成しない。
2. workspace file や任意 local file を tool argument の path から読まない。
3. workspace、`data_dir`、control-plane state を変更しない。
4. endpoint は startup 時に検証済みの trusted configuration からのみ得る。
5. outbound HTTP request の method、headers、content type は WLMCP が固定し、caller は変更できない。
6. ambient proxy を使用しない。
7. redirect を追従しない。
8. request body size、field lengths、list sizes、metadata depth/entry count を bounded にする。
9. timeout を bounded にする。
10. response body は bounded receipt 判定に不要であり、model へ返さない。
11. Bearer token と exported `content` 本文を audit record へ平文保存しない。
12. success/failure、endpoint の非機密な origin/path、payload byte 数、content hash、export/idempotency ID は監査可能にする。
13. export failure を理由に Sandbox、Approved Host、別 URL、shell/curl 等へ fallback しない。

この機能の主リスクは privilege escalation ではなく information disclosure / unintended export である。trusted operator が設定した endpoint は WLMCP の信頼境界外の sink であり、export した情報がその受信先へ開示されることは機能上の意図された side effect とする。

## 7. HTTP transport policy

- method は `POST` 固定。
- `Content-Type: application/json` 固定。
- `Accept: application/json` を送ってよいが、response body は trust しない。
- optional Bearer token は `Authorization: Bearer ...` 固定形式のみ。
- ambient Cookie、browser session、client certificate、OS credential forwarding は使用しない。
- OS / Python 標準 TLS verification を無効化しない。
- non-loopback HTTP は `context_export_allow_insecure_http=true` がない限り startup validation で拒否する。
- 2xx のみ success とし、それ以外は bounded error として fail closed。

## 8. 入力 bounds

初期既定値の目安:

- serialized payload: 256 KiB。
- `kind`: 1..64 characters。
- `title`: optional、最大 512 characters。
- `tags`: 最大 32 個、各最大 128 characters。
- `metadata`: JSON-compatible object、最大 depth 4、最大 64 entries、string value 最大 4096 characters。
- `idempotency_key`: optional、1..128 characters。制御文字を拒否する。
- timeout: 既定 10 秒、設定上限 60 秒。

serialized payload の byte limit を最終 authoritative bound とする。

## 9. Audit

既存 `_safe_request()` は `content` key の値を `{bytes, sha256}` へ置換するため、`export_context` の request/result audit はこの仕組みを利用する。

audit に保存してよい情報:

- operation/export/idempotency ID。
- kind/title/tags の bounded redacted form。
- content byte count / SHA-256。
- serialized payload byte count。
- configured endpoint の scheme/host/port/path/query の非 secret 表現。
- HTTP status または bounded error class。

保存してはならない情報:

- `content` 本文。
- Bearer token。
- Authorization header。
- receiver response body。

## 10. Verification scope

今回の変更は新しい bounded outbound Broker primitive であり、既存 command execution security boundary を変更しない。

必須 regression:

- capability disabled / endpoint missing の fail-closed。
- URL validation。
- non-loopback insecure HTTP gate。
- endpoint を tool argument で変更できないこと。
- redirect refusal。
- ambient proxy refusal。
- Bearer header の固定注入と audit 非露出。
- payload/field/metadata limits。
- exact serialized payload schema。
- idempotency key generation / preservation。
- 2xx success / non-2xx failure / timeout failure。
- response body が MCP result/audit に流入しないこと。
- `content` が audit では hash/size のみになること。
- `session_info` が configured/enabled/available を区別し、secret を返さないこと。

既存 Approved Host、Codex Sandbox、Automatic Git の Windows live verification marker/version、Job Object、LocalSystem authority separation、durable recovery、WFP policy は変更しない。これらの implementation path に触れない限り、Context Export 追加だけを理由に release-level Windows live lifecycle を再実施しない。

## 11. 非目標

初期実装では次を行わない。

- ChatGPT Web の Playwright 操作。
- ChatGPT Memory の直接列挙・dump。
- Decision Deck Memory 正本への直接 mutation。
- receiver discovery。
- model 指定 URL への送信。
- generic webhook client / arbitrary HTTP client。
- file attachment / binary export。
- receiver response を次の model instruction として利用すること。

Playwright による Decision Deck -> ChatGPT Web の要求送信は別 capability とし、この Context Export Broker はその逆方向の明示的な情報出口だけを担当する。
