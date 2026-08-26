# Codex 作業指示

このリポジトリで Codex が Windows 上の調査・修正を行う場合は、次を守ってください。

## ユーザーへの報告言語

- ユーザーへの進捗報告、調査結果、検証結果、判断理由、最終報告、残存リスクの説明は、原則として日本語で記述する。
- 一般的な概念や説明まで不必要に英語へ置き換えない。日本語で意味を正確に表現できる場合は、日本語を優先する。
- 英語表記をそのまま使用してよいのは、固有名詞、コード上の識別子、API・CLI・ファイル名・設定値、原文のエラーメッセージ、正式名称を保つ必要がある用語など、日本語化すると識別性または技術的精度を損なう場合に限る。
- 技術上必要な英語用語を使用する場合も、ユーザー向け報告では可能な限り日本語の説明を併記し、英語だけで意味を伝えない。
- リポジトリ内のコード、既存 API 名、プロトコル名、外部仕様の正式名称まで機械的に日本語化する趣旨ではない。この規則は主としてユーザーへの説明・報告の表現に適用する。

## プロダクト不変条件と機能維持

- セキュリティ修正は、明示されたプロダクト目的と中核機能を維持したまま成立させる。脆弱な経路を単に削除・無効化・恒久的に fail closed にすることで finding を `fixed` / `closed` と扱ってはならない。ただし trusted operator が、その具体的な capability reduction を明示的に承認した場合を除く。
- 特に Approved Host は optional な便宜機能ではない。Codex Sandbox または Broker では実行できないが、trusted operator が明示承認した処理を通常の Windows user authority で実行するための中核 fallback / escalation route である。この役割を失わせる変更は、セキュリティ上有利でも final remediation として採用しない。
- Approved Host の脆弱性を修正する際は、Approved Host 自体を停止するのではなく、承認、monitor / postflight、durable tamper state、process authority separation 等の根本原因を修正して、機能と security invariant の両方を成立させる。
- 現行 architecture では security invariant と Approved Host の機能維持を同時に満たせないと判断した場合、finding を未解決または blocked のまま報告し、必要な architecture change、選択肢、trade-off を trusted operator に提示する。ユーザー確認なしに capability reduction を final fix として commit / merge しない。
- 緊急の exploit containment として一時的な fail-closed を導入する場合は、`temporary mitigation` / `product regression` と明記し、finding の根本解決とは区別する。機能停止だけを根拠に release blocker を解除したり `closed` と記録したりしない。
- `SECURITY_CONTRACT.md`、`SPEC.md`、`VERIFICATION.md` その他の文書を、実装上の都合だけで capability reduction を正当化する方向へ書き換えない。中核 capability の削除・停止・意味的縮小を契約へ反映するには、その変更自体について trusted operator の明示承認が必要である。
- 2026-08-27 に WLMCP-R2-001 対応として行われた「Approved Host execution を current v1 で全面停止して finding を close する」方針は trusted operator により拒否された。この方針を precedent として再利用しない。詳細は `docs/APPROVED_HOST_PRODUCT_INVARIANT.md` を必ず読む。

## ドキュメントと実装仕様の整合性

- 実装作業を行う場合は、変更対象に関係する仕様書・設計資料・運用資料などのドキュメントを確認し、依頼された仕様および現行実装との整合性を確認する。
- ドキュメント、ユーザーから依頼された仕様、現行実装の間に矛盾・不一致・解釈上の衝突が見つかった場合、その差異を黙って解消したり、どれか一方を独断で正本として扱ったりしない。
- 矛盾を発見した場合は、該当するドキュメントの path、関連する実装箇所、矛盾している内容を具体的に報告し、ドキュメント側と実装仕様側のどちらを正として扱うべきかユーザーに確認する。
- ユーザーの回答を得るまでは、矛盾する部分について不可逆な実装変更やドキュメント改変を進めない。矛盾と無関係な調査・検証は継続してよい。
- ユーザーの判断によって既存ドキュメントの内容が置き換わる場合は、必要なドキュメント更新も同じ作業範囲に含め、実装とドキュメントを再び整合させる。

## Windows でのテキスト読み取り

- このリポジトリの Markdown、TOML、Python などのテキストファイルは UTF-8 として読む。
- PowerShell で日本語を含むファイルを読む場合、文字コードの自動判定に依存しない。
- `Get-Content` を使う場合は、原則として `Get-Content -Raw -Encoding UTF8 <path>` のように UTF-8 を明示する。
- 文字化けした出力を内容判断、差分判断、セキュリティ判断に使用しない。文字化けを検出した場合は、その出力を破棄して UTF-8 を明示して読み直す。
- Python で読む場合も `encoding="utf-8"` を明示する。

## Codex Security scan の `userContext`

- Windows 上で Codex Security scan を開始する場合、MCP へ渡す `userContext` は ASCII 文字だけで構成する。
- 日本語の依頼内容を省略・弱化せず、同じ要件を ASCII の英語要約へ変換して渡す。詳細は UTF-8 の `SECURITY_CONTRACT.md`、`WFP_GUARD_VALIDATION.md`、`VERIFICATION.md` など、対象の正本文書を相対 path で参照させる。
- `userContext` の文字数を減らす目的で security invariant、fail-closed 条件、禁止事項、検証範囲を落とさない。
- この回避策は Windows の Codex Security helper が標準入力を CP932 として読む場合の文字化けと単独 surrogate の生成を避けるためのものであり、repository の UTF-8 文書や通常の日本語応答を ASCII 化する指示ではない。
- Codex Security plugin の更新後は、現在インストールされている版の Windows launcher が `PYTHONIOENCODING=utf-8` を設定しているか確認する。更新でこのPC固有の修正が消えていた場合は、同じ設定を復元して Codex を再起動してから scan する。

## Codex skills の解決

- skill の絶対パスを過去の実行環境から推測して決め打ちしない。
- skill が必要な場合は、現在の実行環境で利用可能な skill root または skill resource を確認してから読む。
- 想定した skill path が存在しない場合、同じ誤った絶対パスを繰り返さず、現在の環境で利用可能な配置を解決する。
- 以前のタスクで有効だったローカルの skill path が、別タスクや別実行環境でも有効だと仮定しない。
- skill path の探索失敗は、リポジトリ本体の問題や対象機能の失敗として扱わない。

## 開発用一時出力

- 開発・テスト用の一時出力は、原則としてリポジトリルートの `.dev-tmp/` 配下に置く。
- pytest で明示的な `--basetemp` が必要な場合は `.dev-tmp/pytest/<purpose>` を使い、リポジトリルート直下へ新しい `.pytest-tmp-*` を作らない。
- 一時ファイルやキャッシュの整理を目的として ACL や owner を変更せず、`takeown` や `icacls` による権限取得を行わない。

## Windows Sandbox 実機検証

- Codex Desktop 自身の Sandbox 内から、さらに Codex Windows Sandbox を起動した入れ子実行の結果を、通常 Windows host 上の実機検証結果として扱わない。
- `CreateRestrictedToken failed: 87`、`Access is denied`、または Sandbox launcher 生成後に対象コマンドが開始されない場合は、まず入れ子 Sandbox や実行文脈の影響を疑う。
- 通常 Windows user 文脈での実機確認が必要で、現在の Codex 実行環境から直接確認できない場合は、ユーザーが通常の PowerShell から実行できる検証コマンドまたはスクリプトを提示する。
