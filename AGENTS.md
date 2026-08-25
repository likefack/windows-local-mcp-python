# Codex 作業指示

このリポジトリで Codex が Windows 上の調査・修正を行う場合は、次を守ってください。

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
