# Security Hardening Review: Codex Windows Sandbox localhost 遮断

## Evidence Basis

現行リポジトリ `e28bf9538ce0f350f01eb4f543e8480e36af0b7a`、通常 Windows user 文脈の
実通信結果、WFP filter dump、OpenAI Codex upstream、Microsoft WFP 一次資料を確認した。
詳細な証拠台帳は [context.md](context.md)、技術的な判断過程は
[提案書](proposals/codex-loopback-os-enforcement.md) にまとめている。

実測済みなのは、通常の Windows Firewall block が存在しても、Sandbox の parent／child／grandchild から
IPv4／IPv6、TCP／UDP の localhost 通信が到達し、許可イベントが
`AppContainerLoopback` Filter 70511／70512 を指したことまでである。独自 WFP filter の遮断効果はまだ未実測である。

## Constraints

- open-ended execution は OpenAI Codex Windows Sandbox へ委譲する。
- 独自 AppContainer、独自仮想化、カーネル callout driver は最後の手段とする。
- host 全体や通常 user の localhost は遮断しない。
- child／grandchild を含めて OS レベルで遮断する。
- crash 後に fail open せず、安全に回収できることを必要とする。
- 現行契約では localhost が `failed`／`unverified` の間、Sandbox route は unavailable のままとする。

## Opportunity Portfolio

| Opportunity | Evidence | Options | Recommendation | Proposal |
| --- | --- | --- | --- | --- |
| Codex offline principal の loopback を WFP の正しい裁定位置で遮断する | 3世代・4通信種別の到達、Filter 70511／70512、Codex の `INetFwPolicy2` 実装 | 1. 現行 fail-closed、2. 直接 WFP、3. 残存 risk 化 | Option 2 の動的 filter 対照実験だけを先に行い、成功するまで Option 1 を維持する | [詳細](proposals/codex-loopback-os-enforcement.md) |

## Recommendation Summary

最も小さい有望案は、管理者として開いた user-mode の WFP dynamic session に、
`FWPM_SUBLAYER_MPSSVC_APP_ISOLATION` より厳密に高い重みの独自 sublayer と、
`CodexSandboxOffline` SID＋loopback flag を条件にした `ALE_AUTH_CONNECT_V4/V6` hard block を置く対照実験である。
これは Windows Firewall 規則の追加とは異なり、sublayer と action right を明示的に選べる。
動的 filter を本運用へ使う場合は、helper lease の喪失時に実行中 Sandbox Job を終了する結合も必須であり、
WFP object の自動削除だけでは fail-closed にならない。

ただし、対象 PC の App Isolation sublayer weight と runtime action right をまだ取得していない。
独自 sublayer を厳密に先行させられない場合、user-mode static filter だけで確実に拒否できるとは言えず、
kernel callout veto、別 principal／AppContainer、仮想化のいずれかが必要になる。その場合は軽量解決不能と判定し、
upstream 修正を待つ間は現行 fail-closed を維持するのが最も安全である。

## Next Decisions

- まず read-only で `MPSSVC_APP_ISOLATION` sublayer weight と Filter 70511／70512 の action-right 関連情報を取る。
- 条件が満たせる場合だけ、persistent flag を使わない一時 filter の対照実験を行う。
- 成功後に、WLMCP が lifecycle を持つか、Codex upstream へ修正を寄せるかを選ぶ。
- 実験が不成立なら、localhost の残存 risk 化は契約変更として別途明示承認を受ける。
