# 調査コンテキスト: Codex Windows Sandbox の localhost 遮断

## 対象

- リポジトリ: `C:\dev\windows-local-mcp-python`
- 対象リビジョン: `e28bf9538ce0f350f01eb4f543e8480e36af0b7a`
- 調査開始時の作業ツリー: 変更なし
- 証拠収集日: 2026-08-15
- ローカル証拠コレクション SHA-256:
  `5233a6ab221bdda9363f6238298c6c802c4d528f2d6c4738c103f7069edee706`
- source drift: `unknown`
  - リポジトリは上記リビジョンへ固定した。
  - OpenAI Codex upstream は 2026-08-14 の `main` 先頭（短縮 SHA `8630bb3`）を閲覧したが、
    ローカルへ固定チェックアウトしていない。

## ローカル証拠

| ID | 証拠 | SHA-256 | 用途 |
| --- | --- | --- | --- |
| `E001` | `SECURITY_CONTRACT.md` | `76d9f02964bda5833a8bfff8a5fcd860b0a9720c7657bbff905546559534091f` | localhost が必須遮断境界で、未確認時は fail closed であること |
| `E002` | `VERIFICATION.md` | `41afb8a726ca056550f6abbc2f73d522c0cf820dfac904847e9ca623b791b6ed` | 通常 Windows user 文脈の既存実機結果と検証限界 |
| `E003` | `diagnostics/CODEX_LOOPBACK_DIAGNOSTICS.md` | `ba0ff10d56499a5db19ead88d366f774bf1e2ef200ffab4dc41598e7558427af` | 診断の判定基準 |
| `E004` | `diagnostics/Invoke-CodexLoopbackProbe.ps1` | `8a2a888fb76361aacf57a4001345fa9e589e761e6116f94f67429cb02a8e9463` | parent／child／grandchild、IPv4／IPv6、TCP／UDP の実通信手順 |
| `E005` | `diagnostics/Collect-CodexWfpState.Admin.ps1` | `e09d326cb9e7bae44feb8ae142635e97a3e6dd47c764a0f1c66276b9fc38dcc3` | WFP filter と netevent の読取手順 |
| `E006` | `src/windows_local_mcp/sandbox_backend.py` | `f14dbe8d3fc1064c642be541ac5e912fa898bb774b159334ce09c8cf7ca3cfeb` | Codex Sandbox 起動、network restricted、backend identity 結合 |
| `E007` | `src/windows_local_mcp/sandbox_live_verify.py` | `bce8e20f369b16a22d3015e7abfd6e20b2cb357512df1d21c5ca02a3c2ae6c09` | localhost 実通信の property 判定 |
| `E008` | `tests/test_sandbox_architecture.py` | `b541f6a3fad8fccf78faa4532b1e46ce8e23bb36bbaa82dbad6fa714b7ce3566` | marker、fail-closed、Job Object の回帰範囲 |
| `E009` | `C:\Users\22905\AppData\Local\Temp\codex-wfp-state-20260814-174758\summary.json` | `62b3647c1997109e871bd63eae54c7a40cd3a6e525e2d738f816d598aca0727f` | Sandbox SID と Codex Firewall ActiveStore の一致 |
| `E010` | `C:\Users\22905\AppData\Local\Temp\codex-wfp-state-20260814-174758\filters-tcp4-loopback.xml` | `ef24ded931a9fe1483a0e9a6d4f590fac1e69f4dace9c593e724142d8489ec73` | Filter 70511 と 74502 の WFP 内部表現 |
| `E011` | `C:\Users\22905\AppData\Local\Temp\codex-loopback-probe-20260814-231638.json` | `32e646c28bdedf9427cb4dc12ef77c5eed432149d56bf5083bb0d914b261599d` | 4通信種別が3世代すべてから host listener へ到達した証拠 |

ユーザーが今回提示した追加の実機観測を `E021` とする。内容は、5156 の FilterRTID が IPv4 で
70511、IPv6 で 70512 を指したこと、対象 PID の 5157 がなかったこと、および user／program／port 条件を
除いた診断用 TCP4 block（Filter 75081）でも到達したことである。これは通常 user 文脈の実測として扱うが、
元の EVTX／XML は今回の作業環境から再取得していないため、再解析済みローカル artifact とは区別する。

## 外部一次資料

| ID | 資料 | 用途 |
| --- | --- | --- |
| `E012` | [OpenAI Codex `firewall.rs`](https://github.com/openai/codex/blob/main/codex-rs/windows-sandbox-rs/src/bin/setup_main/win/firewall.rs) | 現行 upstream が `INetFwPolicy2` で loopback 規則を作ること |
| `E013` | [OpenAI Codex `setup.rs`](https://github.com/openai/codex/blob/main/codex-rs/windows-sandbox-rs/src/setup.rs) | offline identity、proxy port、`allow_local_binding` の現行入力 |
| `E014` | [OpenAI Codex PR #22353](https://github.com/openai/codex/pull/22353) | LocalPolicyModifyState の確認であり、実通信強制の検証ではないこと |
| `E015` | [OpenAI 公式 Windows sandbox 文書](https://learn.chatgpt.com/docs/windows/windows-sandbox) | elevated sandbox が dedicated user と Firewall 規則を使う現行説明 |
| `E016` | [Microsoft: Filter Arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration) | sublayer、action right、hard permit／hard block、callout veto の裁定規則 |
| `E017` | [Microsoft: Object Management](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management) | dynamic session 終了時の WFP object 自動削除 |
| `E018` | [Microsoft: FWPS_FILTER](https://learn.microsoft.com/en-us/windows/win32/api/fwpstypes/ns-fwpstypes-fwps_filter3) | sublayer weight が高い filter から呼ばれること |
| `E019` | [Microsoft: FwpmSubLayerAdd0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmsublayeradd0) | user-mode 管理 API と必要な access right |
| `E020` | [Microsoft: WFP Access Control](https://learn.microsoft.com/en-us/windows/win32/fwp/access-control) | BFE object の access control と既定の管理者権限 |

## 実測と未実測の境界

この調査では、2026-08-14 に通常 Windows user 文脈で取得済みのローカル JSON／XML を再読し、
リポジトリの現行コードと upstream／Microsoft の一次資料を確認した。現在の Codex Desktop 内 Sandbox
から別の Codex Sandbox を起動する入れ子検証は、host 実機証拠として実施していない。

独自 WFP sublayer／filter はまだ追加していない。したがって、直接 WFP 案は source-derived な有望案であり、
この時点では measured な解決ではない。
