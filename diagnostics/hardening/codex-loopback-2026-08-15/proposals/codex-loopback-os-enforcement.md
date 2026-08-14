# Security Hardening Proposal: Codex Sandbox localhost の OS 強制遮断

## Decision

いま決めるべきことは本実装ではなく、kernel driver なしの小さな user-mode WFP filter が、
この PC の `AppContainerLoopback` permit より先に hard block を確定できるかである。
私は、直接 WFP の一時 filter を最初の対照実験にすることを勧める。成功するまでは現行の fail-closed を維持する。

## Executive Recommendation

検討対象は次の3案である。

- Option 1: 現行 fail-closed と upstream 待ち
- Option 2: 独自 sublayer の直接 WFP hard block
- Option 3: localhost を明示的な残存 risk として受容し、補助防御だけを加える

Option 2 は最小の有望案だが、現時点では未実証である。まず動的セッションで成立性だけを測り、
成功した場合に限って production lifecycle を設計する。Option 3 は契約を弱めるため、技術的に軽いという理由だけでは選ばない。

## Evidence

| Evidence | Finding or document | What it establishes |
| --- | --- | --- |
| `E001` | WLMCP Security Contract | 未許可 localhost は必須遮断境界であり、失敗・未確認時は route unavailable である |
| `E004`／`E011` | 3世代・4通信種別の実通信 probe | parent／child／grandchild の TCP4／TCP6／UDP4／UDP6 が host listener へ到達した |
| `E009`／`E010` | Firewall／WFP state | Codex block と SID は存在するが、Filter 70511 が loopback flag だけで permit する |
| `E021` | ユーザー提示の 5156／5157 と無条件診断 block | 70511／70512 が permit 元で、Firewall block の条件削減でも結果が変わらない |
| `E012`／`E013` | OpenAI Codex upstream source | 現行実装は Windows Firewall COM を使い、代替の直接 WFP deny 設定を公開していない |
| `E014` | OpenAI Codex PR #22353 | setup は local policy が受理されるかを確認するが、実通信の遮断成立までは検証しない |
| `E016`／`E018` | Microsoft WFP arbitration | sublayer weight、filter weight、action right が最終 action を決める |
| `E017`／`E019`／`E020` | Microsoft WFP management | user-mode API、dynamic lifetime、管理者／BFE access right の要件 |

私はローカルの XML を再解析し、Filter 70511 が `ALE_AUTH_CONNECT_V4`、
`MPSSVC_APP_ISOLATION`、`FWP_ACTION_PERMIT`、filter weight `UINT64_MAX` で、条件が
`FWPM_CONDITION_FLAGS ALL_SET 1` だけであることを確認した。Filter 74502 は同じ layer の
`MPSSVC_WF` にあり、Sandbox SID、127/8、TCP、port を条件に `BLOCK` する。
この組合せと 5156 の FilterRTID は、SID／program／port の指定誤りではなく、異なる sublayer 間の裁定が中心であることを示す。

## Current Design And Failure Mode

### 観測済み

- Codex は `CodexSandboxOffline` 用に TCP／UDP loopback block と non-loopback outbound block を作る。
- WFP 内にも `ALE_AUTH_CONNECT_V4` の Codex block filter がある。
- ユーザー提示の実機観測では、user／program／port 条件を除いた診断用 Firewall block でも TCP4 localhost は通る。
- 同じ提示結果では、実通信時の 5156 は Filter 70511／70512 を permit 元として記録し、対象 PID の 5157 はない。
- Filter 70511 の条件は generic loopback flag だけであるため、名前が `AppContainerLoopback` でも
  Codex process が AppContainer かどうかだけでは回避できない。

### 最も有力な説明（推論）

Windows の App Isolation policy が loopback classification を `MPSSVC_APP_ISOLATION` で先に終端し、
`MPSSVC_WF` に変換された通常 Firewall block が最終 action を変更できない経路になっている。
Filter 70511 の `UINT64_MAX` はその sublayer 内の filter weight であり、別 sublayer より必ず先という意味ではない。
最終順序は sublayer weight が先に決める。

ここで断定を避けるべき点がある。現在の filter XML には sublayer object 自体の weight と、分類中に
引き継がれた `FWPS_RIGHT_ACTION_WRITE` がない。そのため、「70511 が hard permit だった」のか、
「より高い sublayer で終端し、Firewall sublayer が実効的に参加しなかった」のかは未確定である。
この違いは直接 WFP 案の成立条件を左右する。

### Windows Firewall 規則と直接 WFP の違い

`INetFwPolicy2`／`New-NetFirewallRule` は Windows Firewall policy を作り、MpsSvc が
`MPSSVC_WF` sublayer の WFP filter へ変換する。呼出側は任意の sublayer、sublayer weight、
filter weight、`FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT` を選べない。

`FwpmSubLayerAdd0`／`FwpmFilterAdd0` を直接使う案では、独自 sublayer とその重み、
`ALE_AUTH_CONNECT_V4/V6`、条件、action、action right を明示する。Microsoft の裁定規則では高い
sublayer weight が先に評価され、hard block は最終となる。したがって、独自 sublayer を
`MPSSVC_APP_ISOLATION` より厳密に高く置けるなら、70511 が評価される前に拒否できると考えられる。
逆に同順位以下なら確実性はなく、hard permit を後段から覆すには kernel callout の veto が必要になる。

## Desired Invariants

- `CodexSandboxOffline` token で動く process と descendant は、127/8 と ::1 の未許可 endpoint へ接続できない。
- host の通常 user、Android Emulator、開発サーバー、他の host application の localhost は遮断しない。
- security decision は argv、source 文字列、DNS 名の検査に依存しない。
- filter が有効であることではなく、TCP／UDP、IPv4／IPv6、3世代の実通信と drop event で成立を証明する。
- helper／WLMCP crash は実行中 Sandbox を残したまま fail open にしない。filter lease の喪失時は
  route を即時 unavailable にし、対象 Job を終了する。残留 state は限定され、検出・回収できる。
- Codex の SID、binary、setup generation、filter topology が変わったら過去の証拠を拒否する。

## Constraints And Non-Goals

- 独自 AppContainer sandbox、VM、HNS network namespace、kernel driver の新規開発は今回の非目標である。
- PC 全体の loopback block、Windows 所有 filter の削除、`MPSSVC_APP_ISOLATION` の改変は行わない。
- Codex の proxy port 例外と両立する設計は、WLMCP が offline／proxy ports なしを要求する現段階では非目標とする。
- current Windows user の完全侵害を防ぐ目的ではない。

## Before Architecture

[現状図](../diagrams/codex-loopback-os-enforcement-before.mmd)

現状では WLMCP が restricted network を要求しても、実際の loopback 強制は Codex が作る
Windows Firewall policy に依存する。実測上は App Isolation permit が host listener への経路を残している。

## Options

### Option 1: 現行 fail-closed と upstream 待ち

WLMCP の実装は変えず、`loopback` または `descendant_containment` が `failed`／`unverified` なら
Sandbox route を unavailable に保つ。OpenAI へ再現資料を提出し、Codex が正しい WFP policy と live verification を
持った版へ更新された後に再検証する。

[Option 1 の図](../diagrams/codex-loopback-os-enforcement-current-fail-closed-after.mmd)

| Change | Before | After | Security consequence | Cost |
| --- | --- | --- | --- | --- |
| route 判定 | localhost が通る backend を拒否 | 同じ | 境界を偽って利用しない | open-ended execution が利用不能 |
| policy owner | Codex Firewall | Codex Firewall／upstream | WLMCP の追加 TCB なし | 修正時期を制御できない |

この案は最も安全で保守しやすい一方、実用性を回復しない。upstream の current `firewall.rs` はなお
`INetFwPolicy2` を使い、2026-05-13 の PR #22353 も policy が受理されるかの確認に留まる。
したがって「更新を待てば近く直る」とは現時点で言えない。

### Option 2: 独自 sublayer の直接 WFP hard block

user-mode helper が WFP engine を dynamic session で開き、対象 PC の
`MPSSVC_APP_ISOLATION` より高い custom sublayer を作る。そこへ `ALE_AUTH_CONNECT_V4/V6` の filter を置き、
`ALE_USER_ID=CodexSandboxOffline` と `FWP_CONDITION_FLAG_IS_LOOPBACK` を条件に `FWP_ACTION_BLOCK`、
最高 filter weight、`FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT` を指定する。

[Option 2 の図](../diagrams/codex-loopback-os-enforcement-direct-wfp-after.mmd)

| Change | Before | After | Security consequence | Cost |
| --- | --- | --- | --- | --- |
| policy API | Windows Firewall COM | WFP management API | sublayer と action right を直接制御 | 管理者権限と native helper |
| scope | Sandbox SID だが Firewall sublayer | Sandbox SID＋loopback flag＋高優先 sublayer | host 通常 user を対象外にできる | 同じ offline SID の他 Codex session も一時影響 |
| lifetime | persistent Firewall rule | dynamic session | helper 終了／RPC rundown で自動削除 | helper lease と Sandbox Job の生存期間を結合 |
| descendant | 同じ SID の Firewall rule | 同じ SID の WFP filter | parent／child／grandchild を同じ OS 条件で拘束 | 別 SID へ移れる回帰がないか検証が必要 |

この案の魅力は、独自 sandbox を作らず、Windows が既に提供する ALE boundary を使えることにある。
フィルター条件は argv や executable path ではなく token の user SID なので、任意コードが socket API を直接呼んでも同じ分類を通る。
dynamic session は helper の異常終了時にも BFE の RPC rundown で object を削除するため、cleanup の基本機構も OS 側にある。

ただし、自動削除は cleanup には有利でも、それ単独では fail-closed ではない。helper が先に落ちて
Sandbox process が残れば、deny filter が消えた後も任意コードが動けるためである。production 化する場合は、
WLMCP が有効な helper lease を確認してからだけ Sandbox を起動し、lease handle／heartbeat の喪失時に
新規起動を止め、実行中の Sandbox Job 全体を終了する必要がある。PoC でもこの順序を検証対象にする。

一方、production 化には権限の扱いが残る。最小 PoC は一度だけ管理者起動した helper が filter を保持し、
通常 user の probe と handshake すればよい。本運用で毎回 UAC を出すのは現実的でない。
成功後は、(a) Codex upstream setup が persistent な SID 限定 hard block を所有する、
(b) 小さな承認済み管理 service が動的 lease を所有する、(c) 一度だけ BFE ACL を限定委任する、の順で検討する。
私はまず upstream 所有を優先する。WLMCP service は小規模でも新しい TCB と更新責任を増やすからである。

### Option 3: localhost を明示的な残存 risk にする

`SECURITY_CONTRACT.md` を明示承認のうえ変更し、localhost failure 単独では route を閉じない。
WLMCP は command preview の localhost 文字列、既知 proxy／開発 server、接続関連環境変数を検出して警告または追加承認を求める。
upstream 修正後は live verification を再実行し、必須境界へ戻す。

[Option 3 の図](../diagrams/codex-loopback-os-enforcement-residual-risk-after.mmd)

| Change | Before | After | Security consequence | Cost |
| --- | --- | --- | --- | --- |
| 契約 | localhost は必須 deny | accepted residual risk | host service 経由の権限迂回が残る | 実用性は戻る |
| 補助防御 | 実通信で fail closed | 文字列／環境／既知 endpoint 警告 | 単純事故は減らせる | socket 直接利用で迂回可能 |
| 復帰 | 不要 | upstream 修正を監視して再検証 | 将来の境界復帰を明示 | 継続的な追跡が必要 |

この案は実装量が最小だが、OS boundary の代替ではない。悪意ある project code は IP の整数表現、IPv6、
名前解決、直接 socket、既存 localhost client の起動で検査を回避できる。したがって、警告は usability guard であって
security control ではない。WLMCP の threat model では host localhost service が認証なし、弱い認証、または
ユーザー権限操作を公開している可能性を除外できないため、私は直接 WFP 実験が不成立と判明する前にこの案を選ばない。

## Comparison

| 観点 | Option 1: fail-closed | Option 2: 直接 WFP | Option 3: 残存 risk |
| --- | --- | --- | --- |
| OS レベル遮断 | route を使わないことで成立 | 条件付きで成立見込み、未実測 | 不成立 |
| child／grandchild | 実行しない | 同一 SID により継承見込み、要実測 | 不成立 |
| 管理者権限 | 不要 | PoC と setup に必要。本運用方式で変わる | 不要 |
| 実装量 | なし | PoC は小、本運用 lifecycle は小～中 | 小 |
| システム副作用 | なし | 同じ offline SID の他 Codex session に限定影響 | host service への攻撃面が残る |
| crash／recovery | fail closed | object は自動削除。lease 喪失時の Job 終了を加えて初めて fail closed | cleanup 不要だが fail open |
| Codex 更新追従 | upstream 待ち | SID／topology を live verification に結合 | 修正監視が必要 |
| 性能 | 実行不能 | ALE filter 2本の分類負荷。実測必要だが小さい見込み | 追加負荷ほぼなし |
| memory | 追加なし | helper／BFE object の小さな増加見込み | 追加なし |
| reliability | 安全だが利用不能 | helper／BFE／UAC lifecycle が増える | 利用可能だが security reliability が低い |

## Recommendation

現行制約では、Option 2 の成立性実験を選び、production 選択は保留することを勧める。
Option 2 が勝つ条件は、対象 PC で custom sublayer を App Isolation より厳密に先行させ、
追加 driver なしで 12 通信経路をすべて 5157／drop event 付きで拒否できることである。

その条件を満たせなければ Option 1 に戻る。App Isolation が最大 sublayer weight の hard permit を先に確定する場合、
user-mode filter では後段から veto できない。このとき driver callout、別 sandbox principal／AppContainer、VM は
今回の「小規模」制約を外れるため採用せず、軽量な OS レベル解決はないと判断する。

Option 3 が選択可能になるのは、open-ended execution の可用性を localhost 権限迂回 risk より優先し、
trusted operator が契約変更を明示受容した場合だけである。

## Evidence Coverage And Residual Risk

| Evidence | Option 1 | Option 2 | Option 3 |
| --- | --- | --- | --- |
| `E011` — 3世代・4通信種別の到達 | addresses（route拒否） | addresses 見込み、PoC 必須 | unaffected |
| `E010` — 70511 permit／74502 block | unaffected | addresses 見込み、sublayer 条件付き | unaffected |
| `E012` — Codex Firewall COM 実装 | mitigates（upstream 待ち） | mitigates（WLMCP 側または upstream で別 enforcement） | unaffected |
| `E001` — localhost 必須境界 | preserves | preserves | requires explicit contract change |

Option 2 が成功しても、同じ `CodexSandboxOffline` SID を使う他の Codex session への一時的影響、
proxy port 例外との競合、Codex が将来別 SID／online identity を使う drift は残る。filter の存在だけで verified にせず、
WLMCP の既存 live markerへ provider key、sublayer key／weight、filter key／ID、SID、helper identity と12経路の結果を結合する必要がある。

## Migration And Rollout

本段階では migration を開始しない。PoC が成功した場合も、次の順で進める。

- dynamic session の実験結果と crash cleanup を保存する。
- upstream issue に最小再現、70511／70512、sublayer weight、drop event を添付する。
- upstream ownership が得られない場合だけ、WLMCP 用の小さな lifecycle owner を設計する。
- canary release では同時 Codex session、Android Emulator、開発 server、proxy 無しの host control を確認する。
- filter または helper identity が変われば route を fail closed に戻す。

rollback は dynamic session を閉じるだけにする。PoC では persistent flag、Windows Firewall rule の変更、
Windows 所有 filter の削除を禁止する。

## Validation Plan

### Phase A: 変更なしの read-only 確認

- `FwpmSubLayerGetByKey0` または完全な `netsh wfp show state` で
  `FWPM_SUBLAYER_MPSSVC_APP_ISOLATION` と `FWPM_SUBLAYER_MPSSVC_WF` の sublayer weight を保存する。
- Filter 70511／70512 の flags、provider context、runtime action-right 関連情報を保存する。
- App Isolation weight が `UINT16_MAX` で、厳密に高い custom sublayer を作れない場合は Phase B を中止する。

### Phase B: 最小対照実験

- 管理者 helper は `FWPM_SESSION_FLAG_DYNAMIC` で engine を開く。
- transaction 内で一意な provider／sublayer を作り、sublayer weight を App Isolation より厳密に高くする。
- V4／V6 の `ALE_AUTH_CONNECT` に、`CodexSandboxOffline` SID＋loopback flag の hard block を1本ずつ置く。
- helper は ready event を通知して engine handle を保持する。通常 user の PowerShell から既存 probe を実行する。
- baseline（filterなし）と candidate（filterあり）で同一 port／listener 手順を使う。

成功条件は次のすべてである。

- parent／child／grandchild × TCP4／TCP6／UDP4／UDP6 の12経路で host token を1件も受信しない。
- 12経路それぞれが対象 custom filter ID の 5157 または同等の WFP classify-drop event を持つ。
- 同時刻に host 通常 user の4経路は成功する。
- Sandbox の Internet deny、Job Object containment、timeout／descendant cleanup は退行しない。
- helper を正常終了して filter／sublayer が消える。
- 実行中 Sandbox がある状態で helper を強制終了すると、新規 Sandbox 起動が拒否され、対象 Job が終了する。
- その後、BFE RPC rundown で object が消え、通常 host 接続は維持される。
- candidate 実行後に persistent WFP／Firewall／registry state が増えていない。

### Phase C: production 選択のための測定

- 1000回の短い localhost 接続で baseline と filter 有効時の p50／p95 latency と CPU を比較する。
- 同じ offline SID の別 Codex session が受ける影響を測る。
- WLMCP crash、helper crash、BFE restart、Windows restart、Codex update、SID 再作成を試す。
- live marker が stale SID／filter topology／helper hash を拒否することを確認する。
- helper lease 喪失から対象 Job 終了までの時間を測り、その間に localhost 接続が成立しないことを確認する。

## Implementation Work Packages

未選択のため実装計画ではなく、成立性確認に必要な作業単位だけを示す。

- WFP sublayer／filter の read-only collector 拡張
- dynamic session PoC helper
- 既存 loopback probe との ready／done handshake
- 5157／netevent と filter ID の相関検証
- crash cleanup と host 非影響の対照試験
- upstream issue 用の再現資料整理

## Open Questions

- 対象 Windows build の `MPSSVC_APP_ISOLATION` sublayer weight はいくつか。
- Filter 70511／70512 は runtime で action right を保持するか、hard permit になるか。
- 最高 custom sublayer の hard block は 70511／70512 より先に終端するか。
- BFE ACL の限定委任は、管理 service より小さく、かつ host user authority の前提内で安全か。
- Codex upstream は Windows Firewall COM を直接 WFP policy へ変更する意向があるか。
