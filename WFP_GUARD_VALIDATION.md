# WFP Guard セキュリティ検証記録 — Phase A から C7

更新日: 2026-08-20

この文書は、Codex Windows Sandbox から Windows ホストの localhost へ到達できていた問題について、調査開始から WLMCP の production WFP Guard へ統合し、異常終了試験 C6.4 と identity binding C7 までの経緯を、後から再検証できる形で残すための記録である。

`VERIFICATION.md` がリポジトリ全体の検証履歴を扱うのに対し、この文書は localhost / WFP Guard 系列だけを詳細に追う。

この文書では、public repository に不要な端末固有情報を増やさないため、実機 SID、PID、ユーザー名、ローカル絶対パス、runtime filter ID などの生値は原則として記載しない。必要な事実は、役割・状態・結果で記録する。

---

## 1. 問題の出発点

Codex Windows Sandbox は専用の低権限 Windows account を使い、network restriction も要求していたが、実機試験では Sandbox の parent / child / grandchild から Windows ホストの localhost listener へ接続できた。

重要なのは、当時すでに Codex 側の Firewall / WFP 関連設定や block rule が存在していた点である。設定や rule の存在だけでは実効境界の証拠にならなかった。

したがって、WLMCP 側では次の原則を採用した。

1. 設定値や registry の存在ではなく、実際の WFP object と実通信で判断する。
2. WLMCP 全体を管理者権限で動かさない。
3. 任意の Firewall / WFP 操作 API を WLMCP に公開しない。
4. localhost だけを、小さく固定された direct WFP Guard で補う。
5. Guard の成立を read-back できない場合は Codex Sandbox を起動しない。
6. Guard 失敗から Approved Host へ自動 fallback しない。

最終的な設計は、open-ended execution の隔離を Codex Windows Sandbox に任せ、localhost 境界だけを WLMCP の direct WFP Guard で補強する構成である。

---

## 2. 用語

### WFP

Windows Filtering Platform。Windows の低レベル通信フィルタ機構。

### Guard

WLMCP が持つ、Codex Sandbox 用 localhost BLOCK の作成・確認だけを担当する小さな特権 helper。

### WFP read-back

「作成 API が成功した」という戻り値だけを信用せず、実際に WFP object を読み直し、security-relevant field が期待値と一致することを確認する処理。

### static non-persistent WFP object

作成 process が終了しても残るが、persistent flag を使って恒久保存はしない WFP object。この方式を C1 で採用した。

### fail closed

安全境界を確認できないときに実行を続けず、operation を失敗させること。

---

# Phase A — 現状 WFP の read-only 調査

## 3. 目的

Phase A では WFP を変更せず、localhost に関係する既存 filter / sublayer の実体と優先関係を確認した。

調べた中心は次である。

- Codex Sandbox の既存 AppContainerLoopback PERMIT
- その filter が属する App Isolation sublayer
- Windows Firewall 側の関連 sublayer
- より高い優先順位の独自 sublayer を置けるか
- 対象 Sandbox account が実機に存在するか

## 4. 調査方法

初期 collector の後、より限定した read-only collector を使った。

全 WFP state を無差別に dump するのではなく、対象 runtime filter を読み、その identity が期待する `AppContainerLoopback` / `FWP_ACTION_PERMIT` であることを確認してから sublayer を追跡した。

Phase A の collector は WFP / Firewall / registry / service の変更を行わない設計とし、runtime filter ID だけを security identity として信用しないようにした。runtime ID は reboot や BFE policy refresh で変わり得るためである。

## 5. Phase A で分かったこと

実機では、AppContainerLoopback PERMIT が App Isolation sublayer 上に存在し、その sublayer より高い数値 weight を持つ独自 sublayer を作る余地があった。

ただし、この時点の判定は意図的に `CANDIDATE_ONLY` とした。

理由は、static policy metadata だけでは live classify 時の最終 arbitration を証明できず、「高い weight の BLOCK を置けば勝つはず」という推論だけで production boundary とするべきではなかったためである。

Phase A の結論は次である。

> direct user-mode WFP block は有力候補だが、実通信試験を通るまでは安全性を主張しない。

---

# Phase B — direct WFP BLOCK の実通信検証

## 6. 目的

Phase B では、Phase A の候補が本当に localhost traffic を止めるかを、実際の Codex Sandbox process tree から確認した。

対象は parent / child / grandchild の 3 世代とし、それぞれについて次を試した。

- TCP IPv4 loopback
- TCP IPv6 loopback
- UDP IPv4 loopback
- UDP IPv6 loopback

合計 12 経路である。

## 7. 実験 policy

最終的に有効だった direct WFP block の基本形は次である。

- layer: `ALE_AUTH_CONNECT_V4` / `ALE_AUTH_CONNECT_V6`
- target identity: Codex Sandbox 用 local user
- condition: loopback
- action: BLOCK
- sublayer: App Isolation より高い WLMCP 固定 sublayer

この段階では寿命方式を検討するため、まず dynamic WFP session も用いた。

## 8. 中間失敗も fail closed として扱った

Phase B の途中では、一時 sublayer の追加 API 自体は成功したが、その直後の read-back verification が期待値と一致せず試験を停止した run がある。

その run では、dynamic session を閉じた後に一時 sublayer が消失したことまで確認した。

この失敗を「WFP が効かなかった」とは分類していない。正確には「作成後の read-back を信頼できなかったため、その run を証拠に採用しなかった」である。

## 9. 最終実通信結果

WFP BLOCK なしの control では Sandbox parent / child / grandchild の loopback 経路が到達可能だった。

最終 direct WFP BLOCK 適用後は、対象 12 経路すべてで localhost 到達を遮断できた。

同時に、通常 Windows user からの localhost 通信は正常のままであることも確認した。

Phase B の結論は次である。

> user-mode WFP API だけで、通常 user を巻き込まず、Codex Sandbox 用 user の loopback 接続だけを実際に遮断できる。

---

# C1 — Guard crash 時にも BLOCK が残る寿命方式

## 10. dynamic session の問題

Phase B で通信遮断自体は成立したが、dynamic WFP session を production boundary にすると次の危険がある。

```text
Guard process crash
↓
dynamic session close
↓
WFP block disappears
↓
Sandbox process remains alive
↓
localhost becomes reachable
```

この状態は許容できない。

## 11. 採用した方式

C1 では WFP object の寿命を `static non-persistent` とした。

期待する性質は次である。

- Guard process が正常終了しても BLOCK が残る
- Guard process が強制終了しても BLOCK が残る
- Sandbox operation 終了時に BLOCK を削除しない
- WFP persistent flag は使わない
- runtime を dynamic session の寿命に結び付けない

## 12. C1A / C1B

### C1A: creator 正常終了

Guard creator の正常終了後も sublayer と V4/V6 block filter が残り、Sandbox localhost の遮断が維持されることを確認した。

### C1B: creator 強制終了

creator を強制終了しても同じ BLOCK が残ることを確認した。

通常 user の localhost は両ケースとも維持された。

C1 の結論は次である。

> Guard の process lifetime と security boundary を切り離し、Guard crash が localhost 再開の trigger にならないようにする。

---

# C2 — 実験 policy の production WFP Guard 化

## 13. 初回 production 統合

基礎実装は次の commit で入った。

- `55bfb66d508ce6a8880345b6db22373ee38b864a`
- `feat(security): Codex Sandbox起動前にdirect WFP Guardを必須化`

主要実装は次である。

- `src/windows_local_mcp/wfp_guard.py`
- `src/windows_local_mcp/windows_wfp.py`
- `src/windows_local_mcp/wfp_guard_runtime.py`

Guard は任意 WFP editor ではなく、固定された Codex loopback policy だけを扱う。

現在の policy は、固定された Guard version / policy generation / sublayer key / V4 filter key / V6 filter key / layer / action / condition を read-back して一致を要求する。

## 14. fixed policy と read-back

`wfp_guard.py` は、既存 object がある場合に「key が同じだから使う」のではなく、security-relevant field を検証する。

主な検証対象は次である。

- App Isolation sublayer identity
- Guard sublayer identity
- Guard sublayer weight
- V4/V6 layer identity
- Guard sublayer への所属
- BLOCK action
- target user condition
- loopback condition
- runtime filter が実在すること

部分的に壊れた state を無条件で修復することもしない。たとえば Guard sublayer がないのに Guard filter だけ存在するなど、予期しない不整合では fail closed する。

runtime 用 ensure と、明示的 maintenance cleanup は分離した。通常 Sandbox 終了時に cleanup は呼ばない。

---

## 15. C2 review で見つかった blocker 1 — UAC 越しの auth key

初回実装の review では、通常権限 process から UAC `runas` で起動する elevated Guard へ、一時環境変数で認証情報を渡す設計に問題があると判断した。

UAC elevation 後の process へその caller-local environment を安全な transport として扱うべきではない。

したがって C2 は最初の実装時点では完了扱いにしなかった。

## 16. blocker 2 — Sandbox account の SID 解決

`CodexSandboxOffline` という単純名だけの解決も security identity として弱かった。

修正後は、Windows の物理 NetBIOS computer name を取得し、

```text
COMPUTER_NAME\CodexSandboxOffline
```

の完全修飾名として `LookupAccountNameW` に渡す。

さらに次をすべて要求する。

- returned domain が物理 NetBIOS computer name と一致
- `SID_NAME_USE == SidTypeUser (1)`
- 解決された SID が Guard operator 自身の SID と異なる
- SID 文字列表現が妥当

不一致時は fail closed する。

この hardening は次の commit に含まれる。

- `77ec908fed542c51e7a6b723f1978cca1bdd1964`
- `fix(security): CodexSandboxOfflineのローカルユーザーSID解決を厳密化`
- `fix(wfp): UAC越しのGuard IPCをプロセスIDへ結合する`

---

## 17. UAC / IPC の最終構造

production Guard の elevation path は概ね次である。

```text
unelevated WLMCP
↓
Windows named pipe listener
↓
ShellExecuteExW("runas")
↓
UAC
↓
elevated wfp_guard_runtime
↓
named pipe connection
↓
peer process identity verification
↓
proceed token
↓
WFP ensure/read-back
↓
verification payload
```

Python venv では `venv\Scripts\python.exe` launcher と base Python process が分かれる場合があるため、単に runas が返した PID だけを信頼しない。

最終的には、named pipe client が期待する venv launcher 自身、またはその launcher から直接生成された期待する base Python process であることを executable path / ancestry で確認するようにした。

関連 commit:

- `dbf5952b77a248722b4f91b938015ca3302bac2a`
- `fix(security): WFP Guard IPCの子プロセス実体を検証する`

UAC / IPC を実際に通す integration diagnostic も追加した。

- `991ed4e8bd096cf7676b065f1f1a27ad590b7166`
- `test(security): WFP Guard UAC一気通貫integration診断を追加`

診断証跡の表現が実際に証明した内容より強くならないよう、後続 commit でラベルも修正した。

---

# C3 — Guard verification と Sandbox launch ordering

## 18. C3 の security property

C3 の目的は単純である。

> `wfp_guard_verified` が成立する前に Sandbox child を 1 process も起動しない。

現在の worker は、Sandbox policy と runtime storage を準備した後、`guard_and_launch_codex_sandbox(...)` を呼び、Guard verification callback が成功して初めて child launch へ進む。

大まかな順序は次である。

```text
worker start
↓
approval bundle re-verification
↓
backend / executable hold
↓
sandbox_policy_prepared
↓
runtime storage preflight
↓
WFP Guard ensure/read-back
↓
wfp_guard_verified
↓
Sandbox child launch
↓
child_started
```

## 19. Guard failure 時

Guard path が `ApprovedSandboxUnavailable` を返すと、worker は次を記録する。

- `network_policy.wfp_guard_status = verification_failed`
- event `wfp_guard_verification_failed`
- payload `host_fallback = false`

その後 operation を失敗させる。

つまり、

```text
Guard verification failed
↓
Sandbox child not launched
↓
Approved Host fallback not performed
```

が contract である。

## 20. WFP より前の preflight failure

C6.4 準備中、staging tree に NTFS alternate data stream が含まれた run が runtime storage preflight で拒否された。

この場合、event は `runtime_storage_preflight_failed` で止まり、WFP Guard まで到達しない。

これは WFP failure ではなく、別の fail-closed security boundary が先に働いた正常な挙動である。

同様に、非常に深い staging tree で `WinError 206` が起きた run もあった。これは security bypass ではないが、approval staging robustness の別改善候補として扱う。

---

# C4 — 通常 WLMCP route / audit への統合

## 21. audit へ残す情報

WFP Guard の結果は Sandbox launch の一時的な内部状態ではなく、operation の audit evidence に含める。

正常時には `wfp_guard_verified` を記録し、network policy の `wfp_guard_status` を `verified_before_launch` に更新する。

verification payload には少なくとも次の policy identity が含まれる。

- Guard version
- Guard policy generation
- target account / SID
- App Isolation sublayer identity / weight
- WLMCP Guard sublayer identity / weight
- V4/V6 filter identity / runtime ID / effective weight
- static non-persistent / non-dynamic / non-persistent state

失敗時には `wfp_guard_verification_failed` を残す。

## 22. Sandbox 終了時に WFP を消さない

C1 の設計に従い、正常 Sandbox 終了時にも Guard cleanup は呼ばない。

cleanup は明示的な maintenance operation として分離し、対象 object の identity を read-back して完全一致したものだけを削除する。

これにより Sandbox A の終了が Sandbox B の localhost protection を解除する、といった lifecycle race を避ける。

---

# C4.5 — 実 WLMCP worker → 実 Codex Sandbox smoke test

## 23. 目的

C4.5 は単独 WFP diagnostic ではなく、実際の WLMCP worker から real Codex Windows Sandbox を起動する一気通貫 test とした。

確認経路は次である。

```text
WLMCP approval
↓
worker
↓
Guard
↓
UAC / read-back
↓
real Codex Sandbox
↓
localhost test
↓
audit result
```

## 24. 結果と注意点

localhost / WFP Guard 系列については production route で遮断が成立し、C5 へ進める状態になった。

一方、同時期の full live verification では filesystem / protected-information など WFP 以外の property に別問題も観測された。

そのため C4.5 の PASS は「Codex Sandbox の全 property が完全に verified」という意味ではない。

この project では property ごとの verification を分離し、未確認 property をまとめて `verified` と表示しない。

---

# C5 — 並行実行 / 二重 ensure / lifecycle race

## 25. 目的

static non-persistent BLOCK を複数 Sandbox が共有する構造なので、次を確認した。

- Sandbox A 単独
- A + B 同時実行
- A 終了後も B 継続
- 実行中に C を追加
- 複数 worker から同時 Guard verification
- ensure の重複

合格条件は次である。

1. Sandbox 数にかかわらず localhost BLOCK が維持される。
2. Guard object が壊れない。
3. 通常 Windows user の localhost を壊さない。

## 26. 実機 concurrent smoke

C5-A / C5-B / C5-C の 3 operation を異なる hold time で重ねて起動した。

すべて `codex_sandbox` route を使用し、approval 表示上も direct WFP Guard が network enforcement に含まれていた。

3 operation は実際に重複して `Running` となり、その後すべて `succeeded` で終了した。

C5 の結論は次である。

> 固定 WFP object を operation ごとに削除しない設計により、複数 Sandbox の overlap 中も Guard state を維持できる。

---

# C6 — crash / force-kill 系列

## 27. C6 の目的

C6 は正常終了ではなく、execution chain の一部が突然死んだ場合に unsafe state が生じないことを確認する段階である。

最重要禁止状態は次である。

```text
Codex-related process remains alive
+
localhost becomes reachable
```

一方、

```text
Codex process dies
+
WFP BLOCK remains
```

は過剰に閉じるだけなので安全側として許容する。

試験対象は worker / launcher / payload / elevated Guard helper を含む。

---

## 28. C6.1 — WLMCP worker crash

worker を途中で終了させる試験を行った。

初期 run には kill target / timing が不十分なものもあり、それらは証拠から除外した。

最終的には、worker crash が WFP BLOCK の削除 trigger にならないことを確認した。C1 で Guard object の lifetime を worker と分離しているため、worker が死んでも localhost protection は worker lifetime に連動して消えない。

stale audit state / process identity の扱いも、この系列の試験で再確認した。

---

## 29. C6.2 — Codex launcher crash

Codex launcher を execution 中に終了させた。

期待値は success ではなく、operation が安全側で失敗し、Host fallback を行わず、固定 WFP BLOCK が残ることである。

launcher crash が localhost を再開する経路にはならなかった。

---

## 30. C6.3 — Sandbox payload crash と worker identity hardening

payload crash 系列では、payload kill 後に Sandbox 関連 process / filesystem accounting が完全に期待どおり回収できず、

```text
sandbox filesystem write accounting became unavailable
```

として fail closed に入った run があった。

これは localhost が開いた証拠ではない。operation は失敗となり、Host fallback も行われなかった。

この crash 調査から、Python venv launcher の一時的 PID を durable worker identity として扱うと不安定になる問題も見つかった。

そこで、worker 起動後に実際の stable base Python process identity へ再 bind する修正を入れた。

- `3a592694abad53e9b80d703506b665845dc002b0`
- `fix: worker identityを安定した実プロセスへ再バインドする`

### C6.3 の証拠上の注意

利用可能な保存ログでは、C6.3 を「同じ独立試験を修正後に再実行して全項目 PASS」と明記した最終ログを確認できていない。

したがって、この文書では C6.3 単独を過剰に `fully re-run verified` と表現しない。

確認できている事実は次である。

- payload / process lifecycle の異常を fail closed で処理した。
- Host fallback は行わなかった。
- crash 調査で worker identity の弱点を発見し、stable worker identity rebind を実装した。
- 後続の C6.4 / recovery / post-cleanup production smoke はこの hardening 後の worker path で成功している。

---

# C6.4 — elevated WFP helper crash

## 31. なぜ C6.4 が必要だったか

C6 で最も重要な未確認点は、WFP ensure/read-back を担当する elevated helper 自身が verification evidence を返す前に死んだ場合である。

通常の helper は短時間で終了するため、人手で狙って kill するのは再現性が低い。

そのため、一時的な fault-injection hook を追加した。

- `efbc0c4ccfc4cc74be77507bec6f1419f0581f06`
- `test(security): C6.4 WFP helper crash試験を追加`

追加内容:

- `diagnostics/Invoke-WlmcpWfpGuardCrashKiller.ps1`
- `wfp_guard_runtime.py` の marker-based 15 秒 pause
- `tests/test_wfp_guard_crash_diagnostic.py`

## 32. fault window の位置

marker が存在するときだけ elevated helper は概ね次の順で進むようにした。

```text
UAC elevation
↓
named pipe peer verification
↓
proceed token
↓
administrator confirmation
↓
15 second diagnostic pause
↓
WFP ensure/read-back
```

つまり pause 中に helper を kill すれば、

- helper identity / UAC は成立済み
- しかし WFP verification evidence はまだ返っていない

という狙った fault state を作れる。

## 33. crash killer

管理者側 diagnostic script は次を行った。

```text
marker arm
↓
--elevated-ensure process monitor
↓
target helper found
↓
force kill
↓
local evidence JSON write
↓
finally: marker remove
```

Python venv launcher と base Python helper の race を考慮し、同じ elevated-ensure argument を持つ該当 process をまとめて終了する設計にした。

raw evidence は local `%TEMP%` にのみ残し、public repository には PID / command line / local path を含む生 evidence を追加しない。

---

## 34. C6.4 の試行中に除外した run

C6.4 では、security boundary の失敗ではなく test coordination の失敗で証拠に採用しなかった run が複数ある。

例:

- killer timeout 前に human approval / UAC が間に合わなかった
- killer を arm する前に approval を実行した
- UAC elevation launch が OS 側で cancel 扱いになった
- 別 PowerShell の killer がまだ待機しており marker が残っていた
- staging source の NTFS ADS を runtime storage preflight が拒否した
- full workspace staging が深い test tree で `WinError 206` になった

これらは final C6.4 proof に含めていない。

---

## 35. C6.4 final crash-path result

最終成功 run では、elevated WFP helper を UAC 起動後、WFP ensure/read-back 前の fault window で強制終了できた。

その operation では次を確認した。

- helper kill evidence が存在
- operation status = `failed`
- `wfp_guard_status = verification_failed`
- `failure_class = sandbox_backend_failure`
- `host_fallback_performed = false`
- `wfp_guard_verification = null`
- event `wfp_guard_verification_failed` が存在
- event `wfp_guard_verified` が存在しない
- event `child_started` が存在しない
- `child_pid` が存在しない

これにより、production security property として次を実機確認した。

> Elevated Guard が verification evidence を返す前に死んだ場合、WLMCP は WFP state を推測せず verification failure とし、Codex child を起動せず、Approved Host へも fallback しない。

---

## 36. C6.4 recovery

crash-path だけでなく、その後の正常 operation も確認した。

recovery run では次が成立した。

- operation = `succeeded`
- exit code = 0
- `wfp_guard_status = verified_before_launch`
- `wfp_guard_verified` が `child_started` より先
- operation 完了後に worker / child が残留していない

したがって、一度 Guard helper crash を起こしたことによって以後の Sandbox route が壊れたままになる状態も観測されなかった。

---

## 37. C6.4 fault-injection hook の撤去

fault-injection hook は証拠採取専用であり、production security code に恒久的な pause route を残さない方針とした。

次の commit で完全撤去した。

- `6db48785d4825c1886e371d9f9a0a30e2dfd06a1`
- `chore(security): C6.4 fault-injection hookを撤去`

削除したもの:

- crash killer script
- marker constant
- 15 秒 pause function / call
- diagnostic-only unit test

撤去後に、main tree 上で marker / killer / diagnostic test / runtime hook reference が残っていないことを確認した。

さらに cleanup 後の production tree で real Sandbox operation を再実行し、

```text
wfp_guard_verified
↓
child_started
↓
worker_finished
```

の正常順序と operation success を確認した。

---

# 38. C6 までに確立した security properties

Phase A から C6.4 までの実機結果から、localhost / WFP Guard 系列について少なくとも次を確認した。

## 実通信

- Codex Sandbox 用 identity に対する localhost BLOCK が実際に効く。
- parent / child / grandchild の複数 protocol / address-family probe で確認した。
- 通常 Windows user の localhost を同時に壊さない。

## Guard lifecycle

- Guard creator 正常終了で BLOCK が消えない。
- Guard creator 強制終了で BLOCK が消えない。
- Sandbox operation 終了時に BLOCK を削除しない。
- 複数 Sandbox の overlap で Guard state を共有できる。

## Guard identity / privilege boundary

- Guard target account をこの物理 machine の local user として厳格に解決する。
- `SidTypeUser` を要求する。
- WLMCP 全体ではなく小さな helper だけを UAC elevation する。
- named pipe peer を expected process identity / ancestry に bind する。

## read-back / launch ordering

- WFP object の存在だけでなく security-relevant field を read-back する。
- Guard verification 完了前に Sandbox child を起動しない。
- Guard verification failure では `child_started` へ進まない。

## failure behavior

- worker / launcher / helper crash が WFP BLOCK cleanup trigger にならない。
- Guard helper が verification 前に死亡した場合は fail closed。
- Sandbox failure から Approved Host へ自動 fallback しない。
- fault-injection 後に正常 route へ recovery できる。

---

# 39. 自動回帰の checkpoint

C2 hardening 後の checkpoint として、次の自動検査結果が記録されている。

- `270 passed, 2 skipped`
- Ruff check pass
- `git diff --check` pass

この数字は C6.4 diagnostic hook の追加・撤去より前の checkpoint であるため、「現在の最終 tree 6db48785... に対して full suite を再実行した証拠」とは扱わない。

C6.4 の cleanup commit について確認済みなのは、

- hook の diff 上の完全撤去
- current tree に diagnostic reference が残っていないこと
- cleanup 後の real Sandbox production smoke success

である。

release gate では、最終 tree に対する full pytest / Ruff / compileall / diff check を改めて取得する。

---

# 40. 証拠として扱わないもの / 未完了事項

## C6.3 単独 rerun

前述のとおり、修正後 C6.3 を同じ独立手順で再実行し、全 assertion PASS とした保存証拠は確認できていない。

後続の hardening 後 route が C6.4 / recovery / cleanup smoke を通ったこととは区別する。

## observer-user isolation

別 local observer user から WLMCP process / control-plane / credential 等が読めないかを確認する試験は準備されたが、C6.4 の証拠には含めていない。

これは localhost WFP Guard の成立とは別 security property である。

## public raw diagnostics

過去 commit には Phase A / B / C1 の machine-specific diagnostic output が含まれている。

これは password / token ではないが、public repository には不要な SID / PID / local path / runtime metadata を含み得る。

今後の診断 evidence は原則 local 保管または sanitize 済み summary とし、raw machine evidence をそのまま commit しない。

---

# 41. 主要 commit の時系列

| commit | 内容 |
| --- | --- |
| `55bfb66d508ce6a8880345b6db22373ee38b864a` | direct WFP Guard を Sandbox launch 前に必須化 |
| `77ec908fed542c51e7a6b723f1978cca1bdd1964` | local SID 解決厳格化、UAC IPC を process identity へ bind |
| `dbf5952b77a248722b4f91b938015ca3302bac2a` | elevated IPC peer の venv/base-Python identity 検証を強化 |
| `991ed4e8bd096cf7676b065f1f1a27ad590b7166` | real UAC / IPC / Guard integration diagnostic |
| `3a592694abad53e9b80d703506b665845dc002b0` | stable worker identity への rebind、C5/C4.5 系 diagnostic hardening |
| `efbc0c4ccfc4cc74be77507bec6f1419f0581f06` | C6.4 elevated helper crash fault-injection を追加 |
| `6db48785d4825c1886e371d9f9a0a30e2dfd06a1` | C6.4 fault-injection hook を production tree から撤去 |
| `1733701aea9ff8af0966a42a07605f646de62079` | C7 schema v4 identity binding、missing-only WFP reconstruction、TOCTOU hold を実装 |
| `215d46b98515e487eb26d7500ed148f80e47f744` | IPv6 UDP loopback probe の DualMode 設定順を修正 |

---

# 42. C7 — verified state と現在実体の identity binding

C6 までで、WFP policy / UAC / IPC / read-back / fail-closed / launch ordering / concurrency / crash behavior を確認した。C7 では、過去に live verification した security boundary と、現在実際に使う binary / source / policy が同一であることを marker schema v4 へ結合した。

C7 の本体実装 commit は次である。

- `1733701aea9ff8af0966a42a07605f646de62079`
- `feat(security): C7検証済み状態を実行時実体へ結合する`

## 42.1 schema v4 の identity

v4 marker は次を必須とする。

- 実際に import された Guard module 群の canonical path、content SHA-256、Windows handle 由来の volume serial number / file index、size
- Guard version と policy generation
- Codex launcher / helper の canonical path、content SHA-256、Windows stable file identity、size、実際の version
- Authenticode `Valid`、leaf signer subject、leaf certificate thumbprint
- Windows product、build、UBR、native architecture
- この PC へ完全修飾した Sandbox account、SID、`SidTypeUser`
- live verification で complete read-back した WFP fixed object の stable identity
- 従来の `isolation_context_digest` が含む roots、policy、resource limit 等

mtime は補助的な drift signal として marker に含めるが、単独では security identity の根拠にしない。Guard module と Codex executable closure は verification から child 起動まで handle で保持し、置換・書込みを拒否する。

v1～v3 または必須 field 欠損から v4 field を推測・移行しない。identity mismatch は marker stale として扱い、通常 operation は live verification を自動実行せず、route unavailable / fail closed とする。再検証には `verify-codex-sandbox` の明示実行が必要である。

## 42.2 missing と mismatch の分離

static non-persistent WFP object は reboot や BFE restart で消失し得る。marker v4 の Guard implementation、policy generation、Codex backend、Sandbox account、OS identity、schema がすべて現在値と一致する場合、exact fixed object が単に missing であれば trusted Guard による ensure / recreate を許可する。

順序は C2～C6 と同じく次を必須とする。

```text
ensure exact missing object
↓
complete read-back verification
↓
wfp_guard_verified
↓
Sandbox child launch
```

一方、既存 object の security-relevant field 不一致、unexpected conflicting object、または marker identity 不一致では silent repair しない。存在する object をすべて検証してから不足分を作るため、missing と mismatch が混在する場合も何も追加せず fail closed する。

## 42.3 自動回帰で確認した範囲

- schema v1～v3、必須 field 欠損、backend / Guard / policy / account / OS mismatch の拒否
- stale marker が Guard 昇格経路、live probe、child launch、Approved Host fallback へ進まないこと
- exact missing object だけが trusted ensure 経路へ進むこと
- existing mismatch が silent repair へ進まないこと
- missing sibling と conflicting object が混在しても object を追加しないこと
- complete read-back → `wfp_guard_verified` → child launch の順序
- 実 import module の canonical path / SHA-256 / stable identity manifest と hold

C7 重点回帰は `92 passed`、通常 Windows user 文脈の full pytest は `304 passed, 2 skipped`。Ruff、compileall、`git diff --check` も pass した。

## 42.4 C7 live verification

C7 実装後、通常 Windows user 文脈で `verify-codex-sandbox` を実行した。

確認した事実:

- marker schema = v4
- route eligibility = true
- 実際の installed Codex backend の version / Authenticode / stable file identity を取得
- Guard implementation digest を取得
- Windows build / UBR を identity へ含めた
- local physical computer に完全修飾した Sandbox account identity を確認
- WFP Guard binding digest を取得
- `filesystem_read` / `filesystem_write` / `internet` / `loopback` / `termination` / `resource_bound` は route 判定上の必要条件を満たした
- `protected_information_read` と descendant の protected-information denial は residual risk として失敗を保持し、aggregate `passed=false` を無理に success 表示へ変換していない

この結果は「全 Sandbox property が完全 verified」という意味ではない。C7 の目的である identity binding と route eligibility の成立を確認した checkpoint である。

## 42.5 exact missing WFP object の production-route reconstruction

live marker を更新せず、maintenance cleanup で WLMCP の exact Guard sublayer と V4/V6 fixed filter だけを削除した。cleanup 前後で marker の SHA-256 が不変であることを確認した。

その後、通常の `request_sandbox_command` production route を one-shot approval で実行した。

実機 audit では次の順序を確認した。

```text
created
↓
approved_and_claimed
↓
worker_spawned
↓
approval_bundle_verified
↓
worker_started
↓
sandbox_policy_prepared
↓
wfp_guard_verified
↓
sandbox_policy_applied
↓
child_started
↓
worker_finished
```

operation は `codex_sandbox` tier、`status=succeeded`、`exit_code=0` で完了した。`wfp_guard_verified` と operation の final network policy に記録された V4/V6 filter は、cleanup 後に新しく割り当てられた runtime ID を持っており、削除前の object が残っていたのではなく fixed object が再作成されたことを確認した。

重要な点は、再作成後も marker binding に含まれる V4/V6 `effective_weight` が削除前と一致し、完全 read-back の後にのみ `wfp_guard_verified` へ進み、その後に初めて `child_started` が記録されたことである。

C7 実装時に懸念していた「`FWP_EMPTY` の再作成で `effective_weight` が変化し、valid marker + missing-only reconstruction が毎回 binding mismatch になる」問題は、この実機では再現しなかった。

## 42.6 Host fallback の不在

上記 production operation の全 event を確認し、`fallback` / `host` / `escalation` に該当する event は存在しなかった。

したがって、missing-only reconstruction の正常系は Approved Host へ経路変更せず、そのまま `codex_sandbox` tier で完了した。

これは C7 の設計原則である「Codex Sandbox failure / Guard failure から Approved Host へ自動 fallback しない」と整合する。

## 42.7 再構築後の localhost 実通信

fixed Guard 再構築後、maintained diagnostic `Invoke-CodexLoopbackProbe.ps1 -RunSandboxProbe` で parent / child / grandchild の実通信を再確認した。

最初の再測定で host 側 IPv6 listener の `DualMode` 設定が bind 後に行われていたため、IPv6 UDP listener 作成時に Windows が `InvalidArgument` を返す diagnostic bug を発見した。

次の commit で diagnostic を限定修正した。

- `215d46b98515e487eb26d7500ed148f80e47f744`
- `fix(diagnostics): IPv6 UDP listenerのDualMode設定順を修正`

修正内容:

- IPv6 UDP socket を `AddressFamily.InterNetworkV6` で未 bind の状態に生成
- `DualMode = false` を設定してから `::1` へ bind
- IPv6 TCP と UDP の listener 失敗処理を分離
- listener 初期化失敗時に半端な socket / listener を残さない

修正後の再実行では `listener_errors=[]` を確認した。

実通信結果:

- TCP IPv4: parent / child / grandchild のすべてで connection 成立せず、host 受信 token なし
- TCP IPv6: parent / child / grandchild のすべてで connection 成立せず、host 受信 token なし
- UDP IPv4: Sandbox 側 `Send()` は成功するが host 受信 token なし
- UDP IPv6: Sandbox 側 `Send()` は成功するが host 受信 token なし
- setup marker は probe 前後で不変

UDP は connection-oriented ではなく `Send()` success だけで到達を証明できないため、diagnostic 自身も host token 受信を到達証拠としている。今回 host 受信は 0 であり遮断と整合するが、UDP のみをこの probe 単独で「WFP Guard が唯一の原因で drop した」とは表現しない。

また、この direct Codex traffic probe では Codex 側 Firewall rule も有効であるため、実通信遮断の唯一の原因を WLMCP custom Guard へ帰属する証拠ではない。Phase B の Guard 有無対照試験と、今回の production-route reconstruction / complete read-back / launch ordering の証拠を組み合わせて評価する。

## 42.8 C7 の結論

C7 の実機 checkpoint は PASS とする。

実証した性質は次である。

1. schema v4 marker が現在の Guard implementation / Codex backend / account / OS / WFP stable binding に結合する。
2. marker を変えず exact fixed WFP object だけが消失した場合、通常 production route から trusted Guard が missing object を再構築できる。
3. 再構築後は complete read-back を通過しない限り `wfp_guard_verified` にならない。
4. `wfp_guard_verified` より前に Sandbox child は起動しない。
5. missing-only reconstruction 後も marker binding が成立し、operation は同じ `codex_sandbox` tier で成功する。
6. Approved Host への自動 fallback / escalation は発生しない。
7. 再構築後の localhost 実通信は IPv4 / IPv6、parent / child / grandchild で遮断結果と整合する。

C7 完了後も、WFP Guard だけを見て release しない。repository-wide Security Review / Scan、findings 修正、再 scan、最終 production-route E2E を別 release gate として扱う。

---

# 43. 現在地

C7 実装の開始 baseline は main commit `b81ebe654bf99d0e64d9b4e1c7a7bc1bb04d9026`、本体実装 commit は `1733701aea9ff8af0966a42a07605f646de62079` である。

localhost / WFP Guard 問題については「有効な block 方法を見つけた」という段階を越え、C6 で crash / fail-closed / lifecycle を実機確認し、C7 で verified state と現在実体を identity binding し、その missing-only reconstruction と production launch ordering を実機で完了まで確認した。

C7 は PASS。以後は repository-wide security validation、findings 修正・再 scan、最終 production-route E2E、packaging / install / upgrade / uninstall / release gate へ進む。
