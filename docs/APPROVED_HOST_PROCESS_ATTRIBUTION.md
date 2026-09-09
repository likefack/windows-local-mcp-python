# Approved Host process attribution

## Status

- Finding: `WLMCP-R3-004 — Medium`
- Revalidated baseline: `eba8b8ac59e0730ad2c8abe646b6ac997d31d433`
- Validity: `valid`
- Remediation decision: `unresolved / architecture-blocked`
- Operational disposition: `known / deferred` — 現時点では production remediation を実施しない。
- Revisit trigger: 実運用で本 finding に起因する Approved Host の failure / `recovery_required` が反復し、無視できない availability impact が確認された場合に再検討する。
- Scope: Approved Host requester-user process census の attribution precision と、それに起因する availability failure。
- `WLMCP-R2-001` は `fixed / live verified` を維持する。本 finding は LocalSystem authority separation、SYSTEM-worker-owned Job Object、durable authority/postflight latch、requester PID/create-time/SID/token binding、control-plane tamper detection の成立を否定しない。

本 finding のために production security boundary は弱めない。non-bypassable な replacement attribution boundary を実装して live verification できるまで、現行 requester-user census と uncertainty fail-closed は維持する。

### Current disposition and revisit policy

R3-004 は既知の valid finding として記録を維持するが、現時点では修正を実施しない。現在確認されている影響は、unrelated same-user process を operation 起因と誤認することによる availability / result-integrity failure であり、安全側への fail-closed である。これを回避するために current broad census を緩和すると、WMI/CIM / `Win32_Process.Create` 等による Job-external process を見逃す fail-open risk を導入し得るため、既存 security guarantee を優先する。

再検討は、実運用 telemetry、再現可能な incident、または repeated E2E verification により、本 finding が Approved Host の通常利用を実質的に阻害していると確認された場合に行う。単発または低頻度の false positive のみを理由に architecture を変更しない。再検討時も、下記 acceptance criteria と fail-closed requirement を満たす root attribution mechanism がない限り、単純な ignore/filter、timeout 延長、PPID/command-line 等の heuristic による緩和は採用しない。

## Current behavior

現行 Approved Host postflight は requester-user の temporal process census を使用する。

1. Approved Host child launch 直前に requester user で実行中の全 process を `(pid, create_time)` として baseline に記録する。
2. command 実行後、SYSTEM-owned Job Object を terminate して empty を確認する。
3. requester user を再列挙し、`current - baseline` の全 process を untracked と扱う。
4. operation deadline までその集合が空になるのを待つ。
5. process が残れば postflight verification を失敗させ、normal completion proof を生成せず fail closed にする。

この方式は `Win32_Process.Create` により Approved Host Job 外へ生成された requester-user helper を捕捉できる。しかし、baseline 後に Approved Host と無関係に開始した同一 user process も同じ `(pid, create_time)` で表現されるため、operation provenance を持たない。

また、runtime limit 到達時に一度 `status=timed_out` / `failure_class=runtime_limit` が設定されても、その後の census postflight が失敗すると broad postflight uncertainty path が最終状態を `failed` へ上書きできる。このため process census の false positive は単なる遅延ではなく operation outcome の誤分類と durable fail-closed state につながり得る。

## Reproduction and supporting evidence

### Deterministic semantic reproduction

current census algorithm と同じ `capture_user_processes()` / `current - baseline` semantics を実 process 上で再現した。

1. requester-user baseline を取得。
2. Approved Host-like child を開始し、PID/create-time を取得して child start を同期。
3. child start 後に別の long-lived same-user ambient process を開始。
4. Approved Host-like child を終了。
5. current wait algorithm と同じ差集合を deadline まで評価。

ambient process は operation と無関係でも `current - baseline` に残り、deadline まで `untracked` と判定された。したがって false positive は census algorithm から deterministic に導出できる。

### Repository verification evidence

current `VERIFICATION.md` には full pytest の既存記録として、`test_approved_host_terminates_descendants_at_runtime_limit` が期待した `timed_out` ではなく `failed` となったケースが記録されている。この記録だけでは untracked PID / failure class が保存されていないため R3-004 が原因と断定しないが、現行 postflight overwrite semantics と強く整合する supporting evidence である。

historical PR #26 run `33131753950` attempt 1 にも同じ test の `timed_out` vs `failed` failure があり、source change なしの rerun では成功している。これも supporting evidence としてのみ扱う。

## Root cause

`pid + create_time` は process instance identity を確立するが、causal attribution を確立しない。

この区別は current product authority model の下では process metadata だけから一般的に復元できない。

pre-existing same-user process `P` と、新規 process `Q` を考える。

- unrelated case: `P` が timer、UI action、network input、その他の ambient event を受け、`Q` を生成する。
- operation-caused case: Approved Host child が same-user IPC で同じ `P` に依頼し、`P` が同じ process-creation path から同じ `Q` を生成する。

両ケースの `Q` は、creator process、user SID、logon session、token properties、executable、command line、terminal session、process-creation API を同一にできる。postflight observer が process state だけを見る場合、両ケースを security proof として区別できない。

Approved Host child は product requirement 上、通常の Windows user authority を保持する。そのため pre-existing same-user process と RPC/COM、named pipe、loopback、file、shared memory、window message、application-specific IPC 等で通信できる。generic causal attribution を成立させるには process metadata より強い isolation または mediation boundary が必要になる。

## Rejected attribution candidates

### Username / SID / logon session / terminal session

同一 interactive user の unrelated application 間で共有されるため operation provenance にならない。

### PID / create-time

PID reuse を防ぐ process-instance identity として必要だが、因果関係を表さない。

### Parent PID / process tree

Job-external broker creation では creator が Approved Host child とは限らない。WMI provider、COM/RPC broker、task infrastructure、pre-existing cooperating process 等が creator になり得る。PPID-only attribution は採用しない。

### Executable / command line / environment nonce / self-report

untrusted child が制御、再現、除去、偽装できるため security attribution proof として使用しない。

### Token `AuthenticationId`

logon session identity であり、unrelated same-user processes が共有できる。

### Token `TokenId`

operation lineage marker として使用しない。Windows CI run `33171577348` の probe では `DuplicateTokenEx` によって `TokenId` が変化しても `AuthenticationId` は同じ logon session のまま維持された。untrusted process が usable token を duplicate して token-object identity を洗い替えられるためである。

### Token claims / security attributes

public token claim APIs から、通常 user authority を保ったまま application が設定でき、child が除去・複製・借用できない operation-specific marker を構成できる根拠を確認できなかった。`TokenSecurityAttributes` は Microsoft documentation 上 system use reserved であり production contract dependency にしない。

### Restricted token / AppContainer / lower integrity

より強い isolation は作れるが、Approved Host が提供すべき通常 Windows user authority を変更または縮小するため transparent bug fix ではない。

## WMI Activity ETW probe

Security Contract / Approved Host Product Invariant は current remediation の必須要素を requester-user `WMI/CIM process census` と記述し、required live verification も real `Win32_Process.Create` Job-external helper を要求している。このため broad all-same-user temporal census を、SYSTEM-owned WMI-created-process evidence へ置き換えられるか追加検証した。

Microsoft は Windows Vista 以降の WMI activity tracing が ETW を使用することを文書化している。また `Win32_Process.Create` は成功時に created process ID を返す。

temporary probe では以下を試した。

- trusted System32 `logman.exe` で `Microsoft-Windows-WMI-Activity` file trace session を開始。
- unrelated ambient `ping.exe` を通常起動。
- real `[wmiclass]'Win32_Process'` / `InvokeMethod('Create')` で別の process を作成。
- trace stop 後に trusted System32 `tracerpt.exe` で解析し、WMI Activity process-created event の `CreatedProcessId` / creation time と実 process identity の一致、ambient process の非混同を検証する。

### Probe result

この方式は production fix の採用条件を満たさなかった。

- Windows CI run `33222397947` では provider を広く有効化した trace 中、real `Win32_Process.Create` invocation が 20 秒 timeout し、created-process event validation まで到達しなかった。
- trace keyword を WMI Trace 用 `0x8000000000000000` に狭めた Windows CI run `33222639804` でも同じ `Win32_Process.Create` invocation が 20 秒 timeout した。
- run `33222639804` では Ruff、Compile、Runtime closure、MCP stdio、diff whitespace は成功しており、probe 自体の Python formatting/packaging failure ではない。
- 同一 run の既存 `tests/test_approval_execution_integration.py` の Approved Host WMI integration tests は probe より前に成功している。したがって「Hosted Windows で WMI provider 自体が unavailable」だけでは probe failure を説明できない。

この evidence だけから ETW session が timeout の唯一の原因だとは断定しない。しかし security-critical monitoring mechanism には、対象 operation を阻害せず deterministic に start / collect / stop / drain できる証明が必要であり、現在の probe はその条件を満たしていない。

さらに ETW は event loss を明示的に考慮する必要がある。production boundary に採用する場合でも、少なくとも SYSTEM-owned controller、protected ETL location/session ACL、provider disable、session stop/flush、`EventsLost` / `LogBuffersLost` 等の loss-counter zero verification、parser/schema fail-closed、worker/service abnormal termination 時の durable recovery semantics が必要になる。

しかし、これらを実装して direct WMI creation を安定して census できても、unrelated same-user WMI request と operation-caused WMI request の安全な causal distinction、または pre-existing same-user broker を経由する非-WMI IPC process creation の generic distinctionは解決しない。したがって ETW-only replacement を current root fix として採用しない。

参考 Microsoft documentation:

- [Tracing WMI Activity](https://learn.microsoft.com/windows/win32/wmisdk/tracing-wmi-activity)
- [Create method of the Win32_Process class](https://learn.microsoft.com/windows/win32/cimwin32prov/create-method-in-class-win32-process)
- [ControlTraceW function](https://learn.microsoft.com/windows/win32/api/evntrace/nf-evntrace-controltracew)
- [Configuring and Starting an Event Tracing Session](https://learn.microsoft.com/windows/win32/etw/configuring-and-starting-an-event-tracing-session)

## Required root architecture

complete fix は、unrelated process と operation-caused process を security proof として区別可能にしなければならない。少なくとも次のいずれかの architecture property が必要になる。

### 1. Operation-isolated authority identity

operation-specific Windows security identity を作り、以下をすべて満たす。

- Approved Host が必要とする通常 host capability を保持する。
- SYSTEM monitor が ambient same-user process と区別できる。
- permitted brokered process creation を通して identity/provenance が維持される。
- untrusted child が marker を除去、洗い替え、unmarked equivalent token へ duplicate、ambient process から借用できない。
- required profile/network/device/local semantics を維持する。

単なる token object ID はこの条件を満たさない。separate logon/principal 等を使用する場合、通常 user capability を意味的に縮小しないことを real Windows で証明する必要がある。

### 2. Privileged process-creation mediation

SYSTEM-owned mediation boundary を導入し、Approved Host が許可される Job-external process creation はすべて、

- authenticated operation-bound broker が exact created PID/create-time を記録して生成する、または
- mediation を bypass する process creation を OS policy で拒否する

のどちらかにする。

WMI/CIM だけでなく、product が許す全 broker/IPC process-creation surface を扱い、Approved Host child が equivalent ambient broker を迂回利用できないことが必要である。telemetry correlation だけでは不十分。

### 3. Explicit contract narrowing

保証対象を有限の broker family に明示的に狭め、それぞれに authenticated monitoring を実装する選択肢はある。ただしこれは current security contract / capability semantics の変更であり、本 finding の bug fix として自動採用しない。trusted operator の明示承認が必要である。

## Fail-closed requirement while unresolved

root attribution boundary が実装・live verified されるまで以下を維持する。

- requester-user temporal census を削除しない。
- real WMI / `Win32_Process.Create` Job-external regression を削除・skip・期待値緩和しない。
- uncertainty は fail closed のままにする。
- executable name、PPID、session、command line、短い timing window、CI environment、user-provided marker で baseline-after process を広く ignore しない。
- timeout を延長して false positive を隠さない。
- Job Object だけへ縮小しない。
- durable authority/postflight latch、LocalSystem authority、requester binding、tamper detection を弱めない。
- WLMCP-R2-001 を本 finding だけを理由に reopen しない。

現在の residual defect は availability / result-integrity defect である。unrelated same-user process が Approved Host baseline 後に開始し operation deadline まで残れば、安全側へ倒れる代わりに legitimate operation が失敗し得る。これは security guarantee を失うより安全だが、valid unresolved product defect である。

## Acceptance criteria for a future fix

future implementation は、同一 candidate 上の real Windows verification で少なくとも以下を満たすまで complete としない。

1. Approved Host child start 後に unrelated same-user process を開始し、Approved Host completion より長く生存させても、その process だけを理由に operation が failure / `recovery_required` にならない。
2. Approved Host operation が real WMI/CIM `Win32_Process.Create` Job-external helper を生成し、その exact PID/create-time が operation に帰属され、helper が残る間は postflight が fail closed になる。
3. untrusted child が token duplication、alternate same-user token、pre-existing same-user broker、supported IPC path を用いて attribution laundering を試みても、unattributed surviving Job-external process を作れない。
4. unrelated same-user WMI/CIM activity がある場合にも、safe operation attribution が証明できるか、不明なら明示的に fail closed する。
5. PID reuse、process-exit race、monitor start/stop race、telemetry/provider/session loss で process が消失・誤帰属しない。
6. LocalSystem authority separation、SYSTEM-owned Job Object、durable `active.json` / postflight latch、requester identity binding、control-plane tamper detection、explicit coordinated recovery を維持する。
7. monitor/worker/service abnormal termination、service restart、ambiguous attribution は fail closed のままにする。
8. recovery 後の normal Approved Host operation が再び成功する。
9. hosted regression に加えて、required real-machine Approved Host normal / abnormal / recovery lifecycle verification を完了する。