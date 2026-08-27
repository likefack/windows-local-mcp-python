# Approved Host runtime and authority boundary

Approved Host は、Codex Sandbox／Broker では満たせない処理を trusted operator の one-shot approval 後に通常の Windows user authority で実行する中核 route です。

WLMCP-R2-001 は、旧 architecture で Approved Host child と worker／postflight monitor が同一 Windows user authority にあり、child が監視側を停止して postflight を回避できることを示しました。2026-08-27 に main へ入った total fail-closed は exploit containment としては有効でしたが、Approved Host の intended function を失う temporary capability reduction／product regression であり、最終 remediation ではありません。

この branch の remediation candidate は monitor／postflight owner を LocalSystem service 配下へ移し、実 command だけを元の非昇格 runtime-user token で起動します。same-desktop UAC elevation は security boundary として使いません。

重要: source／CI 上で architecture を実装しただけでは WLMCP-R2-001 を fixed／closed としません。通常 Windows user と実際の LocalSystem service／SCM／ProgramData ACL を使った normal-path と abnormal-path の live verification が両方成功するまで status は `valid / remediation implemented / Windows live verification pending` です。

## Production layout

既定 layout は次です。

```text
C:\Program Files\WindowsLocalMCP\
  runtime\
  run-server.ps1
  run-approvals.ps1
  install-approved-host-authority.ps1
  recover-approved-host-authority.ps1
  verify-approved-host-runtime.ps1
  verify-approved-host-authority.ps1
  verify-approved-host-authority-abnormal.ps1
  config.example.toml

C:\ProgramData\WindowsLocalMCP\ApprovedHostAuthority\
  active.json
  active-status.json                 # active operation 中だけ存在し得る
  completion-<operation>-<nonce>.json # worker completion handoff。通常は service が消費
  completed\
```

Program Files の WLMCP／Python runtime は通常 runtime user から RX、SYSTEM／Administrators から Full Control とします。`runtime` venv が参照する base Python も non-elevated WLMCP user から immutable でなければなりません。

ProgramData の authority state root は LocalSystem owner、protected DACL、SYSTEM／Administrators だけが変更可能であることを production service 自身が起動時と各 RPC で Win32 security descriptor から再検証します。runtime user に state directory の enumerate／create／delete／replace／WRITE_DAC／WRITE_OWNER capability を与えません。

SCM service `WindowsLocalMCPApprovedHost` も protected DACL を要求します。runtime user に許す service right は `SERVICE_QUERY_STATUS` だけで、STOP、CHANGE_CONFIG、DELETE、WRITE_DAC、WRITE_OWNER は許しません。

## Runtime immutability

runtime immutability は authority separation と別の必須 layer です。

管理者 PowerShell から provision します。

```powershell
.\install-approved-host-runtime.ps1 `
  -BasePython "C:\Program Files\Python312\python.exe" `
  -RuntimeUser "$env:USERDOMAIN\$env:USERNAME"
```

通常 user の非昇格 PowerShell で確認します。

```powershell
& "C:\Program Files\WindowsLocalMCP\verify-approved-host-runtime.ps1"
```

lower-level verifier は installed Python を `-I -B` で起動し、WLMCP package、startup-active dependency、import namespace、launcher、base Python／stdlib／DLL、ancestor replacement access、reparse point 等を検査します。runtime immutability 成功だけを Approved Host availability／R2-001 fix の証拠にしません。

## LocalSystem authority provisioning

runtime immutability を確認した後、管理者 PowerShell から authority service を provision します。

```powershell
& "C:\Program Files\WindowsLocalMCP\install-approved-host-authority.ps1" `
  -RuntimeUser "$env:USERDOMAIN\$env:USERNAME"
```

production service entry は `windows_local_mcp.approved_host_service_entry` です。base service implementation に diagnostic／test helper が残っていても installer は production entry 以外を登録しません。

service は named pipe peer PID と SCM の service PID を相互確認し、client PID／create-time、configured runtime SID、non-elevated token を検証します。runtime user／Approved Host child には monitor cancellation RPC を公開しません。

## Execution authority split

Approved Host の control-plane worker は LocalSystem として動作し、preflight、Job Object ownership、control-plane digest、audit mirror、postflight、WMI／CIM job-external process census、durable completion proof を所有します。

実 command は service が pipe client の verified process token から primary token を複製し、`CreateProcessAsUserW` で suspended 作成します。child を SYSTEM worker 所有 Job Object へ割り当てた後に resume します。

したがって intended function は「通常 Windows user authority」のままです。child を SYSTEM に昇格させません。live verifier は child SID が requester SID と一致し、非昇格のまま、runtime user が自分の child に通常の process authority を持つことを確認します。

## Durable state machine

production `active.json` は operation arm 時に `O_EXCL` で作成し、正常 completion が service により受理されるまで内容を置換しません。running／recovery diagnostic は `active-status.json` sidecar に書きます。

active latch は少なくとも次へ binding されます。

- operation id
- service epoch
- authority nonce
- requester PID／create-time／SID
- immutable worker-context SHA-256
- completion proof path

worker が child を一度でも作成した場合、completion proof には SYSTEM worker 内で control-plane postflight が expected state と一致したことが必要です。さらに production worker が `run_operation()` から正常 return した場合だけ `worker_returned_normally=true` の proof を作れます。

worker kill、unhandled exception、thread/process termination、channel loss、postflight failure、WMI／CIM helper 残存、service restart、epoch mismatch では normal proof が成立せず、`active.json` は残ります。service restart 中に active state を見つけた場合は `recovery_required` にします。旧 service epoch の proof を新 epoch で受理しません。service が provision 済みなら、user-owned config で `approved_host_enabled=false` に変更しても active／recovery latch の global health check は継続します。

service が valid proof を消費する際は completion record を `completed/` に archive してから proof／status を消し、immutable `active.json` を最後に unlink します。途中 power loss／exception では active latch が残る方向に倒します。

## WMI / Win32_Process.Create and Job-external processes

SYSTEM worker 化によって current-user census を SYSTEM process census に変えてはいけません。Approved Host worker hook は pipe requester の PID／create-time から元 runtime-user username を固定し、child launch 直前の same-user PID／create-time baseline と postflight census をその user に対して行います。

これにより Job Object descendant handling と、`Win32_Process.Create` 等で provider が作る Job 外 same-user process の fail-closed detection を維持します。process identity を列挙できない、または operation deadline まで job-external process が残る場合は postflight を成功扱いしません。

## stop / recovery semantics

active Approved Host は runtime-user control plane の `stop_job` から停止できません。これは Approved Host execution を削除する capability reduction ではなく、untrusted child と同一 authority に monitor-stop primitive を与えないための security invariant です。command timeout／Job cleanup／postflight は SYSTEM worker が所有します。

異常 operation の recovery は elevated Administrator が durable state をレビューした後だけ `recover-approved-host-authority.ps1 -AcknowledgeReviewedState` で行います。recorded SYSTEM worker identity がまだ live の場合は recovery 自体を拒否し、monitor-stop mechanism として利用できないようにします。recovery evidence は `completed/` へ archive します。

user-owned control-plane tamper／postflight marker が別途残る場合、この authority recovery script はそれを消しません。

## Windows live verification

### Normal path

通常 runtime user の非昇格 PowerShell から実行します。

```powershell
& "C:\Program Files\WindowsLocalMCP\verify-approved-host-authority.ps1" `
  -ConfigPath C:\path\to\config.toml `
  -Cwd C:\path\to\workspace
```

operator が `VERIFY` を明示入力した後、verifier は non-project-controlled System32 command を `request_host_command` → immutable approval verification → one-shot claim → SYSTEM worker → non-elevated child → postflight → durable latch clear まで実行します。

同時に runtime-user token から service／SYSTEM worker に対する PROCESS_TERMINATE、SUSPEND_RESUME、CREATE_THREAD、VM_WRITE／VM_OPERATION、DUP_HANDLE、SET_INFORMATION、WRITE_DAC／WRITE_OWNER、sensitive token rights、thread terminate／suspend／set-context、SCM stop／change-config 等が拒否されることを実測します。ProgramData authority state の enumerate／write denial と child authority retention も確認します。

### Abnormal path

`verify-approved-host-authority-abnormal.ps1` を 3 phase で実行します。

1. 非昇格 runtime user: `-Phase Arm`
   - `WMIC.exe process call create` / `Win32_Process.Create` で requester-user の Job 外 `ping.exe` helper が実在することを PID／create-time／executable で確認。
   - Approved Host SYSTEM worker と legacy pending approval を handoff に固定。
2. elevated Administrator: `-Phase KillAndRestart`
   - handoff の PID／create-time／executable が一致する SYSTEM worker だけを fault injection として kill。
   - kill 前／kill 後／service restart 後で immutable `active.json` SHA-256 が同一であることを確認。
   - `recovery_required` が service restart を跨ぐことを確認。
3. 非昇格 runtime user: `-Phase Check`
   - authority が healthy に戻らないこと。
   - ProgramData state enumerate／create／delete／replace が拒否されること。
   - abnormal Host 前に作った pending approval の generation が使えず、approval UI を迂回して claim しても Executor authority gate で worker／child を spawn できないこと。

WMIC optional feature がない PC では mandatory WMI abnormal-path live verification を完了したとは扱いません。別の preinstalled non-project-controlled WMI/CIM client で同等 evidence を実装するか WMIC feature を有効化してから確認します。

## Current status

この branch では LocalSystem authority、requester-token launch、durable state、restart recovery、WMI requester-user census、runtime-user monitor-stop denial、unit/integration regressions、live verification scripts を実装しています。

R2-001 専用 live verifier は別 finding WLMCP-R3-002 の `workspace_write=false` materialization 経路に依存しないよう、non-project-controlled command を `workspace_write=true` で実行します。

ただし GitHub Hosted Windows CI は実際の installed service／SCM ACL／ProgramData ACL／runtime-user-vs-SYSTEM process authority を証明しません。normal path と abnormal path の実 Windows live verification が未実施である限り、WLMCP-R2-001 は `valid / remediation implemented / live verification pending` のままです。main へ merge して `fixed / closed` と記録する条件は、CI と両 live verification の成功です。
