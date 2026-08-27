# Approved Host runtime and authority boundary

Approved Host は、Codex Sandbox／Broker では満たせない処理を trusted operator の one-shot approval 後に通常の Windows user authority で実行する中核 route です。

WLMCP-R2-001 は、旧 architecture で Approved Host child と worker／postflight monitor が同一 Windows user authority にあり、child が監視側を停止して postflight を回避できることを示しました。2026-08-27 に main へ入った total fail-closed は exploit containment としては有効でしたが、Approved Host の intended function を失う temporary capability reduction／product regression であり、最終 remediation ではありません。

この branch の remediation candidate は monitor／postflight owner を LocalSystem service 配下へ移し、実 command だけを元の非昇格 runtime-user token で起動します。same-desktop UAC elevation は security boundary として使いません。

重要: source／CI 上で architecture を実装しただけでは WLMCP-R2-001 を fixed／closed としません。通常 Windows user と実際の LocalSystem service／SCM／ProgramData ACL を使った normal-path、abnormal-path、explicit recovery、recovery 後の normal-path がすべて成功するまで status は `valid / remediation implemented / Windows live verification incomplete` です。

## Production layout

既定 layout は次です。

```text
C:\Program Files\WindowsLocalMCP\
  runtime\
  run-server.ps1
  run-approvals.ps1
  install-approved-host-authority.ps1
  recover-approved-host-authority.ps1
  recover-approved-host-postflight.ps1   # historical split-recovery compatibility only
  verify-approved-host-runtime.ps1
  verify-approved-host-authority.ps1
  verify-approved-host-authority-abnormal.ps1
  config.example.toml

C:\ProgramData\WindowsLocalMCP\ApprovedHostAuthority\
  active.json
  active-status.json                  # active operation 中だけ存在し得る
  completion-<operation>-<nonce>.json # worker completion handoff。通常は service が消費
  completed\

<data_dir>\control-plane\
  approved-host-postflight-pending.json
  approved-host-postflight-recovered-<operation>-<digest-prefix>.json # explicit recovery evidence
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

SYSTEM-owned authority latch とは別に、runtime-user control plane は `approved-host-postflight-pending.json` を保持します。これは worker kill 等で trusted postflight path が失われた場合に、authority state のみを解除しても operations が自動再開しないための第二 latch です。この marker が存在する間は `assert_control_plane_healthy()` が全 operation creation を拒否します。

## WMI / Win32_Process.Create and Job-external processes

SYSTEM worker 化によって current-user census を SYSTEM process census に変えてはいけません。Approved Host worker hook は pipe requester の PID／create-time から元 runtime-user username を固定し、child launch 直前の same-user PID／create-time baseline と postflight census をその user に対して行います。

これにより Job Object descendant handling と、`Win32_Process.Create` 等で provider が作る Job 外 same-user process の fail-closed detection を維持します。process identity を列挙できない、または operation deadline まで job-external process が残る場合は postflight を成功扱いしません。

## stop / recovery semantics

active Approved Host は runtime-user control plane の `stop_job` から停止できません。これは Approved Host execution を削除する capability reduction ではなく、untrusted child と同一 authority に monitor-stop primitive を与えないための security invariant です。command timeout／Job cleanup／postflight は SYSTEM worker が所有します。

異常 operation の標準 recovery は elevated Administrator が durable state をレビューした後だけ、config を明示して実行します。

```powershell
.\recover-approved-host-authority.ps1 `
  -ConfigPath C:\path\to\config.toml `
  -AcknowledgeReviewedState
```

recorded SYSTEM worker identity がまだ live の場合は recovery 自体を拒否し、monitor-stop mechanism として利用できないようにします。recovery は SYSTEM-owned authority latch と、その operation に binding された user-owned postflight latch を一体として扱います。

immutable Program Files runtime の `windows_local_mcp.approved_host_recovery` は postflight marker について次を確認します。

- configured `data_dir/control-plane` 内の non-reparse regular single-link file であること
- schema version／`postflight_pending` state／manual-recovery contract が期待値であること
- marker `operation_id` が SYSTEM authority recovery operation と一致すること
- reviewed SHA-256 と stable file identity が quarantine move 前後で一致すること
- independent `tamper-detected.json` が存在しないこと

標準 recovery の ordering は次です。

1. SYSTEM-owned `completed/` に authority／status／postflight preflight evidence を archive。
2. reviewed postflight marker を同一 control-plane directory の digest-bound recovery quarantine 名へ move し、移動後に同一 content／stable identity を再検証。
3. completion proof と `active-status.json` を削除。
4. immutable SYSTEM `active.json` を最後に削除。
5. service を Running へ戻す。

marker mismatch、SHA mismatch、operation mismatch、independent tamper marker、unexpected missing marker は default で fail closed にします。postflight quarantine 後・`active.json` 削除前に recovery process が中断した場合、次回 recovery は一意な digest-bound quarantine を再検証して安全に resume できます。recovery 自体が失敗しても service は `finally` で再起動し、`active.json` が残っていれば再び `recovery_required` のままです。

本当に marker が失われたことを operator が別 evidence から確認した場合だけ `-AcknowledgeMissingPostflightMarker` を追加できます。これは通常 recovery の shortcut ではありません。independent control-plane tamper marker はこの recovery path では絶対に解除しません。

旧版 `recover-approved-host-authority.ps1` が SYSTEM latch だけを先に解除してしまい、version-1 SYSTEM recovery archive と user-owned postflight marker が残っている historical split-recovery state に限り、`recover-approved-host-postflight.ps1` を使います。この compatibility path は protected `ApprovedHostAuthority/completed` 配下の version-1 archive、archive 内 active/status operation binding、`recovery_required`、旧 administrator acknowledgement を検証し、同じ operation の postflight marker を immutable runtime で quarantine します。新規 recovery では使用しません。

## Windows live verification

### Normal path

通常 runtime user の非昇格 PowerShell から実行します。

```powershell
& "C:\Program Files\WindowsLocalMCP\verify-approved-host-authority.ps1" `
  -ConfigPath C:\path\to\config.toml `
  -Cwd .
```

operator が `VERIFY` を明示入力した後、verifier は non-project-controlled System32 command を `request_host_command` → immutable approval verification → one-shot claim → SYSTEM worker → non-elevated child → postflight → durable latch clear まで実行します。

同時に runtime-user token から service／SYSTEM worker に対する PROCESS_TERMINATE、SUSPEND_RESUME、CREATE_THREAD、VM_WRITE／VM_OPERATION、DUP_HANDLE、SET_INFORMATION、WRITE_DAC／WRITE_OWNER、sensitive token rights、thread terminate／suspend／set-context、SCM stop／change-config 等が拒否されることを実測します。ProgramData authority state の enumerate／write denial と child authority retention も確認します。

### Abnormal path

`verify-approved-host-authority-abnormal.ps1` を 3 phase で実行します。

1. 非昇格 runtime user: `-Phase Arm`
   - `WMIC.exe process call create` / `Win32_Process.Create` で requester-user の Job 外 `ping.exe -t` helper が実在することを PID／create-time／executable で確認。
   - Approved Host SYSTEM worker と legacy pending approval を handoff に固定。
   - `ABNORMAL_ARM_READY` を出した後も Arm process 自身を生かし、authenticated authority probe が service restart 後の recovery state を確認するまで待つ。operator の shell-switch 時間に依存しない。
2. elevated Administrator: `-Phase KillAndRestart`
   - handoff の PID／create-time／executable が一致する SYSTEM worker だけを fault injection として kill。
   - kill 前／kill 後／service restart 後で immutable `active.json` SHA-256 が同一であることを確認。
   - WMI-created Job 外 helper が kill 前／worker loss 後／service restart 後のすべてで同一 PID／create-time／executable のまま生存することを確認。
   - `recovery_required` が service restart を跨ぐことを確認。
3. 非昇格 runtime user: `-Phase Check`
   - authority が healthy に戻らず、service epoch transition と元 operation の authenticated recovery binding が成立していること。
   - ProgramData state enumerate／create／delete／replace が拒否されること。
   - abnormal Host 前に作った pending approval の generation が使えず、approval UI を迂回して claim しても Executor authority gate で worker／child を spawn できないこと。
   - exact WMI helper identity を再確認した後、その helper だけを cleanup すること。

WMIC optional feature がない PC では mandatory WMI abnormal-path live verification を完了したとは扱いません。別の preinstalled non-project-controlled WMI/CIM client で同等 evidence を実装するか WMIC feature を有効化してから確認します。

### Recovery path

abnormal `Check` 成功後は evidence をレビューし、標準 coordinated recovery を実行します。その後 `active.json`／`active-status.json` と canonical postflight pending marker がなく、service が Running／LocalSystem であることを確認し、normal-path verifier をもう一度実行して product availability が安全に回復したことまで確認します。

## Current status

LocalSystem authority、requester-token launch、durable state、restart recovery、WMI requester-user census、runtime-user monitor-stop denial、normal／abnormal live verifier は実装済みです。実 Windows では normal path と synchronized abnormal Arm／KillAndRestart／Check が成功し、worker loss と service restart を跨いで同一 immutable `active.json` hash、`recovery_required`、Job 外 WMI helper identity、legacy approval spawn denial を確認しました。

その後、旧 authority-only recovery を実行すると SYSTEM `active.json` は正常に archive／clear された一方、user-owned `approved-host-postflight-pending.json` が残り、post-recovery normal operation が `assert_control_plane_healthy()` で拒否される lifecycle gap を実機で検出しました。これは security latch が失敗したのではなく、explicit recovery が二つの durable latch を一体で解除できず intended Approved Host availability を回復できない product/recovery defect でした。

現在の candidate は coordinated recovery、digest／stable-identity-bound postflight quarantine、interruption resume、historical split-recovery compatibility を追加しています。この新 recovery implementation について CI と実 Windows の compatibility recovery、再度の abnormal → coordinated recovery → post-recovery normal path が成功するまでは WLMCP-R2-001 を `fixed / closed` としません。

R2-001 専用 live verifier は別 finding WLMCP-R3-002 の `workspace_write=false` materialization 経路に依存しないよう、non-project-controlled command を `workspace_write=true` で実行します。
