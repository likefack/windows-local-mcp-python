# 検証記録

## 2026-08-28 WLMCP-R2-001 LocalSystem authority remediation — LIVE VERIFIED

### Current verdict

- Finding: `WLMCP-R2-001 — High`。
- Root cause 判定: `valid`。旧 architecture では Approved Host child と monitor／postflight worker が同一 Windows user authority にあり、child が監視側を停止すると trusted postflight path を失い、restart reconciliation だけでは durable tamper latch が残らなかった。
- Remediation: monitor／postflight authority を LocalSystem service 配下へ分離し、実 command だけを verified non-elevated requester-user token で起動する構成へ変更した。same-desktop UAC elevation は security boundary として採用しない。
- Final disposition: `fixed / live verified`。
- Security code candidate: `bb66eb30a6b7a8cf3f174d576f8eaed0687eb14c`。
- この verdict 後の commit は documentation-only sync であり、下記実機 security evidence の対象 code は上記 candidate である。
- PR #27 は 2026-08-28 に merge / closed。main merge commit は `63e3e75b4bf9fb1cf9ce8cef9c4eb1380b3e264a`。
- 後続の PR #26 Automatic Git integration は Approved Host authority separation を保持したまま main へ統合され、最終 main merge commit は `a466f86e46a635e9390569971d6d1ee160d77dbf`。Automatic Git の実機 E2E を Approved Host の新しい release-level live verification として扱わない。

pre-closure の詳細な検証履歴、過去の capability-reduction checkpoint、Security Scan Round 2 の当時判定、Codex Sandbox／WFP／その他の historical evidence は `VERIFICATION_HISTORY_PRE_R2_001_CLOSURE.md` に byte-identical blob として保存する。historical section 内の `pending`／`unresolved`／`BLOCKED` は各時点の記録であり、この current verdict を上書きしない。

### Current security boundary

- production service: `WindowsLocalMCPApprovedHost` / LocalSystem / protected SCM DACL。
- durable state: `%ProgramData%\WindowsLocalMCP\ApprovedHostAuthority` / LocalSystem owner / protected SYSTEM+Administrators DACL。
- final command: authenticated pipe requester PID／create-time／SID／non-elevated token を検証し、`CreateProcessAsUserW` で suspended child を作成する。child を SYSTEM へ昇格しない。
- SYSTEM worker-owned Job Object へ child を assign してから resume する。
- requester-user WMI／CIM process census を保持し、`Win32_Process.Create` 等による Job 外 same-user helper を postflight まで fail closed に追跡する。
- SYSTEM-owned immutable `active.json` は normal verified completion まで残す。worker loss、service restart、channel loss、postflight uncertainty、epoch mismatch では解除せず `recovery_required` とする。
- user-owned `approved-host-postflight-pending.json` を第二 latch とし、SYSTEM authority state だけの解除で operations が自動再開しないようにする。
- explicit recovery は elevated Administrator の reviewed coordinated recovery のみ。bound postflight marker を operation id、SHA-256、stable file identity で確認・quarantine してから subordinate state を処理し、immutable `active.json` を最後に削除する。
- runtime user／Approved Host child に service stop/change-config、monitor cancellation、SYSTEM worker の terminate／suspend／duplicate-handle／VM-write／token-manipulation authority を与えない。
- project-controlled code-loader と workspace executable は Approved Host で拒否し、Sandbox failure から Host へ automatic fallback しない。

### Final hosted regression checkpoint

Security code candidate `bb66eb30a6b7a8cf3f174d576f8eaed0687eb14c` に対する Windows CI run #402 / run id `33122963524` は全 job 成功。

- focused process identity security regression: `17 passed`
- focused race／recovery／transaction regression: `38 passed`
- focused WLMCP-R2-001 authority regression: `49 passed`
- full pytest: `506 passed in 111.26s`
- Ruff: pass
- compileall: pass
- PowerShell parser: pass
- diff whitespace: pass

Hosted CI は OS authority separation の代替証拠ではないため、以下の実 Windows lifecycle を別途完了した。

### Immutable runtime live verification

通常の非管理者 runtime user から `verify-approved-host-runtime.ps1` を実行。

- scope: `complete-runtime`
- digest: `e403e846d0af50a1fa330400350bf6f5085d1866fd3bfe419ada558c06a60bc5`
- ancestor directories: `2`
- directories: `1211`
- files: `14818`
- paths: `16031`
- result: `Approved Host immutable-runtime verification PASSED.`

### Normal path before fault injection — PASS

Operation `fc1db167-ed6f-42ed-ad7c-8f8116239be6`。

- child authority: same non-elevated runtime user
- durable authority state: runtime-user enumerate/write denied
- monitor authority: LocalSystem sensitive rights denied to runtime user
- requester SID: `S-1-5-21-1787218830-4025776409-3138769905-1001`
- service epoch remained stable: `231ea540adbf1e80f2f20fd986a4357d4aec9d55b518e3b03620e111d740b81c`
- status: `passed`
- final output: `Approved Host authority normal-path live verification PASSED.`

### Fresh synchronized abnormal path — PASS

Operation `d7cf5dec-8c5e-48b2-a109-2ecec82672d9`。

- SYSTEM worker PID: `21304`
- verified WMI／`Win32_Process.Create` Job-external helper: `C:\Windows\System32\PING.EXE`, PID `53036`
- initial service epoch: `231ea540adbf1e80f2f20fd986a4357d4aec9d55b518e3b03620e111d740b81c`
- recovery service epoch: `155242ee1a1cda201d4eb9b49244cf9f8e628e531df09ce34224405cfbc8251f`
- Arm remained alive after `ABNORMAL_ARM_READY` and observed authenticated recovery after the service epoch changed。
- elevated `KillAndRestart` verified exact SYSTEM worker identity before fault injection and exact WMI helper PID／create-time／executable before worker loss、after worker loss、after service restart。
- immutable `active.json` SHA-256 remained identical before kill、after kill、after restart、and at evidence review: `2385EBDB71B2311E5504B9350B59A1FB30B97CC400D51B5C1DF5C40BA7FB567F`。
- `active-status.json.state` remained `recovery_required` across service restart。

Abnormal `Check` result:

- `authority_healthy=false` — explicit recovery 前の期待値
- `legacy_generation_blocked=true`
- `legacy_worker_spawn_blocked=true`
- `service_epoch_transition_verified=true`
- `state_tamper_denied=true`
- WMI helper survived worker loss／restart, exact identity was reverified, then only that helper was cleaned up
- status: `passed`
- final output: `Abnormal worker-loss/WMI/restart/legacy-approval verification PASSED.`

### Durable recovery evidence review — PASS

handoff、administrator evidence、`active.json`、`active-status.json`、user-owned postflight marker はすべて operation `d7cf5dec-8c5e-48b2-a109-2ecec82672d9` に binding されていた。

- `active-status.json.state = recovery_required`
- postflight marker state: `postflight_pending`
- postflight marker SHA-256: `7950489679d87bd4eab2650e40d387e2a40885094cb318d4734d3f30f1412e49`
- independent `tamper-detected.json`: absent
- authority service: Running / Auto / LocalSystem

### Coordinated recovery — PASS

Current `recover-approved-host-authority.ps1 -ConfigPath ... -AcknowledgeReviewedState` のみを使用した。historical split-recovery compatibility path は使用していない。

Recovery archive:

`C:\ProgramData\WindowsLocalMCP\ApprovedHostAuthority\completed\recovery-20260827T230138194Z-fd23f3a167174c54bb6e575f3fbcd3a2.json`

Quarantine:

`C:\Users\22905\AppData\Local\WindowsLocalMCP-R2-001-Live\control-plane\approved-host-postflight-recovered-d7cf5dec-8c5e-48b2-a109-2ecec82672d9-7950489679d87bd4.json`

- archive version: `2`
- archive state: `operator_recovered`
- postflight preflight／quarantine operation id: fresh abnormal operation と一致
- quarantine SHA-256: preflight marker と同一
- stable file identity: quarantine move 前後で同一
- `quarantined=true`
- `resumed_partial_recovery=false` — fresh coordinated path が最初から最後まで完了した証拠
- recovery 後 `active.json`／`active-status.json` は absent
- authority service は Running / Auto / LocalSystem へ復帰
- independent tamper marker を recovery path は解除していない

### Post-recovery normal path — PASS

Operation `cb890f60-c8b4-4784-8b5e-725f904ac738`。

- child authority: same non-elevated runtime user
- durable authority state: runtime-user enumerate/write denied
- monitor authority: LocalSystem sensitive rights denied to runtime user
- requester SID: `S-1-5-21-1787218830-4025776409-3138769905-1001`
- initial/final service epoch: `cab773eed279823ca5b3f6faf04a93bc29d40b0b722d4da42382059772dc0d04`
- status: `passed`
- final output: `Approved Host authority normal-path live verification PASSED.`

### Additional real-machine blockers discovered and remediated

Live verification 自体を security design review の一部として扱い、実機で露呈した blocker も closure 前に root fix した。

1. historical split recovery が SYSTEM-owned authority latch だけを解除し、user-owned `approved-host-postflight-pending.json` を残して後続 operation を恒久停止させ得た。標準 recovery を authority＋bound postflight の coordinated transaction に変更した。
2. recovery script は authority service を意図的に停止する一方、recovery helper が normal-operation 用 authority health gate を呼び、停止した同じ pipe を要求する self-dependency があった。recovery-specific marker verification を normal authority-availability gate から分離し、通常 operation の authenticated service requirement は維持した。
3. `_acl_state_digest()` が directory と exact file を区別せず全 root に `icacls <root> /T /C` を実行し、実機では config file `C:\dev\wlmcp-r2-001-live-config.toml` の preflight が 30 秒 timeout した。directory は recursive `/T /C` を維持し、single file は exact-file `/C` のみに変更した。directory recursion を弱めず root type ごとの regression を追加した。
4. immutable-runtime installer／ACL preflight の複数の実機 blockerについて、runtime user RX、SYSTEM/Admin F、protected root inheritance、safe old-runtime replacement、volume-root DELETE semantics を修正し、最終 complete-runtime verification を通過した。

### Closure rule

以上により、security code candidate `bb66eb30a6b7a8cf3f174d576f8eaed0687eb14c` では次の mandatory lifecycle が同一 real Windows environment で完了した。

`normal operation → SYSTEM worker loss → Job-external WMI helper survival → service restart + durable recovery_required → stale/legacy execution rejection → exact helper cleanup → reviewed coordinated recovery → restored normal operation`

WLMCP-R2-001 は `fixed / live verified` とする。これは別 PC、別 runtime、別 service configuration、または authority/security-boundary code の変更後にも自動的に live-verified とみなす意味ではない。production execution は各環境で immutable runtime と authenticated LocalSystem authority service の current preflight を引き続き要求し、security boundary を変更した場合は normal／abnormal／recovery lifecycle を再検証する。

## Historical verification record

WLMCP-R2-001 closure 前の詳細な repository-wide verification chronology は `VERIFICATION_HISTORY_PRE_R2_001_CLOSURE.md` を参照する。そこに記録された古い `LIVE VERIFICATION PENDING`、capability-reduction、Round 2 `unresolved / release blocker` 等は historical point-in-time evidence として保持し、上記 current verdict により supersede される。
