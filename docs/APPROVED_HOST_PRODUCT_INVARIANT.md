# Approved Host Product Invariant

## 目的

Approved Host は Windows Local MCP の中核 execution route です。

Codex Sandbox または Broker では実行できない、またはそれらの security boundary では必要な host authority を持てない処理について、trusted operator が内容を確認し、明示的に承認した場合に限って、通常の Windows user authority で実行するために存在します。

したがって Approved Host は optional な convenience feature ではありません。Sandbox / Broker で実行不能な処理を人間の明示承認で実行可能にするという product concept を担っています。

## 非交渉要件

次を product invariant とします。

1. Approved Host の安全性を修正するために、Approved Host execution 自体を恒久的に削除・全面停止・常時 fail closed にしてはなりません。
2. 脆弱な route を停止しただけで、その脆弱性を `fixed` / `closed` として最終処理してはなりません。
3. `request_host_command`、approval state、worker launch、Host execution capability のいずれかを実質的に無効化する capability reduction は、trusted operator がその具体的な縮小を明示承認した場合に限って final design として採用できます。
4. Security Contract を満たすために architecture change が必要なら、monitor / postflight owner、durable tamper state、Windows principal / session、service boundary、process authority 等の根本境界を修正します。機能停止を根本修正の代用にしません。
5. 現行 architecture で安全性と機能維持を同時に満たせない場合、finding は `valid / unresolved`、`blocked`、または同等の未解決状態として残します。機能を壊して release blocker を消すことを優先しません。
6. 一時的な exploit containment として fail closed にすることは可能ですが、その場合は `temporary mitigation` と `product regression` を明記し、root fix と区別します。trusted operator の明示承認なしに、その一時停止を恒久仕様へ昇格させません。
7. Security fix、refactor、hardening、documentation correction、test correction の名目であっても、中核 product capability を意味的に縮小する変更は通常の実装修正より高い承認閾値を持ちます。必ず trusted operator に明示確認します。
8. abnormal operation を安全に fail closed にするだけでは不十分です。trusted operator が durable evidence をレビューして explicit recovery を行った後、security boundary を弱めずに Approved Host の intended function を再び利用可能にできなければなりません。永久 latch は最終 design として受容しません。

## WLMCP-R2-001 に関する operator decision

2026-08-27、WLMCP-R2-001 の対処として current v1 の Approved Host execution を全面的に fail closed にし、capability reduction をもって finding を close する変更が main に入りました。

trusted operator はこの対処を product concept に反するとして拒否しました。

このため、以下を current operator decision として固定します。

- Approved Host を全面停止することは WLMCP-R2-001 の受容可能な最終修正ではありません。
- `VERIFICATION.md` にある旧 `fixed by capability reduction / closed` 記録は、その時点で exploit sink を停止した temporary mitigation の履歴としてのみ扱います。product requirement を満たした root remediation の受容記録ではありません。
- WLMCP-R2-001 の最終 remediation は、Approved Host の intended function を復元したうえで、same-user monitor termination / postflight bypass を成立させない security boundary を実装・検証する必要があります。
- abnormal state は explicit reviewed recovery まで fail closed に残し、recovery 後は正常 Approved Host operation が再び成立することまで検証対象とします。
- 将来の agent は旧全面停止状態を precedent として別 finding に capability reduction を適用してはなりません。

## Current root remediation

現行 main は上記 operator decision に従い、Approved Host を停止するのではなく authority boundary を変更しています。

- monitor／postflight worker は LocalSystem service `WindowsLocalMCPApprovedHost` 配下で実行する。
- 実 Approved Host command は、verified named-pipe requester の元の非昇格 Windows user token を `CreateProcessAsUserW` で使用する。child を SYSTEM に昇格しない。
- SYSTEM worker は child を suspended 作成し Job Object に割り当ててから resume する。
- WMI／CIM provider が Job 外に作る process の census は SYSTEM user ではなく元 requester user の PID／create-time を追う。
- durable `active.json` は `%ProgramData%\WindowsLocalMCP\ApprovedHostAuthority` の LocalSystem-owned protected namespace に置き、normal completion まで immutable とする。
- running／recovery 状態は sidecar に分け、service epoch、authority nonce、requester identity、worker context を binding する。
- runtime-user control plane 側にも operation-bound `approved-host-postflight-pending.json` を第二 latch として保持し、trusted postflight path が失われた場合は authority latch だけを解除しても operations を再開しない。
- worker kill、service restart、channel loss、unhandled exception、postflight mismatch、Job 外 helper 残存では valid normal-completion proof が成立せず latch を解除しない。
- runtime user／Approved Host child には service stop/change-config、monitor cancel、SYSTEM worker terminate/suspend/duplicate-handle/VM-write/token-manipulation 等の authority を与えない。
- active Approved Host の `stop_job` は runtime-user control plane から monitor を停止する primitive にならないよう拒否する。これは Host execution capability の削除ではなく、independent monitor survival の security invariant とする。
- explicit recovery は SYSTEM authority latch と同じ operation に binding された user-owned postflight latch を一体で扱い、postflight marker の schema／operation id／reviewed digest／stable file identity を immutable runtime で検証する。independent tamper latch は解除しない。
- recovery ordering は postflight marker quarantine を `active.json` 削除より先に行い、SYSTEM `active.json` を最後に消す。marker mismatch／missing／race では authority latch を残して fail closed にする。
- recovery が postflight quarantine 後に中断しても digest-bound quarantine から再開可能とし、recovery failure で authority service を停止したまま残さない。

この architecture は source／tests 上の実装だけでは受容せず、実 Windows の SCM DACL、ProgramData DACL、process/thread/token access、requester-token child authority、WMI job-external helper、worker kill、service restart、coordinated recovery、recovery 後の normal operation まで live verification しました。

Current status は `fixed / live verified` です。実証済み環境と証拠の範囲、別環境・security boundary変更時の再検証条件は `VERIFICATION.md` を正本とします。

## セキュリティ修正時の判断手順

Approved Host または他の中核 capability に security finding がある場合は、次の順序で判断します。

1. finding が成立するかを検証する。
2. exploit の root cause と守るべき product capability を別々に特定する。
3. capability を維持する root fix を優先して設計する。
4. root fix が現在の task / architecture で成立しない場合、その事実を報告し、必要な architecture change と選択肢を提示する。
5. trusted operator の明示承認なしに、機能削除・全面停止・意味的縮小を final fix として採用しない。
6. 一時 mitigation が必要なら、temporary であること、失われる capability、未解決 finding を明記する。
7. 最終 verification は security invariant と intended product function の両方を regression test / live verification の対象にする。
8. abnormal fail-closed state を作った verification は、explicit recovery と post-recovery normal operation まで完了して初めて lifecycle verification とする。

## Approved Host の最低 security conditions

具体的な実装方式の名前だけを保証とみなしません。少なくとも次を同時に実証する必要があります。

- Approved Host child が monitor / postflight owner を terminate、suspend、thread-kill、inject、VM-write、handle-duplicate、token-manipulate、security-descriptor rewrite できないこと。
- Approved Host child が durable tamper / pending / recovery / epoch state を削除・置換・偽造・rollback できないこと。
- worker / server / UI / service abnormal termination 後も security-relevant state が restart を跨いで fail closed に残ること。
- 正常 operation と crash / kill / out-of-Job helper / channel loss / restart recovery を自律的に区別し、child が normal completion を偽造できないこと。
- one-shot human approval、TTL、immutable input／manifest／executable identity binding を維持すること。
- project-controlled code-loader と workspace executable を Approved Host で実行しない既存境界を維持すること。
- Approved Host command 自体は本来必要とする通常 Windows user authority を失わないこと。
- Codex Sandbox / Broker で代替不能な non-project-controlled command を Approved Host で正常実行できることを regression／live E2E で確認すること。
- explicit operator recovery が live monitor stop primitive にならず、reviewed abnormal state にだけ作用すること。
- recovery 後に canonical authority／postflight latch が消え、正常 Approved Host operation を再利用できること。
- Sandbox／Broker の既存 security regressions を弱めないこと。

## Required Windows live verification

最終受容には少なくとも以下を要求します。

1. normal path: request → local one-shot approval → SYSTEM worker → ordinary non-elevated requester-user child → postflight → latch clear。
2. runtime-user token から authority service／SYSTEM worker の sensitive process/thread/token/SCM rights が拒否されること。
3. durable ProgramData state の enumerate／create／delete／replace が runtime user から拒否されること。
4. `Win32_Process.Create` で requester-user の Job 外 helper が実在する状態を確認すること。
5. verified SYSTEM worker identity を fault injection で kill しても immutable latch が残ること。
6. service restart 後も同じ latch が残り `recovery_required` であること。
7. WMI-created Job 外 helper が worker loss と service restart を同一 PID／create-time／executable identity で跨ぐこと。
8. abnormal Host 前に作った legacy pending approval が generation check／Executor authority gate を bypass できないこと。
9. explicit administrator recovery が live monitor の stop API にならず、SYSTEM authority latch と bound postflight latch を reviewed operation として coordinated に解除できること。
10. recovery 後に authority service が Running／LocalSystem、canonical recovery latches が absent で、normal Approved Host E2E が再び成功すること。

GitHub Hosted Windows の unit/integration test はこの OS-level live evidence の代替ではありません。

## 実機で検出した recovery lifecycle gap

2026-08-28 の root-remediation live verification では、normal path と synchronized abnormal Arm／worker kill／service restart／Check まで成功しました。SYSTEM `active.json` は kill 前後／restart 後で同一 SHA-256 のまま残り、`recovery_required`、Job 外 WMI helper survival、runtime-user state tamper denial、legacy approval spawn denial を確認しました。

その後、旧 `recover-approved-host-authority.ps1` で SYSTEM latch だけを explicit recovery すると、`active.json`／`active-status.json` と service state は正常に回復した一方、user-owned `approved-host-postflight-pending.json` が残りました。post-recovery normal verification は `assert_control_plane_healthy()` により正しく fail closed し、Approved Host availability は復元しませんでした。

この結果を隠したり marker を手動削除したりせず、recovery workflow 自体の defect として修正しました。standard recovery を coordinated dual-latch recovery に変更し、旧 recovery 済み state 専用の protected version-1 archive-bound compatibility path を追加しました。その後、fresh abnormal path、coordinated recovery、post-recovery normal pathを同一実 Windows環境で完了したため、WLMCP-R2-001は `fixed / live verified` です。

## ドキュメントの優先関係

この文書は Approved Host の product intent に関する trusted operator の明示決定を記録します。

`SECURITY_CONTRACT.md`、`SPEC.md`、`README.md`、`VERIFICATION.md` に旧 temporary capability reduction を permanent / accepted current design と読める記述が残っている場合、それはこの operator decision と衝突します。その衝突を理由に全面停止を正当化せず、LocalSystem authority remediation と検証状態に合わせて関連文書を整合させます。

security invariant を弱める指示ではありません。要求は「安全性を下げて機能を残す」ことではなく、「安全性と Approved Host の中核機能の両方を満たす修正を行う。両立を実証できない間は未解決として扱う」ことです。
