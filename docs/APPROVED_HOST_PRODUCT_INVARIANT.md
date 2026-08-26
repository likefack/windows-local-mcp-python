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

## WLMCP-R2-001 に関する operator decision

2026-08-27、WLMCP-R2-001 の対処として current v1 の Approved Host execution を全面的に fail closed にし、capability reduction をもって finding を close する変更が main に入りました。

trusted operator はこの対処を product concept に反するとして拒否しました。

このため、以下を current operator decision として固定します。

- Approved Host を全面停止することは WLMCP-R2-001 の受容可能な最終修正ではありません。
- `VERIFICATION.md` にある `fixed by capability reduction / closed` という記録は、その時点で exploit sink を停止した技術的 mitigation の履歴としてのみ扱います。product requirement を満たした root remediation の受容記録として扱ってはなりません。
- 現在の実装が Approved Host execution を停止している間、その状態は security mitigation であると同時に既知の product regression です。
- WLMCP-R2-001 の最終 remediation は、Approved Host の intended function を復元したうえで、same-user monitor termination / postflight bypass を成立させない security boundary を実装・検証する必要があります。
- 将来の agent は、現在の全面停止状態を precedent として別 finding に capability reduction を適用してはなりません。

## セキュリティ修正時の判断手順

Approved Host または他の中核 capability に security finding がある場合は、次の順序で判断します。

1. finding が成立するかを検証する。
2. exploit の root cause と守るべき product capability を別々に特定する。
3. capability を維持する root fix を優先して設計する。
4. root fix が現在の task / architecture で成立しない場合、その事実を報告し、必要な architecture change と選択肢を提示する。
5. trusted operator の明示承認なしに、機能削除・全面停止・意味的縮小を final fix として採用しない。
6. 一時 mitigation が必要なら、temporary であること、失われる capability、未解決 finding を明記する。
7. 最終 verification は security invariant と intended product function の両方を regression test / live verification の対象にする。

## Approved Host を安全に再設計する場合の最低条件

具体的な実装方式は固定しません。ただし、WLMCP-R2-001 のような monitor termination / postflight bypass を閉じる場合、少なくとも次を同時に満たす設計を要求します。

- Approved Host child が monitor / postflight owner を停止・改変できないこと。
- Approved Host child が durable tamper / pending state を削除・偽造できないこと。
- worker / server abnormal termination 後も security-relevant state が restart を跨いで fail closed に残ること。
- 正常 operation と crash / kill / out-of-Job helper / restart recovery を区別して検証できること。
- one-shot human approval と immutable input binding を維持すること。
- Approved Host が本来必要とする通常 Windows user authority を失わないこと。
- Codex Sandbox / Broker で代替不能な処理を Approved Host で実行できることを regression で確認すること。

別 user、別 session、SYSTEM service、service-owned durable state、ACL / token separation 等は候補になり得ますが、特定方式の採用自体を保証とみなしません。実際の Windows authority boundary と bypass resistance を検証して初めて根拠とします。

## ドキュメントの優先関係

この文書は Approved Host の product intent に関する trusted operator の明示決定を記録します。

`SECURITY_CONTRACT.md`、`SPEC.md`、`README.md`、`VERIFICATION.md` に current implementation の全面停止を permanent / accepted design と読める記述が残っている場合、それはこの operator decision と衝突します。その衝突を理由に全面停止を正当化せず、差異を報告し、Approved Host の安全な機能復元に合わせて関連文書を整合させます。

security invariant を弱める指示ではありません。要求は「安全性を下げて機能を残す」ことではなく、「安全性と Approved Host の中核機能の両方を満たす修正を行う。両立できない間は未解決として扱う」ことです。
