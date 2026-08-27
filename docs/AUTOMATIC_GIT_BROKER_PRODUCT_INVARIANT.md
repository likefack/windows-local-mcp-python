# Automatic Git Broker Product Invariant

## 目的

Automatic Git Broker は、`git_info` および `execute_readonly` の固定 Git 読み取りを、人間の個別承認なしで安全に実行するための Broker capability です。

この capability は、Git executable の本人性だけでなく、workspace-controlled repository metadata が Git の挙動へ与える影響を OS-level containment と固定文法で閉じることを前提にします。

## 非交渉要件

1. Automatic Git Broker の security finding を、Git execution 自体の恒久停止・全面 fail-closed だけで最終解決してはなりません。trusted operator が具体的な capability reduction を明示承認した場合を除きます。
2. `git_info`、`execute_readonly` の Git route、固定 Git snapshot が実際に Git child を起動できることを product capability として維持します。
3. Git child は通常 Broker process の unrestricted Windows user authority で直接実行しません。固定 Git grammar を Broker primitive として維持しつつ、内部実装では OS-enforced containment を使用します。
4. repository-controlled `.git/config`、attributes、filters、hooks、object alternates、gitfile、reparse point、external helper 等を trusted input とみなしません。危険な metadata が存在しても workspace 外 read/write、control-plane access、network access、project-controlled executable executionへ作用を拡大できないことを主境界とします。
5. Git executable は trusted operator が固定した絶対 path、SHA-256、stable file identity を実行直前まで binding し、replacement を拒否します。
6. Automatic route は repository metadata root が workspace 内の実 `.git` directory である場合だけ許可します。外部 gitdir、reparse/junction、unsafe hardlink、ADS、未検証 filesystem feature は fail closed とし、必要なら承認済み route へ送ります。
7. network capability は付与しません。Internet、LAN、未許可 loopback を OS-level boundary と live verification で deny します。
8. process tree は Job Object の process/memory/kill-on-close boundary に収容し、Job 外 process creation を live verification で否定できない環境では automatic Git を available と表示しません。
9. protected information への read access は Broker policy と OS ACL の両方で deny し、Git config/filter 等を経由した stdout/stderr への持ち出しを許可しません。
10. security fix、hardening、test correction、documentation correction の名目で、この capability を再び恒久停止する場合は trusted operator の明示承認を必要とします。

## 2026-08-27 operator decision

2026-08-24 以降の main では、workspace-controlled Git repository metadata を confinement できないことを理由に automatic Git Broker execution が全面 fail-closed となっていました。

2026-08-27、trusted operator は Automatic Git Broker を安全に復元する root remediation の実装開始を指示しました。

したがって、現在の全面 fail-closed は歴史的な temporary capability reduction として扱い、最終仕様として固定しません。root remediation は、固定 Git grammar と executable identity binding を維持したまま OS containment、metadata validation、resource/process/network boundary、live verification を追加し、`git_info` と `execute_readonly` の正常 E2E を復元することを完了条件とします。
