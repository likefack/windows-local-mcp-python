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
9. protected information への read access は Broker policy と OS boundary の両方で deny し、Git config/filter 等を経由した stdout/stderr への持ち出しを許可しません。
10. security fix、hardening、test correction、documentation correction の名目で、この capability を再び恒久停止する場合は trusted operator の明示承認を必要とします。

## Current implementation contract

Automatic Git は第五の policy tier ではありません。固定 Git grammar を持つ Broker primitive であり、内部 containment engine として live-verified Codex Windows Sandbox、WFP loopback guard、Windows Job Object、brokered-process denial preflight を再利用します。

Git child は live `workspace_root` や `data_dir` を直接読みません。Broker は operation ごとに `sandbox_scratch_dir/git-broker/` 配下へ bounded disposable repository projection を作成し、protected worktree file、`.gitattributes`、`.git/info/attributes`、hooks、submodule metadata、external object alternates、extended repository metadata を除外または拒否します。source `.git/config` は raw bytes を scratch へ書かず trusted Broker memory 上で解析し、必要な inert `core` settings だけを sanitized config として projection に生成します。

Git child の environment は system/global Git config、system attributes、credential prompt、optional lock、Git protocol access を無効化し、PATH は workspace、`data_dir`、scratch を除外した trusted dependency path に限定します。Git child と descendant は disposable projection 以外へ write capability を持たず、source workspace と control-plane は Sandbox policy で deny します。Approved Host への automatic fallback はありません。

## Git-specific live verification

Generic Codex Sandbox の route eligibility だけでは Automatic Git の availability とみなしません。Automatic Git は追加で Git-specific live marker schema v1 を要求します。

Git-specific marker は次へ exact binding します。

- pinned `git.exe` の path、SHA-256、stable file identity、size、mtime/provenance
- Codex Sandbox backend identity と Automatic Git containment policy digest
- current generic Sandbox live evidence 全体の digest
- current `workspace_root`
- source workspace deny、sanitized disposable projection、network deny、host fallback 禁止という route policy

Automatic Git は generic Sandbox で受容済み residual risk とされる property を継承して自動実行を許可しません。Git-specific route では `filesystem_read`、`filesystem_write`、`protected_information_read`、`internet`、`lan`、`loopback`、`descendant_containment`、`termination`、`resource_bound` の全 property が `verified` であることを要求します。

明示的な `verify-git-broker` は pinned Git を同じ containment 内で実際に起動し、少なくとも worktree 認識、top-level projection binding、read-only status の E2E を確認してから marker を atomic に更新します。通常 operation は marker を自動生成・repair せず、missing/stale/failed marker なら fail closed します。worker は queue 時の validation だけに依存せず、child launch 直前にも Git-specific marker を再検証します。

## 2026-08-27 operator decision

2026-08-24 以降の main では、workspace-controlled Git repository metadata を confinement できないことを理由に automatic Git Broker execution が全面 fail-closed となっていました。

2026-08-27、trusted operator は Automatic Git Broker を安全に復元する root remediation の実装開始を指示しました。

したがって、全面 fail-closed は歴史的な temporary capability reduction として扱い、最終仕様として固定しません。root remediation は、固定 Git grammar と executable identity binding を維持したまま OS containment、sanitized disposable repository projection、metadata validation、resource/process/network boundary、Git-specific live verification を追加し、`git_info` と `execute_readonly` の正常 E2E を復元することを完了条件とします。

実装と unit/CI regression が存在しても、その PC で `verify-git-broker` が成功して current marker が存在するまでは `available=false` が正しい表示です。real-machine verification を実施していない branch/CI の結果を Windows live verification の代替にはしません。
