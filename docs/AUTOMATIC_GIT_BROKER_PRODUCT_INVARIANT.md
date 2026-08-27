# Automatic Git Broker Product Invariant

## 目的

Automatic Git Broker は、`git_info` および `execute_readonly` の固定 Git 読み取りを、人間の個別承認なしで安全に実行するための Broker capability です。

この capability は、Git executable の本人性だけでなく、workspace-controlled repository metadata が Git の挙動へ与える影響を OS-level containment と固定文法で閉じることを前提にします。

## 非交渉要件

1. Automatic Git Broker の security finding を、Git execution 自体の恒久停止・全面 fail-closed だけで最終解決してはなりません。trusted operator が具体的な capability reduction を明示承認した場合を除きます。
2. `git_info`、`execute_readonly` の Git route、固定 Git snapshot が実際に Git child を起動できることを product capability として維持します。
3. Git child は通常 Broker process の unrestricted Windows user authority で直接実行しません。固定 Git grammar を Broker primitive として維持しつつ、内部実装では OS-enforced containment を使用します。
4. repository-controlled `.git/config`、attributes、filters、hooks、object alternates、gitfile、reparse point、external helper 等を trusted input とみなしません。危険な metadata が存在しても workspace 外 read/write、control-plane access、network access、project-controlled executable executionへ作用を拡大できないことを主境界とします。
5. Git executable は trusted operator が固定した絶対 path、SHA-256、stable file identity を実行直前まで binding し、replacement を拒否します。Git for Windows の既知 wrapper／redirector を primary trust anchor とせず、実際に Git command を実装する runtime executable を直接 pin します。
6. Automatic route は repository metadata root が workspace 内の実 `.git` directory である場合だけ許可します。外部 gitdir、reparse/junction、security-relevant hardlink、nested `.git`、external/extended metadata、検証不能な required input は fail closed とします。source file の named NTFS ADS は Git が受け取る unnamed data stream とは別の metadata として projection boundary で切り落とし、staged projection に named ADS が存在することは引き続き拒否します。
7. Git process の Windows process cwd を project-controlled projection にしません。process は trusted runtime executable directory から起動し、repository selection は Broker が固定挿入する `git -C <sanitized projection cwd>` によって行います。
8. network capability は付与しません。Internet、LAN、未許可 loopback を OS-level boundary と live verification で deny します。
9. process tree は Job Object の process/memory/kill-on-close boundary に収容し、Job 外 process creation を live verification で否定できない環境では automatic Git を available と表示しません。
10. protected information への read access は Broker policy と OS boundary の両方で deny し、Git config/filter 等を経由した stdout/stderr への持ち出しを許可しません。projection 内の Git object database に protected file の historical blob が存在し得ることを前提にし、raw object ID、commit/tree path、index entry のいずれも protected-content provenance の根拠にはしません。
11. Automatic `diff`／`show` は metadata-only output に限定します。patch、binary patch、`--check`、または pathspec を伴う暗黙 patch output 等、Git object database の blob bytes を stdout/stderr へ出し得る content-bearing mode は `request_sandbox_command` へ送ります。fixed Git capability 全体を停止するのではなく、status／metadata diff／log／show metadata／rev-parse／ls-files／snapshot は維持します。
12. Automatic grammar で使用する Git subcommand は、Git-specific live verification で exact pinned runtime の builtin command であることを確認します。外部 `git-*` helper へ委譲される runtime を verified とみなしません。
13. security fix、hardening、test correction、documentation correction の名目で、この capability を再び恒久停止する場合は trusted operator の明示承認を必要とします。

## Current implementation contract

Automatic Git は第五の policy tier ではありません。固定 Git grammar を持つ Broker primitive であり、内部 containment engine として live-verified Codex Windows Sandbox、WFP loopback guard、Windows Job Object、brokered-process denial preflight を再利用します。

Git child は live `workspace_root` や `data_dir` を直接読みません。Broker は operation ごとに `sandbox_scratch_dir/git-broker/` 配下へ bounded disposable repository projection を作成し、protected worktree file、`.gitattributes`、`.git/info/attributes`、hooks、submodule metadata、external object alternates、extended repository metadata、nested `.git` を除外または拒否します。source `.git/config` は raw bytes を scratch へ書かず trusted Broker memory 上で解析し、1 MiB を越える config は解析前に fail closed とし、repository format v0 の必要な inert `core` settings だけを sanitized config として projection に生成します。

Source workspace 全体を projection 作成前に一括で「安全」と認定する blanket scan は security boundary としません。security property は、Git child が実際に受け取る sanitized projection を構成する入力ごとに、必要になった時点で verified handle を用いて検証します。`.git` metadata、index、refs、objects、projection へ取り込む worktree content など security-relevant input が読み取り不能・検証不能なら fail closed します。一方、Git operation の意味論上観測されず projection に取り込まれない artifact の存在だけを repository 全体の失格理由にはしません。

Ignored/generated tree の省略は「unreadable だから skip」ではありません。現在の実装は、対象 batch が ignored untracked entry を観測しないこと、root `.gitignore` の保守的に解釈可能な whole-directory pattern に一致すること、整合した通常 Git index からその subtree に tracked entry がないことを証明できる場合だけ root subtree を projection から省略します。whole-directory pattern は `/generated-*/` のような root-anchored form に加えて、`.venv/` のような single-component directory-only form も root entry との一致判定に利用できますが、nested pattern、negation、複雑な wildmatch、または安全に解釈できない形式を一般化して受理しません。`ls-files --others` のように ignored entry を観測し得る command、unsupported/malformed/split index、複雑または否定規則を含む ignore semantics、tracked descendant がある tree では pruning を行わず、required tree が検査不能なら fail closed します。planning に使う `.git/index` と `.gitignore` は projection copy 中も verified handle で pin し、同じ verified bytes を staged input として使用します。

Named NTFS ADS は source repository の blanket rejection 条件にはしません。Automatic Git が file input として読むのは verified file handle が指す unnamed data stream の bytes だけであり、destination は新規 file へその bytes を書くため source の `Zone.Identifier` 等の named stream はコピーされません。copy 完了後の sanitized projection は `reject_alternate_streams=True` で再検証し、projection に named ADS が生成・残存していれば fail closed します。ADS を path alias、executable/helper lookup、object substitution の入力として利用する経路は child に与えません。

Git object database は repository semantics のため projection に含まれますが、その blob content を Automatic Git の安全な read source とは扱いません。攻撃者は protected blob を一見安全な path の tree／commit／index entry に再結合できるため、Broker が current workspace path を検証しただけでは object content の provenance を保証できません。そのため Automatic `diff`／`show` は `--stat`、`--name-only`、`--name-status`、`--quiet`、`--no-patch` 等の metadata-only mode に限定し、patch／`--binary`／`--check`／暗黙 patch mode は拒否します。revision 自体も defense-in-depth として `^{commit}` へ binding し、range は両 endpoint を commit-bound にします。

`git_info` snapshot の Git commands も branch、HEAD、status、diff/staged の stat/name-status、recent log metadata、changed-file name-status に限定し、blob content を返しません。`ls-files --stage` が object hash を返し得ても、Automatic grammar 内にその blob bytes を dereference する content-bearing route を残しません。

Git for Windows では `cmd\git.exe` や install-root の `bin\git.exe` が別 runtime へ委譲する構成を取り得ます。Automatic Git はその wrapper／redirector の hash だけを execution identity として受理せず、通常は `mingw64\bin\git.exe`、architecture に応じて `clangarm64\bin\git.exe`／`mingw32\bin\git.exe` のような実 runtime を直接 operator pin します。Git process の process cwd はこの trusted executable directory とし、Broker が argv へ固定 `-C <sanitized projection cwd>` を挿入します。これにより projection を current-directory DLL search surface として利用しません。

Git child の environment は system/global Git config、system attributes、credential prompt、optional lock、Git protocol access を無効化し、PATH は workspace、`data_dir`、scratch を除外した trusted dependency path に限定します。さらに Broker runner は `maintenance.auto=false` と `gc.auto=0` を固定し、automatic maintenance／GC を command semantics から除外します。Git child と descendant は disposable projection 以外へ write capability を持たず、source workspace と control-plane は Sandbox policy で deny します。Approved Host への automatic fallback はありません。

Current `broker` operation だけでなく upgrade 前に残り得る legacy `safe_command`／`safe_sandbox` Git operation も `Executor` で dedicated Git worker へ収束させます。legacy row が standard worker の unrestricted child path を復活させることを許可しません。worker は original safe request、normalized command、settings digest、control-plane generation、process nonce を再検証します。

Repository projection の byte limit は configured `max_sandbox_scratch_bytes` の 1/2 以下とし、旧 16 MiB floor のように operator quota を上回る下限を持ちません。残りの scratch budget は operation 固有 runtime／transient output のために確保します。copy loop 自体にも entry-count bound を適用し、concurrent directory growth で final scan 前に scratch を無制限に増幅させません。pruned subtree の内部 entry は projection に materialize されないため quota consumption には数えませんが、その root entry の検査自体は bounded traversal の entry として扱います。scratch quota 自体も Git-specific live context に binding し、変更時は marker を stale にします。

Windows で source 側では有効な required path が長い scratch prefix の追加によって projection 側だけ legacy path limit を越える場合、raw `FileNotFoundError` 等へ崩さず、projection construction の時点で明示的な `GitBrokerUnavailable` として fail closed します。ignored/untracked tree を不要に materialize してこの制約を踏むことは上記 pruning proof で回避します。extended-length path を security-sensitive verified-handle／TOCTOU boundary と統合した live verification はまだ存在しないため、未検証の long-path bypass を自動 route へ導入しません。

## Git-specific live verification

Generic Codex Sandbox の route eligibility だけでは Automatic Git の availability とみなしません。Automatic Git は追加で Git-specific live marker schema v1 を要求します。

Git-specific marker は次へ exact binding します。

- pinned Git runtime executable の path、SHA-256、stable file identity、size、mtime/provenance
- trusted executable-directory process cwd と Broker-fixed `-C` repository selection policy
- Automatic grammar の required subcommand が pinned runtime の builtin であるという policy
- Codex Sandbox backend identity と Automatic Git containment policy digest
- Automatic Git command-policy generation v4
- current generic Sandbox live evidence 全体の digest
- current `workspace_root`
- `max_sandbox_scratch_bytes`
- source workspace deny、sanitized disposable projection、network deny、host fallback 禁止という route policy

Automatic Git は generic Sandbox で受容済み residual risk とされる property を継承して自動実行を許可しません。Git-specific route では `filesystem_read`、`filesystem_write`、`protected_information_read`、`internet`、`lan`、`loopback`、`descendant_containment`、`termination`、`resource_bound` の全 property が `verified` であることを要求します。

明示的な `verify-git-broker` は pinned runtime Git を同じ containment 内で実際に起動し、worktree 認識、strict source-workspace deny 下での read-only `status` 成功、Automatic grammar の `status`／`diff`／`log`／`show`／`rev-parse`／`ls-files` がその exact runtime の builtin であること、および同一 sanitized projection snapshot digest への probe batch binding を確認してから marker を atomic に更新します。user-facing path remap 後の `--show-toplevel` 文字列を projection 実行の独立証拠として扱いません。通常 operation は marker を自動生成・repair せず、missing/stale/failed marker なら fail closed します。dedicated worker と `git_info` が共有する runner は child launch 直前にも Git-specific marker を再検証します。

Source／CI evidence と Windows machine-local evidence の記録は `docs/AUTOMATIC_GIT_BROKER_VERIFICATION.md` に分離します。

## 2026-08-27 operator decision

2026-08-24 以降の main では、workspace-controlled Git repository metadata を confinement できないことを理由に automatic Git Broker execution が全面 fail-closed となっていました。

2026-08-27、trusted operator は Automatic Git Broker を安全に復元する root remediation の実装開始を指示しました。

したがって、全面 fail-closed は歴史的な temporary capability reduction として扱い、最終仕様として固定しません。root remediation は、固定 Git grammar と executable identity binding を維持したまま OS containment、sanitized disposable repository projection、metadata validation、resource/process/network boundary、Git-specific live verification を追加し、`git_info` と `execute_readonly` の正常 E2E を復元することを完了条件とします。

2026-08-28 の projection-boundary remediation では、source workspace 全体への blanket preflight を security guarantee として使わず、sanitized projection が実際に consume する input に検証を集中させる方針を追加しました。benign named ADS や、意味論上観測されないことを証明できる ignored/generated subtree は projection 外に切り落とせますが、security-relevant input が検証不能な場合の fail-closed rule は維持します。

実装と unit/CI regression が存在しても、その PC で `verify-git-broker` が成功して current marker が存在するまでは `available=false` が正しい表示です。real-machine verification を実施していない branch/CI の結果を Windows live verification の代替にはしません。
