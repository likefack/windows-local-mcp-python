# Windows Local MCP v1 Security Contract

この文書は、個人利用向け Windows Local MCP v1 が満たさなければならない固定の
セキュリティ契約です。実装、テスト、README、`SPEC.md`、`VERIFICATION.md` がこの文書と
食い違う場合、契約を弱めて実装へ合わせるのではなく、実装修正、安全な fail-closed、
能力縮小、または表現の訂正によって解消します。

この契約は 2026-08-14 時点の `broker-centered-sandboxed-processing-v1` を前提に固定します。
保証を弱める変更が必要な場合は自動採用せず、現行契約、変更案、理由、保証への影響、既知問題の
判定への影響を提示し、trusted operator が明示的に受容した場合だけ契約へ反映します。

2026-08-14 改訂では、通常 Windows user 文脈での実機検証により workspace 外 user file の
read denial、workspace write 境界、Internet denial、termination、resource bound が成立する一方、
workspace 内 protected information の read denial と LAN denial が現在の installed Codex Windows Sandbox
では成立しないことを確認したため、この 2 点を個人利用 v1 の明示的な受容済み残存 risk へ変更します。
未許可 loopback／localhost access は Sandbox 外の同一 host service を経由する権限迂回になり得るため、
引き続き必須遮断境界とします。

2026-08-26 改訂では、workspace-controlled な Git repository metadata が unapproved Git child の作用を
`workspace_root` 内へ安全に閉じ込められることを当時実証できていなかったため、automatic Git Broker execution を
一時的な capability reduction として fail closed にしました。`git_info`／`execute_readonly` の surface が存在することや
Git executable の path／SHA-256 が設定済みであることだけを、automatic Git 利用可能性の根拠にしないという
truthfulness requirement は現在も維持します。この全面停止は 2026-08-27 の Automatic Git remediation により
恒久仕様としては supersede されます。

同日追加改訂では、承認済み Codex Sandbox の open-ended／project-controlled execution を
immutable snapshot/run projection だけから実行する境界へ強化します。original `workspace_root` は Sandbox policy で
parent／child／grandchild から read／write deny を要求し、一般 source canary の denial を継続して検証します。
trusted toolchain と明示設定した external dependency だけを追加 read capability として許可します。
Approved Host は同一 Windows user authority のためこの filesystem isolation を提供できず、project-controlled
code-loader または workspace 内 executable を Approved Host で実行しません。これは defense-in-depth の強化であり、
2026-08-14 に受容した workspace 内 protected-information direct read の残存 risk を解消した保証とは扱いません。
current v1 では `protected_information_read` と LAN access の 2 property を Codex Sandbox 一般 route の明示的な
受容済み残存 risk とします。

2026-08-27 改訂では、Codex Sandbox account から WMI／CIM 等を経由して Job 外 process を生成する経路を
termination／resource-bound の必須境界として扱い、live verification marker を schema v5 へ更新します。
`Win32_Process.Create` を含む brokered process creation の denial が実測されない marker は route eligibility を
満たしません。

同日、Automatic Git Broker は product capability として安全に復元する方針を固定しました。Automatic Git は
第五の policy tier や通常 user authority の unrestricted child として復活させず、固定 Git grammar を持つ Broker
primitive の内部で、operation 固有の bounded／sanitized disposable repository projection と live-verified Codex
Windows Sandbox、WFP loopback guard、Windows Job Object、brokered-process denial preflight を組み合わせます。
Git child は original `workspace_root`／`data_dir` を直接読まず、raw repository config、attributes、hooks、external
alternates 等の workspace-controlled behavior input を trusted input にしません。

Automatic Git の route eligibility は generic Codex Sandbox の利用可能性より厳しくします。generic Sandbox で
受容済み residual risk として route を許容する `protected_information_read` と `lan` を含め、Automatic Git では
filesystem read/write、protected-information read、Internet、LAN、loopback、descendant containment、termination、
resource bound の全 property が `verified` であることを要求します。さらに pinned `git.exe` identity、Sandbox backend、
current generic live evidence digest、workspace、scratch quota、Automatic Git containment policy と command-policy generation
に結合した Git-specific live marker schema v1 と、同じ containment 内での固定 Git E2E を要求します。通常 operation は
missing/stale marker を自動 repair せず fail closed し、worker は child launch 直前にも marker を再検証します。この PC で
`verify-git-broker` が未実施、失敗、または stale の場合、実装や設定が存在しても Automatic Git は `available=false` です。

Automatic Git の protected-information boundary では、Git object database の blob が tree／commit／index 上で安全に見える
path へ再結合できることを前提にします。current workspace path の Broker validation や commit type binding だけを blob
content provenance の根拠にしません。このため automatic `diff`／`show` は metadata-only output に限定し、patch、binary
patch、`--check`、pathspec 付き暗黙 patch 等の content-bearing mode は `request_sandbox_command` へ送ります。status、
metadata-only diff/show、log metadata、rev-parse、ls-files、`git_info` snapshot は Automatic Git capability として維持します。

同日、Approved Host の guarded interval について、same Windows user authority の child が worker／監視 process を
停止して postflight を回避でき、restart 時の stale reconciliation だけでは永続 tamper latch が残らないことを
WLMCP-R2-001 として valid と判定しました。same-desktop UAC elevation は Windows security boundary として受理せず、
この問題を受容済み残存 risk に移しません。同日 main に入った Approved Host 全面 fail-closed は temporary exploit
containment／product regression の履歴であり、final remediation ではありません。

最終 remediation は monitor／postflight worker を LocalSystem service へ分離し、実 command だけを verified requester の
非昇格 Windows user token で起動します。service-owned ProgramData durable state、service epoch、normal-return completion
proof、requester-user WMI／CIM process census を必須境界とし、runtime user／Approved Host child に service stop/change-config、
monitor cancellation、SYSTEM worker の terminate／suspend／duplicate-handle／VM-write／token-manipulation authority を
与えません。2026-08-28 に normal path、SYSTEM worker loss、WMI Job 外 helper survival、service restart、`recovery_required`、
stale execution rejection、coordinated recovery、post-recovery normal path の Windows live verification を完了したため、
WLMCP-R2-001 は `fixed / live verified` とします。ただし別 PC や runtime／service／policy 変更後の execution availability は、
current immutable runtime と authenticated authority service の preflight を毎回満たす必要があります。

## 1. 適用範囲と信頼モデル

1 台の Windows PC で、1 人の利用者が、1 つの明示設定された `workspace_root` を扱う
ローカル MCP サーバーを対象にします。標準 transport は stdio です。

次を信頼しません。

- AI／model の判断、説明、操作要求
- workspace 内の source、script、設定、plugin、hook、autoload、test、build input
- child／grandchild process と、それらが出力する path、状態、安全性の自己申告
- DOCX、XLSX、CSV／TSV、ZIP、画像、opaque binary を含む入力 file
- 「read-only」「安全」「この path だけを使う」といった project 側の自己申告

次を Trusted Computing Base とします。

- Windows kernel と Windows security model
- 事前に侵害されていない WLMCP runtime、Python runtime、検証済み依存 package
- Broker が自動実行する installed external helper と通常の trusted OS／toolchain dependency。
  少なくとも primary executable は、署名等の provenance または trusted operator が固定した絶対 path と
  content hash／file identity を trust anchor とし、ambient PATH で名前が一致しただけでは信頼しません。
  Automatic Git の primary `git.exe` も同じ identity binding を要求しますが、identity 単独を route authorization
  には使わず、Git-specific live verification と sanitized projection containment を追加で要求します。
- provenance と必要な Windows live verification を通過した Codex Sandbox 実装
- Approved Host の authenticated LocalSystem authority service と、その protection／recovery に依存する Windows service model
- 明示承認を行う local user と trusted operator
- Windows user authority が既に完全奪取されていないこと

通常起動は非 Administrator とします。Administrator や trusted operator が意図的に
security state を変更する攻撃は対象外ですが、通常の非管理者権限、workspace code、一般入力
から到達できる同種の攻撃は対象内です。

## 2. 実行経路

### 2.1 WLMCP Broker

WLMCP が入力、出力、対象 path、resource 上限、filesystem／network／device／外部作用を
閉じて検証できる処理だけを直接扱います。主な対象は bounded file read/write、Automatic Git の固定読み取り、
固定対象の ADB 読み取り、binary transfer、checkpoint、transaction、rollback／Undo、監査です。

Automatic Git は `git_info` と `execute_readonly` の deny-by-default 固定文法だけを対象にします。Git child は
live workspace ではなく sanitized disposable repository projection を入力とし、live-verified Sandbox/WFP/Job 境界内で
実行します。pinned Git identity、全 required Sandbox property、Git-specific live marker のいずれかが欠ける場合は
fail closed します。`diff`／`show` は metadata-only output に限定し、object-backed blob bytes を返し得る patch／binary／
`--check`／暗黙 patch mode は automatic route の対象外です。open-ended Git、network Git、workspace metadata semantics を
完全に維持する必要がある Git 操作も automatic Broker route の対象外です。

### 2.2 Structured Processing

DOCX、XLSX、CSV／TSV、ZIP、画像を bounded かつ宣言的に処理します。WLMCP 内で処理する
場合も ChatGPT container へ byte-exact artifact を渡す場合も、最終反映は Broker の
検証と transaction を通します。format の保存能力と embedded code の実行能力は分離します。

### 2.3 Codex Sandbox

arbitrary code、project-controlled code、plugin／autoload、test／build、一般 command、
Python、Node、PowerShell、Dart、Flutter など open-ended な処理を実行する経路です。
ローカル承認と、実行に必須と定めた security property が同一 backend に対する Windows live verification を
通過していることを必要とします。受容済み残存 risk の property が `failed` または `unverified` でも、その事実を
保持・表示したうえで、その他の必須境界がすべて成立していれば general Sandbox route 利用を妨げません。
この residual-risk allowance は Automatic Git Broker には適用しません。Sandbox の失敗、timeout、未対応を理由に
Approved Host へ自動 fallback しません。

### 2.4 Approved Host

Approved Host は Codex Sandbox／Broker では満たせない eligible command を、separate one-shot human approval 後に通常の
Windows user authority で実行する中核 route です。project-controlled code-loader と workspace executable は引き続き
拒否し、Sandbox failure から Host への automatic fallback は行いません。

production execution は immutable Program Files runtime と authenticated LocalSystem authority service の両方を必要とします。
monitor／postflight は LocalSystem worker が所有し、実 child は pipe requester の verified non-elevated token を
`CreateProcessAsUserW` で使用します。same-desktop UAC elevation を security boundary としません。

service-owned durable `active.json` は normal verified completion まで immutable とし、worker kill、service restart、channel
loss、postflight mismatch、Job 外 helper 残存では解除しません。authority service が provision 済みである限り、user-owned
configuration の `approved_host_enabled=false` は active／recovery latch の global health gate を無効化しません。active Approved Host
monitor は runtime-user `stop_job` から停止できません。異常 state の解除は elevated Administrator による explicit reviewed
coordinated recovery だけです。

release-level WLMCP-R2-001 boundary は 2026-08-28 の normal／abnormal／recovery Windows live lifecycle で検証済みです。
一方、`available=true` は current machine で immutable runtime と authority-service preflight が成立したことだけを意味し、
過去の live evidence を別 machine／changed runtime の current availability として再利用しません。

旧 Safe Tier／AppContainer は第五の policy tier として復活させません。固定文法の低 risk
処理は Broker primitive として狭く実装し、open-ended execution は Codex Sandbox へ送ります。

## 3. 必須保証

### A. Model／workspace trust

- model と project code は security boundary の判断主体にしません。
- project-controlled file や設定から実行能力、対象範囲、network 能力を暗黙に拡大しません。
- protected information を「project が安全と申告した」ことだけで読み取り対象にしません。

### B. Broker boundary

- Broker は deny-by-default の完全な文法、path 検証、resource bound を通過した閉じた操作だけを
  実行します。
- Broker operation から未許可の workspace 外 filesystem、control-plane、network、device、
  external service へ副作用を拡大できません。
- external process を使うこと自体ではなく、作用を閉じて事後検証できるかで経路を決めます。
- Broker が自動実行する external helper は、workspace／`data_dir`／scratch その他 MCP が書き換え可能な
  root から解決しません。primary executable の path、content hash、file identity 等の
  security-relevant identity を固定し、実行直前の差し替え、PATH shadowing、stale identity を検出したら
  fail closed します。署名等の provenance が利用できない場合は、trusted operator が固定した executable
  identity を明示的な trust anchor とします。
- Automatic Git は executable identity だけでは Broker helper として十分とみなしません。repository metadata、
  config、attributes、helper resolution 等の workspace-controlled behavior input を sanitized disposable projection
  へ閉じ、raw `.git/config` を scratch へ永続化せず、dangerous config／attributes／hooks／external alternates を
  除外または拒否します。source workspace／`data_dir` は child から deny し、Internet／LAN／loopback、descendant、
  termination、resource boundary を含む全 required property と Git-specific live marker が current identity に
  結合していない場合は fail closed します。
- Automatic Git は Git object graph 上の path 名を protected-content provenance とみなしません。`diff`／`show` の
  automatic mode は metadata-only とし、blob bytes を stdout/stderr へ materialize し得る content-bearing mode を
  human-approved Sandbox route へ送ります。revision の `^{commit}` binding は defense-in-depth として維持します。
- Automatic Git repository projection は configured `max_sandbox_scratch_bytes` の 1/2 以下に bound し、operator quota を
  上回る hard-coded byte floor を持ちません。scratch quota と command-policy generation は Git-specific marker context に
  binding し、変更時は stale とします。
- Automatic Git の normal worker への unrestricted fallback、Approved Host fallback、stale live marker の
  silent repair／自動再検証を禁止します。
- Broker が作用を閉じられない場合は、承認済み Codex Sandbox へ送るか fail closed します。

### C. Open-ended execution

- arbitrary command、project script、plugin、autoload、test、build、一般 shell は Broker の通常権限で
  実行しません。
- 実行内容が固定文法に見えても project code を読み込む処理は Codex Sandbox の対象です。
- Sandbox から Host への自動 fallback、暗黙の再実行、二重実行を禁止します。

### D. Codex Sandbox boundary

Codex Sandbox の `available` は必要な local dependency と起動前提が解決できることだけを意味し、
OS 境界の安全性を証明した意味には使いません。`Windows live-verified` または個別の property を
`verified` と表示するには、同一の launcher、helper、version、署名、hash、policy generation に
対して、その property を実機で確認します。

Live verification marker は schema v5 のみを受理します。v1～v4 または必須 field が欠けた marker から
identity を推測・移行しません。v5 は、実際に import された WFP Guard module の canonical path、
content SHA-256、Windows handle から取得した volume serial number と file index、size、Guard version、
policy generation に結合します。mtime は補助的な drift signal であり、単独では trust anchor にしません。
Guard module は verification から child 起動まで置換・書込みを拒否する handle を保持します。

Codex launcher と adjacent helper は canonical path、content SHA-256、Windows stable file identity、size、
実際の version、Authenticode の `Valid` status、leaf signer subject、leaf certificate thumbprint に結合します。
さらに Windows product、build、UBR、native architecture、Sandbox account identity、WFP read-back identity を
marker に結合し、現在値と異なれば marker を stale として通常 operation を停止します。通常 operation は
stale marker を理由に live verification を自動実行せず、`verify-codex-sandbox` の明示実行を必要とします。
`Win32_Process.Create` を含む WMI／CIM brokered process creation は explicit denial probe の成功を必須とし、
`brokered_process_creation_denied` が欠損または false の evidence は route eligible としません。

WFP の static non-persistent fixed object は reboot や BFE restart で消失し得るため、marker v5 の Guard、
policy、backend、account、OS identity がすべて現在値と一致し、object が単に missing の場合だけ、trusted
Guard が exact object を再構築できます。その場合も `ensure → complete read-back → wfp_guard_verified →
child launch` の順序を崩しません。既存 object の security-relevant field 不一致、conflicting object、または
marker identity 不一致は無変更で fail closed とし、silent repair しません。

Sandbox route の必須境界は少なくとも次です。

- workspace 外の不要な user file を読めない。workspace 外の `.env`、credential、secret もこの必須境界に含む
- control-plane と `data_dir` を読み書きできない
- write 可能範囲が、明示された scratch／実行 copy と Broker が検証して反映する出力範囲に限定される
- original source workspace は Sandbox policy で parent／child／grandchild から read／write deny を要求し、一般 source canary の read／write denial を必須検証する。ただし workspace 内 protected information の direct read denial は Section 5 の受容済み残存 risk として general Sandbox route gate から除外する
- project-controlled execution は承認済み immutable snapshot から作成した operation 固有 run projection だけを使用し、trusted toolchain と明示的 external dependency 以外の ambient filesystem read capability を要求しない
- Internet へ接続できない
- 未許可 loopback／localhost endpoint へ接続できない
- loopback Guard の対象 SID は、この PC のコンピューター名で完全修飾して解決し、返された参照ドメインがこの PC 自身であり、`SID_NAME_USE == SidTypeUser (1)` であることを確認できない場合は Sandbox route を利用しない
- child／grandchild に上記の必須 filesystem、network、control-plane 境界が継承される。ただし workspace 内 protected-information direct read の child／grandchild denial は general Sandbox の受容済み残存 risk として route gate から除外する
- WMI／CIM 等の brokered process creation が拒否され、Job 外 process で termination／process／memory bound を迂回できない
- timeout／cancel で descendant を含め停止できる
- scratch、出力、時間、process、memory／filesystem consumption に現実的な上限がある

個人利用 v1 の general Codex Sandbox route では、workspace 内に存在する `.env`、credential、secret 等を Sandbox
parent／child／grandchild が直接読み取れる場合があることと、LAN／private network endpoint へ接続できる場合が
あることを明示的に受容する残存 risk とします。`protected_information_read` または `lan` が `failed`／`unverified`
であることだけを理由に general Sandbox route を unavailable にしません。

これらは安全、遮断済み、`verified` とは表示しません。実機で境界突破を確認した場合は該当 property と
parent／child／grandchild check をそのまま `failed` として保存・表示し、検証不能なら `unverified` として残します。
受容済み残存 risk を route 判定から分離しても、結果を削除したり成功へ丸めたりしません。

Automatic Git Broker はこの residual-risk allowance を使用しません。Git-specific marker 作成時と通常 route gate の
双方で全 Sandbox security property が `verified` でなければならず、general Sandbox が route eligible でも Automatic
Git は unavailable のままとします。

workspace 外 protected information の read、一般 source-workspace canary の read／write、Internet access、
未許可 loopback／localhost access、control-plane 境界、brokered process creation denial はこの受容に含みません。
これらの必須境界が `failed` または `unverified` の場合、Sandbox route は unavailable として fail closed します。

snapshot/run projection、source-workspace deny、staging からの protected file 除外、stdout／stderr の redaction、
network deny は defense-in-depth として維持します。これらを workspace 内 protected information の secrecy が
guaranteed された根拠にはせず、general Sandbox の受容済み残存 risk の存在を隠したり `verified` に書き換えたりしません。

### E. Approved Host boundary

- Codex Sandbox とは別の one-shot human approval を必要とする。
- project-controlled code-loader と workspace 内 executable は Approved Host で受理せず、Codex Sandbox の snapshot-only route を要求する。
- monitor／postflight owner は LocalSystem service 配下とし、実 command は元 requester の non-elevated Windows user token で起動する。
- runtime user／Approved Host child から monitor／worker／service の terminate、suspend、thread control、duplicate handle、VM write、token manipulation、security descriptor rewrite、SCM stop/change-config を許さない。
- same-desktop UAC elevation だけを authority separation の根拠にしない。
- durable pending／recovery／epoch state は LocalSystem-owned protected ProgramData namespace に置き、normal verified completion まで immutable active latch を残す。
- child／worker／monitor の異常終了、channel loss、timeout、postflight 未完了、control-plane mismatch、service restart、旧 epoch proof を restart 後にも残る fail-closed state へ結合する。
- Windows Job Object の全 descendant と、WMI／CIM 等の Job 外 requester-user process creation の双方を閉じる。process identity を列挙できない、または期限内に終了しない場合も postflight を成功扱いしない。
- Host の device、network、external service、process side effect を workspace rollback 可能とは表示しない。
- Hosted CI の unit/integration evidence を Windows service/process authority の live verification と表示しない。
- 2026-08-28 に確認した normal／abnormal／recovery lifecycle を release-level evidence として保持しつつ、current machine の runtime／service preflight を省略しない。

### F. Approval integrity

- approval は operation、完全な argv、cwd／execution scope、executable identity と content、
  relevant input、environment、effective settings、workspace identity、WLMCP build／policy generation、
  Sandbox backend identity、timeout、workspace-write 意図に結合します。
- approval 後に security-relevant input が変化した場合、古い approval を実行しません。
- pending TTL、execution TTL、atomic approve-and-claim、double approval、double claim、replay、cancel race を
  fail closed で処理します。
- request API は実行せず、local approval UI の approve-and-run が一度だけ claim します。

### G. Workspace mutation／concurrency

- 書き込みは stale source、target replacement、parent／path identity change、hardlink、reparse point、
  concurrent modification を検出します。
- 検証から atomic commit までの race で別 file や第三者変更を上書きしません。
- 排他範囲は correctness と conflict detection を満たすために必要な範囲へ限定することを原則とします。
  より広い lock が安全性のため必要な場合は許容しますが、性能上の問題は L とリリース判定で別途扱います。
- 並列化や高速化のために stale／concurrent change detection を弱めません。

### H. Transaction／recovery

- write、replace、ZIP 複数展開、rollback、Undo は durable journal、staging、commit-time 再検証、
  post-write 検証を使用します。
- crash、timeout、cancel、復旧失敗時に第三者の新しい変更を自動上書きしません。
- 安全な復旧を完了できない場合は `recovery_required` として mutation を fail closed します。
- hardware power loss の全 timing に対する完全 ACID は保証しません。

### I. Binary artifact boundary

- 任意の regular binary file を format 非依存に、bounded、byte-exact、whole-artifact SHA-256 bound、
  exact offset、incomplete transfer 拒否、concurrent modification 検出、atomic commit で扱います。
- local source から container result への workflow は source identity binding を必須にし、source が変化した
  result の反映を拒否します。
- target replacement は expected destination identity へ結合します。
- macro／embedded code の bytes を保存する能力と、それを実行する能力を分離します。
- chunk 読み取りごとに source 全体を再読込／再hash する計算量は許容しません。transfer 開始時に固定した
  immutable snapshot または同等の単純な source binding を使用し、必要な整合性確認は開始時、終了時、
  commit-time など境界点へ集約します。

### J. Structured file safety

- malformed DOCX、XLSX、CSV／TSV、ZIP、画像から workspace escape、code execution、unbounded resource
  consumption、silent destructive corruption を容易に発生させません。
- 未対応 feature を安全に保持できることを実証できない場合は、file-wide に fail closed して構いません。
  一方、対象 format／feature について保存能力を回帰テスト等で実証済みであり、変更対象と独立して
  byte／semantic preservation できる場合は、未対応 feature の存在だけを理由に file-wide rejection しません。
- 「読める」「編集できる」「byte-preserve できる」「semantic-preserve できる」を別々の capability として
  扱い、実証していない保存能力を表示しません。
- DOCX は paragraph／run／text／format／table／header／footer／style／section／page／metadata と、
  対応を表明する範囲の hyperlink／image／relationship の保持を確認します。
- XLSX は value／formula／range／sheet／row／column／copy／fill／format／merge／freeze pane／filter／table／
  validation／conditional formatting／chart／page setup について、対応を表明する範囲を確認します。
- CSV／TSV は encoding、BOM、delimiter、quote、newline、final newline、row／column／cell を確認し、semantic
  preservation と byte／lexical preservation の保証範囲を区別します。
- ZIP は traversal、absolute path、ADS、Windows reserved name、case collision、file／directory collision、
  expanded size、entry count、source identity、multi-file transaction、rollback／recovery を検査します。
- 画像は inspect、resize、thumbnail、crop、rotate、flip、format conversion、quality、metadata policy、EXIF、
  ICC、DPI、multi-frame、pixel／decoded-memory bound について、対応を表明する範囲を確認します。

### K. Protected information

- policy で保護した `.env`、credential、secret を Broker read、automatic helper／snapshot、audit／UI、
  Sandbox staging、artifact processing から意図せず model へ露出させません。Automatic Git Broker の disposable
  projection は protected worktree file を除外し、source `.git/config` は raw bytes を scratch へ書かず trusted
  Broker memory 上で inert core settings だけへ変換します。Git object database に historical protected blob が残る
  場合を考慮し、Automatic `diff`／`show` は metadata-only output に限定して object graph から blob bytes を model へ
  materialize する経路を残しません。
- workspace 外の protected path は、Codex Sandbox process とその descendant からも実効 OS capability で
  直接読めないことを必要とします。
- workspace 内 protected information は general Sandbox staging へ自動追加せず、original source workspace への read deny を
  parent／child／grandchild に要求して direct read も継続して probe します。ただし current installed Codex Windows
  Sandbox でこの direct-read denial を完全保証できないため、失敗または未検証は Section 5 の general Sandbox residual risk
  とします。この例外は Automatic Git Broker には適用しません。
- staging exclusion、argv／environment／stdout／stderr preview／error／audit field の redaction は防御を
  多層化する補助策であり、workspace 外 protected-information read denial の代替にしません。
- argv、environment、stdout／stderr preview、error、audit field は semantic redaction と容量制限を通します。
- Approved Host は separate human approval 後の通常 Windows user command であるため、人間が明示的に secret access を承認した operation についてまで絶対に読めないことは保証しません。

### L. Resource safety／practicality

Security boundary として、disk、stdout／stderr、pending approval、transfer、concurrent job、process、scratch、
memory、filesystem entry、structured element、decoded pixel、archive expansion、execution time に現実的な
admission／runtime bound を設けます。

実用性・性能については次を release criterion として別に評価します。

- `.venv`、`node_modules`、build tree、cache の存在だけで、不要な全量 copy／scan／hash を繰り返さない設計を
  優先します。
- Broker／staging は protected `.env` や secret を test／build へ自動注入しません。Sandbox が workspace 内の
  protected information を直接読み取れる general-route residual risk は、秘密情報を意図的に追加提供する根拠にはしません。
- 既知 target の operation で全 workspace checkpoint が不要なら、対象限定を優先します。ただし manual／
  concurrent change detection を失う shortcut は使いません。
- 性能改善のために workspace 外 protected-information boundary、rollback correctness、approval integrity、
  race detection を弱めません。

### M. Rollback truthfulness

- rollback／Undo が戻せる範囲を正確に表示します。
- workspace checkpoint manifest に含まれる通常 file bytes 以外の `.git`、ACL、device state、network side
  effect、external service、external process side effect を「元に戻せる」と表示しません。
- selective Undo は独立した text 変更を保持しますが、binary、重複／曖昧 hunk、unsafe lifecycle change は
  conflict として停止します。

### N. Transport／principal

- v1 は single-user local MCP を前提とします。
- 認証された principal ownership のない remote HTTP／multi-user transport は起動時に fail closed します。
- loopback であることだけを multi-principal authentication の代替にしません。
- transport の説明と capability 表示は、実際の startup validation と一致させます。設定上必ず拒否される
  transport を「optional」「available」「利用可能」と表示しません。

### O. Capability／verification truthfulness

次の状態を分離して表示します。

- `configured`: 設定値が存在する
- `enabled`: policy 上有効
- `available`: 必要な local dependency と起動前提が解決できる
- `unit-tested`: mock／unit／integration test の対象
- `Windows live-verified`: 現在の PC と backend で、表示対象の OS 境界を実測済み
- `Secure MCP Tunnel / ChatGPT E2E verified`: 実際の接続経路で end-to-end 検証済み

複数の security property を持つ capability は、少なくとも filesystem read、filesystem write、
protected-information read、Internet、LAN、loopback、descendant containment、termination、resource bound を
必要に応じて個別に `verified`／`failed`／`unverified`／`not-applicable` と記録します。

property の実測結果と general Sandbox route の利用可否は分離します。workspace 内 `protected_information_read` と LAN が
`failed` または `unverified` でも、受容済み残存 risk としてその事実を保持・表示し、その他の必須境界が route
eligibility を満たすなら general Sandbox route は利用可能として構いません。対応する child／grandchild protected-information
check の失敗も隠さず保持しますが、それだけで descendant route を失格にしません。受容済み risk を `verified` に
書き換えたり検証結果から削除したりしません。必須境界が `failed` または `unverified` の状態を capability 全体の
`Windows live-verified=true` または execution-route-available へ丸めません。

transport も capability truthfulness の対象です。stdio／HTTP 等の各 transport について、`configured`、
`enabled`、`available` と実効 authentication／principal 前提を区別し、startup validation が拒否する状態を
利用可能であるかのように session／UI／documentation へ表示しません。

Git も capability truthfulness の対象です。`git_enabled=true`、Git executable path/hash の設定、generic Codex Sandbox
marker、または `git_info`／`execute_readonly` surface の公開を Automatic Git availability と同一視しません。
Automatic Git は pinned executable identity、sanitized disposable projection policy、全 required Sandbox property、
Git-specific live marker schema v1 が current identity、scratch quota、command-policy generation に一致した場合だけ
`available=true`／`windows_live_verified=true` と表示します。実機で `verify-git-broker` を実行していない branch/PC、
または marker が stale の状態は unavailable です。`available=true` でも content-bearing Git diff/show が Automatic
capability に含まれることは意味しません。

Approved Host も capability truthfulness の対象です。`approved_host_enabled=true`、`request_host_command` surface、
または pending／approved row の存在を execution availability と同一視しません。`available=true` は immutable runtime と
authenticated LocalSystem authority service の current preflight が両方成功した場合だけです。source／unit evidence や service
health だけを full capability の `live_verified`／`windows_live_verified` へ昇格しません。release-level R2-001 Windows live
evidence と、current-machine execution preflight を別の状態として扱います。

過去の結果、mock、static test、direct ADB、stdio integration を、現在の commit に対する Windows live、
Automatic Git E2E、Approved Host authority E2E、MCP ADB E2E、Tunnel、deployment の代替にしません。

## 4. 原則対象内

次は実装困難、性能、backend 制約だけを理由に対象外へ移しません。

- model の誤判断／過剰行動、悪意または予期しない workspace code
- project-controlled config／plugin／hook／autoload、arbitrary child／grandchild process
- malformed structured／binary input、secret leakage、workspace escape。ただし Section 5 で明示した general Sandbox の workspace 内 protected-information direct read の残存 risk 自体を除く
- unintended network／device／external-service access。ただし Section 5 で general Sandbox に明示的に受容した LAN access を除く
- workspace、`data_dir`、control-plane、scratch の境界違反。ただし Section 5 の general Sandbox workspace 内 protected-information direct read の明示的例外を除く
- stale approval、replay、double execution、cancel race、ordinary TOCTOU
- crash／timeout／cancellation、stale source／destination、path／filesystem race
- Broker helper の PATH shadowing、差し替え、stale executable identity
- Automatic Git Broker の repository metadata confinement、object-content provenance、sanitized projection、Git-specific live-marker binding、dedicated-worker routing、capability 表示の不一致
- Codex Sandbox の一般 source workspace read／write、workspace 外 protected information direct read、workspace 外 read／write、Internet／loopback／control-plane／必須 descendant boundary 不足。ただし Section 5 の general Sandbox workspace 内 protected-information direct read は除く
- Approved Host の LocalSystem authority separation、monitor／postflight kill・bypass・restart persistence、requester-token preservation、recovery、capability 表示の不一致
- ordinary non-admin Windows user 権限で成立する現実的な攻撃
- common project layout で起こる機能破綻、通常操作での重大 UX 破綻
- 容易に trigger できる resource exhaustion、過剰 copy／scan／hash／lock／approval
- Sandbox から Host への automatic fallback、capability と UI 表示の不一致

### 4.1 脅威の現実性と修正優先度

Section 4 の対象内に入ること、または security finding が技術的に `valid` であることだけでは、その finding が
current product で直ちに `must-fix` であることを意味しません。finding の成立判定と remediation priority は分離し、
個人利用・single-user・local MCP という実際の脅威モデルに対して、得られる risk reduction と対策コストを比較します。

各 finding では少なくとも次を評価します。

- 攻撃成立前に必要な権限、principal、local code execution、Administrator 権限、trusted runtime compromise 等の前提
- 攻撃後に新たに得られる authority、filesystem／secret access、別 principal への越境、network／device／external service 作用、永続性
- model の誤判断、prompt injection、悪意ある workspace、一般入力、通常の user operation から attack path が到達可能か
- timing／race window、worker kill、複数 process の協調、特殊な OS state、再起動等の前提数と再現容易性
- confidentiality、integrity、availability への実害と、通常利用で自然発生する可能性
- localhost／single-user product としての exposure、想定利用頻度、攻撃者がその機会を得る現実性
- remediation に伴うコード量、状態遷移、Trusted Computing Base、privileged service／principal、依存 component の増加
- remediation が生む性能低下、false positive、恒常的 fail-closed、UX 回帰、保守性低下、新しい故障・race・recovery mode
- より単純な mitigation、scope reduction、検出・監査、文書化された residual risk で十分か

「理論上成立する」「特殊な操作を組み合わせれば成立する」ことだけを修正根拠にせず、severity と remediation priority を
同一視しません。特に、攻撃成立前に攻撃後と同等以上の authority を security boundary 外ですでに完全取得している必要があり、
その exploit により privilege expansion、別 principal への越境、新しい protected-information access、未承認外部作用等が
増えない場合は、原則として修正優先度を下げます。ただし project code、一般入力、prompt injection 等からその前提 authority
自体を新たに獲得できる経路はこの扱いに含めません。

availability／DoS finding では、攻撃者の既存権限と trigger 容易性だけでなく、対策が正常利用へ与える false positive、
fail-closed、性能・運用停止のコストも比較します。hardening の複雑化により Trusted Computing Base や状態遷移が増え、
元の脅威より大きい現実的な故障面を作る場合、その対策を自動的に安全側とは扱いません。

remediation decision は少なくとも `must-fix`、`proportionate-fix`、`accepted-residual-risk`、`out-of-scope`、`invalid` を区別し、
finding の技術的 validity、severity、攻撃前提、実害、remediation decision とその理由を別々に記録します。
`accepted-residual-risk` とする場合は、成立条件、想定実害、受容理由、再評価条件を残し、継続的な product policy とする場合は
Section 5 または関連する正本文書へ明示します。

ただし Section 3 で既に必須保証として固定している境界の実証済み violation、または current route eligibility に明示的に
必須とされている property を、費用対効果だけを理由に自動で `accepted-residual-risk` へ変更してはなりません。その保証を
弱める必要がある場合は、現行契約、変更案、攻撃現実性、修正コスト、product complexity／availability への影響を提示し、
trusted operator が明示的に受容した場合だけ本契約を更新します。

## 5. 対象外または受容する残存 risk

次は v1 の Trusted Computing Base、明示的対象外、または trusted operator が明示的に受容した残存 risk です。
ただし同じ技術分類でも、ここで明示していないものや通常の project code／一般入力から別の必須境界を
破るものは対象内です。

- workspace 内に存在する `.env`、credential、secret 等を general Codex Sandbox process またはその descendant が
  直接読み取れること。workspace 外 protected information の read は含まない。snapshot/run projection、source
  workspace deny、staging exclusion と direct-read probe は defense-in-depth として維持する。この例外は Automatic
  Git Broker には適用しない
- general Codex Sandbox process またはその descendant が LAN／private network endpoint へ接続できること。
  Internet と未許可 loopback／localhost access は含まない。この例外は Automatic Git Broker には適用しない
- Windows kernel、hardware、firmware、Windows security model 自体の compromise
- Administrator／trusted operator による意図的な security state 変更
- provenance／live verification を通過した Sandbox 実装自体の未知の OS sandbox 0-day
- trusted runtime／dependency environment が起動前から完全 compromise されている状態
- security boundary 外で同等以上の Windows user authority が既に完全奪取されている状態
- hardware power loss の全 timing に対する完全 ACID durability
- 通常の validation／resource bound で防止不能な third-party parser の未知の 0-day
- 別 kernel component、専用 service、別 user principal を必須とし、個人利用 v1 として cost が明らかに
  不釣り合いな極端な攻撃

Approved Host の same-principal monitor termination／postflight bypass はこの受容済み残存 risk に含めません。
current v1 は Section E の LocalSystem authority boundary と durable recovery state で対処し、この境界または current
preflight が成立しない場合は Approved Host execution を fail closed します。

## 6. 既知問題と契約の対応

この表は問題の存在を確定するものではありません。現行実装で再検証し、`already fixed`、`obsolete`、
`partially fixed`、`still valid`、`reformulated` のいずれかを記録します。

| 重点確認項目 | 主な契約項目 |
| --- | --- |
| Broker helper executable の provenance／path／hash／file identity と差し替え耐性 | A, B, O |
| Automatic Git Broker の repository metadata/object-content confinement、Git-specific live marker、fail-closed capability 表示 | B, K, O |
| legacy `:workspace` と `workspace_write=false` の実効 filesystem boundary | C, D, O |
| workspace 外 protected information の read denial | D, K, O |
| workspace 内 `.env`／credential／secret の直接 read は general Sandbox の受容済み残存 risk として正確に表示されるか | D, K, O |
| `.env`／dependency tree を含む過剰 staging | K, L |
| known-path operation の full workspace checkpoint | G, H, L |
| artifact chunk ごとの全 file 再hash | I, L |
| ChatGPT container source→result binding | G, I |
| Sandbox launcher の host-side cwd／DLL／search-path | C, D, F |
| Internet／loopback と child／grandchild の必須 containment | D, O |
| WMI／CIM brokered process creation denial と Job 外 escape | D, O |
| LAN access が general Sandbox の受容済み残存 risk として正確に表示されるか | D, O |
| Sandbox property ごとの live verification と route 判定の分離 | D, O |
| DOCX／XLSX の過剰な file-wide rejection と保存能力表示 | J, L, O |
| 画像 format conversion の実用性と capability 表示 | J, L, O |
| CSV／TSV preservation 表示の正確性 | J, O |
| workspace／data／scratch の Windows physical identity | G, H, O |
| Approved Host monitor termination／postflight bypass と restart 後の fail-closed persistence | E, F, H, O |
| checkpoint／CAS／GC concurrency と rollback／Undo | G, H, L, M |
| resource admission、protected information leakage | K, L |
| Live Activity／Timeline／preview／conflict／recovery 表示 | M, O |
| ADB emulator 固定 read integration | B, D, K, O |
| transport の実効 startup 可用性と session／UI／documentation 表示 | N, O |
| 古い README／SPEC／VERIFICATION | O |

## 7. リリース判定

release candidate と判断するには、少なくとも次を満たします。

1. Section 3 の明示的な必須保証 violation が残っておらず、Section 4.1 の評価で `must-fix` とされた未解決 finding と
   release-blocking な実用性回帰が残っていない。`proportionate-fix` は合意した軽減策を実装または文書化し、残存 risk と
   再評価条件を記録する。Section 5 で general Sandbox に明示的に受容した workspace 内 protected-information read と LAN access は、
   それ自体では blocker としないが、実測結果と残存 risk を隠してはならない。Automatic Git にはこの例外を適用しない。
2. 修正後に security、practicality／performance、regression の独立 pass を繰り返し、2 回連続で新しい
   対象内 blocker を発見しない。
3. full pytest、Ruff、compileall、`git diff --check` と、該当する security／structured-file／race／approval／
   recovery／transfer／resource／Activity／Undo の回帰を現在の commit に対して実行する。
4. 実行可能な Windows live test、Automatic Git `verify-git-broker`、Approved Host normal／abnormal／recovery authority verification、
   ADB emulator integration、Secure MCP Tunnel／ChatGPT E2E を実行し、実行不能なものは未検証として理由を記録する。
   Sandbox は property ごとの実測結果と、それが必須境界か general-route 受容済み残存 risk かを残す。Automatic Git は全
   required property と Git-specific marker の成功を別に残し、Approved Host は release-level live evidence と current-machine
   runtime／authority preflight を区別する。
5. README、`SPEC.md`、`VERIFICATION.md` と関連文書を現行実装へ合わせ、過去の architecture や過去の
   検証結果を現在の保証として再利用しない。
