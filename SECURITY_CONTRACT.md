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
- Broker が自動実行する Git／ADB 等の installed external helper と通常の trusted OS／toolchain dependency。
  少なくとも primary executable は、署名等の provenance または trusted operator が固定した絶対 path と
  content hash／file identity を trust anchor とし、ambient PATH で名前が一致しただけでは信頼しません。
- provenance と必要な Windows live verification を通過した Codex Sandbox 実装
- 明示承認を行う local user と trusted operator
- Windows user authority が既に完全奪取されていないこと

通常起動は非 Administrator とします。Administrator や trusted operator が意図的に
security state を変更する攻撃は対象外ですが、通常の非管理者権限、workspace code、一般入力
から到達できる同種の攻撃は対象内です。

## 2. 実行経路

### 2.1 WLMCP Broker

WLMCP が入力、出力、対象 path、resource 上限、filesystem／network／device／外部作用を
閉じて検証できる処理だけを直接扱います。主な対象は bounded file read/write、固定文法の
Git 読み取り、固定対象の ADB 読み取り、binary transfer、checkpoint、transaction、
rollback／Undo、監査です。

### 2.2 Structured Processing

DOCX、XLSX、CSV／TSV、ZIP、画像を bounded かつ宣言的に処理します。WLMCP 内で処理する
場合も ChatGPT container へ byte-exact artifact を渡す場合も、最終反映は Broker の
検証と transaction を通します。format の保存能力と embedded code の実行能力は分離します。

### 2.3 Codex Sandbox

arbitrary code、project-controlled code、plugin／autoload、test／build、一般 command、
Python、Node、PowerShell、Dart、Flutter など open-ended な処理を実行する経路です。
ローカル承認と、実行に必須と定めた security property が同一 backend に対する Windows live verification を
通過していることを必要とします。受容済み残存 risk の property が `failed` でも、その事実を保持・表示した
うえで、必須境界がすべて成立していれば route 利用を妨げません。Sandbox の失敗、timeout、未対応を理由に
Approved Host へ自動 fallback しません。

### 2.4 Approved Host

real Windows user authority が本当に必要な処理だけを、Codex Sandbox とは別の明示承認で
1 回実行します。別 OS principal による完全隔離は v1 の保証外ですが、control-plane の
通常の改変を検出して fail closed します。

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

Sandbox route の必須境界は少なくとも次です。

- workspace 外の不要な user file を読めない。workspace 外の `.env`、credential、secret もこの必須境界に含む
- control-plane と `data_dir` を読み書きできない
- write 可能範囲が、明示された scratch／実行 copy と Broker が検証して反映する出力範囲に限定される
- source workspace を read-only と表示する場合、実効 OS capability でも write できない
- Internet へ接続できない
- 未許可 loopback／localhost endpoint へ接続できない
- child／grandchild に上記の必須 filesystem、network、control-plane 境界が継承される
- timeout／cancel で descendant を含め停止できる
- scratch、出力、時間、process、memory／filesystem consumption に現実的な上限がある

個人利用 v1 では、次の 2 点を明示的に受容する残存 risk とし、それ単独を理由に Sandbox route を
unavailable にしません。

- workspace 内に存在する `.env`、credential、secret 等の protected information を Sandbox process または
  child／grandchild が直接読み取れる場合があること
- Sandbox process または child／grandchild が LAN／private network 上の endpoint へ接続できる場合があること

これらは安全、遮断済み、`verified` とは表示しません。実機で境界突破を確認した場合は property を
`failed` のまま保存・表示し、受容済み残存 risk として route 判定から分離します。

workspace 外 protected information の read、Internet access、未許可 loopback／localhost access はこの受容に
含みません。これらの必須境界が `failed` または `unverified` の場合、Sandbox route は unavailable として
fail closed します。

staging からの除外、stdout／stderr の redaction、network deny は補助防御です。受容済み残存 risk の存在を
隠したり `verified` に書き換えたりする根拠にはしません。現在の installed Codex Sandbox で必須境界を
表現または検証できない場合、その execution route は unavailable として fail closed します。

### E. Approved Host boundary

- Codex Sandbox とは別の one-shot human approval を必要とします。
- 同一 Windows user principal のため防止できない瞬間的な完全復元型改変は残存 risk としますが、
  audit DB、approval state、CAS、journal、worker context、transfer state、runtime、policy generation の
  通常の改変は検出します。
- 改変または検証不能を検出した場合は tamper／recovery marker を残し、後続処理を停止します。
- Host の device、network、external service、process side effect を workspace rollback 可能とは表示しません。

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

- policy で保護した `.env`、credential、secret を Broker read、automatic Git／diff／snapshot、audit／UI、
  Sandbox staging、artifact processing から意図せず model へ露出させません。
- workspace 外の protected path は、Codex Sandbox process とその descendant からも実効 OS capability で
  直接読めないことを必要とします。
- workspace 内 protected information は Sandbox staging へ自動追加しませんが、open-ended execution が
  source workspace の実体を直接読める場合に `.env`、credential、secret の read denial が成立しないことを、
  個人利用 v1 の受容済み残存 risk とします。この状態を「secret が Sandbox から読めない」と表示しません。
- staging exclusion、argv／environment／stdout／stderr preview／error／audit field の redaction は防御を
  多層化する補助策であり、workspace 外 protected-information read denial の代替にしません。
- argv、environment、stdout／stderr preview、error、audit field は semantic redaction と容量制限を通します。
- Approved Host で人間が明示的に secret access を承認した場合まで絶対に読めないことは保証しません。

### L. Resource safety／practicality

Security boundary として、disk、stdout／stderr、pending approval、transfer、concurrent job、process、scratch、
memory、filesystem entry、structured element、decoded pixel、archive expansion、execution time に現実的な
admission／runtime bound を設けます。

実用性・性能については次を release criterion として別に評価します。

- `.venv`、`node_modules`、build tree、cache の存在だけで、不要な全量 copy／scan／hash を繰り返さない設計を
  優先します。
- Broker／staging は protected `.env` や secret を test／build へ自動注入しません。Sandbox が workspace 内の
  protected information を直接読み取れる受容済み残存 risk は、秘密情報を意図的に追加提供する根拠にはしません。
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

property の実測結果と Sandbox route の利用可否は分離します。workspace 内 protected-information read と LAN が
`failed` でも、受容済み残存 risk としてその事実を保持・表示し、その他の必須境界がすべて `verified` なら
Sandbox route は利用可能として構いません。受容済み risk を `verified` に書き換えたり検証結果から削除したり
しません。必須境界が `failed` または `unverified` の状態を capability 全体の
`Windows live-verified=true` または execution-route-available へ丸めません。

transport も capability truthfulness の対象です。stdio／HTTP 等の各 transport について、`configured`、
`enabled`、`available` と実効 authentication／principal 前提を区別し、startup validation が拒否する状態を
利用可能であるかのように session／UI／documentation へ表示しません。

過去の結果、mock、static test、direct ADB、stdio integration を、現在の commit に対する Windows live、
MCP ADB E2E、Tunnel、deployment の代替にしません。

## 4. 原則対象内

次は実装困難、性能、backend 制約だけを理由に対象外へ移しません。

- model の誤判断／過剰行動、悪意または予期しない workspace code
- project-controlled config／plugin／hook／autoload、arbitrary child／grandchild process
- malformed structured／binary input、secret leakage、workspace escape
- unintended network／device／external-service access。ただし Section 5 で明示的に受容した LAN access を除く
- workspace、`data_dir`、control-plane、scratch の境界違反
- stale approval、replay、double execution、cancel race、ordinary TOCTOU
- crash／timeout／cancellation、stale source／destination、path／filesystem race
- Broker helper の PATH shadowing、差し替え、stale executable identity
- Codex Sandbox の workspace 外 read／write／Internet／loopback／control-plane／必須 descendant boundary 不足
- ordinary non-admin Windows user 権限で成立する現実的な攻撃
- common project layout で起こる機能破綻、通常操作での重大 UX 破綻
- 容易に trigger できる resource exhaustion、過剰 copy／scan／hash／lock／approval
- Sandbox から Host への automatic fallback、capability と UI 表示の不一致

## 5. 対象外または受容する残存 risk

次は v1 の Trusted Computing Base、明示的対象外、または trusted operator が明示的に受容した残存 risk です。
ただし同じ技術分類でも、ここで明示していないものや通常の project code／一般入力から別の必須境界を
破るものは対象内です。

- workspace 内に存在する `.env`、credential、secret 等を Codex Sandbox process またはその descendant が
  直接読み取れること。workspace 外 protected information の read は含まない
- Codex Sandbox process またはその descendant が LAN／private network endpoint へ接続できること。
  Internet と未許可 loopback／localhost access は含まない
- Windows kernel、hardware、firmware、Windows security model 自体の compromise
- Administrator／trusted operator による意図的な security state 変更
- provenance／live verification を通過した Sandbox 実装自体の未知の OS sandbox 0-day
- trusted runtime／dependency environment が起動前から完全 compromise されている状態
- security boundary 外で同等以上の Windows user authority が既に完全奪取されている状態
- Approved Host と同一 principal で別 service／SID を導入しなければ防げない瞬間的な完全復元型改変
- hardware power loss の全 timing に対する完全 ACID durability
- 通常の validation／resource bound で防止不能な third-party parser の未知の 0-day
- 別 kernel component、専用 service、別 user principal を必須とし、個人利用 v1 として cost が明らかに
  不釣り合いな極端な攻撃

## 6. 既知問題と契約の対応

この表は問題の存在を確定するものではありません。現行実装で再検証し、`already fixed`、`obsolete`、
`partially fixed`、`still valid`、`reformulated` のいずれかを記録します。

| 重点確認項目 | 主な契約項目 |
| --- | --- |
| Broker helper executable の provenance／path／hash／file identity と差し替え耐性 | A, B, O |
| legacy `:workspace` と `workspace_write=false` の実効 filesystem boundary | C, D, O |
| workspace 外 protected information の read denial | D, K, O |
| workspace 内 `.env`／credential／secret の直接 read は受容済み残存 risk として正確に表示されるか | D, K, O |
| `.env`／dependency tree を含む過剰 staging | K, L |
| known-path operation の full workspace checkpoint | G, H, L |
| artifact chunk ごとの全 file 再hash | I, L |
| ChatGPT container source→result binding | G, I |
| Sandbox launcher の host-side cwd／DLL／search-path | C, D, F |
| Internet／loopback と child／grandchild の必須 containment | D, O |
| LAN access が受容済み残存 risk として正確に表示されるか | D, O |
| Sandbox property ごとの live verification と route 判定の分離 | D, O |
| DOCX／XLSX の過剰な file-wide rejection と保存能力表示 | J, L, O |
| 画像 format conversion の実用性と capability 表示 | J, L, O |
| CSV／TSV preservation 表示の正確性 | J, O |
| workspace／data／scratch の Windows physical identity | G, H, O |
| control-plane tamper、worker／approval／process lifecycle | E, F, H |
| checkpoint／CAS／GC concurrency と rollback／Undo | G, H, L, M |
| resource admission、protected information leakage | K, L |
| Live Activity／Timeline／preview／conflict／recovery 表示 | M, O |
| ADB emulator 固定 read integration | B, D, K, O |
| transport の実効 startup 可用性と session／UI／documentation 表示 | N, O |
| 古い README／SPEC／VERIFICATION | O |

## 7. リリース判定

release candidate と判断するには、少なくとも次を満たします。

1. 対象内の既知または新規 Security Contract violation と release-blocking な実用性回帰が残っていない。
   Section 5 で明示的に受容した workspace 内 protected-information read と LAN access は、それ自体では blocker
   としないが、実測結果と残存 risk を隠してはならない。
2. 修正後に security、practicality／performance、regression の独立 pass を繰り返し、2 回連続で新しい
   対象内 blocker を発見しない。
3. full pytest、Ruff、compileall、`git diff --check` と、該当する security／structured-file／race／approval／
   recovery／transfer／resource／Activity／Undo の回帰を現在の commit に対して実行する。
4. 実行可能な Windows live test、ADB emulator integration、Secure MCP Tunnel／ChatGPT E2E を実行し、
   実行不能なものは未検証として理由を記録する。Sandbox は property ごとの実測結果と、それが必須境界か
   受容済み残存 risk かを残す。
5. README、`SPEC.md`、`VERIFICATION.md` と関連文書を現行実装へ合わせ、過去の architecture や過去の
   検証結果を現在の保証として再利用しない。
