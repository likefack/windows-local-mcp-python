# 2026-09-21 Codex Sandbox 復旧調査

## 結論

Codex Sandbox はこの PC の正式設定では引き続き利用不可とする。検証結果を成功へ丸めたり、Approved Host へ自動切り替えたりはしない。

- 自動選択される Codex `0.155.0-alpha.2.6` は、最初の固定コマンドで ``elevated Windows sandbox requires effective `:root` read access`` を返す。WLMCP の最小読み取りポリシーを `:root` へ広げる変更は行わない。
- 導入済み公式 npm 版 Codex `0.146.0` は、署名と helper identity の検証を通過し、親プロセス側を含む大部分の境界を実行できる。ただし正式な `verify-codex-sandbox` では `child_outside_user_read_denied=false` と `grandchild_outside_user_read_denied=false` になり、必須の descendant containment を満たさない。
- 調査用に行った `approved_sandbox_codex_path` の `0.146.0` 固定は、正式検証失敗後に検証済みバックアップから元の自動選択へ戻した。失敗した候補を運用設定へ残していない。

## 起動停止の別原因と修正

Sandbox の検証とは別に、`data_dir` の ACL 検査が、Codex Windows Sandbox がローカル `CodexSandboxUsers` グループへ追加する既知の読み取り拒否 ACE 2 本を未知の ACL として拒否していた。このため Sandbox を一度使用した後、次の `run-localmcp.bat` が設定読み込みで停止していた。

`config.py` は、現在の PC でネイティブに解決した `CodexSandboxUsers` SID に対する正確な root 読み取り拒否と子要素継承用読み取り拒否だけを受理する。未知の SID、許可 ACE、拒否 mask、順序、重複、継承条件は引き続き fail closed とする。既存の許可 marker digest は現在ユーザーと SYSTEM の canonical な許可 ACE に結合したままで、拒否 ACE を成功扱いへ丸めない。

## Sandbox の実機結果

正式設定へ npm 版 Codex `0.146.0` を一時的に明示指定し、導入済み運用用 runtime から次を実行した。

```powershell
python -I -B -m windows_local_mcp.cli verify-codex-sandbox
```

結果は fail closed だった。

- parent filesystem／network／resource／WFP／brokered-process checks: 成功
- `child_outside_user_read_denied`: `false`
- `grandchild_outside_user_read_denied`: `false`
- `descendant_containment`: `failed`
- `passed`: `false`
- execution route: 利用不可

保存された最新 evidence は `%LOCALAPPDATA%\WindowsLocalMCP\0ee2f1f2f578a4f88b19258f\control-plane\sandbox-live-verification.json` にある。

追加診断では、probe の子プロセスは現在ユーザーへ戻ったのではなく、`CodexSandboxOffline` の専用ローカルアカウント、`CodexSandboxUsers` グループ、medium integrity で動作していた。それでもユーザープロファイル直下に作成した outside canary を子・孫から読み取れた。したがって、WLMCP の必須契約である workspace 外 user file の read denial は成立していない。

同じ候補が一時設定の `persist_evidence=False` 検査で全項目成功した実行もあったが、正式設定の再検査で再現しなかった。現在の route 判定では、永続化した正式検査の失敗を正本とする。

## 採用しなかった変更

- `:minimal` を `:root` に変更して Sandbox の読み取り範囲を広げること
- 検証用 canary だけへ拒否 ACE を追加し、workspace 外の一般ファイルも保護されたように扱うこと
- `C:\Users\22905` 全体の ACL をこの作業だけで変更すること
- Sandbox 失敗時に Approved Host へ自動で切り替えること

これらは、必須境界を弱める、検証対象だけを特別扱いする、または広範な OS 状態変更を伴う。Sandbox は upstream backend と WLMCP の全必須境界が同じ正式検証で通過するまで unavailable を維持する。

## OpenAI 公式情報との照合

OpenAI の Windows Sandbox ガイドは、elevated sandbox が専用の低権限ユーザーとファイルシステム権限の境界を使用すること、停止時には setup の再実行と `.sandbox` ログの確認を案内している。今回も `%USERPROFILE%\.codex\.sandbox\sandbox.2026-09-20.log` を確認した。`0.146.0` の setup 自体は `errors=[]` で完了しており、今回の最終停止理由は setup 起動失敗ではなく descendant の outside-user read denial 不成立である。

参考: [OpenAI 公式 Windows Sandbox ガイド](https://learn.chatgpt.com/docs/windows/windows-sandbox?translationFallback=ja-JP)

## 追加調査とポリシー互換性の表示修正

### 現時点の判定

Sandbox の安全な復旧は未解決。以下の表示修正だけで復旧完了やリリース可能とはしない。
今回の復旧受け入れ条件は、一般 Sandbox の既存の残存リスク例外を成功の代用とせず、protected information、LAN を含む全項目の成功とする。
この追加調査では既存の例外を恒久仕様から削除していない。

タスク開始時の追跡対象差分、未追跡ファイル一覧、変更済みファイルの内容とハッシュは
`.dev-tmp/sandbox-recovery-20260921/start.patch`、`start-status.txt`、`baseline/` に保存した。
並行作業による Approved Host・ランチャー・設定関連の変更は、本調査の変更に含めない。

### 実測と候補の比較

| 候補 | 今回の確認 | 判定 |
| --- | --- | --- |
| Desktop `0.155.0-alpha.2.6` | 導入済みの変更不能な runtime から正式 `verify-codex-sandbox` を再実行。最初の固定コマンドが終了コード1で ``requires effective `:root` read access`` を返した | `verification_status=unverified`、`route_eligible=false`、`passed=false` |
| 公式 npm 安定版 `0.155.1` | 既存インストールと分離して取得。OpenAI 署名、実体、SHA-256、helper、version を確認した候補へ同じ最小ポリシーの固定コマンドを渡し、同じ拒否と終了コード1を観測 | ポリシー非互換。診断結果を正式 marker へ書き込んでいない |
| 公式 npm `0.146.0` | 本文に記録した過去の正式検証で子・孫の outside-user read denial が失敗 | 今回の復旧候補として成功扱いしない。今回の再実測とは区別する |
| 公式 npm `0.153.4` | 過去の別実行で成功記録があるため分離配置へ取得。今回の診断は正式設定読み込みの filesystem replace 検査が `WinError 32` で停止 | Sandbox 実行前の検証不能。過去の成功を現在の根拠に流用しない |

正式 Desktop 検証の時刻は `2026-09-21T16:58:14+09:00`。証拠は
`.dev-tmp/sandbox-recovery-20260921/turn2-formal-desktop.json` に保存した。
`source_workspace_read_acl_guard.added=false`、`added_before_verification=false` であり、今回の正式検証では
source ACL の追加は行われていない。WFP やユーザープロファイル全体の ACL を広げる変更も行っていない。
同じホスト実行経路の Windows token 検査は `restricted_token=false`、`elevated=false`、`app_container=false`。
Codex Desktop の制限トークン内で行った入れ子の Sandbox 結果を実機成功として扱っていない。

安定版の診断は `turn2-stable-probe.json` に保存した。launcher SHA-256 は
`eba0f32c976667cb9298efafd98513e823eeda7b576a03ec658bb8be8d336316`。
候補ディレクトリは `%LOCALAPPDATA%\WLMCP-Sandbox-Candidates\` 配下で、運用設定や既存 Codex を置換していない。
Windows のパッケージ仮想化で実パスが異なるため、診断時は canonical path を再解決し、指定候補が実際に選択されたことを照合した。
候補の npm resource directory にある command runner と setup helper の署名も別途確認したが、
新配布構成の全実行時依存関係を承認経路として正式検証したものではない。

### 原因

backend resolver は、明示 path、Desktop cache（新しい更新日時順）、Programs、standalone、npm の順で探索し、
署名・helper identity・`--version` を通過した最初の実体を返す。管理対象ポリシーの受理までは確認しない。
このため起動非互換の Desktop でも、従来の `session_info` は `dependency_available=true` と
`available=true` を同時に表示していた。正式 marker の gate により実行は拒否されており、拒否を迂回していたわけではない。

公式 `rust-v0.155.1` の `codex-rs/windows-sandbox-rs/src/resolved_permissions.rs` にある
`validate_elevated_filesystem_policy` は、cwd の filesystem root が実効的に読めることと、root が read deny でないことを要求する。
公式 `rust-v0.156.0-alpha.14` の同関数にも同じ拒否がある。後者は公開ソース確認であり、その alpha 配布物の実機検証ではない。
これは `:minimal=read` と必要な実行依存だけを許可する WLMCP の要件と両立しない。
`:root=deny` の追加や、設定名の変更ではこの必要条件を満たせない。

### 実装変更と残る条件

`dependency_available` は署名済み依存関係の解決、`policy_compatibility` はポリシー受理、
`execution_route_available` は全必須境界の成立として分離した。
正式検証の `simple_command=true` を受理証拠として使う際は、失敗・未検証 marker でも
backend、version、isolation context、Windows、account、WFP binding、TTL を照合する。
identity 不一致や期限切れは `unverified`、既知の root-read 拒否は `rejected` とし、
いずれも `available=false`。固定コマンドが成功しても他の必須境界が失敗すれば実行経路は閉じたままとする。
通常の状態取得は読み取り専用であり、候補の自動実行、UAC、修復、別経路への fallback を追加していない。

今回の実 MCP `request_sandbox_command` は承認登録前に拒否された。
監査 operation `c4860abf-747a-45b4-aa15-670dbc1d5ba3` は `status=rejected`、
理由は `ApprovedSandboxUnavailable` と未検証 marker。承認IDは発行されておらず、
ローカル承認後の一回限りの実行、`poll_approval` による実行結果、stdout、終了コードは未検証。
接続中 MCP の状態取得・拒否監査を確認したことを、Windows local の正常実行 E2E や
Secure MCP Tunnel／ChatGPT connector の正常実行 E2E 成功とは扱わない。

復旧には、最小読み取りポリシーを正式に受理し、子・孫にも outside-user read denial を維持する署名済み upstream backend が必要。
別案は、その保証を提供する OS 境界へ実行方式を変更することだが、Windows ツール互換性、配布・署名、
承認 identity、WFP／Job／resource bound の設計と全実機再検証が必要になる。
広範な read 許可、canary だけの ACL 拒否、旧版の単純固定は採用しない。

### この追加調査で変更したファイル

- `src/windows_local_mcp/sandbox_backend.py`: 正式 marker に結合したポリシー互換性の読み取り専用判定。
- `src/windows_local_mcp/server.py`: 依存関係・ポリシー受理・実行経路を分離した capability 表示。
- `tests/test_sandbox_policy_compatibility.py`: root-read 拒否、部分成功、identity／policy／TTL 変更の回帰。
- `tests/test_server_operations.py`: 署名済み依存関係だけでは available にしない回帰。
- `SECURITY_CONTRACT.md`: 起動前提に管理対象ポリシーの受理が必要なことを明確化。必須保証と既存の残存リスク例外は縮小・変更しない。
- `SPEC.md`: ポリシー互換性の状態と読み取り専用判定を追記。
- `README.md`: 状態表示の見方を追記。
- `VERIFICATION.md`: 今回の実測、回帰結果、未検証範囲、運用 runtime 未配布を記録。
- `docs/SANDBOX_RECOVERY_2026_09_21.md`: 本追加調査の記録。

既存変更ファイルとの比較では、本調査が編集しない12ファイルの SHA-256 は開始時と同一だった。
上記のうち開始時から変更済みだった仕様・検証・復旧記録の3ファイルは追記のみ。
テスト終了後、今回のテスト専用ディレクトリを参照する検証プロセスの残存は観測されなかった。
コミットは行っていない。

## 方式選定に向けた追加実測

同日後続の調査では、公式 npm `0.153.4` の設定読み込みを通過し、通常 Windows user 文脈で導入済み runtime の境界検査を実行できた。
前述の `WinError 32` は今回再現しなかったが、原因を特定・修正したとは扱わない。
署名は `Valid`、launcher SHA-256 は `444a3f0008050605cae73cd9b7a2dcac61294062dfaab56dd20430fd6498518b`。
検査結果は `passed=false` で、次の3項目が失敗した。

- `outside_user_read_denied`
- `child_outside_user_read_denied`
- `grandchild_outside_user_read_denied`

これは実ファイルの読み取り拒否検査の失敗であり、署名の有効性や単純起動の成功では補えない。
結果は `.dev-tmp/sandbox-native-implementation-20260921/candidate-01534.json` に保存した。
`verify_codex_sandbox_live(..., persist_evidence=False)` による候補診断であり、正式 CLI の全工程を完了したものではない。
正式 marker を更新せず、運用設定を候補へ切り替えていない。brokered process の正式な追加工程と承認後 E2E の成功証拠もない。
過去の `0.153.4` の成功記録は今回の失敗を上書きしない。

方式の比較では、適合する署名済み backend がある場合、既存方式の維持が変更範囲、起動負荷、既存 Windows ツール利用の面で有利と判断する。
ただし確認した候補はすべて必須条件を満たさず、WLMCP 側の設定変更だけで安全に復旧できる根拠は得られていない。
必要な upstream 対応は、最小読み取りポリシーの受理に加え、親・子・孫へ既定拒否を実効的に適用することである。
根本原因の詳細は未確定であり、単に root-read の事前検査を削除する修正だけでは十分としない。
変更した backend の OpenAI 署名付き配布物と、同一の正式検証による全境界成功が必要になる。

仮想マシン方式はホストとは別のカーネルを隔離境界にできるが、共有フォルダー、入出力回収、通信、承認、資源制限を含めた設計・検証が必要であり、自動的に WLMCP の保証を満たすわけではない。
ホストの確認結果は `Microsoft Windows 11 Home`、`10.0.26200`、`HypervisorPresent=true`。
Microsoft の Windows Sandbox は Home 非対応で、当該実行ファイルと Hyper-V PowerShell module も見つからなかった。
これは Codex Windows Sandbox 自体の OS 非対応を意味しない。両者は別の実装である。
参考: [Microsoft Windows Sandbox の対応エディションと隔離方式](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/)。

このため仮想マシン方式には、対応エディションへの変更、または Home で対応する別製品・ゲスト環境の選定が先に必要になる。
OS 購入・更新・再起動や別製品の導入は実施していない。方式変更の追加負担に関するユーザー判断を待つ。
現時点の状態は引き続き **未解決**。経路を閉じることは根本修正の完了ではなく、必須境界が成立しない状態での実行を防ぐ措置である。

## 18:27 以降の読み取り漏れ原因調査による訂正

上記の `0.153.4` による outside-user read 失敗は実測だが、**`0.153.4` 自身が読み取り許可を追加した証拠ではない**。同じ Sandbox アカウントと `CodexSandboxUsers` グループを使う Codex Desktop の並行した設定処理が検証へ干渉していた。先の「確認した候補はすべて必須条件を満たさない」という記述は、候補単独の能力判定としては撤回する。Desktop `0.155.0-alpha.2.6` の最小ポリシー拒否は別の実測であり、この訂正の対象ではない。

無害な検証用ファイルを一つ作り、同じファイルに対して `0.146.0` → `0.153.4` → `0.146.0` の順で親・子・孫の読み取りを測定した。最初の `0.146.0` は全て拒否し、次の実行時にファイルの ACL へ `CodexSandboxUsers` の読み取り許可 ACE `0x1200a9` が追加されて全て読めるようになり、最後の `0.146.0` でも読めた。記録は `.dev-tmp/sandbox-read-cause-20260921/sequence-869e129ee82b4e38ba83fcc4a0bb89bb.json` にある。コマンドの引数に名前を渡していない別の検証用ファイルにも同じ許可が追加された。起動後に作成したファイルは拒否された。

ただし、共有 Sandbox ログの時系列を照合すると、上記 ACL 追加の直前 `18:46:00.093 JST` に Codex Desktop 配下の `codex-windows-sandbox-setup.exe` が二つ起動し、`18:46:00.185 JST` に対象 ACE が追加された。`0.153.4` 候補の helper 起動は `18:46:04.274 JST` で、その読み取り ACL 処理に当該許可追加は記録されていない。同様の過去4回の検証用ファイルへの許可追加も、全て Desktop helper の起動直後だった。ログに PID がないため、同時起動した Desktop helper のうちどちらが書いたかまでは特定できない。

さらに通常 Windows ユーザー文脈の導入済み runtime から `0.153.4` を明示指定して一回再測定した。新しい検証用ファイルの ACL は実行中に変わり、親・子・孫が読めた。しかし今回も `18:59:16.833 JST` に Desktop helper が先に起動し、`18:59:16.907 JST` に読み取り許可 ACE が追加された。候補 `0.153.4` の helper 起動は `18:59:17.893 JST` だった。結果は `.dev-tmp/sandbox-read-cause-20260921/single-0.153.4-b2c7fc0b84d64885a3aec2b7b3c445aa.json` に保存した。検証用ファイルは削除済み、既存 ACL の変更や復元はしていない。これは候補単独の正式 live verification ではなく、正式 marker も更新していない。

WLMCP の管理対象ポリシーにはユーザープロファイル全体の読み取り許可はない。[OpenAI 公開ソースの `rust-v0.153.4` の設定処理](https://github.com/openai/codex/blob/rust-v0.153.4/codex-rs/windows-sandbox-rs/src/setup.rs)では、`:root` の実効読み取りがある場合に profile 直下を読み取り root として列挙する経路があり、設定 helper は渡された root に Sandbox グループの許可 ACE を付ける。一方、WLMCP の `:minimal=read` と明示依存先だけのポリシーは、当該 root-read 経路を要求しない。この実測とソースは、**共有 Sandbox グループへの別の設定処理による許可が、狭いポリシーの実行にも残る**ことと整合する。Desktop が広い読み取り範囲を要求した理由や、その利用における適否は今回判定していない。

現在の正式 marker は Desktop `0.155.0-alpha.2.6` に対する `verification_status=unverified`、`passed=false` であり、Sandbox 経路は利用不可のままである。仮に旧版が単独実行で新しい検証用ファイルの読み取りを拒否しても、別の Codex 処理が以前に許可した既存ファイルは読める可能性がある。正式 marker は backend・隔離文脈・OS・アカウント・WFP 等へ結合するが、共有グループに対する作業領域外ファイルの ACL 変化を継続監視しない。このため旧版固定や新規ファイル一個の合格を、持続的な読み取り境界の証明に使わない。

この境界違反の技術的判定は `valid`、現行契約上の修正判断は `must-fix` とする。前提は、別の Codex 実行が先に同じ Sandbox グループへ対象ファイルの読み取りを許可していることと、その後に WLMCP の Sandbox で信頼できないコマンドが動くことである。後者は本来の製品用途であり、攻撃者が事前に Windows 管理者権限を得る必要はない。取得し得る新しい能力は指定外の既存ユーザーファイルの内容を Sandbox の標準出力へ出すことで、主な実害は機密性にある。通常の並行 Codex 利用で前提が発生したため、特殊な競合のみの理論上の問題として受容しない。一方、ユーザーフォルダー全体への拒否 ACL や全ファイル走査は通常利用への影響と競合を増やし、検証用ファイルだけの ACL 操作は保証を偽るため、局所対策として採用しない。

安全な復旧には、同じ Windows 上で他の Codex 実行が共有 ACL を更新しても、WLMCP の Sandbox 実行に指定外ファイルの読み取り能力が加わらない OS 境界が必要である。これを実現できる署名済み backend、または同等の principal 分離を伴う実行方式が得られた後、既存ファイルと新規ファイル、親・子・孫、他の Codex 設定処理との同時実行を含めて検証し、全ての必須境界と承認後実行を正式手順で再確認する。検証用ファイルだけの拒否 ACL、ユーザープロファイル全体の ACL 変更、`:root=read`、Approved Host への自動切り替えは行わない。

## 当面の運用判断と再検討条件（2026-09-21）

この PC では WLMCP の Codex Sandbox 経路を現状の利用不可状態のままとし、専用 backend の新規実装や仮想マシン方式への移行はいったん保留する。WLMCP は Broker の範囲でファイルの読み書き・検索などの軽作業に使い、テスト、ビルド、Python・Node・PowerShell のスクリプト実行は Codex 側の別の実行経路で行う。Codex 側の実行環境には WLMCP の Sandbox 境界が適用されないため、それぞれの権限設定と検証結果を混同しない。WLMCP の Automatic Git も Sandbox の正式検証が前提であり、現状は利用不可とする。

これは開発優先度と運用方法の判断であり、Sandbox の読み取り制限違反を解決済みとするものでも、`SECURITY_CONTRACT.md` の必須境界や将来の機能要件を縮小するものでもない。必須境界が成立しない Sandbox 実行は引き続き fail closed とし、Approved Host への自動切り替えを追加しない。OpenAI 版の更新という事実だけでは安全性を認定しない。現行実装は `approved_sandbox_enabled=true` なら backend 変更後に正式検証を自動開始し、全必須条件を満たせば経路を利用可能と判定する。再検討まで利用停止を設定として固定する場合は `approved_sandbox_enabled=false` が必要であり、この記録の追記だけでは運用設定を変更していない。

OpenAI から修正を含む署名済み backend が提供された場合は、既存方式での復旧を再検討してよい。再検討では、まず WLMCP の最小読み取りポリシーをその実体が受理することを確認する。そのうえで、他の Codex 処理が共有 ACL を更新した既存ファイルを含め、指定外ファイルの読み取り拒否が親・子・孫で保たれることを通常 Windows ユーザー文脈の実機テストで確かめる。ファイル・ネットワーク・子孫プロセス・終了・資源制限など既存の必須境界を同じ正式手順で検証し、承認後の一回限りの実行と結果取得まで確認してから利用再開を判断する。Automatic Git を再開する場合は、別途 Git 固有の正式検証も必要である。
