# 検証記録

## 2026-08-13 既知セキュリティ問題の再検証と修正

### 対象と基準

- 最終確認対象: `main` / `30cd90f709793088621f5fbc2224077d5b0c374b`
- 作業開始時は `81c8e86d39900d9ca0fcf4bb75ea1bc91b7dba31` だったが、作業中に別プロセスの `git pull origin main` が `0bcac0e` と `30cd90f` を fast-forward した。巻き戻さず、追加された Timeline 実装と回帰も含む現在の `main` で再検証した。
- 基準: `SECURITY_CONTRACT.md`、SHA-256 `abc0c0bf47dd2952d97dbbc52b01f65e8b091fd8ce1f49cb98d955dc4e54c0e1`
- `SECURITY_CONTRACT.md` 自体は変更していない。
- 作業開始時の working tree は clean で、既存 user changes はなかった。commit／push は実施していない。

### Section 6 の判定

判定は修正前の現行コードを基準にし、右端にこの作業後の扱いを記録する。

| # | 重点確認項目 | 判定 | この作業後の扱い |
| --- | --- | --- | --- |
| 1 | Broker helper executable の provenance／path／hash／file identity と差し替え耐性 | still valid | Git／ADB を明示 path・SHA-256・file identity に固定し、Windows では実行中の差し替えを拒否 |
| 2 | legacy `:workspace` と `workspace_write=false` の実効 filesystem boundary | reformulated | profile 名や staging 表示を OS 境界の証拠にせず、必要 property 未検証時は実行経路を unavailable にする |
| 3 | Sandbox runtime から protected information を直接読める可能性 | reformulated | staging 漏えいを除去し、process／descendant の直接 read denial が実機未検証なら実行不可 |
| 4 | `.env`／dependency tree を含む過剰 staging | still valid | 保護 file と `.venv`／`node_modules`／`build`／`__pycache__` 等を除外 |
| 5 | known-path operation の full workspace checkpoint | still valid | 単一・複数の既知 path scope と source／destination の決定順 lock へ局所化 |
| 6 | artifact chunk ごとの全 file 再hash | already fixed | 不変 snapshot と開始／完了／commit 境界の検証を維持し、回帰なし |
| 7 | ChatGPT container source→result binding | already fixed | 既存拘束を維持し、派生出力の置換後 source 再検証と復旧を追加 |
| 8 | Sandbox launcher の host-side cwd／DLL／search-path | still valid | host cwd を信頼済み install directory に固定し、相対・workspace・data・scratch・利用不能 PATH entry を除外 |
| 9 | Internet／LAN／loopback と child／grandchild containment | partially fixed | property を分離し、現在の実機で未確認のためすべて unverified、実行不可 |
| 10 | Sandbox property ごとの live verification と aggregate 表示 | still valid | marker v2、9 property、backend digest 拘束、旧／部分 marker 拒否、`available`／`windows_live_verified`／`execution_route_available` 分離 |
| 11 | DOCX／XLSX の過剰な file-wide rejection と保存能力表示 | already fixed | package patch と既存保存回帰を確認、変更なし |
| 12 | 画像 format conversion の実用性と capability 表示 | still valid | extension が一致する別 `output_path` と source／既存 destination hash を導入 |
| 13 | CSV／TSV preservation 表示 | reformulated | semantic preservation と lexical quoting／byte identity 非保証を明示 |
| 14 | workspace／data／scratch の Windows physical identity | partially fixed | 3 root を安定 identity と handle-resolved physical path で比較し、SUBST 別名を実機拒否 |
| 15 | control-plane tamper、worker／approval／process lifecycle | partially fixed | 既存 one-shot／TTL／claim／tamper guard を維持し、承認後 executable identity と実行中 hold を追加 |
| 16 | checkpoint／CAS／GC concurrency と rollback／Undo | already fixed | 既存 journal／CAS／GC／Undo 整合性を維持し、checkpoint scope を全経路へ伝播 |
| 17 | resource admission、protected information leakage | partially fixed | 既存上限・redaction を維持。Sandbox の process／memory 等は未検証なので resource property と経路を fail closed |
| 18 | Live Activity／Timeline／preview／conflict／recovery 表示 | already fixed | 作業中に更新された現在の main の binary transfer lifecycle 修正と既存 Activity 回帰を含め全回帰通過 |
| 19 | ADB emulator 固定 read integration | partially fixed | 固定 target 文法・emulator policy を維持し、helper trust anchor を追加、未許可 device 列挙を自動文法から除外 |
| 20 | transport の startup 可用性と session／UI／documentation 表示 | still valid | stdio／HTTP の configured・enabled・available・startup validation を分離し、拒否される HTTP を available としない |
| 21 | 古い README／SPEC／VERIFICATION | still valid | README／SPEC／この検証記録を現行実装と現在の検証限界へ更新 |

内訳は `already fixed` 5、`obsolete` 0、`partially fixed` 5、`still valid` 8、`reformulated` 3、合計 21 項目。

### 自動回帰と静的検査

- 全回帰: `.venv\Scripts\python.exe -m pytest -q --basetemp .pytest-tmp-task3-final` は 215 passed、2 skipped。skip はこの権限で symlink／junction を作成できない 2 件で、hardlink 回帰と Windows 固有回帰は通過した。
- 対象回帰: helper trust／実行中差し替え、実 Git stdio、approval TTL／one-shot／tamper、Sandbox marker／PATH／timeout、scoped checkpoint／lock／rollback、artifact source binding、image／CSV／ZIP、transport 表示を実行し通過した。
- 変更 file に対する Ruff: pass。
- `python -m compileall -q src tests`: pass。
- `git diff --check`: pass。LF／CRLF の将来変換 warning のみ。
- repository-wide `ruff check .` は、作業中に現在の main へ追加された `src/windows_local_mcp/timeline.py` の import order 1 件で failure。この独立した非 security 変更は本作業で書き換えていない。

### Windows 実機確認

- 実 Git を明示 path／SHA-256 で固定した stdio MCP から `git_info` と固定文法 `git status --short` を実行した。
- Win32 file sharing を使い、保持中の helper file replacement と親 directory rename が拒否され、解放後だけ成功することを確認した。
- subprocess timeout 時に identity-bound parent と descendant を終了し、grandchild heartbeat が停止することを Windows process-tree probe で確認した。これは Codex Sandbox 内の descendant containment の証拠ではない。
- `SUBST W:` で workspace の別名を data path として構成し、physical overlap として設定拒否されることを確認した。割り当ては試験内で解除した。
- installed Codex CLI `0.147.0-alpha.6.6` の backend identity／version 解決を確認した。最小 `codex sandbox` command は 20 秒で timeout したため、次の全 property は `unverified`、`passed=false`、実行経路 unavailable と記録した。
  - `filesystem_read`
  - `filesystem_write`
  - `protected_information_read`
  - `internet`
  - `lan`
  - `loopback`
  - `descendant_containment`
  - `termination`
  - `resource_bound`
- Sandbox live verifier の初回実行で、アクセス不能な Windows App Execution Alias が host PATH sanitization を停止させる問題を再現した。信頼済み root の解決失敗は fail closed のまま、ambient PATH の利用不能 entry だけを除外する修正後に backend version 解決まで進むことを確認した。

### unit／mock／integration のみで確認した範囲

- Sandbox property marker の旧版／部分成功／backend mismatch 拒否と、全 property 成功時だけの経路許可。
- Sandbox 失敗／未検証から Approved Host へ自動 fallback しない control flow。
- protected file／dependency tree の staging 除外。ただし Sandbox process 自身の OS read denial の代替証拠ではない。
- approval request hash、argv／cwd／executable／input／settings binding、stale／double claim／expiry／cancel terminal race。
- Approved Host 後の control-plane tamper detection と後続 fail closed。
- scoped checkpoint／CAS／journal／rollback／selective Undo、source・destination concurrent modification、ZIP transaction recovery。
- DOCX／XLSX／CSV／TSV／ZIP／image の malformed／preservation／resource 回帰。
- stdio transport と HTTP startup rejection の表示整合性。

### 未検証

- 上記 9 つの Codex Sandbox OS property と、Sandbox 内での simple command／developer command 成功経路。
- Codex Sandbox の process 数、memory、filesystem entry を含む完全な resource bound。
- real ADB server／emulator／device identity／5037／screenshot と MCP ADB E2E。この端末では `adb` が見つからなかった。
- Secure MCP Tunnel／ChatGPT E2E、deployment、外部 service、実運用負荷。
- hardware power loss の全 fsync／SQLite timing に対する永続性。
- Section 7 の release 用 repository-wide 2 回連続独立 review pass。本作業は既知問題と修正箇所の回帰に限定した。

### 性能・実用性への影響

- known-path mutation は full workspace scan／checkpoint から対象 path scope へ縮小した。ZIP 複数展開も source と既知出力 path の lock／checkpoint だけを使う。
- 別 target slot の mutation は並行可能で、同一 source／destination と workspace-wide writer は引き続き競合する。
- Git snapshot の固定コマンド群は helper identity hold を共有し、Windows での helper 全体 hash は一連の snapshot 当たり trust capture と hold 開始の 2 回へ集約した。
- `.venv`／`node_modules`／`build` 等の不要な staging copy を除去した。
- artifact chunk は開始時の不変 snapshot を読み、chunk ごとの全 file rehash／data_dir 全走査を行わない既存実装を維持した。
- 定量 benchmark は実施していないため、速度向上率は保証しない。

### 次の新規セキュリティ監査への引き継ぎ

- 本作業中に、既知問題と独立した新規脆弱性は確認していない。
- 次タスクでは未知問題の探索と、本記録の未検証項目を区別する。特に Codex Sandbox の 9 property を実測できる backend／setup が得られた場合は、property ごとの probe を再実行する。
- repository-wide Ruff の `timeline.py` import order は独立した非 security 品質事項であり、新規脆弱性としては扱わない。
