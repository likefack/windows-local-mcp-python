# Approved Host immutable runtime

Approved Host は通常の Windows user authority で one-shot command を実行するため、同じ user が WLMCP／Python runtime を永続改変できる配置では利用しません。

ただし runtime immutability は Approved Host 全体の security boundary ではありません。WLMCP-R2-001 の再検証により、Approved Host child と worker／postflight monitor が同一 Windows user authority にある current architecture では、child が監視側を停止して postflight を回避でき、restart 時の stale reconciliation だけでは durable tamper latch が残らないことを valid と判定しました。same-desktop UAC elevation だけではこの authority separation を満たしたものと扱いません。

そのため current v1 の Approved Host execution route は capability reduction として fail closed です。`approved_host_enabled=true`、immutable runtime の存在、`request_host_command`、pending／approved operation は execution availability を意味しません。production runtime gate は Approved Host worker spawn 前に必ず拒否し、upgrade 前の queued／approved operation も実行しません。

開発用の repository checkout と `.venv` は user-writable であることを前提とします。この開発 runtime は Broker／Codex Sandbox の開発・テストには使用できますが、Approved Host の production trust anchor にはしません。

## Runtime immutability mechanism

既存の installer／verification code は、将来 Approved Host を安全に再有効化する場合の runtime immutability layer として残します。これは Python／WLMCP runtime を same-user child の永続改変から守るための一層であり、monitor／postflight kill resistance や restart-persistent tamper state を単独で証明しません。

既定の immutable runtime layout は次です。

```text
C:\Program Files\WindowsLocalMCP\
  runtime\
  run-server.ps1
  run-approvals.ps1
  verify-approved-host-runtime.ps1
  config.example.toml
```

`runtime` の venv だけでなく、その venv が参照する base Python も non-elevated WLMCP user から immutable である必要があります。配置場所の名前だけを trust anchor にはせず、Windows effective-access check で検証します。

## Provisioning reference

将来の再有効化検証や runtime immutability layer の開発目的では、管理者 PowerShell から通常 Windows account を `RuntimeUser` に指定して provision できます。

```powershell
.\install-approved-host-runtime.ps1 `
  -BasePython "C:\Program Files\Python312\python.exe" `
  -RuntimeUser "$env:USERDOMAIN\$env:USERNAME"
```

既存 install を置換する場合だけ `-Replace` を付けます。

installer は `InstallRoot`、`BasePython`、`sys.base_prefix` が Windows の Program Files 配下であることを admission 時に要求します。そのうえで wheel を `.dev-tmp\approved-host-runtime` に build し、staging directory へ非 editable install した後、staging 全体の owner／ACL を固定してから active `InstallRoot` へ移します。通常 runtime user には RX、SYSTEM と Administrators には Full Control を与えます。Program Files 配下という名前だけを immutability の証拠にはせず、base Python を含む実効 access は後段の non-elevated verification で再検証します。

## Non-elevated runtime verification

通常 user の非昇格 PowerShell では次の verifier を実行できます。

```powershell
& "C:\Program Files\WindowsLocalMCP\verify-approved-host-runtime.ps1"
```

lower-level verifier は installed Python を `-I -B` で起動し、runtime immutability algorithm を検査します。current v1 の production `assert_approved_host_runtime_immutable()` は WLMCP-R2-001 capability reduction のため意図的に fail closed するので、この lower-level mechanism の成功を Approved Host availability と解釈してはいけません。

runtime immutability layer は少なくとも次を拒否します。

- Python が isolated mode ではない
- WLMCP package、startup-active dependency、import namespace、launcher が user-writable
- runtime path／TCB path に危険な reparse point がある
- runtime directory／ancestor に置換可能な effective access がある
- base Python／stdlib／DLL 等が current user から永続改変可能

`python3.exe` のように import/startup に参加しない namespace sibling が reparse point であることだけでは runtime 全体を unavailable にしません。一方、`.pth`、Python source／bytecode、native extension、package directory、declared dependency tree の reparse／mutation は引き続き拒否します。

## Current v1 execution status

current v1 では、immutable runtime を provision して verifier の lower-level check が成功しても Approved Host command を実行してはいけません。server／approval UI を immutable runtime から起動すること自体は Broker／Codex Sandbox の運用や将来境界の検証に利用できますが、Approved Host tier は worker spawn 前に停止します。

`session_info()` では Approved Host の設定意図と実行可否を混同しないでください。current capability は `available=false`、`live_verified=false`、`windows_live_verified=false` です。runtime immutability の unit／synthetic evidence を Approved Host 全体の live verification へ昇格させません。

## Requirements before re-enabling Approved Host

Approved Host execution を再有効化する変更は、少なくとも次を先に満たす必要があります。

1. monitor／postflight owner と durable tamper state を untrusted Approved Host child と同じ有効 authority に置かない。
2. child から monitor／worker／postflight owner を terminate、suspend、rewrite、ACL-reset できない Windows security boundary を使う。same-desktop UAC elevation 単独をこの根拠にしない。
3. child／worker／monitor の異常終了、channel loss、timeout、postflight 未完了、control-plane mismatch を restart 後にも残る durable fail-closed state に結合する。
4. stale operation を単に `interrupted` へ変える処理だけで tamper state を解除しない。
5. Job Object descendant と WMI／CIM 等の Job 外 process creation の双方を閉じる。
6. monitor kill、worker kill、postflight bypass、restart recovery、normal completion を Windows 実機 regression で確認する。
7. capability 表示を `configured`／`enabled`／`available`／`Windows live-verified` に分離し、未実証状態を availability に丸めない。

別 user／session、SYSTEM service、または Microsoft が security boundary として扱う同等の authority separation が候補になりますが、採用時には実際の ACL／token／process／IPC／durable-state semantics を個別に実証します。

## CI と Windows live verification

GitHub hosted runner では、current v1 が Approved Host worker を spawn しないこと、upgrade-existing queued／approved Host operation が production gate で停止すること、lower-level runtime immutability unit tests が維持されることを確認します。

Hosted CI の synthetic／integration test を将来の Approved Host OS boundary の Windows live verification の代替にはしません。current v1 では Approved Host route 自体が unavailable なので、Approved Host command の production E2E 成功を release criterion にしません。再有効化する変更では、上記 requirements を実 PC／account／service/session boundary で別途 live-verify する必要があります。
