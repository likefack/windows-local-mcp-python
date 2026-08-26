# Approved Host immutable runtime

Approved Host は通常の Windows user authority で one-shot command を実行するため、同じ user が WLMCP／Python runtime を永続改変できる配置では利用しません。

開発用の repository checkout と `.venv` は user-writable であることを前提とします。この開発 runtime は Broker／Codex Sandbox の開発・テストには使用できますが、Approved Host の production trust anchor にはしません。

## Production 配置

production Approved Host runtime は、通常 user が read/execute のみ可能な非 editable install として配置します。既定の installer は次を使用します。

```text
C:\Program Files\WindowsLocalMCP\
  runtime\
  run-server.ps1
  run-approvals.ps1
  verify-approved-host-runtime.ps1
  config.example.toml
```

`runtime` の venv だけでなく、その venv が参照する base Python も non-elevated WLMCP user から immutable である必要があります。配置場所の名前だけを trust anchor にはせず、実行前の Windows effective-access check が最終判定します。

## Install

1. machine-wide Python 等、通常 WLMCP user から書換え不能にできる base Python の `python.exe` を用意します。
2. repository root で elevated PowerShell を開きます。
3. Approved Host を実際に使う Windows account を `RuntimeUser` に指定して install します。

```powershell
.\install-approved-host-runtime.ps1 `
  -BasePython "C:\Program Files\Python312\python.exe" `
  -RuntimeUser "$env:USERDOMAIN\$env:USERNAME"
```

既存 install を置換する場合だけ `-Replace` を付けます。

installer は `InstallRoot`、`BasePython`、`sys.base_prefix` が Windows の Program Files 配下であることを admission 時に要求します。そのうえで wheel を `.dev-tmp\approved-host-runtime` に build し、staging directory へ非 editable install した後、staging 全体の owner／ACL を固定してから active `InstallRoot` へ移します。通常 runtime user には RX、SYSTEM と Administrators には Full Control を与えます。Program Files 配下という名前だけを immutability の証拠にはせず、base Python を含む実効 access は後段の non-elevated verification で再検証します。

## Non-elevated verification

install 後は elevated shell を閉じ、Approved Host を使う通常 user の非昇格 PowerShell で次を実行します。

```powershell
& "C:\Program Files\WindowsLocalMCP\verify-approved-host-runtime.ps1"
```

verification は installed Python を `-I -B` で起動し、`assert_approved_host_runtime_immutable()` を実行します。次のいずれかを検出した場合は fail closed します。

- Python が isolated mode ではない
- WLMCP package、startup-active dependency、import namespace、launcher が user-writable
- runtime path／TCB path に危険な reparse point がある
- runtime directory／ancestor に置換可能な effective access がある
- base Python／stdlib／DLL 等が current user から永続改変可能

`python3.exe` のように import/startup に参加しない namespace sibling が reparse point であることだけでは runtime 全体を unavailable にしません。一方、`.pth`、Python source／bytecode、native extension、package directory、declared dependency tree の reparse／mutation は引き続き拒否します。

## Start

verification 成功後、production launcher から server／approval UI を起動します。

```powershell
& "C:\Program Files\WindowsLocalMCP\run-server.ps1" -Config "C:\path\to\config.local.toml"
& "C:\Program Files\WindowsLocalMCP\run-approvals.ps1" -Config "C:\path\to\config.local.toml"
```

production launcher は `runtime\Scripts\python.exe` を優先し、source repository の launcher は production runtime が存在しない場合だけ `.venv` を開発用 fallback として使います。どちらも Python を `-I -B` で起動します。

## Update

runtime 更新は trusted operator が elevated installer を `-Replace` 付きで再実行し、その後に必ず non-elevated verification を再実行します。Approved Host 実行直前の runtime immutability gate は verification 済みであっても省略しません。

## CI と Windows live verification

GitHub hosted runner の editable checkout は production immutable runtime ではありません。CI では runtime gate の semantics と、gate 通過後の approval／audit／descendant／tamper controls を分離して検証します。

release 判定では、CI の synthetic／integration test を production Windows live verification の代替にはしません。実際に使用する PC／account／base Python／installed runtime で `verify-approved-host-runtime.ps1` を成功させてください。

`session_info()` の `runtime_preflight=passed` は、この runtime immutability scope に対する current-machine evidence だけを表します。Approved Host 全体の `live_verified`／`windows_live_verified` へ昇格させず、control-plane tamper detection、approval integrity、Job descendant handling、Job 外 same-user process detection、timeout termination は個別 property として unit／integration evidence と Windows live evidence を分離して表示します。
