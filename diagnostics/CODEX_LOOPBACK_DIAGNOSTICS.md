# Codex Windows Sandbox loopback診断

このdirectoryのscriptは、Codex Windows Sandboxのloopback遮断不全を、設定変更と
診断を分離して調べるためのものです。Firewall規則、WFP filter、ACL、Sandbox userを
修復、削除、再生成しません。

## 1. 通常Windows userでの状態収集

通常のPowerShellで実行します。`-RunSandboxProbe`を付けない場合は、installed binary、
setup marker、Sandbox user、Firewall ActiveStoreを読み取るだけです。

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
  C:\dev\windows-local-mcp-python\diagnostics\Invoke-CodexLoopbackProbe.ps1
```

IPv4／IPv6、TCP／UDP、parent／child／grandchildの実通信を確認する場合だけ、
`-RunSandboxProbe`を明示します。

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
  C:\dev\windows-local-mcp-python\diagnostics\Invoke-CodexLoopbackProbe.ps1 `
  -RunSandboxProbe
```

このmodeは通常Windows user文脈からinstalled `codex sandbox`を起動します。scriptは
setup markerがversion 5、`proxy_ports=[]`、`allow_local_binding=false`でない場合、
setup refreshを避けるため起動前に中止します。ただし、最終的なsetup refresh判断は
installed Codex backendが行うため、完全に変更不可能な読取専用操作とは扱いません。
実行前後のmarker hashを結果へ記録します。

結果は既定で`%TEMP%\codex-loopback-probe-<timestamp>.json`へ保存されます。

## 2. 管理者権限でのWFP読取

WFP filterの列挙は通常userでは`ERROR_ACCESS_DENIED`になります。管理者として開いた
PowerShellで次を実行します。このscriptが行うのは`netsh wfp show filters`、
`netsh wfp show netevents`、Firewall ActiveStoreの読取だけです。

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
  C:\dev\windows-local-mcp-python\diagnostics\Collect-CodexWfpState.Admin.ps1
```

結果は既定で`%TEMP%\codex-wfp-state-<timestamp>\summary.json`と、IPv4／IPv6・
TCP／UDPごとのWFP XMLへ保存されます。

判定上の中心は次の3点です。

- Sandbox SID、宛先、protocolに一致するblock filterがALE AUTH CONNECT v4/v6に存在するか
- 存在する場合、loopbackを許可する別filterのsublayer／weightがblockより優先していないか
- 実通信時のneteventがblock、allow、または記録なしのどれか

block filterが生成されていなければ、Firewall ruleからWFPへの変換・適用区間が直接原因です。
block filterが存在しても上位のloopback allowが勝つ場合は、CodexのFirewall rule設計が
Windowsのloopback分類・優先順位を拘束できていないことが直接原因です。
