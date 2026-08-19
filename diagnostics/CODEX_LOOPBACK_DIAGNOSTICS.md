# Codex Windows Sandbox loopback診断

このdirectoryのscriptは、Codex Windows Sandboxのloopback遮断不全を、設定変更と
診断を分離して調べるためのものです。既存のprobe／collectorはFirewall規則、WFP filter、
ACL、Sandbox userを修復、削除、再生成しません。後述の一気通貫Guard診断だけは、固定された
WFP Guardが欠けている場合に、UACで昇格したGuardからそのexact objectをensureします。

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

## 3. 通常権限WLMCPからのGuard一気通貫診断

この診断は、通常権限のPythonプロセスから本番の
`ensure_runtime_codex_loopback_guard` を強制的にUAC経路へ通し、
`ShellExecuteExW` の `runas`、昇格Guard、named pipeの接続元PID検証、
実WFPのensure/read-backを1回で記録します。固定Guardが既に存在する場合は削除せず再利用し、
存在しない場合だけ昇格Guardが固定のstatic／non-persistent objectを追加します。

Codex Desktopの入れ子Sandboxや管理者PowerShellではなく、通常のWindowsユーザーが開いた
PowerShellで実行してください。UACの承認または管理者資格情報の入力が必要です。

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
  C:\dev\windows-local-mcp-python\diagnostics\Invoke-WlmcpWfpGuardIntegration.ps1
```

成功の最低条件は、結果JSONの `success=true`、通常側の `is_administrator=false`、
`shell_execute.api=ShellExecuteExW` と `verb=runas`、
`pipe_peer_identity_verified=true`、昇格側の `is_administrator=true`、
`elevated_ensure_called=true`、`parent_readback_validation=true`、および
`wfp.verification` の固定v4／v6 filter・static／non-persistent証跡です。
この診断はWFP裁定が実通信をdropしたことや12経路のloopback遮断までは証明しないため、
それらは別の実通信診断として扱います。
