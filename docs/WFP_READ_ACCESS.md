# WFP 読み取り権限の設定と復旧

## 原因

WFP は、通常ユーザーが BFE に接続できても、個別のサブレイヤーやフィルターを読み取れるとは限りません。`FwpmSubLayerGetByKey0 failed with WFP status 0x00000005` は読み取りのアクセス拒否です。独自 Guard より先に検証する Windows の App Isolation サブレイヤーでも発生します。

従来の Guard は通常ユーザーによる読み取りを前提にしていましたが、その権限を設定していませんでした。読み取り失敗を object の消失とみなして自動昇格することはできないため、明示的な管理者セットアップで解決します。

## 初回設定・アクセス拒否からの復旧

LocalMCP を利用する本人のアカウントで、管理者 PowerShell を開き、リポジトリのディレクトリで実行します。別の管理者アカウントの資格情報を使用すると、その別アカウントが設定対象になります。

```powershell
.\.venv\Scripts\python.exe -m windows_local_mcp.wfp_guard_runtime --maintenance-prepare-read-access
```

この操作は完全な Guard policy 検証を先に行い、正確に欠けている Guard object だけを作成します。不一致は修復しません。その後、App Isolation サブレイヤー、Guard サブレイヤー、IPv4 と IPv6 の Guard フィルターの固定4個に限り、実行者本人の SID に `FWPM_ACTRL_READ` を追加します。既存 DACL と拒否 ACE、所有者を維持し、engine や container 全体には権限を追加しません。フィルターの変更・削除権限は追加しません。

途中で失敗した場合は成功扱いにしません。既に追加された読み取り権限が残る場合がありますが、再実行できます。通信制限や検証条件は解除しません。

## 通常利用の前の確認

管理者 PowerShell を閉じ、通常の PowerShell から次を実行します。

```powershell
.\.venv\Scripts\python.exe -m windows_local_mcp.wfp_guard_runtime --maintenance-verify
$env:LOCAL_MCP_CONFIG = Join-Path $env:LOCALAPPDATA 'WindowsLocalMCP\config.toml'
.\.venv\Scripts\python.exe -m windows_local_mcp.cli verify-codex-sandbox
```

別の設定ファイルを利用している場合は、その設定ファイルを指定します。WFP 読み取り成功だけでは隔離の実測を証明できません。必須項目の実機検証が成功し、`route_eligible=true` になった後に利用します。設定済みでも、未検証・失敗・期限切れの間は実行を拒否します。

通常の Sandbox 起動では権限変更や UAC の再試行を行いません。検証開始時に正確な Guard 消失が確認された場合だけ、既存の管理者 Guard 経路で再構築し、後続の通常権限 probe に必要な読み取り権限も設定します。Windows 再起動、BFE 再起動、Windows の設定更新などで App Isolation の読み取り権限も失われた場合は、この明示的な設定からやり直します。

## 変更しない安全条件

- 不明な読み取りエラー、既存 object の不一致、検証失敗から自動昇格しません。
- Sandbox account の SID、全フィルター条件、weight、静的・非永続属性を引き続き照合します。
- 通常ユーザーの LocalMCP と Sandbox command を管理者として常用しません。
- live marker を手作業で成功に書き換えず、Approved Host へ自動移行しません。

WFP の既定権限と個別 object の読み取り権限は [Microsoft のアクセス制御仕様](https://learn.microsoft.com/en-us/windows/win32/fwp/access-control) に基づきます。
