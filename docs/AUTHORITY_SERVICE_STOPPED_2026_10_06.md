# 権限サービス停止による通常ファイル操作の障害（2026-10-06）

## 現在の結論

18:21 JSTに利用者が管理者PowerShellで復旧スクリプトを実行し、既存サービスは
`Stopped` から `Running` へ移行した。18:26までの実接続検証で、権限サービスの健全性、
通常のファイル操作、fileParamsを使った試験PNGの直接保存とハッシュ一致を確認した。
今回の通常ファイル操作の障害は復旧済みである。午前の調査記録は以下に履歴として保持する。

## 午前の調査と復旧待ち状態

09:36〜09:46 JSTの実機調査では、接続用TunnelとMCP serverは応答している一方、
Windowsサービス `WindowsLocalMCPApprovedHost` が `Stopped` だった。
名前付きパイプ `\\.\pipe\WindowsLocalMCPApprovedHost-v1` への接続が `WinError 2` で失敗し、
通常のBrokerファイル操作も拒否される。

サービスは登録済みで、レジストリの `ObjectName=LocalSystem`、`Start=2`（自動起動）、
実行パス・対象ユーザーSID・状態保存先は既存の運用構成と一致した。
`sc.exe queryex` は `STOPPED`、PID 0、終了コード0を返した。
通常ユーザーからの `sc.exe qc` と `sc.exe start` はともにアクセス拒否（終了コード5）。
開始の拒否は実際に確認した。管理者確認を承認できない状況のため、復旧は未完了である。

## 障害の切り分け

- `C:\Program Files\WindowsLocalMCP\runtime\Scripts\python.exe` とサービス用モジュールは存在する。
- 運用Pythonによる `import windows_local_mcp.approved_host_service_entry` は成功。
- 運用Pythonの `pip check` は `No broken requirements found.`。
- `session_info` の運用版変更不能性検査は成功、authority事前検査だけが失敗。
- サービス管理イベントには、04:40の起動タイムアウト（7000/7009）と、08:30を含む
  Python起動用プロセスと実プロセスのPID差異（7039）がある。
  これだけでは現在の停止を起こした原因を特定できない。
- 08:31の運用版更新は `installed`、08:33の接続検査は成功と記録されている。
  過去の成功記録を現在の稼働証明には使わず、今回の実測で停止を確認した。
- 保護されたProgramDataの状態・ACLは現在の通常権限では詳細確認できない。
  起動後に回復待ち状態が判明した場合は、別途証拠確認を要する。状態ファイルは削除していない。

今回の直接原因は権限サービス停止とパイプ不在である。停止に至った契機は未特定。
Codex Sandboxの ``elevated Windows sandbox requires effective `:root` read access`` は別件であり、
今回の通常ファイル操作を実行するためのSandbox経路へ切り替える必要はない。

## Brokerが権限サービスを確認する理由

`src/windows_local_mcp/server.py::_require_filesystem()` は
`assert_control_plane_healthy()` を呼ぶ。
`src/windows_local_mcp/approved_host_policy.py::install_approved_host_authority_health_gate()` は、
権限サービスが登録されている環境では、その確認に認証付きauthority接続を追加する。
稼働版の同関数にも同じ処理が存在することを読み取りで確認した。

これは通常ファイル操作をApproved Hostコマンドとして実行するための依存ではなく、
SYSTEMが保持する実行中・回復待ち状態を確認する共通の保護条件である。
`SECURITY_CONTRACT.md` のSection Eと `docs/APPROVED_HOST_RUNTIME.md` の永続状態の契約に
対応するため、サービス停止時にこの確認を省略したり、設定を無効化して復旧扱いにしたりしない。

## 実操作の検証

| 項目 | 調査前・再確認の結果 |
|---|---|
| `session_info` | 成功。対象は既存の `Personal_knowledge` |
| `list_directory(".")` | 拒否。監査記録でもauthority pipeの `WinError 2` |
| `workspace_tree` | 拒否。同じエラー |
| `make_directory` | 拒否。同じエラー |
| `workspace_batch` のpreview | 失敗。同じエラー。適用操作は行っていない |
| `artifact_import_file` | 実在する161バイトのPNGを端末パスで指定した呼び出しは `INVALID_ARGUMENT`。保存成功は未確認 |
| テスト項目の残存 | 対象テストディレクトリ2件の不存在をホストから確認。削除対象なし |

作成確認の対象は `00_受け取り/LocalMCP_復旧確認_20261006_b4d50ef8`。
一括操作previewの対象は `00_受け取り/LocalMCP_復旧確認_一括_20261006_b4d50ef8`。
失敗した取り込み呼び出しの監査記録は確認できていない。
運用版関数は参照形式の検査・HTTPS取得より先に共通のファイル操作保護条件を確認するため、
サービス復旧後にfileParams変換と保存を改めて検証する必要がある。

取り込みの運用モジュール、`fileParams` のobject schema、必要項目 `download_url` / `file_id`、
完全一致の許可ホスト `sdmntprkoreacentral.oaiusercontent.com` は確認済み。
今回、許可ホストを追加・拡大していない。名刺画像の実データはこの作業に添付されていない。
Base64転記・分割転送を代用にした成功報告は行わない。

## 実施した変更と次の復旧操作

製品コード、運用設定、サービス登録・起動方式、ACL、資格情報、個人ナレッジは変更していない。
configのSHA-256は調査前後とも
`b762409f1663e8a9395d2d45c1777b7a4c51e58dc9cb0f1c2f9c1b35a1d4fa36`。
サービス状態も調査前後とも `Stopped`。

`.dev-tmp/authority-recovery-20261006/Start-ExistingAuthority.ps1` に、このPC用の復旧処理を用意した。
Windows PowerShell 5.1の構文検査は成功し、非昇格での実行は変更前に拒否された。
登録済みのアカウント・実行パスが今回確認した構成と一致する場合だけ既存サービスを開始し、
開始前後の状態をJSONへ保存する。再インストール、ACL変更、設定初期化、回復状態の削除は行わない。

管理者として開いたPowerShellで実行する:

```powershell
& 'C:\dev\windows-local-mcp-python\.dev-tmp\authority-recovery-20261006\Start-ExistingAuthority.ps1'
```

開始後に、通常ユーザーの接続からauthority事前検査、閲覧、フォルダー作成・安全な削除、
`artifact_import_file` の保存とSHA-256一致を確認する。
サービスを開始しただけでApproved Hostの承認後実行・異常終了回復まで検証済みとは扱わない。

証拠は同フォルダーの `before-host.json`、`after-host.json`、`direct-start-result.json`、
`service-start-result.json`、`remote-verification.json`。

記録用コミットメッセージ案: `docs: 権限サービス停止によるファイル操作障害と復旧条件を記録`

## 18:21のサービス開始後の実検証

`service-start-result.json` は `status=running`、サービスPID 26156、LocalSystem、
開始前後ともactive／recovery状態なしを記録した。独立した `sc.exe queryex` でも
`RUNNING` を確認した。configのSHA-256は午前の記録と一致し、設定・サービス登録・ACLの変更はない。

| 項目 | 復旧前 | サービス開始後 |
|---|---|---|
| 権限サービス | Stopped、パイプ不在 | Running、認証付き事前検査passed／healthy=true |
| Approved Hostの事前確認上の利用可否 | available=false | available=true |
| `session_info` | 成功、authorityだけ失敗 | 成功、authorityも正常 |
| `list_directory(".")` | authorityエラーで拒否 | 成功、15項目 |
| `workspace_tree` | authorityエラーで拒否 | 成功、深さ2で153項目 |
| `make_directory` | authorityエラーで拒否 | Broker経路・Windows TxFで成功 |
| `workspace_batch` | 事前確認がauthorityエラーで失敗 | 作成と置換の2操作が成功、内容を読み戻して一致 |
| `artifact_import_file` | 保存成功未確認 | fileParamsで試験PNGを直接保存、161バイト、SHA-256一致 |
| テスト項目の削除 | 未作成 | ファイル2件と空ディレクトリ1件を削除し、不存在を確認 |

復旧直後のtree試験では取得上限を70件に指定したため `WorkspaceEntryLimitExceededError` になった。
上限を1000件として再実行すると153件を取得できた。製品コード・設定を変更して回避したものではなく、
authorityエラーとも異なる、正常な取得件数制限である。

試験画像には既存の `client-probe.png` を使った。モデルがBase64を生成・転記・分割する経路は使用せず、
このCodex接続の端末パス指定をクライアントがfileParamsへ実体化する経路を検証した。
保存後のファイルをホストから別に読み取り、元ファイルと同じ
`be883ccd8d000bf0edabfcab8f85c9d6c71175547a7a7a3f056066759cf97c89` を確認した。
利用者の名刺画像自体はこの検証で保存していない。

作成先は `00_受け取り/LocalMCP_復旧確認_20261006_1825_72c41ee2`。
PNGとテキストは、確認済みのSHA-256を指定して `delete_file` で削除した。
空ディレクトリはワークスペース内の正確なパス、通常のディレクトリ、空であることを確認し、
ホストから非再帰で削除した。個人ナレッジの既存項目を削除していない。

主要operation ID:

- session_info: `a78392d2-c392-439c-ac16-21b77cf813ba`
- list_directory: `7c99f63f-b16d-4fc3-9f62-f6c14a5658cf`
- workspace_tree: `d9d19a87-5dbe-4976-99a5-19a4f6727f51`
- make_directory: `0461cb1c-d698-4ea7-92b3-ed1d86923663`
- artifact_import_file: `ca57e857-6be2-4081-b204-46400399f73f`
- workspace_batch: `531ac6a9-cc6f-4e91-ad72-7446cc8326ce`

証拠は `restored-file-readback.json`、`restored-cleanup.json`、`restored-verification.json`。
成功した操作の監査記録に `ApprovedHostAuthorityUnavailable` はない。
Codex Sandboxの `:root` 読み取り権限に関する別件は未解決のままであり、今回の修正対象には含めていない。
Approved Hostの実際の承認後コマンド実行・異常終了回復試験を完了したという意味でもない。

更新後の記録用コミットメッセージ案: `docs: 権限サービス復旧後のファイル操作と添付直接保存を検証`
