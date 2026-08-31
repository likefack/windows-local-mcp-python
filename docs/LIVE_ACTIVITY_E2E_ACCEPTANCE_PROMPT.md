# Live Activity 実機 E2E 受入試験プロンプト

この文書のコードブロック内を、そのまま ChatGPT の新しい会話へ貼り付けて使用します。これは単体テストやモック用ではなく、次の実経路を確認する受入試験です。

```text
ChatGPT chat
  -> Secure MCP Tunnel
  -> 起動中の Windows Local MCP
  -> 実 workspace / audit.db / Windows Approval UI
```

Codex Desktop 内の入れ子 Sandbox、コードリーディング、モック、単体テスト、CI の結果を、この試験の PASS に読み替えてはいけません。

## ChatGPT へ貼り付けるプロンプト

```text
Windows Local MCP の Live Activity 実機 E2E 受入試験を実施してください。

目的は、ChatGPT -> Secure MCP Tunnel -> 実際に起動している Windows Local MCP の経路で、Windows Approval UI の Live Activity、実ファイル、Audit、Activity Timeline、Selective Undo、point-in-time rollback が互いに整合することを確認することです。

重要な制約:

- 最初に session_info で現在の接続、capability、workspace を確認してください。Secure MCP Tunnel または Local MCP の実経路を確認できない場合は BLOCKED です。direct 接続、モック、推測で代替しないでください。
- workspace 内に、この試験専用の新しい一時ディレクトリを1つ作り、その配下だけを変更してください。名称には衝突しにくい日時またはランダム値を含めてください。
- 既存ファイル、.git、設定、data_dir、Audit DB、credential、Approved Host state、Sandbox marker、Automatic Git stateを変更しないでください。
- 各操作前後に専用ディレクトリのファイル名、byte数、SHA-256、必要なテキスト内容を記録し、期待外のファイル変更がないことを確認してください。ファイル本文は必要最小限の専用fixtureだけを扱い、Live Activityや報告へ秘密情報を出さないでください。
- Live Activity の確認は、実際の Windows Approval UI に表示された行を利用者が目視した結果に基づきます。あなたがUIを直接読めない場合は、期待する表示と確認時刻を示して利用者へ確認を依頼し、その返答があるまで該当項目を PASS にしないでください。
- audit_list / audit_get / activity_timeline / activity_get は対応 operation の確認に使います。Live Activity の表示文字列を承認、policy、rollback、security decision の根拠にしないでください。
- operation ID、request hash、credential、token、秘密値、ファイル本文、diff本文、stdout/stderr本文を Live Activity に表示させたり、最終報告へ不用意に複製したりしないでください。必要な operation ID は試験証跡の表だけに記録してください。
- ある独立ケースが FAIL / BLOCKED / TIMEOUT になっても、安全に続行できる別ケースは続けてください。ただし workspace の期待状態が不明、復旧が必要、または cleanup の安全性を証明できない場合は mutation を停止してください。
- policy、承認、checkpoint、transaction、rollback、Undo、Approved Host、Codex Sandbox、Automatic Git、structured processing、artifact transfer の保証を無効化、迂回、弱体化しないでください。

承認時の絶対停止ルール:

request_selective_undo、request_workspace_rollback、request_sandbox_command、request_host_command、またはその他のローカル承認が生成されたら、承認済みと仮定して先へ進んではいけません。次を報告して、その応答を終了してください。

- approval ID
- tool / operation
- target
- preview（changed file count、create / restore / delete、競合の有無など、安全な要約だけ）
- expected effect
- Windows Approval UI で確認すべき Live Activity の Approval 表示

利用者が「承認した」と明示した次のメッセージで、同じ試験状態から再開してください。拒否試験では利用者が実際に拒否した後に再開してください。承認待ちの間は BLOCKED（local approval pending）であり、PASSではありません。

判定:

PASS は、実経路でoperationを実行し、Windows上の実ファイル状態、実Live Activity表示、Audit / Activityの対応operation、期待外変更なし、正常な終端状態を確認できた場合だけです。Undo / rollback はローカル承認を実際に通し、承認後の実ファイルが期待状態になった場合だけPASSです。

FAIL は、operationは実行されたが期待状態と異なる、Live Activityが期待した意味を示さない、Auditと表示が矛盾する、対象外変更を消す、指定時点へ戻らない、競合を推測上書きする、sanitization / redactionを破る、または安全にcleanupできない予期しない変更が生じた場合です。

BLOCKED は、Tunnel接続不能、Local MCP未起動、必要capability unavailable、ローカル承認待ち、安全なfixture作成不能、またはsecurity policyが試験操作を正しく拒否したため先へ進めない場合です。BLOCKEDをPASSにしないでください。

TIMEOUT は実operationまたは利用者確認が定めた待ち時間内に終わらない場合、UNVERIFIED は実表示など必要証拠を確認できない場合の補助状態です。最終判定ではPASSへ繰り上げないでください。

最初に、次の結果表を作成し、各ケースを順次更新してください。

| Case | 判定 | operation ID / approval ID | 実ファイル証拠 | Live Activity証拠 | Audit / Activity証拠 | 備考 |
| --- | --- | --- | --- | --- | --- | --- |

A. Baseline

1. session_info、activity_timeline、audit_listを取得し、実経路、workspace、利用可能なstructured / artifact / Undo / rollback capabilityを記録してください。
2. 試験開始時の専用ディレクトリ外の状態を、変更を伴わない方法で記録してください。
3. Windows Approval UIを起動または既存画面で確認し、過去の完了済みoperationが大量再生されないことを利用者に確認させてください。
4. 既にpending approval、queued、running、committing等の重要operationがある場合は見落とされず表示されることを確認してください。既存operationを承認・拒否・停止してはいけません。
5. audit_list等を呼んだだけでLive Activityが監査操作の行で埋まらないことを確認してください。

B. Read

1. 専用の read-fixture.txt を UTF-8 の短い固定内容で作成し、その作成operationをCで使用できるよう記録してください。
2. read_fileで読み、Live Activityに Read と安全な対象名が表示されることを確認してください。
3. list_directoryも実行し、Readとして表示されることを確認してください。
4. Audit / activity_getでtool、status、targetが一致することを確認してください。本文がLive Activityへ出ていないことも確認してください。

C. Edited

1. 専用の edit-fixture.txt を新規作成し、E0からE1へ編集してください。
2. Live Activityに Edited と対象名が表示されること、Auditにwrite_fileの成功operationとcheckpointがあること、実内容がE1であることを確認してください。

D. Structured processing

1. 専用の小さなXLSX fixtureだけを使用してください。安全に作成できない場合はBLOCKEDです。既存XLSXをコピーして使わないでください。
2. structured_file_inspectで形式と対象を確認し、structured_file_applyで1セルだけを既知の値へ変更してください。必要なexpected SHA-256を使ってください。
3. Live Activityで「Excelを編集」等の人間向けRunningと、完了時のEdited相当が確認できること、tool名だけの低レベル行にならないことを確認してください。
4. 実XLSXを再inspectして期待セルを確認し、Audit / activity_getのstatus、format、target、checkpointと一致させてください。

E. Artifact transfer

1. ChatGPT側で生成した専用の小さなバイナリfixtureを、artifact uploadのbegin / chunk / commitでWindowsの専用ディレクトリへ転送してください。元bytesのSHA-256とWindows側のSHA-256が一致することを確認してください。
2. Live Activityに「PCへ転送」のRunningとUploaded相当が対象名付きで表示され、begin / chunk / commitの内部行だけが大量表示されないことを確認してください。
3. そのWindowsファイルをartifact downloadでChatGPT側へ取得し、全chunkを結合したbytesとSHA-256がWindows側と一致することを確認してください。
4. Live Activityに「ChatGPTへ取得」のRunningとDownloaded相当が表示され、chunkごとの大量ノイズがないことを確認してください。
5. Auditでは親operationとchunk event、upload commitを必要な技術証跡として確認してください。

F. Safe failure

専用fixtureだけを対象に、既存データを変更せず安全に失敗する重要operationを1件発生させてください。例えば、専用structured fixtureに対する意図的に不一致なexpected SHA-256など、失敗前に停止する方法を優先してください。Live ActivityにFailed相当と人間向けの操作・対象が表示され、Audit statusと一致することを確認してください。成功へfallbackしてはいけません。

G. Rejection

専用ディレクトリを対象に、policyまたは入力検証が安全に拒否するoperationを1件発生させてください。workspace外や保護情報を実際に読もうとせず、明らかに無効な専用path / bound / stale identity等、外部作用前に拒否されるケースを選んでください。Live ActivityにRejected相当が表示され、Audit statusと一致することを確認してください。security policyによる正しい拒否で試験の後続操作ができない場合、そのケースはBLOCKEDとして理由を残してください。

H. Selective Undo

1. 専用fixtureを次で初期化し、各write operation IDを記録してください。
   - undo-a.txt = A0
   - undo-b.txt = B0
2. 操作Aでundo-a.txtをA1へ、操作Bでundo-b.txtをB1へ変更してください。
3. 操作Aだけをrequest_selective_undoのtargetにしてください。承認が生成されたら絶対停止ルールに従ってください。
4. 承認後、Live ActivityのApproval / Running / Undone相当を確認してください。
5. 実ファイルが undo-a.txt=A0、undo-b.txt=B1 であることをbyte / text比較してください。
6. audit_get / activity_getで操作AとUndo operationのtarget関係、before / after checkpoint、正常終端、undo_can_be_undoneを確認してください。

I. Point-in-time rollback

1. Selective Undoとは別の専用ファイルを複数使い、状態0、操作A、操作B、操作Cを作って各時点の期待ファイル一覧・内容・SHA-256を操作前に表へ書いてください。
2. request_workspace_rollbackで明示したoperation完了時点をtargetにしてください。承認が生成されたら絶対停止ルールに従ってください。
3. 承認後、Live ActivityのApproval / Running / Rolled back相当を確認し、Selective UndoのUndone表示と区別できることを確認してください。
4. target時点の期待状態と、実際の全専用ファイルの存在、bytes、SHA-256を比較してください。対象外ファイルが変わっていないことも確認してください。
5. Audit / activity_getでpoint_in_time_rollback、preview、checkpoint、transactionの正常終端を確認してください。

J. Undo の Undo

1. 専用のundo-of-undo.txtをU0からU1へ変更する操作Aを作ります。
2. 操作AをSelective Undoし、承認後にU0へ戻ったことを確認します。
3. そのSelective Undo operation自体をtargetに、もう一度request_selective_undoを行います。各承認で絶対停止ルールに従ってください。
4. 最終状態がU1であること、Live Activityが内部tool名とUUIDだけでなく「Undoを取り消す」意味を可能な範囲で示すこと、Auditのtarget関係が正しいことを確認してください。
5. current仕様や安全なmetadataでは実施・判定できない場合、推測せずBLOCKEDとし、具体的理由を記録してください。

K. Text conflict and independent edit preservation

1. 専用テキストでoperation Aを行い、その後、Aと重ならない別箇所をoperation Bで編集してください。
2. AだけをSelective Undoし、承認後にBの独立変更が保持され、Aだけが戻ることを確認してください。
3. 別の専用テキストでは、Aの後にAと曖昧または重複する変更を作り、Selective Undo previewがconflictとして停止し、推測上書きしないことを確認してください。承認要求が生成されないconflictも正常な安全動作としてAuditとLive Activityを確認してください。

L. Binary conflict

専用バイナリだけを使い、Undo対象operationの後に別の内容へ変更した状態でSelective Undoを要求してください。既存仕様で安全に作れる場合のみ実施し、変更済みbinaryを推測上書きせずconflict / rejectionになることを確認してください。安全なfixtureまたは必要toolがない場合はBLOCKEDです。

M. Audit と Live Activity の役割分担、安全表示

1. audit_list、audit_get、activity_timeline、activity_get、session_infoを複数回実行し、Auditにはaccess記録が残る一方、通常のLive Activityがこれらで埋まらないことを確認してください。
2. 専用fixtureのpathまたは安全な表示metadataへ、改行、ANSI ESC、C0 / C1、双方向制御文字を含む入力を安全に渡せる場合だけ試験してください。Windows path規則やtool validationで拒否された場合は、その層の結果を記録し、無理に迂回しないでください。
3. secret風の文字列は実credentialを使わず、明確な偽fixture値だけを使用してください。Live Activityに偽secret全文、stdout / stderr本文、ファイル本文、diff本文が漏れず、端末行の改行・色・表示方向を注入できないことを利用者に確認させてください。
4. 同じoperationのstatus更新で同じ意味の行が不自然に重複しないこと、異常終端は消えないことを確認してください。

N. Cleanup

1. 結果表と必要なoperation ID / hash証跡を確定してから、今回作成した専用ディレクトリ内だけを通常の削除、または検証済みUndo / rollbackで片付けてください。
2. cleanupで承認が必要になった場合も絶対停止ルールに従ってください。
3. 専用fixtureがなくなったこと、専用ディレクトリ外の開始時状態に期待外変更がないこと、未解決のpending / running / recovery_requiredが試験によって残っていないことを確認してください。
4. cleanup不能または状態不明ならFAILとして停止し、追加の推測上書きや権限変更をしないでください。

最終報告:

- A〜Nを1行ずつPASS / FAIL / BLOCKED / TIMEOUT / UNVERIFIEDで示してください。
- 各行に実経路、実ファイル、Live Activity、Audit / Activityの証拠がそろっているかを示してください。
- Live Activityの表示例は秘密や本文を含まない短い行だけにしてください。
- 自動テスト結果と実機E2E結果を混同しないでください。
- 未実施、利用者の目視待ち、承認待ち、capability unavailableは明記し、PASSにしないでください。
- cleanup結果、期待外変更の有無、残ったpending / recovery state、既知の制約を最後に報告してください。
```

