# Verification

## 2026-08-13 バイナリ転送の性能・安全性確認

- 全回帰: `python -m pytest -q` は 194 passed、2 skipped。
- 静的検査: `ruff check .`、`python -m compileall -q src tests`、`git diff --check` は成功。
- 16 MiB、512 KiB × 32 チャンクのローカル比較では、チャンク処理は約 1.93 秒から約 0.62 秒、開始処理を含む全体は約 2.01 秒から約 0.87 秒へ短縮した。単発測定であり、実環境の保証値ではない。
- ダウンロード開始時に元ファイルを前後で識別・全体 SHA-256 検証し、制御領域の固定スナップショットも再ハッシュした。チャンクは固定スナップショットの必要範囲だけを読む。
- アップロードは開始時に申告全容量を予約し、チャンクごとの `data_dir` 全走査を除去した。チャンクの順序、fsync、完了時の全体 SHA-256、commit 時の元ファイル・出力先再検証は維持した。
- 32 チャンクすべてが親転送操作の SHA-256 付き監査イベントとして永続化されることを確認した。スナップショット改変、容量超過、不完全アップロード、元ファイル変更後の結果 commit は拒否される。
- これはローカル Python 回帰とローカル性能測定であり、Secure MCP Tunnel／ChatGPT E2E、実運用負荷、停電相当の永続性試験を確認したものではない。

最終確認日: 2026-08-09

## Automated regression

- `python -m pytest -q`: 161 passed, 2 skipped
- `python -m ruff check .`: pass
- `python -m compileall -q src tests`: pass
- `git diff --check`: pass（Gitの将来のLF/CRLF変換warningのみ）

追加した主な回帰は、Approved Sandbox request全体のhash binding、Codex signer/helper closure、不完全checkpoint拒否、journalのlegacy `complete` recovery、operation-owned rollback checkpoint、Timeline artifact integrity、外部Dart dependency境界、AppContainer HANDLE signature/profile identity/ACL write-aheadです。

## Windows environment

- Windows kernel build: `10.0.26200.0`、DisplayVersion `25H2`
- Python: 3.14
- Git: `C:\Program Files\Git\cmd\git.exe`
- Dart/Flutter: `C:\flutter\bin`
- Codex CLI: `0.147.0-alpha.6.5`
- Node/npm/npx、Windows PowerShell: installed
- ADB、`pwsh`: not installed

## Safe Sandbox / AppContainer live results

確認済み:

- profile作成、ACL付与、AppContainer process launch
- stdout/stderr pipe、exit code
- timeout/explicit terminationとJob Objectによるdescendant終了
- data_dir read denial
- offline profileでInternet (`1.1.1.1:443`)、LAN (`192.168.1.1:80`)、loopback denial
- `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`によるstdin/stdout/stderr allowlistとpointer-sized HANDLE contract（static/regression）
- Git/AppContainer互換性failureが`SafeSandboxCompatibilityError`となり、host fallbackせずApproved Sandbox再試行案内になること

実機結果ではGit for Windowsが狭いancestor traverse/read-attributes権限でcwdを利用できず、`git status/diff/log/show`はいずれもSafe成功には至りませんでした。workspace ancestorへ広いRXを与える変更はsecurity boundaryを広げるため採用していません。Dart analyze/formatとFlutter analyzeもtoolchain/runtime ACL setup時間・互換性のため成功確認に至っていません。

ADB profileの通常設定は`127.0.0.1:5037`ですが、設計上のOS capabilityはport限定ではなく一般loopback exemptionです。この端末では最新setup時の`CheckNetIsolation LoopbackExempt`追加が失敗し、一覧にもexemptionが残らなかったため、ADB loopbackは利用可能・検証済みとは扱いません。Internet/LAN denyはoffline profileで確認済みですが、ADB profileとしてのdenyは未検証です。

不要なinheritable handleが実childへ存在しないことは、allowlist実装とWin32 signature testまでです。child側のhandle tableを列挙する独立実機probeは未実施です。

## Approved Sandbox live results

確認済み:

- installed Codex discovery
- `codex.exe`、`codex-command-runner.exe`、`codex-windows-sandbox-setup.exe`のOpenAI Authenticode identity、hash/stat/path binding
- 3 binaryをwrite/delete replacementからlockした状態で`codex --version`
- backend missing/changed/unsigned requestのfail-closed unit path
- Approved SandboxからApproved Hostへfallbackしないcontrol flow

この端末では`codex sandbox`のsimple commandが`CreateRestrictedToken failed: 87`または長時間停止となり、停止したprocessはPID identity確認後に終了しました。したがってApproved Sandbox内のsimple command、Python、pytest、PowerShell、Node/npm、child process、workspace write、network/filesystem boundaryは実行成功未検証です。Codex helper discoveryだけでOpenAI authentication、prompt、model inference、API通信は発生しません。

## Checkpoint performance

100 files・約102 KBの一時workspaceで、初回full checkpointは0.946秒、1 fileだけ変更した2回目も0.186秒でした。CASはblob storageをdeduplicateしますが、manifest完全性と外部/manual変更検出を維持するため現在もO(files + bytes)のfull scanです。信頼できる変更journalなしに既知pathだけへ縮小する最適化は採用していません。1000-file probeは30秒以内に完了しなかったため、大規模workspaceではI/O costが重要な残存制約です。

## Not verified

- real ADB server/emulator/device identity、screenshot、5037接続
- Safe Dart/Flutterの成功経路
- Approved Sandbox内のdeveloper command成功経路と実効filesystem/network/child境界
- AppContainer child側からのhandle table enumeration
- power-lossを各fsync/SQLite境界で強制するhardware-level test
- Secure MCP Tunnel / ChatGPT接続

mock/unit/static evidenceを、上記のWindows実機未検証項目の代替とは扱いません。
