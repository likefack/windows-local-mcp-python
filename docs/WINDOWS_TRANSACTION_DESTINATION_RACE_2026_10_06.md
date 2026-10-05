# Windowsコピー・移動の保存先競合テストの修正

確認日: 2026-10-06。対象は `tests/test_windows_transaction.py` の
`test_transactional_copy_destination_creation_race_never_overwrites` と
`test_transactional_move_destination_creation_race_never_overwrites`。

## 結論

今回の2失敗はテストの前提と例外の捕捉範囲の誤りだった。保存先が既にTxF
（Transactional NTFS）のトランザクション内で予約された後に、競合側のファイル作成が
成功することを要求していた。競合側を拒否していた本体の実行処理は変更しない。
保存先を先に作られる場合も追加検証し、第三者ファイルの上書きや削除は再現しなかった。
この結論は対象の競合条件についてのものであり、全リポジトリの安全性を証明するものではない。

一般的な「古いテストだから無視する」という対応ではなく、失敗する操作と競合時点を
特定して、上書き防止の保証を検証する試験へ修正した。公開API・CAS・権限・復旧の仕様変更はない。

## 原因と根拠

コピーは `CreateFileTransactedW(..., CREATE_NEW, ...)` で保存先を作成し、移動は
上書きフラグを付けない `MoveFileTransactedW` で移動を準備する。その後でテスト用の
`_before_commit` が呼ばれるため、この時点では保存先の名前は予約済みである。

旧テストの処理は次の順序だった。

1. `_before_commit` 内で通常の `destination.write_bytes(b"intruder")` を呼ぶ。
2. 競合側の書き込みが例外となり、コールバックから本体へ伝播する。
3. 本体は例外を受けてトランザクションをロールバックする。
4. 本体全体を囲んだ `pytest.raises(OSError)` が、そのコールバック例外を捕捉する。
5. 実際には作成されなかった `destination` に `intruder` が残ることを要求して失敗する。

通常Windowsプロセスで同じ合成ファイルを使って切り分けた結果:

| 診断 | コピー | 移動 |
| --- | --- | --- |
| 旧テストの再現 | 保存先の読取が `FileNotFoundError` | 同左 |
| 競合側 `Path.write_bytes` | `OSError`, `errno=22`, `winerror=None` | 同左 |
| 通常の `CreateFileW` による競合側作成 | エラー6800、`ERROR_TRANSACTIONAL_CONFLICT` | 同左 |
| 競合側の例外をコールバック内で扱った場合 | 本体成功、元ファイル不変、保存先の内容一致 | 本体成功、元パス消滅、内容・ファイルID保持 |

PythonのCRT経由ではWindowsのエラー番号が変換されるため、修正後の試験は
`CreateFileW` のエラーを直接確認する。32（共有違反）または6800（トランザクション競合）だけを
受け入れ、単なるアクセス拒否や無関係な `OSError` を合格にしない。

Microsoftの仕様も、トランザクション内で作成した名前は終了まで予約され、外部からの同名作成を
拒否すると定めている。また、TxFの隔離と通常の共有モードのうち厳しい制約が適用される。
[TxFの作成・改名に関する仕様](https://learn.microsoft.com/en-us/windows/win32/fileio/programming-considerations-for-transacted-fileio-)
と[TxFのロックと共有モード](https://learn.microsoft.com/en-us/windows/win32/fileio/txf-basic-concepts)を参照。

## 修正した検証

対象2テストの名前を維持し、それぞれ次の2時点で競合側の拒否と本体の成功を確認する。

- 保存先の準備後、ファイルHANDLEを保持している時点。
- ファイルHANDLEを閉じた後、実際の `CommitTransaction` の直前。

さらにコピー・移動のそれぞれで次を追加した。

- 保存先の存在確認後、Win32で名前を確保する直前に競合ファイルを作成する。実際のWin32 APIで
  本体が拒否され、元ファイルと競合側ファイルの内容・WindowsファイルIDが維持されることを確認する。
- 名前を確保した後に、識別可能なコールバック例外を注入する。元ファイルが復元され、保存先が残らず、
  同じパスへの再実行が成功することを確認する。例外の発生源も明示的に検証する。

実際のWin32 APIを模擬した合格結果に置き換えてはいない。テスト用の呼出し位置で競合を起こし、
通常のファイル作成・実際のTxFによる拒否・確定・復元を使用する。待ち時間頼みの競合試験でもない。

## 実行結果

- 修正前の対象2件: **2 failed**。保存先の `FileNotFoundError` を再現。
- 修正後の `tests/test_windows_transaction.py` 全体: **15 passed**。
- ファイル操作、復元、一括操作、高水準操作、時間計測を含む関連回帰: **105 passed, 1 skipped**。
  対象2件を除外するフィルターは使用していない。15件はこの105件にも含まれる。
- 対象PythonファイルのRuff（キャッシュなし）と差分の空白検査: 成功。

```powershell
$env:PYTHONIOENCODING = 'utf-8'
.\.venv\Scripts\python.exe -m pytest tests/test_windows_transaction.py -q --tb=short --basetemp=.dev-tmp/pytest/destination-race-corrected-20261006
.\.venv\Scripts\python.exe -m pytest tests/test_windows_transaction.py tests/test_filesystem_primitives.py tests/test_deterministic_workspace_operations.py tests/test_timeline_and_rollback.py tests/test_high_level_operations.py tests/test_performance_trace.py -q --tb=short --basetemp=.dev-tmp/pytest/destination-race-regression-20261006
.\.venv\Scripts\ruff.exe check --no-cache tests/test_windows_transaction.py src/windows_local_mcp/windows_transaction.py
```

再実行時は `--basetemp` に新しい専用フォルダー名を使う。最初の制限環境では一時フォルダー作成が
`WinError 5` で拒否されたため、許可された通常Windowsホスト実行へ切り替えた。ACL変更や検査の迂回はしていない。

確認はこのPCのWindows/NTFS上の合成ファイルで行った。競合操作は同じプロセスから
トランザクションに参加しない通常APIで実行している。長時間のランダム負荷、他のWindows環境、
実ユーザーデータ、実ChatGPT/Tunnel、Approved Host/Sandboxの実機受容試験、全リポジトリ試験は実施していない。

## 変更ファイル

- `tests/test_windows_transaction.py`: 競合時点と例外の発生源を分け、予約・上書き防止・復元・再実行を検証する。
- `src/windows_local_mcp/windows_transaction.py`: 競合が常にcommit失敗になると読めるコメントを訂正する。実行コードは変更しない。
- `VERIFICATION.md`、`docs/DETERMINISTIC_WORKSPACE_OPERATIONS.md`: 過去の失敗記録を残し、本追跡調査で解消したことを明記する。
- 本書: 原因、根拠、試験条件と限界を記録する。

コミットメッセージ案: `test: TxFコピー・移動の保存先競合テストを修正`
