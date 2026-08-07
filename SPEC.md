# Windows Local MCP 仕様

## 1. 目的

ChatGPTなどのMCPホストが、Windows上の現在のローカル作業ツリーを直接読み、変更し、検証できるようにする。

GitHub上の別コピーを編集する方式と異なり、未コミット変更を含む実際の作業状態を対象にする。

## 2. 非目的

- Decision Deck本体の機能をこのリポジトリへ実装しない
- ChatGPTの内部メモリを直接更新しない
- Windows全体を無制限に操作させない
- OSレベルの完全なサンドボックスを提供したと主張しない

## 3. 権限モデル

### Tier 0: 読み取り

`session_info`、`list_directory`、`read_file`、`get_image`、`audit_list`、`audit_get`

### Tier 1: 制限付き自動実行

`write_file`、`execute`、`start_command`、`poll_job`、`stop_job`

`execute` は許可リストに登録されたプログラムとサブコマンドだけを実行する。

### Tier 2: 人間承認

`request_host_command`、`poll_approval`、`execute_approved`

任意PowerShell、ネットワークアクセス、削除、プロセス操作などはこの経路へ送る。

承認対象は正規化JSONからSHA-256を作り、承認後の差し替えを拒否する。

## 4. executeの設計

`execute` は自由なシェルではない。次を共通化する。

- 実行ファイルの解決
- 作業ディレクトリ制限
- 入力検証
- プロセス起動
- stdout / stderr回収
- タイムアウト
- バックグラウンド化
- 停止
- Git状態取得
- 監査ログ

push、deploy、delete、外部送信、本番DB変更などは専用ツール化すべきである。

## 5. ジョブ管理

コマンドは専用workerプロセスで実行する。

- 受付時点でSQLiteへ `queued`
- worker開始時に `running`
- 30秒以内に終了すれば同期結果
- 30秒を超えれば `job_id`
- 終了時に `succeeded` または `failed`
- 最大実行時間超過時に `timed_out`
- stop_jobで `cancelled`

## 6. 監査ログ

操作要求を受信した時点でDBへ記録する。

ファイル編集は変更前後SHA、unified diff、バックアップを保存する。

コマンドはargv、cwd、stdout、stderr、終了コード、実行前後のGit状態を保存する。

## 7. セキュリティ上の限界

- Windowsのネットワーク隔離は未実装
- 管理者権限で起動しない
- 作業フォルダに秘密鍵や本番資格情報を置かない
- PowerShellの任意実行は必ず承認経路
- 監査DB自体への悪意あるローカル改ざんは防げない
