# コードスタイル・規約

## 命名
- 関数: snake_case (`process_account`, `load_uidl_state`)
- 定数: UPPER_SNAKE_CASE (`SCOPES`, `MAX_EMAILS_PER_LOOP`)
- 変数: snake_case

## 構成
- 単一ファイル (main.py) にすべてのロジック
- クラスは使わず関数ベース
- .envで設定管理（環境変数）
- アカウント設定: `ACCOUNT{N}_` プレフィックス

## ロギング
- `logging` モジュール使用
- `Account {num}:` プレフィックスで各メッセージ識別
- パスワード・メールアドレスはマスク処理

## エラーハンドリング
- 各関数でtry/except、エラーログ出力
- 失敗時は次のメール/ループで再試行

## 状態管理
- UIDL: JSONL形式 (state/account{N}_uidl.jsonl)
- 各レコード: {uidl, timestamp, gmail_target, backup_file}
