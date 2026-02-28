# POP3 to Gmail Importer v3.0

## 概要
複数のPOP3アカウントからGmail APIを使って直接Gmailにメールをインポートするデーモン。
SPF/DKIM/DMARCの問題を回避するため、Gmail API `messages.import()` を使用。

## 技術スタック
- Python 3.9+
- Gmail API (google-api-python-client)
- OAuth 2.0 認証 (google-auth-oauthlib)
- python-dotenv (環境変数管理)

## プロジェクト構造
- `main.py` - メインプログラム（単一ファイル、約655行）
- `test_connection.py` - 接続テスト用スクリプト
- `start.sh` / `start.bat` - 起動スクリプト (macOS/Windows)
- `.env` - 設定ファイル (最大5アカウント)
- `credentials.json` - Google OAuth認証情報
- `tokens/` - OAuthトークン保存先
- `state/` - UIDL状態管理 (JSONL形式)
- `backup/` - メールバックアップ
- `logs/` - ログファイル（ローテーション付き）

## 主要機能
- 最大5アカウントの同時処理
- UIDLベースの重複防止
- デバッグモード（DELETE_AFTER_FORWARD=false時、最新5件のみ）
- メールバックアップ（保持期間付き）
- グレースフルシャットダウン（SIGINT/SIGTERM対応）

## 実行中のアカウント（ログより）
- Account 1: Yahoo Mail (pop.mail.yahoo.co.jp) → Gmail (o***@gmail.com)
- Account 2: kov.jp (info) → Gmail
- Account 3: kov.jp (kei31ai) → Gmail (k***@gmail.com)
