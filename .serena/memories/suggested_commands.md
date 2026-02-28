# 開発コマンド

## 実行
```bash
# macOS起動
./start.sh

# 直接実行
source venv_mac/bin/activate
python main.py

# 接続テスト
python test_connection.py
```

## 依存関係
```bash
pip install -r requirements.txt
```

## Git
```bash
git status
git log --oneline -10
```

## ログ確認
```bash
tail -100 logs/pop3_gmail_importer.log
```

## システムコマンド (macOS/Darwin)
- `ls`, `cat`, `grep`, `find` - 標準Unix互換
