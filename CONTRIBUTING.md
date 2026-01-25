# Contributing to portal-oidc

## 開発環境のセットアップ

### 必要なツール

- [mise](https://mise.jdx.dev/) (推奨) または以下を個別インストール
  - Go 1.25+
  - golangci-lint
  - sqlc
  - Docker / Docker Compose

### セットアップ手順

```bash
# 依存ツールのインストール
mise install

# DB 起動
mise run start:db

# サーバー起動
mise run start:server
```

### Docker を使う場合

```bash
docker compose up
```

## 開発フロー

### 1. ブランチ作成

```bash
git checkout -b feat/your-feature
```

### 2. コード変更

```bash
# コード生成 (sqlc, oapi-codegen)
mise run gen

# リンター実行
mise run lint

# テスト実行
mise run test
```

### 3. コミット

[Conventional Commits](https://www.conventionalcommits.org/) に従う:

- `feat:` 新機能
- `fix:` バグ修正
- `docs:` ドキュメント
- `chore:` その他

### 4. Pull Request

- タイトルは Conventional Commits 形式
- 変更内容を簡潔に説明
- 関連 Issue があればリンク

## Pre-commit hooks (推奨)

```bash
mise run setup
```

## コードスタイル

- `gofmt` / `goimports` でフォーマット
- `golangci-lint` でリント
- 生成コードは編集しない (`gen/` ディレクトリ)

## テスト

```bash
# 全テスト
mise run test

# カバレッジ付き
mise run test:coverage
```

## 質問・相談

Issue または traP の Slack で気軽にどうぞ。
