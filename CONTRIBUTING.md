# Contributing to portal-oidc

## 開発環境のセットアップ

### 必要なツール

- Docker / Docker Compose
- [mise](https://mise.jdx.dev/) (コード生成・リント用)

### セットアップ手順

```bash
# mise 設定を信頼
mise trust

# pre-commit hooks のセットアップ
mise run setup

# 開発サーバー起動 (Air によるホットリロード)
mise run dev
```

これで http://localhost:8080 でサーバーが起動します。
コードを変更すると自動的にリビルド・再起動されます。

### Adminer (DB 管理 UI)

```bash
docker compose --profile tools up
```

http://localhost:3001 でアクセス可能。

## 開発フロー

### 1. ブランチ作成

```bash
git switch -c feat/your-feature
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
