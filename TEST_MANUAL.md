# Conformance Suite でのテストのやり方

## 目的

OpenID Connect Conformance Suite を使って本リポジトリの OIDC 実装を手動で検証する。

## 1. OIDC サーバーの起動

1. 開発環境を起動する

   ```bash
   mise run dev
   ```

   `config.yaml`のhostを`http://host.docker.internal:8080` に書き換える必要があるはず。

## 2. Discovery の確認

次の URL が 200 で返ることを確認する。

- OpenID Provider Configuration: `http://localhost:8080/.well-known/openid-configuration`
- JWKS: `http://localhost:8080/.well-known/jwks.json`

例:

```bash
curl -sS http://localhost:8080/.well-known/openid-configuration | head -n 5
curl -sS http://localhost:8080/.well-known/jwks.json | head -n 5
```

## 3. Conformance Suite 用クライアントの作成

Conformance Suite が提示する Redirect URI を登録する。`client_type` は `confidential` を推奨。
`<callback-uri>`の例: `https://localhost.emobix.co.uk:8443/test/a/alias/callback`　<- 一度Create Test Planをすると表示されたはず。

```bash
curl -sS -X POST http://localhost:8080/api/v1/admin/clients \
  -H 'Content-Type: application/json' \
  -d '{"name":"conformance-suite","client_type":"confidential","redirect_uris":["<callback-uri>"]}'
```

レスポンスに `client_id` と `client_secret` が含まれるので控えておく。

## 4. Conformance Suite の起動

```bash
git clone git@github.com:openid-certification/conformance-suite.git
docker compose up
```

## 5. Suite 側の設定

Suite の新規テスト作成画面で、以下を設定する。

- Alias: 好きな名称
- Client ID: 手順 3 で作成した `client_id`
- Client Secret: 手順 3 で作成した `client_secret`
- Discovery URL: `http://host.docker.internal:8080/.well-known/openid-configuration`

## 7. 実行と結果確認

Suite からテストを実行し、失敗したテスト項目のログを確認して修正する。
