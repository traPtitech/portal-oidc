# Portal identity integration

Portal provisions authentication accounts through the internal API in
`api/internal.openapi.yaml`. Set `OIDC_INTERNAL__TOKEN` to the same value as
Portal's `PORTAL_INTERNAL_TOKEN`. If the token is empty, the server does not
register the internal routes. Expose these routes only to Portal on the service
network.

`POST /internal/users/provision` stores the account under the Portal user UUID.
The account keeps the SHA-256 verifier that Portal sends. It does not keep the
password or the auth secret. A request that repeats a stored account exactly
returns 200. A request with the same UUID and different content returns 409. A
request with a traQ ID or an email that another account uses also returns 409.
A request whose `expiresAt` is not in the future returns 422. The `trapId` field
is case-sensitive and must match Portal's traQ ID format.

The OIDC service does not read the Portal database. Portal calls provision
before it commits its own transaction. `DELETE /internal/users/{userId}` removes
the account after a confirmed provision and a confirmed Portal rollback. Until
that DELETE succeeds, the account can log in. DELETE does not stop a delayed
POST. If a provision response is lost, operators must compare the UUID in both
databases before they retry or delete anything.

## Login

The login page asks for the traQ ID and the password. The browser derives the
auth secret with Web Crypto and policy v1:

```text
salt        = SHA-256(UTF-8("traPortal kdf v1:" + trapId))
root        = PBKDF2-HMAC-SHA-256(UTF-8(password), salt, iterations=100000, length=32)
auth_secret = HKDF-SHA-256(root, empty salt, UTF-8("traPortal auth v1"), length=32)
```

The browser removes whitespace around the traQ ID and keeps its case. The form
posts `trapId`, `auth_secret` as unpadded base64url, a session CSRF token and
`return_url` to `POST /login`. The browser does not send or store the password
or the root key. If JavaScript or the derivation fails, the form is not submitted.

The server compares the SHA-256 of `auth_secret` with the stored verifier.
Login also requires an unexpired account. An email that is not verified does
not block login. The `sub` claim is the user UUID. The `profile` scope returns
`trap_id`, and the `email` scope returns the email and `email_verified`. Both
come from the OIDC account.

The traQ ID is part of the salt. For this reason, this service does not support
a traQ ID rename. `web/test/vector.json` is the same test vector as Portal's
`service/identity/testdata/auth-secret-v1.json`.

## Local fixtures

Use these fixtures only in a disposable development or test database.

1. Apply `db/schema.sql` to the OIDC database.
2. Start the server with `OIDC_INTERNAL__TOKEN` set.
3. Send `development/provision.json` to `POST /internal/users/provision`.
   Put the token in `X-Portal-Internal-Token` and set `Content-Type: application/json`.
4. Log in as `TestUser_01` with the password `password`.

## Login assets

The server embeds the built files in `internal/router/v1/loginassets`. If you
change `web/src`, run `npm --prefix web ci --ignore-scripts` and
`npm --prefix web run build`, and commit the output. The build needs Node.js
20.19 or later. `npm --prefix web test` checks the test vector.

To run the browser tests, install Chromium with `cd web && npx playwright install chromium`.
Then start the server on port 8080 with the internal token
`browser-test-internal-token`, and run `npm --prefix web run test:browser`.
`OIDC_TEST_URL` and `OIDC_TEST_INTERNAL_TOKEN` override the URL and the token.
