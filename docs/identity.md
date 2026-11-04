# Portal identity integration

The internal API is specified in `api/internal.openapi.yaml`. Configure
`OIDC_INTERNAL__TOKEN` with the same secret as Portal's `PORTAL_INTERNAL_TOKEN`.
An empty token disables the internal routes. Expose these routes only to Portal
through the service network; the token must never be given to a browser.

Apply the OIDC schema before starting the new binary. The Portal database is
owned by Portal and must not be migrated with the OIDC schema task.

Provisioning is synchronous and keyed by the Portal-generated user UUID. The
payload fingerprint includes the case-sensitive traQ ID and makes identical
replays successful without changing credentials. Different content, a duplicate
traQ ID or a duplicate email returns 409.
The account stores the supplied SHA-256 verifier, not the password or auth secret.
The membership expiry is not a request timeout. Expired initial requests are
rejected; identical retries still acknowledge a previously committed account.

Portal calls provision before committing its own transaction. There is therefore
no cross-database foreign key or profile lookup during provisioning. DELETE is
compensation for a confirmed provision followed by a confirmed Portal rollback.
It does not fence a delayed POST. After a lost response or uncertain commit,
operators must reconcile the UUID in both databases before retrying registration
or deleting anything. Logs contain UUID and failure category only.

The provisioning and login changes are stacked below the traQ ID update. Deploy
the complete stack with the matching Portal registration branch.

## Login

The login form submits `trapId` and `auth_secret`; the browser presents traQ ID
and password fields. Policy v1
trims surrounding login whitespace, preserves ID case, and hashes
`traPortal kdf v1:` plus that traQ ID for the Argon2id salt. It derives 32 bytes
with Argon2id (64 MiB, 3 iterations, 4 lanes), then uses HKDF-SHA-256 with info `traPortal auth v1` to derive a
32-byte auth secret. The submitted encoding is canonical unpadded base64url.
The OIDC service verifies its SHA-256 against the registered verifier.

The worker runs from the OIDC origin. Passwords and intermediate key material
stay in browser memory; neither password nor root key is submitted or persisted.
JavaScript/worker failure has no plaintext fallback. Login retains the OIDC
session, authorization-code flow, UUID subject, safe return URL and rate limit,
and adds a session-bound CSRF token. The form contract is in
`api/login.openapi.yaml`. An incorrect credential produces a generic error.

Both an unexpired OIDC account and its committed Portal profile must exist.
Unverified email does not prevent login; the email scope returns the stored
`email_verified` value, including false. The profile scope reads `trap_id` from
Portal by UUID. Development uses the same authentication path as production;
there is no fixed-user bypass or legacy PBKDF2 fallback. There are no existing
users to migrate. Password changes/reset, email verification and E2EE key
unwrapping are outside these PRs.

## Local fixtures and asset builds

Use the fixtures only in disposable development/test databases:

1. Apply `db/schema.sql` to the OIDC database and `db/portal-schema.sql` to a
   disposable Portal database. The latter is a development snapshot, not a
   production Portal migration.
2. Apply `development/seed-profile.sql` to that Portal database.
3. Start the server with `OIDC_INTERNAL__TOKEN` configured. Send
   `development/provision.json` to `POST /internal/users/provision`, with that
   value in `X-Portal-Internal-Token` and `Content-Type: application/json`.
4. Log in as `TestUser_01` with password `password`. These public
   fixture credentials are shared by the browser and conformance tests.

`npm --prefix web ci --ignore-scripts` and `npm --prefix web run build` regenerate
the committed Go-embedded assets. Node.js 20.19 or newer is required. CI verifies
regeneration, the shared Go/JavaScript KDF vector, and the real browser flow.
After installing Chromium with `cd web && npx playwright install chromium`,
run `npm --prefix web run test:browser` against the disposable server on port
8080 with internal token `browser-test-internal-token` (or configure
`OIDC_TEST_URL` and `OIDC_TEST_INTERNAL_TOKEN`).

## traQ ID contract

Provisioning requires `trapId`, matching Portal's case-sensitive ASCII ID format:
`^[a-zA-Z0-9]([a-zA-Z0-9_-]{0,30}[a-zA-Z0-9])?$`. OIDC stores it uniquely and
includes it in the immutable provisioning fingerprint. The committed Portal
profile must contain the same ID. Email remains an account attribute and an
OIDC claim; it is not a login identifier or KDF input. The UUID remains `sub`.

This changes the unreleased policy-v1 salt input from email to traQ ID. Deploy
the paired Portal PR with this PR. There are no existing users to migrate;
recreate disposable email-derived test accounts. Renaming a traQ ID requires a
separate credential/key rewrapping design, because it would change the salt.
Password change/reset clients must use the same original traQ ID.

The shared vector in `web/test/vector.json` matches Portal's
`service/identity/testdata/auth-secret-v1.json`. Registration clients must use
the same salt for the root key and all credentials/wraps derived from it.
