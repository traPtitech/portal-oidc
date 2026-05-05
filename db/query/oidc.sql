-- Client queries

-- name: CreateClient :exec
INSERT INTO clients (
    client_id,
    client_secret_hash,
    name,
    client_type,
    redirect_uris
) VALUES ($1, $2, $3, $4, $5);

-- name: GetClient :one
SELECT * FROM clients WHERE client_id = $1;

-- name: ListClients :many
SELECT * FROM clients;

-- name: UpdateClient :exec
UPDATE clients SET
    name = $1,
    client_type = $2,
    redirect_uris = $3
WHERE client_id = $4;

-- name: UpdateClientSecret :exec
UPDATE clients SET
    client_secret_hash = $1
WHERE client_id = $2;

-- name: DeleteClient :exec
DELETE FROM clients WHERE client_id = $1;

-- name: DeleteAllClients :exec
DELETE FROM clients;

-- Authorization Code queries

-- name: CreateAuthorizationCode :exec
INSERT INTO authorization_codes (
    code,
    client_id,
    user_id,
    redirect_uri,
    scopes,
    code_challenge,
    code_challenge_method,
    nonce,
    expires_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: GetAuthorizationCode :one
SELECT * FROM authorization_codes WHERE code = $1;

-- name: DeleteAuthorizationCode :exec
DELETE FROM authorization_codes WHERE code = $1;

-- name: MarkAuthorizationCodeUsed :exec
UPDATE authorization_codes SET used = TRUE WHERE code = $1;

-- name: UpdateAuthorizationCodePKCE :exec
UPDATE authorization_codes SET
    code_challenge = $1,
    code_challenge_method = $2
WHERE code = $3;

-- name: DeleteExpiredAuthorizationCodes :exec
DELETE FROM authorization_codes WHERE expires_at < NOW();

-- name: DeleteAllAuthorizationCodes :exec
DELETE FROM authorization_codes;

-- Token queries

-- name: CreateToken :exec
INSERT INTO tokens (
    id,
    request_id,
    client_id,
    user_id,
    access_token,
    refresh_token,
    scopes,
    expires_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: GetTokenByAccessToken :one
SELECT * FROM tokens WHERE access_token = $1;

-- name: GetTokenByRefreshToken :one
SELECT * FROM tokens WHERE refresh_token = $1;

-- name: GetTokenByID :one
SELECT * FROM tokens WHERE id = $1;

-- name: DeleteToken :exec
DELETE FROM tokens WHERE id = $1;

-- name: DeleteTokenByAccessToken :exec
DELETE FROM tokens WHERE access_token = $1;

-- name: DeleteTokenByRefreshToken :exec
DELETE FROM tokens WHERE refresh_token = $1;

-- name: DeleteExpiredTokens :exec
DELETE FROM tokens WHERE expires_at < NOW();

-- name: DeleteTokensByUserAndClient :exec
DELETE FROM tokens WHERE user_id = $1 AND client_id = $2;

-- name: DeleteTokensByRequestID :exec
DELETE FROM tokens WHERE request_id = $1;

-- name: DeleteAllTokens :exec
DELETE FROM tokens;

-- OIDC Session queries

-- name: CreateOIDCSession :exec
INSERT INTO oidc_sessions (
    authorize_code,
    client_id,
    user_id,
    scopes,
    nonce,
    auth_time,
    requested_at
) VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: GetOIDCSession :one
SELECT * FROM oidc_sessions WHERE authorize_code = $1;

-- name: DeleteOIDCSession :exec
DELETE FROM oidc_sessions WHERE authorize_code = $1;

-- name: DeleteAllOIDCSessions :exec
DELETE FROM oidc_sessions;

-- WebAuthn credential queries

-- name: CreateWebAuthnCredential :exec
INSERT INTO webauthn_credentials (
    id,
    user_id,
    credential_id,
    public_key,
    public_key_alg,
    attestation_format,
    aaguid,
    sign_count,
    transports,
    device_name,
    backed_up
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);

-- name: GetWebAuthnCredentialByCredentialID :one
SELECT * FROM webauthn_credentials WHERE credential_id = $1;

-- name: ListWebAuthnCredentialsByUser :many
SELECT * FROM webauthn_credentials WHERE user_id = $1 ORDER BY created_at;

-- name: UpdateWebAuthnCredentialSignCount :exec
UPDATE webauthn_credentials
SET sign_count = $1, last_used_at = CURRENT_TIMESTAMP
WHERE id = $2;

-- name: UpdateWebAuthnCredentialDeviceName :exec
UPDATE webauthn_credentials SET device_name = $1 WHERE id = $2 AND user_id = $3;

-- name: DeleteWebAuthnCredential :exec
DELETE FROM webauthn_credentials WHERE id = $1 AND user_id = $2;

-- WebAuthn challenge queries

-- name: CreateWebAuthnChallenge :exec
INSERT INTO webauthn_challenges (
    id,
    challenge,
    user_id,
    session_id,
    type,
    data,
    expires_at
) VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: GetWebAuthnChallengeBySessionID :one
SELECT * FROM webauthn_challenges
WHERE session_id = $1 AND type = $2 AND expires_at > CURRENT_TIMESTAMP
ORDER BY created_at DESC
LIMIT 1;

-- name: DeleteWebAuthnChallenge :exec
DELETE FROM webauthn_challenges WHERE id = $1;

-- name: DeleteExpiredWebAuthnChallenges :exec
DELETE FROM webauthn_challenges WHERE expires_at < CURRENT_TIMESTAMP;
