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

-- Access token queries

-- name: CreateAccessToken :exec
INSERT INTO access_tokens (
    id,
    jti,
    request_id,
    client_id,
    user_id,
    scopes,
    audience,
    expires_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: GetAccessTokenByJTI :one
SELECT * FROM access_tokens WHERE jti = $1;

-- name: DeleteAccessTokenByJTI :exec
DELETE FROM access_tokens WHERE jti = $1;

-- name: DeleteAccessTokensByRequestID :exec
DELETE FROM access_tokens WHERE request_id = $1;

-- name: RevokeAccessTokensByRequestID :exec
UPDATE access_tokens SET revoked_at = CURRENT_TIMESTAMP
WHERE request_id = $1 AND revoked_at IS NULL;

-- name: DeleteExpiredAccessTokens :exec
DELETE FROM access_tokens WHERE expires_at < NOW();

-- name: DeleteAllAccessTokens :exec
DELETE FROM access_tokens;

-- Refresh token queries

-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (
    id,
    token_hash,
    request_id,
    client_id,
    user_id,
    scopes,
    expires_at,
    previous_token_id
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: GetRefreshTokenByHash :one
SELECT * FROM refresh_tokens WHERE token_hash = $1;

-- name: DeleteRefreshTokenByHash :exec
DELETE FROM refresh_tokens WHERE token_hash = $1;

-- name: MarkRefreshTokenRotated :exec
UPDATE refresh_tokens SET rotated_at = CURRENT_TIMESTAMP
WHERE token_hash = $1 AND rotated_at IS NULL;

-- name: RevokeRefreshTokensByRequestID :exec
UPDATE refresh_tokens SET revoked_at = CURRENT_TIMESTAMP
WHERE request_id = $1 AND revoked_at IS NULL;

-- name: DeleteRefreshTokensByRequestID :exec
DELETE FROM refresh_tokens WHERE request_id = $1;

-- name: DeleteExpiredRefreshTokens :exec
DELETE FROM refresh_tokens WHERE expires_at < NOW();

-- name: DeleteAllRefreshTokens :exec
DELETE FROM refresh_tokens;

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
