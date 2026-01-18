-- Client queries

-- name: CreateClient :exec
INSERT INTO clients (
    client_id,
    client_secret_hash,
    name,
    client_type,
    redirect_uris
) VALUES (?, ?, ?, ?, ?);

-- name: GetClient :one
SELECT * FROM clients WHERE client_id = ?;

-- name: ListClients :many
SELECT * FROM clients;

-- name: UpdateClient :exec
UPDATE clients SET
    name = ?,
    client_type = ?,
    redirect_uris = ?
WHERE client_id = ?;

-- name: UpdateClientSecret :exec
UPDATE clients SET
    client_secret_hash = ?
WHERE client_id = ?;

-- name: DeleteClient :exec
DELETE FROM clients WHERE client_id = ?;

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
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetAuthorizationCode :one
SELECT * FROM authorization_codes WHERE code = ?;

-- name: DeleteAuthorizationCode :exec
DELETE FROM authorization_codes WHERE code = ?;

-- name: UpdateAuthorizationCodePKCE :exec
UPDATE authorization_codes SET
    code_challenge = ?,
    code_challenge_method = ?
WHERE code = ?;

-- name: DeleteExpiredAuthorizationCodes :exec
DELETE FROM authorization_codes WHERE expires_at < NOW();

-- name: DeleteAllAuthorizationCodes :exec
DELETE FROM authorization_codes;

-- Token queries

-- name: CreateToken :exec
INSERT INTO tokens (
    id,
    client_id,
    user_id,
    access_token,
    refresh_token,
    scopes,
    expires_at
) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetTokenByAccessToken :one
SELECT * FROM tokens WHERE access_token = ?;

-- name: GetTokenByRefreshToken :one
SELECT * FROM tokens WHERE refresh_token = ?;

-- name: GetTokenByID :one
SELECT * FROM tokens WHERE id = ?;

-- name: DeleteToken :exec
DELETE FROM tokens WHERE id = ?;

-- name: DeleteTokenByAccessToken :exec
DELETE FROM tokens WHERE access_token = ?;

-- name: DeleteTokenByRefreshToken :exec
DELETE FROM tokens WHERE refresh_token = ?;

-- name: DeleteExpiredTokens :exec
DELETE FROM tokens WHERE expires_at < NOW();

-- name: DeleteTokensByUserAndClient :exec
DELETE FROM tokens WHERE user_id = ? AND client_id = ?;

-- name: DeleteAllTokens :exec
DELETE FROM tokens;