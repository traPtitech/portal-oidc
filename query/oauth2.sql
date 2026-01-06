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

-- Session queries (認証済みセッション)

-- name: CreateSession :exec
INSERT INTO sessions (id, user_id, user_agent, ip_address, auth_time, last_active_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetSession :one
SELECT * FROM sessions WHERE id = ?;

-- name: DeleteSession :exec
DELETE FROM sessions WHERE id = ?;

-- AuthorizationRequest queries (認可リクエスト一時保存)

-- name: CreateAuthorizationRequest :exec
INSERT INTO authorization_requests (id, client_id, redirect_uri, scope, state, code_challenge, code_challenge_method, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetAuthorizationRequest :one
SELECT * FROM authorization_requests WHERE id = ?;

-- name: UpdateAuthorizationRequestUserID :exec
UPDATE authorization_requests SET user_id = ? WHERE id = ?;

-- name: DeleteAuthorizationRequest :exec
DELETE FROM authorization_requests WHERE id = ?;

-- AuthorizationCode queries (認可コード)

-- name: CreateAuthorizationCode :exec
INSERT INTO authorization_codes (code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, session_data, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetAuthorizationCode :one
SELECT * FROM authorization_codes WHERE code = ?;

-- name: MarkAuthorizationCodeUsed :exec
UPDATE authorization_codes SET used = TRUE WHERE code = ?;

-- name: DeleteAuthorizationCode :exec
DELETE FROM authorization_codes WHERE code = ?;
