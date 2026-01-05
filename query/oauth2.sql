-- Client queries (OAuthクライアント)

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

-- Session queries (ログインセッション)

-- name: CreateSession :exec
INSERT INTO sessions (id, user_id, user_agent, ip_address, auth_time, last_active_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetSession :one
SELECT * FROM sessions WHERE id = ? AND revoked_at IS NULL;

-- name: UpdateSessionLastActive :exec
UPDATE sessions SET last_active_at = ? WHERE id = ?;

-- name: RevokeSession :exec
UPDATE sessions SET revoked_at = NOW() WHERE id = ?;

-- name: DeleteExpiredSessions :exec
DELETE FROM sessions WHERE expires_at < NOW();

-- name: ListSessionsByUser :many
SELECT * FROM sessions WHERE user_id = ? AND revoked_at IS NULL ORDER BY last_active_at DESC;

-- User consent queries (ユーザー同意情報)

-- name: CreateUserConsent :exec
INSERT INTO user_consents (id, user_id, client_id, scopes, granted_at)
VALUES (?, ?, ?, ?, ?);

-- name: GetUserConsent :one
SELECT * FROM user_consents WHERE user_id = ? AND client_id = ? AND revoked_at IS NULL;

-- name: UpdateUserConsentScopes :exec
UPDATE user_consents SET scopes = ?, granted_at = ? WHERE user_id = ? AND client_id = ?;

-- name: RevokeUserConsent :exec
UPDATE user_consents SET revoked_at = NOW() WHERE user_id = ? AND client_id = ?;

-- Login session queries (OAuth認可フロー一時状態)

-- name: CreateLoginSession :exec
INSERT INTO login_sessions (id, client_id, redirect_uri, form_data, scopes, expires_at)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetLoginSession :one
SELECT * FROM login_sessions WHERE id = ?;

-- name: DeleteLoginSession :exec
DELETE FROM login_sessions WHERE id = ?;

-- name: DeleteExpiredLoginSessions :exec
DELETE FROM login_sessions WHERE expires_at < NOW();
