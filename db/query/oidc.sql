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

-- Sessions

-- name: CreateSession :exec
INSERT INTO sessions (
    session_id,
    user_id,
    client_id,
    allowed_scopes,
    expires_at
) VALUES (?, ?, ?, ?, ?);

-- name: GetSession :one
SELECT * FROM sessions WHERE session_id = ? AND expires_at > NOW();

-- name: DeleteSession :exec
DELETE FROM sessions WHERE session_id = ?;

-- name: DeleteExpiredSessions :exec
DELETE FROM sessions WHERE expires_at <= NOW();

-- Login Sessions

-- name: CreateLoginSession :exec
INSERT INTO login_sessions (
    login_session_id,
    forms,
    allowed_scopes,
    user_id,
    client_id,
    expires_at
) VALUES (?, ?, ?, ?, ?, ?);

-- name: GetLoginSession :one
SELECT * FROM login_sessions WHERE login_session_id = ? AND expires_at > NOW();

-- name: DeleteLoginSession :exec
DELETE FROM login_sessions WHERE login_session_id = ?;

-- name: DeleteExpiredLoginSessions :exec
DELETE FROM login_sessions WHERE expires_at <= NOW();
