
-- name: CreateClient :exec
INSERT INTO clients (
    id, 
    user_id, 
    type, 
    name, 
    description, 
    secret_key, 
    redirect_uris
    ) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetClient :one
SELECT * FROM clients WHERE id = ?;

-- name: ListClientsByUserID :many
SELECT * FROM clients WHERE user_id = ?;

-- name: UpdateClient :exec
UPDATE clients SET
    type = ?,
    name = ?,
    description = ?,
    redirect_uris = ?
WHERE id = ?;


-- name: UpdateClientSecret :exec
UPDATE clients SET
    secret_key = ?
WHERE id = ?;

-- name: DeleteClient :exec
DELETE FROM clients WHERE id = ?;

-- name: AddBlacklistJTI :exec
INSERT INTO blacklisted_jtis (jti, after) VALUES (?, ?);

-- name: GetBlacklistJTI :one
SELECT jti, after FROM blacklisted_jtis WHERE jti = ?;

-- name: DeleteOldBlacklistJTI :exec
DELETE FROM blacklisted_jtis WHERE after < NOW();

-- name: CreateBlacklistJTI :exec
INSERT INTO blacklisted_jtis (jti, after) VALUES (?, ?);

-- name: CreateToken :exec
INSERT INTO authorization_sessions (
    id,
    signature,
    token_type,
    client_id,
    user_id,
    requested_scope,
    granted_scope,
    form_data,
    expired_at,
    username,
    subject,
    active,
    requested_audience,
    granted_audience
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetToken :one
SELECT * FROM authorization_sessions WHERE signature = ? AND token_type = ? AND active = 1 LIMIT 1;

-- name: RevokeToken :exec
UPDATE authorization_sessions SET active = 0 WHERE signature = ? AND token_type = ?;
