
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

-- name: CreateAccessTokenSession :exec
INSERT INTO access_tokens (
    id,
    signature,
    requested_at,
    token_type,
    client_id,
    user_id,
    requested_scope,
    granted_scope,
    form_data,
    session_data,
    active,
    requested_audience,
    granted_audience
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: CreateRefreshTokenSession :exec
INSERT INTO refresh_tokens (
    id,
    signature,
    requested_at,
    token_type,
    client_id,
    user_id,
    requested_scope,
    granted_scope,
    form_data,
    session_data,
    active,
    requested_audience,
    granted_audience
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: CreateAuthorizeCodeSession :exec
INSERT INTO authorize_code_sessions (
    id,
    code,
    requested_at,
    token_type,
    client_id,
    user_id,
    requested_scope,
    granted_scope,
    form_data,
    session_data,
    active,
    requested_audience,
    granted_audience
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: CreateOpenIDConnectSession :exec
INSERT INTO open_id_connect_sessions (
    id,
    authorize_code,
    requested_at,
    token_type,
    client_id,
    user_id,
    requested_scope,
    granted_scope,
    form_data,
    session_data,
    active,
    requested_audience,
    granted_audience
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: CreatePKCERequestSession :exec
INSERT INTO pkce_request_sessions (
    id,
    code,
    requested_at,
    token_type,
    client_id,
    user_id,
    requested_scope,
    granted_scope,
    form_data,
    session_data,
    active,
    requested_audience,
    granted_audience
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);


-- name: GetAccessToken :one
SELECT * FROM access_tokens WHERE signature = ? AND active = 1 LIMIT 1;

-- name: RevokeAccessTokenBySignature :exec
UPDATE access_tokens SET active = 0 WHERE signature = ?;

-- name: GetRefreshToken :one
SELECT * FROM refresh_tokens WHERE signature = ? AND active = 1 LIMIT 1;

-- name: RevokeRefreshTokenBySignature :exec
UPDATE refresh_tokens SET active = 0 WHERE signature = ?;

-- name: GetAuthorizeCodeSession :one
SELECT * FROM authorize_code_sessions WHERE code = ? AND active = 1 LIMIT 1;

-- name: RevokeAuthorizeCodeSession :exec
UPDATE authorize_code_sessions SET active = 0 WHERE code = ?;

-- name: GetOpenIDConnectSession :one
SELECT * FROM open_id_connect_sessions WHERE authorize_code = ? AND active = 1 LIMIT 1;

-- name: RevokeOpenIDConnectSession :exec
UPDATE open_id_connect_sessions SET active = 0 WHERE authorize_code = ?;

-- name: GetPKCERequestSession :one
SELECT * FROM pkce_request_sessions WHERE code = ? AND active = 1 LIMIT 1;

-- name: RevokePKCERequestSession :exec
UPDATE pkce_request_sessions SET active = 0 WHERE code = ?;

-- name: RevokeAccessTokenByID :exec
UPDATE access_tokens SET active = 0 WHERE id = ?;

-- name: RevokeRefreshTokenByID :exec
UPDATE refresh_tokens SET active = 0 WHERE id = ?;




