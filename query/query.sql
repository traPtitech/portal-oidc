
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

-- name: CreateAccessTokenSession :exec
INSERT INTO access_token_sessions (
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

-- name: CreateRefreshTokenSession :exec
INSERT INTO refresh_token_sessions (
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

-- name: CreateAuthorizationCodeSession :exec
INSERT INTO authorization_code_sessions (
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

-- name: CreateOpenIDConnectSession :exec
INSERT INTO open_id_connect_sessions (
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

-- name: CreatePKCERequestSession :exec
INSERT INTO pkce_request_sessions (
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

-- name: RevokeTokenWithSignature :exec
UPDATE authorization_sessions SET active = 0 WHERE signature = ? AND token_type = ?;

-- name: RevokeTokenByClientID :exec
UPDATE authorization_sessions SET active = 0 WHERE client_id = ? AND token_type = ?;

-- name: GetAccessTokenSession :one
SELECT * FROM access_token_sessions WHERE signature = ? AND active = 1 LIMIT 1;

-- name: RevokeAccessTokenSessionWithSignature :exec
UPDATE access_token_sessions SET active = 0 WHERE signature = ?;

-- name: RevokeAccessTokenSessionByClientID :exec
UPDATE access_token_sessions SET active = 0 WHERE client_id = ?;

-- name: GetRefreshTokenSession :one
SELECT * FROM refresh_token_sessions WHERE signature = ? AND active = 1 LIMIT 1;

-- name: RevokeRefreshTokenSessionWithSignature :exec
UPDATE refresh_token_sessions SET active = 0 WHERE signature = ?;

-- name: RevokeRefreshTokenSessionByClientID :exec
UPDATE refresh_token_sessions SET active = 0 WHERE client_id = ?;

-- name: GetAuthorizationCodeSession :one
SELECT * FROM authorization_code_sessions WHERE signature = ? AND active = 1 LIMIT 1;

-- name: RevokeAuthorizationCodeSessionWithSignature :exec
UPDATE authorization_code_sessions SET active = 0 WHERE signature = ?;

-- name: RevokeAuthorizationCodeSessionByClientID :exec
UPDATE authorization_code_sessions SET active = 0 WHERE client_id = ?;

-- name: GetOpenIDConnectSession :one
SELECT * FROM open_id_connect_sessions WHERE signature = ? AND active = 1 LIMIT 1;

-- name: RevokeOpenIDConnectSessionWithSignature :exec
UPDATE open_id_connect_sessions SET active = 0 WHERE signature = ?;

-- name: RevokeOpenIDConnectSessionByClientID :exec
UPDATE open_id_connect_sessions SET active = 0 WHERE client_id = ?;

-- name: GetPKCERequestSession :one
SELECT * FROM pkce_request_sessions WHERE signature = ? AND active = 1 LIMIT 1;

-- name: RevokePKCERequestSessionWithSignature :exec
UPDATE pkce_request_sessions SET active = 0 WHERE signature = ?;

-- name: RevokePKCERequestSessionByClientID :exec
UPDATE pkce_request_sessions SET active = 0 WHERE client_id = ?;
