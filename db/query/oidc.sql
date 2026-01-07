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
