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
    name = $2,
    client_type = $3,
    redirect_uris = $4
WHERE client_id = $1;

-- name: UpdateClientSecret :exec
UPDATE clients SET
    client_secret_hash = $2
WHERE client_id = $1;

-- name: DeleteClient :exec
DELETE FROM clients WHERE client_id = $1;
