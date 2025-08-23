
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