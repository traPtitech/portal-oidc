-- name: GetUserByID :one
SELECT id, trap_id FROM users WHERE id=$1;
