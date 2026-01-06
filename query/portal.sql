-- name: GetUserByID :one
SELECT id, student_number
FROM users WHERE id = ?;

-- name: GetUserAuth :one
SELECT id, password
FROM users WHERE id = ?;
