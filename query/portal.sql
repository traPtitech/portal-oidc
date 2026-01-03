-- name: GetUserByID :one
SELECT id, student_number, alphabetic_name, email
FROM users WHERE id = ?;
