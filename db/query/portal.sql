-- name: GetUserByID :one
SELECT id, trap_id, password_hash, student_number, created_at, updated_at
FROM users WHERE id = ?;

-- name: GetUserByTrapID :one
SELECT id, trap_id, password_hash, student_number, created_at, updated_at
FROM users WHERE trap_id = ?;

-- name: GetUserByStudentNumber :one
SELECT id, trap_id, password_hash, student_number, created_at, updated_at
FROM users WHERE student_number = ?;

-- name: ListUserStatuses :many
SELECT user_id, status, detail, created_at
FROM user_statuses WHERE user_id = ?;
