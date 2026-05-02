-- name: GetUserByID :one
SELECT id, trap_id, password_hash, student_number, created_at, updated_at
FROM users WHERE id = $1;

-- name: GetUserByTrapID :one
SELECT id, trap_id, password_hash, student_number, created_at, updated_at
FROM users WHERE trap_id = $1;

-- name: GetUserByStudentNumber :one
SELECT id, trap_id, password_hash, student_number, created_at, updated_at
FROM users WHERE student_number = $1;

-- name: ListUserStatuses :many
SELECT user_id, status, detail, created_at
FROM user_statuses WHERE user_id = $1;
