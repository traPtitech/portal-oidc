package domain

import "github.com/google/uuid"

type User struct {
	ID     uuid.UUID
	TrapID string
}

type UserWithPassword struct {
	User
	PasswordHash string
}
