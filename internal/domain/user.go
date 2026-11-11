package domain

import "github.com/google/uuid"

type User struct {
	ID            uuid.UUID
	TrapID        string
	Email         string
	EmailVerified bool
}
