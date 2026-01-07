package domain

import (
	"time"

	"github.com/google/uuid"
)

type SessionID uuid.UUID

type Session struct {
	ID            SessionID
	UserID        TrapID
	ClientID      ClientID
	AllowedScopes []string
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

type LoginSessionID uuid.UUID

type LoginSession struct {
	ID            LoginSessionID
	Forms         string
	AllowedScopes []string
	UserID        TrapID
	ClientID      ClientID
	CreatedAt     time.Time
	ExpiresAt     time.Time
}
