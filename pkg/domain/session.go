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
