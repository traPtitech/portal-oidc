package domain

import (
	"time"

	"github.com/google/uuid"
)

// UserSession is a single login session belonging to a user. session_id is the
// opaque value persisted in the End-User's cookie; multiple rows per user
// represent separate browsers / devices.
type UserSession struct {
	ID           uuid.UUID
	SessionID    string
	UserID       uuid.UUID
	UserAgent    string
	IPAddress    string
	ACR          string
	AMR          []string
	AuthTime     time.Time
	LastActiveAt time.Time
	ExpiresAt    time.Time
	RevokedAt    *time.Time
	CreatedAt    time.Time
}

// IsActive reports whether this session can still authenticate requests.
func (s UserSession) IsActive(now time.Time) bool {
	if s.RevokedAt != nil {
		return false
	}
	return now.Before(s.ExpiresAt)
}
