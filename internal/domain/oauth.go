package domain

import (
	"time"

	"github.com/google/uuid"
)

type AuthCode struct {
	Code                string
	ClientID            uuid.UUID
	UserID              uuid.UUID
	RedirectURI         string
	Scopes              []string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
	Used                bool
	ExpiresAt           time.Time
	CreatedAt           time.Time
}

type Token struct {
	ID           uuid.UUID
	RequestID    string
	ClientID     uuid.UUID
	UserID       uuid.UUID
	AccessToken  string // #nosec G117 -- domain field name, not a credential
	RefreshToken string // #nosec G117 -- domain field name, not a credential
	Scopes       []string
	ExpiresAt    time.Time
	CreatedAt    time.Time
}

type OIDCSession struct {
	AuthorizeCode string
	ClientID      uuid.UUID
	UserID        uuid.UUID
	Nonce         string
	AuthTime      time.Time
	Scopes        []string
	RequestedAt   time.Time
	CreatedAt     time.Time
}
