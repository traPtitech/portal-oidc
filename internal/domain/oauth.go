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

// AccessToken mirrors traPortal v2 spec §access_tokens. JTI is the fosite
// signature used as the lookup key. UserID is optional because the
// client_credentials grant (future) issues subject-less tokens.
type AccessToken struct {
	ID        uuid.UUID
	JTI       string
	RequestID string
	ClientID  uuid.UUID
	UserID    *uuid.UUID
	Scopes    []string
	Audience  []string
	IssuedAt  time.Time
	ExpiresAt time.Time
	RevokedAt *time.Time
}

// RefreshToken mirrors spec §refresh_tokens. PreviousTokenID forms the
// rotation chain so OAuth 2.1 §4.13.2 family-revocation can be implemented
// when a leaked refresh token is detected.
type RefreshToken struct {
	ID              uuid.UUID
	TokenHash       string
	RequestID       string
	ClientID        uuid.UUID
	UserID          uuid.UUID
	Scopes          []string
	IssuedAt        time.Time
	ExpiresAt       time.Time
	RotatedAt       *time.Time
	PreviousTokenID *uuid.UUID
	RevokedAt       *time.Time
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
