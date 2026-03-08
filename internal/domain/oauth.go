package domain

import "time"

type AuthCode struct {
	Code                string
	ClientID            string
	UserID              string
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
	ID           string
	RequestID    string
	ClientID     string
	UserID       string
	AccessToken  string // #nosec G117 -- domain field name, not a credential
	RefreshToken string // #nosec G117 -- domain field name, not a credential
	Scopes       []string
	ExpiresAt    time.Time
	CreatedAt    time.Time
}

type OIDCSession struct {
	AuthorizeCode string
	ClientID      string
	UserID        string
	Nonce         string
	AuthTime      time.Time
	Scopes        []string
	RequestedAt   time.Time
	CreatedAt     time.Time
}
