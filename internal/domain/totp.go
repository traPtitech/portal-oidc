package domain

import (
	"time"

	"github.com/google/uuid"
)

// TOTPCredential is a user's TOTP shared secret. Enabled flips to true only
// once the user has typed back a valid code during enrolment, so a partial
// enrolment never gates login (RFC 6238 §3 implies the verifier must validate
// at least one OTP before trusting the seed).
type TOTPCredential struct {
	UserID     uuid.UUID
	Secret     string
	Enabled    bool
	CreatedAt  time.Time
	LastUsedAt *time.Time
}
