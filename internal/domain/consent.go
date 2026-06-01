package domain

import (
	"time"

	"github.com/google/uuid"
)

// UserConsent records the OAuth scopes a user has granted to a particular
// client. There is at most one row per (UserID, ClientID); a fresh grant
// replaces the prior scope set.
type UserConsent struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	ClientID  uuid.UUID
	Scopes    []string
	GrantedAt time.Time
	ExpiresAt *time.Time
	RevokedAt *time.Time
}

// IsActive reports whether the consent should still be honoured. A consent is
// inactive once revoked or after its expiry (when set).
func (c UserConsent) IsActive(now time.Time) bool {
	if c.RevokedAt != nil {
		return false
	}
	if c.ExpiresAt != nil && !now.Before(*c.ExpiresAt) {
		return false
	}
	return true
}

// Covers returns true when every scope in needed is contained in the
// consent's scope set. Used to decide whether to skip the consent screen on a
// repeat authorization.
func (c UserConsent) Covers(needed []string) bool {
	have := make(map[string]struct{}, len(c.Scopes))
	for _, s := range c.Scopes {
		have[s] = struct{}{}
	}
	for _, s := range needed {
		if _, ok := have[s]; !ok {
			return false
		}
	}
	return true
}
