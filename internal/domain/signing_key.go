package domain

import (
	"time"

	"github.com/google/uuid"
)

// SigningKeyStatus represents the lifecycle position of a JWT signing key.
//
//   - active:  newly issued tokens are signed with this key
//   - rotated: still published in JWKS so tokens issued before rotation remain
//     verifiable, but new tokens are signed with the active key
//   - revoked: removed from JWKS; verifications fail
type SigningKeyStatus string

const (
	SigningKeyStatusActive  SigningKeyStatus = "active"
	SigningKeyStatusRotated SigningKeyStatus = "rotated"
	SigningKeyStatusRevoked SigningKeyStatus = "revoked"
)

// SigningKeyUse mirrors RFC 7517 §4.2 ("use" parameter).
type SigningKeyUse string

const (
	SigningKeyUseSig SigningKeyUse = "sig"
	SigningKeyUseEnc SigningKeyUse = "enc"
)

// SigningKey is the persistent form of a JWT signing key. PrivateKeyPEM and
// PublicKeyPEM hold PEM-encoded RSA material; rotation is driven by Status
// transitions (active → rotated → revoked) rather than deletion so already-
// issued tokens keep verifying.
type SigningKey struct {
	ID            uuid.UUID
	KID           string
	Algorithm     string // RS256, ES256, ...
	Use           SigningKeyUse
	Status        SigningKeyStatus
	PublicKeyPEM  string
	PrivateKeyPEM string
	ExpiresAt     *time.Time
	RotatedAt     *time.Time
	CreatedAt     time.Time
}
