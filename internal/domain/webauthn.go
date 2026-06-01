package domain

import (
	"time"

	"github.com/google/uuid"
)

// WebAuthnCredential is one registered authenticator (security key, Passkey)
// belonging to a user. CredentialID is the rawId returned by the
// authenticator and is the lookup key on subsequent assertions. PublicKey is
// stored COSE-encoded so the WebAuthn library can re-parse it verbatim at
// sign-in time.
type WebAuthnCredential struct {
	ID                uuid.UUID
	UserID            uuid.UUID
	CredentialID      []byte
	PublicKey         []byte // COSE-encoded
	PublicKeyAlg      int    // COSE algorithm identifier (e.g. -7 ES256, -257 RS256)
	AttestationFormat string // "packed" / "tpm" / "none" / ...
	AAGUID            *uuid.UUID
	SignCount         uint32
	Transports        []string // "usb" / "nfc" / "ble" / "internal" / "hybrid"
	DeviceName        string   // user-supplied nickname
	BackedUp          bool     // Passkey synced across devices
	CreatedAt         time.Time
	LastUsedAt        *time.Time
}

// WebAuthnChallengeType identifies whether a stored challenge is for the
// registration ceremony or the assertion (authentication) ceremony.
type WebAuthnChallengeType string

const (
	WebAuthnChallengeRegister     WebAuthnChallengeType = "register"
	WebAuthnChallengeAuthenticate WebAuthnChallengeType = "authenticate"
)

// WebAuthnChallenge captures the per-ceremony state the WebAuthn library
// needs to validate the response. Data holds the JSON-encoded SessionData
// from go-webauthn so we can replay it on the verify step.
type WebAuthnChallenge struct {
	ID        uuid.UUID
	Challenge []byte
	UserID    *uuid.UUID
	SessionID string
	Type      WebAuthnChallengeType
	Data      []byte // raw JSON: webauthn.SessionData
	ExpiresAt time.Time
	CreatedAt time.Time
}
