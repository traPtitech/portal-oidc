package domain

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

var ErrInvalidAccount = errors.New("invalid account")

var trapIDPattern = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9_-]{0,30}[a-zA-Z0-9])?$`)

func ValidTrapID(id string) bool { return trapIDPattern.MatchString(id) }

type KDFParams struct {
	Kdf        string `json:"kdf"`
	Version    int    `json:"version"`
	Iterations int    `json:"iterations"`
}

func CurrentKDFPolicy() KDFParams {
	return KDFParams{Kdf: "pbkdf2-sha256", Version: 1, Iterations: 100000}
}

type AuthVerifier struct {
	Version int       `json:"version"`
	Alg     string    `json:"alg"`
	Params  KDFParams `json:"params"`
	Hash    string    `json:"hash"`
}

func DecodeSecret(value string) ([]byte, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != value {
		return nil, ErrInvalidAccount
	}
	return b, nil
}
func (v AuthVerifier) Validate() error {
	if v.Version != 1 || v.Alg != "pbkdf2-sha256-verifier-v1" || v.Params != CurrentKDFPolicy() {
		return ErrInvalidAccount
	}
	_, err := DecodeSecret(v.Hash)
	return err
}

type Account struct {
	UserID        uuid.UUID    `json:"userId"`
	TrapID        string       `json:"trapId"`
	Email         string       `json:"email"`
	EmailVerified bool         `json:"emailVerified"`
	AuthVerifier  AuthVerifier `json:"authVerifier"`
	ExpiresAt     time.Time    `json:"expiresAt"`
}

func NormalizeEmail(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
func (a Account) Validate() error {
	at := strings.IndexByte(a.Email, '@')
	if a.UserID == uuid.Nil || !ValidTrapID(a.TrapID) || len(a.Email) > 254 || at <= 0 || at == len(a.Email)-1 || !a.ExpiresAt.After(time.Now()) {
		return ErrInvalidAccount
	}
	return a.AuthVerifier.Validate()
}
func (a Account) Fingerprint() ([32]byte, error) {
	a.Email = NormalizeEmail(a.Email)
	a.ExpiresAt = a.ExpiresAt.UTC()
	b, err := json.Marshal(a)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}
