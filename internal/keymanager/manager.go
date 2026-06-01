// Package keymanager owns the lifecycle of JWT signing keys.
//
// The DB-backed signing_keys table is the source of truth (see
// traPortal v2 spec §signing_keys). On startup the manager ensures at least
// one ACTIVE key exists, generating one if the table is empty. Token issuance
// uses ActiveKey(); JWKS exposes every PublishableKey so previously-issued
// tokens remain verifiable across rotations.
package keymanager

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"

	"github.com/google/uuid"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository"
)

const (
	defaultAlgorithm = "RS256"
	rsaKeyBits       = 2048
)

// PublicKeyView is a serialisation-friendly snapshot for JWKS rendering.
// Holding the parsed public key avoids re-decoding the PEM on every request.
type PublicKeyView struct {
	KID       string
	Algorithm string
	Use       domain.SigningKeyUse
	PublicKey *rsa.PublicKey
}

// Manager wraps a SigningKeyRepository to provide the policy layer
// ("which key signs?", "which keys verify?") on top of pure storage.
type Manager struct {
	repo repository.SigningKeyRepository

	mu        sync.RWMutex
	activeKey *signedKey
}

type signedKey struct {
	id         uuid.UUID
	kid        string
	algorithm  string
	privateKey *rsa.PrivateKey
}

func New(repo repository.SigningKeyRepository) *Manager {
	return &Manager{repo: repo}
}

// EnsureActiveKey loads the current active key from storage and parses it. If
// no active key exists, a fresh RSA-2048 / RS256 key is generated and
// persisted with status=active. Idempotent across restarts.
func (m *Manager) EnsureActiveKey(ctx context.Context) error {
	key, err := m.repo.GetActive(ctx)
	if err != nil && !errors.Is(err, repository.ErrSigningKeyNotFound) {
		return fmt.Errorf("load active signing key: %w", err)
	}
	if errors.Is(err, repository.ErrSigningKeyNotFound) {
		key, err = generateAndPersist(ctx, m.repo)
		if err != nil {
			return err
		}
	}

	priv, err := decodePrivateKey(key.PrivateKeyPEM)
	if err != nil {
		return fmt.Errorf("decode active signing key: %w", err)
	}

	m.mu.Lock()
	m.activeKey = &signedKey{
		id:         key.ID,
		kid:        key.KID,
		algorithm:  key.Algorithm,
		privateKey: priv,
	}
	m.mu.Unlock()
	return nil
}

// ActiveKey returns the parsed private key currently used to sign new tokens.
func (m *Manager) ActiveKey() (*rsa.PrivateKey, string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.activeKey == nil {
		return nil, "", errors.New("no active signing key")
	}
	return m.activeKey.privateKey, m.activeKey.kid, nil
}

// PublishableKeys returns every key that should appear in JWKS (active +
// rotated). The result is freshly read from storage so admin rotations show
// up without process restart.
func (m *Manager) PublishableKeys(ctx context.Context) ([]PublicKeyView, error) {
	keys, err := m.repo.ListPublishable(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]PublicKeyView, 0, len(keys))
	for _, k := range keys {
		pub, err := decodePublicKey(k.PublicKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("decode public key %s: %w", k.KID, err)
		}
		out = append(out, PublicKeyView{
			KID:       k.KID,
			Algorithm: k.Algorithm,
			Use:       k.Use,
			PublicKey: pub,
		})
	}
	return out, nil
}

// Rotate marks the current active key as rotated and provisions a new one.
// Old tokens stay verifiable until their natural expiry; new tokens use the
// fresh key.
func (m *Manager) Rotate(ctx context.Context) error {
	current, err := m.repo.GetActive(ctx)
	if err == nil {
		if err := m.repo.MarkRotated(ctx, current.ID); err != nil {
			return fmt.Errorf("mark current key rotated: %w", err)
		}
	} else if !errors.Is(err, repository.ErrSigningKeyNotFound) {
		return err
	}
	if _, err := generateAndPersist(ctx, m.repo); err != nil {
		return err
	}
	return m.EnsureActiveKey(ctx)
}

func generateAndPersist(ctx context.Context, repo repository.SigningKeyRepository) (domain.SigningKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return domain.SigningKey{}, fmt.Errorf("generate RSA key: %w", err)
	}
	kid := computeKID(&priv.PublicKey)
	pubPEM, err := encodePublicKey(&priv.PublicKey)
	if err != nil {
		return domain.SigningKey{}, err
	}
	privPEM := encodePrivateKey(priv)

	key := domain.SigningKey{
		ID:            uuid.New(),
		KID:           kid,
		Algorithm:     defaultAlgorithm,
		Use:           domain.SigningKeyUseSig,
		Status:        domain.SigningKeyStatusActive,
		PublicKeyPEM:  pubPEM,
		PrivateKeyPEM: privPEM,
	}
	if err := repo.Create(ctx, key); err != nil {
		return domain.SigningKey{}, fmt.Errorf("persist signing key: %w", err)
	}
	return key, nil
}

// computeKID is a deterministic key-id derived from the RSA modulus. Same
// scheme the previous PEM-only handler used, so JWKS clients keep observing
// the same kid for the same key material.
func computeKID(pub *rsa.PublicKey) string {
	hash := sha256.Sum256(pub.N.Bytes())
	return base64.RawURLEncoding.EncodeToString(hash[:8])
}

func encodePrivateKey(priv *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}))
}

func encodePublicKey(pub *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})), nil
}

func decodePrivateKey(p string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(p))
	if block == nil {
		return nil, errors.New("invalid private key PEM")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("private key is not RSA")
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported PEM type: %s", block.Type)
	}
}

func decodePublicKey(p string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(p))
	if block == nil {
		return nil, errors.New("invalid public key PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not RSA")
	}
	return pub, nil
}
