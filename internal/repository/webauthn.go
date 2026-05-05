package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/sqlc-dev/pqtype"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository/oidc"
)

var (
	ErrWebAuthnCredentialNotFound = errors.New("webauthn credential not found")
	ErrWebAuthnChallengeNotFound  = errors.New("webauthn challenge not found")
)

type WebAuthnCredentialRepository interface {
	Create(ctx context.Context, cred domain.WebAuthnCredential) error
	GetByCredentialID(ctx context.Context, credentialID []byte) (domain.WebAuthnCredential, error)
	ListByUser(ctx context.Context, userID uuid.UUID) ([]domain.WebAuthnCredential, error)
	UpdateSignCount(ctx context.Context, id uuid.UUID, signCount uint32) error
	UpdateDeviceName(ctx context.Context, id, userID uuid.UUID, name string) error
	Delete(ctx context.Context, id, userID uuid.UUID) error
}

type webAuthnCredentialRepository struct {
	queries *oidc.Queries
}

func NewWebAuthnCredentialRepository(queries *oidc.Queries) WebAuthnCredentialRepository {
	return &webAuthnCredentialRepository{queries: queries}
}

func (r *webAuthnCredentialRepository) Create(ctx context.Context, c domain.WebAuthnCredential) error {
	id := c.ID
	if id == uuid.Nil {
		id = uuid.New()
	}
	transports := pqtype.NullRawMessage{}
	if len(c.Transports) > 0 {
		raw, err := json.Marshal(c.Transports)
		if err != nil {
			return err
		}
		transports = pqtype.NullRawMessage{RawMessage: raw, Valid: true}
	}
	return r.queries.CreateWebAuthnCredential(ctx, oidc.CreateWebAuthnCredentialParams{
		ID:           id,
		UserID:       c.UserID,
		CredentialID: c.CredentialID,
		PublicKey:    c.PublicKey,
		// #nosec G115 -- COSE algorithm identifiers (e.g. -7 ES256, -257 RS256) fit in int32
		PublicKeyAlg:      int32(c.PublicKeyAlg),
		AttestationFormat: nullString(c.AttestationFormat),
		Aaguid:            nullUUID(c.AAGUID),
		SignCount:         int64(c.SignCount),
		Transports:        transports,
		DeviceName:        nullString(c.DeviceName),
		BackedUp:          c.BackedUp,
	})
}

func (r *webAuthnCredentialRepository) GetByCredentialID(ctx context.Context, credentialID []byte) (domain.WebAuthnCredential, error) {
	row, err := r.queries.GetWebAuthnCredentialByCredentialID(ctx, credentialID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.WebAuthnCredential{}, ErrWebAuthnCredentialNotFound
		}
		return domain.WebAuthnCredential{}, err
	}
	return toDomainWebAuthnCredential(row)
}

func (r *webAuthnCredentialRepository) ListByUser(ctx context.Context, userID uuid.UUID) ([]domain.WebAuthnCredential, error) {
	rows, err := r.queries.ListWebAuthnCredentialsByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]domain.WebAuthnCredential, 0, len(rows))
	for _, row := range rows {
		c, err := toDomainWebAuthnCredential(row)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

func (r *webAuthnCredentialRepository) UpdateSignCount(ctx context.Context, id uuid.UUID, signCount uint32) error {
	return r.queries.UpdateWebAuthnCredentialSignCount(ctx, oidc.UpdateWebAuthnCredentialSignCountParams{
		ID:        id,
		SignCount: int64(signCount),
	})
}

func (r *webAuthnCredentialRepository) UpdateDeviceName(ctx context.Context, id, userID uuid.UUID, name string) error {
	return r.queries.UpdateWebAuthnCredentialDeviceName(ctx, oidc.UpdateWebAuthnCredentialDeviceNameParams{
		ID:         id,
		UserID:     userID,
		DeviceName: nullString(name),
	})
}

func (r *webAuthnCredentialRepository) Delete(ctx context.Context, id, userID uuid.UUID) error {
	return r.queries.DeleteWebAuthnCredential(ctx, oidc.DeleteWebAuthnCredentialParams{
		ID:     id,
		UserID: userID,
	})
}

func toDomainWebAuthnCredential(row oidc.WebauthnCredential) (domain.WebAuthnCredential, error) {
	var transports []string
	if row.Transports.Valid {
		if err := json.Unmarshal(row.Transports.RawMessage, &transports); err != nil {
			return domain.WebAuthnCredential{}, err
		}
	}
	var aaguid *uuid.UUID
	if row.Aaguid.Valid {
		id := row.Aaguid.UUID
		aaguid = &id
	}
	// W3C WebAuthn Level 3 §6.1.1 defines sign_count as a uint32. We persist
	// in BIGINT for headroom but clamp on the way back so an out-of-range row
	// (which shouldn't occur unless the column was hand-edited) cannot wrap
	// silently.
	signCount := row.SignCount
	if signCount < 0 {
		signCount = 0
	} else if signCount > int64(^uint32(0)) {
		signCount = int64(^uint32(0))
	}
	c := domain.WebAuthnCredential{
		ID:                row.ID,
		UserID:            row.UserID,
		CredentialID:      row.CredentialID,
		PublicKey:         row.PublicKey,
		PublicKeyAlg:      int(row.PublicKeyAlg),
		AttestationFormat: row.AttestationFormat.String,
		AAGUID:            aaguid,
		SignCount:         uint32(signCount), // bounded above
		Transports:        transports,
		DeviceName:        row.DeviceName.String,
		BackedUp:          row.BackedUp,
		CreatedAt:         row.CreatedAt,
	}
	if row.LastUsedAt.Valid {
		t := row.LastUsedAt.Time
		c.LastUsedAt = &t
	}
	return c, nil
}

type WebAuthnChallengeRepository interface {
	Create(ctx context.Context, ch domain.WebAuthnChallenge) error
	GetLatestForSession(ctx context.Context, sessionID string, t domain.WebAuthnChallengeType) (domain.WebAuthnChallenge, error)
	Delete(ctx context.Context, id uuid.UUID) error
	DeleteExpired(ctx context.Context) error
}

type webAuthnChallengeRepository struct {
	queries *oidc.Queries
}

func NewWebAuthnChallengeRepository(queries *oidc.Queries) WebAuthnChallengeRepository {
	return &webAuthnChallengeRepository{queries: queries}
}

func (r *webAuthnChallengeRepository) Create(ctx context.Context, ch domain.WebAuthnChallenge) error {
	id := ch.ID
	if id == uuid.Nil {
		id = uuid.New()
	}
	return r.queries.CreateWebAuthnChallenge(ctx, oidc.CreateWebAuthnChallengeParams{
		ID:        id,
		Challenge: ch.Challenge,
		UserID:    nullUUID(ch.UserID),
		SessionID: nullString(ch.SessionID),
		Type:      string(ch.Type),
		Data:      ch.Data,
		ExpiresAt: ch.ExpiresAt,
	})
}

func (r *webAuthnChallengeRepository) GetLatestForSession(ctx context.Context, sessionID string, t domain.WebAuthnChallengeType) (domain.WebAuthnChallenge, error) {
	row, err := r.queries.GetWebAuthnChallengeBySessionID(ctx, oidc.GetWebAuthnChallengeBySessionIDParams{
		SessionID: nullString(sessionID),
		Type:      string(t),
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.WebAuthnChallenge{}, ErrWebAuthnChallengeNotFound
		}
		return domain.WebAuthnChallenge{}, err
	}
	return toDomainWebAuthnChallenge(row), nil
}

func (r *webAuthnChallengeRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.queries.DeleteWebAuthnChallenge(ctx, id)
}

func (r *webAuthnChallengeRepository) DeleteExpired(ctx context.Context) error {
	return r.queries.DeleteExpiredWebAuthnChallenges(ctx)
}

func toDomainWebAuthnChallenge(row oidc.WebauthnChallenge) domain.WebAuthnChallenge {
	ch := domain.WebAuthnChallenge{
		ID:        row.ID,
		Challenge: row.Challenge,
		SessionID: row.SessionID.String,
		Type:      domain.WebAuthnChallengeType(row.Type),
		Data:      row.Data,
		ExpiresAt: row.ExpiresAt,
		CreatedAt: row.CreatedAt,
	}
	if row.UserID.Valid {
		id := row.UserID.UUID
		ch.UserID = &id
	}
	return ch
}
