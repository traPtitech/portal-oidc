package repository

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/google/uuid"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository/oidc"
)

var ErrDeviceAuthorizationNotFound = errors.New("device authorization not found")

type DeviceAuthorizationRepository interface {
	Create(ctx context.Context, d domain.DeviceAuthorization) error
	GetByDeviceCode(ctx context.Context, deviceCode string) (domain.DeviceAuthorization, error)
	GetByUserCode(ctx context.Context, userCode string) (domain.DeviceAuthorization, error)
	Approve(ctx context.Context, id, userID uuid.UUID) error
	Deny(ctx context.Context, id uuid.UUID) error
	Touch(ctx context.Context, deviceCode string) error
	ExpirePending(ctx context.Context) error
}

type deviceAuthorizationRepository struct {
	queries *oidc.Queries
}

func NewDeviceAuthorizationRepository(queries *oidc.Queries) DeviceAuthorizationRepository {
	return &deviceAuthorizationRepository{queries: queries}
}

func (r *deviceAuthorizationRepository) Create(ctx context.Context, d domain.DeviceAuthorization) error {
	id := d.ID
	if id == uuid.Nil {
		id = uuid.New()
	}
	return r.queries.CreateDeviceAuthorization(ctx, oidc.CreateDeviceAuthorizationParams{
		ID:         id,
		DeviceCode: d.DeviceCode,
		UserCode:   d.UserCode,
		ClientID:   d.ClientID,
		Scopes:     strings.Join(d.Scopes, " "),
		ExpiresAt:  d.ExpiresAt,
		// #nosec G115 -- poll intervals are seconds and fit in int32
		PollInterval: int32(d.PollInterval),
	})
}

func (r *deviceAuthorizationRepository) GetByDeviceCode(ctx context.Context, deviceCode string) (domain.DeviceAuthorization, error) {
	row, err := r.queries.GetDeviceAuthorizationByDeviceCode(ctx, deviceCode)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.DeviceAuthorization{}, ErrDeviceAuthorizationNotFound
		}
		return domain.DeviceAuthorization{}, err
	}
	return toDomainDeviceAuthorization(row), nil
}

func (r *deviceAuthorizationRepository) GetByUserCode(ctx context.Context, userCode string) (domain.DeviceAuthorization, error) {
	row, err := r.queries.GetDeviceAuthorizationByUserCode(ctx, userCode)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.DeviceAuthorization{}, ErrDeviceAuthorizationNotFound
		}
		return domain.DeviceAuthorization{}, err
	}
	return toDomainDeviceAuthorization(row), nil
}

func (r *deviceAuthorizationRepository) Approve(ctx context.Context, id, userID uuid.UUID) error {
	return r.queries.ApproveDeviceAuthorization(ctx, oidc.ApproveDeviceAuthorizationParams{
		ID:     id,
		UserID: uuid.NullUUID{UUID: userID, Valid: true},
	})
}

func (r *deviceAuthorizationRepository) Deny(ctx context.Context, id uuid.UUID) error {
	return r.queries.DenyDeviceAuthorization(ctx, id)
}

func (r *deviceAuthorizationRepository) Touch(ctx context.Context, deviceCode string) error {
	return r.queries.TouchDeviceAuthorization(ctx, deviceCode)
}

func (r *deviceAuthorizationRepository) ExpirePending(ctx context.Context) error {
	return r.queries.ExpireDeviceAuthorizations(ctx)
}

func toDomainDeviceAuthorization(row oidc.DeviceAuthorization) domain.DeviceAuthorization {
	d := domain.DeviceAuthorization{
		ID:           row.ID,
		DeviceCode:   row.DeviceCode,
		UserCode:     row.UserCode,
		ClientID:     row.ClientID,
		Scopes:       splitScopes(row.Scopes),
		Status:       domain.DeviceAuthorizationStatus(row.Status),
		ExpiresAt:    row.ExpiresAt,
		PollInterval: int(row.PollInterval),
		CreatedAt:    row.CreatedAt,
	}
	if row.UserID.Valid {
		id := row.UserID.UUID
		d.UserID = &id
	}
	if row.LastPolledAt.Valid {
		d.LastPolledAt = &row.LastPolledAt.Time
	}
	if row.AuthorizedAt.Valid {
		d.AuthorizedAt = &row.AuthorizedAt.Time
	}
	return d
}
