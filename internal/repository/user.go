package repository

import (
	"context"
	"database/sql"
	"errors"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository/portal"
)

var ErrUserNotFound = errors.New("user not found")

type UserRepository interface {
	GetByID(ctx context.Context, id string) (*domain.User, error)
	GetByTrapID(ctx context.Context, trapID string) (*domain.UserWithPassword, error)
	ListStatuses(ctx context.Context, userID string) ([]string, error)
}

type userRepository struct {
	queries *portal.Queries
}

func NewUserRepository(queries *portal.Queries) UserRepository {
	return &userRepository{queries: queries}
}

func (r *userRepository) GetByID(ctx context.Context, id string) (*domain.User, error) {
	user, err := r.queries.GetUserByID(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	return &domain.User{
		ID:     user.ID,
		TrapID: user.TrapID,
	}, nil
}

func (r *userRepository) GetByTrapID(ctx context.Context, trapID string) (*domain.UserWithPassword, error) {
	user, err := r.queries.GetUserByTrapID(ctx, trapID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	return &domain.UserWithPassword{
		User: domain.User{
			ID:     user.ID,
			TrapID: user.TrapID,
		},
		PasswordHash: user.PasswordHash,
	}, nil
}

func (r *userRepository) ListStatuses(ctx context.Context, userID string) ([]string, error) {
	statuses, err := r.queries.ListUserStatuses(ctx, userID)
	if err != nil {
		return nil, err
	}

	result := make([]string, len(statuses))
	for i, s := range statuses {
		result[i] = s.Status
	}
	return result, nil
}
