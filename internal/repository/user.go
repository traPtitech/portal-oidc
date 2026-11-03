package repository

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository/portal"
)

var ErrUserNotFound = errors.New("user not found")

type UserRepository interface {
	GetByID(context.Context, uuid.UUID) (*domain.User, error)
}
type userRepository struct{ queries *portal.Queries }

func NewUserRepository(q *portal.Queries) UserRepository { return &userRepository{q} }
func (r *userRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	u, err := r.queries.GetUserByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return &domain.User{ID: u.ID, TrapID: u.TrapID}, nil
}
