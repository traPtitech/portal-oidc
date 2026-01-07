package v1

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	postgres "github.com/traPtitech/portal-oidc/pkg/infrastructure/postgres/v1/gen"
)

type Repository struct {
	q *postgres.Queries
}

func NewRepository(conf Config) (*Repository, error) {
	connStr := fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=disable",
		conf.User,
		conf.Password,
		conf.Host,
		conf.Port,
		conf.Name,
	)

	pool, err := pgxpool.New(context.Background(), connStr)
	if err != nil {
		return nil, err
	}

	return &Repository{
		q: postgres.New(pool),
	}, nil
}
