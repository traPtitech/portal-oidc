package portal

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/traPtitech/portal-oidc/pkg/domain/portal"
	portalgen "github.com/traPtitech/portal-oidc/pkg/infrastructure/portal/gen"
)

type Portal struct {
	q *portalgen.Queries
}

var _ portal.Portal = (*Portal)(nil)

func NewPortal(conf Config) (*Portal, error) {
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

	return &Portal{q: portalgen.New(pool)}, nil
}
