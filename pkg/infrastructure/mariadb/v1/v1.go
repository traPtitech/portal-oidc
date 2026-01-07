package v1

import (
	"database/sql"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
	mariadb "github.com/traPtitech/portal-oidc/pkg/infrastructure/mariadb/v1/gen"
)

type Repository struct {
	q *mariadb.Queries
}

func NewRepository(conf Config) (*Repository, error) {
	connStr := fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/%s?parseTime=true",
		conf.User,
		conf.Password,
		conf.Host,
		conf.Port,
		conf.Name,
	)

	db, err := sql.Open("mysql", connStr)
	if err != nil {
		return nil, err
	}

	return &Repository{
		q: mariadb.New(db),
	}, nil
}
