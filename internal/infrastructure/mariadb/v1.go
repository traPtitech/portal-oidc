package mariadb

import (
	"database/sql"
	"strconv"

	"github.com/go-sql-driver/mysql"
	mariadb "github.com/traPtitech/portal-oidc/internal/infrastructure/mariadb/gen"
)

type MariaDBRepository struct {
	q *mariadb.Queries
}

func NewRepository(conf Config) (*MariaDBRepository, error) {
	mycnf := mysql.Config{
		User:                 conf.User,
		Passwd:               conf.Password,
		Net:                  "tcp",
		Addr:                 conf.Host + ":" + strconv.Itoa(conf.Port),
		DBName:               conf.Name,
		AllowNativePasswords: true,
		ParseTime:            true,
	}

	db, err := sql.Open("mysql", mycnf.FormatDSN())
	if err != nil {
		return nil, err
	}

	return &MariaDBRepository{
		q: mariadb.New(db),
	}, nil
}
