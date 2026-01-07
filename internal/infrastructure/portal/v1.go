package portal

import (
	"database/sql"
	"strconv"

	"github.com/go-sql-driver/mysql"
	"github.com/traPtitech/portal-oidc/internal/domain/portal"
	portalgen "github.com/traPtitech/portal-oidc/internal/infrastructure/portal/gen"
)

type Portal struct {
	q *portalgen.Queries
}

var _ portal.Portal = (*Portal)(nil)

func NewPortal(conf Config) (*Portal, error) {
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

	return &Portal{q: portalgen.New(db)}, nil
}
