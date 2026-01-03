package v1

import (
	"database/sql"
	"strconv"

	"github.com/go-sql-driver/mysql"
	"github.com/traPtitech/portal-oidc/pkg/domain/portal"
	"github.com/traPtitech/portal-oidc/pkg/domain/rs"
	portalgen "github.com/traPtitech/portal-oidc/pkg/infrastructure/portal/v1/gen"
)

type Portal struct {
	q *portalgen.Queries
}

var _ rs.ResourceServer = (*Portal)(nil)
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
