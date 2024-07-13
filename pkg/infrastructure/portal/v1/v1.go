package v1

import (
	"database/sql"
	"strconv"

	"github.com/go-sql-driver/mysql"
	"github.com/traPtitech/portal-oidc/pkg/domain/portal"
	"github.com/traPtitech/portal-oidc/pkg/domain/rs"
)

type Portal struct {
	db *sql.DB
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

	return &Portal{db: db}, nil

}
