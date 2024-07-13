package v1

import (
	"database/sql"
	"strconv"

	"github.com/go-sql-driver/mysql"
)

type MariaDBRepository struct {
	db *sql.DB
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
		db: db,
	}, nil
}
