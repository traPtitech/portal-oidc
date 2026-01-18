package server

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
	"github.com/labstack/echo/v4"
	"github.com/rs/cors"

	v1 "github.com/traPtitech/portal-oidc/internal/adapter/handler/v1"
	"github.com/traPtitech/portal-oidc/internal/adapter/handler/v1/gen"
	oidcgen "github.com/traPtitech/portal-oidc/internal/infrastructure/oidc/gen"
	"github.com/traPtitech/portal-oidc/internal/repository"
	"github.com/traPtitech/portal-oidc/internal/usecase"
)

type Config struct {
	Host     string         `koanf:"host"`
	Database DatabaseConfig `koanf:"database"`
}

type DatabaseConfig struct {
	Host     string `koanf:"host"`
	Port     int    `koanf:"port"`
	User     string `koanf:"user"`
	Password string `koanf:"password"`
	Name     string `koanf:"name"`
}

func NewServer(cfg Config) (http.Handler, error) {
	db, err := sql.Open("mysql", fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/%s?parseTime=true",
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.Name,
	))
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	queries, err := oidcgen.Prepare(context.Background(), db)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare queries: %w", err)
	}

	clientRepo := repository.NewClientRepository(queries)
	clientUseCase := usecase.NewClientUseCase(clientRepo)
	handler := v1.NewHandler(clientUseCase)

	e := echo.New()
	gen.RegisterHandlers(e, handler)

	return cors.New(cors.Options{
		AllowOriginFunc: func(origin string) bool {
			return true
		},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
	}).Handler(e), nil
}
