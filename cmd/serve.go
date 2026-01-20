package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"github.com/traPtitech/portal-oidc/internal/repository/oidc"
	v1 "github.com/traPtitech/portal-oidc/internal/router/v1"
	"github.com/traPtitech/portal-oidc/internal/router/v1/gen"
)

func newServer(cfg Config) (http.Handler, error) {
	queries, err := setupDatabase(cfg.Database)
	if err != nil {
		return nil, err
	}

	handler := v1.NewHandler(queries)
	strictHandler := gen.NewStrictHandler(handler, nil)

	e := echo.New()
	e.Use(middleware.Recover())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowHeaders: []string{"*"},
		AllowMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
	}))

	gen.RegisterHandlers(e, strictHandler)

	e.GET("/health", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})

	return e, nil
}

func setupDatabase(cfg DatabaseConfig) (*oidc.Queries, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true",
		cfg.User, cfg.Password, cfg.Host, cfg.Port, cfg.Name)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.PingContext(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	queries, err := oidc.Prepare(context.Background(), db)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare queries: %w", err)
	}

	return queries, nil
}
