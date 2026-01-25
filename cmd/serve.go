package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"github.com/traPtitech/portal-oidc/internal/repository"
	"github.com/traPtitech/portal-oidc/internal/repository/oidc"
	v1 "github.com/traPtitech/portal-oidc/internal/router/v1"
	"github.com/traPtitech/portal-oidc/internal/router/v1/gen"
	"github.com/traPtitech/portal-oidc/internal/usecase"
)

func newServer(cfg Config) (http.Handler, error) {
	queries, err := setupDatabase(cfg.Database)
	if err != nil {
		return nil, err
	}

	privateKey, err := loadOrGenerateKey(cfg.OAuth.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load/generate RSA key: %w", err)
	}

	oauthStorage := repository.NewOAuthStorage(queries)
	defaults := defaultOAuthProviderConfig()
	oauth2Provider := newOAuthProvider(oauthStorage, OAuthProviderConfig{
		Issuer:               cfg.Host,
		AccessTokenLifespan:  defaults.AccessTokenLifespan,
		RefreshTokenLifespan: defaults.RefreshTokenLifespan,
		AuthCodeLifespan:     defaults.AuthCodeLifespan,
		IDTokenLifespan:      defaults.IDTokenLifespan,
		Secret:               []byte(cfg.OAuth.Secret),
	}, privateKey)

	handler := v1.NewHandler(
		usecase.NewClientUseCase(repository.NewClientRepository(queries)),
		oauth2Provider,
		v1.OAuthConfig{
			Issuer:        cfg.Host,
			SessionSecret: []byte(cfg.OAuth.Secret),
			PrivateKey:    privateKey,
			Environment:   cfg.Environment,
			TestUserID:    cfg.OAuth.TestUserID,
		},
	)

	e := echo.New()
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowHeaders: []string{"*"},
		AllowMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
	}))
	gen.RegisterHandlers(e, handler)
	e.GET("/login", handler.GetLogin)
	e.POST("/login", handler.PostLogin)
	e.GET("/logout", handler.Logout)

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
