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
	"github.com/traPtitech/portal-oidc/internal/repository/oauth"
	"github.com/traPtitech/portal-oidc/internal/repository/oidc"
	"github.com/traPtitech/portal-oidc/internal/repository/portal"
	v1 "github.com/traPtitech/portal-oidc/internal/router/v1"
	"github.com/traPtitech/portal-oidc/internal/router/v1/gen"
	"github.com/traPtitech/portal-oidc/internal/usecase"
)

func newServer(cfg Config) (http.Handler, error) {
	oidcDB, queries, err := setupOIDCDatabase(cfg.Database)
	if err != nil {
		return nil, err
	}

	portalQueries, err := setupPortalDatabase(cfg.Portal.Database)
	if err != nil {
		return nil, err
	}

	privateKey, err := loadOrGenerateKey(cfg.OAuth.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load/generate RSA key: %w", err)
	}

	clientRepo := repository.NewClientRepository(queries)
	oauthStorage := oauth.NewStorage(
		oidcDB,
		queries,
		clientRepo,
		repository.NewAuthCodeRepository(queries),
		repository.NewTokenRepository(queries),
		repository.NewOIDCSessionRepository(queries),
	)
	defaults := defaultOAuthProviderConfig()
	oauth2Provider := newOAuthProvider(oauthStorage, OAuthProviderConfig{
		Issuer:               cfg.Host,
		AccessTokenLifespan:  defaults.AccessTokenLifespan,
		RefreshTokenLifespan: defaults.RefreshTokenLifespan,
		AuthCodeLifespan:     defaults.AuthCodeLifespan,
		IDTokenLifespan:      defaults.IDTokenLifespan,
		Secret:               []byte(cfg.OAuth.Secret),
	}, privateKey)

	userUseCase := usecase.NewUserUseCase(repository.NewUserRepository(portalQueries))
	handler := v1.NewHandler(
		usecase.NewClientUseCase(clientRepo),
		oauth2Provider,
		userUseCase,
		v1.OAuthConfig{
			Issuer:        cfg.Host,
			SessionSecret: []byte(cfg.OAuth.Secret),
			PrivateKey:    privateKey,
			Environment:   cfg.Environment,
			TestUserID:    cfg.OAuth.TestUserID,
		},
	)

	e := echo.New()
	e.Use(middleware.Recover())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowHeaders: []string{"*"},
		AllowMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
	}))
	gen.RegisterHandlers(e, handler)
	e.POST("/oauth2/authorize", func(c echo.Context) error {
		return handler.Authorize(c, gen.AuthorizeParams{})
	})
	e.GET("/login", handler.GetLogin)
	e.POST("/login", handler.PostLogin)
	e.GET("/logout", handler.Logout)
	e.GET("/health", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})

	return e, nil
}

func setupOIDCDatabase(cfg DatabaseConfig) (*sql.DB, *oidc.Queries, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true",
		cfg.User, cfg.Password, cfg.Host, cfg.Port, cfg.Name)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open oidc database: %w", err)
	}

	if err := db.PingContext(context.Background()); err != nil {
		return nil, nil, fmt.Errorf("failed to ping oidc database: %w", err)
	}

	queries, err := oidc.Prepare(context.Background(), db)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to prepare oidc queries: %w", err)
	}

	return db, queries, nil
}

func setupPortalDatabase(cfg DatabaseConfig) (*portal.Queries, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true",
		cfg.User, cfg.Password, cfg.Host, cfg.Port, cfg.Name)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open portal database: %w", err)
	}

	if err := db.PingContext(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to ping portal database: %w", err)
	}

	queries, err := portal.Prepare(context.Background(), db)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare portal queries: %w", err)
	}

	return queries, nil
}
