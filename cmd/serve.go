package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"

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

	var userUseCase usecase.UserUseCase
	if cfg.Environment == "production" {
		portalQueries, portalErr := setupPortalDatabase(cfg.Portal.Database)
		if portalErr != nil {
			return nil, portalErr
		}
		userUseCase = usecase.NewUserUseCase(repository.NewUserRepository(portalQueries))
	}
	handler := v1.NewHandler(
		usecase.NewClientUseCase(clientRepo),
		usecase.NewOAuthUseCase(oauth2Provider, oauthStorage),
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
	registerMiddleware(e)
	gen.RegisterHandlers(e, handler)
	e.GET("/login", handler.GetLogin)
	e.POST("/login", handler.PostLogin)
	e.GET("/logout", handler.Logout)
	e.GET("/health", func(c *echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})

	return e, nil
}

func registerMiddleware(e *echo.Echo) {
	e.Use(middleware.Recover())
	e.Use(middleware.RequestID())
	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogMethod:    true,
		LogURIPath:   true,
		LogStatus:    true,
		LogLatency:   true,
		LogRemoteIP:  true,
		LogRequestID: true,
		LogValuesFunc: func(_ *echo.Context, v middleware.RequestLoggerValues) error {
			level := slog.LevelInfo
			switch {
			case v.Status >= 500:
				level = slog.LevelError
			case v.Status >= 400:
				level = slog.LevelWarn
			}
			slog.LogAttrs(context.Background(), level, "http_request",
				slog.String("request_id", v.RequestID),
				slog.String("method", v.Method),
				slog.String("path", v.URIPath),
				slog.Int("status", v.Status),
				slog.Duration("latency", v.Latency),
				slog.String("remote_ip", v.RemoteIP),
			)
			return nil
		},
	}))
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowHeaders: []string{"*"},
		AllowMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
	}))
}

func postgresDSN(cfg DatabaseConfig) string {
	sslMode := cfg.SSLMode
	if sslMode == "" {
		sslMode = "disable"
	}
	u := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(cfg.User, cfg.Password),
		Host:   net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)),
		Path:   "/" + cfg.Name,
	}
	q := u.Query()
	q.Set("sslmode", sslMode)
	u.RawQuery = q.Encode()
	return u.String()
}

func setupOIDCDatabase(cfg DatabaseConfig) (*sql.DB, *oidc.Queries, error) {
	db, err := sql.Open("pgx", postgresDSN(cfg))
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
	db, err := sql.Open("pgx", postgresDSN(cfg))
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
