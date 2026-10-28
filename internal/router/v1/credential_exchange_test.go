package v1

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository"
	"github.com/traPtitech/portal-oidc/internal/repository/oauth"
	"github.com/traPtitech/portal-oidc/internal/repository/oidc"
)

// consumeErrors are the errors a credential exchange reports when a
// concurrent exchange already redeemed its credential.
var consumeErrors = map[string]error{
	"authorization_code": fosite.ErrInvalidatedAuthorizeCode,
	"refresh_token":      fosite.ErrSerializationFailure,
}

func TestConcurrentCredentialExchangeConsumesOnce(t *testing.T) {
	for grantType, wantErr := range consumeErrors {
		t.Run(grantType, func(t *testing.T) {
			storage, _, consume := setupClientCredentialExchange(t, grantType)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			firstCtx, err := storage.BeginTX(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer storage.Rollback(firstCtx)
			if err := consume(firstCtx); err != nil {
				t.Fatal(err)
			}

			secondCtx, err := storage.BeginTX(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer storage.Rollback(secondCtx)
			consumed := make(chan error, 1)
			go func() { consumed <- consume(secondCtx) }()
			waitForDatabaseLock(t, ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock')`, consumed)
			if err := storage.Commit(firstCtx); err != nil {
				t.Fatal(err)
			}
			if err := <-consumed; !errors.Is(err, wantErr) {
				t.Fatalf("second consumption = %v, want %v", err, wantErr)
			}
		})
	}
}

func setupClientCredentialExchange(t *testing.T, grantType string) (*oauth.Storage, fosite.Requester, func(context.Context) error) {
	t.Helper()
	ctx := t.Context()
	clients := repository.NewClientRepository(oidc.New(testDB))
	client := &domain.Client{ClientID: uuid.New(), Name: "credential exchange", ClientType: domain.ClientTypeConfidential, RedirectURIs: []string{"https://example.com/callback"}}
	if err := clients.Create(ctx, client, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := clients.Delete(context.WithoutCancel(ctx), client.ClientID); err != nil {
			t.Error(err)
		}
	})
	queries, err := oidc.Prepare(ctx, testDB)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = queries.Close() })
	storage := oauth.NewStorage(testDB, queries, clients, repository.NewAuthCodeRepository(queries), repository.NewTokenRepository(queries), repository.NewOIDCSessionRepository(queries))
	session := oauth.NewSession(uuid.NewString(), time.Now())
	for _, tokenType := range []fosite.TokenType{fosite.AuthorizeCode, fosite.AccessToken, fosite.RefreshToken} {
		session.SetExpiresAt(tokenType, time.Now().Add(time.Hour))
	}
	request := &fosite.Request{
		ID: uuid.NewString(), RequestedAt: time.Now(),
		Client: &oauth.Client{ID: client.ClientID.String()}, Session: session,
		Form: url.Values{"redirect_uri": {client.RedirectURIs[0]}},
	}
	request.SetRequestedScopes([]string{"openid"})
	request.GrantScope("openid")
	return storage, request, createCredential(t, storage, request, grantType)
}

// createCredential stores a credential of the grant type and returns the
// storage call that consumes it during a token exchange.
func createCredential(t *testing.T, storage *oauth.Storage, request fosite.Requester, grantType string) func(context.Context) error {
	t.Helper()
	signature := uuid.NewString()
	if grantType == "authorization_code" {
		if err := storage.CreateAuthorizeCodeSession(t.Context(), signature, request); err != nil {
			t.Fatal(err)
		}
		return func(ctx context.Context) error {
			return storage.InvalidateAuthorizeCodeSession(ctx, signature)
		}
	}
	if err := storage.CreateRefreshTokenSession(t.Context(), signature, "", request); err != nil {
		t.Fatal(err)
	}
	return func(ctx context.Context) error {
		return storage.RotateRefreshToken(ctx, request.GetID(), signature)
	}
}

func waitForDatabaseLock(t *testing.T, ctx context.Context, query string, done <-chan error, args ...any) {
	t.Helper()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		if err := testDB.QueryRowContext(ctx, query, args...).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		select {
		case err := <-done:
			t.Fatalf("operation completed before waiting for the concurrent transaction: %v", err)
		case <-ctx.Done():
			t.Fatalf("waiting for database lock: %v", ctx.Err())
		case <-ticker.C:
		}
	}
}
