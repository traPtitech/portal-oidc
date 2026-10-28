package oauth

import (
	"context"
	"errors"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository"
)

type clientRepositoryStub struct {
	repository.ClientRepository
	client *domain.Client
}

func (r clientRepositoryStub) GetWithSecretHash(context.Context, uuid.UUID) (*domain.Client, string, error) {
	return r.client, "", nil
}

type tokenRepositoryStub struct {
	repository.TokenRepository
	token *domain.Token
}

func (r tokenRepositoryStub) GetByAccessToken(context.Context, string) (domain.Token, error) {
	return *r.token, nil
}

func (r tokenRepositoryStub) GetByRefreshToken(context.Context, string) (domain.Token, error) {
	return *r.token, nil
}

func TestStorageClientStatus(t *testing.T) {
	for _, status := range []string{"active", "suspended", "", "unknown"} {
		t.Run(status, func(t *testing.T) {
			ctx := t.Context()
			client := &domain.Client{
				ClientID: uuid.New(), ClientType: domain.ClientTypeConfidential,
				RedirectURIs:  []string{"https://example.com/callback"},
				GrantTypes:    []string{"authorization_code", "refresh_token"},
				ResponseTypes: []string{"code"}, Scopes: []string{"openid"}, Status: status,
			}
			token := &domain.Token{
				ClientID: client.ClientID, UserID: uuid.New(),
				ExpiresAt: time.Now().Add(time.Hour),
			}
			storage := NewStorage(nil, nil, clientRepositoryStub{client: client}, nil, tokenRepositoryStub{token: token}, nil)
			_, err := storage.GetClient(ctx, client.ClientID.String())
			if status == "active" {
				if err != nil {
					t.Fatalf("GetClient() = %v", err)
				}
			} else if !errors.Is(err, fosite.ErrNotFound) {
				t.Errorf("GetClient() = %v, want ErrNotFound", err)
			}

			t.Run("authorize", func(t *testing.T) {
				provider := fosite.NewOAuth2Provider(storage, &fosite.Config{ScopeStrategy: fosite.ExactScopeStrategy})
				query := url.Values{
					"client_id": {client.ClientID.String()}, "redirect_uri": {client.RedirectURIs[0]},
					"response_type": {"code"}, "scope": {"openid"}, "state": {"client-status-test"},
				}
				request := httptest.NewRequestWithContext(t.Context(), "GET", "https://issuer.example/oauth2/authorize?"+query.Encode(), nil)
				_, err := provider.NewAuthorizeRequest(t.Context(), request)
				if status == "active" {
					if err != nil {
						t.Fatalf("NewAuthorizeRequest() = %v", err)
					}
				} else if !errors.Is(err, fosite.ErrInvalidClient) {
					t.Fatalf("NewAuthorizeRequest() = %v, want ErrInvalidClient", err)
				}
			})

			for name, lookup := range map[string]func(context.Context, string, fosite.Session) (fosite.Requester, error){
				"access_token":  storage.GetAccessTokenSession,
				"refresh_token": storage.GetRefreshTokenSession,
			} {
				t.Run(name, func(t *testing.T) {
					_, err := lookup(t.Context(), "existing-token", nil)
					if status == "active" {
						if err != nil {
							t.Fatalf("token lookup = %v", err)
						}
					} else if !errors.Is(err, fosite.ErrNotFound) {
						t.Fatalf("token lookup = %v, want ErrNotFound", err)
					}
				})
			}
		})
	}
}
