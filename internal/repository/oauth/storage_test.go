package oauth

import (
	"context"
	"errors"
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
	return r.client, "hashed-secret", nil
}

func TestGetClientRejectsInactiveClients(t *testing.T) {
	for _, status := range []string{"active", "suspended", "", "unknown"} {
		t.Run(status, func(t *testing.T) {
			client := &domain.Client{ClientID: uuid.New(), Status: status}
			store := NewStorage(nil, nil, clientRepositoryStub{client: client}, nil, nil, nil, nil)
			got, err := store.GetClient(t.Context(), client.ClientID.String())
			if status == "active" {
				if err != nil || got == nil || got.GetID() != client.ClientID.String() {
					t.Fatalf("active client: got %v, error %v", got, err)
				}
				return
			}
			if got != nil || !errors.Is(err, fosite.ErrNotFound) {
				t.Fatalf("inactive client accepted: got %v, error %v", got, err)
			}
		})
	}
}

type refreshTokenRepositoryStub struct {
	repository.RefreshTokenRepository
	token   domain.RefreshToken
	rotated []string
}

func (r *refreshTokenRepositoryStub) GetByHash(_ context.Context, tokenHash string) (domain.RefreshToken, error) {
	if tokenHash != r.token.TokenHash {
		return domain.RefreshToken{}, repository.ErrRefreshTokenNotFound
	}
	return r.token, nil
}

func (r *refreshTokenRepositoryStub) MarkRotated(_ context.Context, tokenHash string) error {
	r.rotated = append(r.rotated, tokenHash)
	return nil
}

type accessTokenRepositoryStub struct {
	repository.AccessTokenRepository
	revoked []string
}

func (r *accessTokenRepositoryStub) RevokeByRequestID(_ context.Context, requestID string) error {
	r.revoked = append(r.revoked, requestID)
	return nil
}

func TestGetRefreshTokenSessionReturnsRequesterForInactiveTokens(t *testing.T) {
	now := time.Now()
	for name, mutate := range map[string]func(*domain.RefreshToken){
		"revoked": func(tok *domain.RefreshToken) { tok.RevokedAt = &now },
		"rotated": func(tok *domain.RefreshToken) { tok.RotatedAt = &now },
	} {
		t.Run(name, func(t *testing.T) {
			client := &domain.Client{ClientID: uuid.New(), Status: "active"}
			token := domain.RefreshToken{
				TokenHash: "sig",
				RequestID: "req-1",
				ClientID:  client.ClientID,
				UserID:    uuid.New(),
				ExpiresAt: now.Add(time.Hour),
			}
			mutate(&token)
			store := NewStorage(nil, nil, clientRepositoryStub{client: client}, nil, nil, &refreshTokenRepositoryStub{token: token}, nil)

			got, err := store.GetRefreshTokenSession(t.Context(), "sig", nil)
			if !errors.Is(err, fosite.ErrInactiveToken) {
				t.Fatalf("expected ErrInactiveToken, got %v", err)
			}
			// fosite's handleRefreshTokenReuse calls GetID() on this value.
			if got == nil || got.GetID() != "req-1" {
				t.Fatalf("expected requester with request id, got %v", got)
			}
		})
	}
}

func TestRotateRefreshTokenMarksRotatedAndRevokesAccessTokens(t *testing.T) {
	refreshTokens := &refreshTokenRepositoryStub{}
	accessTokens := &accessTokenRepositoryStub{}
	store := NewStorage(nil, nil, nil, nil, accessTokens, refreshTokens, nil)

	if err := store.RotateRefreshToken(t.Context(), "req-1", "sig"); err != nil {
		t.Fatalf("RotateRefreshToken: %v", err)
	}
	if len(refreshTokens.rotated) != 1 || refreshTokens.rotated[0] != "sig" {
		t.Fatalf("expected sig to be marked rotated, got %v", refreshTokens.rotated)
	}
	if len(accessTokens.revoked) != 1 || accessTokens.revoked[0] != "req-1" {
		t.Fatalf("expected access tokens of req-1 to be revoked, got %v", accessTokens.revoked)
	}
}
