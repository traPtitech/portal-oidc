package oauth

import (
	"context"
	"errors"
	"testing"

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
