package v1

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository"
	"github.com/traPtitech/portal-oidc/internal/repository/oidc"
)

func TestClientUpdateMissingClient(t *testing.T) {
	repo := repository.NewClientRepository(oidc.New(testDB))
	missing := &domain.Client{ClientID: uuid.New(), Name: "missing", ClientType: domain.ClientTypeConfidential}
	if err := repo.Update(t.Context(), missing); !errors.Is(err, repository.ErrClientNotFound) {
		t.Fatalf("Update() = %v, want %v", err, repository.ErrClientNotFound)
	}
}
