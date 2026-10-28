package v1

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository"
	"github.com/traPtitech/portal-oidc/internal/repository/oidc"
)

func createMetadataClient(t *testing.T) (repository.ClientRepository, *domain.Client) {
	t.Helper()
	repo := repository.NewClientRepository(oidc.New(testDB))
	client := &domain.Client{ClientID: uuid.New(), Name: "metadata", ClientType: domain.ClientTypeConfidential, RedirectURIs: []string{"https://example.com/callback"}}
	if err := repo.Create(t.Context(), client, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := repo.Delete(context.WithoutCancel(t.Context()), client.ClientID); err != nil {
			t.Error(err)
		}
	})
	stored, err := repo.Get(t.Context(), client.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	return repo, stored
}

func TestClientUpdateRejectsStaleSnapshot(t *testing.T) {
	repo, stale := createMetadataClient(t)
	// A suspension committed after the rename's read must not be undone.
	if _, err := testDB.ExecContext(t.Context(), `UPDATE clients SET status = 'suspended', scopes = '[]' WHERE client_id = $1`, stale.ClientID); err != nil {
		t.Fatal(err)
	}
	stale.Name = "renamed"
	if err := repo.Update(t.Context(), stale); !errors.Is(err, repository.ErrClientConflict) {
		t.Fatalf("stale update = %v", err)
	}
	current, err := repo.Get(t.Context(), stale.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Status != "suspended" || len(current.Scopes) != 0 || current.Name != "metadata" {
		t.Fatalf("concurrent changes overwritten: %+v", current)
	}
	current.Name = "renamed"
	if err := repo.Update(t.Context(), current); err != nil {
		t.Fatal(err)
	}
	// Reusing the same snapshot must also fail, even in rapid succession.
	if err := repo.Update(t.Context(), current); !errors.Is(err, repository.ErrClientConflict) {
		t.Fatalf("repeated update = %v", err)
	}
}
