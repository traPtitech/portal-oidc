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

func TestClientSuspensionPermanentlyRevokesCredentials(t *testing.T) {
	repo, client := createMetadataClient(t)
	_, other := createMetadataClient(t)
	tokenSQL := `INSERT INTO tokens (id, request_id, client_id, user_id, access_token, refresh_token, scopes, expires_at) VALUES ($1, $2, $3, $4, $5, $6, 'openid', NOW() + INTERVAL '1 hour')`
	insertToken := func(id uuid.UUID) error {
		_, err := testDB.ExecContext(t.Context(), tokenSQL, uuid.New(), uuid.NewString(), id, uuid.New(), uuid.NewString(), uuid.NewString())
		return err
	}
	for _, id := range []uuid.UUID{client.ClientID, other.ClientID} {
		if err := insertToken(id); err != nil {
			t.Fatal(err)
		}
	}
	code := uuid.NewString()
	if _, err := testDB.ExecContext(t.Context(), `INSERT INTO authorization_codes (code, client_id, user_id, redirect_uri, scopes, expires_at) VALUES ($1, $2, $3, 'https://example.com/callback', 'openid', NOW() + INTERVAL '1 hour')`, code, client.ClientID, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if _, err := testDB.ExecContext(t.Context(), `INSERT INTO oidc_sessions (authorize_code, client_id, user_id, scopes, requested_at) VALUES ($1, $2, $3, 'openid', NOW())`, code, client.ClientID, uuid.New()); err != nil {
		t.Fatal(err)
	}
	client.Status = "suspended"
	if err := repo.Update(t.Context(), client); err != nil {
		t.Fatal(err)
	}
	if err := insertToken(client.ClientID); err == nil {
		t.Fatal("issued a token while suspended")
	}
	client, err := repo.Get(t.Context(), client.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	client.Status = "active"
	if err := repo.Update(t.Context(), client); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := testDB.QueryRowContext(t.Context(), `SELECT (SELECT COUNT(*) FROM tokens WHERE client_id=$1) + (SELECT COUNT(*) FROM authorization_codes WHERE client_id=$1) + (SELECT COUNT(*) FROM oidc_sessions WHERE client_id=$1)`, client.ClientID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("resumed client retained %d credentials", count)
	}
	if err := testDB.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM tokens WHERE client_id=$1`, other.ClientID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("other client's token count = %d", count)
	}
	if err := insertToken(client.ClientID); err != nil {
		t.Fatalf("new issuance after resuming: %v", err)
	}
}
