package v1

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository"
	"github.com/traPtitech/portal-oidc/internal/repository/oidc"
)

func TestClientStatusConstraint(t *testing.T) {
	tests := []struct {
		name   string
		status domain.ClientStatus
		valid  bool
	}{
		{name: "active", status: domain.ClientStatusActive, valid: true},
		{name: "suspended", status: domain.ClientStatusSuspended, valid: true},
		{name: "empty"},
		{name: "wrong case", status: "Active"},
		{name: "whitespace", status: "active "},
		{name: "unknown", status: "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.status.Valid() != tt.valid {
				t.Fatalf("domain validity = %v, want %v", tt.status.Valid(), tt.valid)
			}
			for operation, statement := range map[string]string{
				"insert": `INSERT INTO clients (client_id, name, client_type, redirect_uris, status) VALUES ($1, 'status test', 'confidential', '[]', $2)`,
				"update": `UPDATE clients SET status = $2 WHERE client_id = $1`,
			} {
				t.Run(operation, func(t *testing.T) {
					repo := repository.NewClientRepository(oidc.New(testDB))
					clientID := uuid.New()
					var before *domain.Client
					if operation == "update" {
						repo, before = createMetadataClient(t)
						clientID = before.ClientID
					} else {
						t.Cleanup(func() {
							if err := repo.Delete(context.WithoutCancel(t.Context()), clientID); err != nil {
								t.Error(err)
							}
						})
					}

					// Bypass repository validation to exercise the database constraint.
					_, err := testDB.ExecContext(t.Context(), statement, clientID, string(tt.status))
					if tt.valid {
						if err != nil {
							t.Fatalf("valid status rejected: %v", err)
						}
					} else {
						var pgErr *pgconn.PgError
						if !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != "clients_status_check" {
							t.Fatalf("error = %v, want clients_status_check violation", err)
						}
					}

					stored, err := repo.Get(t.Context(), clientID)
					if !tt.valid && operation == "insert" {
						if !errors.Is(err, repository.ErrClientNotFound) {
							t.Fatalf("invalid insert persisted a client: %v", err)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					if tt.valid {
						if stored.Status != tt.status {
							t.Fatalf("persisted status = %q, want %q", stored.Status, tt.status)
						}
					} else if stored.Status != before.Status || !stored.UpdatedAt.Equal(before.UpdatedAt) {
						t.Fatalf("invalid update changed client status or timestamp: %+v", stored)
					}
				})
			}
		})
	}
}
