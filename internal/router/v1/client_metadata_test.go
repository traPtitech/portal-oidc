package v1

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/ory/fosite"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository"
	"github.com/traPtitech/portal-oidc/internal/repository/oauth"
	"github.com/traPtitech/portal-oidc/internal/repository/oidc"
)

func newMetadataClient(t *testing.T) (repository.ClientRepository, *domain.Client, *oauth.Storage) {
	t.Helper()
	queries := oidc.New(testDB)
	repo := repository.NewClientRepository(queries)
	client := &domain.Client{
		ClientID: uuid.New(), Name: "metadata test", ClientType: domain.ClientTypeConfidential,
		RedirectURIs: []string{"https://client.example/callback"},
	}
	if err := repo.Create(t.Context(), client, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Delete(context.Background(), client.ClientID) })
	client, err := repo.Get(t.Context(), client.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	store := oauth.NewStorage(testDB, queries, repo, repository.NewAuthCodeRepository(queries),
		repository.NewTokenRepository(queries), repository.NewOIDCSessionRepository(queries))
	return repo, client, store
}

var credentialInserts = map[string]string{
	"tokens": `INSERT INTO tokens (id, request_id, client_id, user_id, access_token, refresh_token, scopes, expires_at)
		VALUES ($2::text::uuid, $2::text, $1, $2::text::uuid, $2::text, $2::text, 'openid', now() + interval '1 hour')`,
	"authorization_codes": `INSERT INTO authorization_codes (code, client_id, user_id, redirect_uri, scopes, expires_at)
		VALUES ($2::text, $1, $2::text::uuid, 'https://client.example/callback', 'openid', now() + interval '1 hour')`,
	"oidc_sessions": `INSERT INTO oidc_sessions (authorize_code, client_id, user_id, scopes, requested_at)
		VALUES ($2::text, $1, $2::text::uuid, 'openid', now())`,
}

func insertCredential(ctx context.Context, db oidc.DBTX, table string, clientID uuid.UUID) error {
	_, err := db.ExecContext(ctx, credentialInserts[table], clientID, uuid.NewString())
	return err
}

func assertCredentialCount(t *testing.T, clientID uuid.UUID, want int) {
	t.Helper()
	queries := []string{
		"SELECT count(*) FROM tokens WHERE client_id = $1",
		"SELECT count(*) FROM authorization_codes WHERE client_id = $1",
		"SELECT count(*) FROM oidc_sessions WHERE client_id = $1",
	}
	for _, query := range queries {
		var got int
		if err := testDB.QueryRowContext(t.Context(), query, clientID).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("%s: got %d, want %d", query, got, want)
		}
	}
}

func TestIntegration_ClientSuspensionRevokesCredentials(t *testing.T) {
	for _, via := range []string{"repository", "sql"} {
		t.Run(via, func(t *testing.T) {
			repo, client, store := newMetadataClient(t)
			_, other, _ := newMetadataClient(t)
			for table := range credentialInserts {
				for _, id := range []uuid.UUID{client.ClientID, other.ClientID} {
					if err := insertCredential(t.Context(), testDB, table, id); err != nil {
						t.Fatal(err)
					}
				}
			}
			client.Name = "renamed"
			if err := repo.Update(t.Context(), client); err != nil {
				t.Fatal(err)
			}
			assertCredentialCount(t, client.ClientID, 1)
			client.Status = "suspended"
			if via == "repository" {
				if err := repo.Update(t.Context(), client); err != nil {
					t.Fatal(err)
				}
			} else if _, err := testDB.ExecContext(t.Context(), "UPDATE clients SET status = 'suspended' WHERE client_id = $1", client.ClientID); err != nil {
				t.Fatal(err)
			}
			assertCredentialCount(t, client.ClientID, 0)
			assertCredentialCount(t, other.ClientID, 1)
			if _, err := store.GetClient(t.Context(), client.ClientID.String()); !errors.Is(err, fosite.ErrNotFound) {
				t.Fatalf("suspended client: %v", err)
			}
			client.Status = "active"
			if err := repo.Update(t.Context(), client); err != nil {
				t.Fatal(err)
			}
			if _, err := store.GetClient(t.Context(), client.ClientID.String()); err != nil {
				t.Fatal(err)
			}
			assertCredentialCount(t, client.ClientID, 0)
		})
	}
}

func assertPostgresError(t *testing.T, err error, code string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != code {
		t.Fatalf("got %v, want PostgreSQL error %s", err, code)
	}
}

func TestIntegration_InactiveClientRejectsIssuance(t *testing.T) {
	for _, status := range []string{"suspended", "unknown"} {
		t.Run(status, func(t *testing.T) {
			repo, client, _ := newMetadataClient(t)
			client.Status = status
			if err := repo.Update(t.Context(), client); err != nil {
				t.Fatal(err)
			}
			for table := range credentialInserts {
				assertPostgresError(t, insertCredential(t.Context(), testDB, table, client.ClientID), "23514")
			}
			assertCredentialCount(t, client.ClientID, 0)
		})
	}
}

func metadataTransaction(t *testing.T, lockTimeout bool) *sql.Tx {
	t.Helper()
	tx, err := testDB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	if lockTimeout {
		if _, err := tx.ExecContext(t.Context(), "SET LOCAL lock_timeout = '100ms'"); err != nil {
			t.Fatal(err)
		}
	}
	return tx
}

func TestIntegration_ClientSuspensionSerializesIssuance(t *testing.T) {
	for table := range credentialInserts {
		for _, first := range []string{"issuance", "suspension"} {
			t.Run(table+"/"+first, func(t *testing.T) {
				_, client, _ := newMetadataClient(t)
				ctx := t.Context()
				holder := metadataTransaction(t, false)
				contender := metadataTransaction(t, true)
				const suspend = "UPDATE clients SET status = 'suspended' WHERE client_id = $1"
				if first == "issuance" {
					if err := insertCredential(ctx, holder, table, client.ClientID); err != nil {
						t.Fatal(err)
					}
					_, err := contender.ExecContext(ctx, suspend, client.ClientID)
					assertPostgresError(t, err, "55P03")
				} else {
					if _, err := holder.ExecContext(ctx, suspend, client.ClientID); err != nil {
						t.Fatal(err)
					}
					assertPostgresError(t, insertCredential(ctx, contender, table, client.ClientID), "55P03")
				}
				if err := contender.Rollback(); err != nil {
					t.Fatal(err)
				}
				if err := holder.Commit(); err != nil {
					t.Fatal(err)
				}
				if first == "issuance" {
					if _, err := testDB.ExecContext(ctx, suspend, client.ClientID); err != nil {
						t.Fatal(err)
					}
				} else {
					assertPostgresError(t, insertCredential(ctx, testDB, table, client.ClientID), "23514")
				}
				assertCredentialCount(t, client.ClientID, 0)
			})
		}
	}
}
