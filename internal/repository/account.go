package repository

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/google/uuid"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository/oidc"
)

var ErrAccountConflict = errors.New("account conflict")
var ErrAccountNotFound = errors.New("account not found")

type AccountRepository interface {
	Provision(context.Context, domain.Account) (bool, error)
	Delete(context.Context, uuid.UUID) error
	GetByID(context.Context, uuid.UUID) (*domain.Account, error)
	GetByTrapID(context.Context, string) (*domain.Account, error)
}
type accountRepository struct{ queries *oidc.Queries }

func NewAccountRepository(q *oidc.Queries) AccountRepository { return &accountRepository{q} }

// Provision reports whether it created the account. An identical replay returns false.
func (r *accountRepository) Provision(ctx context.Context, a domain.Account) (bool, error) {
	fp, err := a.Fingerprint()
	if err != nil {
		return false, err
	}
	verifier, err := json.Marshal(a.AuthVerifier)
	if err != nil {
		return false, err
	}
	count, err := r.queries.InsertIdentityAccount(ctx, oidc.InsertIdentityAccountParams{UserID: a.UserID, TrapID: a.TrapID, Email: a.Email, EmailVerified: a.EmailVerified, AuthVerifier: verifier, ExpiresAt: a.ExpiresAt, ProvisionFingerprint: fp[:]})
	if err != nil {
		return false, err
	}
	if count == 1 {
		return true, nil
	}
	// The insert hit a unique constraint on the user ID, the traQ ID or the email.
	row, err := r.queries.GetIdentityAccountByID(ctx, a.UserID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrAccountConflict
	}
	if err != nil {
		return false, err
	}
	if subtle.ConstantTimeCompare(row.ProvisionFingerprint, fp[:]) != 1 {
		return false, ErrAccountConflict
	}
	return false, nil
}
func (r *accountRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.queries.DeleteIdentityAccount(ctx, id)
}
func (r *accountRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.Account, error) {
	a, e := r.queries.GetIdentityAccountByID(ctx, id)
	return accountFromRow(a, e)
}
func (r *accountRepository) GetByTrapID(ctx context.Context, trapID string) (*domain.Account, error) {
	a, e := r.queries.GetIdentityAccountByTrapID(ctx, trapID)
	return accountFromRow(a, e)
}
func accountFromRow(a oidc.IdentityAccount, err error) (*domain.Account, error) {
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAccountNotFound
	}
	if err != nil {
		return nil, err
	}
	var v domain.AuthVerifier
	if err := json.Unmarshal(a.AuthVerifier, &v); err != nil {
		return nil, err
	}
	return &domain.Account{UserID: a.UserID, TrapID: a.TrapID, Email: a.Email, EmailVerified: a.EmailVerified, AuthVerifier: v, ExpiresAt: a.ExpiresAt}, nil
}
