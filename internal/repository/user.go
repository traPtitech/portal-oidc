package repository

import (
	"context"
	"crypto/sha512"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"

	"golang.org/x/crypto/pbkdf2"

	"github.com/traPtitech/portal-oidc/internal/repository/portal"
)

var (
	ErrUserNotFound    = errors.New("user not found")
	ErrInvalidPassword = errors.New("invalid password")
	ErrUserNotActive   = errors.New("user is not active")
)

type User struct {
	ID     string
	TrapID string
}

type UserRepository interface {
	Authenticate(ctx context.Context, trapID, password string) (*User, error)
	GetByID(ctx context.Context, id string) (*User, error)
}

type userRepository struct {
	queries *portal.Queries
}

func NewUserRepository(queries *portal.Queries) UserRepository {
	return &userRepository{queries: queries}
}

func (r *userRepository) Authenticate(ctx context.Context, trapID, password string) (*User, error) {
	user, err := r.queries.GetUserByTrapID(ctx, trapID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	if !verifyPBKDF2Password(password, user.PasswordHash) {
		return nil, ErrInvalidPassword
	}

	statuses, err := r.queries.ListUserStatuses(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	isActive := false
	for _, status := range statuses {
		if status.Status == "active" {
			isActive = true
			break
		}
	}

	if !isActive && len(statuses) > 0 {
		return nil, ErrUserNotActive
	}

	return &User{
		ID:     user.ID,
		TrapID: user.TrapID,
	}, nil
}

func (r *userRepository) GetByID(ctx context.Context, id string) (*User, error) {
	user, err := r.queries.GetUserByID(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	return &User{
		ID:     user.ID,
		TrapID: user.TrapID,
	}, nil
}

// verifyPBKDF2Password verifies a password against a PBKDF2-SHA512 hash.
// Expected format: "pbkdf2_sha512$iterations$salt$hash" (base64 encoded)
func verifyPBKDF2Password(password, storedHash string) bool {
	parts := strings.Split(storedHash, "$")
	if len(parts) != 4 {
		return false
	}

	algorithm := parts[0]
	if algorithm != "pbkdf2_sha512" {
		return false
	}

	iterations, err := parseIterations(parts[1])
	if err != nil {
		return false
	}

	salt, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}

	expectedHash, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}

	computedHash := pbkdf2.Key([]byte(password), salt, iterations, len(expectedHash), sha512.New)

	return subtle.ConstantTimeCompare(computedHash, expectedHash) == 1
}

func parseIterations(s string) (int, error) {
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("invalid iterations")
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}
