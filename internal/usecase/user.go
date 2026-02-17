package usecase

import (
	"context"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository"
)

var (
	ErrInvalidPassword          = errors.New("invalid password")
	ErrUnsupportedHashAlgorithm = errors.New("unsupported hash algorithm")
	ErrUserNotActive            = errors.New("user is not active")
	ErrUserNotFound             = errors.New("user not found")
)

type UserUseCase interface {
	Authenticate(ctx context.Context, trapID, password string) (*domain.User, error)
	GetByID(ctx context.Context, id string) (*domain.User, error)
}

type userUseCase struct {
	repo repository.UserRepository
}

func NewUserUseCase(repo repository.UserRepository) UserUseCase {
	return &userUseCase{repo: repo}
}

func (u *userUseCase) GetByID(ctx context.Context, id string) (*domain.User, error) {
	user, err := u.repo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return user, nil
}

func (u *userUseCase) Authenticate(ctx context.Context, trapID, password string) (*domain.User, error) {
	user, err := u.repo.GetByTrapID(ctx, trapID)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	if err := verifyPassword(password, user.PasswordHash); err != nil {
		return nil, err
	}

	statuses, err := u.repo.ListStatuses(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	if len(statuses) > 0 {
		isActive := false
		for _, status := range statuses {
			if status == "active" {
				isActive = true
				break
			}
		}
		if !isActive {
			return nil, ErrUserNotActive
		}
	}

	return &user.User, nil
}

func verifyPassword(password, storedHash string) error {
	parts := strings.Split(storedHash, "$")
	if len(parts) != 4 {
		return fmt.Errorf("%w: invalid hash format", ErrUnsupportedHashAlgorithm)
	}

	switch parts[0] {
	case "pbkdf2_sha512":
		return verifyPBKDF2SHA512(password, parts[1], parts[2], parts[3])
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedHashAlgorithm, parts[0])
	}
}

func verifyPBKDF2SHA512(password, iterationsStr, saltB64, hashB64 string) error {
	iterations, err := strconv.Atoi(iterationsStr)
	if err != nil {
		return fmt.Errorf("%w: invalid iterations: %w", ErrUnsupportedHashAlgorithm, err)
	}

	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return fmt.Errorf("%w: invalid salt: %w", ErrUnsupportedHashAlgorithm, err)
	}

	expectedHash, err := base64.StdEncoding.DecodeString(hashB64)
	if err != nil {
		return fmt.Errorf("%w: invalid hash: %w", ErrUnsupportedHashAlgorithm, err)
	}

	computedHash := pbkdf2.Key([]byte(password), salt, iterations, len(expectedHash), sha512.New)

	if subtle.ConstantTimeCompare(computedHash, expectedHash) != 1 {
		return ErrInvalidPassword
	}
	return nil
}
