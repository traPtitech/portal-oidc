package store

import "github.com/traPtitech/portal-oidc/pkg/domain/repository"

type Store struct {
	repo repository.Repository
}

func NewStore(repo repository.Repository) *Store {
	return &Store{repo: repo}
}
