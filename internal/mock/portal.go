package mock

import (
	"context"

	"github.com/traPtitech/portal-oidc/internal/domain"
)

// Portal implements portal.Portal for testing
type Portal struct {
	Users map[string]string // trapID -> password
}

func NewPortal() *Portal {
	return &Portal{
		Users: make(map[string]string),
	}
}

func (m *Portal) GetGrade(_ context.Context, _ domain.TrapID) (string, error) {
	return "B1", nil
}

func (m *Portal) VerifyPassword(_ context.Context, id domain.TrapID, password string) (bool, error) {
	if m.Users == nil {
		return true, nil
	}
	expected, ok := m.Users[string(id)]
	if !ok {
		return false, nil
	}
	return expected == password, nil
}
