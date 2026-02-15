package oauth

import (
	"context"

	"github.com/ory/fosite"
)

func (s *Storage) CreateOpenIDConnectSession(_ context.Context, authorizeCode string, requester fosite.Requester) error {
	s.oidcSessionsMutex.Lock()
	defer s.oidcSessionsMutex.Unlock()
	s.oidcSessions[authorizeCode] = requester
	return nil
}

func (s *Storage) GetOpenIDConnectSession(_ context.Context, authorizeCode string, _ fosite.Requester) (fosite.Requester, error) {
	s.oidcSessionsMutex.RLock()
	defer s.oidcSessionsMutex.RUnlock()
	req, ok := s.oidcSessions[authorizeCode]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return req, nil
}

func (s *Storage) DeleteOpenIDConnectSession(_ context.Context, authorizeCode string) error {
	s.oidcSessionsMutex.Lock()
	defer s.oidcSessionsMutex.Unlock()
	delete(s.oidcSessions, authorizeCode)
	return nil
}
