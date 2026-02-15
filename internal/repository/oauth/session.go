package oauth

import (
	"maps"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

var _ openid.Session = (*Session)(nil)

type Session struct {
	subject        string
	username       string
	expiresAt      map[fosite.TokenType]time.Time
	extra          map[string]interface{}
	idTokenClaims  *jwt.IDTokenClaims
	idTokenHeaders *jwt.Headers
}

func NewSession(subject string) *Session {
	now := time.Now()
	return &Session{
		subject:   subject,
		username:  subject,
		expiresAt: make(map[fosite.TokenType]time.Time),
		extra:     make(map[string]interface{}),
		idTokenClaims: &jwt.IDTokenClaims{
			Subject:  subject,
			AuthTime: now,
		},
		idTokenHeaders: &jwt.Headers{
			Extra: make(map[string]interface{}),
		},
	}
}

func (s *Session) SetExpiresAt(key fosite.TokenType, exp time.Time) {
	if s.expiresAt == nil {
		s.expiresAt = make(map[fosite.TokenType]time.Time)
	}
	s.expiresAt[key] = exp
}

func (s *Session) GetExpiresAt(key fosite.TokenType) time.Time {
	if s.expiresAt == nil {
		return time.Time{}
	}
	return s.expiresAt[key]
}

func (s *Session) GetUsername() string               { return s.username }
func (s *Session) GetSubject() string                { return s.subject }
func (s *Session) IDTokenClaims() *jwt.IDTokenClaims { return s.idTokenClaims }
func (s *Session) IDTokenHeaders() *jwt.Headers      { return s.idTokenHeaders }

func (s *Session) Clone() fosite.Session {
	expiresAt := make(map[fosite.TokenType]time.Time)
	maps.Copy(expiresAt, s.expiresAt)
	extra := make(map[string]interface{})
	maps.Copy(extra, s.extra)
	idTokenClaimsClone := *s.idTokenClaims
	idTokenHeadersClone := *s.idTokenHeaders
	idTokenHeadersClone.Extra = make(map[string]interface{})
	maps.Copy(idTokenHeadersClone.Extra, s.idTokenHeaders.Extra)
	return &Session{
		subject:        s.subject,
		username:       s.username,
		expiresAt:      expiresAt,
		extra:          extra,
		idTokenClaims:  &idTokenClaimsClone,
		idTokenHeaders: &idTokenHeadersClone,
	}
}
