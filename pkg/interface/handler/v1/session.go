package v1

import (
	"net/http"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"

	"github.com/traPtitech/portal-oidc/pkg/domain"
)

const (
	oidcCookieKeySessionID = "gate_token"
)

var (
	errNoSessionID = errors.New("session ID not found")
)

func extractSessionID(req *http.Request) (domain.SessionID, error) {
	cookies := req.Cookies()
	cookieMap := map[string]string{}
	for _, c := range cookies {
		cookieMap[c.Name] = c.Value
	}

	// cookieからweb sessionを取得
	sessionIDStr, ok := cookieMap[oidcCookieKeySessionID]
	if !ok {
		return domain.SessionID{}, errNoSessionID
	}

	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		return domain.SessionID{}, errors.Wrap(err, "Failed to parse session ID")
	}

	return domain.SessionID(sessionID), nil
}

func newFositeSession(
	clientID domain.ClientID,
	userID domain.TrapID,
	issuer string,
	issuedAt time.Time,
	expiresAt time.Time,
	authTime time.Time,
	opts ...func(sess *openid.DefaultSession),
) *openid.DefaultSession {
	sess := &openid.DefaultSession{
		Subject:  userID.String(),
		Username: userID.String(),
		ExpiresAt: map[fosite.TokenType]time.Time{
			fosite.AccessToken:   expiresAt,
			fosite.RefreshToken:  expiresAt,
			fosite.AuthorizeCode: authTime.Add(10 * time.Minute),
		},
		Claims: &jwt.IDTokenClaims{
			Subject:     userID.String(),
			Issuer:      issuer,
			Audience:    []string{clientID.String()},
			IssuedAt:    issuedAt,
			ExpiresAt:   expiresAt,
			RequestedAt: time.Now(),
			AuthTime:    authTime,
			Extra:       make(map[string]any),
		},
		Headers: &jwt.Headers{
			Extra: make(map[string]any),
		},
	}

	for _, opt := range opts {
		opt(sess)
	}
	return sess
}
