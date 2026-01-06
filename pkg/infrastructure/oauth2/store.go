package oauth2

import (
	"context"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"

	"github.com/traPtitech/portal-oidc/pkg/domain"
	"github.com/traPtitech/portal-oidc/pkg/domain/repository"
)

// Store implements minimal fosite storage for Authorization Code Flow
type Store struct {
	repo repository.Repository

	// In-memory storage for authorization codes (short-lived)
	authCodes   map[string]fosite.Requester
	authCodesMu sync.RWMutex

	// In-memory storage for OIDC sessions
	oidcSessions   map[string]*openid.DefaultSession
	oidcSessionsMu sync.RWMutex
}

func NewStore(repo repository.Repository) *Store {
	return &Store{
		repo:         repo,
		authCodes:    make(map[string]fosite.Requester),
		oidcSessions: make(map[string]*openid.DefaultSession),
	}
}

// fosite.ClientManager implementation

func (s *Store) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	clientID, err := uuid.Parse(id)
	if err != nil {
		return nil, fosite.ErrNotFound
	}

	client, err := s.repo.GetClient(ctx, domain.ClientID(clientID))
	if err != nil {
		return nil, fosite.ErrNotFound
	}

	return &fositeClient{client: client}, nil
}

// oauth2.AuthorizeCodeStorage implementation

func (s *Store) CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) error {
	s.authCodesMu.Lock()
	defer s.authCodesMu.Unlock()
	s.authCodes[code] = request
	return nil
}

func (s *Store) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	s.authCodesMu.RLock()
	defer s.authCodesMu.RUnlock()

	req, ok := s.authCodes[code]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return req, nil
}

func (s *Store) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	s.authCodesMu.Lock()
	defer s.authCodesMu.Unlock()
	delete(s.authCodes, code)
	return nil
}

// oauth2.AccessTokenStorage implementation (stateless - no storage needed)

func (s *Store) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	return nil // Stateless JWT
}

func (s *Store) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return nil, fosite.ErrNotFound // Stateless JWT
}

func (s *Store) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return nil // Stateless JWT
}

// pkce.PKCERequestStorage implementation

func (s *Store) GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.GetAuthorizeCodeSession(ctx, signature, session)
}

func (s *Store) CreatePKCERequestSession(ctx context.Context, signature string, requester fosite.Requester) error {
	return nil // Stored with auth code
}

func (s *Store) DeletePKCERequestSession(ctx context.Context, signature string) error {
	return nil // Deleted with auth code
}

// openid.OpenIDConnectRequestStorage implementation

func (s *Store) CreateOpenIDConnectSession(ctx context.Context, code string, request fosite.Requester) error {
	s.oidcSessionsMu.Lock()
	defer s.oidcSessionsMu.Unlock()

	if sess, ok := request.GetSession().(*openid.DefaultSession); ok {
		s.oidcSessions[code] = sess
	}
	return nil
}

func (s *Store) GetOpenIDConnectSession(ctx context.Context, code string, request fosite.Requester) (fosite.Requester, error) {
	s.oidcSessionsMu.RLock()
	defer s.oidcSessionsMu.RUnlock()

	_, ok := s.oidcSessions[code]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return request, nil
}

func (s *Store) DeleteOpenIDConnectSession(ctx context.Context, code string) error {
	s.oidcSessionsMu.Lock()
	defer s.oidcSessionsMu.Unlock()
	delete(s.oidcSessions, code)
	return nil
}

// fositeClient wraps domain.Client to implement fosite.Client
type fositeClient struct {
	client domain.Client
}

func (c *fositeClient) GetID() string {
	return c.client.ID.String()
}

func (c *fositeClient) GetHashedSecret() []byte {
	if c.client.SecretHash == nil {
		return nil
	}
	return []byte(*c.client.SecretHash)
}

func (c *fositeClient) GetRedirectURIs() []string {
	return c.client.RedirectURIs
}

func (c *fositeClient) GetGrantTypes() fosite.Arguments {
	return fosite.Arguments{"authorization_code"}
}

func (c *fositeClient) GetResponseTypes() fosite.Arguments {
	return fosite.Arguments{"code"}
}

func (c *fositeClient) GetScopes() fosite.Arguments {
	return fosite.Arguments{"openid", "profile"}
}

func (c *fositeClient) IsPublic() bool {
	return c.client.Type == domain.ClientTypePublic
}

func (c *fositeClient) GetAudience() fosite.Arguments {
	return fosite.Arguments{}
}

func (c *fositeClient) GetRequestURIs() []string {
	return nil
}

func (c *fositeClient) GetJSONWebKeysURI() string {
	return ""
}

func (c *fositeClient) GetJSONWebKeys() *jose.JSONWebKeySet {
	return nil
}

func (c *fositeClient) GetTokenEndpointAuthSigningAlgorithm() string {
	return "RS256"
}

func (c *fositeClient) GetRequestObjectSigningAlgorithm() string {
	return ""
}

func (c *fositeClient) GetTokenEndpointAuthMethod() string {
	if c.client.Type == domain.ClientTypePublic {
		return "none"
	}
	return "client_secret_basic"
}

func (c *fositeClient) GetIDTokenSignedResponseAlg() string {
	return "RS256"
}

func (c *fositeClient) GetIDTokenEncryptedResponseAlg() string {
	return ""
}

func (c *fositeClient) GetIDTokenEncryptedResponseEnc() string {
	return ""
}

// rfc7523.RFC7523KeyStorage implementation

func (s *Store) GetPublicKey(ctx context.Context, issuer string, subject string, keyId string) (*jose.JSONWebKey, error) {
	return nil, fosite.ErrNotFound
}

func (s *Store) GetPublicKeys(ctx context.Context, issuer string, subject string) (*jose.JSONWebKeySet, error) {
	return nil, fosite.ErrNotFound
}

func (s *Store) GetPublicKeyScopes(ctx context.Context, issuer string, subject string, keyId string) ([]string, error) {
	return nil, fosite.ErrNotFound
}

func (s *Store) IsJWTUsed(ctx context.Context, jti string) (bool, error) {
	return false, nil
}

func (s *Store) MarkJWTUsedForTime(ctx context.Context, jti string, exp time.Time) error {
	return nil
}

// oauth2.RefreshTokenStorage implementation (not used, but required)

func (s *Store) CreateRefreshTokenSession(ctx context.Context, signature string, accessSignature string, request fosite.Requester) error {
	return nil
}

func (s *Store) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return nil, fosite.ErrNotFound
}

func (s *Store) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return nil
}

func (s *Store) RotateRefreshToken(ctx context.Context, requestID string, refreshTokenSignature string) error {
	return nil
}

// oauth2.TokenRevocationStorage implementation

func (s *Store) RevokeRefreshToken(ctx context.Context, requestID string) error {
	return nil
}

func (s *Store) RevokeAccessToken(ctx context.Context, requestID string) error {
	return nil
}

// fosite.ClientCredentialsGrantStorage implementation

func (s *Store) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	return nil
}

func (s *Store) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	return nil
}

// Cleanup old auth codes periodically
func (s *Store) Cleanup(maxAge time.Duration) {
	s.authCodesMu.Lock()
	defer s.authCodesMu.Unlock()

	now := time.Now()
	for code, req := range s.authCodes {
		if req.GetRequestedAt().Add(maxAge).Before(now) {
			delete(s.authCodes, code)
		}
	}
}
