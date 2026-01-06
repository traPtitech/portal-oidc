package oauth2

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/go-jose/go-jose/v3"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"

	"github.com/traPtitech/portal-oidc/pkg/domain"
	"github.com/traPtitech/portal-oidc/pkg/domain/repository"
)

// Store implements fosite storage interfaces with DB persistence
type Store struct {
	repo            repository.Repository
	authCodeExpiry  time.Duration
}

func NewStore(repo repository.Repository, authCodeExpiry time.Duration) *Store {
	return &Store{
		repo:           repo,
		authCodeExpiry: authCodeExpiry,
	}
}

// sessionData is serialized to JSON for DB storage
type sessionData struct {
	Subject   string            `json:"subject"`
	Username  string            `json:"username"`
	ExpiresAt map[string]int64  `json:"expires_at"`
	Extra     map[string]string `json:"extra"`
}

func serializeSession(sess fosite.Session) (string, error) {
	if sess == nil {
		return "{}", nil
	}

	data := sessionData{
		Subject:   sess.GetSubject(),
		Username:  sess.GetUsername(),
		ExpiresAt: make(map[string]int64),
	}

	// Store expiry times
	for _, key := range []fosite.TokenType{fosite.AccessToken, fosite.AuthorizeCode, fosite.RefreshToken} {
		if t := sess.GetExpiresAt(key); !t.IsZero() {
			data.ExpiresAt[string(key)] = t.Unix()
		}
	}

	bytes, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func deserializeSession(s string) (*openid.DefaultSession, error) {
	var data sessionData
	if err := json.Unmarshal([]byte(s), &data); err != nil {
		return nil, err
	}

	sess := &openid.DefaultSession{
		Subject:  data.Subject,
		Username: data.Username,
	}

	// Restore expiry times
	if len(data.ExpiresAt) > 0 {
		sess.ExpiresAt = make(map[fosite.TokenType]time.Time)
		for key, val := range data.ExpiresAt {
			sess.ExpiresAt[fosite.TokenType(key)] = time.Unix(val, 0)
		}
	}

	return sess, nil
}

// fosite.ClientManager implementation

func (s *Store) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	clientID, err := domain.ParseClientID(id)
	if err != nil {
		return nil, fosite.ErrNotFound
	}

	client, err := s.repo.GetClient(ctx, clientID)
	if err != nil {
		return nil, fosite.ErrNotFound
	}
	return &fositeClient{client: client}, nil
}

// oauth2.AuthorizeCodeStorage implementation

func (s *Store) CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) error {
	sessData, err := serializeSession(request.GetSession())
	if err != nil {
		return errors.Wrap(err, "failed to serialize session")
	}

	// Get PKCE data from form
	form := request.GetRequestForm()

	authCode := domain.AuthorizationCode{
		Code:                code,
		ClientID:            request.GetClient().GetID(),
		UserID:              domain.TrapID(request.GetSession().GetSubject()),
		RedirectURI:         form.Get("redirect_uri"),
		Scope:               strings.Join(request.GetGrantedScopes(), " "),
		CodeChallenge:       form.Get("code_challenge"),
		CodeChallengeMethod: form.Get("code_challenge_method"),
		SessionData:         sessData,
		Used:                false,
		ExpiresAt:           time.Now().Add(s.authCodeExpiry),
		CreatedAt:           time.Now(),
	}

	return s.repo.CreateAuthorizationCode(ctx, authCode)
}

func (s *Store) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	authCode, err := s.repo.GetAuthorizationCode(ctx, code)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}

	// Check if already used (replay attack)
	if authCode.Used {
		return nil, fosite.ErrInvalidatedAuthorizeCode
	}

	// Check expiry
	if time.Now().After(authCode.ExpiresAt) {
		return nil, fosite.ErrNotFound
	}

	// Deserialize session
	sess, err := deserializeSession(authCode.SessionData)
	if err != nil {
		return nil, errors.Wrap(err, "failed to deserialize session")
	}

	// Get client
	client, err := s.GetClient(ctx, authCode.ClientID)
	if err != nil {
		return nil, err
	}

	// Reconstruct the request
	form := url.Values{}
	form.Set("code_challenge", authCode.CodeChallenge)
	form.Set("code_challenge_method", authCode.CodeChallengeMethod)
	form.Set("redirect_uri", authCode.RedirectURI)

	req := &fosite.Request{
		ID:             code,
		RequestedAt:    authCode.CreatedAt,
		Client:         client,
		Session:        sess,
		GrantedScope:   strings.Split(authCode.Scope, " "),
		RequestedScope: strings.Split(authCode.Scope, " "),
		Form:           form,
	}

	return req, nil
}

func (s *Store) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	return s.repo.MarkAuthorizationCodeUsed(ctx, code)
}

// oauth2.AccessTokenStorage implementation (stateless JWT - no storage needed)

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

// openid.OpenIDConnectRequestStorage implementation (minimal - uses auth code session)

func (s *Store) CreateOpenIDConnectSession(ctx context.Context, code string, request fosite.Requester) error {
	return nil // Stored with auth code
}

func (s *Store) GetOpenIDConnectSession(ctx context.Context, code string, request fosite.Requester) (fosite.Requester, error) {
	return s.GetAuthorizeCodeSession(ctx, code, request.GetSession())
}

func (s *Store) DeleteOpenIDConnectSession(ctx context.Context, code string) error {
	return nil // Deleted with auth code
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

// oauth2.RefreshTokenStorage implementation (not used)

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
