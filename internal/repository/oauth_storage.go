package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"
	"golang.org/x/crypto/bcrypt"

	"github.com/traPtitech/portal-oidc/internal/repository/oidc"
)

// OAuthStorage implements fosite.Storage interface
type OAuthStorage struct {
	queries *oidc.Queries
}

func NewOAuthStorage(queries *oidc.Queries) *OAuthStorage {
	return &OAuthStorage{queries: queries}
}

// ClientCredentials implements fosite.ClientCredentialsStorage
func (s *OAuthStorage) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	dbClient, err := s.queries.GetClient(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}

	var redirectURIs []string
	if err := json.Unmarshal(dbClient.RedirectUris, &redirectURIs); err != nil {
		return nil, err
	}

	return &OAuthClient{
		ID:            dbClient.ClientID,
		Secret:        []byte(dbClient.ClientSecretHash.String),
		RedirectURIs:  redirectURIs,
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid", "profile", "email"},
		Public:        dbClient.ClientType == "public",
	}, nil
}

func (s *OAuthStorage) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	return fosite.ErrNotFound
}

func (s *OAuthStorage) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	return nil
}

// AuthorizeCodeStorage implements fosite.AuthorizeCodeStorage
func (s *OAuthStorage) CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) error {
	sess, ok := request.GetSession().(*OAuthSession)
	if !ok {
		return errors.New("invalid session type")
	}

	return s.queries.CreateAuthorizationCode(ctx, oidc.CreateAuthorizationCodeParams{
		Code:                code,
		ClientID:            request.GetClient().GetID(),
		UserID:              sess.Subject,
		RedirectUri:         request.GetRequestForm().Get("redirect_uri"),
		Scopes:              strings.Join(request.GetRequestedScopes(), " "),
		CodeChallenge:       sql.NullString{Valid: false},
		CodeChallengeMethod: sql.NullString{Valid: false},
		Nonce: sql.NullString{
			String: request.GetRequestForm().Get("nonce"),
			Valid:  request.GetRequestForm().Get("nonce") != "",
		},
		ExpiresAt: sess.ExpiresAt[fosite.AuthorizeCode],
	})
}

func (s *OAuthStorage) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	dbCode, err := s.queries.GetAuthorizationCode(ctx, code)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}

	if time.Now().After(dbCode.ExpiresAt) {
		return nil, fosite.ErrTokenExpired
	}

	client, err := s.GetClient(ctx, dbCode.ClientID)
	if err != nil {
		return nil, err
	}

	scopes := strings.Split(dbCode.Scopes, " ")
	if dbCode.Scopes == "" {
		scopes = []string{}
	}

	sess := &OAuthSession{
		Subject:   dbCode.UserID,
		Username:  dbCode.UserID,
		ExpiresAt: map[fosite.TokenType]time.Time{fosite.AuthorizeCode: dbCode.ExpiresAt},
	}

	form := make(map[string][]string)
	form["redirect_uri"] = []string{dbCode.RedirectUri}
	if dbCode.CodeChallenge.Valid {
		form["code_challenge"] = []string{dbCode.CodeChallenge.String}
	}
	if dbCode.CodeChallengeMethod.Valid {
		form["code_challenge_method"] = []string{dbCode.CodeChallengeMethod.String}
	}
	if dbCode.Nonce.Valid {
		form["nonce"] = []string{dbCode.Nonce.String}
	}

	req := &fosite.Request{
		ID:          code,
		RequestedAt: dbCode.CreatedAt,
		Client:      client,
		Form:        form,
		Session:     sess,
	}
	req.SetRequestedScopes(scopes)
	for _, scope := range scopes {
		req.GrantScope(scope)
	}
	return req, nil
}

func (s *OAuthStorage) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	return s.queries.DeleteAuthorizationCode(ctx, code)
}

// PKCERequestStorage implements fosite.PKCERequestStorage
func (s *OAuthStorage) GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.GetAuthorizeCodeSession(ctx, signature, session)
}

func (s *OAuthStorage) CreatePKCERequestSession(ctx context.Context, signature string, requester fosite.Requester) error {
	challenge := requester.GetRequestForm().Get("code_challenge")
	method := requester.GetRequestForm().Get("code_challenge_method")

	if challenge == "" {
		return nil
	}

	return s.queries.UpdateAuthorizationCodePKCE(ctx, oidc.UpdateAuthorizationCodePKCEParams{
		CodeChallenge: sql.NullString{
			String: challenge,
			Valid:  true,
		},
		CodeChallengeMethod: sql.NullString{
			String: method,
			Valid:  method != "",
		},
		Code: signature,
	})
}

func (s *OAuthStorage) DeletePKCERequestSession(ctx context.Context, signature string) error {
	return nil
}

// AccessTokenStorage implements fosite.AccessTokenStorage
func (s *OAuthStorage) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	sess, ok := request.GetSession().(*OAuthSession)
	if !ok {
		return errors.New("invalid session type")
	}

	tokenID := uuid.New()
	return s.queries.CreateToken(ctx, oidc.CreateTokenParams{
		ID:          tokenID.String(),
		ClientID:    request.GetClient().GetID(),
		UserID:      sess.Subject,
		AccessToken: signature,
		RefreshToken: sql.NullString{
			Valid: false,
		},
		Scopes:    strings.Join(request.GetGrantedScopes(), " "),
		ExpiresAt: sess.ExpiresAt[fosite.AccessToken],
	})
}

func (s *OAuthStorage) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	dbToken, err := s.queries.GetTokenByAccessToken(ctx, signature)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}

	if time.Now().After(dbToken.ExpiresAt) {
		return nil, fosite.ErrTokenExpired
	}

	client, err := s.GetClient(ctx, dbToken.ClientID)
	if err != nil {
		return nil, err
	}

	scopes := strings.Split(dbToken.Scopes, " ")
	if dbToken.Scopes == "" {
		scopes = []string{}
	}

	sess := &OAuthSession{
		Subject:   dbToken.UserID,
		Username:  dbToken.UserID,
		ExpiresAt: map[fosite.TokenType]time.Time{fosite.AccessToken: dbToken.ExpiresAt},
	}

	req := &fosite.Request{
		ID:          dbToken.ID,
		RequestedAt: dbToken.CreatedAt,
		Client:      client,
		Session:     sess,
	}
	req.SetRequestedScopes(scopes)
	for _, scope := range scopes {
		req.GrantScope(scope)
	}
	return req, nil
}

func (s *OAuthStorage) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return s.queries.DeleteTokenByAccessToken(ctx, signature)
}

// RefreshTokenStorage implements fosite.RefreshTokenStorage
func (s *OAuthStorage) CreateRefreshTokenSession(ctx context.Context, signature string, accessSignature string, request fosite.Requester) error {
	sess, ok := request.GetSession().(*OAuthSession)
	if !ok {
		return errors.New("invalid session type")
	}

	tokenID := uuid.New()
	return s.queries.CreateToken(ctx, oidc.CreateTokenParams{
		ID:          tokenID.String(),
		ClientID:    request.GetClient().GetID(),
		UserID:      sess.Subject,
		AccessToken: accessSignature,
		RefreshToken: sql.NullString{
			String: signature,
			Valid:  true,
		},
		Scopes:    strings.Join(request.GetGrantedScopes(), " "),
		ExpiresAt: sess.ExpiresAt[fosite.RefreshToken],
	})
}

func (s *OAuthStorage) RotateRefreshToken(ctx context.Context, requestID string, refreshTokenSignature string) error {
	return nil
}

func (s *OAuthStorage) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	dbToken, err := s.queries.GetTokenByRefreshToken(ctx, sql.NullString{String: signature, Valid: true})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}

	client, err := s.GetClient(ctx, dbToken.ClientID)
	if err != nil {
		return nil, err
	}

	scopes := strings.Split(dbToken.Scopes, " ")
	if dbToken.Scopes == "" {
		scopes = []string{}
	}

	sess := &OAuthSession{
		Subject:   dbToken.UserID,
		Username:  dbToken.UserID,
		ExpiresAt: map[fosite.TokenType]time.Time{fosite.RefreshToken: dbToken.ExpiresAt},
	}

	req := &fosite.Request{
		ID:          dbToken.ID,
		RequestedAt: dbToken.CreatedAt,
		Client:      client,
		Session:     sess,
	}
	req.SetRequestedScopes(scopes)
	for _, scope := range scopes {
		req.GrantScope(scope)
	}
	return req, nil
}

func (s *OAuthStorage) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return s.queries.DeleteTokenByRefreshToken(ctx, sql.NullString{String: signature, Valid: true})
}

func (s *OAuthStorage) RevokeRefreshToken(ctx context.Context, requestID string) error {
	return nil
}

func (s *OAuthStorage) RevokeRefreshTokenMaybeGracePeriod(ctx context.Context, requestID string, signature string) error {
	return s.DeleteRefreshTokenSession(ctx, signature)
}

func (s *OAuthStorage) RevokeAccessToken(ctx context.Context, requestID string) error {
	return nil
}

// OAuthClient implements fosite.Client
type OAuthClient struct {
	ID            string
	Secret        []byte
	RedirectURIs  []string
	GrantTypes    []string
	ResponseTypes []string
	Scopes        []string
	Public        bool
}

func (c *OAuthClient) GetID() string                   { return c.ID }
func (c *OAuthClient) GetHashedSecret() []byte         { return c.Secret }
func (c *OAuthClient) GetRedirectURIs() []string       { return c.RedirectURIs }
func (c *OAuthClient) GetGrantTypes() fosite.Arguments { return c.GrantTypes }
func (c *OAuthClient) GetResponseTypes() fosite.Arguments {
	if len(c.ResponseTypes) == 0 {
		return []string{"code"}
	}
	return c.ResponseTypes
}
func (c *OAuthClient) GetScopes() fosite.Arguments   { return c.Scopes }
func (c *OAuthClient) IsPublic() bool                { return c.Public }
func (c *OAuthClient) GetAudience() fosite.Arguments { return nil }

// OAuthSession implements fosite.Session
type OAuthSession struct {
	Subject   string
	Username  string
	ExpiresAt map[fosite.TokenType]time.Time
	Extra     map[string]interface{}
}

func NewOAuthSession(subject string) *OAuthSession {
	return &OAuthSession{
		Subject:   subject,
		Username:  subject,
		ExpiresAt: make(map[fosite.TokenType]time.Time),
		Extra:     make(map[string]interface{}),
	}
}

func (s *OAuthSession) SetExpiresAt(key fosite.TokenType, exp time.Time) {
	if s.ExpiresAt == nil {
		s.ExpiresAt = make(map[fosite.TokenType]time.Time)
	}
	s.ExpiresAt[key] = exp
}

func (s *OAuthSession) GetExpiresAt(key fosite.TokenType) time.Time {
	if s.ExpiresAt == nil {
		return time.Time{}
	}
	return s.ExpiresAt[key]
}

func (s *OAuthSession) GetUsername() string { return s.Username }
func (s *OAuthSession) GetSubject() string  { return s.Subject }

func (s *OAuthSession) Clone() fosite.Session {
	expiresAt := make(map[fosite.TokenType]time.Time)
	for k, v := range s.ExpiresAt {
		expiresAt[k] = v
	}
	extra := make(map[string]interface{})
	for k, v := range s.Extra {
		extra[k] = v
	}
	return &OAuthSession{
		Subject:   s.Subject,
		Username:  s.Username,
		ExpiresAt: expiresAt,
		Extra:     extra,
	}
}

// ValidateClientSecret validates the client secret using bcrypt
func ValidateClientSecret(hashedSecret []byte, secret string) bool {
	return bcrypt.CompareHashAndPassword(hashedSecret, []byte(secret)) == nil
}
