package v1

import (
	"context"
	"encoding/json"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/traPtitech/portal-oidc/pkg/domain"
	mariadb "github.com/traPtitech/portal-oidc/pkg/infrastructure/mariadb/v1/gen"
)

func convertToDomainClient(client *mariadb.Client) (domain.Client, error) {
	redirectURIs := []string{}
	err := json.Unmarshal(client.RedirectUris, &redirectURIs)
	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to unmarshal redirect uris")
	}

	clientID, err := uuid.Parse(client.ID)
	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to parse client id")
	}

	return domain.Client{
		ID:           domain.ClientID(clientID),
		UserID:       domain.TrapID(client.UserID),
		Type:         domain.ClientType(client.Type),
		Name:         client.Name,
		Description:  client.Description,
		Secret:       client.SecretKey,
		RedirectURIs: redirectURIs,
	}, nil
}

func (r *MariaDBRepository) CreateOIDCClient(ctx context.Context, id uuid.UUID, userID domain.TrapID, typ domain.ClientType, name string, desc string, secret string, redirectURIs []string) (domain.Client, error) {
	encURLs, err := json.Marshal(redirectURIs)
	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to marshal redirect uris")
	}

	err = r.q.CreateClient(ctx, mariadb.CreateClientParams{
		ID:           id.String(),
		UserID:       userID.String(),
		Type:         typ.String(),
		Name:         name,
		Description:  desc,
		SecretKey:    secret,
		RedirectUris: encURLs,
	})

	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to create client")
	}

	client, err := r.q.GetClient(ctx, id.String())
	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to get client")
	}

	return convertToDomainClient(&client)
}

func (r *MariaDBRepository) GetOIDCClient(ctx context.Context, id domain.ClientID) (domain.Client, error) {
	client, err := r.q.GetClient(ctx, id.String())

	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to get client")
	}

	return convertToDomainClient(&client)
}

func (r *MariaDBRepository) ListOIDCClientsByUser(ctx context.Context, userID domain.TrapID) ([]domain.Client, error) {

	clients, err := r.q.ListClientsByUserID(ctx, userID.String())

	if err != nil {
		return nil, errors.Wrap(err, "Failed to get clients")
	}

	clientList := make([]domain.Client, len(clients))
	for i, client := range clients {

		c, err := convertToDomainClient(&client)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to convert client")
		}

		clientList[i] = c
	}

	return clientList, nil
}

func (r *MariaDBRepository) UpdateOIDCClient(ctx context.Context, id domain.ClientID, userID domain.TrapID, typ domain.ClientType, name string, desc string, redirectURIs []string) (domain.Client, error) {
	encURLs, err := json.Marshal(redirectURIs)
	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to marshal redirect uris")
	}

	err = r.q.UpdateClient(ctx, mariadb.UpdateClientParams{
		ID:           id.String(),
		Type:         typ.String(),
		Name:         name,
		Description:  desc,
		RedirectUris: encURLs,
	})

	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to update client")
	}

	newclient, err := r.q.GetClient(ctx, id.String())

	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to get client")
	}

	return convertToDomainClient(&newclient)
}

func (r *MariaDBRepository) UpdateOIDCClientSecret(ctx context.Context, id domain.ClientID, secret string) (domain.Client, error) {
	err := r.q.UpdateClientSecret(ctx, mariadb.UpdateClientSecretParams{
		ID:        id.String(),
		SecretKey: secret,
	})

	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to update client secret")
	}

	newclient, err := r.q.GetClient(ctx, id.String())

	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to get client")
	}

	return convertToDomainClient(&newclient)

}

func (r *MariaDBRepository) DeleteOIDCClient(ctx context.Context, id domain.ClientID) error {
	err := r.q.DeleteClient(ctx, id.String())

	if err != nil {
		return errors.Wrap(err, "Failed to delete client")
	}

	return nil

}

func (r *MariaDBRepository) GetBlacklistJTI(ctx context.Context, jti string) (domain.BlacklistedJTI, error) {
	blacklistedJTI, err := r.q.GetBlacklistJTI(ctx, jti)
	if err != nil {
		return domain.BlacklistedJTI{}, errors.Wrap(err, "Failed to get blacklisted JTI")
	}

	return domain.BlacklistedJTI{
		JTI:   blacklistedJTI.Jti,
		After: blacklistedJTI.After,
	}, nil
}

func (r *MariaDBRepository) AddBlacklistJTI(ctx context.Context, blacklistedJTI domain.BlacklistedJTI) error {
	if err := r.q.AddBlacklistJTI(ctx, mariadb.AddBlacklistJTIParams{
		Jti:   blacklistedJTI.JTI,
		After: blacklistedJTI.After,
	}); err != nil {
		return errors.Wrap(err, "Failed to add blacklisted JTI")
	}

	return nil
}

func (r *MariaDBRepository) DeleteOldBlacklistJTI(ctx context.Context) error {
	if err := r.q.DeleteOldBlacklistJTI(ctx); err != nil {
		return errors.Wrap(err, "Failed to delete old blacklisted JTI")
	}

	return nil
}

func (r *MariaDBRepository) CreateBlacklistJTI(ctx context.Context, jti string, after time.Time) error {
	if err := r.q.CreateBlacklistJTI(ctx, mariadb.CreateBlacklistJTIParams{
		Jti:   jti,
		After: after,
	}); err != nil {
		return errors.Wrap(err, "Failed to create blacklisted JTI")
	}

	return nil
}

func (r *MariaDBRepository) CreateAccessTokenSession(ctx context.Context, req *fosite.Request) error {
	encRequestedScopes, err := json.Marshal(req.GetRequestedScopes())
	if err != nil {
		return errors.Wrap(err, "Failed to marshal requested scopes")
	}
	encGrantedScopes, err := json.Marshal(req.GetGrantedScopes())
	if err != nil {
		return errors.Wrap(err, "Failed to marshal granted scopes")
	}
	encForm, err := json.Marshal(req.GetRequestForm())
	if err != nil {
		return errors.Wrap(err, "Failed to marshal form data")
	}
	encRequestedAudience, err := json.Marshal(req.GetRequestedAudience())
	if err != nil {
		return errors.Wrap(err, "Failed to marshal requested audience")
	}
	encGrantedAudience, err := json.Marshal(req.GetGrantedAudience())
	if err != nil {
		return errors.Wrap(err, "Failed to marshal granted audience")
	}

	if err := r.q.CreateAccessTokenSession(ctx, mariadb.CreateAccessTokenSessionParams{
		ID:                req.GetID(),
		Signature:         req.ID,
		TokenType:         uint8(domain.TokenTypeAccessToken),
		ClientID:          req.GetClient().GetID(),
		UserID:            req.GetSession().GetSubject(),
		RequestedScope:    encRequestedScopes,
		GrantedScope:      encGrantedScopes,
		FormData:          encForm,
		ExpiredAt:         req.GetSession().GetExpiresAt(fosite.AccessToken),
		Username:          req.GetSession().GetUsername(),
		Subject:           req.GetSession().GetSubject(),
		Active:            true,
		RequestedAudience: encRequestedAudience,
		GrantedAudience:   encGrantedAudience,
	}); err != nil {
		return errors.Wrap(err, "Failed to create access token session")
	}
	return nil
}

func (r *MariaDBRepository) CreateRefreshTokenSession(ctx context.Context, req *fosite.Request) error {
	encRequestedScopes, err := json.Marshal(req.GetRequestedScopes())
	if err != nil {
		return errors.Wrap(err, "Failed to marshal requested scopes")
	}
	encGrantedScopes, err := json.Marshal(req.GetGrantedScopes())
	if err != nil {
		return errors.Wrap(err, "Failed to marshal granted scopes")
	}
	encForm, err := json.Marshal(req.GetRequestForm())
	if err != nil {
		return errors.Wrap(err, "Failed to marshal form data")
	}
	encRequestedAudience, err := json.Marshal(req.GetRequestedAudience())
	if err != nil {
		return errors.Wrap(err, "Failed to marshal requested audience")
	}
	encGrantedAudience, err := json.Marshal(req.GetGrantedAudience())
	if err != nil {
		return errors.Wrap(err, "Failed to marshal granted audience")
	}

	if err := r.q.CreateRefreshTokenSession(ctx, mariadb.CreateRefreshTokenSessionParams{
		ID:                req.GetID(),
		Signature:         req.ID,
		TokenType:         uint8(domain.TokenTypeRefreshToken),
		ClientID:          req.GetClient().GetID(),
		UserID:            req.GetSession().GetSubject(),
		RequestedScope:    encRequestedScopes,
		GrantedScope:      encGrantedScopes,
		FormData:          encForm,
		ExpiredAt:         req.GetSession().GetExpiresAt(fosite.RefreshToken),
		Username:          req.GetSession().GetUsername(),
		Subject:           req.GetSession().GetSubject(),
		Active:            true,
		RequestedAudience: encRequestedAudience,
		GrantedAudience:   encGrantedAudience,
	}); err != nil {
		return errors.Wrap(err, "Failed to create refresh token session")
	}
	return nil
}

func (r *MariaDBRepository) CreateAuthorizeCodeSession(ctx context.Context, code string, req *fosite.Request) error {
	encRequestedScopes, err := json.Marshal(req.GetRequestedScopes())
	if err != nil {
		return errors.Wrap(err, "Failed to marshal requested scopes")
	}
	encGrantedScopes, err := json.Marshal(req.GetGrantedScopes())
	if err != nil {
		return errors.Wrap(err, "Failed to marshal granted scopes")
	}
	encForm, err := json.Marshal(req.GetRequestForm())
	if err != nil {
		return errors.Wrap(err, "Failed to marshal form data")
	}
	encRequestedAudience, err := json.Marshal(req.GetRequestedAudience())
	if err != nil {
		return errors.Wrap(err, "Failed to marshal requested audience")
	}
	encGrantedAudience, err := json.Marshal(req.GetGrantedAudience())
	if err != nil {
		return errors.Wrap(err, "Failed to marshal granted audience")
	}

	if err := r.q.CreateAuthorizeCodeSession(ctx, mariadb.CreateAuthorizeCodeSessionParams{
		ID:                req.GetID(),
		Code:              code,
		TokenType:         uint8(domain.TokenTypeAuthorizeCode),
		ClientID:          req.GetClient().GetID(),
		UserID:            req.GetSession().GetSubject(),
		RequestedScope:    encRequestedScopes,
		GrantedScope:      encGrantedScopes,
		FormData:          encForm,
		ExpiredAt:         req.GetSession().GetExpiresAt(fosite.AuthorizeCode),
		Username:          req.GetSession().GetUsername(),
		Subject:           req.GetSession().GetSubject(),
		Active:            true,
		RequestedAudience: encRequestedAudience,
		GrantedAudience:   encGrantedAudience,
	}); err != nil {
		return errors.Wrap(err, "Failed to create authorization code session")
	}
	return nil
}

func (r *MariaDBRepository) CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, req *fosite.Request) error {
	encRequestedScopes, err := json.Marshal(req.GetRequestedScopes())
	if err != nil {
		return errors.Wrap(err, "Failed to marshal requested scopes")
	}
	encGrantedScopes, err := json.Marshal(req.GetGrantedScopes())
	if err != nil {
		return errors.Wrap(err, "Failed to marshal granted scopes")
	}
	encForm, err := json.Marshal(req.GetRequestForm())
	if err != nil {
		return errors.Wrap(err, "Failed to marshal form data")
	}
	encRequestedAudience, err := json.Marshal(req.GetRequestedAudience())
	if err != nil {
		return errors.Wrap(err, "Failed to marshal requested audience")
	}
	encGrantedAudience, err := json.Marshal(req.GetGrantedAudience())
	if err != nil {
		return errors.Wrap(err, "Failed to marshal granted audience")
	}

	if err := r.q.CreateOpenIDConnectSession(ctx, mariadb.CreateOpenIDConnectSessionParams{
		ID:                req.GetID(),
		AuthorizeCode:     req.ID,
		TokenType:         uint8(domain.TokenTypeOpenIDConnectSession),
		ClientID:          req.GetClient().GetID(),
		UserID:            req.GetSession().GetSubject(),
		RequestedScope:    encRequestedScopes,
		GrantedScope:      encGrantedScopes,
		FormData:          encForm,
		ExpiredAt:         req.GetSession().GetExpiresAt(fosite.IDToken),
		Username:          req.GetSession().GetUsername(),
		Subject:           req.GetSession().GetSubject(),
		Active:            true,
		RequestedAudience: encRequestedAudience,
		GrantedAudience:   encGrantedAudience,
	}); err != nil {
		return errors.Wrap(err, "Failed to create OpenID Connect session")
	}
	return nil
}

func (r *MariaDBRepository) CreatePKCERequestSession(ctx context.Context, code string, req *fosite.Request) error {
	encRequestedScopes, err := json.Marshal(req.GetRequestedScopes())
	if err != nil {
		return errors.Wrap(err, "Failed to marshal requested scopes")
	}
	encGrantedScopes, err := json.Marshal(req.GetGrantedScopes())
	if err != nil {
		return errors.Wrap(err, "Failed to marshal granted scopes")
	}
	encForm, err := json.Marshal(req.GetRequestForm())
	if err != nil {
		return errors.Wrap(err, "Failed to marshal form data")
	}
	encRequestedAudience, err := json.Marshal(req.GetRequestedAudience())
	if err != nil {
		return errors.Wrap(err, "Failed to marshal requested audience")
	}
	encGrantedAudience, err := json.Marshal(req.GetGrantedAudience())
	if err != nil {
		return errors.Wrap(err, "Failed to marshal granted audience")
	}

	if err := r.q.CreatePKCERequestSession(ctx, mariadb.CreatePKCERequestSessionParams{
		ID:                req.GetID(),
		Code:              code,
		TokenType:         uint8(domain.TokenTypePKCERequestSession),
		ClientID:          req.GetClient().GetID(),
		UserID:            req.GetSession().GetSubject(),
		RequestedScope:    encRequestedScopes,
		GrantedScope:      encGrantedScopes,
		FormData:          encForm,
		ExpiredAt:         req.GetSession().GetExpiresAt(fosite.AccessToken),
		Username:          req.GetSession().GetUsername(),
		Subject:           req.GetSession().GetSubject(),
		Active:            true,
		RequestedAudience: encRequestedAudience,
		GrantedAudience:   encGrantedAudience,
	}); err != nil {
		return errors.Wrap(err, "Failed to create PKCE request session")
	}
	return nil
}

type sessionRecord struct {
	ID                string
	ClientID          string
	RequestedScope    json.RawMessage
	GrantedScope      json.RawMessage
	FormData          json.RawMessage
	RequestedAudience json.RawMessage
	GrantedAudience   json.RawMessage
	Username          string
	Subject           string
	ExpiredAt         time.Time
	CreatedAt         time.Time
}

func (r *MariaDBRepository) buildFositeRequestFromRecord(ctx context.Context, record sessionRecord, tokenType domain.TokenType) (*fosite.Request, error) {
	requestedScopes := []string{}
	if len(record.RequestedScope) != 0 {
		if err := json.Unmarshal(record.RequestedScope, &requestedScopes); err != nil {
			return nil, errors.Wrap(err, "Failed to unmarshal requested scopes")
		}
	}
	grantedScopes := []string{}
	if len(record.GrantedScope) != 0 {
		if err := json.Unmarshal(record.GrantedScope, &grantedScopes); err != nil {
			return nil, errors.Wrap(err, "Failed to unmarshal granted scopes")
		}
	}
	form := map[string][]string{}
	if len(record.FormData) != 0 {
		if err := json.Unmarshal(record.FormData, &form); err != nil {
			return nil, errors.Wrap(err, "Failed to unmarshal form data")
		}
	}
	requestedAudience := []string{}
	if len(record.RequestedAudience) != 0 {
		if err := json.Unmarshal(record.RequestedAudience, &requestedAudience); err != nil {
			return nil, errors.Wrap(err, "Failed to unmarshal requested audience")
		}
	}
	grantedAudience := []string{}
	if len(record.GrantedAudience) != 0 {
		if err := json.Unmarshal(record.GrantedAudience, &grantedAudience); err != nil {
			return nil, errors.Wrap(err, "Failed to unmarshal granted audience")
		}
	}

	clientID, err := domain.ParseClientID(record.ClientID)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse client id")
	}

	client, err := r.GetOIDCClient(ctx, clientID)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to get client")
	}

	return &fosite.Request{
		ID:          record.ID,
		RequestedAt: record.CreatedAt,
		Client: &fosite.DefaultClient{
			ID:            client.ID.String(),
			Secret:        []byte(client.Secret),
			RedirectURIs:  client.RedirectURIs,
			GrantTypes:    []string{"refresh_token", "authorization_code"},
			ResponseTypes: []string{"code", "code id_token"},
		},
		RequestedScope: requestedScopes,
		GrantedScope:   grantedScopes,
		Form:           form,
		Session: &fosite.DefaultSession{
			Subject:   record.Subject,
			Username:  record.Username,
			ExpiresAt: map[fosite.TokenType]time.Time{fositeTokenType(tokenType): record.ExpiredAt},
		},
		RequestedAudience: requestedAudience,
		GrantedAudience:   grantedAudience,
	}, nil
}

func fositeTokenType(tokenType domain.TokenType) fosite.TokenType {
	switch tokenType {
	case domain.TokenTypeAccessToken:
		return fosite.AccessToken
	case domain.TokenTypeRefreshToken:
		return fosite.RefreshToken
	case domain.TokenTypeAuthorizeCode:
		return fosite.AuthorizeCode
	case domain.TokenTypeOpenIDConnectSession:
		return fosite.IDToken
	case domain.TokenTypePKCERequestSession:
		return fosite.AccessToken
	default:
		return fosite.AccessToken
	}
}

func (r *MariaDBRepository) GetAccessToken(ctx context.Context, signature string) (*fosite.Request, error) {
	session, err := r.q.GetAccessToken(ctx, signature)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to get access token session")
	}

	return r.buildFositeRequestFromRecord(ctx, sessionRecord{
		ID:                session.ID,
		ClientID:          session.ClientID,
		RequestedScope:    session.RequestedScope,
		GrantedScope:      session.GrantedScope,
		FormData:          session.FormData,
		RequestedAudience: session.RequestedAudience,
		GrantedAudience:   session.GrantedAudience,
		Username:          session.Username,
		Subject:           session.Subject,
		ExpiredAt:         session.ExpiredAt,
		CreatedAt:         session.CreatedAt,
	}, domain.TokenTypeAccessToken)
}

func (r *MariaDBRepository) GetRefreshToken(ctx context.Context, signature string) (*fosite.Request, error) {
	session, err := r.q.GetRefreshToken(ctx, signature)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to get refresh token session")
	}

	return r.buildFositeRequestFromRecord(ctx, sessionRecord{
		ID:                session.ID,
		ClientID:          session.ClientID,
		RequestedScope:    session.RequestedScope,
		GrantedScope:      session.GrantedScope,
		FormData:          session.FormData,
		RequestedAudience: session.RequestedAudience,
		GrantedAudience:   session.GrantedAudience,
		Username:          session.Username,
		Subject:           session.Subject,
		ExpiredAt:         session.ExpiredAt,
		CreatedAt:         session.CreatedAt,
	}, domain.TokenTypeRefreshToken)
}

func (r *MariaDBRepository) GetAuthorizeCodeSession(ctx context.Context, signature string) (*fosite.Request, error) {
	session, err := r.q.GetAuthorizeCodeSession(ctx, signature)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to get authorization code session")
	}

	return r.buildFositeRequestFromRecord(ctx, sessionRecord{
		ID:                session.ID,
		ClientID:          session.ClientID,
		RequestedScope:    session.RequestedScope,
		GrantedScope:      session.GrantedScope,
		FormData:          session.FormData,
		RequestedAudience: session.RequestedAudience,
		GrantedAudience:   session.GrantedAudience,
		Username:          session.Username,
		Subject:           session.Subject,
		ExpiredAt:         session.ExpiredAt,
		CreatedAt:         session.CreatedAt,
	}, domain.TokenTypeAuthorizeCode)
}

func (r *MariaDBRepository) GetOpenIDConnectSession(ctx context.Context, signature string) (*fosite.Request, error) {
	session, err := r.q.GetOpenIDConnectSession(ctx, signature)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to get OpenID Connect session")
	}

	return r.buildFositeRequestFromRecord(ctx, sessionRecord{
		ID:                session.ID,
		ClientID:          session.ClientID,
		RequestedScope:    session.RequestedScope,
		GrantedScope:      session.GrantedScope,
		FormData:          session.FormData,
		RequestedAudience: session.RequestedAudience,
		GrantedAudience:   session.GrantedAudience,
		Username:          session.Username,
		Subject:           session.Subject,
		ExpiredAt:         session.ExpiredAt,
		CreatedAt:         session.CreatedAt,
	}, domain.TokenTypeOpenIDConnectSession)
}

func (r *MariaDBRepository) GetPKCERequestSession(ctx context.Context, signature string) (*fosite.Request, error) {
	session, err := r.q.GetPKCERequestSession(ctx, signature)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to get PKCE request session")
	}

	return r.buildFositeRequestFromRecord(ctx, sessionRecord{
		ID:                session.ID,
		ClientID:          session.ClientID,
		RequestedScope:    session.RequestedScope,
		GrantedScope:      session.GrantedScope,
		FormData:          session.FormData,
		RequestedAudience: session.RequestedAudience,
		GrantedAudience:   session.GrantedAudience,
		Username:          session.Username,
		Subject:           session.Subject,
		ExpiredAt:         session.ExpiredAt,
		CreatedAt:         session.CreatedAt,
	}, domain.TokenTypePKCERequestSession)
}

func (r *MariaDBRepository) RevokeAccessTokenByID(ctx context.Context, requestID string) error {
	if err := r.q.RevokeAccessTokenByID(ctx, requestID); err != nil {
		return errors.Wrap(err, "Failed to revoke access token session")
	}
	return nil
}

func (r *MariaDBRepository) RevokeAccessTokenBySignature(ctx context.Context, signature string) error {
	if err := r.q.RevokeAccessTokenBySignature(ctx, signature); err != nil {
		return errors.Wrap(err, "Failed to revoke access token session")
	}
	return nil
}

func (r *MariaDBRepository) RevokeRefreshTokenByID(ctx context.Context, requestID string) error {
	if err := r.q.RevokeRefreshTokenByID(ctx, requestID); err != nil {
		return errors.Wrap(err, "Failed to revoke refresh token session")
	}
	return nil
}

func (r *MariaDBRepository) RevokeRefreshTokenBySignature(ctx context.Context, signature string) error {
	if err := r.q.RevokeRefreshTokenBySignature(ctx, signature); err != nil {
		return errors.Wrap(err, "Failed to revoke refresh token session")
	}
	return nil
}

func (r *MariaDBRepository) RevokeAuthorizeCodeSession(ctx context.Context, code string) error {
	if err := r.q.RevokeAuthorizeCodeSession(ctx, code); err != nil {
		return errors.Wrap(err, "Failed to revoke authorization code session")
	}
	return nil
}

func (r *MariaDBRepository) RevokeOpenIDConnectSession(ctx context.Context, signature string) error {
	if err := r.q.RevokeOpenIDConnectSession(ctx, signature); err != nil {
		return errors.Wrap(err, "Failed to revoke OpenID Connect session")
	}
	return nil
}

func (r *MariaDBRepository) RevokePKCERequestSession(ctx context.Context, signature string) error {
	if err := r.q.RevokePKCERequestSession(ctx, signature); err != nil {
		return errors.Wrap(err, "Failed to revoke PKCE request session")
	}
	return nil
}
