package v1

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/ory/x/stringsx"
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

func (r *MariaDBRepository) CreateAccessTokenSession(ctx context.Context, signature string, req *fosite.Request) error {
	encRequestedScopes := strings.Join(req.GetRequestedScopes(), "|")

	encGrantedScopes := strings.Join(req.GetGrantedScopes(), "|")

	encForm := req.GetRequestForm().Encode()

	encRequestedAudience := strings.Join(req.GetRequestedAudience(), "|")

	encGrantedAudience := strings.Join(req.GetGrantedAudience(), "|")

	encSession, err := json.Marshal(req.GetSession())
	if err != nil {
		return errors.Wrap(err, "Failed to marshal session data")
	}

	if err := r.q.CreateAccessTokenSession(ctx, mariadb.CreateAccessTokenSessionParams{
		ID:                req.GetID(),
		Signature:         signature,
		RequestedAt:       req.GetRequestedAt(),
		TokenType:         uint8(domain.TokenTypeAccessToken),
		ClientID:          req.GetClient().GetID(),
		UserID:            req.GetSession().GetSubject(),
		RequestedScope:    encRequestedScopes,
		GrantedScope:      encGrantedScopes,
		FormData:          encForm,
		SessionData:       encSession,
		Active:            true,
		RequestedAudience: encRequestedAudience,
		GrantedAudience:   encGrantedAudience,
	}); err != nil {
		return errors.Wrap(err, "Failed to create access token session")
	}
	return nil
}

func (r *MariaDBRepository) CreateRefreshTokenSession(ctx context.Context, signature string, req *fosite.Request) error {
	encRequestedScopes := strings.Join(req.GetRequestedScopes(), "|")

	encGrantedScopes := strings.Join(req.GetGrantedScopes(), "|")

	encForm := req.GetRequestForm().Encode()

	encRequestedAudience := strings.Join(req.GetRequestedAudience(), "|")

	encGrantedAudience := strings.Join(req.GetGrantedAudience(), "|")

	encSession, err := json.Marshal(req.GetSession())
	if err != nil {
		return errors.Wrap(err, "Failed to marshal session data")
	}

	if err := r.q.CreateRefreshTokenSession(ctx, mariadb.CreateRefreshTokenSessionParams{
		ID:                req.GetID(),
		Signature:         signature,
		RequestedAt:       req.GetRequestedAt(),
		TokenType:         uint8(domain.TokenTypeRefreshToken),
		ClientID:          req.GetClient().GetID(),
		UserID:            req.GetSession().GetSubject(),
		RequestedScope:    encRequestedScopes,
		GrantedScope:      encGrantedScopes,
		FormData:          encForm,
		SessionData:       encSession,
		Active:            true,
		RequestedAudience: encRequestedAudience,
		GrantedAudience:   encGrantedAudience,
	}); err != nil {
		return errors.Wrap(err, "Failed to create refresh token session")
	}
	return nil
}

func (r *MariaDBRepository) CreateAuthorizeCodeSession(ctx context.Context, code string, req *fosite.Request) error {
	encRequestedScopes := strings.Join(req.GetRequestedScopes(), "|")

	encGrantedScopes := strings.Join(req.GetGrantedScopes(), "|")

	encForm := req.GetRequestForm().Encode()

	encRequestedAudience := strings.Join(req.GetRequestedAudience(), "|")

	encGrantedAudience := strings.Join(req.GetGrantedAudience(), "|")

	encSession, err := json.Marshal(req.GetSession())
	if err != nil {
		return errors.Wrap(err, "Failed to marshal session data")
	}

	if err := r.q.CreateAuthorizeCodeSession(ctx, mariadb.CreateAuthorizeCodeSessionParams{
		ID:                req.GetID(),
		Code:              code,
		RequestedAt:       req.GetRequestedAt(),
		TokenType:         uint8(domain.TokenTypeAuthorizeCode),
		ClientID:          req.GetClient().GetID(),
		UserID:            req.GetSession().GetSubject(),
		RequestedScope:    encRequestedScopes,
		GrantedScope:      encGrantedScopes,
		FormData:          encForm,
		SessionData:       encSession,
		Active:            true,
		RequestedAudience: encRequestedAudience,
		GrantedAudience:   encGrantedAudience,
	}); err != nil {
		return errors.Wrap(err, "Failed to create authorization code session")
	}
	return nil
}

func (r *MariaDBRepository) CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, req *fosite.Request) error {
	encRequestedScopes := strings.Join(req.GetRequestedScopes(), "|")

	encGrantedScopes := strings.Join(req.GetGrantedScopes(), "|")

	encForm := req.GetRequestForm().Encode()

	encRequestedAudience := strings.Join(req.GetRequestedAudience(), "|")

	encGrantedAudience := strings.Join(req.GetGrantedAudience(), "|")

	encSession, err := json.Marshal(req.GetSession())
	if err != nil {
		return errors.Wrap(err, "Failed to marshal session data")
	}

	if err := r.q.CreateOpenIDConnectSession(ctx, mariadb.CreateOpenIDConnectSessionParams{
		ID:                req.GetID(),
		AuthorizeCode:     authorizeCode,
		RequestedAt:       req.GetRequestedAt(),
		TokenType:         uint8(domain.TokenTypeOpenIDConnectSession),
		ClientID:          req.GetClient().GetID(),
		UserID:            req.GetSession().GetSubject(),
		RequestedScope:    encRequestedScopes,
		GrantedScope:      encGrantedScopes,
		FormData:          encForm,
		SessionData:       encSession,
		Active:            true,
		RequestedAudience: encRequestedAudience,
		GrantedAudience:   encGrantedAudience,
	}); err != nil {
		return errors.Wrap(err, "Failed to create OpenID Connect session")
	}
	return nil
}

func (r *MariaDBRepository) CreatePKCERequestSession(ctx context.Context, code string, req *fosite.Request) error {
	encRequestedScopes := strings.Join(req.GetRequestedScopes(), "|")

	encGrantedScopes := strings.Join(req.GetGrantedScopes(), "|")

	encForm := req.GetRequestForm().Encode()

	encRequestedAudience := strings.Join(req.GetRequestedAudience(), "|")

	encGrantedAudience := strings.Join(req.GetGrantedAudience(), "|")

	encSession, err := json.Marshal(req.GetSession())
	if err != nil {
		return errors.Wrap(err, "Failed to marshal session data")
	}

	if err := r.q.CreatePKCERequestSession(ctx, mariadb.CreatePKCERequestSessionParams{
		ID:                req.GetID(),
		Code:              code,
		RequestedAt:       req.GetRequestedAt(),
		TokenType:         uint8(domain.TokenTypePKCERequestSession),
		ClientID:          req.GetClient().GetID(),
		UserID:            req.GetSession().GetSubject(),
		RequestedScope:    encRequestedScopes,
		GrantedScope:      encGrantedScopes,
		FormData:          encForm,
		SessionData:       encSession,
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
	RequestedAt       time.Time
	RequestedScope    string
	GrantedScope      string
	FormData          string
	RequestedAudience string
	GrantedAudience   string
	SessionData       json.RawMessage
}

func (r *MariaDBRepository) buildFositeRequestFromRecord(ctx context.Context, record sessionRecord, session fosite.Session) (*fosite.Request, error) {

	clientID, err := domain.ParseClientID(record.ClientID)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse client id")
	}

	client, err := r.GetOIDCClient(ctx, clientID)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to get client")
	}

	if session != nil {
		if err := json.Unmarshal(record.SessionData, session); err != nil {
			return nil, errors.WithStack(err)
		}
	}

	form, err := url.ParseQuery(record.FormData)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse form data")
	}

	return &fosite.Request{
		ID:          record.ID,
		RequestedAt: record.RequestedAt,
		Client: &fosite.DefaultClient{
			ID:            client.ID.String(),
			Secret:        []byte(client.Secret),
			RedirectURIs:  client.RedirectURIs,
			GrantTypes:    []string{"refresh_token", "authorization_code"},
			ResponseTypes: []string{"code", "code id_token"},
		},
		RequestedScope:    stringsx.Splitx(record.RequestedScope, "|"),
		GrantedScope:      stringsx.Splitx(record.GrantedScope, "|"),
		Form:              form,
		Session:           session,
		RequestedAudience: stringsx.Splitx(record.RequestedAudience, "|"),
		GrantedAudience:   stringsx.Splitx(record.GrantedAudience, "|"),
	}, nil
}

func (r *MariaDBRepository) GetAccessToken(ctx context.Context, signature string, session fosite.Session) (*fosite.Request, error) {
	accessToken, err := r.q.GetAccessToken(ctx, signature)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to get access token session")
	}

	return r.buildFositeRequestFromRecord(ctx, sessionRecord{
		ID:                accessToken.ID,
		ClientID:          accessToken.ClientID,
		RequestedAt:       accessToken.RequestedAt,
		RequestedScope:    accessToken.RequestedScope,
		GrantedScope:      accessToken.GrantedScope,
		FormData:          accessToken.FormData,
		RequestedAudience: accessToken.RequestedAudience,
		GrantedAudience:   accessToken.GrantedAudience,
		SessionData:       accessToken.SessionData,
	}, session)
}

func (r *MariaDBRepository) GetRefreshToken(ctx context.Context, signature string, session fosite.Session) (*fosite.Request, error) {
	refreshToken, err := r.q.GetRefreshToken(ctx, signature)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to get refresh token session")
	}

	return r.buildFositeRequestFromRecord(ctx, sessionRecord{
		ID:                refreshToken.ID,
		ClientID:          refreshToken.ClientID,
		RequestedAt:       refreshToken.RequestedAt,
		RequestedScope:    refreshToken.RequestedScope,
		GrantedScope:      refreshToken.GrantedScope,
		FormData:          refreshToken.FormData,
		RequestedAudience: refreshToken.RequestedAudience,
		GrantedAudience:   refreshToken.GrantedAudience,
		SessionData:       refreshToken.SessionData,
	}, session)
}

func (r *MariaDBRepository) GetAuthorizeCodeSession(ctx context.Context, signature string, session fosite.Session) (*fosite.Request, error) {
	authorizeCodeSession, err := r.q.GetAuthorizeCodeSession(ctx, signature)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to get authorization code session")
	}

	return r.buildFositeRequestFromRecord(ctx, sessionRecord{
		ID:                authorizeCodeSession.ID,
		ClientID:          authorizeCodeSession.ClientID,
		RequestedAt:       authorizeCodeSession.RequestedAt,
		RequestedScope:    authorizeCodeSession.RequestedScope,
		GrantedScope:      authorizeCodeSession.GrantedScope,
		FormData:          authorizeCodeSession.FormData,
		RequestedAudience: authorizeCodeSession.RequestedAudience,
		GrantedAudience:   authorizeCodeSession.GrantedAudience,
		SessionData:       authorizeCodeSession.SessionData,
	}, session)
}

func (r *MariaDBRepository) GetOpenIDConnectSession(ctx context.Context, signature string, session fosite.Session) (*fosite.Request, error) {
	openIDConnectSession, err := r.q.GetOpenIDConnectSession(ctx, signature)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to get OpenID Connect session")
	}

	return r.buildFositeRequestFromRecord(ctx, sessionRecord{
		ID:                openIDConnectSession.ID,
		ClientID:          openIDConnectSession.ClientID,
		RequestedAt:       openIDConnectSession.RequestedAt,
		RequestedScope:    openIDConnectSession.RequestedScope,
		GrantedScope:      openIDConnectSession.GrantedScope,
		FormData:          openIDConnectSession.FormData,
		RequestedAudience: openIDConnectSession.RequestedAudience,
		GrantedAudience:   openIDConnectSession.GrantedAudience,
		SessionData:       openIDConnectSession.SessionData,
	}, session)
}

func (r *MariaDBRepository) GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (*fosite.Request, error) {
	pkceRequestSession, err := r.q.GetPKCERequestSession(ctx, signature)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to get PKCE request session")
	}

	return r.buildFositeRequestFromRecord(ctx, sessionRecord{
		ID:                pkceRequestSession.ID,
		ClientID:          pkceRequestSession.ClientID,
		RequestedAt:       pkceRequestSession.RequestedAt,
		RequestedScope:    pkceRequestSession.RequestedScope,
		GrantedScope:      pkceRequestSession.GrantedScope,
		FormData:          pkceRequestSession.FormData,
		RequestedAudience: pkceRequestSession.RequestedAudience,
		GrantedAudience:   pkceRequestSession.GrantedAudience,
		SessionData:       pkceRequestSession.SessionData,
	}, session)
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
