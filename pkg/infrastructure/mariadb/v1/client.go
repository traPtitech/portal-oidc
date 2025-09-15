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

	if err := r.q.CreateAccessToken(ctx, mariadb.CreateAccessTokenParams{
		ID:                req.GetID(),
		Signature:         req.ID,
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
		return errors.Wrap(err, "Failed to create access token")
	}

	return nil
}

func (r *MariaDBRepository) GetAccessTokenSession(ctx context.Context, signature string) (*fosite.Request, error) {
	accessToken, err := r.q.GetAccessToken(ctx, signature)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to get access token")
	}

	requestedScopes := []string{}
	if err := json.Unmarshal(accessToken.RequestedScope, &requestedScopes); err != nil {
		return nil, errors.Wrap(err, "Failed to unmarshal requested scopes")
	}
	grantedScopes := []string{}
	if err := json.Unmarshal(accessToken.GrantedScope, &grantedScopes); err != nil {
		return nil, errors.Wrap(err, "Failed to unmarshal granted scopes")
	}
	form := map[string][]string{}
	if err := json.Unmarshal(accessToken.FormData, &form); err != nil {
		return nil, errors.Wrap(err, "Failed to unmarshal form data")
	}
	requestedAudience := []string{}
	if err := json.Unmarshal(accessToken.RequestedAudience, &requestedAudience); err != nil {
		return nil, errors.Wrap(err, "Failed to unmarshal requested audience")
	}
	grantedAudience := []string{}
	if err := json.Unmarshal(accessToken.GrantedAudience, &grantedAudience); err != nil {
		return nil, errors.Wrap(err, "Failed to unmarshal granted audience")
	}

	req := &fosite.Request{
		ID:             accessToken.ID,
		RequestedAt:    accessToken.CreatedAt,
		Client:         &fosite.DefaultClient{ID: accessToken.ClientID},
		RequestedScope: requestedScopes,
		GrantedScope:   grantedScopes,
		Form:           form,
		Session: &fosite.DefaultSession{
			Subject:   accessToken.Subject,
			Username:  accessToken.Username,
			ExpiresAt: map[fosite.TokenType]time.Time{fosite.AccessToken: accessToken.ExpiredAt},
		},
		RequestedAudience: requestedAudience,
		GrantedAudience:   grantedAudience,
	}

	return req, nil
}
