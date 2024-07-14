package v1

import (
	"context"

	"github.com/cockroachdb/errors"
	"github.com/google/uuid"
	"github.com/traPtitech/portal-oidc/pkg/domain"
	"github.com/traPtitech/portal-oidc/pkg/domain/portal"
	models "github.com/traPtitech/portal-oidc/pkg/infrastructure/mariadb/v1/gen"
	"github.com/volatiletech/sqlboiler/v4/boil"
	"github.com/volatiletech/sqlboiler/v4/queries/qm"
)

func convertToDomainClient(client *models.Client) (domain.Client, error) {
	redirectURIs := make([]string, len(client.R.RedirectUris))
	for i, uri := range client.R.RedirectUris {
		redirectURIs[i] = uri.URI
	}

	clientID, err := uuid.Parse(client.ID)
	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to parse client id")
	}

	return domain.Client{
		ID:           domain.ClientID(clientID),
		UserID:       domain.UserID(portal.PortalUserID(client.UserID)),
		Type:         domain.ClientType(client.Type),
		Name:         client.Name,
		Description:  client.Description,
		Secret:       client.SecretKey,
		RedirectURIs: redirectURIs,
	}, nil
}

func (r *MariaDBRepository) CreateOIDCClient(ctx context.Context, id uuid.UUID, userID domain.UserID, typ domain.ClientType, name string, desc string, secret string, redirectURIs []string) (domain.Client, error) {
	tx, err := r.db.BeginTx(ctx, nil)

	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to begin transaction")
	}

	client := models.Client{
		ID:          id.String(),
		UserID:      userID.String(),
		Type:        typ.String(),
		Name:        name,
		SecretKey:   secret,
		Description: desc,
	}

	err = client.Insert(ctx, tx, boil.Infer())

	if err != nil {
		tx.Rollback()
		return domain.Client{}, errors.Wrap(err, "Failed to insert client")
	}

	uris := models.RedirectURISlice{}
	for _, uri := range redirectURIs {
		uris = append(uris, &models.RedirectURI{
			ClientID: id.String(),
			URI:      uri,
		})
	}

	_, err = uris.InsertAll(ctx, tx, boil.Infer())

	if err != nil {
		tx.Rollback()
		return domain.Client{}, errors.Wrap(err, "Failed to insert redirect uris")
	}

	err = tx.Commit()

	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to commit transaction")
	}

	return domain.Client{
		ID:           domain.ClientID(id),
		UserID:       userID,
		Type:         typ,
		Name:         name,
		Description:  desc,
		Secret:       secret,
		RedirectURIs: redirectURIs,
	}, nil
}

func (r *MariaDBRepository) GetOIDCClient(ctx context.Context, id domain.ClientID) (domain.Client, error) {
	client, err := models.Clients(
		models.ClientWhere.ID.EQ(id.String()),
		qm.Load("redirect_uri"),
	).One(ctx, r.db)

	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to get client")
	}

	return convertToDomainClient(client)
}

func (r *MariaDBRepository) ListOIDCClientsByUser(ctx context.Context, userID domain.UserID) ([]domain.Client, error) {

	clients, err := models.Clients(
		models.ClientWhere.UserID.EQ(userID.String()),
		qm.Load("redirect_uri"),
	).All(ctx, r.db)

	if err != nil {
		return nil, errors.Wrap(err, "Failed to get clients")
	}

	clientList := make([]domain.Client, len(clients))
	for i, client := range clients {

		c, err := convertToDomainClient(client)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to convert client")
		}

		clientList[i] = c
	}

	return clientList, nil
}

func (r *MariaDBRepository) UpdateOIDCClient(ctx context.Context, id domain.ClientID, userID domain.UserID, typ domain.ClientType, name string, desc string, redirectURIs []string) (domain.Client, error) {
	tx, err := r.db.BeginTx(ctx, nil)

	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to begin transaction")
	}

	client := models.Client{
		ID:          id.String(),
		UserID:      userID.String(),
		Type:        typ.String(),
		Name:        name,
		Description: desc,
	}

	_, err = client.Update(ctx, tx, boil.Infer())

	if err != nil {
		tx.Rollback()
		return domain.Client{}, errors.Wrap(err, "Failed to update client")
	}

	_, err = models.RedirectUris(
		models.RedirectURIWhere.ClientID.EQ(id.String()),
	).DeleteAll(ctx, tx)

	if err != nil {
		tx.Rollback()
		return domain.Client{}, errors.Wrap(err, "Failed to delete redirect uris")
	}

	uris := models.RedirectURISlice{}
	for _, uri := range redirectURIs {
		uris = append(uris, &models.RedirectURI{
			ClientID: id.String(),
			URI:      uri,
		})
	}

	_, err = uris.InsertAll(ctx, tx, boil.Infer())

	if err != nil {
		tx.Rollback()
		return domain.Client{}, errors.Wrap(err, "Failed to insert redirect uris")
	}

	newclient, err := models.Clients(
		models.ClientWhere.ID.EQ(id.String()),
		models.ClientWhere.UserID.EQ(userID.String()),
		qm.Load("redirect_uri"),
	).One(ctx, tx)

	if err != nil {
		tx.Rollback()
		return domain.Client{}, errors.Wrap(err, "Failed to get client")
	}

	err = tx.Commit()

	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to commit transaction")
	}

	return convertToDomainClient(newclient)
}

func (r *MariaDBRepository) UpdateOIDCClientSecret(ctx context.Context, id domain.ClientID, secret string) (domain.Client, error) {
	tx, err := r.db.BeginTx(ctx, nil)

	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to begin transaction")
	}

	client := models.Client{
		ID:        id.String(),
		SecretKey: secret,
	}

	_, err = client.Update(ctx, tx, boil.Infer())

	if err != nil {
		tx.Rollback()
		return domain.Client{}, errors.Wrap(err, "Failed to update client")
	}

	newclient, err := models.Clients(
		models.ClientWhere.ID.EQ(id.String()),
		qm.Load("redirect_uri"),
	).One(ctx, tx)

	if err != nil {
		tx.Rollback()
		return domain.Client{}, errors.Wrap(err, "Failed to get client")
	}

	err = tx.Commit()

	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to commit transaction")
	}

	return convertToDomainClient(newclient)
}

func (r *MariaDBRepository) DeleteOIDCClient(ctx context.Context, id domain.ClientID) error {
	tx, err := r.db.BeginTx(ctx, nil)

	if err != nil {
		return errors.Wrap(err, "Failed to begin transaction")
	}

	_, err = models.Clients(
		models.ClientWhere.ID.EQ(id.String()),
	).DeleteAll(ctx, tx)

	if err != nil {
		tx.Rollback()
		return errors.Wrap(err, "Failed to delete client")
	}

	_, err = models.RedirectUris(
		models.RedirectURIWhere.ClientID.EQ(id.String()),
	).DeleteAll(ctx, tx)

	if err != nil {
		tx.Rollback()
		return errors.Wrap(err, "Failed to delete redirect uris")
	}

	err = tx.Commit()

	if err != nil {
		return errors.Wrap(err, "Failed to commit transaction")
	}

	return nil
}
