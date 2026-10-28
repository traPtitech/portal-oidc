package domain

import (
	"time"

	"github.com/google/uuid"
)

type ClientType string

const (
	ClientTypePublic       ClientType = "public"
	ClientTypeConfidential ClientType = "confidential"
)

// Client contains the persisted per-client OAuth metadata.
// Creation defaults are applied by the repository and the database schema;
// their equivalence is covered by TestClientCreationDefaultsMatchSchema.
type Client struct {
	ClientID               uuid.UUID
	Name                   string
	ClientType             ClientType
	RedirectURIs           []string
	ClientURI              string
	LogoURI                string
	PostLogoutRedirectURIs []string
	AllowedOrigins         []string
	GrantTypes             []string
	ResponseTypes          []string
	Scopes                 []string
	TokenEndpointAuth      string
	JWKSURI                string
	JWKS                   []byte // raw JSON, nil when unset
	IDTokenAlg             string
	Status                 string // "active" or "suspended"
	OwnerID                *uuid.UUID
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

type ClientWithSecret struct {
	Client
	ClientSecret string // #nosec G117 -- returned only on creation, not persisted
}
