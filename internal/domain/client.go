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

type ClientStatus string

const (
	ClientStatusActive    ClientStatus = "active"
	ClientStatusSuspended ClientStatus = "suspended"
)

func (s ClientStatus) Valid() bool {
	return s == ClientStatusActive || s == ClientStatusSuspended
}

// Client contains the persisted per-client OAuth metadata.
// Creation defaults are applied by the repository and the database schema;
// their equivalence is covered by TestClientCreationDefaultsMatchSchema.
type Client struct {
	ClientID      uuid.UUID
	Name          string
	ClientType    ClientType
	RedirectURIs  []string
	GrantTypes    []string
	ResponseTypes []string
	Scopes        []string
	Status        ClientStatus
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type ClientWithSecret struct {
	Client
	ClientSecret string // #nosec G117 -- returned only on creation, not persisted
}
