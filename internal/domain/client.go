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

type Client struct {
	ClientID               uuid.UUID
	Name                   string
	ClientType             ClientType
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	AllowedOrigins         []string
	GrantTypes             []string
	ResponseTypes          []string
	Scopes                 []string
	TokenEndpointAuth      string
	IDTokenAlg             string
	Status                 string // "active" or "suspended"
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

type ClientWithSecret struct {
	Client
	ClientSecret string // #nosec G117 -- returned only on creation, not persisted
}
