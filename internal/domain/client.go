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

// Client mirrors the spec table traPortal v2 §clients.
//
// New per-client OAuth metadata is added with sensible defaults so older clients
// (created before the fields existed) still operate identically to the previous
// hard-coded behaviour:
//
//	GrantTypes        = ["authorization_code", "refresh_token"]
//	ResponseTypes     = ["code"]
//	Scopes            = ["openid", "profile", "email"]
//	TokenEndpointAuth = "client_secret_basic"
//	IDTokenAlg        = "RS256"
//	Status            = "active"
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
