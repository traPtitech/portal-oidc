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
	ClientID     uuid.UUID
	Name         string
	ClientType   ClientType
	RedirectURIs []string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type ClientWithSecret struct {
	Client
	ClientSecret string
}
