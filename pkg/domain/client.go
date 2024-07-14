package domain

import (
	"time"

	"github.com/google/uuid"
)

type ClientID uuid.UUID

func (c ClientID) String() string {
	return uuid.UUID(c).String()
}

type ClientType string

func (c ClientType) String() string {
	return string(c)
}

const (
	ClientTypeConfidential ClientType = "confidential"
	ClientTypePublic       ClientType = "public"
)

type Client struct {
	ID           ClientID
	UserID       UserID
	Type         ClientType
	Name         string
	Secret       string
	Description  string
	RedirectURIs []string

	CreatedAt time.Time
	UpdatedAt time.Time
}
