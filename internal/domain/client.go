package domain

import (
	"time"

	"github.com/cockroachdb/errors"
	"github.com/google/uuid"
)

type ClientID uuid.UUID

func (c ClientID) String() string {
	return uuid.UUID(c).String()
}

func (c ClientID) UUID() uuid.UUID {
	return uuid.UUID(c)
}

type ClientType string

func (c ClientType) String() string {
	return string(c)
}

func ParseClientType(s string) (ClientType, error) {
	switch s {
	case ClientTypeConfidential.String():
		return ClientTypeConfidential, nil
	case ClientTypePublic.String():
		return ClientTypePublic, nil
	default:
		return "", errors.New("invalid client type")
	}
}

const (
	ClientTypeConfidential ClientType = "confidential"
	ClientTypePublic       ClientType = "public"
)

type Client struct {
	ID           ClientID
	SecretHash   *string // NULL for public clients
	Name         string
	Type         ClientType
	RedirectURIs []string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}
