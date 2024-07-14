package domain

import (
	"time"

	"github.com/cockroachdb/errors"
	"github.com/google/uuid"
)

const DefaultSecretLength = 32

type ClientID uuid.UUID

func (c ClientID) String() string {
	return uuid.UUID(c).String()
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
	UserID       UserID
	Type         ClientType
	Name         string
	Secret       string
	Description  string
	RedirectURIs []string

	CreatedAt time.Time
	UpdatedAt time.Time
}
