package domain

import (
	"time"

	"github.com/google/uuid"
)

// DeviceAuthorizationStatus represents the lifecycle of a Device
// Authorization Grant (RFC 8628). A row begins as Pending; the user either
// approves it (Authorized) or denies it (Denied), and a sweep marks any
// row whose expires_at has passed as Expired.
type DeviceAuthorizationStatus string

const (
	DeviceAuthorizationStatusPending    DeviceAuthorizationStatus = "pending"
	DeviceAuthorizationStatusAuthorized DeviceAuthorizationStatus = "authorized"
	DeviceAuthorizationStatusDenied     DeviceAuthorizationStatus = "denied"
	DeviceAuthorizationStatusExpired    DeviceAuthorizationStatus = "expired"
)

// DeviceAuthorization is the server-side state of an in-flight Device
// Authorization Grant. DeviceCode is shared with the device polling for
// tokens; UserCode is shown to the human entering it on a browser.
type DeviceAuthorization struct {
	ID           uuid.UUID
	DeviceCode   string
	UserCode     string
	ClientID     uuid.UUID
	UserID       *uuid.UUID
	Scopes       []string
	Status       DeviceAuthorizationStatus
	ExpiresAt    time.Time
	PollInterval int
	LastPolledAt *time.Time
	AuthorizedAt *time.Time
	CreatedAt    time.Time
}

// IsExpired reports whether the authorization has passed its TTL irrespective
// of stored Status (Status may not have been swept yet).
func (d DeviceAuthorization) IsExpired(now time.Time) bool {
	return !now.Before(d.ExpiresAt)
}
