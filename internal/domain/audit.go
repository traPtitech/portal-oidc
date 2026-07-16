package domain

import (
	"time"

	"github.com/google/uuid"
)

// AuditEventType is a stable string identifier for security-relevant events.
// New types may be added freely; consumers should treat unknown values as
// generic events.
type AuditEventType string

const (
	AuditEventLoginSuccess     AuditEventType = "auth.login.success"
	AuditEventLoginFailure     AuditEventType = "auth.login.failure"
	AuditEventLogout           AuditEventType = "auth.logout"
	AuditEventTokenIssued      AuditEventType = "token.issued"
	AuditEventTokenRevoked     AuditEventType = "token.revoked"
	AuditEventTokenIntrospect  AuditEventType = "token.introspected"
	AuditEventClientCreated    AuditEventType = "client.created"
	AuditEventClientUpdated    AuditEventType = "client.updated"
	AuditEventClientDeleted    AuditEventType = "client.deleted"
	AuditEventClientSecretGen  AuditEventType = "client.secret_regenerated"
	AuditEventSigningKeyRotate AuditEventType = "signing_key.rotated"
)

// AuditLog is one persisted entry in the audit_logs table.
//
// UserID and ClientID are optional because not every event has a subject
// (e.g. an anonymous introspection still gets logged for forensics). Details
// is free-form JSON so adding new event shapes does not require schema
// changes.
type AuditLog struct {
	ID        uuid.UUID
	EventType AuditEventType
	UserID    *uuid.UUID
	ClientID  *uuid.UUID
	SessionID string
	IPAddress string
	UserAgent string
	Details   []byte // raw JSON; nil when no details captured
	CreatedAt time.Time
}
