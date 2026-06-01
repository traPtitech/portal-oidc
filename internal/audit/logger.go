// Package audit captures security-sensitive events to the audit_logs table.
//
// Audit logging is best-effort by design: a failure to persist an event is
// logged via the standard log package but never propagated to the caller,
// because dropping a real request because of a logging failure would create
// a broader security problem than missing an audit row.
package audit

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"

	"github.com/google/uuid"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository"
)

// Logger persists audit events through a repository.
type Logger struct {
	repo repository.AuditLogRepository
}

func NewLogger(repo repository.AuditLogRepository) *Logger {
	return &Logger{repo: repo}
}

// Event is the minimal payload callers fill in. Convenience constructors
// (LoginSuccess, TokenIssued, ...) mostly translate handler-side data into
// this shape.
type Event struct {
	Type      domain.AuditEventType
	UserID    *uuid.UUID
	ClientID  *uuid.UUID
	SessionID string
	IPAddress string
	UserAgent string
	Details   map[string]any
}

// Record persists one event. Best-effort: errors are logged and swallowed.
func (l *Logger) Record(ctx context.Context, ev Event) {
	if l == nil {
		return
	}
	var details []byte
	if len(ev.Details) > 0 {
		raw, err := json.Marshal(ev.Details)
		if err != nil {
			log.Printf("audit: marshal details for %s: %v", ev.Type, err)
		} else {
			details = raw
		}
	}
	row := domain.AuditLog{
		ID:        uuid.New(),
		EventType: ev.Type,
		UserID:    ev.UserID,
		ClientID:  ev.ClientID,
		SessionID: ev.SessionID,
		IPAddress: ev.IPAddress,
		UserAgent: ev.UserAgent,
		Details:   details,
	}
	if err := l.repo.Create(ctx, row); err != nil {
		log.Printf("audit: persist %s: %v", ev.Type, err)
	}
}

// FromRequest extracts the IP address (honouring X-Forwarded-For when
// trusted) and User-Agent from the inbound request. The X-Forwarded-For
// handling is deliberately permissive because traPortal sits behind a single
// trusted reverse proxy in production; tighten if that assumption changes.
func FromRequest(r *http.Request) (ip, ua string) {
	if r == nil {
		return "", ""
	}
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		// First entry is the original client per RFC 7239 / common proxy
		// convention.
		if comma := indexComma(forwarded); comma >= 0 {
			ip = trimSpace(forwarded[:comma])
		} else {
			ip = trimSpace(forwarded)
		}
	}
	if ip == "" {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		} else {
			ip = host
		}
	}
	ua = r.Header.Get("User-Agent")
	return ip, ua
}

func indexComma(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			return i
		}
	}
	return -1
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
