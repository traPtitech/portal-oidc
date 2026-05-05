package repository

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/sqlc-dev/pqtype"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository/oidc"
)

type AuditLogQuery struct {
	UserID    *uuid.UUID
	ClientID  *uuid.UUID
	EventType *domain.AuditEventType
	Limit     int32
	Offset    int32
}

type AuditLogRepository interface {
	Create(ctx context.Context, log domain.AuditLog) error
	List(ctx context.Context, q AuditLogQuery) ([]domain.AuditLog, error)
}

type auditLogRepository struct {
	queries *oidc.Queries
}

func NewAuditLogRepository(queries *oidc.Queries) AuditLogRepository {
	return &auditLogRepository{queries: queries}
}

func (r *auditLogRepository) Create(ctx context.Context, log domain.AuditLog) error {
	details := pqtype.NullRawMessage{}
	if len(log.Details) > 0 {
		details = pqtype.NullRawMessage{RawMessage: log.Details, Valid: true}
	}
	return r.queries.CreateAuditLog(ctx, oidc.CreateAuditLogParams{
		ID:        log.ID,
		EventType: string(log.EventType),
		UserID:    nullUUID(log.UserID),
		ClientID:  nullUUID(log.ClientID),
		SessionID: nullString(log.SessionID),
		IpAddress: nullString(log.IPAddress),
		UserAgent: nullString(log.UserAgent),
		Details:   details,
	})
}

// List dispatches to the most selective sqlc query supported by the filter.
// Filters are combined as AND; the helper currently supports single-field
// queries (userID OR clientID OR eventType). Combining filters at the SQL
// layer is a follow-up.
func (r *auditLogRepository) List(ctx context.Context, q AuditLogQuery) ([]domain.AuditLog, error) {
	limit := q.Limit
	if limit <= 0 {
		limit = 100
	}
	offset := q.Offset

	switch {
	case q.UserID != nil:
		rows, err := r.queries.ListAuditLogsByUser(ctx, oidc.ListAuditLogsByUserParams{
			UserID: nullUUID(q.UserID),
			Limit:  limit,
			Offset: offset,
		})
		if err != nil {
			return nil, err
		}
		return mapAuditRows(rows), nil
	case q.ClientID != nil:
		rows, err := r.queries.ListAuditLogsByClient(ctx, oidc.ListAuditLogsByClientParams{
			ClientID: nullUUID(q.ClientID),
			Limit:    limit,
			Offset:   offset,
		})
		if err != nil {
			return nil, err
		}
		return mapAuditRows(rows), nil
	case q.EventType != nil:
		rows, err := r.queries.ListAuditLogsByEventType(ctx, oidc.ListAuditLogsByEventTypeParams{
			EventType: string(*q.EventType),
			Limit:     limit,
			Offset:    offset,
		})
		if err != nil {
			return nil, err
		}
		return mapAuditRows(rows), nil
	default:
		return nil, sql.ErrNoRows
	}
}

func mapAuditRows(rows []oidc.AuditLog) []domain.AuditLog {
	out := make([]domain.AuditLog, 0, len(rows))
	for _, row := range rows {
		out = append(out, toDomainAuditLog(row))
	}
	return out
}

// nullUUID converts an optional uuid.UUID into the sql.NullUUID shape
// required by the sqlc-generated parameter structs. (A package-level helper
// will live in repository.go once #135 lands; until then this is duplicated
// to keep the audit branch independently buildable.)
func nullUUID(id *uuid.UUID) uuid.NullUUID {
	if id == nil {
		return uuid.NullUUID{}
	}
	return uuid.NullUUID{UUID: *id, Valid: true}
}

func nullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

func toDomainAuditLog(row oidc.AuditLog) domain.AuditLog {
	var userID, clientID *uuid.UUID
	if row.UserID.Valid {
		id := row.UserID.UUID
		userID = &id
	}
	if row.ClientID.Valid {
		id := row.ClientID.UUID
		clientID = &id
	}
	var details []byte
	if row.Details.Valid {
		details = row.Details.RawMessage
	}
	return domain.AuditLog{
		ID:        row.ID,
		EventType: domain.AuditEventType(row.EventType),
		UserID:    userID,
		ClientID:  clientID,
		SessionID: row.SessionID.String,
		IPAddress: row.IpAddress.String,
		UserAgent: row.UserAgent.String,
		Details:   details,
		CreatedAt: row.CreatedAt,
	}
}
