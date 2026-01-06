package domain

import (
	"time"

	"github.com/google/uuid"
)

// SessionID はログインセッションの識別子
type SessionID uuid.UUID

// Session はログインセッション (spec.md sessions テーブル準拠)
type Session struct {
	ID           SessionID
	UserID       TrapID
	UserAgent    string
	IPAddress    string
	AuthTime     time.Time
	LastActiveAt time.Time
	ExpiresAt    time.Time
	RevokedAt    *time.Time
	CreatedAt    time.Time
}

// UserConsentID はユーザー同意の識別子
type UserConsentID uuid.UUID

// UserConsent はユーザーの同意情報 (spec.md user_consents テーブル準拠)
type UserConsent struct {
	ID        UserConsentID
	UserID    TrapID
	ClientID  ClientID
	Scopes    []string
	GrantedAt time.Time
	ExpiresAt *time.Time
	RevokedAt *time.Time
}

// LoginSessionID はOAuth認可フロー一時状態の識別子
type LoginSessionID uuid.UUID

// LoginSession はOAuth認可フロー一時状態
type LoginSession struct {
	ID          LoginSessionID
	ClientID    ClientID
	RedirectURI string
	FormData    string
	Scopes      []string
	CreatedAt   time.Time
	ExpiresAt   time.Time
}
