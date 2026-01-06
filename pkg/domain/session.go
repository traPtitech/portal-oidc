package domain

import (
	"time"

	"github.com/google/uuid"
)

// SessionID はセッションの識別子
type SessionID uuid.UUID

// Session は認証済みユーザーのセッション
type Session struct {
	ID           SessionID
	UserID       TrapID
	UserAgent    string
	IPAddress    string
	AuthTime     time.Time
	LastActiveAt time.Time
	ExpiresAt    time.Time
	CreatedAt    time.Time
}

// AuthorizationRequestID は認可リクエストの識別子
type AuthorizationRequestID uuid.UUID

// AuthorizationRequest は認可フロー中の一時状態 (ログインリダイレクト用)
type AuthorizationRequest struct {
	ID                  AuthorizationRequestID
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	UserID              *TrapID // ログイン後に設定
	ExpiresAt           time.Time
	CreatedAt           time.Time
}

// AuthorizationCode は認可コード
type AuthorizationCode struct {
	Code                string
	ClientID            string
	UserID              TrapID
	RedirectURI         string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	SessionData         string // fosite session (JSON)
	Used                bool
	ExpiresAt           time.Time
	CreatedAt           time.Time
}
