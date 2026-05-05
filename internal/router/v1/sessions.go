package v1

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository"
)

// sessionView is the JSON shape returned by the /auth/session endpoints.
// It deliberately omits the raw cookie session_id because callers should not
// be able to read another browser's cookie value out of this API.
type sessionView struct {
	ID           uuid.UUID `json:"id"`
	UserAgent    string    `json:"user_agent,omitempty"`
	IPAddress    string    `json:"ip_address,omitempty"`
	ACR          string    `json:"acr,omitempty"`
	AMR          []string  `json:"amr,omitempty"`
	AuthTime     int64     `json:"auth_time"`
	LastActiveAt int64     `json:"last_active_at"`
	ExpiresAt    int64     `json:"expires_at"`
	Current      bool      `json:"current"`
}

// GetSession returns metadata about the caller's currently-active session.
//
// Refs:
//   - traPortal v2 仕様 §セッション (GET /auth/session)
func (h *Handler) GetSession(ctx *echo.Context) error {
	cookieID, info, ok := h.currentSession(ctx)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "not logged in")
	}
	if h.userSessions == nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "session storage not configured")
	}
	current, err := h.userSessions.GetBySessionID(ctx.Request().Context(), cookieID)
	if err != nil {
		if errors.Is(err, repository.ErrUserSessionNotFound) {
			return echo.NewHTTPError(http.StatusUnauthorized, "session not tracked")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to load session")
	}
	_ = info // info is only used to confirm the cookie was decryptable
	return ctx.JSON(http.StatusOK, toSessionView(current, true))
}

// ListSessions returns every active session belonging to the caller, with the
// caller's own session marked Current=true so the UI can render a hint.
func (h *Handler) ListSessions(ctx *echo.Context) error {
	cookieID, info, ok := h.currentSession(ctx)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "not logged in")
	}
	if h.userSessions == nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "session storage not configured")
	}
	userID, err := uuid.Parse(info.UserID)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid session subject")
	}

	rows, err := h.userSessions.ListByUser(ctx.Request().Context(), userID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to list sessions")
	}
	out := make([]sessionView, 0, len(rows))
	for _, row := range rows {
		out = append(out, toSessionView(row, row.SessionID == cookieID))
	}
	return ctx.JSON(http.StatusOK, out)
}

// RevokeSession terminates the session identified by the path parameter,
// rejecting attempts to revoke sessions that belong to a different user.
func (h *Handler) RevokeSession(ctx *echo.Context) error {
	_, info, ok := h.currentSession(ctx)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "not logged in")
	}
	if h.userSessions == nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "session storage not configured")
	}
	userID, err := uuid.Parse(info.UserID)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid session subject")
	}
	id, err := uuid.Parse(ctx.Param("sessionId"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid sessionId")
	}
	if err := h.userSessions.Revoke(ctx.Request().Context(), id, userID); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to revoke session")
	}
	return ctx.NoContent(http.StatusNoContent)
}

// RevokeAllOtherSessions terminates every active session for the caller
// except the one currently in use. Useful for "sign out everywhere else".
func (h *Handler) RevokeAllOtherSessions(ctx *echo.Context) error {
	cookieID, info, ok := h.currentSession(ctx)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "not logged in")
	}
	if h.userSessions == nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "session storage not configured")
	}
	userID, err := uuid.Parse(info.UserID)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid session subject")
	}
	if err := h.userSessions.RevokeAllExcept(ctx.Request().Context(), userID, cookieID); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to revoke sessions")
	}
	return ctx.NoContent(http.StatusNoContent)
}

// currentSession returns the cookie session ID and authInfo for the caller.
// The cookie session is the source of truth for "who is logged in" today;
// the user_sessions table is a parallel record keyed by the same cookie value.
func (h *Handler) currentSession(ctx *echo.Context) (string, authInfo, bool) {
	info, ok := h.getAuthInfo(ctx)
	if !ok {
		return "", authInfo{}, false
	}
	sess, err := h.sessions.Get(ctx.Request(), sessionName)
	if err != nil {
		return "", authInfo{}, false
	}
	return sess.ID, info, true
}

func toSessionView(s domain.UserSession, current bool) sessionView {
	return sessionView{
		ID:           s.ID,
		UserAgent:    s.UserAgent,
		IPAddress:    s.IPAddress,
		ACR:          s.ACR,
		AMR:          s.AMR,
		AuthTime:     s.AuthTime.Unix(),
		LastActiveAt: s.LastActiveAt.Unix(),
		ExpiresAt:    s.ExpiresAt.Unix(),
		Current:      current,
	}
}
