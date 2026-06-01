package v1

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/labstack/echo/v5"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository"
)

// webAuthnSessionKey is the session.Values entry holding a per-browser random
// identifier used to bind a WebAuthn challenge to the browser that requested
// it. Required because gorilla/sessions' CookieStore leaves Session.ID empty
// (the cookie itself is the identifier in that store), so naively keying on
// sess.ID would collide every challenge across every browser.
const webAuthnSessionKey = "webauthn_session_key"

const webauthnChallengeTTL = 5 * time.Minute

// webAuthnUser implements webauthn.User on top of the user_id stored in the
// cookie session and the credentials persisted in webauthn_credentials. The
// WebAuthn library uses the methods to fill in PublicKeyCredentialUserEntity
// and to load the allowCredentials list during BeginLogin.
type webAuthnUser struct {
	id          uuid.UUID
	displayName string
	credentials []webauthn.Credential
}

func (u *webAuthnUser) WebAuthnID() []byte                         { id := u.id; return id[:] }
func (u *webAuthnUser) WebAuthnName() string                       { return u.displayName }
func (u *webAuthnUser) WebAuthnDisplayName() string                { return u.displayName }
func (u *webAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }
func (u *webAuthnUser) WebAuthnIcon() string                       { return "" }

// BeginWebAuthnRegistration starts the registration ceremony for the
// currently-logged-in user. The challenge is persisted server-side (per
// W3C-WebAuthn-Level-3 §13.1.1: the server MUST verify the challenge it
// originally sent) so the verify step can replay the SessionData.
//
// Refs:
//   - W3C WebAuthn Level 3 §7.1 (Registering a New Credential)
//     https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential
func (h *Handler) BeginWebAuthnRegistration(ctx *echo.Context) error {
	cookieID, info, ok := h.currentWebAuthnSession(ctx)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "not logged in")
	}
	user, err := h.loadWebAuthnUser(ctx.Request().Context(), info.UserID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	options, sessionData, err := h.webauthn.BeginRegistration(user)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to begin registration: "+err.Error())
	}
	if err := h.persistChallenge(ctx, cookieID, &user.id, domain.WebAuthnChallengeRegister, sessionData); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	return ctx.JSON(http.StatusOK, options)
}

// FinishWebAuthnRegistration verifies the attestation produced by the
// authenticator and persists the resulting credential.
func (h *Handler) FinishWebAuthnRegistration(ctx *echo.Context) error {
	cookieID, info, ok := h.currentWebAuthnSession(ctx)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "not logged in")
	}
	user, err := h.loadWebAuthnUser(ctx.Request().Context(), info.UserID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	sessionData, err := h.consumeChallenge(ctx, cookieID, domain.WebAuthnChallengeRegister)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	parsed, err := protocol.ParseCredentialCreationResponse(ctx.Request())
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid registration response: "+err.Error())
	}
	credential, err := h.webauthn.CreateCredential(user, *sessionData, parsed)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "failed to verify credential: "+err.Error())
	}

	transports := make([]string, 0, len(credential.Transport))
	for _, t := range credential.Transport {
		transports = append(transports, string(t))
	}
	var aaguidPtr *uuid.UUID
	if len(credential.Authenticator.AAGUID) == 16 {
		aaguid, parseErr := uuid.FromBytes(credential.Authenticator.AAGUID)
		if parseErr == nil && aaguid != uuid.Nil {
			aaguidPtr = &aaguid
		}
	}

	persisted := domain.WebAuthnCredential{
		UserID:            user.id,
		CredentialID:      credential.ID,
		PublicKey:         credential.PublicKey,
		PublicKeyAlg:      0,
		AttestationFormat: credential.AttestationType,
		AAGUID:            aaguidPtr,
		SignCount:         credential.Authenticator.SignCount,
		Transports:        transports,
		BackedUp:          credential.Flags.BackupState,
	}
	if err := h.webAuthnCreds.Create(ctx.Request().Context(), persisted); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to persist credential")
	}

	return ctx.JSON(http.StatusOK, map[string]any{"status": "ok"})
}

// BeginWebAuthnLogin starts the assertion ceremony. The user must already be
// identified (e.g. via username submission); the discoverable-credential
// usernameless flow is intentionally out of scope until the frontend supports
// it.
func (h *Handler) BeginWebAuthnLogin(ctx *echo.Context) error {
	cookieID, info, ok := h.currentWebAuthnSession(ctx)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "not logged in")
	}
	user, err := h.loadWebAuthnUser(ctx.Request().Context(), info.UserID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	if len(user.credentials) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "no registered credentials")
	}

	options, sessionData, err := h.webauthn.BeginLogin(user)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to begin login: "+err.Error())
	}
	if err := h.persistChallenge(ctx, cookieID, &user.id, domain.WebAuthnChallengeAuthenticate, sessionData); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	return ctx.JSON(http.StatusOK, options)
}

// FinishWebAuthnLogin verifies the authenticator assertion and updates the
// stored sign_count. A non-monotonic sign_count signals a cloned authenticator
// per W3C-WebAuthn-Level-3 §6.1.1; the library returns an error in that case
// and we propagate it as 401 so the client cannot quietly continue.
func (h *Handler) FinishWebAuthnLogin(ctx *echo.Context) error {
	cookieID, info, ok := h.currentWebAuthnSession(ctx)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "not logged in")
	}
	user, err := h.loadWebAuthnUser(ctx.Request().Context(), info.UserID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	sessionData, err := h.consumeChallenge(ctx, cookieID, domain.WebAuthnChallengeAuthenticate)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	parsed, err := protocol.ParseCredentialRequestResponse(ctx.Request())
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid assertion response: "+err.Error())
	}
	credential, err := h.webauthn.ValidateLogin(user, *sessionData, parsed)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "assertion verification failed: "+err.Error())
	}

	stored, err := h.webAuthnCreds.GetByCredentialID(ctx.Request().Context(), credential.ID)
	if err == nil {
		if err := h.webAuthnCreds.UpdateSignCount(ctx.Request().Context(), stored.ID, credential.Authenticator.SignCount); err != nil {
			log.Printf("webauthn: failed to update sign_count: %v", err)
		}
	}

	return ctx.JSON(http.StatusOK, map[string]any{"status": "ok"})
}

// ListWebAuthnCredentials returns the caller's registered credentials so they
// can be displayed in account settings (and selectively removed).
func (h *Handler) ListWebAuthnCredentials(ctx *echo.Context) error {
	_, info, ok := h.currentWebAuthnSession(ctx)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "not logged in")
	}
	userID, err := uuid.Parse(info.UserID)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid session subject")
	}
	creds, err := h.webAuthnCreds.ListByUser(ctx.Request().Context(), userID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to list credentials")
	}
	out := make([]map[string]any, 0, len(creds))
	for _, c := range creds {
		entry := map[string]any{
			"id":          c.ID,
			"device_name": c.DeviceName,
			"transports":  c.Transports,
			"backed_up":   c.BackedUp,
			"sign_count":  c.SignCount,
			"created_at":  c.CreatedAt.Unix(),
		}
		if c.LastUsedAt != nil {
			entry["last_used_at"] = c.LastUsedAt.Unix()
		}
		out = append(out, entry)
	}
	return ctx.JSON(http.StatusOK, out)
}

// UpdateWebAuthnCredential lets the user rename a registered authenticator.
// Only device_name is mutable; the cryptographic material is immutable by
// design.
func (h *Handler) UpdateWebAuthnCredential(ctx *echo.Context) error {
	_, info, ok := h.currentWebAuthnSession(ctx)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "not logged in")
	}
	userID, err := uuid.Parse(info.UserID)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid session subject")
	}
	id, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid id")
	}
	var body struct {
		DeviceName string `json:"device_name"`
	}
	if err := json.NewDecoder(ctx.Request().Body).Decode(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid body")
	}
	if err := h.webAuthnCreds.UpdateDeviceName(ctx.Request().Context(), id, userID, body.DeviceName); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to update credential")
	}
	return ctx.NoContent(http.StatusNoContent)
}

// DeleteWebAuthnCredential removes one registered authenticator. Defends
// against cross-user deletion by scoping the WHERE clause on user_id.
func (h *Handler) DeleteWebAuthnCredential(ctx *echo.Context) error {
	_, info, ok := h.currentWebAuthnSession(ctx)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "not logged in")
	}
	userID, err := uuid.Parse(info.UserID)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid session subject")
	}
	id, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid id")
	}
	if err := h.webAuthnCreds.Delete(ctx.Request().Context(), id, userID); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to delete credential")
	}
	return ctx.NoContent(http.StatusNoContent)
}

// loadWebAuthnUser hydrates a webAuthnUser from persistent storage so the
// WebAuthn library can populate the allowCredentials list during BeginLogin
// and rebuild the authenticator state during ValidateLogin.
func (h *Handler) loadWebAuthnUser(ctx context.Context, userIDStr string) (*webAuthnUser, error) {
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, errors.New("invalid session subject")
	}
	rows, err := h.webAuthnCreds.ListByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	creds := make([]webauthn.Credential, 0, len(rows))
	for _, r := range rows {
		transports := make([]protocol.AuthenticatorTransport, 0, len(r.Transports))
		for _, t := range r.Transports {
			transports = append(transports, protocol.AuthenticatorTransport(t))
		}
		var aaguid []byte
		if r.AAGUID != nil {
			id := *r.AAGUID
			aaguid = id[:]
		}
		creds = append(creds, webauthn.Credential{
			ID:              r.CredentialID,
			PublicKey:       r.PublicKey,
			AttestationType: r.AttestationFormat,
			Transport:       transports,
			Authenticator: webauthn.Authenticator{
				AAGUID:    aaguid,
				SignCount: r.SignCount,
			},
		})
	}
	return &webAuthnUser{
		id:          userID,
		displayName: userIDStr,
		credentials: creds,
	}, nil
}

// currentWebAuthnSession returns the per-browser session identifier used to
// bind a WebAuthn challenge to its origin. Generates and persists a random
// 32-byte value in session.Values on first use because CookieStore does not
// supply a Session.ID.
func (h *Handler) currentWebAuthnSession(ctx *echo.Context) (string, authInfo, bool) {
	info, ok := h.getAuthInfo(ctx)
	if !ok {
		return "", authInfo{}, false
	}
	sess, err := h.sessions.Get(ctx.Request(), sessionName)
	if err != nil {
		return "", authInfo{}, false
	}
	key, _ := sess.Values[webAuthnSessionKey].(string) //nolint:errcheck // ok-style assertion: empty string triggers regeneration below
	if key == "" {
		var buf [32]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return "", authInfo{}, false
		}
		key = base64.RawURLEncoding.EncodeToString(buf[:])
		sess.Values[webAuthnSessionKey] = key
		if err := sess.Save(ctx.Request(), ctx.Response()); err != nil {
			return "", authInfo{}, false
		}
	}
	return key, info, true
}

func (h *Handler) persistChallenge(ctx *echo.Context, sessionID string, userID *uuid.UUID, t domain.WebAuthnChallengeType, sessionData *webauthn.SessionData) error {
	raw, err := json.Marshal(sessionData)
	if err != nil {
		return err
	}
	return h.webAuthnChalls.Create(ctx.Request().Context(), domain.WebAuthnChallenge{
		Challenge: []byte(sessionData.Challenge),
		UserID:    userID,
		SessionID: sessionID,
		Type:      t,
		Data:      raw,
		ExpiresAt: time.Now().Add(webauthnChallengeTTL),
	})
}

// consumeChallenge atomically removes the pending challenge for this browser
// session before returning it to the caller. Concurrent verify attempts
// against the same challenge see ErrWebAuthnChallengeNotFound.
func (h *Handler) consumeChallenge(ctx *echo.Context, sessionID string, t domain.WebAuthnChallengeType) (*webauthn.SessionData, error) {
	stored, err := h.webAuthnChalls.Consume(ctx.Request().Context(), sessionID, t)
	if err != nil {
		if errors.Is(err, repository.ErrWebAuthnChallengeNotFound) {
			return nil, errors.New("no pending webauthn challenge")
		}
		return nil, err
	}
	var sessionData webauthn.SessionData
	if err := json.Unmarshal(stored.Data, &sessionData); err != nil {
		return nil, errors.New("corrupt webauthn challenge state")
	}
	return &sessionData, nil
}
