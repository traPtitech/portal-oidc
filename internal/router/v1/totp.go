package v1

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"
	"github.com/pquerna/otp/totp"

	"github.com/traPtitech/portal-oidc/internal/repository"
)

const totpIssuer = "traPortal"

// RegisterTOTP starts TOTP enrolment for the logged-in user. The generated
// secret is stored with enabled=false so a half-finished enrolment cannot
// gate subsequent logins. The response contains the otpauth:// URI plus the
// raw secret in case the client wants to display a manual entry option.
//
// Refs:
//   - RFC 6238 §3 (TOTP algorithm requires a successful verification before
//     accepting the seed for authentication)
//     https://datatracker.ietf.org/doc/html/rfc6238#section-3
func (h *Handler) RegisterTOTP(ctx *echo.Context) error {
	info, ok := h.getAuthInfo(ctx)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "not logged in")
	}
	userID, err := uuid.Parse(info.UserID)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid session subject")
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: info.UserID,
	})
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	if err := h.totpCreds.Upsert(ctx.Request().Context(), userID, key.Secret(), false); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return ctx.JSON(http.StatusOK, map[string]any{
		"otpauth_url": key.URL(),
		"secret":      key.Secret(),
	})
}

// VerifyTOTPRegistration accepts the first OTP from the user and, on success,
// flips the credential to enabled. RFC 6238 §3 requires this round-trip
// before the OP can rely on the seed.
func (h *Handler) VerifyTOTPRegistration(ctx *echo.Context) error {
	info, ok := h.getAuthInfo(ctx)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "not logged in")
	}
	userID, err := uuid.Parse(info.UserID)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid session subject")
	}
	code, err := readTOTPCode(ctx)
	if err != nil {
		return err
	}

	cred, err := h.totpCreds.Get(ctx.Request().Context(), userID)
	if err != nil {
		if errors.Is(err, repository.ErrTOTPCredentialNotFound) {
			return echo.NewHTTPError(http.StatusBadRequest, "no pending TOTP enrolment")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	if !totp.Validate(code, cred.Secret) {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid code")
	}
	if err := h.totpCreds.Enable(ctx.Request().Context(), userID); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	return ctx.NoContent(http.StatusNoContent)
}

// LoginTOTP verifies a TOTP code as a second factor during login. The caller
// must already be logged in via primary authentication; the endpoint touches
// last_used_at on success but does not yet integrate with the AMR claim
// (Phase 5.3 will do that).
func (h *Handler) LoginTOTP(ctx *echo.Context) error {
	info, ok := h.getAuthInfo(ctx)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "primary authentication required")
	}
	userID, err := uuid.Parse(info.UserID)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid session subject")
	}
	code, err := readTOTPCode(ctx)
	if err != nil {
		return err
	}

	cred, err := h.totpCreds.Get(ctx.Request().Context(), userID)
	if err != nil {
		if errors.Is(err, repository.ErrTOTPCredentialNotFound) {
			return echo.NewHTTPError(http.StatusBadRequest, "TOTP not enrolled")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	if !cred.Enabled {
		return echo.NewHTTPError(http.StatusBadRequest, "TOTP enrolment incomplete")
	}
	if !totp.Validate(code, cred.Secret) {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid code")
	}
	if err := h.totpCreds.Touch(ctx.Request().Context(), userID); err != nil {
		// Best-effort timestamp update; failure does not invalidate the auth.
		_ = err
	}
	return ctx.NoContent(http.StatusNoContent)
}

// GetTOTPStatus reports whether the caller has a usable TOTP credential.
func (h *Handler) GetTOTPStatus(ctx *echo.Context) error {
	info, ok := h.getAuthInfo(ctx)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "not logged in")
	}
	userID, err := uuid.Parse(info.UserID)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid session subject")
	}
	cred, err := h.totpCreds.Get(ctx.Request().Context(), userID)
	if err != nil {
		if errors.Is(err, repository.ErrTOTPCredentialNotFound) {
			return ctx.JSON(http.StatusOK, map[string]any{"enrolled": false})
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	out := map[string]any{
		"enrolled": true,
		"enabled":  cred.Enabled,
	}
	if cred.LastUsedAt != nil {
		out["last_used_at"] = cred.LastUsedAt.Unix()
	}
	return ctx.JSON(http.StatusOK, out)
}

// DisableTOTP removes the user's TOTP credential entirely.
func (h *Handler) DisableTOTP(ctx *echo.Context) error {
	info, ok := h.getAuthInfo(ctx)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "not logged in")
	}
	userID, err := uuid.Parse(info.UserID)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid session subject")
	}
	if err := h.totpCreds.Delete(ctx.Request().Context(), userID); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	return ctx.NoContent(http.StatusNoContent)
}

func readTOTPCode(ctx *echo.Context) (string, error) {
	var body struct {
		Code string `json:"code"`
	}
	if ctx.Request().Header.Get("Content-Type") == "application/json" {
		if err := json.NewDecoder(ctx.Request().Body).Decode(&body); err != nil {
			return "", echo.NewHTTPError(http.StatusBadRequest, "invalid body")
		}
	} else {
		if err := ctx.Request().ParseForm(); err != nil {
			return "", echo.NewHTTPError(http.StatusBadRequest, "invalid body")
		}
		body.Code = ctx.Request().Form.Get("code")
	}
	if body.Code == "" {
		return "", echo.NewHTTPError(http.StatusBadRequest, "code required")
	}
	return body.Code, nil
}

// _ keeps net/url imported if a future code path needs to URL-encode the
// otpauth response field.
var _ = url.QueryEscape
