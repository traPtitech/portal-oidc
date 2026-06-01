package v1

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/labstack/echo/v5"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/router/v1/gen"
)

// RegisterClient implements RFC 7591 OAuth 2.0 Dynamic Client Registration.
//
// Per §3.1 the request body is a JSON document of client metadata; per §3.2.1
// the response echoes the metadata back together with the issued client_id
// and (for confidential clients) client_secret. We currently treat the
// endpoint as open: anyone with network access can register a client. Tighten
// to require an Initial Access Token (§3) once the deployment grows.
//
// Refs:
//   - RFC 7591 §3.1 (Client Registration Request)
//     https://datatracker.ietf.org/doc/html/rfc7591#section-3.1
//   - RFC 7591 §3.2.1 (Client Information Response)
//     https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.1
//   - RFC 7591 §3.2.2 (Client Registration Error Response)
//     https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.2
func (h *Handler) RegisterClient(ctx *echo.Context) error {
	var req gen.ClientRegistrationRequest
	if err := json.NewDecoder(ctx.Request().Body).Decode(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, gen.OAuthError{Error: gen.InvalidRequest})
	}
	if len(req.RedirectUris) == 0 {
		return ctx.JSON(http.StatusBadRequest, gen.OAuthError{
			Error:            gen.InvalidRequest,
			ErrorDescription: stringPtr("redirect_uris is required"),
		})
	}

	clientType := domain.ClientTypeConfidential
	if method := str(req.TokenEndpointAuthMethod); method == "none" {
		clientType = domain.ClientTypePublic
	}

	name := str(req.ClientName)
	if name == "" {
		name = "Dynamically Registered Client"
	}

	created, err := h.clientUseCase.Create(ctx.Request().Context(), name, clientType, req.RedirectUris)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, gen.OAuthError{
			Error:            gen.ServerError,
			ErrorDescription: stringPtr(err.Error()),
		})
	}

	resp := gen.ClientRegistrationResponse{
		ClientId:         created.ClientID,
		ClientIdIssuedAt: created.CreatedAt.Unix(),
		ClientName:       stringPtr(created.Name),
		RedirectUris:     created.RedirectURIs,
	}
	if clientType == domain.ClientTypeConfidential {
		secret := created.ClientSecret
		resp.ClientSecret = &secret
		// RFC 7591 §3.2.1: 0 means the secret does not expire. We do not
		// rotate registered client secrets automatically yet.
		zero := int64(0)
		resp.ClientSecretExpiresAt = &zero
	}
	return ctx.JSON(http.StatusCreated, resp)
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return strings.TrimSpace(*p)
}

func stringPtr(s string) *string { return &s }
