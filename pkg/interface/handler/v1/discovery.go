package v1

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/traPtitech/portal-oidc/pkg/domain"
)

// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
type discoveryResponse struct {
	Issuer                            string   `json:"issuer"`
	AuthEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserInfoEndpoint                  string   `json:"userinfo_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ScopeSupported                    []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	ACRValuesSupported                []string `json:"acr_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
}

func (h *Handler) SetupOIDCDiscoveryHandler(host string) func(c echo.Context) error {
	return func(c echo.Context) error {
		resp := discoveryResponse{
			Issuer:                            formatURL(host, ""),
			AuthEndpoint:                      formatURL(host, "/auth"),
			TokenEndpoint:                     formatURL(host, "/token"),
			JWKSURI:                           formatURL(host, "/jwks"),
			UserInfoEndpoint:                  formatURL(host, "/userinfo"),
			ScopeSupported:                    domain.SupportedScopes,
			ResponseTypesSupported:            domain.SupportedResponseTypes,
			GrantTypesSupported:               domain.SupportedGrantTypes,
			SubjectTypesSupported:             domain.SupportedSubjectTypes,
			IDTokenSigningAlgValuesSupported:  domain.SupportedIDTokenSigningAlgs,
			ClaimsSupported:                   domain.SupportedClaims,
			ACRValuesSupported:                domain.SupportedACRValues,
			TokenEndpointAuthMethodsSupported: domain.SupportedTokenEndpointAuthMethods,
		}
		return c.JSON(http.StatusOK, resp)
	}
}

func formatURL(host, path string) string {
	return "https://" + host + path
}
