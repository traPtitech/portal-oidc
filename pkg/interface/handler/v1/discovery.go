package v1

import (
	"encoding/json"
	"net/http"

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

func (h *Handler) SetupOIDCDiscoveryHandler(host string) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		resp := discoveryResponse{
			Issuer:                            formatURL(host, ""),
			AuthEndpoint:                      formatURL(host, "/oauth2/auth"),
			TokenEndpoint:                     formatURL(host, "/oauth2/token"),
			JWKSURI:                           formatURL(host, "/oauth2/jwks"),
			UserInfoEndpoint:                  formatURL(host, "/oauth2/userinfo"),
			ScopeSupported:                    domain.SupportedScopes,
			ResponseTypesSupported:            domain.SupportedResponseTypes,
			GrantTypesSupported:               domain.SupportedGrantTypes,
			SubjectTypesSupported:             domain.SupportedSubjectTypes,
			IDTokenSigningAlgValuesSupported:  domain.SupportedIDTokenSigningAlgs,
			ClaimsSupported:                   domain.SupportedClaims,
			ACRValuesSupported:                domain.SupportedACRValues,
			TokenEndpointAuthMethodsSupported: domain.SupportedTokenEndpointAuthMethods,
		}

		rw.Header().Set("Content-Type", "application/json; charset=utf-8")
		rw.WriteHeader(http.StatusOK)
		err := json.NewEncoder(rw).Encode(resp)
		if err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}
		return
	}
}

func formatURL(host, path string) string {
	return "https://" + host + path
}
