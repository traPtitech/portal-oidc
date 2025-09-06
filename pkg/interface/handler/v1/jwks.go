package v1

import (
	"encoding/json"
	"net/http"

	es256jwt "github.com/traPtitech/portal-oidc/pkg/infrastructure/jwt"
)

type JWKSResponse struct {
	Keys []map[string]interface{} `json:"keys"`
}

func (h *Handler) JWKSHandler(signer *es256jwt.RotatingSigner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jwks := JWKSResponse{
			Keys: signer.GetAllJWKs(),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		
		if err := json.NewEncoder(w).Encode(jwks); err != nil {
			http.Error(w, "Failed to encode JWKS", http.StatusInternalServerError)
			return
		}
	}
}