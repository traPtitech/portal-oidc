package v1

import (
	"encoding/json"
	"net/http"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/traPtitech/portal-oidc/pkg/domain/portal"
)

func (h *Handler) UserInfoHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	sess := &openid.DefaultSession{}

	tt, ar, err := h.oauth2.IntrospectToken(ctx, fosite.AccessTokenFromRequest(r), fosite.AccessToken, sess)
	if err != nil {
		h.oauth2.WriteAccessError(ctx, w, ar, err)
		return
	}

	if tt != fosite.AccessToken {
		h.oauth2.WriteAccessError(ctx, w, ar, fosite.ErrRequestUnauthorized.WithHint("The token is not an access token"))
		return
	}

	claims := sess.IDTokenClaims()
	sub := portal.PortalUserID(claims.Subject)
	ui, err := h.usecase.GetUserInfo(ctx, sub)
	if err != nil {
		h.oauth2.WriteAccessError(ctx, w, ar, err)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(ui)
	if err != nil {
		h.oauth2.WriteAccessError(ctx, w, ar, err)
		return
	}

	return
}
