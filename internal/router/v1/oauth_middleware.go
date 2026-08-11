package v1

import (
	"net/http"

	"github.com/labstack/echo/v5"
)

// AllowMissingAuthorizeResponseType lets fosite handle a missing response_type.
// The generated OpenAPI wrapper otherwise rejects the request before fosite can
// return the OAuth error to a validated redirect URI. An empty value satisfies
// only the wrapper's presence check; fosite still rejects it as required.
func AllowMissingAuthorizeResponseType(next echo.HandlerFunc) echo.HandlerFunc {
	return func(ctx *echo.Context) error {
		req := ctx.Request()
		if req.Method == http.MethodGet && req.URL.Path == "/oauth2/authorize" {
			if !req.URL.Query().Has("response_type") {
				if req.URL.RawQuery != "" {
					req.URL.RawQuery += "&"
				}
				req.URL.RawQuery += "response_type="
			}
		}

		return next(ctx)
	}
}
