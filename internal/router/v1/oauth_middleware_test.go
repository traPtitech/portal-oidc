package v1

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v5"
)

func TestAllowMissingAuthorizeResponseType(t *testing.T) {
	tests := []struct {
		name         string
		method       string
		target       string
		wantRawQuery string
	}{
		{
			name:         "missing response type",
			method:       http.MethodGet,
			target:       "/oauth2/authorize?client_id=client",
			wantRawQuery: "client_id=client&response_type=",
		},
		{
			name:         "present response type",
			method:       http.MethodGet,
			target:       "/oauth2/authorize?client_id=client&response_type=code",
			wantRawQuery: "client_id=client&response_type=code",
		},
		{
			name:         "other GET endpoint",
			method:       http.MethodGet,
			target:       "/health?client_id=client",
			wantRawQuery: "client_id=client",
		},
		{
			name:         "authorize POST",
			method:       http.MethodPost,
			target:       "/oauth2/authorize?client_id=client",
			wantRawQuery: "client_id=client",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := echo.New()
			req := httptest.NewRequestWithContext(
				context.Background(),
				tt.method,
				tt.target,
				nil,
			)
			ctx := e.NewContext(req, httptest.NewRecorder())
			var gotRawQuery string
			next := func(ctx *echo.Context) error {
				gotRawQuery = ctx.Request().URL.RawQuery
				return nil
			}

			if err := AllowMissingAuthorizeResponseType(next)(ctx); err != nil {
				t.Fatalf("middleware returned error: %v", err)
			}
			if gotRawQuery != tt.wantRawQuery {
				t.Fatalf("RawQuery = %q, want %q", gotRawQuery, tt.wantRawQuery)
			}
		})
	}
}
