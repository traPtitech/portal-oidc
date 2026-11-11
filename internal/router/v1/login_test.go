package v1

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/traPtitech/portal-oidc/internal/usecase"
)

func TestAuthSecretLogin(t *testing.T) {
	_, accounts := identityHandler()
	a := provisionFixture()
	a.TrapID = "TestUser"
	raw := make([]byte, 32)
	raw[0] = 42
	secret := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256(raw)
	a.AuthVerifier.Hash = base64.RawURLEncoding.EncodeToString(hash[:])
	if _, e := accounts.Provision(t.Context(), a); e != nil {
		t.Fatal(e)
	}
	users := usecase.NewUserUseCase(accounts)
	for _, bad := range []string{a.AuthVerifier.Hash, "password", secret + "="} {
		if _, e := users.Authenticate(t.Context(), a.TrapID, bad); !errors.Is(e, usecase.ErrInvalidPassword) {
			t.Fatal("accepted wrong secret", e)
		}
	}
	for _, badID := range []string{a.Email, strings.ToLower(a.TrapID), "missing", ""} {
		if _, err := users.Authenticate(t.Context(), badID, secret); !errors.Is(err, usecase.ErrInvalidPassword) {
			t.Fatalf("accepted identifier %q: %v", badID, err)
		}
	}
	user, e := users.Authenticate(t.Context(), a.TrapID, secret)
	if e != nil || user.EmailVerified || user.ID != a.UserID {
		t.Fatal("unverified login failed", e)
	}
	h := NewHandler(nil, nil, nil, users, OAuthConfig{Issuer: "http://localhost", SessionSecret: []byte("01234567890123456789012345678901")})
	router := echo.New()
	router.GET("/login", h.GetLogin)
	router.POST("/login", h.PostLogin)
	page := httptest.NewRecorder()
	router.ServeHTTP(page, httptest.NewRequestWithContext(t.Context(), "GET", "/login?return_url=%2Foauth2%2Fauthorize", nil))
	match := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindStringSubmatch(page.Body.String())
	if len(match) != 2 {
		t.Fatal("missing CSRF")
	}
	post := func(csrf, credential string) *httptest.ResponseRecorder {
		form := url.Values{"trapId": {a.TrapID}, "auth_secret": {credential}, "csrf_token": {csrf}, "return_url": {"//attacker.test"}}
		req := httptest.NewRequestWithContext(t.Context(), "POST", "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, cookie := range page.Result().Cookies() {
			req.AddCookie(cookie)
		}
		out := httptest.NewRecorder()
		router.ServeHTTP(out, req)
		return out
	}
	if out := post("bad", secret); out.Code != 403 {
		t.Fatal(out.Code)
	}
	if out := post(match[1], a.AuthVerifier.Hash); out.Code != 401 {
		t.Fatal(out.Code)
	}
	out := post(match[1], secret)
	if out.Code != 302 || out.Header().Get("Location") != "/" {
		t.Fatal(out.Code)
	}
	if _, e := testDB.ExecContext(t.Context(), "UPDATE identity_accounts SET email=$1 WHERE user_id=$2", "changed-"+a.Email, a.UserID); e != nil {
		t.Fatal(e)
	}
	if _, e := users.Authenticate(t.Context(), a.TrapID, secret); e != nil {
		t.Fatalf("email change affected credentials: %v", e)
	}
	if _, e := testDB.ExecContext(t.Context(), "UPDATE identity_accounts SET expires_at=$1 WHERE user_id=$2", time.Now().Add(-time.Hour), a.UserID); e != nil {
		t.Fatal(e)
	}
	if _, e := users.Authenticate(t.Context(), a.TrapID, secret); !errors.Is(e, usecase.ErrUserNotActive) {
		t.Fatal(e)
	}
}
