package v1

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository"
	"github.com/traPtitech/portal-oidc/internal/repository/oidc"
	"github.com/traPtitech/portal-oidc/internal/router/internalapi"
	"github.com/traPtitech/portal-oidc/internal/usecase"
)

func provisionFixture() domain.Account {
	return domain.Account{UserID: uuid.New(), Email: uuid.NewString() + "@example.test", EmailVerified: false, ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond), AuthVerifier: domain.AuthVerifier{Version: 1, Alg: "argon2id-verifier-v1", Params: domain.CurrentKDFPolicy(), Hash: base64.RawURLEncoding.EncodeToString(make([]byte, 32))}}
}
func identityHandler() (*echo.Echo, repository.AccountRepository) {
	r := repository.NewAccountRepository(testDB, oidc.New(testDB))
	e := echo.New()
	internalapi.Register(e, usecase.NewAccountUseCase(r), "test-internal-token")
	return e, r
}
func identityRequest(e *echo.Echo, method, path, token string, body []byte) int {
	r := httptest.NewRequestWithContext(context.Background(), method, path, bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Portal-Internal-Token", token)
	w := httptest.NewRecorder()
	e.ServeHTTP(w, r)
	return w.Code
}
func TestProvisionContract(t *testing.T) {
	e, repo := identityHandler()
	a := provisionFixture()
	body := mustIdentityJSON(t, a)
	call := func(data []byte, want int) {
		t.Helper()
		if got := identityRequest(e, "POST", "/internal/users/provision", "test-internal-token", data); got != want {
			t.Fatalf("status %d, want %d", got, want)
		}
	}
	if got := identityRequest(e, "POST", "/internal/users/provision", "", body); got != 401 {
		t.Fatal(got)
	}
	call(body, 201)
	call(body, 200)
	stored, err := repo.GetByID(t.Context(), a.UserID)
	if err != nil || stored.EmailVerified || stored.AuthVerifier != a.AuthVerifier {
		t.Fatalf("stored account mismatch: %v", err)
	}
	other := a
	other.Email = "different@example.test"
	b := mustIdentityJSON(t, other)
	call(b, 409)
	other = a
	other.UserID = uuid.New()
	b = mustIdentityJSON(t, other)
	call(b, 409)
	var object map[string]any
	_ = json.Unmarshal(body, &object)
	delete(object, "emailVerified")
	b = mustIdentityJSON(t, object)
	call(b, 400)
	object["emailVerified"] = nil
	b = mustIdentityJSON(t, object)
	call(b, 400)
	object["emailVerified"] = false
	object["password"] = "must-not-be-accepted"
	b = mustIdentityJSON(t, object)
	call(b, 400)
	call(append(body, []byte("{}")...), 400)
	invalid := provisionFixture()
	invalid.AuthVerifier.Params.MemoryKiB = 1
	b = mustIdentityJSON(t, invalid)
	call(b, 422)
	expired := provisionFixture()
	expired.ExpiresAt = time.Now().Add(-time.Hour)
	b = mustIdentityJSON(t, expired)
	call(b, 422)
	for range 2 {
		if got := identityRequest(e, "DELETE", "/internal/users/"+a.UserID.String(), "test-internal-token", nil); got != 204 {
			t.Fatal(got)
		}
	}
	if _, err := repo.GetByID(t.Context(), a.UserID); err != repository.ErrAccountNotFound {
		t.Fatal("account survived deletion")
	}
	disabled := echo.New()
	internalapi.Register(disabled, usecase.NewAccountUseCase(repo), "")
	if got := identityRequest(disabled, "POST", "/internal/users/provision", "", body); got != 404 {
		t.Fatal(got)
	}
}
func TestConcurrentProvision(t *testing.T) {
	e, _ := identityHandler()
	a := provisionFixture()
	b := mustIdentityJSON(t, a)
	results := make(chan int, 16)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() { results <- identityRequest(e, "POST", "/internal/users/provision", "test-internal-token", b) })
	}
	wg.Wait()
	close(results)
	created := 0
	for s := range results {
		if s == 201 {
			created++
		} else if s != 200 {
			t.Fatal(s)
		}
	}
	if created != 1 {
		t.Fatal(created)
	}
	a.Email = uuid.NewString() + "@example.test"
	results = make(chan int, 16)
	for range 16 {
		v := a
		v.UserID = uuid.New()
		data := mustIdentityJSON(t, v)
		wg.Go(func() {
			results <- identityRequest(e, "POST", "/internal/users/provision", "test-internal-token", data)
		})
	}
	wg.Wait()
	close(results)
	created = 0
	for s := range results {
		if s == 201 {
			created++
		} else if s != 409 {
			t.Fatal(s)
		}
	}
	if created != 1 {
		t.Fatal(created)
	}
}
func TestProvisionDatabaseFailure(t *testing.T) {
	e, _ := identityHandler()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	a := provisionFixture()
	body := mustIdentityJSON(t, a)
	req := httptest.NewRequestWithContext(ctx, "POST", "/internal/users/provision", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Portal-Internal-Token", "test-internal-token")
	w := httptest.NewRecorder()
	e.ServeHTTP(w, req)
	if w.Code != 500 {
		t.Fatal(w.Code)
	}
}

func mustIdentityJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
