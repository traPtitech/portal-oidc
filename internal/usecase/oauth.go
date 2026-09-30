package usecase

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/ory/fosite"

	"github.com/traPtitech/portal-oidc/internal/repository/oauth"
)

// AuthorizeAction represents the result of authorization decision logic.
type AuthorizeAction int

const (
	AuthorizeActionProceed        AuthorizeAction = iota // Proceed with authorization
	AuthorizeActionLogin                                 // Redirect to login
	AuthorizeActionLoginError                            // Return login_required error (prompt=none)
	AuthorizeActionInvalidRequest                        // Return invalid_request error (malformed prompt)
)

// AuthorizeInput contains the parameters needed to decide the authorization action.
//
// The fields mirror OpenID Connect Core 1.0 §3.1.2.1 request parameters.
type AuthorizeInput struct {
	Prompt          string    // OIDC Core §3.1.2.1 (prompt)
	Authenticated   bool      // session-backed login state
	AuthTime        time.Time // OIDC Core §2 auth_time claim
	MaxAge          *int64    // OIDC Core §3.1.2.1 (max_age); nil when absent
	ReauthCompleted bool      // true after the user re-authenticated for this request
}

// OAuthUseCase handles OAuth authorization decision logic.
type OAuthUseCase interface {
	EvaluateAuthorize(input AuthorizeInput) AuthorizeAction
	ProcessToken(ctx context.Context, request *http.Request, session fosite.Session) (OAuthTokenResult, error)
}

type oauthUseCase struct {
	provider fosite.OAuth2Provider
	storage  *oauth.Storage
}

func NewOAuthUseCase(provider fosite.OAuth2Provider, storage *oauth.Storage) OAuthUseCase {
	return &oauthUseCase{
		provider: provider,
		storage:  storage,
	}
}

// EvaluateAuthorize implements the prompt / max_age decision tree from
// OpenID Connect Core 1.0 §3.1.2.3 (Authorization Server Authenticates End-User)
// and §3.1.2.6 (Authentication Error Response).
func (u *oauthUseCase) EvaluateAuthorize(input AuthorizeInput) AuthorizeAction {
	// OIDC Core §3.1.2.1: prompt is a space-delimited, case-sensitive list of
	// ASCII values (e.g. "login consent"), so match individual tokens rather
	// than the raw string.
	prompts := strings.Fields(input.Prompt)
	promptNone := slices.Contains(prompts, "none")
	promptLogin := slices.Contains(prompts, "login")

	// OIDC Core §3.1.2.1: "If this parameter contains none with any other
	// value, an error is returned." Same condition as fosite's openid
	// validator, which also rejects duplicated tokens alongside none.
	if promptNone && len(prompts) > 1 {
		return AuthorizeActionInvalidRequest
	}

	switch {
	case promptNone:
		// OIDC Core §3.1.2.1: prompt=none MUST NOT prompt the user.
		// If no authenticated session exists, return login_required.
		if !input.Authenticated {
			return AuthorizeActionLoginError
		}
	case promptLogin:
		// OIDC Core §3.1.2.1: prompt=login SHOULD reauthenticate the user.
		if !input.Authenticated || !input.ReauthCompleted {
			return AuthorizeActionLogin
		}
	default:
		if !input.Authenticated {
			return AuthorizeActionLogin
		}
	}

	// OIDC Core §3.1.2.1: max_age requires reauth when the elapsed time since
	// the last authentication exceeds the supplied number of seconds.
	if input.MaxAge != nil && time.Since(input.AuthTime) > time.Duration(*input.MaxAge)*time.Second && !input.ReauthCompleted {
		// Under prompt=none no UI may be shown (§3.1.2.1), so report
		// login_required (§3.1.2.6) instead of redirecting to login.
		if promptNone {
			return AuthorizeActionLoginError
		}
		return AuthorizeActionLogin
	}

	return AuthorizeActionProceed
}

type OAuthTokenResult struct {
	Context  context.Context
	Request  fosite.AccessRequester
	Response fosite.AccessResponder
}

func (u *oauthUseCase) ProcessToken(
	ctx context.Context,
	request *http.Request,
	session fosite.Session,
) (OAuthTokenResult, error) {
	result := OAuthTokenResult{Context: ctx}
	accessRequest, err := u.provider.NewAccessRequest(ctx, request, session)
	result.Request = accessRequest
	if err != nil {
		if errors.Is(err, fosite.ErrInvalidGrant) && accessRequest != nil {
			if invalidateErr := u.storage.InvalidateAuthorizeCodeSession(ctx, accessRequest.GetID()); invalidateErr != nil {
				err = fosite.ErrServerError.WithWrap(invalidateErr)
			}
		}
		return result, err
	}

	for _, scope := range accessRequest.GetRequestedScopes() {
		accessRequest.GrantScope(scope)
	}

	response, err := u.provider.NewAccessResponse(ctx, accessRequest)
	result.Response = response
	if err != nil {
		return result, err
	}

	return result, nil
}
