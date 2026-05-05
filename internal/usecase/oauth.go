package usecase

import "time"

// AuthorizeAction represents the result of authorization decision logic.
type AuthorizeAction int

const (
	AuthorizeActionProceed    AuthorizeAction = iota // Proceed with authorization
	AuthorizeActionLogin                             // Redirect to login
	AuthorizeActionLoginError                        // Return login_required error (prompt=none)
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
}

type oauthUseCase struct{}

func NewOAuthUseCase() OAuthUseCase {
	return &oauthUseCase{}
}

// EvaluateAuthorize implements the prompt / max_age decision tree from
// OpenID Connect Core 1.0 §3.1.2.3 (Authorization Server Authenticates End-User)
// and §3.1.2.6 (Authentication Error Response).
func (u *oauthUseCase) EvaluateAuthorize(input AuthorizeInput) AuthorizeAction {
	switch input.Prompt {
	case "none":
		// OIDC Core §3.1.2.1: prompt=none MUST NOT prompt the user.
		// If no authenticated session exists, return login_required.
		if !input.Authenticated {
			return AuthorizeActionLoginError
		}
	case "login":
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
		return AuthorizeActionLogin
	}

	return AuthorizeActionProceed
}
