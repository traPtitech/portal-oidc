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
type AuthorizeInput struct {
	Prompt          string
	Authenticated   bool
	AuthTime        time.Time
	MaxAge          *int64 // nil means max_age parameter is not present
	ReauthCompleted bool
	IsNonProd       bool
}

// OAuthUseCase handles OAuth authorization decision logic.
type OAuthUseCase interface {
	EvaluateAuthorize(input AuthorizeInput) AuthorizeAction
}

type oauthUseCase struct{}

func NewOAuthUseCase() OAuthUseCase {
	return &oauthUseCase{}
}

func (u *oauthUseCase) EvaluateAuthorize(input AuthorizeInput) AuthorizeAction {
	if input.IsNonProd {
		return AuthorizeActionProceed
	}

	switch input.Prompt {
	case "none":
		if !input.Authenticated {
			return AuthorizeActionLoginError
		}
	case "login":
		if !input.Authenticated || !input.ReauthCompleted {
			return AuthorizeActionLogin
		}
	default:
		if !input.Authenticated {
			return AuthorizeActionLogin
		}
	}

	if input.MaxAge != nil && time.Since(input.AuthTime) > time.Duration(*input.MaxAge)*time.Second && !input.ReauthCompleted {
		return AuthorizeActionLogin
	}

	return AuthorizeActionProceed
}
