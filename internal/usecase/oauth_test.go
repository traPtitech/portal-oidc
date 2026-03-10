package usecase

import (
	"testing"
	"time"
)

func TestOAuthUseCase_DecideAuthorize(t *testing.T) {
	uc := NewOAuthUseCase()
	now := time.Now()

	int64Ptr := func(v int64) *int64 { return &v }

	tests := []struct {
		name  string
		input AuthorizeInput
		want  AuthorizeAction
	}{
		{
			name: "non-prod always proceeds",
			input: AuthorizeInput{
				Prompt:        "",
				Authenticated: false,
				IsNonProd:     true,
			},
			want: AuthorizeActionProceed,
		},
		{
			name: "prompt=none with authenticated user proceeds",
			input: AuthorizeInput{
				Prompt:        "none",
				Authenticated: true,
				AuthTime:      now,
			},
			want: AuthorizeActionProceed,
		},
		{
			name: "prompt=none with unauthenticated user returns error",
			input: AuthorizeInput{
				Prompt:        "none",
				Authenticated: false,
			},
			want: AuthorizeActionLoginError,
		},
		{
			name: "prompt=login with unauthenticated user redirects to login",
			input: AuthorizeInput{
				Prompt:        "login",
				Authenticated: false,
			},
			want: AuthorizeActionLogin,
		},
		{
			name: "prompt=login with authenticated but reauth not completed redirects to login",
			input: AuthorizeInput{
				Prompt:          "login",
				Authenticated:   true,
				AuthTime:        now,
				ReauthCompleted: false,
			},
			want: AuthorizeActionLogin,
		},
		{
			name: "prompt=login with authenticated and reauth completed proceeds",
			input: AuthorizeInput{
				Prompt:          "login",
				Authenticated:   true,
				AuthTime:        now,
				ReauthCompleted: true,
			},
			want: AuthorizeActionProceed,
		},
		{
			name: "default prompt with unauthenticated user redirects to login",
			input: AuthorizeInput{
				Prompt:        "",
				Authenticated: false,
			},
			want: AuthorizeActionLogin,
		},
		{
			name: "default prompt with authenticated user proceeds",
			input: AuthorizeInput{
				Prompt:        "",
				Authenticated: true,
				AuthTime:      now,
			},
			want: AuthorizeActionProceed,
		},
		{
			name: "max_age expired and reauth not completed redirects to login",
			input: AuthorizeInput{
				Prompt:          "",
				Authenticated:   true,
				AuthTime:        now.Add(-2 * time.Hour),
				MaxAge:          int64Ptr(3600),
				ReauthCompleted: false,
			},
			want: AuthorizeActionLogin,
		},
		{
			name: "max_age expired but reauth completed proceeds",
			input: AuthorizeInput{
				Prompt:          "",
				Authenticated:   true,
				AuthTime:        now.Add(-2 * time.Hour),
				MaxAge:          int64Ptr(3600),
				ReauthCompleted: true,
			},
			want: AuthorizeActionProceed,
		},
		{
			name: "max_age not expired proceeds",
			input: AuthorizeInput{
				Prompt:        "",
				Authenticated: true,
				AuthTime:      now,
				MaxAge:        int64Ptr(3600),
			},
			want: AuthorizeActionProceed,
		},
		{
			name: "max_age nil proceeds",
			input: AuthorizeInput{
				Prompt:        "",
				Authenticated: true,
				AuthTime:      now.Add(-2 * time.Hour),
			},
			want: AuthorizeActionProceed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := uc.EvaluateAuthorize(tt.input)
			if got != tt.want {
				t.Errorf("DecideAuthorize() = %d, want %d", got, tt.want)
			}
		})
	}
}
