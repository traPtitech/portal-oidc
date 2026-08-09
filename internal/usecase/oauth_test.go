package usecase

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/ory/fosite"

	"github.com/traPtitech/portal-oidc/internal/repository"
	"github.com/traPtitech/portal-oidc/internal/repository/oauth"
)

func TestOAuthUseCase_DecideAuthorize(t *testing.T) {
	uc := NewOAuthUseCase(nil, nil)
	now := time.Now()

	int64Ptr := func(v int64) *int64 { return &v }

	tests := []struct {
		name  string
		input AuthorizeInput
		want  AuthorizeAction
	}{
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
		{
			name: "prompt=none with expired max_age returns error instead of showing UI",
			input: AuthorizeInput{
				Prompt:          "none",
				Authenticated:   true,
				AuthTime:        now.Add(-2 * time.Hour),
				MaxAge:          int64Ptr(3600),
				ReauthCompleted: false,
			},
			want: AuthorizeActionLoginError,
		},
		{
			name: "space-delimited prompt list containing login forces reauth",
			input: AuthorizeInput{
				Prompt:          "login consent",
				Authenticated:   true,
				AuthTime:        now,
				ReauthCompleted: false,
			},
			want: AuthorizeActionLogin,
		},
		{
			name: "prompt combining none with another value returns invalid_request",
			input: AuthorizeInput{
				Prompt:        "consent none",
				Authenticated: false,
			},
			want: AuthorizeActionInvalidRequest,
		},
		{
			name: "prompt combining none with another value returns invalid_request even when authenticated",
			input: AuthorizeInput{
				Prompt:          "none login",
				Authenticated:   true,
				AuthTime:        now,
				ReauthCompleted: true,
			},
			want: AuthorizeActionInvalidRequest,
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

func TestOAuthUseCase_ProcessToken(t *testing.T) {
	requestErr := fosite.ErrInvalidGrant.WithHint("invalid access request")
	responseErr := errors.New("failed to create response")
	invalidationErr := errors.New("failed to invalidate authorization code")

	tests := []struct {
		name               string
		requestErr         error
		responseErr        error
		invalidationErr    error
		requestID          string
		wantErrors         []error
		wantInvalidated    bool
		wantResponseCalled bool
		wantResponse       bool
		wantScopesGranted  bool
	}{
		{
			name:               "successful token request returns response",
			requestID:          "authorization-code",
			wantResponseCalled: true,
			wantResponse:       true,
			wantScopesGranted:  true,
		},
		{
			name:            "invalid grant invalidates authorization code",
			requestErr:      requestErr,
			requestID:       "authorization-code",
			wantErrors:      []error{requestErr},
			wantInvalidated: true,
		},
		{
			name:               "response error does not invalidate authorization code",
			responseErr:        responseErr,
			requestID:          "authorization-code",
			wantErrors:         []error{responseErr},
			wantResponseCalled: true,
			wantScopesGranted:  true,
		},
		{
			name:       "server error does not invalidate authorization code",
			requestErr: fosite.ErrServerError,
			wantErrors: []error{fosite.ErrServerError},
		},
		{
			name:            "invalidation error returns server error",
			requestErr:      requestErr,
			invalidationErr: invalidationErr,
			requestID:       "authorization-code",
			wantErrors:      []error{fosite.ErrServerError, invalidationErr},
			wantInvalidated: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/oauth2/token", nil)
			if err != nil {
				t.Fatal(err)
			}

			session := &fosite.DefaultSession{}
			accessRequest := fosite.NewAccessRequest(session)
			accessRequest.SetRequestedScopes(fosite.Arguments{"openid", "profile"})
			accessResponse := fosite.NewAccessResponse()
			invalidated := false
			storage := newOAuthTokenStorage(func(_ context.Context, code string) error {
				if code != "authorization-code" {
					t.Errorf("authorization code = %q", code)
				}
				invalidated = true
				return tt.invalidationErr
			})

			responseCalled := false
			provider := &oauthTokenProviderStub{
				newAccessRequest: func(gotCtx context.Context, gotReq *http.Request, gotSession fosite.Session) (fosite.AccessRequester, error) {
					if gotCtx != ctx || gotReq != req {
						t.Error("NewAccessRequest received unexpected arguments")
					}
					if gotSession != session {
						t.Error("NewAccessRequest received a different session")
					}
					if tt.requestID != "" {
						accessRequest.SetID(tt.requestID)
					}
					return accessRequest, tt.requestErr
				},
				newAccessResponse: func(gotCtx context.Context, gotRequest fosite.AccessRequester) (fosite.AccessResponder, error) {
					responseCalled = true
					if gotCtx != ctx || gotRequest != accessRequest {
						t.Error("NewAccessResponse received unexpected arguments")
					}
					if tt.responseErr != nil {
						return nil, tt.responseErr
					}
					return accessResponse, nil
				},
			}

			result, err := NewOAuthUseCase(provider, storage).ProcessToken(ctx, req, session)
			if len(tt.wantErrors) == 0 && err != nil {
				t.Fatalf("ProcessToken() error = %v", err)
			}
			for _, wantErr := range tt.wantErrors {
				if !errors.Is(err, wantErr) {
					t.Errorf("ProcessToken() error = %v, want %v", err, wantErr)
				}
			}
			if result.Context != ctx {
				t.Error("ProcessToken() returned a different context")
			}
			if result.Request != accessRequest {
				t.Error("ProcessToken() returned a different request")
			}
			if invalidated != tt.wantInvalidated {
				t.Errorf("authorization code invalidated = %t, want %t", invalidated, tt.wantInvalidated)
			}
			if responseCalled != tt.wantResponseCalled {
				t.Errorf("NewAccessResponse called = %t, want %t", responseCalled, tt.wantResponseCalled)
			}
			if (result.Response == accessResponse) != tt.wantResponse {
				t.Errorf("ProcessToken() returned response = %t, want %t", result.Response == accessResponse, tt.wantResponse)
			}
			scopesGranted := accessRequest.GetGrantedScopes().Has("openid", "profile")
			if scopesGranted != tt.wantScopesGranted {
				t.Errorf("requested scopes granted = %t, want %t", scopesGranted, tt.wantScopesGranted)
			}
		})
	}
}

type oauthTokenProviderStub struct {
	fosite.OAuth2Provider
	newAccessRequest  func(context.Context, *http.Request, fosite.Session) (fosite.AccessRequester, error)
	newAccessResponse func(context.Context, fosite.AccessRequester) (fosite.AccessResponder, error)
}

func (s *oauthTokenProviderStub) NewAccessRequest(
	ctx context.Context,
	req *http.Request,
	session fosite.Session,
) (fosite.AccessRequester, error) {
	return s.newAccessRequest(ctx, req, session)
}

func (s *oauthTokenProviderStub) NewAccessResponse(
	ctx context.Context,
	requester fosite.AccessRequester,
) (fosite.AccessResponder, error) {
	return s.newAccessResponse(ctx, requester)
}

type oauthTokenAuthCodeRepositoryStub struct {
	repository.AuthCodeRepository
	markUsed func(context.Context, string) error
}

func (s *oauthTokenAuthCodeRepositoryStub) MarkUsed(ctx context.Context, code string) error {
	return s.markUsed(ctx, code)
}

func newOAuthTokenStorage(markUsed func(context.Context, string) error) *oauth.Storage {
	return oauth.NewStorage(nil, nil, nil, &oauthTokenAuthCodeRepositoryStub{markUsed: markUsed}, nil, nil)
}
