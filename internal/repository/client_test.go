package repository

import (
	"testing"

	"github.com/traPtitech/portal-oidc/internal/domain"
)

func TestClientPermissionDefaults(t *testing.T) {
	tests := []struct {
		name                      string
		grants, responses, scopes []string
		wantGrants, wantResponses string
		wantScopes                string
	}{
		{
			name:       "omitted",
			wantGrants: `["authorization_code","refresh_token"]`, wantResponses: `["code"]`,
			wantScopes: `["openid","profile","email"]`,
		},
		{
			name: "explicit empty", grants: []string{}, responses: []string{}, scopes: []string{},
			wantGrants: `[]`, wantResponses: `[]`, wantScopes: `[]`,
		},
		{
			name: "custom", grants: []string{"authorization_code"}, responses: []string{"code"}, scopes: []string{"openid"},
			wantGrants: `["authorization_code"]`, wantResponses: `["code"]`, wantScopes: `["openid"]`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &domain.Client{GrantTypes: tt.grants, ResponseTypes: tt.responses, Scopes: tt.scopes}
			create, err := buildCreateParams(client, "")
			if err != nil {
				t.Fatal(err)
			}
			update, err := buildUpdateParams(client)
			if err != nil {
				t.Fatal(err)
			}
			for operation, values := range map[string][3]string{
				"create": {string(create.GrantTypes), string(create.ResponseTypes), string(create.Scopes)},
				"update": {string(update.GrantTypes), string(update.ResponseTypes), string(update.Scopes)},
			} {
				want := [3]string{tt.wantGrants, tt.wantResponses, tt.wantScopes}
				if values != want {
					t.Errorf("%s permissions: got %v, want %v", operation, values, want)
				}
			}
		})
	}
}
