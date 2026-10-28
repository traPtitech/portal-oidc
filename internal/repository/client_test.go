package repository

import (
	"errors"
	"testing"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository/oidc"
)

func TestClientPermissionDefaults(t *testing.T) {
	tests := []struct {
		name       string
		values     []string
		wantCreate [3]string
		wantUpdate [3]string
	}{
		{
			name:       "unspecified",
			wantCreate: [3]string{`["authorization_code","refresh_token"]`, `["code"]`, `["openid","profile","email"]`},
			wantUpdate: [3]string{`[]`, `[]`, `[]`},
		},
		{
			name: "explicitly empty", values: []string{},
			wantCreate: [3]string{`[]`, `[]`, `[]`},
			wantUpdate: [3]string{`[]`, `[]`, `[]`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &domain.Client{Status: "active", TokenEndpointAuth: "client_secret_basic", IDTokenAlg: "RS256", GrantTypes: tt.values, ResponseTypes: tt.values, Scopes: tt.values}
			created, err := buildCreateParams(client, "")
			if err != nil {
				t.Fatal(err)
			}
			gotCreate := [3]string{string(created.GrantTypes), string(created.ResponseTypes), string(created.Scopes)}
			if gotCreate != tt.wantCreate {
				t.Errorf("create permissions = %v, want %v", gotCreate, tt.wantCreate)
			}
			updated, err := buildUpdateParams(client)
			if err != nil {
				t.Fatal(err)
			}
			gotUpdate := [3]string{string(updated.GrantTypes), string(updated.ResponseTypes), string(updated.Scopes)}
			if gotUpdate != tt.wantUpdate {
				t.Errorf("update permissions = %v, want %v", gotUpdate, tt.wantUpdate)
			}
		})
	}
}

func TestClientRenamePreservesPermissions(t *testing.T) {
	for _, permissions := range [][3]string{
		{`[]`, `[]`, `[]`},
		{`["authorization_code"]`, `["code"]`, `["openid"]`},
	} {
		t.Run(permissions[0], func(t *testing.T) {
			r := &clientRepository{}
			client, err := r.toDomain(oidc.Client{
				Status: "active", TokenEndpointAuth: "client_secret_basic", IDTokenAlg: "RS256",
				Name: "before", GrantTypes: []byte(permissions[0]),
				ResponseTypes: []byte(permissions[1]), Scopes: []byte(permissions[2]),
			})
			if err != nil {
				t.Fatal(err)
			}
			client.Name = "after"
			params, err := buildUpdateParams(client)
			if err != nil {
				t.Fatal(err)
			}
			got := [3]string{string(params.GrantTypes), string(params.ResponseTypes), string(params.Scopes)}
			if got != permissions {
				t.Errorf("rename changed permissions: %v -> %v", permissions, got)
			}
		})
	}
}

func TestClientUpdateRejectsMissingSecurityMetadata(t *testing.T) {
	for _, field := range []string{"status", "unknown_status", "token_endpoint_auth", "id_token_alg"} {
		t.Run(field, func(t *testing.T) {
			c := &domain.Client{Status: "suspended", TokenEndpointAuth: "client_secret_basic", IDTokenAlg: "RS256"}
			switch field {
			case "status":
				c.Status = ""
			case "unknown_status":
				c.Status = "Active"
			case "token_endpoint_auth":
				c.TokenEndpointAuth = ""
			case "id_token_alg":
				c.IDTokenAlg = ""
			}
			if _, err := buildUpdateParams(c); !errors.Is(err, ErrInvalidClientMetadata) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}
