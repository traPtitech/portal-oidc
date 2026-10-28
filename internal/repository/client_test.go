package repository

import (
	"errors"
	"testing"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository/oidc"
)

func TestClientPermissionDefaults(t *testing.T) {
	tests := []struct {
		name            string
		values          []string
		wantCreate      [3]string
		wantUpdate      [3]string
		wantUpdateError bool
	}{
		{
			name:            "unspecified",
			wantUpdateError: true,
			wantCreate:      [3]string{`["authorization_code","refresh_token"]`, `["code"]`, `["openid","profile","email"]`},
			wantUpdate:      [3]string{`[]`, `[]`, `[]`},
		},
		{
			name: "explicitly empty", values: []string{},
			wantCreate: [3]string{`[]`, `[]`, `[]`},
			wantUpdate: [3]string{`[]`, `[]`, `[]`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &domain.Client{Status: domain.ClientStatusActive, GrantTypes: tt.values, ResponseTypes: tt.values, Scopes: tt.values}
			created, err := buildCreateParams(client, "")
			if err != nil {
				t.Fatal(err)
			}
			gotCreate := [3]string{string(created.GrantTypes), string(created.ResponseTypes), string(created.Scopes)}
			if gotCreate != tt.wantCreate {
				t.Errorf("create permissions = %v, want %v", gotCreate, tt.wantCreate)
			}
			updated, err := buildUpdateParams(client)
			if tt.wantUpdateError {
				if !errors.Is(err, ErrInvalidClientMetadata) {
					t.Fatalf("unspecified permissions: error = %v", err)
				}
				return
			}
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
				Status: string(domain.ClientStatusActive),
				Name:   "before", GrantTypes: []byte(permissions[0]),
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

func TestClientStatusValidation(t *testing.T) {
	tests := []struct {
		name            string
		status          domain.ClientStatus
		wantCreate      domain.ClientStatus
		wantCreateError bool
		wantUpdateError bool
	}{
		{name: "omitted", wantCreate: domain.ClientStatusActive, wantUpdateError: true},
		{name: "active", status: domain.ClientStatusActive, wantCreate: domain.ClientStatusActive},
		{name: "suspended", status: domain.ClientStatusSuspended, wantCreate: domain.ClientStatusSuspended},
		{name: "wrong case", status: "Active", wantCreateError: true, wantUpdateError: true},
		{name: "whitespace", status: "active ", wantCreateError: true, wantUpdateError: true},
		{name: "unknown", status: "unknown", wantCreateError: true, wantUpdateError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &domain.Client{Status: tt.status, GrantTypes: []string{}, ResponseTypes: []string{}, Scopes: []string{}}
			created, err := buildCreateParams(client, "")
			if tt.wantCreateError {
				if !errors.Is(err, ErrInvalidClientMetadata) {
					t.Fatalf("create error = %v, want ErrInvalidClientMetadata", err)
				}
			} else if err != nil || created.Status != string(tt.wantCreate) {
				t.Fatalf("create status = %q, error = %v; want %q", created.Status, err, tt.wantCreate)
			}
			updated, err := buildUpdateParams(client)
			if tt.wantUpdateError {
				if !errors.Is(err, ErrInvalidClientMetadata) {
					t.Fatalf("update error = %v, want ErrInvalidClientMetadata", err)
				}
			} else if err != nil || updated.Status != string(tt.status) {
				t.Fatalf("update status = %q, error = %v; want %q", updated.Status, err, tt.status)
			}
			if client.Status != tt.status {
				t.Fatalf("validation mutated the caller's status: %q", client.Status)
			}
		})
	}
}

func TestClientUpdateRequiresEachPermissionSlice(t *testing.T) {
	for _, field := range []string{"grant_types", "response_types", "scopes"} {
		t.Run(field, func(t *testing.T) {
			c := &domain.Client{Status: domain.ClientStatusActive, GrantTypes: []string{}, ResponseTypes: []string{}, Scopes: []string{}}
			switch field {
			case "grant_types":
				c.GrantTypes = nil
			case "response_types":
				c.ResponseTypes = nil
			case "scopes":
				c.Scopes = nil
			}
			if _, err := buildUpdateParams(c); !errors.Is(err, ErrInvalidClientMetadata) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}
