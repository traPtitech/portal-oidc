package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/traPtitech/portal-oidc/pkg/domain"
	"github.com/traPtitech/portal-oidc/pkg/domain/portal"
)

var _ portal.Portal = (*Portal)(nil)

type Portal struct {
	client  *http.Client
	baseURL string
}

func NewPortal(conf Config) *Portal {
	return &Portal{
		client:  &http.Client{},
		baseURL: conf.BaseURL,
	}
}

type userResponse struct {
	Grade string `json:"grade"`
}

func (p *Portal) GetGrade(ctx context.Context, id domain.TrapID) (string, error) {
	url := fmt.Sprintf("%s/api/users/%s", p.baseURL, id.String())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("portal API returned status %d", resp.StatusCode)
	}

	var user userResponse
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return "", err
	}

	return user.Grade, nil
}

type verifyPasswordRequest struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type verifyPasswordResponse struct {
	Valid bool `json:"valid"`
}

func (p *Portal) VerifyPassword(ctx context.Context, id domain.TrapID, password string) (bool, error) {
	url := fmt.Sprintf("%s/api/auth/verify", p.baseURL)

	body, err := json.Marshal(verifyPasswordRequest{
		Name:     id.String(),
		Password: password,
	})
	if err != nil {
		return false, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("portal API returned status %d", resp.StatusCode)
	}

	var result verifyPasswordResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}

	return result.Valid, nil
}
