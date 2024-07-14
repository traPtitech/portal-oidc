package v1

const (
	queryKeyClientID = "client_id"
)

type createClientRequest struct {
	Typ          string   `json:"client_type"`
	Name         string   `json:"client_name"`
	Description  string   `json:"description"`
	RedirectURIs []string `json:"redirect_uris"`
}

type createClientResponse struct {
	ClientID     string   `json:"client_id"`
	Typ          string   `json:"client_type"`
	Name         string   `json:"client_name"`
	Description  string   `json:"description"`
	RedirectURIs []string `json:"redirect_uris"`
	Secret       string   `json:"client_secret"`
	Expires      int64    `json:"client_secret_expires_at"`
}

type updateClientSecretRequest struct {
	ClientID string `json:"client_id"`
}

type deleteClientRequest struct {
	ClientID string `json:"client_id"`
}

type clientSecret struct {
	ClientID string `json:"client_id"`
	Secret   string `json:"client_secret"`
	Expires  int64  `json:"client_secret_expires_at"`
}

type client struct {
	ClientID     string   `json:"client_id"`
	Typ          string   `json:"client_type"`
	Name         string   `json:"client_name"`
	Description  string   `json:"description"`
	RedirectURIs []string `json:"redirect_uris"`
}
