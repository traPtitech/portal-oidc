package oauth

import (
	"github.com/ory/fosite"
	"golang.org/x/crypto/bcrypt"
)

var _ fosite.Client = (*Client)(nil)

type Client struct {
	ID            string
	Secret        []byte
	RedirectURIs  []string
	GrantTypes    []string
	ResponseTypes []string
	Scopes        []string
	Public        bool
}

func (c *Client) GetID() string                   { return c.ID }
func (c *Client) GetHashedSecret() []byte         { return c.Secret }
func (c *Client) GetRedirectURIs() []string       { return c.RedirectURIs }
func (c *Client) GetGrantTypes() fosite.Arguments { return c.GrantTypes }
func (c *Client) GetResponseTypes() fosite.Arguments {
	if len(c.ResponseTypes) == 0 {
		return []string{"code"}
	}
	return c.ResponseTypes
}
func (c *Client) GetScopes() fosite.Arguments   { return c.Scopes }
func (c *Client) IsPublic() bool                { return c.Public }
func (c *Client) GetAudience() fosite.Arguments { return nil }

func ValidateClientSecret(hashedSecret []byte, secret string) bool {
	return bcrypt.CompareHashAndPassword(hashedSecret, []byte(secret)) == nil
}
