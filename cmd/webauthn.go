package main

import (
	"fmt"
	"net/url"

	"github.com/go-webauthn/webauthn/webauthn"
)

// newWebAuthn builds the per-process WebAuthn configuration. RPID is the
// effective domain extracted from the issuer URL — WebAuthn relies on this
// being a registrable suffix of the page origin (W3C-WebAuthn-Level-3 §5.1.3).
// RPOrigins lists the exact origins from which assertions are accepted.
func newWebAuthn(issuer string) (*webauthn.WebAuthn, error) {
	u, err := url.Parse(issuer)
	if err != nil {
		return nil, fmt.Errorf("parse issuer %q: %w", issuer, err)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("issuer %q has no host", issuer)
	}
	return webauthn.New(&webauthn.Config{
		RPDisplayName: "traPortal",
		RPID:          host,
		RPOrigins:     []string{u.Scheme + "://" + u.Host},
	})
}
