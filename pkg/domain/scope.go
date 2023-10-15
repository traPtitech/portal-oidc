package domain

var (
	SupportedResponseTypes            = []string{"id_token", "code", "token", "id_token token", "code id_token", "code token", "code id_token token", "token id_token"}
	SupportedGrantTypes               = []string{"implicit", "refresh_token", "authorization_code", "client_credentials"}
	SupportedScopes                   = []string{"openid", "offline", "offline_access"}
	SupportedACRValues                = []string{"urn:oasis:names:tc:SAML:2.0:ac:classes:Password"}
	SupportedTokenEndpointAuthMethods = []string{"client_secret_basic", "client_secret_post"}
	SupportedSubjectTypes             = []string{"public"}
	SupportedIDTokenSigningAlgs       = []string{"RS256"}
	SupportedClaims                   = []string{"aud", "exp", "iat", "iss", "sub"}
)
