package domain

type TokenType int

const (
	TokenTypeAccessToken TokenType = iota
	TokenTypeRefreshToken
	TokenTypeAuthorizeCode
	TokenTypeOpenIDConnectSession
	TokenTypePKCERequestSession
)

// String method for better debugging
func (t TokenType) String() string {
	switch t {
	case TokenTypeAccessToken:
		return "access_token"
	case TokenTypeRefreshToken:
		return "refresh_token"
	case TokenTypeAuthorizeCode:
		return "authorize_code"
	case TokenTypeOpenIDConnectSession:
		return "openid_connect_session"
	case TokenTypePKCERequestSession:
		return "pkce_request_session"
	default:
		return "unknown"
	}
}

// FromString converts string to TokenType
func TokenTypeFromString(s string) TokenType {
	switch s {
	case "access_token":
		return TokenTypeAccessToken
	case "refresh_token":
		return TokenTypeRefreshToken
	case "authorize_code":
		return TokenTypeAuthorizeCode
	case "openid_connect_session":
		return TokenTypeOpenIDConnectSession
	case "pkce_request_session":
		return TokenTypePKCERequestSession
	default:
		return -1
	}
}

func (t TokenType) Valid() bool {
	return t == TokenTypeAccessToken || t == TokenTypeRefreshToken || t == TokenTypeAuthorizeCode || t == TokenTypeOpenIDConnectSession || t == TokenTypePKCERequestSession
}
