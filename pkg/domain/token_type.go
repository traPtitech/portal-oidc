package domain

type TokenType int

const (
	TokenTypeAccessToken TokenType = iota
	TokenTypeRefreshToken
)

// String method for better debugging
func (t TokenType) String() string {
	switch t {
	case TokenTypeAccessToken:
		return "access_token"
	case TokenTypeRefreshToken:
		return "refresh_token"
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
	default:
		return -1
	}
}

func (t TokenType) Valid() bool {
	return t == TokenTypeAccessToken || t == TokenTypeRefreshToken
}
