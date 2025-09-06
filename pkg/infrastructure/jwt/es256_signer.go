package jwt

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"

	jwtgo "github.com/golang-jwt/jwt/v5"
	"github.com/ory/fosite/token/jwt"
)

type ES256Signer struct {
	privateKey *ecdsa.PrivateKey
	kid        string
}

func (s *ES256Signer) Generate(ctx context.Context, claims jwt.MapClaims, header jwt.Mapper) (string, string, error) {
	header.Add("alg", "ES256")
	header.Add("typ", "JWT")
	header.Add("kid", s.kid)

	goClaims := jwtgo.MapClaims{}
	for k, v := range claims {
		goClaims[k] = v
	}

	token := jwtgo.NewWithClaims(jwtgo.SigningMethodES256, goClaims)
	
	for key, value := range header.ToMap() {
		token.Header[key] = value
	}

	tokenString, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign token: %w", err)
	}

	signature := extractSignature(tokenString)

	return tokenString, signature, nil
}

func (s *ES256Signer) Validate(ctx context.Context, tokenString string) (string, error) {
	token, err := jwtgo.Parse(tokenString, func(token *jwtgo.Token) (interface{}, error) {
		if token.Method.Alg() != "ES256" {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Method.Alg())
		}
		return &s.privateKey.PublicKey, nil
	})

	if err != nil {
		return "", fmt.Errorf("failed to validate token: %w", err)
	}

	if !token.Valid {
		return "", fmt.Errorf("token is invalid")
	}

	return extractSignature(tokenString), nil
}

func (s *ES256Signer) Hash(ctx context.Context, in []byte) ([]byte, error) {
	return nil, fmt.Errorf("Hash method not applicable for ES256")
}

func (s *ES256Signer) Decode(ctx context.Context, tokenString string) (*jwt.Token, error) {
	parser := jwtgo.NewParser(jwtgo.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenString, jwtgo.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to decode token: %w", err)
	}

	goClaims, ok := token.Claims.(jwtgo.MapClaims)
	if !ok {
		return nil, fmt.Errorf("failed to convert claims")
	}
	
	fositeClaims := jwt.MapClaims{}
	for k, v := range goClaims {
		fositeClaims[k] = v
	}

	return &jwt.Token{
		Header: token.Header,
		Claims: fositeClaims,
	}, nil
}

func (s *ES256Signer) GetSignature(ctx context.Context, tokenString string) (string, error) {
	return extractSignature(tokenString), nil
}

func (s *ES256Signer) GetSigningMethodLength(ctx context.Context) int {
	return 64
}

func generateKID(pub *ecdsa.PublicKey) string {
	h := pub.X.Bytes()
	h = append(h, pub.Y.Bytes()...)
	return base64.RawURLEncoding.EncodeToString(h[:8])
}