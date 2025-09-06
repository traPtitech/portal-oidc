package jwt

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"strings"

	jwtgo "github.com/golang-jwt/jwt/v5"
	"github.com/ory/fosite/token/jwt"
)

type RotatingSigner struct {
	manager *KeyRotationManager
}

func NewRotatingSigner(manager *KeyRotationManager) *RotatingSigner {
	return &RotatingSigner{
		manager: manager,
	}
}

func (s *RotatingSigner) Generate(ctx context.Context, claims jwt.MapClaims, header jwt.Mapper) (string, string, error) {
	currentSigner := s.manager.GetCurrentSigner()
	return currentSigner.Generate(ctx, claims, header)
}

func (s *RotatingSigner) Validate(ctx context.Context, tokenString string) (string, error) {
	parser := jwtgo.NewParser(jwtgo.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenString, jwtgo.MapClaims{})
	if err != nil {
		return "", fmt.Errorf("failed to parse token for validation: %w", err)
	}

	kid, ok := token.Header["kid"].(string)
	if !ok {
		return "", fmt.Errorf("no kid in token header")
	}

	keyInfo, err := s.manager.GetKeyByKID(kid)
	if err != nil {
		return "", fmt.Errorf("key not found for validation: %w", err)
	}

	_, err = jwtgo.Parse(tokenString, func(token *jwtgo.Token) (interface{}, error) {
		if token.Method.Alg() != "ES256" {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Method.Alg())
		}
		return keyInfo.PublicKey, nil
	})

	if err != nil {
		return "", fmt.Errorf("failed to validate token: %w", err)
	}

	return extractSignature(tokenString), nil
}

func (s *RotatingSigner) Hash(ctx context.Context, in []byte) ([]byte, error) {
	return nil, fmt.Errorf("Hash method not applicable for ES256")
}

func (s *RotatingSigner) Decode(ctx context.Context, tokenString string) (*jwt.Token, error) {
	currentSigner := s.manager.GetCurrentSigner()
	return currentSigner.Decode(ctx, tokenString)
}

func (s *RotatingSigner) GetSignature(ctx context.Context, tokenString string) (string, error) {
	return extractSignature(tokenString), nil
}

func (s *RotatingSigner) GetSigningMethodLength(ctx context.Context) int {
	return 64
}

func (s *RotatingSigner) GetAllJWKs() []map[string]interface{} {
	keys := s.manager.GetAllKeys()
	jwks := make([]map[string]interface{}, 0, len(keys))

	for _, keyInfo := range keys {
		jwk := convertToJWK(keyInfo.PublicKey, keyInfo.KID)
		jwks = append(jwks, jwk)
	}

	return jwks
}

func convertToJWK(pub *ecdsa.PublicKey, kid string) map[string]interface{} {
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()
	
	xPadded := make([]byte, 32)
	yPadded := make([]byte, 32)
	copy(xPadded[32-len(xBytes):], xBytes)
	copy(yPadded[32-len(yBytes):], yBytes)

	return map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(xPadded),
		"y":   base64.RawURLEncoding.EncodeToString(yPadded),
		"use": "sig",
		"alg": "ES256",
		"kid": kid,
	}
}

func extractSignature(tokenString string) string {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return ""
	}
	return parts[2]
}