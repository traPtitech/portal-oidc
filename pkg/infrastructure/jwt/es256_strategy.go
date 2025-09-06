package jwt

import (
	"context"
	"fmt"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/token/jwt"
)

type ES256JWTStrategy struct {
	Signer    *RotatingSigner
	Config    fosite.Configurator
	IssuerURL string
}

func NewES256JWTStrategy(signer *RotatingSigner, config fosite.Configurator, issuerURL string) *ES256JWTStrategy {
	return &ES256JWTStrategy{
		Signer:    signer,
		Config:    config,
		IssuerURL: issuerURL,
	}
}

func (s *ES256JWTStrategy) GenerateAccessToken(ctx context.Context, requester fosite.Requester) (string, string, error) {
	claims := s.accessTokenClaims(requester)
	header := jwt.NewHeaders()
	
	token, sig, err := s.Signer.Generate(ctx, claims, header)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate access token: %w", err)
	}
	
	return token, sig, nil
}

func (s *ES256JWTStrategy) ValidateAccessToken(ctx context.Context, requester fosite.Requester, token string) error {
	_, err := s.Signer.Validate(ctx, token)
	if err != nil {
		return fmt.Errorf("failed to validate access token: %w", err)
	}
	
	decodedToken, err := s.Signer.Decode(ctx, token)
	if err != nil {
		return fmt.Errorf("failed to decode token: %w", err)
	}
	
	claims := decodedToken.Claims
	
	if err := s.validateStandardClaims(claims); err != nil {
		return err
	}
	
	return nil
}

func (s *ES256JWTStrategy) GenerateRefreshToken(ctx context.Context, requester fosite.Requester) (string, string, error) {
	claims := s.refreshTokenClaims(requester)
	header := jwt.NewHeaders()
	
	token, sig, err := s.Signer.Generate(ctx, claims, header)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate refresh token: %w", err)
	}
	
	return token, sig, nil
}

func (s *ES256JWTStrategy) ValidateRefreshToken(ctx context.Context, requester fosite.Requester, token string) error {
	_, err := s.Signer.Validate(ctx, token)
	if err != nil {
		return fmt.Errorf("failed to validate refresh token: %w", err)
	}
	
	return nil
}

func (s *ES256JWTStrategy) GenerateAuthorizeCode(ctx context.Context, requester fosite.Requester) (string, string, error) {
	claims := s.authorizeCodeClaims(requester)
	header := jwt.NewHeaders()
	
	token, sig, err := s.Signer.Generate(ctx, claims, header)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate authorize code: %w", err)
	}
	
	return token, sig, nil
}

func (s *ES256JWTStrategy) ValidateAuthorizeCode(ctx context.Context, requester fosite.Requester, token string) error {
	_, err := s.Signer.Validate(ctx, token)
	if err != nil {
		return fmt.Errorf("failed to validate authorize code: %w", err)
	}
	
	return nil
}

func (s *ES256JWTStrategy) AccessTokenSignature(ctx context.Context, token string) string {
	sig, _ := s.Signer.GetSignature(ctx, token)
	return sig
}

func (s *ES256JWTStrategy) RefreshTokenSignature(ctx context.Context, token string) string {
	sig, _ := s.Signer.GetSignature(ctx, token)
	return sig
}

func (s *ES256JWTStrategy) AuthorizeCodeSignature(ctx context.Context, token string) string {
	sig, _ := s.Signer.GetSignature(ctx, token)
	return sig
}


func (s *ES256JWTStrategy) accessTokenClaims(requester fosite.Requester) jwt.MapClaims {
	now := time.Now().UTC()
	
	claims := jwt.MapClaims{
		"iss":   s.IssuerURL,
		"sub":   requester.GetSession().GetSubject(),
		"aud":   requester.GetClient().GetID(),
		"exp":   now.Add(s.Config.GetAccessTokenLifespan(context.Background())).Unix(),
		"iat":   now.Unix(),
		"nbf":   now.Unix(),
		"jti":   requester.GetID(),
		"scope": requester.GetGrantedScopes(),
		"client_id": requester.GetClient().GetID(),
	}
	
	if session, ok := requester.GetSession().(*fosite.DefaultSession); ok {
		if session.Username != "" {
			claims["preferred_username"] = session.Username
		}
	}
	
	return claims
}

func (s *ES256JWTStrategy) refreshTokenClaims(requester fosite.Requester) jwt.MapClaims {
	now := time.Now().UTC()
	
	return jwt.MapClaims{
		"iss":   s.IssuerURL,
		"sub":   requester.GetSession().GetSubject(),
		"aud":   requester.GetClient().GetID(),
		"exp":   now.Add(s.Config.GetRefreshTokenLifespan(context.Background())).Unix(),
		"iat":   now.Unix(),
		"nbf":   now.Unix(),
		"jti":   requester.GetID(),
		"scope": requester.GetGrantedScopes(),
		"client_id": requester.GetClient().GetID(),
	}
}

func (s *ES256JWTStrategy) authorizeCodeClaims(requester fosite.Requester) jwt.MapClaims {
	now := time.Now().UTC()
	
	return jwt.MapClaims{
		"iss":   s.IssuerURL,
		"sub":   requester.GetSession().GetSubject(),
		"aud":   requester.GetClient().GetID(),
		"exp":   now.Add(s.Config.GetAuthorizeCodeLifespan(context.Background())).Unix(),
		"iat":   now.Unix(),
		"nbf":   now.Unix(),
		"jti":   requester.GetID(),
		"scope": requester.GetGrantedScopes(),
		"client_id": requester.GetClient().GetID(),
	}
}

func (s *ES256JWTStrategy) validateStandardClaims(claims jwt.Claims) error {
	now := time.Now().UTC().Unix()
	
	mapClaims, ok := claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("invalid claims type")
	}
	
	if exp, ok := mapClaims["exp"].(float64); ok {
		if int64(exp) < now {
			return fmt.Errorf("token has expired")
		}
	}
	
	if nbf, ok := mapClaims["nbf"].(float64); ok {
		if int64(nbf) > now {
			return fmt.Errorf("token not yet valid")
		}
	}
	
	if iat, ok := mapClaims["iat"].(float64); ok {
		if int64(iat) > now {
			return fmt.Errorf("token issued in the future")
		}
	}
	
	return nil
}