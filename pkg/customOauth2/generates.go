package customOauth2

import (
	"context"
	"github.com/go-oauth2/oauth2/v4"
)

// NewJWTAccessGenerate create to generate the jwt access token instance
func NewJWTAccessGenerate(cfg JWTConfig) *JWTAccessGenerate {
	return &JWTAccessGenerate{
		cfg: cfg,
	}
}

// JWTAccessGenerate generate the jwt access token
type JWTAccessGenerate struct {
	cfg JWTConfig
}

// Token based on the UUID generated token
// Registered Claim Names: 	https://tools.ietf.org/html/rfc7519#section-4.1
func (a *JWTAccessGenerate) Token(ctx context.Context, data *oauth2.TokenGenerateRequest, isGenRefresh bool) (access string, err error) {
	claims := AccessClaims(data)
	access, err = GenerateJWT(a.cfg.SigningMethod, a.cfg.SignedKey, claims)
	if err != nil {
		return
	}

	if isGenRefresh {
		//claims := RefreshClaims(data)
		//refresh, err = GenerateJWT(a.cfg.SigningMethod, a.cfg.SignedKey, claims)
	}

	return
}
