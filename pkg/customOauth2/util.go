package customOauth2

import (
	"fmt"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/models"
	"time"

	"github.com/dgrijalva/jwt-go"
)

//AccessClaims from token info
func AccessClaims(tokenInfo *oauth2.TokenGenerateRequest) *Oauth2Claims {
	createAt := time.Now()
	return &Oauth2Claims{
		Issuer:    tokenInfo.ClientID,
		Scope:     tokenInfo.Scope,
		IssuedAt:  createAt.Unix(),
		ExpiresAt: createAt.Add(tokenInfo.AccessTokenExp).Unix(),
	}
}

//RefreshClaims from token info
func RefreshClaims(tokenInfo oauth2.TokenInfo) *Oauth2Claims {
	createAt := tokenInfo.GetRefreshCreateAt().Round(time.Second)
	return &Oauth2Claims{
		Issuer:    tokenInfo.GetClientID(),
		Subject:   tokenInfo.GetUserID(),
		Scope:     tokenInfo.GetScope(),
		IssuedAt:  createAt.Unix(),
		ExpiresAt: createAt.Add(tokenInfo.GetRefreshExpiresIn()).Unix(),
	}
}

//GenerateJWT jwt token
func GenerateJWT(signingMethod jwt.SigningMethod, signedKey []byte, claims *Oauth2Claims) (access string, err error) {
	token := jwt.NewWithClaims(signingMethod, claims)
	return token.SignedString(signedKey)
}

//ParseClaims jwt token
func ParseClaims(signingMethod jwt.SigningMethod, signedKey []byte, access string) (claims *Oauth2Claims, err error) {
	token, err := jwt.ParseWithClaims(access, &Oauth2Claims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method != signingMethod {
			return nil, fmt.Errorf("unknown jwt token")
		}
		return signedKey, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Oauth2Claims)
	if !ok {
		return nil, fmt.Errorf("not jwt access claims")
	}
	err = claims.Valid()
	if err != nil {
		return nil, err
	}
	return
}

//ParseAccessTokenInfo from access
func ParseAccessTokenInfo(signingMethod jwt.SigningMethod, signedKey []byte, access string) (tokenInfo oauth2.TokenInfo, err error) {
	claims, err := ParseClaims(signingMethod, signedKey, access)
	if err != nil {
		return
	}

	createAt := time.Unix(claims.IssuedAt, 0)
	tokenInfo = &models.Token{
		ClientID:        claims.Issuer,
		UserID:          claims.Subject,
		Scope:           claims.Scope,
		Access:          access,
		AccessCreateAt:  createAt,
		AccessExpiresIn: time.Unix(claims.ExpiresAt, 0).Sub(createAt),
	}
	return
}

//ParseRefreshTokenInfo from refresh
func ParseRefreshTokenInfo(signingMethod jwt.SigningMethod, signedKey []byte, refresh string) (tokenInfo oauth2.TokenInfo, err error) {
	refreshClaims, err := ParseClaims(signingMethod, signedKey, refresh)
	if err != nil {
		return
	}

	createAt := time.Unix(refreshClaims.IssuedAt, 0)
	tokenInfo = &models.Token{
		ClientID:         refreshClaims.Issuer,
		UserID:           refreshClaims.Subject,
		Scope:            refreshClaims.Scope,
		Refresh:          refresh,
		RefreshCreateAt:  createAt,
		RefreshExpiresIn: time.Unix(refreshClaims.ExpiresAt, 0).Sub(createAt),
	}
	return
}
