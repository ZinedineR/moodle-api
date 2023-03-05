package customOauth2

import jwt "github.com/dgrijalva/jwt-go"

// JWTConfig jwt config
type JWTConfig struct {
	SignedKey     []byte
	SigningMethod jwt.SigningMethod
}
