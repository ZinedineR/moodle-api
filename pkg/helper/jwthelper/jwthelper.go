package jwthelper

import (
	"errors"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-oauth2/oauth2/v4/generates"
)

func ParseJwt(accessToken string) (*generates.JWTAccessClaims, error) {
	token, err := jwt.ParseWithClaims(accessToken, &generates.JWTAccessClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("access token not valid")
		}
		return []byte("00000000"), nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*generates.JWTAccessClaims)
	if !ok || !token.Valid {
		return nil, errors.New("access token not valid")
	}

	return claims, nil
}
