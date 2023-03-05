package customOauth2

import (
	"context"
	"fmt"
	"github.com/go-oauth2/oauth2/v4"
)

// NewJWTTokenStore create a token store instance for jwt, which not store token exactly, but parse and valid the token instead
func NewJWTTokenStore(cfg JWTConfig) (store oauth2.TokenStore, err error) {
	store = &JWTTokenStore{
		cfg: cfg,
	}
	return
}

// JWTTokenStore jwt token store
type JWTTokenStore struct {
	cfg JWTConfig
}

// Create create and store the new token information
func (ts *JWTTokenStore) Create(ctx context.Context, info oauth2.TokenInfo) (err error) {
	return
}

// remove key
func (ts *JWTTokenStore) remove(key string) (err error) {
	return
}

// RemoveByCode use the authorization code to delete the token information
func (ts *JWTTokenStore) RemoveByCode(ctx context.Context, code string) (err error) {
	return
}

// RemoveByAccess use the access token to delete the token information
func (ts *JWTTokenStore) RemoveByAccess(ctx context.Context, access string) (err error) {
	return
}

// RemoveByRefresh use the refresh token to delete the token information
func (ts *JWTTokenStore) RemoveByRefresh(ctx context.Context, refresh string) (err error) {
	return
}

// GetByCode use the authorization code for token information data
func (ts *JWTTokenStore) GetByCode(ctx context.Context, code string) (ti oauth2.TokenInfo, err error) {
	err = fmt.Errorf("GetByCode not support for jwt token store")
	return
}

// GetByAccess use the access token for token information data
func (ts *JWTTokenStore) GetByAccess(ctx context.Context, access string) (ti oauth2.TokenInfo, err error) {
	return ParseAccessTokenInfo(ts.cfg.SigningMethod, ts.cfg.SignedKey, access)
}

// GetByRefresh use the refresh token for token information data
func (ts *JWTTokenStore) GetByRefresh(ctx context.Context, refresh string) (ti oauth2.TokenInfo, err error) {
	return ParseRefreshTokenInfo(ts.cfg.SigningMethod, ts.cfg.SignedKey, refresh)
}
