package service

import (
	"context"
	"moodle-api/internal/base/app"
	domain2 "moodle-api/internal/base/domain"

	"moodle-api/internal/auth/domain"
	"moodle-api/pkg/errs"
)

type Service interface {
	FindCredential(ctx context.Context, clientID string) (*domain.CredentialResponse, errs.Error)
	CheckClientId(ctx context.Context, clientID string) errs.Error
	CheckClientKeyAndPrivateKey(ctx context.Context, clientID, privateKey string) errs.Error
	CheckClientSecret(ctx context.Context, clientSecret string) errs.Error
	StoreCredentials(ctx context.Context, cr domain.Credential) errs.Error
	GetAccessToken(ctx *app.Context) (*domain2.AccessTokenResponse, int, *interface{}, error)
}
