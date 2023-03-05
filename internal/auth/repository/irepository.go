package repository

import (
	"context"

	"moodle-api/internal/auth/domain"
	"moodle-api/pkg/errs"
)

type Repository interface {
	FindCredentialByClientID(ctx context.Context, clientID string) (*domain.CredentialResponse, errs.Error)
	CheckClientSecret(ctx context.Context, clientSecret string) errs.Error
	CheckClientKeyAndPrivateKey(ctx context.Context, clientID, privateKey string) errs.Error
	CheckClientId(ctx context.Context, clientID string) errs.Error
	StoreCredentials(ctx context.Context, cr domain.Credential) errs.Error
}
