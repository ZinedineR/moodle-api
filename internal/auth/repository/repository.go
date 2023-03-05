package repository

import (
	"context"
	"fmt"

	"moodle-api/internal/auth/domain"
	baseModel "moodle-api/pkg/db"
	"moodle-api/pkg/errs"

	"gorm.io/gorm"
)

type repo struct {
	db   *gorm.DB
	base *baseModel.PostgreSQLClientRepository
}

func (r repo) StoreCredentials(ctx context.Context, cr domain.Credential) errs.Error {
	tx := r.db.WithContext(ctx).Table("credential").Create(&cr)
	if tx.Error != nil {
		return errs.Wrap(tx.Error)
	}
	return nil

}

func (r repo) FindCredentialByClientID(ctx context.Context, clientID string) (*domain.CredentialResponse, errs.Error) {
	var (
		credentialResponse domain.CredentialResponse
		tx                 *gorm.DB
	)

	tx = r.db.WithContext(ctx).Table("credential").
		Select("client_id, client_secret, public_key, private_key, callback_token").First(&credentialResponse, "client_id = ?", clientID)

	if tx.Error != nil {
		return nil, errs.Wrap(tx.Error)
	}

	return &credentialResponse, nil

}

// func (r repo) FindCredentialByClientKey(ctx context.Context, clientKey string) (*domain.CredentialResponse, errs.Error) {
// 	var (
// 		credentialResponse domain.CredentialResponse
// 		tx                 *gorm.DB
// 	)

// 	tx = r.db.WithContext(ctx).Table("credential").
// 		Select("client_key, client_secret, private_key, public_key").First(&credentialResponse, "client_key = ?", clientKey)

// 	if tx.Error != nil {
// 		return nil, errs.Wrap(tx.Error)
// 	}

// 	return &credentialResponse, nil

// }

func (r repo) CheckClientSecret(ctx context.Context, clientSecret string) errs.Error {
	var (
		exist bool
	)

	_ = r.db.WithContext(ctx).Table("credential").
		Select("count(client_id) > 0").Where("client_secret = ?", clientSecret).Find(&exist).Error

	if !exist {
		return errs.Wrap(fmt.Errorf("invalid Client Secret"))
	}

	return nil
}

func (r repo) CheckClientKeyAndPrivateKey(ctx context.Context, clientID, privateKey string) errs.Error {
	var (
		exist bool
	)

	_ = r.db.WithContext(ctx).Table("credential").
		Select("count(client_id) > 0").Where("client_id = ? AND private_key = ?", clientID, privateKey).Find(&exist).Error
	if !exist {
		return errs.Wrap(fmt.Errorf("invalid private key"))
	}

	return nil
}

func (r repo) CheckClientId(ctx context.Context, clientID string) errs.Error {
	var (
		exist bool
	)

	_ = r.db.WithContext(ctx).Table("credential").
		Select("count(client_id) > 0").Where("client_id = ?", clientID).Find(&exist).Error

	if !exist {
		return errs.Wrap(fmt.Errorf("invalid clientid"))
	}

	return nil
}

func NewRepository(db *gorm.DB, base *baseModel.PostgreSQLClientRepository) Repository {
	return &repo{db: db, base: base}
}
