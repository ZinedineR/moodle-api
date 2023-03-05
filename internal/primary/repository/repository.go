package repository

import (
	"context"

	"moodle-api/internal/primary/domain"
	baseModel "moodle-api/pkg/db"
	"moodle-api/pkg/errs"

	"gorm.io/gorm"
)

type repo struct {
	db   *gorm.DB
	base *baseModel.PostgreSQLClientRepository
}

func (r repo) StorePrimary(ctx context.Context, cr domain.PrimaryTableEntity) errs.Error {
	tx := r.db.WithContext(ctx).Table("primary").Create(&cr)
	if tx.Error != nil {
		return errs.Wrap(tx.Error)
	}
	return nil

}

func (r repo) ListPrimary(ctx context.Context) (*[]domain.PrimaryTableEntity, errs.Error) {
	var (
		models []domain.PrimaryTableEntity
		tx     *gorm.DB
	)

	tx = r.db.WithContext(ctx).
		Table("primarytableentity").
		Find(&models)

	if tx.Error != nil {
		return nil, errs.Wrap(tx.Error)
	}

	return &models, nil

}

func NewRepository(db *gorm.DB, base *baseModel.PostgreSQLClientRepository) Repository {
	return &repo{db: db, base: base}
}
