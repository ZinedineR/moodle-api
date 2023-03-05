package repository

import (
	"context"

	"moodle-api/internal/primary/domain"
	"moodle-api/pkg/errs"
)

type Repository interface {
	ListPrimary(ctx context.Context) (*[]domain.PrimaryTableEntity, errs.Error)
	StorePrimary(ctx context.Context, cr domain.PrimaryTableEntity) errs.Error
}
