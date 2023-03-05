package service

import (
	"context"

	"moodle-api/pkg/httpclient"

	"moodle-api/internal/primary/domain"
	"moodle-api/internal/primary/repository"
	"moodle-api/pkg/errs"
)

// NewService creates new user service
func NewService(repo repository.Repository, httpClient httpclient.Client) Service {
	return &service{authRepo: repo, httpClient: httpClient}
}

type service struct {
	authRepo   repository.Repository
	httpClient httpclient.Client
}

func (s service) StorePrimary(ctx context.Context, cr domain.PrimaryTableEntity) errs.Error {
	err := s.authRepo.StorePrimary(ctx, cr)
	if err != nil {
		return err
	}
	return nil
}

func (s service) ListPrimary(ctx context.Context) (*[]domain.PrimaryTableEntity, errs.Error) {
	result, err := s.authRepo.ListPrimary(ctx)
	if err != nil {
		return nil, err
	}
	return result, nil
}
