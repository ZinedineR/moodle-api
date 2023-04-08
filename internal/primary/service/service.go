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

func (s service) GetQuiz(ctx context.Context, quizId int) (*domain.GetQuizData, errs.Error) {
	result, err := s.authRepo.GetQuiz(ctx, quizId)
	if err != nil {
		return nil, err
	}
	return result, nil
}
