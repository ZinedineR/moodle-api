package service

import (
	"context"

	"moodle-api/internal/primary/domain"
	"moodle-api/pkg/errs"
)

type Service interface {
	GetQuiz(ctx context.Context, quizId int) (*[]domain.GetQuizData, errs.Error)
}
