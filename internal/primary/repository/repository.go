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

func (r repo) GetQuiz(ctx context.Context, quizId int) (*domain.GetQuizData, errs.Error) {
	var (
		models       domain.GetQuizData
		QuestionData []domain.QuestionData
		quiz         *gorm.DB
		question     *gorm.DB
	)
	query := r.db.WithContext(ctx).
		Table("mdl_quiz_attempts").
		Joins("JOIN mdl_user ON mdl_user.id = mdl_quiz_attempts.userid").
		Joins("JOIN mdl_quiz ON mdl_quiz.id = mdl_quiz_attempts.quiz").
		Joins("JOIN mdl_course on mdl_course.id = mdl_quiz.course").
		Joins("JOIN mdl_question_usages ON mdl_question_usages.id = mdl_quiz_attempts.uniqueid").
		Joins("JOIN mdl_question_attempts ON mdl_question_attempts.questionusageid = mdl_question_usages.id").
		Joins("JOIN mdl_question ON mdl_question.id = mdl_question_attempts.questionid").
		Joins("left JOIN mdl_question_answers ON mdl_question.id = mdl_question_answers.question ").
		Where("mdl_quiz.id = ?", quizId).
		Group("mdl_quiz.course, mdl_course.fullname, mdl_quiz.id, mdl_quiz.name").
		Order("mdl_quiz.id ASC")

	queryquestion := r.db.WithContext(ctx).
		Table("mdl_quiz_attempts").
		Joins("JOIN mdl_user ON mdl_user.id = mdl_quiz_attempts.userid").
		Joins("JOIN mdl_quiz ON mdl_quiz.id = mdl_quiz_attempts.quiz").
		Joins("JOIN mdl_course on mdl_course.id = mdl_quiz.course").
		Joins("JOIN mdl_question_usages ON mdl_question_usages.id = mdl_quiz_attempts.uniqueid").
		Joins("JOIN mdl_question_attempts ON mdl_question_attempts.questionusageid = mdl_question_usages.id").
		Joins("JOIN mdl_question ON mdl_question.id = mdl_question_attempts.questionid").
		Joins("left JOIN mdl_question_answers ON mdl_question.id = mdl_question_answers.question ").
		Where("mdl_quiz.id = ?", quizId).
		Group("mdl_user.id, mdl_user.firstname,mdl_quiz.id, mdl_question_attempts.questionsummary, mdl_question.questiontext, mdl_question_attempts.rightanswer").
		Order("mdl_user.id ASC")

	quiz = query.
		Select(
			"mdl_quiz.course as course_id", "mdl_course.fullname as course_name",
			"mdl_quiz.id as quiz_id", "mdl_quiz.name as quiz_name").
		Take(&models)
	if quiz.Error != nil {
		return nil, errs.Wrap(quiz.Error)
	}

	question = queryquestion.
		Select("mdl_user.id as user_id", "concat(mdl_user.firstname,' ',mdl_user.lastname) as name",
			"mdl_question_attempts.questionsummary as question_summary",
			"mdl_question.questiontext as question_text",
			"ARRAY_AGG(mdl_question_answers.answer ORDER BY mdl_question_answers.id) filter (where mdl_question_answers.answer is not null) AS answers",
			"mdl_question_attempts.rightanswer as right_answer").
		Find(&QuestionData)
	if question.Error != nil {
		return nil, errs.Wrap(question.Error)
	}
	models.QuestionData = QuestionData
	return &models, nil

}

func NewRepository(db *gorm.DB, base *baseModel.PostgreSQLClientRepository) Repository {
	return &repo{db: db, base: base}
}
