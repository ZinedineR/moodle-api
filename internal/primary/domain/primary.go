package domain

import "github.com/lib/pq"

type GetQuizData struct {
	CourseId     string         `json:"course_id"`
	CourseName   string         `json:"course_name"`
	QuizId       string         `json:"quiz_id"`
	QuizName     string         `json:"quiz_name"`
	QuestionData []QuestionData `gorm:"-" json:"question_data"`
}

type QuestionData struct {
	UserId          int            `json:"user_id"`
	Name            string         `json:"name"`
	QuestionSummary string         `json:"question_summary"`
	QuestionText    string         `json:"question_text"`
	Answer          pq.StringArray `gorm:"type:text[];column:answers" json:"answers"`
	RightAnswer     string         `json:"right_answer"`
}

type GetQuizUserData struct {
	TimeOpen     int64              `json:"time_open"`
	TimeClose    int64              `json:"time_close"`
	CourseId     string             `json:"course_id"`
	CourseName   string             `json:"course_name"`
	QuizId       string             `json:"quiz_id"`
	QuizName     string             `json:"quiz_name"`
	UserId       int                `json:"user_id"`
	Name         string             `json:"name"`
	QuestionData []QuestionUserData `gorm:"-" json:"question_data"`
}

type QuestionUserData struct {
	QuestionSummary string         `json:"question_summary"`
	QuestionText    string         `json:"question_text"`
	Answer          pq.StringArray `gorm:"type:text[];column:answers" json:"answers"`
	RightAnswer     string         `json:"right_answer"`
}
