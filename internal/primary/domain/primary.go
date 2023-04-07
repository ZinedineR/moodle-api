package domain

type GetQuizData struct {
	UserId     int    `json:"user_id"`
	Name       string `json:"name"`
	CourseId   string `json:"course_id"`
	CourseName string `json:"course_name"`
	QuizId     string `json:"quiz_id"`
	QuizName   string `json:"quiz_name"`
	// QuestionData QuestionData `json:"question_data"`
}

type QuestionData struct {
	QuestionSummary string   `json:"question_summary"`
	QuestionText    string   `json:"question_text"`
	Answer          []string `json:"answer"`
	RightAnswer     string   `json:"right_answer"`
}
