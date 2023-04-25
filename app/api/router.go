package api

import (
	"fmt"

	"moodle-api/internal/base/handler"
)

func (h *HttpServe) setupRouter() {
	h.MoodleRoute("GET", "/quiz/:quiz", h.primaryHandler.GetQuiz)
	h.MoodleRoute("GET", "/quiz-sql/:quiz/:user", h.primaryHandler.GetQuizUserSQL)
	h.MoodleRoute("GET", "/quiz/:quiz/:user", h.primaryHandler.GetQuizUserRedis)
}

func (h *HttpServe) MoodleRoute(method, path string, f handler.HandlerFnInterface) {
	switch method {
	case "GET":
		h.router.GET(path, h.base.MoodleRunAction(f))
	case "POST":
		h.router.POST(path, h.base.MoodleRunAction(f))
	case "PUT":
		h.router.PUT(path, h.base.MoodleRunAction(f))
	case "DELETE":
		h.router.DELETE(path, h.base.MoodleRunAction(f))
	default:
		panic(fmt.Sprintf(":%s method not allow", method))
	}
}
