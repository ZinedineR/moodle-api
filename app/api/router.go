package api

import (
	"fmt"

	"moodle-api/internal/base/handler"
)

func (h *HttpServe) setupRouter() {
	h.MoodleRoute("GET", "/primary", h.primaryHandler.ListPrimary)

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
