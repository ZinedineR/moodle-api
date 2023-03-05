package app

import (
	"moodle-api/app/appconf"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type Context struct {
	*gin.Context
	Request   *http.Request
	AppConfig *appconf.Config
	APIReqID  string
}

func NewContext(c *gin.Context, conf *appconf.Config) *Context {

	xReqID := c.GetHeader("X-API-Request-ID")

	if xReqID == "" {
		xReqID = uuid.New().String()
	}

	ctx := &Context{
		Context:   c,
		Request:   c.Request,
		AppConfig: conf,
		APIReqID:  xReqID,
	}

	return ctx
}
