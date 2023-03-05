package api

import (
	"fmt"
	"os"
	"strings"

	"moodle-api/internal/base/handler"
	priHandler "moodle-api/internal/primary/handler"
	"moodle-api/pkg/server"

	"github.com/gin-gonic/gin"
	gintrace "gopkg.in/DataDog/dd-trace-go.v1/contrib/gin-gonic/gin"
)

type HttpServe struct {
	router         *gin.Engine
	base           *handler.BaseHTTPHandler
	primaryHandler *priHandler.HTTPHandler
}

func (h *HttpServe) Run() error {
	h.setupRouter()
	h.base.Handlers = h

	if h.base.IsStaging() {
		h.setupDevRouter()
	}

	return h.router.Run(fmt.Sprintf(":%s", os.Getenv("HTTP_SERVER_PORT")))
}

func New(appName string, base *handler.BaseHTTPHandler, primary *priHandler.HTTPHandler) server.App {

	if os.Getenv("APP_ENV") != "production" {
		if os.Getenv("DEV_SHOW_ROUTE") == "False" {
			gin.DebugPrintRouteFunc = func(httpMethod, absolutePath, handlerName string, nuHandlers int) {

			}
		} else {
			gin.DebugPrintRouteFunc = func(httpMethod, absolutePath, handlerName string, nuHandlers int) {
				fmt.Printf("Route: %-6s %-25s --> %s (%d handlers)\n",
					httpMethod, absolutePath, handlerName[strings.LastIndex(handlerName, "/")+1:], nuHandlers)

			}
		}
	}

	pathNamer := func(c *gin.Context) string {
		return fmt.Sprintf("%s %s%s", c.Request.Method, c.Request.Host, c.Request.RequestURI)
	}

	r := gin.New()
	r.Use(gintrace.Middleware(appName, gintrace.WithResourceNamer(pathNamer)))
	r.Use(ResponseHeaderFormat())
	//r.Use(otelgin.Middleware(os.Getenv("SERVICE_NAME")))
	// r.Use(cors.New(cors.Config{
	// 	AllowOrigins:     strings.Split(os.Getenv("ALLOW_ORIGINS"), ","),
	// 	AllowMethods:     strings.Split(os.Getenv("ALLOW_METHODS"), ","),
	// 	AllowHeaders:     strings.Split(os.Getenv("ALLOW_HEADERS"), ","),
	// 	AllowCredentials: true,
	// }))

	return &HttpServe{
		router:         r,
		base:           base,
		primaryHandler: primary,
	}
}
