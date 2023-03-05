package handler

import (
	"fmt"
	"net/http"
	"time"

	"moodle-api/pkg/httpclient"

	"github.com/sirupsen/logrus"

	"moodle-api/app/appconf"
	"moodle-api/internal/base/app"
	redis "moodle-api/internal/base/service/redisser"
	baseModel "moodle-api/pkg/db"
	"moodle-api/pkg/server"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"gorm.io/gorm"
)

type HandlerFn func(ctx *app.Context) *server.Response
type HandlerFnInterface func(ctx *app.Context) *server.ResponseInterface

type BaseHTTPHandler struct {
	Handlers    interface{}
	DB          *gorm.DB
	AppConfig   *appconf.Config
	Validate    *validator.Validate
	BaseModel   *baseModel.PostgreSQLClientRepository
	RedisClient redis.RedisClient
	HttpClient  httpclient.Client
}

func NewBaseHTTPHandler(db *gorm.DB,
	appConfig *appconf.Config,
	baseModel *baseModel.PostgreSQLClientRepository,
	validate *validator.Validate,
	redisClient redis.RedisClient,
	httpClient httpclient.Client,
) *BaseHTTPHandler {
	return &BaseHTTPHandler{
		DB:          db,
		AppConfig:   appConfig,
		Validate:    validate,
		BaseModel:   baseModel,
		RedisClient: redisClient,
		HttpClient:  httpClient,
	}
}

// AsJson to response custom message: 200, 201 with message (Mobile use 500 error)
func (b BaseHTTPHandler) AsJson(ctx *app.Context, status int, message string, data interface{}) *server.Response {

	return &server.Response{
		Status:       status,
		Message:      message,
		Data:         data,
		ResponseType: server.DefaultResponseType,
	}
}

func (b BaseHTTPHandler) AsJsonInterface(ctx *app.Context, status int, data interface{}) *server.ResponseInterface {

	return &server.ResponseInterface{
		Status: status,
		Data:   data,
	}
}

// ThrowExceptionJson for some exception not handle in Yii2 framework
func (b BaseHTTPHandler) ThrowExceptionJson(ctx *app.Context, status, code int, name, message string) *server.Response {
	return &server.Response{
		Status:  status,
		Message: "",
		Log:     nil,
	}
}

func (b BaseHTTPHandler) MoodleAuthentication(c *gin.Context) (*app.Context, error) {
	return app.NewContext(c, b.AppConfig), nil
}

func (b BaseHTTPHandler) MoodleRunAction(handler HandlerFnInterface) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		ctx, err := b.MoodleAuthentication(c)
		if err != nil {
			logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , message: Unauthorized", ctx.APIReqID))
			c.JSON(http.StatusUnauthorized, gin.H{
				"status":  http.StatusUnauthorized,
				"message": "Unauthorized",
				"data":    err.Error(),
			})
			return
		}

		defer func() {
			if err0 := recover(); err0 != nil {
				logrus.Errorln(err0)
				c.JSON(http.StatusInternalServerError, gin.H{
					"status":  http.StatusInternalServerError,
					"message": "Request is halted unexpectedly, please contact the administrator.",
					"data":    nil,
				})
			}
		}()

		resp := handler(ctx)
		httpStatus := resp.Status

		if resp.Data == nil {
			c.Status(httpStatus)
			return
		}
		end := time.Now().Sub(start)
		logrus.Infoln(fmt.Sprintf("REQUEST ID: %s , LATENCY: %vms", ctx.APIReqID, end.Milliseconds()))
		c.JSON(httpStatus, resp.Data)

	}
}
