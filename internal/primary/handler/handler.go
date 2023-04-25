package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	redis "moodle-api/internal/base/service/redisser"

	"moodle-api/internal/primary/domain"
	primaryService "moodle-api/internal/primary/service"

	"moodle-api/internal/base/app"
	"moodle-api/internal/base/handler"
	"moodle-api/pkg/server"

	"github.com/gin-gonic/gin"
)

type HTTPHandler struct {
	App            *handler.BaseHTTPHandler
	PrimaryService primaryService.Service
	RedisClient    redis.RedisClient
}

func NewHTTPHandler(handler *handler.BaseHTTPHandler, primaryService primaryService.Service, redisClient redis.RedisClient) *HTTPHandler {
	return &HTTPHandler{
		App:            handler,
		PrimaryService: primaryService,
		RedisClient:    redisClient,
	}
}

// Handler Basic Method ======================================================================================================

func (h HTTPHandler) AsErrorDefault(ctx *gin.Context, message string) {
	ctx.JSON(http.StatusInternalServerError, gin.H{
		"message": message,
	})
}

func (h HTTPHandler) AsInvalidClientIdError(ctx *gin.Context) {
	ctx.JSON(http.StatusBadRequest, gin.H{
		"responseCode":    "400",
		"responseMessage": "invalid clientid",
	})
}

func (h HTTPHandler) AsInvalidClientIdAccessTokenError(ctx *gin.Context) {
	ctx.JSON(http.StatusUnauthorized, gin.H{
		"responseCode":    "4010000",
		"responseMessage": "Invalid Client Key",
	})
}

func (h HTTPHandler) AsInvalidPrivateKeyError(ctx *gin.Context) {
	ctx.JSON(http.StatusUnauthorized, gin.H{
		"responseCode":    "4010000",
		"responseMessage": "Invalid Private Key",
	})
}

func (h HTTPHandler) AsInvalidPublicKeyError(ctx *gin.Context) {
	ctx.JSON(http.StatusUnauthorized, gin.H{
		"responseCode":    "4010000",
		"responseMessage": "Invalid Public Key",
	})
}

func (h HTTPHandler) AsInvalidSignatureError(ctx *gin.Context) {
	ctx.JSON(http.StatusUnauthorized, gin.H{
		"responseCode":    "4017300",
		"responseMessage": "Invalid Token (B2B)",
	})
}

func (h HTTPHandler) AsRequiredTimeStampError(ctx *gin.Context) {
	ctx.JSON(http.StatusBadRequest, gin.H{
		"responseCode":    "4000000",
		"responseMessage": "The timestamp field is required.",
	})
}

func (h HTTPHandler) AsInvalidFieldTimeStampError(ctx *gin.Context) {
	ctx.JSON(http.StatusBadRequest, gin.H{
		"responseCode":    "4000000",
		"responseMessage": "Invalid Field Format Timestamp",
	})
}

func (h HTTPHandler) AsInvalidLengthTimeStampError(ctx *gin.Context) {
	ctx.JSON(http.StatusBadRequest, gin.H{
		"responseCode":    "4000000",
		"responseMessage": "The field timestamp must be a string or array type with a maximum length of '25'.",
	})
}

func (h HTTPHandler) AsInvalidClientSecretError(ctx *gin.Context) {
	ctx.JSON(http.StatusBadRequest, gin.H{
		"responseCode":    "4010000",
		"responseMessage": "Invalid Client Secret",
	})
}

func (h HTTPHandler) AsInvalidHttpMethodError(ctx *gin.Context) {
	ctx.JSON(http.StatusBadRequest, gin.H{
		"responseCode":    "4010000",
		"responseMessage": "http methods is invalid",
	})
}

func (h HTTPHandler) AsInvalidJsonFormat(ctx *gin.Context, msg string) {
	ctx.JSON(http.StatusBadRequest, gin.H{
		"responseCode":    "400",
		"responseMessage": msg,
	})
}

func (h HTTPHandler) AsRequiredClientSecretError(ctx *gin.Context) {
	ctx.JSON(http.StatusBadRequest, gin.H{
		"responseCode":    "4000000",
		"responseMessage": "The clientSecret field is required.",
	})
}

func (h HTTPHandler) AsRequiredClientIdError(ctx *gin.Context) {
	ctx.JSON(http.StatusBadRequest, gin.H{
		"responseCode":    "4000000",
		"responseMessage": "The clientId field is required.",
	})
}

func (h HTTPHandler) AsRequiredGrantTypeError(ctx *gin.Context) {
	ctx.JSON(http.StatusBadRequest, gin.H{
		"responseCode":    "4007302",
		"responseMessage": "Bad Request. The grantType field is required.",
	})
}

func (h HTTPHandler) AsRequiredGrantTypeClientCredentialsError(ctx *gin.Context) {
	ctx.JSON(http.StatusBadRequest, gin.H{
		"responseCode":    "4007300",
		"responseMessage": "grant_type must be set to client_credentials",
	})
}

func (h HTTPHandler) AsRequiredSignatureError(ctx *gin.Context) {
	ctx.JSON(http.StatusBadRequest, gin.H{
		"responseCode":    "4000000",
		"responseMessage": "The signature field is required.",
	})
}

func (h HTTPHandler) AsRequiredPrivateKeyError(ctx *gin.Context) {
	ctx.JSON(http.StatusBadRequest, gin.H{
		"responseCode":    "4000000",
		"responseMessage": "The privateKey field is required.",
	})
}

func (h HTTPHandler) AsRequiredContentTypeError(ctx *gin.Context) {
	ctx.JSON(http.StatusUnsupportedMediaType, gin.H{
		"responseCode":    "4000000",
		"responseMessage": "Content Type application/json is required.",
	})
}

func (h HTTPHandler) AsInvalidTokenError(ctx *gin.Context) {
	ctx.JSON(http.StatusUnauthorized, gin.H{
		"responseCode":    "4010001",
		"responseMessage": "Access Token Invalid",
	})
}

func (h HTTPHandler) AsRequiredBearer(ctx *gin.Context) {
	ctx.JSON(http.StatusUnauthorized, gin.H{
		"responseCode":    "4000002",
		"responseMessage": "Bearer authorization is required",
	})
}

func (h HTTPHandler) AsRequiredHttpMethodError(ctx *gin.Context) {
	ctx.JSON(http.StatusUnsupportedMediaType, gin.H{
		"responseCode":    "4000000",
		"responseMessage": "The HttpMethod field is required.",
	})
}

func (h HTTPHandler) AsRequiredEndpoinUrlError(ctx *gin.Context) {
	ctx.JSON(http.StatusUnsupportedMediaType, gin.H{
		"responseCode":    "4000000",
		"responseMessage": "The EndpointUrl field is required.",
	})
}

func (h HTTPHandler) AsRequiredAccessTokenError(ctx *gin.Context) {
	ctx.JSON(http.StatusUnsupportedMediaType, gin.H{
		"responseCode":    "4000000",
		"responseMessage": "The AccessToken field is required.",
	})
}
func (h HTTPHandler) AsRequiredBodyError(ctx *gin.Context) {
	ctx.JSON(http.StatusBadRequest, gin.H{
		"responseCode":    "4000000",
		"responseMessage": "A non-empty request body is required.",
	})
}

// Data Not Found return AsJsonInterface 404 when data doesn't exist
func (h HTTPHandler) DataNotFound(ctx *app.Context) *server.ResponseInterface {
	type Response struct {
		StatusCode int         `json:"responseCode"`
		Message    interface{} `json:"responseMessage"`
	}
	resp := Response{
		StatusCode: http.StatusNotFound,
		Message:    "Data not found in database.",
	}
	return h.App.AsJsonInterface(ctx, http.StatusNotFound, resp)

}

// DataReadError return AsJsonInterface error if persist a problem in encoding/decoding JSON data
func (h HTTPHandler) DataReadError(ctx *app.Context, description string) *server.ResponseInterface {
	type Response struct {
		StatusCode int         `json:"responseCode"`
		Message    interface{} `json:"responseMessage"`
	}
	resp := Response{
		StatusCode: http.StatusUnsupportedMediaType,
		Message:    description,
	}
	return h.App.AsJsonInterface(ctx, http.StatusNotFound, resp)
}

// RedisWriteError return AsJsonInterface error if persist a problem in writing data to Redis
func (h HTTPHandler) RedisWriteError(ctx *app.Context, description string) *server.ResponseInterface {
	type Response struct {
		StatusCode int         `json:"responseCode"`
		Message    interface{} `json:"responseMessage"`
	}
	resp := Response{
		StatusCode: http.StatusUnsupportedMediaType,
		Message:    description,
	}
	return h.App.AsJsonInterface(ctx, http.StatusNotFound, resp)

}

// AsJson always return httpStatus: 200, but Status field: 500,400,200...
func (h HTTPHandler) AsJson(ctx *app.Context, status int, message string, data interface{}) *server.Response {
	return h.App.AsJson(ctx, status, message, data)
}

func (h HTTPHandler) AsJsonInterface(ctx *app.Context, status int, data interface{}) *server.ResponseInterface {
	return h.App.AsJsonInterface(ctx, status, data)
}

// BadRequest For mobile, httpStatus:200, but Status field: http.MobileBadRequest
func (h HTTPHandler) BadRequest(ctx *app.Context, err error) *server.Response {
	return h.App.AsJson(ctx, http.StatusBadRequest, err.Error(), nil)
}

// ForbiddenRequest For mobile, httpStatus:200, but Status field: http.StatusForbidden
func (h HTTPHandler) ForbiddenRequest(ctx *app.Context, err error) *server.Response {
	return h.App.AsJson(ctx, http.StatusForbidden, err.Error(), nil)
}

func (h HTTPHandler) AsError(ctx *app.Context, message string) *server.Response {
	return h.App.AsJson(ctx, http.StatusInternalServerError, message, nil)
}

func (h HTTPHandler) ThrowBadRequestException(ctx *app.Context, message string) *server.Response {
	return h.App.ThrowExceptionJson(ctx, http.StatusBadRequest, 0, "Bad Request", message)
}

func (h HTTPHandler) GetQuiz(ctx *app.Context) *server.ResponseInterface {
	quiz := ctx.Param("quiz")
	quizId, _ := strconv.Atoi(quiz)
	resp, err := h.PrimaryService.GetQuiz(ctx, quizId)
	if err != nil {
		return h.AsJsonInterface(ctx, http.StatusBadRequest, err)
	}
	if resp.CourseId == "" {
		return h.DataNotFound(ctx)
	}

	return h.AsJsonInterface(ctx, http.StatusOK, resp)
}

func (h HTTPHandler) GetQuizUser(ctx *app.Context) *server.ResponseInterface {
	//Declaring Variables
	var Response domain.GetQuizUserData
	quiz := ctx.Param("quiz")
	user := ctx.Param("user")
	quizId, _ := strconv.Atoi(quiz)
	userId, _ := strconv.Atoi(user)
	//Getting data from Redis
	Redisresp, _ := h.RedisClient.HGet(ctx, "QUIZ:"+quiz, user)
	if Redisresp == "" {
		resp, err := h.PrimaryService.GetQuizUser(ctx, quizId, userId)
		if err != nil {
			return h.AsJsonInterface(ctx, http.StatusBadRequest, err)
		}
		if resp.CourseId == "" {
			return h.DataNotFound(ctx)
		}
		converter, error := json.Marshal(resp)
		if error != nil {
			return h.DataReadError(ctx, error.Error())
		}
		if err := h.RedisClient.HSet(ctx, "QUIZ:"+quiz, user, string(converter)); err != nil {
			return h.RedisWriteError(ctx, err.Error())
		}
		if err := h.RedisClient.SetHashesExpire(ctx, "QUIZ:"+quiz, resp.TimeOpen, resp.TimeClose); err != nil {
			return h.RedisWriteError(ctx, err.Error())
		}
		return h.AsJsonInterface(ctx, http.StatusOK, resp)
	}
	converter := []byte(Redisresp)
	err := json.Unmarshal(converter, &Response)
	if err != nil {
		return h.DataReadError(ctx, err.Error())
	}
	return h.AsJsonInterface(ctx, http.StatusOK, Response)

}

// func (h HTTPHandler) GetQuizUser(ctx *app.Context) *server.ResponseInterface {
// 	quiz := ctx.Param("quiz")
// 	user := ctx.Param("user")
// 	quizId, _ := strconv.Atoi(quiz)
// 	userId, _ := strconv.Atoi(user)
// 	resp, err := h.PrimaryService.GetQuizUser(ctx, quizId, userId)

// 	if err != nil {
// 		return h.AsJsonInterface(ctx, http.StatusBadRequest, err)
// 	}
// 	if resp.CourseId == "" {
// 		return h.DataNotFound(ctx)
// 	}
// 	out, _ := json.Marshal(resp)
// 	if err != nil {
// 		return h.AsJsonInterface(ctx, http.StatusBadRequest, err)
// 	}
// 	if err := h.RedisClient.HSet(ctx, "QUIZ:"+quiz, user, string(out)); err != nil {
// 		return h.AsJsonInterface(ctx, http.StatusBadRequest, err)
// 	}

// 	return h.AsJsonInterface(ctx, http.StatusOK, resp)
// }
