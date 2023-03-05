package handler

import (
	"encoding/json"
	"fmt"

	"moodle-api/internal/account/domain"
	accountService "moodle-api/internal/account/service"
	authService "moodle-api/internal/auth/service"

	"moodle-api/internal/base/app"
	"moodle-api/internal/base/handler"
	redis "moodle-api/internal/base/service/redisser"

	//"moodle-api/pkg/endpointTracer"

	"net/http"
	"strconv"

	"moodle-api/pkg/helper/bindjson"
	"moodle-api/pkg/helper/netzme"
	"moodle-api/pkg/server"

	"github.com/sirupsen/logrus"
)

type HTTPHandler struct {
	App            *handler.BaseHTTPHandler
	AccountService accountService.Service
	AuthService    authService.Service
	RedisClient    redis.RedisClient
}

func NewHTTPHandler(handler *handler.BaseHTTPHandler, accountService accountService.Service, authService authService.Service, redisClient redis.RedisClient) *HTTPHandler {
	return &HTTPHandler{
		App:            handler,
		AccountService: accountService,
		AuthService:    authService,
		RedisClient:    redisClient,
	}
}
func (h HTTPHandler) AsJsonInterface(ctx *app.Context, status int, data interface{}) *server.ResponseInterface {
	return h.App.AsJsonInterface(ctx, status, data)
}

func (h HTTPHandler) AsJson(ctx *app.Context, status int, message string, data interface{}) *server.Response {
	return h.App.AsJson(ctx, status, message, data)
}

func (h HTTPHandler) AsErrorFindCredential(ctx *app.Context, status int, data interface{}) *server.ResponseInterface {
	type Response struct {
		StatusCode string      `json:"responseCode"`
		Message    interface{} `json:"responseMessage"`
	}
	resp := Response{
		StatusCode: strconv.Itoa(status),
		Message:    data,
	}
	return h.App.AsJsonInterface(ctx, status, resp)
}

func (h HTTPHandler) NetzmeError(ctx *app.Context, err error, statusCode int) *server.Response {
	return h.App.AsJson(ctx, statusCode, err.Error(), nil)
}

func (h HTTPHandler) BadRequest(ctx *app.Context, err error) *server.Response {
	return h.App.AsJson(ctx, http.StatusBadRequest, err.Error(), nil)
}

func (h HTTPHandler) MerchantDetail(ctx *app.Context) *server.ResponseInterface {
	var (
		snapReq domain.SnapMerchantRequest
	)
	serviceCode := "08"

	xPartnerId := ctx.GetHeader("X-PARTNER-ID")
	xExternalId := ctx.GetHeader("X-EXTERNAL-ID")
	channelId := ctx.GetHeader("CHANNEL-ID")
	xTimeStamp := ctx.GetHeader("X-TIMESTAMP")
	errorType, errorField := bindjson.BindJSONHelper(ctx, &snapReq)
	if errorType == "undefined" {
		respStatus := netzme.GetStatusResponse("400", serviceCode, "00", "Invalid Request body")
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return h.AsJsonInterface(ctx, http.StatusBadRequest, respStatus)
	} else if errorType == "invalid_mandatory" {
		respStatus := netzme.GetStatusResponse("400", serviceCode, "02", "Missing Mandatory Field "+errorField)
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return h.App.AsJsonInterface(ctx, http.StatusBadRequest, respStatus)
	} else if errorType == "invalid_format" {
		respStatus := netzme.GetStatusResponse("400", serviceCode, "01", "Invalid Field Format "+errorField)
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return h.App.AsJsonInterface(ctx, http.StatusBadRequest, respStatus)
	}

	// jsonByte, _ := json.Marshal(snapReq)
	// logrus.Infoln(fmt.Sprintf("REQUEST ID: %s , REQUEST HIT BATMAN = HOST: %s ,  ENDPOINT: %s , METHOD: %s , PAYLOAD: %s", ctx.APIReqID, ctx.Request.Host, ctx.Request.RequestURI, ctx.Request.Method, string(jsonByte)))

	resp, statusCode, err := h.AccountService.GetMerchantDetail(ctx, snapReq, xTimeStamp, xPartnerId, xExternalId, channelId)
	if err != nil {
		return h.AsJsonInterface(ctx, statusCode, resp)
	}
	return h.AsJsonInterface(ctx, statusCode, resp)
}

func (h HTTPHandler) ForgotPin(ctx *app.Context) *server.ResponseInterface {
	var snapPinReq domain.SnapForgotPinRequest

	xPartnerId := ctx.GetHeader("X-PARTNER-ID")
	xExternalId := ctx.GetHeader("X-EXTERNAL-ID")
	channelId := ctx.GetHeader("CHANNEL-ID")
	xTimeStamp := ctx.GetHeader("X-TIMESTAMP")
	errorType, errorField := bindjson.BindJSONHelper(ctx, &snapPinReq)
	if errorType == "undefined" {
		respStatus := netzme.GetStatusResponse("400", "00", "00", "Invalid Request body")
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return h.AsJsonInterface(ctx, http.StatusBadRequest, respStatus)
	} else if errorType == "invalid_mandatory" {
		respStatus := netzme.GetStatusResponse("400", "00", "02", "Invalid Mandatory Field "+errorField)
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return h.App.AsJsonInterface(ctx, http.StatusBadRequest, respStatus)
	} else if errorType == "invalid_format" {
		respStatus := netzme.GetStatusResponse("400", "00", "01", "Invalid Field Format "+errorField)
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return h.App.AsJsonInterface(ctx, http.StatusBadRequest, respStatus)
	}

	resp, statusCode, err := h.AccountService.ForgotPin(ctx, snapPinReq, xTimeStamp, xPartnerId, xExternalId, channelId)
	if err != nil {
		return h.AsJsonInterface(ctx, statusCode, resp)
	}

	return h.AsJsonInterface(ctx, statusCode, resp)
}

func (h HTTPHandler) CreatePin(ctx *app.Context) *server.ResponseInterface {
	var (
		snapPinReq domain.SnapPinRequest
	)
	xPartnerId := ctx.GetHeader("X-PARTNER-ID")
	xExternalId := ctx.GetHeader("X-EXTERNAL-ID")
	channelId := ctx.GetHeader("CHANNEL-ID")
	xTimeStamp := ctx.GetHeader("X-TIMESTAMP")

	errorType, errorField := bindjson.BindJSONHelper(ctx, &snapPinReq)
	if errorType == "undefined" {
		respStatus := netzme.GetStatusResponse("400", "00", "00", "Invalid Request body")
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return h.AsJsonInterface(ctx, http.StatusBadRequest, respStatus)
	} else if errorType == "invalid_mandatory" {
		respStatus := netzme.GetStatusResponse("400", "00", "02", "Invalid Mandatory Field "+errorField)
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return h.App.AsJsonInterface(ctx, http.StatusBadRequest, respStatus)
	} else if errorType == "invalid_format" {
		respStatus := netzme.GetStatusResponse("400", "00", "01", "Invalid Field Format "+errorField)
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return h.App.AsJsonInterface(ctx, http.StatusBadRequest, respStatus)
	}

	// jsonByte, _ := json.Marshal(snapPinReq)
	// logrus.Infoln(fmt.Sprintf("REQUEST ID: %s , REQUEST HIT BATMAN = HOST: %s ,  ENDPOINT: %s , METHOD: %s , HEADER: %v PAYLOAD: %s", ctx.APIReqID, ctx.Request.Host, ctx.Request.RequestURI, ctx.Request.Method, ctx.Request.Header, string(jsonByte)))

	resp, statusCode, err := h.AccountService.CreatePin(ctx, snapPinReq, xTimeStamp, xPartnerId, xExternalId, channelId)
	if err != nil {
		// respStatus := netzme.GetStatusResponse(strconv.Itoa(statusCode), "00", "00", err.Error())
		// logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return h.AsJsonInterface(ctx, statusCode, resp)
	}

	return h.AsJsonInterface(ctx, statusCode, resp)
}

func (h HTTPHandler) DeductDepositSplitFee(ctx *app.Context) *server.ResponseInterface {
	var (
		snapReq domain.SnapDeductDepositSplitFeeRequest
	)

	xPartnerId := ctx.GetHeader("X-PARTNER-ID")
	xExternalId := ctx.GetHeader("X-EXTERNAL-ID")
	channelId := ctx.GetHeader("CHANNEL-ID")
	xTimeStamp := ctx.GetHeader("X-TIMESTAMP")

	errorType, errorField := bindjson.BindJSONHelper(ctx, &snapReq)
	if errorType == "undefined" {
		respStatus := netzme.GetStatusResponse("400", "00", "00", "Invalid Request body")
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return h.AsJsonInterface(ctx, http.StatusBadRequest, respStatus)
	} else if errorType == "invalid_mandatory" {
		respStatus := netzme.GetStatusResponse("400", "00", "02", "Invalid Mandatory Field "+errorField)
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return h.App.AsJsonInterface(ctx, http.StatusBadRequest, respStatus)
	} else if errorType == "invalid_format" {
		respStatus := netzme.GetStatusResponse("400", "00", "01", "Invalid Field Format "+errorField)
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return h.App.AsJsonInterface(ctx, http.StatusBadRequest, respStatus)
	}

	jsonByte, _ := json.Marshal(snapReq)
	logrus.Infoln(fmt.Sprintf("REQUEST ID: %s , REQUEST HIT BATMAN = HOST: %s ,  ENDPOINT: %s , METHOD: %s , PAYLOAD: %s", ctx.APIReqID, ctx.Request.Host, ctx.Request.RequestURI, ctx.Request.Method, string(jsonByte)))

	resp, statusCode, err := h.AccountService.DeductDepositSplitFee(ctx, snapReq, xTimeStamp, xPartnerId, xExternalId, channelId)
	if err != nil {
		return h.AsJsonInterface(ctx, statusCode, resp)
	}
	return h.AsJsonInterface(ctx, statusCode, resp)
}
