package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	authService "moodle-api/internal/auth/service"
	"moodle-api/internal/base/domain"
	"moodle-api/pkg/customOauth2"
	"moodle-api/pkg/helper/netzme"
	"moodle-api/pkg/helper/signhelper"
	"moodle-api/pkg/httpclient"

	"github.com/dgrijalva/jwt-go"
	"github.com/sirupsen/logrus"
	"github.com/tdewolff/minify/v2"
	jsonMinify "github.com/tdewolff/minify/v2/json"

	"moodle-api/app/appconf"
	"moodle-api/internal/base/app"
	redis "moodle-api/internal/base/service/redisser"
	baseModel "moodle-api/pkg/db"
	"moodle-api/pkg/server"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/manage"
	oauth2Server "github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/go-playground/validator/v10"
	"gorm.io/gorm"
)

type HandlerFn func(ctx *app.Context) *server.Response
type HandlerFnPayment func(ctx *app.Context) *domain.CallbackNotificationResponse
type HandlerFnInterface func(ctx *app.Context) *server.ResponseInterface

type BaseHTTPHandler struct {
	Handlers      interface{}
	DB            *gorm.DB
	AppConfig     *appconf.Config
	Validate      *validator.Validate
	BaseModel     *baseModel.PostgreSQLClientRepository
	RedisClient   redis.RedisClient
	Oauth2Manager *manage.Manager
	Oauth2Srv     *oauth2Server.Server
	Oauth2Client  *store.ClientStore
	HttpClient    httpclient.Client
	AuthService   authService.Service
}

func NewBaseHTTPHandler(db *gorm.DB,
	appConfig *appconf.Config,
	baseModel *baseModel.PostgreSQLClientRepository,
	validate *validator.Validate,
	redisClient redis.RedisClient,
	oauth2Manager *manage.Manager,
	oauth2Srv *oauth2Server.Server,
	httpClient httpclient.Client,
	oauth2Client *store.ClientStore,
	authService authService.Service,
) *BaseHTTPHandler {
	return &BaseHTTPHandler{
		DB:            db,
		AppConfig:     appConfig,
		Validate:      validate,
		BaseModel:     baseModel,
		RedisClient:   redisClient,
		Oauth2Manager: oauth2Manager,
		Oauth2Srv:     oauth2Srv,
		Oauth2Client:  oauth2Client,
		HttpClient:    httpClient,
		AuthService:   authService,
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

func (b BaseHTTPHandler) InterfaceRunAction(handler HandlerFnInterface) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		// logrus.Infoln(fmt.Sprintf("REQUEST: url= %s header= %v", c.Request.URL, c.Request.Header))
		ctx, httpCode, serviceCode, caseCode, bodyBytes, err := b.Authentication(c)
		if err != nil {
			var bodyBytes []byte
			if c.Request.Body != nil {
				bodyBytes, _ = ioutil.ReadAll(ctx.Request.Body)
			}
			logrus.Infoln(fmt.Sprintf("REQUEST ID: %s , REQUEST HIT BATMAN = HOST: %s ,  ENDPOINT: %s , METHOD: %s , HEADER: %v, PAYLOAD: %s", ctx.APIReqID, ctx.Request.Host, ctx.Request.RequestURI, ctx.Request.Method, c.Request.Header, string(bodyBytes)))
			hc, _ := strconv.Atoi(httpCode)
			respStatus := netzme.GetStatusResponse(httpCode, serviceCode, caseCode, err.Error())
			logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
			c.JSON(hc, netzme.GetStatusResponse(httpCode, serviceCode, caseCode, err.Error()))
			return
		}

		logrus.Infoln(fmt.Sprintf("REQUEST ID: %s , REQUEST HIT BATMAN = HOST: %s ,  ENDPOINT: %s , METHOD: %s , HEADER: %v, PAYLOAD: %s", ctx.APIReqID, ctx.Request.Host, ctx.Request.RequestURI, ctx.Request.Method, ctx.Request.Header, string(bodyBytes)))

		defer func() {
			if err0 := recover(); err0 != nil {
				logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , message: internal status error", ctx.APIReqID))
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

func (b BaseHTTPHandler) AsErrorFindCredential(ctx *app.Context, status int, data interface{}) *server.ResponseInterface {
	type Response struct {
		StatusCode string      `json:"responseCode"`
		Message    interface{} `json:"responseMessage"`
	}
	resp := Response{
		StatusCode: strconv.Itoa(status),
		Message:    data,
	}
	return b.AsJsonInterface(ctx, status, resp)
}

func (b BaseHTTPHandler) AccountRunAction(handler HandlerFnPayment) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, err := b.PaymentAuthentication(c)
		if err != nil {
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
		//httpStatus := http.StatusOK
		//if resp.ResponseCode == 0 {
		//	httpStatus = http.StatusBadRequest
		//}

		httpStatus := resp.ResponseCode

		if httpStatus == 200 {
			resp.ResponseCode = 1
		} else {
			resp.ResponseCode = 0
		}

		//resp.RequestID = ctx.APIReqID
		c.JSON(httpStatus, resp)

	}
}

func (b BaseHTTPHandler) PaymentRunAction(handler HandlerFnPayment) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, err := b.PaymentAuthentication(c)
		if err != nil {
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
		//httpStatus := http.StatusOK
		//if resp.ResponseCode == 0 {
		//	httpStatus = http.StatusBadRequest
		//}

		httpStatus := resp.ResponseCode

		if httpStatus == 200 {
			resp.ResponseCode = 1
		} else {
			resp.ResponseCode = 0
		}

		//resp.RequestID = ctx.APIReqID
		c.JSON(httpStatus, resp)

	}
}

func (b BaseHTTPHandler) RunAction(handler HandlerFn) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, httpCode, serviceCode, caseCode, _, err := b.Authentication(c)
		if err != nil {
			hc, _ := strconv.Atoi(httpCode)
			c.JSON(hc, netzme.GetStatusResponse(httpCode, serviceCode, caseCode, err.Error()))
			return
		}

		defer func() {
			if err0 := recover(); err0 != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"status":  http.StatusInternalServerError,
					"message": "Request is halted unexpectedly, please contact the administrator.",
					"data":    nil,
				})
			}
		}()

		resp := handler(ctx)
		httpStatus := resp.GetStatus()
		resp.RequestID = ctx.APIReqID
		c.JSON(httpStatus, resp)

	}
}

func (b BaseHTTPHandler) MoodleAuthentication(c *gin.Context) (*app.Context, error) {
	return app.NewContext(c, b.AppConfig), nil
}

func (b BaseHTTPHandler) PaymentAuthentication(c *gin.Context) (*app.Context, error) {
	xApiKey := c.GetHeader("X-API-KEY")
	xContentType := c.GetHeader("Content-Type")
	if xApiKey == "" {
		return nil, errors.New("X-API-KEY is required")
	}
	if xContentType != "application/json" {
		return nil, errors.New("Content-Type is required")
	}

	var bodyBytes []byte
	if c.Request.Body != nil {
		bodyBytes, _ = ioutil.ReadAll(c.Request.Body)
	}
	c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

	if len(bodyBytes) == 0 {
		return nil, errors.New("body is required")
	}

	return app.NewContext(c, b.AppConfig), nil
}

func (b BaseHTTPHandler) Authentication(c *gin.Context) (*app.Context, string, string, string, []byte, error) {
	xTimestamp := c.GetHeader("X-TIMESTAMP")
	//xClientKey := c.GetHeader("X-CLIENT-SECRET")
	xSignature := c.GetHeader("X-SIGNATURE")
	xContentType := c.GetHeader("Content-Type")
	authorization := c.GetHeader("Authorization")
	xPartnerId := c.GetHeader("X-PARTNER-ID")
	xExternalId := c.GetHeader("X-EXTERNAL-ID")
	channelId := c.GetHeader("CHANNEL-ID")

	serviceCode := "00"
	serviceName := fmt.Sprintf("%v", c.Request.URL)
	switch serviceName {
	case "/api/v1.0/registration-account-inquiry":
		serviceCode = "08"
	case "/api/v1.0/payment/balance-inquiry":
		serviceCode = "11"
	case "/api/v1.0/transaction/history-list":
		serviceCode = "12"
	case "/api/v1.0/transaction/get-invoice":
		serviceCode = "13"
	case "/api/v1.0/invoice/create-transaction":
		serviceCode = "47"
	case "/api/v1.0/emoney/bank-account-inquiry":
		serviceCode = "42"
	case "/api/v1.0/debit/payment-host-to-host":
		serviceCode = "42"
	case "/api/v1.0/emoney/transfer-bank":
		serviceCode = "43"
	case "/api/v1.0/transaction/get-qris":
		serviceCode = "13"
	case "/api/v1.0/deposit/balance-inquiry":
		serviceCode = "11"
	case "/api/v1.0/debit/payment-host-to-host-deposit":
		serviceCode = "42"
	case "/api/v1.0/emoney/bank-account-inquiry/deposit":
		serviceCode = "42"
	case "/api/v1.0/emoney/transfer-bank/deposit":
		serviceCode = "43"
	case "/api/v1.0/deposit/transaction-history-list":
		serviceCode = "12"
	default:
		serviceCode = "00"
	}

	if xTimestamp == "" {
		// respStatus := netzme.GetStatusResponse("400", serviceCode, "02", errors.New("Missing Mandatory Field X-TIMESTAMP"))
		// logrus.Errorln(fmt.Sprintf("response_code: %s , response_message: %s", respStatus.ResponseCode, respStatus.ResponseMessage))
		return app.NewContext(c, b.AppConfig), "400", serviceCode, "02", nil, errors.New("Missing Mandatory Field X-TIMESTAMP")
	}
	if xSignature == "" {
		// respStatus := netzme.GetStatusResponse("400", serviceCode, "02", errors.New("Missing Mandatory Field X-SIGNATURE"))
		// logrus.Errorln(fmt.Sprintf("response_code: %s , response_message: %s", respStatus.ResponseCode, respStatus.ResponseMessage))
		return app.NewContext(c, b.AppConfig), "400", serviceCode, "02", nil, errors.New("Missing Mandatory Field X-SIGNATURE")
	}
	if xContentType != "application/json" {
		// respStatus := netzme.GetStatusResponse("400", serviceCode, "02", errors.New("Missing Mandatory Field Content-Type"))
		// logrus.Errorln(fmt.Sprintf("response_code: %s , response_message: %s", respStatus.ResponseCode, respStatus.ResponseMessage))
		return app.NewContext(c, b.AppConfig), "400", serviceCode, "02", nil, errors.New("Missing Mandatory Field Content-Type")
	}
	if authorization == "" {
		// respStatus := netzme.GetStatusResponse("400", serviceCode, "02", errors.New("Missing Mandatory Field authorization"))
		// logrus.Errorln(fmt.Sprintf("response_code: %s , response_message: %s", respStatus.ResponseCode, respStatus.ResponseMessage))
		return app.NewContext(c, b.AppConfig), "400", serviceCode, "02", nil, errors.New("Missing Mandatory Field authorization")
	}
	authSpaceCheck := regexp.MustCompile(`\s`).MatchString(authorization)
	if authSpaceCheck == true {
		AuthCheck := strings.Split(authorization, " ")
		if AuthCheck[0] != "Bearer" && AuthCheck[0] != "bearer" {
			// respStatus := netzme.GetStatusResponse("400", serviceCode, "02", errors.New("bearer authorization is required"))
			// logrus.Errorln(fmt.Sprintf("response_code: %s , response_message: %s", respStatus.ResponseCode, respStatus.ResponseMessage))
			return app.NewContext(c, b.AppConfig), "400", serviceCode, "02", nil, errors.New("bearer authorization is required")
		}
		authorization = AuthCheck[1]
	} else {
		// respStatus := netzme.GetStatusResponse("400", serviceCode, "02", errors.New("bearer authorization format invalid"))
		// logrus.Errorln(fmt.Sprintf("response_code: %s , response_message: %s", respStatus.ResponseCode, respStatus.ResponseMessage))
		return app.NewContext(c, b.AppConfig), "400", serviceCode, "02", nil, errors.New("bearer authorization format invalid")
	}

	if xPartnerId == "" {
		// respStatus := netzme.GetStatusResponse("400", serviceCode, "02", errors.New("Missing Mandatory Field X-PARTNER-ID"))
		// logrus.Errorln(fmt.Sprintf("response_code: %s , response_message: %s", respStatus.ResponseCode, respStatus.ResponseMessage))
		return app.NewContext(c, b.AppConfig), "400", serviceCode, "02", nil, errors.New("Missing Mandatory Field X-PARTNER-ID")
	}
	_, errFindCredential := b.AuthService.FindCredential(c, xPartnerId)
	if errFindCredential != nil {
		if errFindCredential.Error() == "record not found" {
			// logrus.Errorln(fmt.Sprintf("response_code: %s , response_message: %s", "401"+serviceCode+"01", "Unauthorized. X-PARTNER-ID is Invalid"))
			return app.NewContext(c, b.AppConfig), "401", serviceCode, "01", nil, errors.New("Unauthorized. X-PARTNER-ID is Invalid")
		}
		// logrus.Errorln(fmt.Sprintf("response_code: %s , response_message: %s", "400", errFindCredential.Error()))
		return app.NewContext(c, b.AppConfig), "401", serviceCode, "01", nil, errFindCredential
	}
	if xExternalId == "" {
		// respStatus := netzme.GetStatusResponse("400", serviceCode, "02", errors.New("Missing Mandatory Field X-EXTERNAL-ID"))
		// logrus.Errorln(fmt.Sprintf("response_code: %s , response_message: %s", respStatus.ResponseCode, respStatus.ResponseMessage))
		return app.NewContext(c, b.AppConfig), "400", serviceCode, "02", nil, errors.New("Missing Mandatory Field X-EXTERNAL-ID")
	}
	if len(xExternalId) > 36 {
		// respStatus := netzme.GetStatusResponse("400", serviceCode, "02", errors.New("X-EXTERNAL-ID is out of range, maximum 36 char"))
		// logrus.Errorln(fmt.Sprintf("response_code: %s , response_message: %s", respStatus.ResponseCode, respStatus.ResponseMessage))
		return app.NewContext(c, b.AppConfig), "400", serviceCode, "02", nil, errors.New("X-EXTERNAL-ID is out of range, maximum 36 char")
	}
	isMatch := regexp.MustCompile(`^[0-9]*$`).MatchString(xExternalId)
	if !isMatch {
		// respStatus := netzme.GetStatusResponse("409", serviceCode, "00", errors.New("character X-EXTERNAL-ID is numeric only"))
		// logrus.Errorln(fmt.Sprintf("response_code: %s , response_message: %s", respStatus.ResponseCode, respStatus.ResponseMessage))
		return app.NewContext(c, b.AppConfig), "409", serviceCode, "00", nil, errors.New("character X-EXTERNAL-ID is numeric only")
	}
	if channelId == "" {
		// respStatus := netzme.GetStatusResponse("400", serviceCode, "02", errors.New("Missing Mandatory Field CHANNEL-ID"))
		// logrus.Errorln(fmt.Sprintf("response_code: %s , response_message: %s", respStatus.ResponseCode, respStatus.ResponseMessage))
		return app.NewContext(c, b.AppConfig), "400", serviceCode, "02", nil, errors.New("Missing Mandatory Field CHANNEL-ID")
	}

	// validate token
	accessToken, errCheck := b.RedisClient.Get(c, "token-"+xPartnerId)
	if errCheck != nil || accessToken != authorization {
		// respStatus := netzme.GetStatusResponse("401", serviceCode, "01", errors.New("Access Token Invalid"))
		// logrus.Errorln(fmt.Sprintf("response_code: %s , response_message: %s", respStatus.ResponseCode, respStatus.ResponseMessage))
		return app.NewContext(c, b.AppConfig), "401", serviceCode, "01", nil, errors.New("Access Token Invalid")
	}

	token, errParse := customOauth2.ParseClaims(jwt.SigningMethodHS512, []byte(os.Getenv("JWT_SECRET")), authorization)

	//token, errParse := jwt.ParseWithClaims(authorization, &generates.JWTAccessClaims{}, func(t *jwt.Token) (interface{}, error) {
	//	if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
	//		return app.NewContext(c, b.AppConfig), fmt.Errorf("parse error")
	//	}
	//	return []byte(os.Getenv("JWT_SECRET")), nil
	//})

	if errParse != nil {
		// logrus.Errorln(errParse)
		return app.NewContext(c, b.AppConfig), "401", serviceCode, "01", nil, errors.New(errParse.Error())
	}

	credential, err := b.AuthService.FindCredential(c, token.Issuer)
	if err != nil {
		return app.NewContext(c, b.AppConfig), "401", serviceCode, "01", nil, errors.New("invalid credential")
	}
	//_, ok := token.Claims.(*generates.JWTAccessClaims)
	//if !ok || !token.Valid {
	//	return app.NewContext(c, b.AppConfig), errors.New("invalid token")
	//}
	//
	_, errParseTime := time.Parse(time.RFC3339, xTimestamp)
	if errParseTime != nil {
		return app.NewContext(c, b.AppConfig), "400", serviceCode, "01", nil, errors.New("invalid Field Format Timestamp")
	}

	if len(xTimestamp) > 25 {
		return app.NewContext(c, b.AppConfig), "400", serviceCode, "01", nil, errors.New("the field timestamp must be a string or array type with a maximum length of '25'")
	}

	// get all body request
	var bodyBytes []byte
	if c.Request.Body != nil {
		bodyBytes, _ = ioutil.ReadAll(c.Request.Body)
	}
	c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

	if c.Request.Method == "POST" && len(bodyBytes) == 0 {
		return app.NewContext(c, b.AppConfig), "400", serviceCode, "01", nil, errors.New("body is required")
	}

	// minify
	m := minify.New()
	m.AddFuncRegexp(regexp.MustCompile("[/+]json$"), jsonMinify.Minify)

	bodyJsonMinify, errMinify := m.Bytes("application/json", bodyBytes)

	if errMinify != nil {
		logrus.Println("minify error reading json")
	}

	c.Set("bodyJSON", string(bodyJsonMinify))

	// --- sha256 hasher
	hasher := sha256.New()
	hasher.Write(bodyJsonMinify)
	// ---

	// to lower case (requirement)
	jsonHash := strings.ToLower(hex.EncodeToString(hasher.Sum(nil)))

	stringToSign := c.Request.Method + ":" + c.Request.RequestURI + ":" + authorization + ":" + jsonHash + ":" + xTimestamp

	resp, _ := signhelper.VerifyHMAC512([]byte(stringToSign), []byte(credential.ClientSecret), xSignature)
	if !resp {
		return app.NewContext(c, b.AppConfig), "401", serviceCode, "00", nil, errors.New("Unauthorized Signature")
	}

	return app.NewContext(c, b.AppConfig), "", "", "", bodyBytes, nil
}

func (b BaseHTTPHandler) WebviewRunAction(handler HandlerFnInterface) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		ctx, err := b.PaymentAuthentication(c)
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
