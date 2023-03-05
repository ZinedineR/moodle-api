package handler

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	redis "moodle-api/internal/base/service/redisser"
	"moodle-api/pkg/customOauth2"

	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/tdewolff/minify/v2"
	jsonMinify "github.com/tdewolff/minify/v2/json"

	authService "moodle-api/internal/auth/service"

	"moodle-api/internal/auth/domain"
	"moodle-api/internal/base/app"
	"moodle-api/internal/base/handler"
	"moodle-api/pkg/helper/signhelper"
	"moodle-api/pkg/server"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/generates"
)

type HTTPHandler struct {
	App         *handler.BaseHTTPHandler
	AuthService authService.Service
	RedisClient redis.RedisClient
}

func NewHTTPHandler(handler *handler.BaseHTTPHandler, authService authService.Service, redisClient redis.RedisClient) *HTTPHandler {
	return &HTTPHandler{
		App:         handler,
		AuthService: authService,
		RedisClient: redisClient,
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

func (h HTTPHandler) AsAccessResponseSuccess(ctx *gin.Context, accessToken, tokenType, expiresIn string, addtionalInfo interface{}) {
	if addtionalInfo == nil {
		ctx.JSON(http.StatusOK, gin.H{
			"responseCode":    "2007300",
			"responseMessage": "Successful",
			"accessToken":     accessToken,
			"tokenType":       tokenType,
			"expiresIn":       expiresIn,
		})
	} else {
		ctx.JSON(http.StatusOK, gin.H{
			"responseCode":    "2007300",
			"responseMessage": "Successful",
			"accessToken":     accessToken,
			"tokenType":       tokenType,
			"expiresIn":       expiresIn,
			"additionalInfo":  addtionalInfo,
		})
	}

}

// AsJson always return httpStatus: 200, but Status field: 500,400,200...
func (h HTTPHandler) AsJson(ctx *app.Context, status int, message string, data interface{}) *server.Response {
	return h.App.AsJson(ctx, status, message, data)
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

func (h HTTPHandler) SignatureAuth(ctx *gin.Context) {
	xTimestamp := ctx.GetHeader("X-TIMESTAMP")
	xClientKey := ctx.GetHeader("X-CLIENT-KEY")
	privateKey := ctx.GetHeader("Private_Key")

	if privateKey == "" {
		h.AsRequiredPrivateKeyError(ctx)
		return
	}

	if xTimestamp == "" {
		h.AsRequiredTimeStampError(ctx)
		return
	}
	if xClientKey == "" {
		h.AsRequiredClientIdError(ctx)
		return
	}

	if len(xTimestamp) > 25 {
		h.AsInvalidLengthTimeStampError(ctx)
		return
	}

	_, errParseTime := time.Parse(time.RFC3339, xTimestamp)
	if errParseTime != nil {
		h.AsInvalidFieldTimeStampError(ctx)
		return
	}

	//check exist client id to database
	credential, err := h.AuthService.FindCredential(ctx, xClientKey)
	if err != nil {
		h.AsInvalidClientIdError(ctx)
		return
	}
	logrus.Println(credential.PrivateKey)
	//check exist client id and private key to database
	// errCheckClientIdAndPrivateKey := h.AuthService.CheckClientKeyAndPrivateKey(ctx, xClientKey, privateKey)
	// if errCheckClientIdAndPrivateKey != nil {
	// 	h.AsInvalidPrivateKeyError(ctx)
	// 	return
	// }
	if credential.PrivateKey != privateKey {
		h.AsInvalidPrivateKeyError(ctx)
		return
	}
	stringToSignIn := xClientKey + "|" + xTimestamp

	//generate signature with SHA256withRSA method
	sign, errRsaSign := signhelper.RsaSign(stringToSignIn, privateKey, crypto.SHA256)
	if errRsaSign != nil {
		h.AsInvalidPrivateKeyError(ctx)
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"signature": sign,
	})
	return
}

func (h HTTPHandler) VerifySignature(ctx *gin.Context) {
	xSignature := ctx.GetHeader("X-SIGNATURE")

	if xSignature == "" {
		h.AsRequiredSignatureError(ctx)
		return
	}

}

func (h HTTPHandler) SignatureService(ctx *gin.Context) {
	xTimestamp := ctx.GetHeader("X-TIMESTAMP")
	xClientSecret := ctx.GetHeader("X-CLIENT-SECRET")
	httpMethod := ctx.GetHeader("HttpMethod")
	endpointUrl := ctx.GetHeader("EndpointUrl")
	accessToken := ctx.GetHeader("AccessToken")
	contentType := ctx.GetHeader("Content-Type")

	AuthCheck := strings.Split(accessToken, " ")
	if AuthCheck[0] != "Bearer" && AuthCheck[0] != "bearer" {
		h.AsRequiredBearer(ctx)
		return
	}
	accessToken = AuthCheck[1]

	if contentType == "" {
		h.AsRequiredContentTypeError(ctx)
		return
	}

	if contentType != "application/json" {
		h.AsRequiredContentTypeError(ctx)
		return
	}

	if xTimestamp == "" {
		h.AsRequiredTimeStampError(ctx)
		return
	}

	token, errParse := jwt.ParseWithClaims(accessToken, &generates.JWTAccessClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("parse error")
		}
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if errParse != nil {
		h.AsInvalidTokenError(ctx)
		return
	}

	_, ok := token.Claims.(*generates.JWTAccessClaims)
	if !ok || !token.Valid {
		h.AsInvalidTokenError(ctx)
		return
	}

	if len(xTimestamp) > 25 {
		h.AsInvalidLengthTimeStampError(ctx)
		return
	}

	_, errParseTime := time.Parse(time.RFC3339, xTimestamp)
	if errParseTime != nil {
		h.AsInvalidFieldTimeStampError(ctx)
		return
	}

	if xClientSecret == "" {
		h.AsRequiredClientSecretError(ctx)
		return
	}

	if httpMethod == "" {
		h.AsRequiredHttpMethodError(ctx)
		return
	}

	if endpointUrl == "" {
		h.AsRequiredEndpoinUrlError(ctx)
		return
	}

	if accessToken == "" {
		h.AsRequiredAccessTokenError(ctx)
		return
	}

	// only valid method allowed (must uppercase based on SNAP BI)
	if httpMethod != "POST" && httpMethod != "GET" && httpMethod != "PUT" && httpMethod != "DELETE" {
		h.AsInvalidHttpMethodError(ctx)
		return
	}

	// check if clientSecret exist
	err := h.AuthService.CheckClientSecret(ctx, xClientSecret)
	if err != nil {
		h.AsInvalidClientSecretError(ctx)
		return
	}

	// get all body request
	bodyJson, errRead := ioutil.ReadAll(ctx.Request.Body)
	if errRead != nil {
		h.AsErrorDefault(ctx, "Failed to read body")
	}

	// check if body is empty
	if len(bodyJson) != 0 {
		var x struct{}
		if err := json.Unmarshal(bodyJson, &x); err != nil {
			h.AsInvalidJsonFormat(ctx, err.Error())
			return
		}
	}

	// minify
	m := minify.New()
	m.AddFuncRegexp(regexp.MustCompile("[/+]json$"), jsonMinify.Minify)

	bodyJsonMinify, errMinify := m.Bytes("application/json", bodyJson)

	if errMinify != nil {
		logrus.Println("minify error reading json")
	}

	// --- sha256 hasher
	hasher := sha256.New()
	hasher.Write(bodyJsonMinify)
	// ---

	// to lower case (requirement)
	jsonHash := strings.ToLower(hex.EncodeToString(hasher.Sum(nil)))

	stringToSign := httpMethod + ":" + endpointUrl + ":" + accessToken + ":" + jsonHash + ":" + xTimestamp

	signature := signhelper.SignHMAC512(xClientSecret, stringToSign)

	ctx.JSON(http.StatusOK, gin.H{
		"signature": signature,
	})
	return

}

func (h HTTPHandler) Credentials(ctx *gin.Context) {

	var (
		cr domain.Credential
	)
	xPartnerId := ctx.GetHeader("X-PARTNER-ID")
	xCallbackToken := ctx.GetHeader("X-CALLBACK-TOKEN")

	if xPartnerId == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"responseCode":    "4000000",
			"responseMessage": "X-PARTNER-ID is required.",
		})
		return
	}

	if xCallbackToken == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"responseCode":    "4000000",
			"responseMessage": "X-CALLBACK-TOKEN is required.",
		})
		return
	}

	// check if xPartnerId is existed
	err := h.AuthService.CheckClientId(ctx, xPartnerId)

	if err == nil {
		res, err := h.AuthService.FindCredential(ctx, xPartnerId)

		if err != nil {
			ctx.JSON(http.StatusInternalServerError, "error get credential")
			return
		}

		ctx.JSON(http.StatusOK, gin.H{
			"x-callback-token": res.CallbackToken,
			"private_key":      res.PrivateKey,
			"client_id":        res.ClientId,
			"client_secret":    res.ClientSecret,
		})
		return
	}
	// sign part
	privateKey, publicKey, err := signhelper.GenerateKeyPair(512)
	if err != nil {
		h.AsErrorDefault(ctx, "could not generate keypair: "+err.Error())
	}

	//export private key to string
	privateKeyStr := strings.ReplaceAll(strings.Replace(strings.Replace(signhelper.ExportRsaPrivateKeyAsPemStr(privateKey),
		"-----BEGIN RSA PRIVATE KEY-----", "", 1), "-----END RSA PRIVATE KEY-----", "", 1), "\n", "")

	//export public key to string
	pubKeyStr := strings.ReplaceAll(strings.Replace(strings.Replace(signhelper.ExportRsaPublicKeyAsPemStr(publicKey),
		"-----BEGIN RSA PUBLIC KEY-----", "", 1), "-----END RSA PUBLIC KEY-----", "", 1), "\n", "")

	clientId := uuid.New().String()
	clientId = strings.Replace(clientId, "-", "", -1)

	clientSecret := uuid.New().String()
	clientSecret = strings.Replace(clientSecret, "-", "", -1)

	cr.ClientId = xPartnerId
	cr.PrivateKey = privateKeyStr
	cr.PublicKey = pubKeyStr
	cr.ClientSecret = clientSecret
	cr.CallbackToken = xCallbackToken

	errStore := h.AuthService.StoreCredentials(ctx, cr)
	if errStore != nil {
		h.AsErrorDefault(ctx, errStore.Error())
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"x-callback-token": cr.CallbackToken,
		"private_key":      cr.PrivateKey,
		"client_id":        cr.ClientId,
		"client_secret":    cr.ClientSecret,
	})
	return

}

func (h HTTPHandler) ProtectedToken(ctx *gin.Context) {
	var (
		response domain.ResponseAccessToken
	)
	lineaccess := ctx.GetHeader("Authorization")

	access := strings.Split(lineaccess, " ")
	token, err := jwt.ParseWithClaims(access[1], &generates.JWTAccessClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("parse error")
		}
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err != nil {
		response.ResponseCode = "4010001"
		response.ResponseMessage = "Access Token Invalid"
		ctx.JSON(http.StatusForbidden, &response)
		return
	}

	_, ok := token.Claims.(*generates.JWTAccessClaims)
	if !ok || !token.Valid {
		response.ResponseCode = "4010001"
		response.ResponseMessage = "Access Token Invalid"
		ctx.JSON(http.StatusForbidden, &response)
		return
	}

	response.ResponseCode = "2002200"
	response.ResponseMessage = "Request successful"

	ctx.JSON(http.StatusOK, &response)

}

func (h HTTPHandler) AccessToken(ctx *gin.Context) {
	var (
		request     domain.AccessTokenRequest
		accessToken string
	)
	xTimestamp := ctx.GetHeader("X-TIMESTAMP")
	xClientKey := ctx.GetHeader("X-CLIENT-KEY")
	xSignature := ctx.GetHeader("X-SIGNATURE")
	contentType := ctx.GetHeader("Content-Type")

	if contentType != "application/json" {
		h.AsRequiredContentTypeError(ctx)
		return
	}

	if len(xTimestamp) > 25 {
		h.AsInvalidLengthTimeStampError(ctx)
		return
	}

	if xSignature == "" {
		h.AsRequiredSignatureError(ctx)
		return
	}

	if xTimestamp == "" {
		h.AsRequiredTimeStampError(ctx)
		return
	}

	if xClientKey == "" {
		h.AsRequiredClientIdError(ctx)
		return
	}

	if err := ctx.ShouldBindJSON(&request); err != nil {
		h.AsErrorDefault(ctx, err.Error())
		return
	}

	if request.GrantType == "" {
		h.AsRequiredGrantTypeError(ctx)
		return
	}

	// only client_credentials grant type allowed
	if request.GrantType != "client_credentials" {
		h.AsRequiredGrantTypeClientCredentialsError(ctx)
		return
	}
	credential, err := h.AuthService.FindCredential(ctx, xClientKey)
	if err != nil {
		h.AsInvalidClientIdAccessTokenError(ctx)
		return
	}
	stringToSignIn := xClientKey + "|" + xTimestamp

	decodedSignature, _ := base64.StdEncoding.DecodeString(xSignature)

	hash := crypto.SHA256
	shaNew := hash.New()
	shaNew.Write([]byte(stringToSignIn))
	hashed := shaNew.Sum(nil)

	publicKey, errParse := signhelper.ParsePublicKey(credential.PublicKey)
	if errParse != nil {
		h.AsErrorDefault(ctx, errParse.Error())
		return
	}

	// verify signature
	verifyErr := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], decodedSignature)
	if verifyErr != nil {
		h.AsInvalidSignatureError(ctx)
		return
	}

	gt := oauth2.GrantType(request.GrantType)

	// check grant type
	if allowed := h.App.Oauth2Srv.CheckGrantType(oauth2.GrantType(gt)); !allowed {
		h.AsRequiredGrantTypeClientCredentialsError(ctx)
		return
	}

	accessToken, errCheck := h.RedisClient.Get(ctx, "token-"+xClientKey)
	if errCheck != nil {

		// set valid credentials to session (mandatory for create access token)
		h.App.Oauth2Client.Set(credential.ClientId, &models.Client{
			ID:     credential.ClientId,
			Secret: credential.ClientSecret,
			Domain: "netzme.id",
		})

		// generate TGR (Token Generate Request) for JWT
		tgr := &oauth2.TokenGenerateRequest{
			ClientID:       credential.ClientId,
			ClientSecret:   credential.ClientSecret,
			Request:        ctx.Request,
			AccessTokenExp: 15 * time.Hour,
		}

		//manual jwt generator
		generator := customOauth2.NewJWTAccessGenerate(customOauth2.JWTConfig{
			SignedKey:     []byte(os.Getenv("JWT_SECRET")),
			SigningMethod: jwt.SigningMethodHS512,
		})

		//// generate process are handled by third party lib
		//ti, errGenerate := h.App.Oauth2Manager.GenerateAccessToken(ctx, gt, tgr)

		accessToken, errGenerate := generator.Token(ctx, tgr, false)

		// check if gtr valid and token generated successfully
		if errGenerate != nil {
			logrus.Errorln(errGenerate)
			return
		}

		_, errCheck = h.RedisClient.SetWithExpire(ctx, "token-"+xClientKey, accessToken, tgr.AccessTokenExp)
		if errCheck != nil {
			h.AsErrorDefault(ctx, "error insert token to redis")
			logrus.Errorln(errGenerate)
			return
		}
		h.AsAccessResponseSuccess(ctx, accessToken, "Bearer",
			strconv.Itoa(int(tgr.AccessTokenExp.Seconds())), request.AdditionalInfo)
		return
	}

	tokenExpiresIn := h.RedisClient.GetTTL(ctx, "token-"+xClientKey)

	h.AsAccessResponseSuccess(ctx, accessToken, "Bearer",
		strconv.Itoa(int(tokenExpiresIn)), request.AdditionalInfo)

	return
}
