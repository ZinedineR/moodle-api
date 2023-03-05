package service

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"moodle-api/internal/account/domain"
	authService "moodle-api/internal/auth/service"
	"moodle-api/internal/base/app"
	domainSnap "moodle-api/internal/base/domain"
	rdis "moodle-api/internal/base/service/redisser"

	"moodle-api/pkg/helper/netzme"
	"moodle-api/pkg/helper/signhelper"
	"moodle-api/pkg/httpclient"

	"github.com/sirupsen/logrus"
)

// NewService creates new user service
func NewService(httpClient httpclient.Client, redisClient rdis.RedisClient, authService authService.Service) Service {
	return &service{httpClient: httpClient, redisClient: redisClient, authService: authService}
}

type service struct {
	httpClient  httpclient.Client
	redisClient rdis.RedisClient
	authService authService.Service
}

func (s service) CreatePin(ctx *app.Context, snapPinReq domain.SnapPinRequest, xTimeStamp, xPartnerId, xExternalId, channelId string) (interface{}, int, error) {
	timeParse, _ := time.Parse(time.RFC3339, xTimeStamp)
	timeMiliString := strconv.FormatInt(timeParse.UnixMilli(), 10)

	accessToken, errCheck := s.redisClient.Get(ctx, os.Getenv("CLIENT_ID_NETZME")+"-batman")
	if errCheck != nil {
		// 1. get access token to authentication netzme
		accessTokenReq, statusCode, response, err := s.authService.GetAccessToken(ctx)
		if statusCode != http.StatusOK || err != nil {
			logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, strconv.Itoa(statusCode)+"0000", "Access Token Error"))
			return response, statusCode, errCheck
		}
		accessToken = accessTokenReq.AccessToken

		expiryToken := time.Unix(0, int64(accessTokenReq.ExpiryToken)*int64(time.Millisecond))
		expiryDuration := expiryToken.Sub(time.Now().Add(2 * time.Minute))

		_, errCheck := s.redisClient.SetWithExpire(ctx, os.Getenv("CLIENT_ID_NETZME")+"-batman", accessToken, expiryDuration)
		if errCheck != nil {
			respStatus := netzme.GetStatusResponse("400", "00", "00", "Redis Client Error")
			logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, strconv.Itoa(http.StatusBadRequest)+"0000", "Redis Client Error"))
			return respStatus, http.StatusBadRequest, errCheck
		}
	}

	auth := "Bearer " + accessToken

	if snapPinReq.AdditionalInfo.Type != "create_pin" {
		respStatus := netzme.GetStatusResponse("400", "00", "01", "Invalid Field Format type")
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return respStatus, http.StatusBadRequest, fmt.Errorf("Invalid Field Format type")
	}
	createPinReq := domain.CreatePinRequest{
		Body: struct {
			Pin      string "json:\"pin\" binding:\"required\""
			Username string "json:\"username\" binding:\"required\""
		}{Pin: snapPinReq.AdditionalInfo.Pin,
			Username: snapPinReq.CustIdMerchant},
		RequestId: snapPinReq.PartnerReferenceNo,
		Type:      snapPinReq.AdditionalInfo.Type,
	}

	bodyJson, err := json.Marshal(&createPinReq)
	if err != nil {
		respStatus := netzme.GetStatusResponse("400", "00", "01", err.Error())
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return respStatus, http.StatusBadRequest, err
	}
	bodyJsonString := string(bodyJson)

	// plain = stringToSign
	plain := netzme.BuildSignature("/api/aggregator/merchant/pin/create_pin", ctx.Request.Method, auth, bodyJsonString, timeMiliString)
	key := netzme.BuildKey(auth, timeMiliString)
	sign := signhelper.SignHMAC256(key, plain)

	var netzmeRes domain.CreatePinResponse

	resp, statusCode, err := s.SendCreatePin(ctx, auth, sign, timeMiliString, bodyJsonString, xPartnerId, xExternalId, channelId, "/api/aggregator/merchant/pin/create_pin", ctx.Request.Method)
	if err != nil {
		if statusCode == 401 {
			response := netzme.GetStatusResponse("401", "00", "00", "")
			logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, response.ResponseCode, response.ResponseMessage))
			return response, http.StatusUnauthorized, fmt.Errorf("")
		}
		respStatus := netzme.GetStatusResponse(strconv.Itoa(statusCode), "00", "00", err.Error())
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return respStatus, statusCode, err
	}

	respByte, err := json.Marshal(resp)
	logrus.Infoln(fmt.Sprintf("REQUEST ID: %s , RESPONSE FROM TOKO-NETZME = %s", ctx.APIReqID, string(respByte)))
	err = json.Unmarshal(respByte, &netzmeRes)
	if err != nil {
		respStatus := netzme.GetStatusResponse(strconv.Itoa(statusCode), "00", "00", err.Error())
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return respStatus, statusCode, fmt.Errorf(err.Error())
	}
	if statusCode != 200 {
		if statusCode == 401 {
			response := netzme.GetStatusResponse("401", "00", "00", "")
			logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, response.ResponseCode, response.ResponseMessage))
			return response, http.StatusUnauthorized, fmt.Errorf("")
		}
		response := netzme.GetStatusResponse(strconv.Itoa(statusCode), "00", "00", resp)
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, response.ResponseCode, response.ResponseMessage))
		return response, statusCode, fmt.Errorf("error")
	}
	var respStatus *domainSnap.SnapStatus

	if netzmeRes.Body.ErrorCode == "" && netzmeRes.Body.ErrorMessage == "" && netzmeRes.StatusMessage == "failed" {
		statusCode = 404
		respStatus = netzme.GetStatusResponse("404", "00", "08", "Invalid Merchant")
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return respStatus, statusCode, fmt.Errorf("Invalid Merchant")
	} else if netzmeRes.StatusMessage == "failed" || netzmeRes.Body.ErrorMessage == "PIN already exist with different value" {
		statusCode = 400
		respStatus = netzme.GetStatusResponse("400", "00", "00", netzmeRes.Body.ErrorMessage)
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return respStatus, statusCode, fmt.Errorf(netzmeRes.Body.ErrorMessage)
	} else if netzmeRes.Status == "100" || netzmeRes.StatusMessage == "success" {
		statusCode = 200
		respStatus = netzme.GetStatusResponse("200", "00", "00", "Successful")
	} else if netzmeRes.Status == "200" {
		statusCode = 200
		respStatus = netzme.GetStatusResponse("200", "00", "00", "Successful")
	} else {
		respStatus = netzme.GetStatusResponse(netzmeRes.Status, "00", "00", netzmeRes.StatusMessage)
	}
	snapCpr := domain.SnapCreatePinResponse{
		PartnerReferenceNo: snapPinReq.PartnerReferenceNo,
	}

	addInfo := domainSnap.SnapAdditionalInfo{
		AdditionalInfo: map[string]interface{}{
			"type": netzmeRes.Type,
		},
	}

	finalResponse := struct {
		*domainSnap.SnapStatus
		*domain.SnapCreatePinResponse
		*domainSnap.SnapAdditionalInfo
	}{respStatus, &snapCpr, &addInfo}
	batmanRespByte, _ := json.Marshal(finalResponse)
	// insert request history
	if err != nil {
		respStatus = netzme.GetStatusResponse("500", "00", "00", "Can't insert history request to db")
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return respStatus, statusCode, err
	}
	logrus.Infoln(fmt.Sprintf("REQUEST ID: %s , RESPONSE FROM BATMAN = %s", ctx.APIReqID, string(batmanRespByte)))
	return finalResponse, statusCode, nil
}

func (s service) ForgotPin(ctx *app.Context, snapPinReq domain.SnapForgotPinRequest, xTimeStamp, xPartnerId, xExternalId, channelId string) (interface{}, int, error) {
	var netzmeResp domain.ForgotPinResponse
	timeParse, _ := time.Parse(time.RFC3339, xTimeStamp)
	timeMiliString := strconv.FormatInt(timeParse.UnixMilli(), 10)

	accessToken, errCheck := s.redisClient.Get(ctx, os.Getenv("CLIENT_ID_NETZME")+"-batman")
	if errCheck != nil {
		accessTokenReq, statusCode, response, err := s.authService.GetAccessToken(ctx)
		if statusCode != http.StatusOK || err != nil {
			logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, strconv.Itoa(statusCode)+"0000", "Access Token Error"))
			return response, statusCode, errCheck
		}
		accessToken = accessTokenReq.AccessToken
		expiryToken := time.Unix(0, int64(accessTokenReq.ExpiryToken)*int64(time.Millisecond))
		expiryDuration := expiryToken.Sub(time.Now().Add(2 * time.Minute))

		_, errCheck := s.redisClient.SetWithExpire(ctx, os.Getenv("CLIENT_ID_NETZME")+"-batman", accessToken, expiryDuration)
		if errCheck != nil {
			respStatus := netzme.GetStatusResponse("400", "00", "00", "Redis Client Error")
			logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, strconv.Itoa(http.StatusBadRequest)+"0000", "Redis Client Error"))
			return respStatus, http.StatusBadRequest, errCheck
		}
	}

	auth := "Bearer " + accessToken

	if snapPinReq.AdditionalInfo.Type != "forgot_pin" {
		respStatus := netzme.GetStatusResponse("400", "00", "01", "Invalid Field Format type")
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return respStatus, http.StatusBadRequest, fmt.Errorf("Invalid Field Format type")
	}
	forgotPinReq := domain.ForgotPinRequest{
		Body: struct {
			Username string "json:\"username\" binding:\"required\""
		}{Username: snapPinReq.CustIdMerchant},
		RequestId: snapPinReq.PartnerReferenceNo,
		Type:      snapPinReq.AdditionalInfo.Type,
	}
	bodyJson, err := json.Marshal(&forgotPinReq)
	if err != nil {
		respStatus := netzme.GetStatusResponse("400", "00", "01", err.Error())
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return respStatus, http.StatusBadRequest, err
	}
	bodyJsonString := string(bodyJson)

	plain := netzme.BuildSignature("/api/aggregator/merchant/pin/forgot_pin", ctx.Request.Method, auth, bodyJsonString, timeMiliString)
	key := netzme.BuildKey(auth, timeMiliString)
	sign := signhelper.SignHMAC256(key, plain)

	resp, statusCode, err := s.SendForgotPin(ctx, auth, sign, timeMiliString, bodyJsonString, xPartnerId, xExternalId, channelId, "/api/aggregator/merchant/pin/forgot_pin", ctx.Request.Method)
	if err != nil {
		if statusCode == 401 {
			response := netzme.GetStatusResponse("401", "00", "00", "")
			logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, response.ResponseCode, response.ResponseMessage))
			return response, http.StatusUnauthorized, fmt.Errorf("")
		}
		respStatus := netzme.GetStatusResponse(strconv.Itoa(statusCode), "00", "00", err.Error())
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return respStatus, statusCode, err
	}

	if statusCode != 200 {
		if statusCode == 404 {
			response := netzme.GetStatusResponse("404", "00", "00", "resource not found")
			logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, response.ResponseCode, response.ResponseMessage))
			return response, http.StatusNotFound, fmt.Errorf("resource not found")
		} else if statusCode == 401 {
			response := netzme.GetStatusResponse("401", "00", "00", "")
			logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, response.ResponseCode, response.ResponseMessage))
			return response, http.StatusUnauthorized, fmt.Errorf("")
		}
		response := netzme.GetStatusResponse(strconv.Itoa(statusCode), "00", "00", resp)
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, response.ResponseCode, response.ResponseMessage))
		return response, statusCode, fmt.Errorf("error")
	}

	respByte, err := json.Marshal(resp)
	logrus.Infoln(fmt.Sprintf("REQUEST ID: %s , RESPONSE FROM TOKO-NETZME = %s", ctx.APIReqID, string(respByte)))
	err = json.Unmarshal(respByte, &netzmeResp)

	if err != nil {
		respStatus := netzme.GetStatusResponse(strconv.Itoa(statusCode), "00", "00", err.Error())
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return respStatus, statusCode, fmt.Errorf(err.Error())
	}
	//
	var respStatus *domainSnap.SnapStatus
	if netzmeResp.Status == 100 {
		statusCode = 200
		respStatus = netzme.GetStatusResponse(strconv.Itoa(statusCode), "00", "00", "Successful")
	} else if netzmeResp.Status == 203 && netzmeResp.StatusMessage == "generic_error" {
		statusCode = 404
		respStatus = netzme.GetStatusResponse("404", "00", "08", "Invalid Merchant")
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return respStatus, statusCode, fmt.Errorf("Invalid Merchant")
	} else if netzmeResp.Status == 201 || netzmeResp.StatusMessage == "not_allow_retry" {
		statusCode = 403
		respStatus = netzme.GetStatusResponse("403", "00", "04", "Activity Count Limit Exceeded. wait "+strconv.Itoa(netzmeResp.Body.TimeLeftInMillis)+" millisecond.")
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return respStatus, statusCode, fmt.Errorf("Activity Count Limit Exceeded. wait " + strconv.Itoa(netzmeResp.Body.TimeLeftInMillis) + " millisecond.")
	} else if netzmeResp.Status == 202 || netzmeResp.StatusMessage == "existing_pin_not_found" {
		statusCode = 404
		respStatus = netzme.GetStatusResponse("404", "00", "25", "Existing Pin not found.")
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return respStatus, statusCode, nil
	} else {
		statusCode = netzmeResp.Status
		respStatus = netzme.GetStatusResponse(strconv.Itoa(statusCode), "00", "00", netzmeResp.StatusMessage)
	}
	addInfo := domain.SnapForgotPinResponse{
		PartnerReferenceNo: snapPinReq.PartnerReferenceNo,
		AdditionalInfo:     netzmeResp.Body,
	}

	finalResponse := struct {
		*domainSnap.SnapStatus
		*domain.SnapForgotPinResponse
	}{respStatus, &addInfo}
	batmanRespByte, _ := json.Marshal(finalResponse)

	if err != nil {
		respStatus = netzme.GetStatusResponse("500", "00", "00", "Can't insert history request to db")
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return respStatus, statusCode, err
	}

	logrus.Infoln(fmt.Sprintf("REQUEST ID: %s , RESPONSE FROM BATMAN = %s", ctx.APIReqID, string(batmanRespByte)))
	return finalResponse, statusCode, nil
}

func (s service) GetMerchantDetail(ctx *app.Context, snapReq domain.SnapMerchantRequest, xTimeStamp, xPartnerId, xExternalId, channelId string) (interface{}, int, error) {
	var netzmeRes domain.NetzmeMerchantDetailResponse
	serviceCode := "08"
	timeParse, _ := time.Parse(time.RFC3339, xTimeStamp)
	timeMiliString := strconv.FormatInt(timeParse.UnixMilli(), 10)

	accessToken, errCheck := s.redisClient.Get(ctx, os.Getenv("CLIENT_ID_NETZME")+"-batman")
	if errCheck != nil {
		// 1. get access token to authentication netzme
		accessTokenReq, statusCode, response, err := s.authService.GetAccessToken(ctx)
		if statusCode != http.StatusOK || err != nil {
			logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, strconv.Itoa(statusCode)+"0800", "Access Token Error"))
			return response, statusCode, errCheck
		}
		accessToken = accessTokenReq.AccessToken

		expiryToken := time.Unix(0, int64(accessTokenReq.ExpiryToken)*int64(time.Millisecond))
		expiryDuration := expiryToken.Sub(time.Now().Add(2 * time.Minute))

		_, errCheck := s.redisClient.SetWithExpire(ctx, os.Getenv("CLIENT_ID_NETZME")+"-batman", accessToken, expiryDuration)
		if errCheck != nil {
			respStatus := netzme.GetStatusResponse("400", serviceCode, "00", "Redis Client Error")
			logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, strconv.Itoa(http.StatusBadRequest)+"0800", "Redis Client Error"))
			return respStatus, http.StatusBadRequest, errCheck
		}
	}

	auth := "Bearer " + accessToken

	phoneNo := snapReq.AdditionalInfo.PhoneNo
	if phoneNo == "" {
		respStatus := netzme.GetStatusResponse("400", serviceCode, "02", "Missing Mandatory Field phoneNo")
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return respStatus, 400, fmt.Errorf("Missing Mandatory Field phoneNo")
	}
	bodyJsonString := ""

	netzmeUrl := "/api/aggregator/merchant/qr/merchant_detail?phoneNo=" + phoneNo

	// plain = stringToSign
	plain := netzme.BuildSignature(netzmeUrl, "GET", auth, bodyJsonString, timeMiliString)
	key := netzme.BuildKey(auth, timeMiliString)
	sign := signhelper.SignHMAC256(key, plain)
	resp, statusCode, err := s.SendGetMerchantDetail(ctx, auth, sign, timeMiliString, phoneNo, xPartnerId, xExternalId, channelId, netzmeUrl, "GET", bodyJsonString)
	if err != nil {
		if statusCode == 401 {
			response := netzme.GetStatusResponse("401", serviceCode, "00", "")
			logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, response.ResponseCode, response.ResponseMessage))
			return response, http.StatusUnauthorized, fmt.Errorf("")
		}
		respStatus := netzme.GetStatusResponse(strconv.Itoa(statusCode), serviceCode, "00", err.Error())
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return respStatus, statusCode, err
	}

	if statusCode != 200 {
		if statusCode == 401 {
			response := netzme.GetStatusResponse("401", serviceCode, "00", "")
			logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, response.ResponseCode, response.ResponseMessage))
			return response, http.StatusUnauthorized, fmt.Errorf("")
		}
		response := netzme.GetStatusResponse(strconv.Itoa(statusCode), serviceCode, "00", resp)
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, response.ResponseCode, response.ResponseMessage))
		return response, statusCode, fmt.Errorf("error")
	}
	respByte, err := json.Marshal(resp)
	logrus.Infoln(fmt.Sprintf("REQUEST ID: %s , RESPONSE FROM TOKO-NETZME = %s", ctx.APIReqID, string(respByte)))
	err = json.Unmarshal(respByte, &netzmeRes)

	if err != nil {
		logrus.Infoln(err)
		respStatus := netzme.GetStatusResponse(strconv.Itoa(statusCode), serviceCode, "00", err.Error())
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return respStatus, statusCode, fmt.Errorf(err.Error())
	}

	if netzmeRes.Status != 100 {
		if netzmeRes.Status == 404 {
			respStatus := netzme.GetStatusResponse("403", serviceCode, "18", "Account Inactive")
			logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
			return respStatus, netzmeRes.Status, fmt.Errorf("Account Inactive")
		}
		respStatus := netzme.GetStatusResponse(strconv.Itoa(netzmeRes.Status), serviceCode, "00", netzmeRes.StatusMessage)
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return respStatus, netzmeRes.Status, fmt.Errorf(netzmeRes.StatusMessage)
	}
	respStatus := netzme.GetStatusResponse(strconv.Itoa(statusCode), serviceCode, "00", "Successful")

	snapRes := &domain.SnapMerchantDetailResponse{
		PartnerReferenceNo: snapReq.PartnerReferenceNo,
		ReferenceNo:        netzmeRes.RequestId,
		AccountName:        netzmeRes.Body.MerchantName,
		AccountNo:          netzmeRes.Body.PhoneNo,
		AdditionalInfo: struct {
			CustIdMerchant string "json:\"custIdMerchant\""
			ClientId       string "json:\"clientId\""
			QrStatic       string "json:\"qrStatic\""
		}{CustIdMerchant: netzmeRes.Body.UserId,
			ClientId: netzmeRes.Body.AggregatorId,
			QrStatic: netzmeRes.Body.QrStatic},
	}

	finalResponse := struct {
		*domainSnap.SnapStatus
		*domain.SnapMerchantDetailResponse
	}{respStatus, snapRes}
	batmanRespByte, _ := json.Marshal(finalResponse)

	if err != nil {
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, "5000800", "Can't insert history request to db"))
		respStatus = netzme.GetStatusResponse("500", serviceCode, "00", "Can't insert history request to db")
		return respStatus, statusCode, err
	}

	logrus.Infoln(fmt.Sprintf("REQUEST ID: %s , RESPONSE FROM BATMAN = %s", ctx.APIReqID, string(batmanRespByte)))
	return finalResponse, statusCode, nil
}

func (s service) DeductDepositSplitFee(ctx *app.Context, snapReq domain.SnapDeductDepositSplitFeeRequest, xTimeStamp, xPartnerId, xExternalId, channelId string) (interface{}, int, error) {
	timeParse, _ := time.Parse(time.RFC3339, xTimeStamp)
	timeMiliString := strconv.FormatInt(timeParse.UnixMilli(), 10)

	accessToken, errCheck := s.redisClient.Get(ctx, os.Getenv("CLIENT_ID_NETZME")+"-batman")
	if errCheck != nil {
		// 1. get access token to authentication netzme
		accessTokenReq, statusCode, response, err := s.authService.GetAccessToken(ctx)
		if statusCode != http.StatusOK || err != nil {
			logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, strconv.Itoa(statusCode)+"0000", "Access Token Error"))
			return response, statusCode, errCheck
		}
		accessToken = accessTokenReq.AccessToken

		expiryToken := time.Unix(0, int64(accessTokenReq.ExpiryToken)*int64(time.Millisecond))
		expiryDuration := expiryToken.Sub(time.Now().Add(2 * time.Minute))

		_, errCheck := s.redisClient.SetWithExpire(ctx, os.Getenv("CLIENT_ID_NETZME")+"-batman", accessToken, expiryDuration)
		if errCheck != nil {
			respStatus := netzme.GetStatusResponse("400", "00", "00", "Redis Client Error")
			logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, strconv.Itoa(http.StatusBadRequest)+"0000", "Redis Client Error"))
			return respStatus, http.StatusBadRequest, errCheck
		}
	}

	auth := "Bearer " + accessToken

	if snapReq.AdditionalInfo.Type != "payment_notification_to_split_fee" {
		respStatus := netzme.GetStatusResponse("400", "00", "01", "Invalid Field Format type")
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return respStatus, http.StatusBadRequest, fmt.Errorf("Invalid Field Format type")
	}

	if snapReq.AdditionalInfo.PaymentStatus == "SUCCESS" {
		snapReq.AdditionalInfo.PaymentStatus = "paid"
	}

	//Validate Currency
	currencyCheck := strings.Split(os.Getenv("ALLOWED_CURRENCY"), ",")
	currencyPass := false
	currencyFeePass := false
	for _, currency := range currencyCheck {
		if snapReq.Amount.Currency == currency {
			currencyPass = true
		}
	}
	for _, currency := range currencyCheck {
		if snapReq.FeeAmount.Currency == currency {
			currencyFeePass = true
		}
	}
	if !currencyPass || !currencyFeePass {
		respStatus := netzme.GetStatusResponse("404", "00", "24", "Invalid Currency.")
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return respStatus, http.StatusNotFound, nil
	}

	netzmeReq := domain.NetzmeDeductDepositSplitFeeRequest{
		RequestId: snapReq.ReferenceNo,
		Type:      snapReq.AdditionalInfo.Type,
		Body: struct {
			MerchantId    string `json:"merchantId"`
			TransactionId string `json:"transactionId"`
			Sku           string `json:"sku"`
			ProductName   string `json:"productName"`
			PaymentStatus string `json:"paymentStatus"`
			PaymentMethod string `json:"paymentMethod"`
			BankName      string `json:"bankName"`
			PaidAmount    string `json:"paidAmount"`
			MdrFeeAmount  string `json:"mdrFeeAmount"`
			Additionals   struct {
				Qty  string `json:"qty"`
				Desc string `json:"desc"`
			} `json:"additionals"`
		}{
			MerchantId:    snapReq.AdditionalInfo.CustIdMerchant,
			TransactionId: snapReq.PartnerReferenceNo,
			Sku:           snapReq.AdditionalInfo.Sku,
			ProductName:   snapReq.AdditionalInfo.ProductName,
			PaymentStatus: snapReq.AdditionalInfo.PaymentStatus,
			PaymentMethod: snapReq.AdditionalInfo.PayMethod,
			BankName:      snapReq.AdditionalInfo.BankName,
			PaidAmount:    snapReq.Amount.Currency + " " + snapReq.Amount.Value,
			MdrFeeAmount:  snapReq.FeeAmount.Currency + " " + snapReq.FeeAmount.Value,
			Additionals: struct {
				Qty  string `json:"qty"`
				Desc string `json:"desc"`
			}{
				Qty:  snapReq.AdditionalInfo.Qty,
				Desc: snapReq.AdditionalInfo.Desc,
			},
		},
	}

	bodyJson, err := json.Marshal(&netzmeReq)
	if err != nil {
		respStatus := netzme.GetStatusResponse("400", "00", "01", "can not read body")
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return respStatus, http.StatusBadRequest, err
	}
	bodyJsonString := string(bodyJson)
	netzmeUrl := "/api/aggregator/merchant/payment/notif"
	// plain = stringToSign
	plain := netzme.BuildSignature(netzmeUrl, ctx.Request.Method, auth, bodyJsonString, timeMiliString)
	key := netzme.BuildKey(auth, timeMiliString)
	sign := signhelper.SignHMAC256(key, plain)

	var netzmeRes domain.NetzmeDeductDepositSplitFeeResponse

	resp, statusCode, err := s.SendDeductDepositSplitFee(ctx, auth, sign, timeMiliString, bodyJsonString, xPartnerId, xExternalId, channelId, netzmeUrl, ctx.Request.Method)
	if err != nil {
		respStatus := netzme.GetStatusResponse(strconv.Itoa(statusCode), "00", "00", err.Error())
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return respStatus, statusCode, err
	}
	respByte, err := json.Marshal(resp)
	logrus.Infoln(fmt.Sprintf("REQUEST ID: %s , RESPONSE FROM TOKO-NETZME = %s", ctx.APIReqID, string(respByte)))
	err = json.Unmarshal(respByte, &netzmeRes)

	if err != nil {
		logrus.Infoln(err)
		respStatus := netzme.GetStatusResponse(strconv.Itoa(statusCode), "00", "00", err.Error())
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return respStatus, statusCode, fmt.Errorf(err.Error())
	}
	if statusCode != 200 {
		if statusCode == 404 {
			response := netzme.GetStatusResponse("404", "00", "00", "resource not found")
			logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, response.ResponseCode, response.ResponseMessage))
			return response, http.StatusNotFound, fmt.Errorf("resource not found")
		} else if statusCode == 401 {
			response := netzme.GetStatusResponse("401", "00", "00", "")
			logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, response.ResponseCode, response.ResponseMessage))
			return response, http.StatusUnauthorized, fmt.Errorf("")
		}
		response := netzme.GetStatusResponse(strconv.Itoa(statusCode), "00", "00", resp)
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, response.ResponseCode, response.ResponseMessage))
		return response, statusCode, fmt.Errorf("error")
	}
	var respStatus *domainSnap.SnapStatus
	if netzmeRes.Status >= 100 && netzmeRes.Status <= 199 {
		statusCode = 200
		respStatus = netzme.GetStatusResponse(strconv.Itoa(statusCode), "00", "00", netzmeRes.StatusMessage)
	} else if netzmeRes.Status == 301 && netzmeRes.StatusMessage == "transaction_already_exist" {
		statusCode = 409
		respStatus = netzme.GetStatusResponse(strconv.Itoa(statusCode), "00", "01", "Duplicate partnerReferenceNo")
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return respStatus, statusCode, nil
	} else if netzmeRes.Status == 302 && netzmeRes.StatusMessage == "invalid_merchant" {
		statusCode = 404
		respStatus = netzme.GetStatusResponse(strconv.Itoa(statusCode), "00", "08", "Invalid Merchant")
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return respStatus, statusCode, nil
	} else if netzmeRes.Status == 303 && netzmeRes.StatusMessage == "not_enough_balance" {
		statusCode = 403
		respStatus = netzme.GetStatusResponse(strconv.Itoa(statusCode), "00", "14", "Insufficient Funds")
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, respStatus.ResponseCode, respStatus.ResponseMessage))
		return respStatus, statusCode, nil
	} else {
		statusCode = netzmeRes.Status
		respStatus = netzme.GetStatusResponse(strconv.Itoa(statusCode), "00", "00", netzmeRes.StatusMessage)
	}

	snapRes := &domain.SnapDeductDepositSplitFeeResponse{
		PartnerReferenceNo: netzmeRes.Body.TransactionId,
		ReferenceNo:        netzmeRes.RequestId,
		AdditionalInfo: struct {
			Type string "json:\"type\""
		}{Type: netzmeRes.Type},
	}

	finalResponse := struct {
		*domainSnap.SnapStatus
		*domain.SnapDeductDepositSplitFeeResponse
	}{respStatus, snapRes}
	batmanRespByte, _ := json.Marshal(finalResponse)

	if err != nil {
		logrus.Errorln(fmt.Sprintf("REQUEST ID: %s , response_code: %s , response_message: %s", ctx.APIReqID, "5000000", "Can't insert history request to db"))
		respStatus = netzme.GetStatusResponse("500", "00", "00", "Can't insert history request to db")
		return respStatus, statusCode, err
	}

	logrus.Infoln(fmt.Sprintf("REQUEST ID: %s , RESPONSE FROM BATMAN = %s", ctx.APIReqID, string(batmanRespByte)))
	return finalResponse, statusCode, nil
}

func (s service) SendCreatePin(ctx *app.Context, auth, signature, timestamp, payloadJson, xPartnerId, xExternalId, channelId, sourceUrl, method string) (interface{}, int, error) {
	var response interface{}

	urlPath := os.Getenv("BASEURL_NETZME") + "/api/aggregator/merchant/pin/create_pin"
	params := map[string]string{"Authorization": auth,
		"X-PARTNER-ID":  xPartnerId,
		"X-EXTERNAL-ID": xExternalId,
		"CHANNEL-ID":    channelId,
		"Client-Id":     os.Getenv("CLIENT_ID_NETZME"),
		"Signature":     signature,
		"Request-Time":  timestamp,
		"Content-Type":  "application/json"}

	statusCode, err := s.httpClient.PostJSONWithRetryCond(ctx, urlPath, payloadJson, params, &response, sourceUrl, method)
	if err != nil {
		return response, statusCode, err
	}

	return response, statusCode, nil
}

func (s service) SendForgotPin(ctx *app.Context, auth, signature, timestamp, payloadJson, xPartnerId, xExternalId, channelId, sourceUrl, method string) (interface{}, int, error) {
	var response interface{}

	urlPath := os.Getenv("BASEURL_NETZME") + "/api/aggregator/merchant/pin/forgot_pin"
	params := map[string]string{"Authorization": auth,
		"X-PARTNER-ID":  xPartnerId,
		"X-EXTERNAL-ID": xExternalId,
		"CHANNEL-ID":    channelId,
		"Client-Id":     os.Getenv("CLIENT_ID_NETZME"),
		"Signature":     signature,
		"Request-Time":  timestamp,
		"Content-Type":  "application/json"}

	statusCode, err := s.httpClient.PostJSONWithRetryCond(ctx, urlPath, payloadJson, params, &response, sourceUrl, method)
	if err != nil {
		return response, statusCode, err
	}

	return response, statusCode, nil
}

func (s service) SendGetMerchantDetail(ctx *app.Context, auth, signature, timestamp, phoneNo, xPartnerId, xExternalId, channelId, sourceUrl, method, bodyJson string) (interface{}, int, error) {
	var response interface{}

	urlPath := os.Getenv("BASEURL_NETZME") + "/api/aggregator/merchant/qr/merchant_detail?phoneNo=" + phoneNo
	params := map[string]string{"Authorization": auth,
		"X-PARTNER-ID":  xPartnerId,
		"X-EXTERNAL-ID": xExternalId,
		"CHANNEL-ID":    channelId,
		"Client-Id":     os.Getenv("CLIENT_ID_NETZME"),
		"Signature":     signature,
		"Request-Time":  timestamp,
		"Content-Type":  "application/json"}

	statusCode, err := s.httpClient.GetWithRetryCond(ctx, urlPath, params, &response, sourceUrl, method, bodyJson)
	if err != nil {
		return response, statusCode, err
	}
	return response, statusCode, nil
}

func (s service) SendDeductDepositSplitFee(ctx *app.Context, auth, signature, timestamp, payloadJson, xPartnerId, xExternalId, channelId, sourceUrl, method string) (interface{}, int, error) {
	var response interface{}

	urlPath := os.Getenv("BASEURL_NETZME") + "/api/aggregator/merchant/payment/notif"
	params := map[string]string{"Authorization": auth,
		"X-PARTNER-ID":  xPartnerId,
		"X-EXTERNAL-ID": xExternalId,
		"CHANNEL-ID":    channelId,
		"Client-Id":     os.Getenv("CLIENT_ID_NETZME"),
		"Signature":     signature,
		"Request-Time":  timestamp,
		"Content-Type":  "application/json"}

	statusCode, err := s.httpClient.PostJSONWithRetryCond(ctx, urlPath, payloadJson, params, &response, sourceUrl, method)
	if err != nil {
		return response, statusCode, err
	}

	return response, statusCode, nil
}
