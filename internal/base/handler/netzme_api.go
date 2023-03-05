package handler

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"

	"moodle-api/internal/base/app"
	"moodle-api/internal/base/domain"
)

func (b *BaseHTTPHandler) GetAccessToken(ctx *app.Context) (*domain.AccessTokenResponse, int, *interface{}, error) {
	var response interface{}
	var atr domain.AccessTokenResponse
	statusCode := http.StatusBadRequest

	credential := os.Getenv("CLIENT_ID_NETZME") + ":" + os.Getenv("CLIENT_SECRET_NETZME")
	authorizationString := "Basic " + base64.StdEncoding.EncodeToString([]byte(credential))

	urlPath := os.Getenv("BASEURL_NETZME") + "/oauth/merchant/accesstoken"
	params := map[string]string{"Authorization": authorizationString}

	payloadJsonRequest := `{"grant_type": "client_credentials"}`

	statusCode, err := b.HttpClient.PostJSON(ctx, urlPath, payloadJsonRequest, params, &response)

	if err != nil {
		return &atr, statusCode, &response, err
	}

	respByte, err := json.Marshal(response)
	if err != nil {
		return &atr, statusCode, &response, err
	}

	err = json.Unmarshal(respByte, &atr)
	if err != nil {
		return &atr, statusCode, &response, err
	}

	// catch weird response unauthorized
	if atr.Status == "UNAUTHORIZED" {
		statusCode = http.StatusUnauthorized
		return &atr, statusCode, &response, err
	}

	return &atr, statusCode, &response, err
}

func (b *BaseHTTPHandler) ForgotPin(ctx *app.Context, auth, signature, timestamp, payloadJson, xPartnerId, xExternalId, channelId, sourceUrl, method string) (interface{}, int, error) {
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

	statusCode, err := b.HttpClient.PostJSONWithRetryCond(ctx, urlPath, payloadJson, params, &response, sourceUrl, method)
	if err != nil {
		return response, statusCode, err
	}

	return response, statusCode, nil
}

func (b *BaseHTTPHandler) CreatePin(ctx *app.Context, auth, signature, timestamp, payloadJson, xPartnerId, xExternalId, channelId, sourceUrl, method string) (interface{}, int, error) {
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

	statusCode, err := b.HttpClient.PostJSONWithRetryCond(ctx, urlPath, payloadJson, params, &response, sourceUrl, method)
	if err != nil {
		return response, statusCode, err
	}

	return response, statusCode, nil
}

func (b *BaseHTTPHandler) DeductDepositSplitFee(ctx *app.Context, auth, signature, timestamp, payloadJson, xPartnerId, xExternalId, channelId, sourceUrl, method string) (interface{}, int, error) {
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

	statusCode, err := b.HttpClient.PostJSONWithRetryCond(ctx, urlPath, payloadJson, params, &response, sourceUrl, method)
	if err != nil {
		return response, statusCode, err
	}

	return response, statusCode, nil
}

func (b *BaseHTTPHandler) PostWithdraw(ctx *app.Context, auth, signature, timestamp, payloadJson, xPartnerId, xExternalId, channelId, sourceUrl, method string) (interface{}, int, error) {
	var response interface{}

	urlPath := os.Getenv("BASEURL_NETZME") + "/api/aggregator/merchant/qr/withdraw"
	params := map[string]string{"Authorization": auth,
		"X-PARTNER-ID":  xPartnerId,
		"X-EXTERNAL-ID": xExternalId,
		"CHANNEL-ID":    channelId,
		"Client-Id":     os.Getenv("CLIENT_ID_NETZME"),
		"Signature":     signature,
		"Request-Time":  timestamp,
		"Content-Type":  "application/json"}

	statusCode, err := b.HttpClient.PostJSONWithRetryCond(ctx, urlPath, payloadJson, params, &response, sourceUrl, method)
	if err != nil {
		return response, statusCode, err
	}

	return response, statusCode, nil
}

func (b *BaseHTTPHandler) PostCreateInvoiceTransaction(ctx *app.Context, auth, signature, timestamp, payloadJson, merchant, xPartnerId, xExternalId, channelId string) (interface{}, int, error) {
	var response interface{}

	urlPath := "https://pay-stg.netzme.com" + "/api/v1/invoice/createTransaction"
	params := map[string]string{
		"Authorization": auth,
		"User-Agent":    xPartnerId + ";" + merchant,
		"X-PARTNER-ID":  xPartnerId,
		"X-EXTERNAL-ID": xExternalId,
		"CHANNEL-ID":    channelId,
		"Content-Type":  "application/json"}

	statusCode, err := b.HttpClient.PostJSON(ctx, urlPath, payloadJson, params, &response)
	if err != nil {
		return response, statusCode, err
	}

	return response, statusCode, nil
}

func (b *BaseHTTPHandler) PostWithdrawInquiry(ctx *app.Context, auth, signature, timestamp, payloadJson, xPartnerId, xExternalId, channelId, sourceUrl, method string) (interface{}, int, error) {
	var response interface{}

	urlPath := os.Getenv("BASEURL_NETZME") + "/api/aggregator/merchant/qr/withdraw/inquiry"
	params := map[string]string{"Authorization": auth,
		"X-PARTNER-ID":  xPartnerId,
		"X-EXTERNAL-ID": xExternalId,
		"CHANNEL-ID":    channelId,
		"Client-Id":     os.Getenv("CLIENT_ID_NETZME"),
		"Signature":     signature,
		"Request-Time":  timestamp,
		"Content-Type":  "application/json"}

	statusCode, err := b.HttpClient.PostJSONWithRetryCond(ctx, urlPath, payloadJson, params, &response, sourceUrl, method)
	if err != nil {
		return response, statusCode, err
	}

	return response, statusCode, nil
}

func (b *BaseHTTPHandler) GetMerchantDetail(ctx *app.Context, auth, signature, timestamp, phoneNo, xPartnerId, xExternalId, channelId, sourceUrl, method, bodyJson string) (interface{}, int, error) {
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

	statusCode, err := b.HttpClient.GetWithRetryCond(ctx, urlPath, params, &response, sourceUrl, method, bodyJson)
	if err != nil {
		return response, statusCode, err
	}
	return response, statusCode, nil
}

func (b *BaseHTTPHandler) GetDetailBalance(ctx *app.Context, auth, signature, timestamp, userId, xPartnerId, xExternalId, channelId, sourceUrl, method, bodyJsonString string) (interface{}, int, error) {
	var response interface{}

	urlPath := os.Getenv("BASEURL_NETZME") + "/api/aggregator/merchant/qr/balance/detail?userId=" + userId
	params := map[string]string{"Authorization": auth,
		"X-PARTNER-ID":  xPartnerId,
		"X-EXTERNAL-ID": xExternalId,
		"CHANNEL-ID":    channelId,
		"Client-Id":     os.Getenv("CLIENT_ID_NETZME"),
		"Signature":     signature,
		"Request-Time":  timestamp,
		"Content-Type":  "application/json"}

	statusCode, err := b.HttpClient.GetWithRetryCond(ctx, urlPath, params, &response, sourceUrl, method, bodyJsonString)
	if err != nil {
		return response, statusCode, err
	}
	return response, statusCode, nil
}

func (b *BaseHTTPHandler) GetTransactionList(ctx *app.Context, auth, signature, timestamp, page, userId, startDate, endDate, xPartnerId, xExternalId, channelId, sourceUrl, method, bodyJsonString string) (interface{}, int, error) {
	var response interface{}

	urlPath := os.Getenv("BASEURL_NETZME") + "/api/aggregator/merchant/qr/transaction/list?" +
		"page=" + page +
		"&userId=" + userId +
		"&startdate=" + startDate +
		"&enddate=" + endDate
	params := map[string]string{"Authorization": auth,
		"X-PARTNER-ID":  xPartnerId,
		"X-EXTERNAL-ID": xExternalId,
		"CHANNEL-ID":    channelId,
		"Client-Id":     os.Getenv("CLIENT_ID_NETZME"),
		"Signature":     signature,
		"Request-Time":  timestamp,
		"Content-Type":  "application/json"}

	statusCode, err := b.HttpClient.GetWithRetryCond(ctx, urlPath, params, &response, sourceUrl, method, bodyJsonString)
	if err != nil {
		return response, statusCode, err
	}
	return response, statusCode, nil
}

func (b *BaseHTTPHandler) CreateInvoice(ctx *app.Context, auth, payloadJson, merchantId, xPartnerId, xExternalId, channelId string) (interface{}, int, error) {
	var response interface{}

	urlPath := os.Getenv("BASEURL_PAY_NETZME") + "/api/v1/invoice/create"
	params := map[string]string{
		"Authorization": auth,
		"User-Agent":    xPartnerId + ";" + merchantId,
		"X-PARTNER-ID":  xPartnerId,
		"X-EXTERNAL-ID": xExternalId,
		"CHANNEL-ID":    channelId,
		//"Client-Id":    os.Getenv("CLIENT_ID_NETZME"),
		//"Signature":    signature,
		//"Request-Time": timestamp,
		"Content-Type": "application/json"}

	statusCode, err := b.HttpClient.PostJSON(ctx, urlPath, payloadJson, params, &response)
	if err != nil {
		return response, statusCode, err
	}

	return response, statusCode, nil
}

func (b *BaseHTTPHandler) GetInvoiceTransaction(ctx *app.Context, auth, signature, timestamp, invoiceTransactionId, xPartnerId, xExternalId, channelId, sourceUrl, method, bodyJsonString string) (interface{}, int, error) {
	var response interface{}

	urlPath := os.Getenv("BASEURL_NETZME") + "/api/aggregator/merchant/invoice/transaction/" + invoiceTransactionId
	params := map[string]string{"Authorization": auth,
		"X-PARTNER-ID":  xPartnerId,
		"X-EXTERNAL-ID": xExternalId,
		"CHANNEL-ID":    channelId,
		"Client-Id":     os.Getenv("CLIENT_ID_NETZME"),
		"Signature":     signature,
		"Request-Time":  timestamp,
		"Content-Type":  "application/json"}

	statusCode, err := b.HttpClient.GetWithRetryCond(ctx, urlPath, params, &response, sourceUrl, method, bodyJsonString)
	if err != nil {
		return response, statusCode, err
	}
	return response, statusCode, nil
}

func (b *BaseHTTPHandler) GetQrisAcquireTransaction(ctx *app.Context, auth, signature, timestamp, rrn, xPartnerId, xExternalId, channelId, sourceUrl, method, bodyJsonString string) (interface{}, int, error) {
	var response interface{}

	urlPath := os.Getenv("BASEURL_NETZME") + "/api/aggregator/merchant/qris/acquire/transaction/" + rrn
	params := map[string]string{"Authorization": auth,
		"X-PARTNER-ID":  xPartnerId,
		"X-EXTERNAL-ID": xExternalId,
		"CHANNEL-ID":    channelId,
		"Client-Id":     os.Getenv("CLIENT_ID_NETZME"),
		"Signature":     signature,
		"Request-Time":  timestamp,
		"Content-Type":  "application/json"}

	statusCode, err := b.HttpClient.GetWithRetryCond(ctx, urlPath, params, &response, sourceUrl, method, bodyJsonString)
	if err != nil {
		return response, statusCode, err
	}
	return response, statusCode, nil
}

func (b *BaseHTTPHandler) GetDepositTransactionList(ctx *app.Context, auth, signature, timestamp, page, userId, startDate, endDate, xPartnerId, xExternalId, channelId, sourceUrl, method, bodyJsonString string) (interface{}, int, error) {
	var response interface{}

	urlPath := os.Getenv("BASEURL_NETZME") + "/api/aggregator/merchant/deposit/transaction/list?" +
		"userId=" + userId +
		"&startdate=" + startDate +
		"&enddate=" + endDate +
		"&page=" + page
	params := map[string]string{"Authorization": auth,
		"X-PARTNER-ID":  xPartnerId,
		"X-EXTERNAL-ID": xExternalId,
		"CHANNEL-ID":    channelId,
		"Client-Id":     os.Getenv("CLIENT_ID_NETZME"),
		"Signature":     signature,
		"Request-Time":  timestamp,
		"Content-Type":  "application/json"}

	statusCode, err := b.HttpClient.GetWithRetryCond(ctx, urlPath, params, &response, sourceUrl, method, bodyJsonString)
	if err != nil {
		return response, statusCode, err
	}

	return response, statusCode, nil
}

func (b *BaseHTTPHandler) PostWithdrawDeposit(ctx *app.Context, auth, signature, timestamp, payloadJson, xPartnerId, xExternalId, channelId, sourceUrl, method string) (interface{}, int, error) {
	var response interface{}

	urlPath := os.Getenv("BASEURL_NETZME") + "/api/aggregator/merchant/deposit/withdraw"
	params := map[string]string{"Authorization": auth,
		"X-PARTNER-ID":  xPartnerId,
		"X-EXTERNAL-ID": xExternalId,
		"CHANNEL-ID":    channelId,
		"Client-Id":     os.Getenv("CLIENT_ID_NETZME"),
		"Signature":     signature,
		"Request-Time":  timestamp,
		"Content-Type":  "application/json"}

	statusCode, err := b.HttpClient.PostJSONWithRetryCond(ctx, urlPath, payloadJson, params, &response, sourceUrl, method)
	if err != nil {
		return response, statusCode, err
	}

	return response, statusCode, nil
}

func (b *BaseHTTPHandler) GetDepositBalance(ctx *app.Context, auth, signature, timestamp, merchantId, xPartnerId, xExternalId, channelId, sourceUrl, method, bodyJsonString string) (interface{}, int, error) {
	var response interface{}

	urlPath := os.Getenv("BASEURL_NETZME") + "/api/aggregator/merchant/institution/balance/" + merchantId
	params := map[string]string{"Authorization": auth,
		"X-PARTNER-ID":  xPartnerId,
		"X-EXTERNAL-ID": xExternalId,
		"CHANNEL-ID":    channelId,
		"Client-Id":     os.Getenv("CLIENT_ID_NETZME"),
		"Signature":     signature,
		"Request-Time":  timestamp,
		"Content-Type":  "application/json"}

	statusCode, err := b.HttpClient.GetWithRetryCond(ctx, urlPath, params, &response, sourceUrl, method, bodyJsonString)
	if err != nil {
		return response, statusCode, err
	}
	return response, statusCode, nil
}

func (b *BaseHTTPHandler) DepositWithdraw(ctx *app.Context, auth, signature, timestamp, payloadJson, xPartnerId, xExternalId, channelId string) (interface{}, int, error) {
	var response interface{}

	urlPath := os.Getenv("BASEURL_NETZME") + "/api/aggregator/merchant/deposit/withdraw"
	params := map[string]string{"Authorization": auth,
		"X-PARTNER-ID":  xPartnerId,
		"X-EXTERNAL-ID": xExternalId,
		"CHANNEL-ID":    channelId,
		"Client-Id":     os.Getenv("CLIENT_ID_NETZME"),
		"Signature":     signature,
		"Request-Time":  timestamp,
		"Content-Type":  "application/json"}

	statusCode, err := b.HttpClient.PostJSON(ctx, urlPath, payloadJson, params, &response)
	if err != nil {
		return response, statusCode, err
	}

	return response, statusCode, nil
}

func (b *BaseHTTPHandler) GetInquiryDepositWithdraw(ctx *app.Context, auth, signature, timestamp, userId, xPartnerId, xExternalId, channelId, sourceUrl, method, bodyJsonString string) (interface{}, int, error) {
	var response interface{}

	urlPath := os.Getenv("BASEURL_NETZME") + "/api/aggregator/merchant/deposit/withdraw/inquiry?userId=" + userId
	params := map[string]string{"Authorization": auth,
		"X-PARTNER-ID":  xPartnerId,
		"X-EXTERNAL-ID": xExternalId,
		"CHANNEL-ID":    channelId,
		"Client-Id":     os.Getenv("CLIENT_ID_NETZME"),
		"Signature":     signature,
		"Request-Time":  timestamp,
		"Content-Type":  "application/json"}

	statusCode, err := b.HttpClient.GetWithRetryCond(ctx, urlPath, params, &response, sourceUrl, method, bodyJsonString)
	if err != nil {
		return response, statusCode, err
	}
	return response, statusCode, nil
}

func (b *BaseHTTPHandler) GetWithdrawDetail(ctx *app.Context, auth, signature, timestamp, requestId, xPartnerId, xExternalId, channelId, sourceUrl, method, bodyJsonString string) (interface{}, int, error) {
	var response interface{}

	urlPath := os.Getenv("BASEURL_NETZME") + "/api/aggregator/merchant/withdraw/" + requestId
	params := map[string]string{"Authorization": auth,
		"X-PARTNER-ID":  xPartnerId,
		"X-EXTERNAL-ID": xExternalId,
		"CHANNEL-ID":    channelId,
		"Client-Id":     os.Getenv("CLIENT_ID_NETZME"),
		"Signature":     signature,
		"Request-Time":  timestamp,
		"Content-Type":  "application/json"}

	statusCode, err := b.HttpClient.GetWithRetryCond(ctx, urlPath, params, &response, sourceUrl, method, bodyJsonString)
	if err != nil {
		return response, statusCode, err
	}
	return response, statusCode, nil
}

func (b *BaseHTTPHandler) GetWithdrawDepositDetail(ctx *app.Context, auth, signature, timestamp, requestId, xPartnerId, xExternalId, channelId, sourceUrl, method, bodyJsonString string) (interface{}, int, error) {
	var response interface{}

	urlPath := os.Getenv("BASEURL_NETZME") + "/api/aggregator/merchant/withdraw/deposit/" + requestId
	params := map[string]string{"Authorization": auth,
		"X-PARTNER-ID":  xPartnerId,
		"X-EXTERNAL-ID": xExternalId,
		"CHANNEL-ID":    channelId,
		"Client-Id":     os.Getenv("CLIENT_ID_NETZME"),
		"Signature":     signature,
		"Request-Time":  timestamp,
		"Content-Type":  "application/json"}

	statusCode, err := b.HttpClient.GetWithRetryCond(ctx, urlPath, params, &response, sourceUrl, method, bodyJsonString)
	if err != nil {
		return response, statusCode, err
	}
	return response, statusCode, nil
}
