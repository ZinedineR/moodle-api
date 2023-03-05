package service

import (
	"moodle-api/internal/account/domain"
	"moodle-api/internal/base/app"
)

type Service interface {
	CreatePin(ctx *app.Context, body domain.SnapPinRequest, xTimeStamp, xPartnerId, xExternalId, channelId string) (interface{}, int, error)
	ForgotPin(ctx *app.Context, snapPinReq domain.SnapForgotPinRequest, xTimeStamp, xPartnerId, xExternalId, channelId string) (interface{}, int, error)
	GetMerchantDetail(ctx *app.Context, snapReq domain.SnapMerchantRequest, xTimeStamp, xPartnerId, xExternalId, channelId string) (interface{}, int, error)
	DeductDepositSplitFee(ctx *app.Context, snapReq domain.SnapDeductDepositSplitFeeRequest, xTimeStamp, xPartnerId, xExternalId, channelId string) (interface{}, int, error)
	SendCreatePin(ctx *app.Context, auth, signature, timestamp, payloadJson, xPartnerId, xExternalId, channelId, sourceUrl, method string) (interface{}, int, error)
	SendForgotPin(ctx *app.Context, auth, signature, timestamp, payloadJson, xPartnerId, xExternalId, channelId, sourceUrl, method string) (interface{}, int, error)
	SendGetMerchantDetail(ctx *app.Context, auth, signature, timestamp, phoneNo, xPartnerId, xExternalId, channelId, sourceUrl, method, bodyJson string) (interface{}, int, error)
	SendDeductDepositSplitFee(ctx *app.Context, auth, signature, timestamp, payloadJson, xPartnerId, xExternalId, channelId, sourceUrl, method string) (interface{}, int, error)
}
