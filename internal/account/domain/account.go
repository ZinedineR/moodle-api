package domain

type SnapPinRequest struct {
	CustIdMerchant     string `json:"custIdMerchant" binding:"required"`
	PartnerReferenceNo string `json:"partnerReferenceNo" binding:"required"`
	AdditionalInfo     *struct {
		Pin  string `json:"pin" binding:"required"`
		Type string `json:"type" binding:"required"`
	} `json:"additionalInfo" binding:"required"`
}

type CreatePinRequest struct {
	Body struct {
		Pin      string `json:"pin" binding:"required"`
		Username string `json:"username" binding:"required"`
	} `json:"body" binding:"required"`
	RequestId string `json:"requestId" binding:"required"`
	Type      string `json:"type" binding:"required"`
}

type SnapForgotPinRequest struct {
	CustIdMerchant     string `json:"custIdMerchant" binding:"required"`
	PartnerReferenceNo string `json:"partnerReferenceNo" binding:"required"`
	AdditionalInfo     *struct {
		Type string `json:"type" binding:"required"`
	} `json:"additionalInfo" binding:"required"`
}

type ForgotPinRequest struct {
	Body struct {
		Username string `json:"username" binding:"required"`
	} `json:"body" binding:"required"`
	RequestId string `json:"requestId" binding:"required"`
	Type      string `json:"type" binding:"required"`
}

type SnapCreatePinResponse struct {
	PartnerReferenceNo string `json:"partnerReferenceNo" binding:"required"`
}

type CreatePinResponse struct {
	Body struct {
		ErrorCode    string `json:"errorCode"`
		ErrorMessage string `json:"errorMessage"`
	} `json:"body"`
	RequestId     string `json:"requestId"`
	Status        string `json:"status"`
	StatusMessage string `json:"statusMessage"`
	Type          string `json:"type"`
}

type ForgotPinResponse struct {
	Body struct {
		TimeLeftInMillis int `json:"timeLeftInMillis"`
	} `json:"body"`
	RequestId     string `json:"requestId"`
	Status        int    `json:"status"`
	StatusMessage string `json:"statusMessage"`
	Type          string `json:"type"`
}
type SnapForgotPinResponse struct {
	PartnerReferenceNo string      `json:"partnerReferenceNo"`
	AdditionalInfo     interface{} `json:"additionalInfo"`
}

//type AccountUpgradeNotification struct {
//	UserId                     string   `json:"userId" binding:"required"`
//	Type                       string   `json:"type" binding:"required"`
//	IdentificationCardImageUrl string   `json:"identificationCardImageUrl" binding:"required"`
//	SelfieImageUrl             string   `json:"selfieImageUrl" binding:"required"`
//	Benefits                   []string `json:"benefits" binding:"required"`
//	Status                     string   `json:"status" binding:"required"`
//	CallbackUrl                string   `json:"callback_url" binding:"required"`
//}
//
//type AccountUpgradeResponse struct {
//	ResponseCode int    `json:"response_code"`
//	ResponseDesc string `json:"response_desc"`
//	ReceiptCode  string `json:"receipt_code"`
//}

type NetzmeGetBalanceResponse struct {
	RequestId     string `json:"requestId"`
	Status        int    `json:"status"`
	StatusMessage string `json:"statusMessage"`
	Body          struct {
		UserId         string `json:"userId"`
		TotalBalance   string `json:"totalBalance"`
		SettledBalance string `json:"settledBalance"`
	} `json:"body"`
}

type NetzmeMerchantDetailResponse struct {
	RequestId     string `json:"requestId"`
	Status        int    `json:"status"`
	StatusMessage string `json:"statusMessage"`
	Body          struct {
		UserId       string `json:"userId"`
		AggregatorId string `json:"aggregatorId"`
		PhoneNo      string `json:"phoneNo"`
		MerchantName string `json:"merchantName"`
		QrStatic     string `json:"qrStatic"`
	} `json:"body"`
}

type SnapMerchantRequest struct {
	PartnerReferenceNo string `json:"partnerReferenceNo" binding:"required"`
	AdditionalInfo     *struct {
		PhoneNo string `json:"phoneNo" binding:"required"`
	} `json:"additionalInfo" binding:"required"`
}

type SnapMerchantDetailResponse struct {
	PartnerReferenceNo string `json:"partnerReferenceNo"`
	ReferenceNo        string `json:"referenceNo"`
	AccountName        string `json:"accountName"`
	AccountNo          string `json:"accountNo"`
	AdditionalInfo     struct {
		CustIdMerchant string `json:"custIdMerchant"`
		ClientId       string `json:"clientId"`
		QrStatic       string `json:"qrStatic"`
	} `json:"additionalInfo"`
}

type NetzmeBody struct {
	RequestId string `json:"requestId"`
	Body      struct {
		UserId       string `json:"userId"`
		TotalBalance struct {
			Value    string `json:"value"`
			Currency string `json:"currency"`
		} `json:"totalBalance"`
		SettledBalance struct {
			Value    string `json:"value"`
			Currency string `json:"currency"`
		} `json:"settledBalance"`
	} `json:"body"`
}

type SnapDeductDepositSplitFeeResponse struct {
	PartnerReferenceNo string `json:"partnerReferenceNo"`
	ReferenceNo        string `json:"referenceNo"`
	AdditionalInfo     struct {
		Type string `json:"type"`
	} `json:"additionalInfo"`
}

type NetzmeDeductDepositSplitFeeResponse struct {
	Body struct {
		TransactionId string `json:"transactionId"`
	} `json:"body"`
	RequestId     string `json:"requestId"`
	Status        int    `json:"status"`
	StatusMessage string `json:"statusMessage"`
	Type          string `json:"type"`
}

type SnapDeductDepositSplitFeeRequest struct {
	ReferenceNo        string `json:"referenceNo" binding:"required"`
	PartnerReferenceNo string `json:"partnerReferenceNo" binding:"required"`
	Amount             *struct {
		Value    string `json:"value" binding:"required"`
		Currency string `json:"currency" binding:"required"`
	} `json:"amount" binding:"required"`
	FeeAmount *struct {
		Value    string `json:"value" binding:"required"`
		Currency string `json:"currency" binding:"required"`
	} `json:"feeAmount" binding:"required"`
	AdditionalInfo *struct {
		CustIdMerchant string `json:"custIdMerchant" binding:"required"`
		Sku            string `json:"sku" binding:"required"`
		ProductName    string `json:"productName" binding:"required"`
		PaymentStatus  string `json:"paymentStatus" binding:"required"`
		PayMethod      string `json:"payMethod" binding:"required"`
		BankName       string `json:"bankName" binding:"required"`
		Qty            string `json:"qty"`
		Desc           string `json:"desc"`
		Type           string `json:"type" binding:"required"`
	} `json:"additionalInfo" binding:"required"`
}

type NetzmeDeductDepositSplitFeeRequest struct {
	RequestId string `json:"requestId"`
	Type      string `json:"type"`
	Body      struct {
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
	} `json:"body"`
}
