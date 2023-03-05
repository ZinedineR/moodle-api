package domain

type AccessTokenResponse struct {
	Status      string `json:"status"`
	Username    string `json:"username"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiryToken int    `json:"expiry_token"`
}

type CallbackNotificationResponse struct {
	ResponseCode int    `json:"response_code"`
	ResponseDesc string `json:"response_desc"`
	ReceiptCode  string `json:"receipt_code"`
}
