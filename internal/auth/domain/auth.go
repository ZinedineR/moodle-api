package domain

type AccessTokenRequest struct {
	GrantType      string      `json:"grantType"`
	AdditionalInfo interface{} `json:"additionalInfo"`
}

type ResponseAccessToken struct {
	ResponseCode    string      `json:"responseCode"`
	ResponseMessage string      `json:"responseMessage"`
	AccessToken     string      `json:"accessToken"`
	TokenType       string      `json:"tokenType"`
	ExpiresIn       string      `json:"expiresIn"`
	AdditionalInfo  interface{} `json:"additionalInfo"`
}

type CredentialResponse struct {
	ClientId      string `json:"client_id"`
	ClientSecret  string `json:"client_secret"`
	PrivateKey    string `json:"private_key"`
	PublicKey     string `json:"public_key"`
	CallbackToken string `json:"callback_token"`
}

type Credential struct {
	ClientId      string `json:"client_id"`
	ClientSecret  string `json:"client_secret"`
	PrivateKey    string `json:"private_key"`
	PublicKey     string `json:"public_key"`
	CallbackToken string `json:"callback_token"`
}
