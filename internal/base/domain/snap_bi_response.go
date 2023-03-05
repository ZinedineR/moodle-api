package domain

type SnapStatus struct {
	ResponseCode    string      `json:"responseCode"`
	ResponseMessage interface{} `json:"responseMessage"`
}

type SnapAdditionalInfo struct {
	AdditionalInfo interface{} `json:"additionalInfo"`
}
