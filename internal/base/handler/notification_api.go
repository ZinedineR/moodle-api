package handler

import (
	"moodle-api/internal/base/app"
)

func (b *BaseHTTPHandler) PostCallbackNotification(ctx *app.Context, urlPath string, paymentQrisRequest string) error {
	var response interface{}
	params := map[string]string{
		"Content-Type": "application/json",
	}
	_, err := b.HttpClient.PostJSON(ctx, urlPath, paymentQrisRequest, params, &response)
	if err != nil {
		return err
	}

	return nil
}
