package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"moodle-api/internal/base/app"
	domain2 "moodle-api/internal/base/domain"
	"moodle-api/pkg/httpclient"

	"github.com/sirupsen/logrus"

	"moodle-api/internal/auth/domain"
	"moodle-api/internal/auth/repository"
	"moodle-api/pkg/errs"
)

// NewService creates new user service
func NewService(repo repository.Repository, httpClient httpclient.Client) Service {
	return &service{authRepo: repo, httpClient: httpClient}
}

type service struct {
	authRepo   repository.Repository
	httpClient httpclient.Client
}

func (s service) StoreCredentials(ctx context.Context, cr domain.Credential) errs.Error {
	err := s.authRepo.StoreCredentials(ctx, cr)
	if err != nil {
		return err
	}
	return nil
}

func (s service) CheckClientId(ctx context.Context, clientID string) errs.Error {
	err := s.authRepo.CheckClientId(ctx, clientID)
	if err != nil {
		return err
	}
	return nil
}

func (s service) CheckClientSecret(ctx context.Context, clientSecret string) errs.Error {
	err := s.authRepo.CheckClientSecret(ctx, clientSecret)
	if err != nil {
		return err
	}
	return nil
}

func (s service) CheckClientKeyAndPrivateKey(ctx context.Context, clientID, privateKey string) errs.Error {
	err := s.authRepo.CheckClientKeyAndPrivateKey(ctx, clientID, privateKey)
	if err != nil {
		return err
	}
	return nil
}

func (s service) FindCredential(ctx context.Context, clientID string) (*domain.CredentialResponse, errs.Error) {
	result, err := s.authRepo.FindCredentialByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s service) GetAccessToken(ctx *app.Context) (*domain2.AccessTokenResponse, int, *interface{}, error) {
	var response interface{}
	var atr domain2.AccessTokenResponse
	statusCode := http.StatusBadRequest

	credential := os.Getenv("CLIENT_ID_NETZME") + ":" + os.Getenv("CLIENT_SECRET_NETZME")
	authorizationString := "Basic " + base64.StdEncoding.EncodeToString([]byte(credential))

	urlPath := os.Getenv("BASEURL_NETZME") + "/oauth/merchant/accesstoken"
	params := map[string]string{"Authorization": authorizationString}

	payloadJsonRequest := `{"grant_type": "client_credentials"}`

	statusCode, err := s.httpClient.PostJSON(ctx, urlPath, payloadJsonRequest, params, &response)

	if err != nil {
		return &atr, statusCode, &response, err
	}

	respByte, err := json.Marshal(response)
	if err != nil {
		return &atr, statusCode, &response, err
	}

	logrus.Infoln(fmt.Sprintf("REQUEST ID: %s , RESPONSE FROM TOKO-NETZME = %s", ctx.APIReqID, string(respByte)))

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
